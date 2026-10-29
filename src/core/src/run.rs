//! The main verb, `rv-hub verify`: whole-case verification. Both front-ends call [`run`].
//!
//! ```text
//! items:   1 the case log ── 2..n every run folder ── (--rehash) every registered evidence file
//! checks:  checks.rs (same verifier code as the tools) ── cross-check: <tool> verify-log <run>/logs
//! outputs: <CASE>/runs/rv-hub/<RUN-ID>/{logs,reports}  (hashes.csv, per-item technical / summary / custody,
//!          statistics, audit chain), linked in the case log by run_started / run_finished.
//! ```
//!
//! The hub never changes another tool's file: it only appends its own run_started / run_finished to the case log
//! (under the case lock, after re-verifying it, like every tool) and writes its own run folder. When the case log
//! fails verification it is not extended: the run is then written to `out_dir/{logs,reports}/<RUN-ID>/` instead.
//! The case role stays [`CaseRole::Analysis`] (recorded in run_started), but no evidence input is needed.

use crate::audit::AuditLog;
use crate::case::{self, CASE_LOG, Case, CaseError, CaseErrorKind, CaseRole, Writer};
use crate::checks::{self, RunRef};
use crate::events::{Event, eta_ms};
use crate::findings::{self as fnd, Finding, Severity};
use crate::hash::{HashAlgo, hash_bytes, hash_reader, validate_selection};
use crate::report::{
    self, AuditRef, CaseInfo, CrossCheck, Item, ItemKind, RunInfo, RunTotals, Tally, Verdict,
};
use crate::signature::OsVerifier;
use crate::time::{utc_compact, utc_now};
use crate::tools::{self, ToolInfo};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// `--crosscheck auto|off`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrossCheckMode {
    /// Ask each run's own tool when it is discovered and Rakvor-signed, or given in `tool_overrides`.
    Auto,
    Off,
}

#[derive(Clone, Debug)]
pub struct RunConfig {
    /// The case folder to verify (`--case-dir`, required).
    pub case_dir: PathBuf,
    /// Also re-hash the registered evidence files (`--rehash`).
    pub rehash: bool,
    /// Restrict --rehash to these evidence ids (E0001…). Empty = every registered item.
    pub evidence_ids: Vec<String>,
    /// Where registered evidence is now when it is not at its registered path (looked up by file name).
    pub evidence_dirs: Vec<PathBuf>,
    pub crosscheck: CrossCheckMode,
    /// tool → CLI executable to use for the cross-check, whatever its signature (`--tool-exe NAME=PATH`).
    pub tool_overrides: BTreeMap<String, PathBuf>,
    /// Discovered tools for the cross-check. None = discover them now (only with `CrossCheckMode::Auto`).
    pub tools: Option<Vec<ToolInfo>>,
    pub crosscheck_timeout: Duration,
    /// Algorithms for the digests of the hub's own files and of the verified logs (1–2).
    pub algorithms: Vec<HashAlgo>,
    pub langs: Vec<String>,
    pub actor: String,
    /// Expected case id (`--case`): must match case.json when given.
    pub case_id: Option<String>,
    /// "cli" or "gui"
    pub frontend: String,
    /// Front-end actions to audit before the run starts: (action, details).
    pub preamble: Vec<(String, Value)>,
    pub command_line: Vec<String>,
    pub tool_name: String,
    pub tool_version: String,
    /// Custody form when the case has no jurisdiction (the case's jurisdiction always wins).
    pub jurisdiction: String,
    pub tsa_url: Option<String>,
    pub sign_cert: Option<PathBuf>,
    /// Never logged.
    pub sign_password: Option<String>,
    /// Used only when the case log fails verification (it is then never extended).
    pub out_dir: PathBuf,
    /// Recorded in run_started; [`crate::CASE_ROLE`].
    pub case_role: CaseRole,
}

impl Default for RunConfig {
    fn default() -> Self {
        RunConfig {
            case_dir: PathBuf::new(),
            rehash: false,
            evidence_ids: vec![],
            evidence_dirs: vec![],
            crosscheck: CrossCheckMode::Auto,
            tool_overrides: BTreeMap::new(),
            tools: None,
            crosscheck_timeout: Duration::from_secs(120),
            algorithms: vec![HashAlgo::Sha256],
            langs: vec!["en".into()],
            actor: "unknown".into(),
            case_id: None,
            frontend: "cli".into(),
            preamble: vec![],
            command_line: vec![],
            tool_name: crate::TOOL_NAME.into(),
            tool_version: crate::TOOL_VERSION.into(),
            jurisdiction: "co".into(),
            tsa_url: None,
            sign_cert: None,
            sign_password: None,
            out_dir: PathBuf::from("rakvor-out"),
            case_role: crate::CASE_ROLE,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RunSummary {
    pub run_id: String,
    pub items: u64,
    pub bytes: u64,
    pub errors: u64,
    pub elapsed_ms: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub info: u64,
    pub cancelled: bool,
    pub report_dir: PathBuf,
    pub log_dir: PathBuf,
    pub audit_head: String,
    /// {"status": "ok"|"pending"|"off", ...}
    pub timestamp: Value,
    pub case: Option<CaseInfo>,
    /// Distinct finding codes, sorted (what `expected_findings.json` lists).
    pub codes: Vec<String>,
}

const PROGRESS_EVERY: Duration = Duration::from_millis(150);

/// "20261029T110057Z-a1b2c3": UTC time + 6 hex of a per-process seed.
pub fn new_run_id() -> String {
    let seed = format!(
        "{:?}-{}-{}",
        std::time::SystemTime::now(),
        std::process::id(),
        crate::env::hostname()
    );
    format!(
        "{}-{}",
        utc_compact(),
        &hash_bytes(seed.as_bytes(), HashAlgo::Sha256)[..6]
    )
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Checks done before anything is written: case.json and its schema, `--case`, evidence ids.
/// Usage errors (exit 2) for a wrong folder, case id or id; Io (exit 1) when case.json cannot be read.
pub fn preflight(cfg: &RunConfig) -> Result<(String, String), CaseError> {
    let dir = &cfg.case_dir;
    let p = dir.join(case::CASE_FILE);
    if !p.is_file() {
        return Err(CaseError::new(
            CaseErrorKind::Usage,
            format!(
                "{} is not a case folder (no {})",
                dir.display(),
                case::CASE_FILE
            ),
        ));
    }
    let v: Value = std::fs::read_to_string(&p)
        .map_err(|e| {
            CaseError::new(
                CaseErrorKind::Io,
                format!("cannot read {}: {e}", p.display()),
            )
        })
        .and_then(|t| {
            serde_json::from_str(&t).map_err(|e| {
                CaseError::new(
                    CaseErrorKind::Usage,
                    format!("{} is not valid JSON: {e}", p.display()),
                )
            })
        })?;
    if v["schema"] != case::SCHEMA_CASE {
        return Err(CaseError::new(
            CaseErrorKind::Usage,
            format!(
                "{} has schema {}; this tool reads {} only",
                p.display(),
                v["schema"],
                case::SCHEMA_CASE
            ),
        ));
    }
    let case_id = v["case_id"].as_str().unwrap_or_default().to_string();
    if let Some(want) = cfg
        .case_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if want != case_id {
            return Err(CaseError::new(
                CaseErrorKind::Usage,
                format!(
                    "the case folder {} belongs to case {case_id}, not {want}",
                    dir.display()
                ),
            ));
        }
    }
    let ids = case::parse_evidence_ids(&cfg.evidence_ids)?;
    if !ids.is_empty() {
        let reg = registry_items(dir).map_err(|e| CaseError::new(CaseErrorKind::Usage, e))?;
        let unknown: Vec<&String> = ids
            .iter()
            .filter(|i| !reg.iter().any(|r| &r.evidence_id == *i))
            .collect();
        if !unknown.is_empty() {
            return Err(CaseError::new(
                CaseErrorKind::Usage,
                format!(
                    "evidence id(s) not in the case registry: {}",
                    unknown
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
    }
    let jurisdiction = match v["jurisdiction"].as_str() {
        Some(j @ ("co" | "fr")) => j.to_string(),
        _ => cfg.jurisdiction.clone(),
    };
    Ok((case_id, jurisdiction))
}

fn registry_items(dir: &Path) -> Result<Vec<case::RegistryItem>, String> {
    let p = dir.join(case::REGISTRY_JSON);
    if !p.is_file() {
        return Ok(vec![]);
    }
    let v: Value = std::fs::read_to_string(&p)
        .map_err(|e| e.to_string())
        .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
        .map_err(|e| format!("{}: {e}", p.display()))?;
    let mut items: Vec<case::RegistryItem> =
        serde_json::from_value(v["items"].clone()).map_err(|e| format!("{}: {e}", p.display()))?;
    items.sort_by_key(|i| {
        i.evidence_id
            .trim_start_matches('E')
            .parse::<u64>()
            .unwrap_or(0)
    });
    Ok(items)
}

/// Where the run writes, and whether it is linked in the case log.
struct Target {
    log_dir: PathBuf,
    report_dir: PathBuf,
    /// Some when the run is linked in the case log.
    link: Option<(Case, Writer, String, u64, String)>,
    not_extended: Option<String>,
}

fn open_target(cfg: &RunConfig, run_id: &str, case_log_intact: bool) -> Result<Target, CaseError> {
    let dir = &cfg.case_dir;
    if !case_log_intact {
        return Ok(Target {
            log_dir: cfg.out_dir.join("logs").join(run_id),
            report_dir: cfg.out_dir.join("reports").join(run_id),
            link: None,
            not_extended: Some(
                "the case log fails verification: a broken case is never extended".into(),
            ),
        });
    }
    let writer = Writer {
        tool: cfg.tool_name.clone(),
        version: cfg.tool_version.clone(),
        run_id: run_id.to_string(),
        actor: cfg.actor.clone(),
    };
    let case = Case::open(dir)?;
    let run_rel = format!("runs/{}/{}", cfg.tool_name, run_id);
    let (seq, head) = case.append(
        &writer,
        "run_started",
        json!({"tool": cfg.tool_name, "version": cfg.tool_version, "run_dir": run_rel, "frontend": cfg.frontend,
               "role": cfg.case_role.name(), "purpose": "verification", "evidence_ids": cfg.evidence_ids,
               "rehash": cfg.rehash}),
    )?;
    let run_dir = dir.join(&run_rel);
    Ok(Target {
        log_dir: run_dir.join("logs"),
        report_dir: run_dir.join("reports"),
        link: Some((case, writer, run_rel, seq, head)),
        not_extended: None,
    })
}

/// Runs the whole-case verification. Events go to `sink`; `cancel` stops after the current chunk (partial
/// reports are still written and the cancellation is audited).
pub fn run(
    cfg: &RunConfig,
    sink: &mut dyn FnMut(&Event),
    cancel: &AtomicBool,
) -> Result<RunSummary, CaseError> {
    let usage = |m: String| CaseError::new(CaseErrorKind::Usage, m);
    validate_selection(&cfg.algorithms).map_err(usage)?;
    if cfg.langs.is_empty() {
        return Err(usage("select at least one report language".into()));
    }
    if cfg.jurisdiction != "co" && cfg.jurisdiction != "fr" {
        return Err(usage(format!(
            "unknown jurisdiction '{}': use co or fr",
            cfg.jurisdiction
        )));
    }
    let (case_id, jurisdiction) = preflight(cfg)?;
    let mut cfg = cfg.clone();
    cfg.evidence_ids = case::parse_evidence_ids(&cfg.evidence_ids)?;
    cfg.jurisdiction = jurisdiction;
    let dir = cfg.case_dir.clone();
    let run_id = new_run_id();

    // Snapshot of the case as found, before the hub appends anything.
    let case_log_path = dir.join(CASE_LOG);
    let case_entries = checks::read_entries(&case_log_path);
    let case_log_bytes = std::fs::read(&case_log_path).ok();
    let case_log_intact = case::verify_log_and_registry(&dir).is_ok();
    let runs = checks::runs_of_case(&dir, &case_entries);
    let registry = registry_items(&dir);

    let target = open_target(&cfg, &run_id, case_log_intact)?;
    let result = pipeline(
        &cfg,
        sink,
        cancel,
        &run_id,
        &target,
        &case_id,
        &case_entries,
        case_log_bytes.as_deref(),
        &runs,
        registry,
    );
    if let Some((case, writer, run_rel, _, _)) = &target.link {
        finish_case(case, writer, run_rel, &cfg, &target.log_dir, &result, sink);
    }
    result.map_err(|e| CaseError::new(CaseErrorKind::Io, e))
}

/// run_finished in the case log (also after a cancel or a failure), with the run's final audit head.
fn finish_case(
    case: &Case,
    writer: &Writer,
    run_rel: &str,
    cfg: &RunConfig,
    log_dir: &Path,
    result: &Result<RunSummary, String>,
    sink: &mut dyn FnMut(&Event),
) {
    let heads = crate::audit::heads(&log_dir.join("audit.jsonl"));
    let (entries, head) = heads
        .iter()
        .next_back()
        .map(|(s, h)| (*s, json!(h)))
        .unwrap_or((0, Value::Null));
    let details = match result {
        Ok(s) => json!({
            "tool": cfg.tool_name, "version": cfg.tool_version, "run_dir": run_rel,
            "status": if s.cancelled { "cancelled" } else { "completed" },
            "audit_head": head, "audit_entries": entries,
            "timestamp_status": s.timestamp["status"].as_str().unwrap_or("off"),
            "totals": {"items": s.items, "bytes": s.bytes, "errors": s.errors, "high": s.high, "medium": s.medium,
                       "low": s.low, "info": s.info},
            "verification": s.case.as_ref().map(|c| json!(c.tally)), "codes": s.codes,
        }),
        Err(e) => json!({
            "tool": cfg.tool_name, "version": cfg.tool_version, "run_dir": run_rel, "status": "failed",
            "reason": e, "audit_head": head, "audit_entries": entries, "timestamp_status": "off", "totals": null,
        }),
    };
    if let Err(e) = case.append(writer, "run_finished", details) {
        sink(&Event::Error {
            path: None,
            message: format!("case log: run_finished not recorded: {}", e),
        });
    }
}

/// One planned item: what to check.
enum Plan {
    CaseLog,
    Run(RunRef),
    Evidence(case::RegistryItem),
}

#[allow(clippy::too_many_arguments)]
fn pipeline(
    cfg: &RunConfig,
    sink: &mut dyn FnMut(&Event),
    cancel: &AtomicBool,
    run_id: &str,
    target: &Target,
    case_id: &str,
    case_entries: &[Value],
    case_log_bytes: Option<&[u8]>,
    runs: &[RunRef],
    registry: Result<Vec<case::RegistryItem>, String>,
) -> Result<RunSummary, String> {
    let started = Instant::now();
    let started_utc = utc_now();
    let dir = &cfg.case_dir;
    let (log_dir, report_dir) = (&target.log_dir, &target.report_dir);
    let mut log = AuditLog::create(log_dir, run_id, &cfg.actor)
        .map_err(|e| format!("cannot create audit log in {}: {}", log_dir.display(), e))?;
    let io = |e: std::io::Error| format!("audit log write failed: {}", e);

    log.record(
        "run_started",
        None,
        json!({
            "tool": cfg.tool_name, "version": cfg.tool_version, "frontend": cfg.frontend, "verb": "verify",
            "algorithms": cfg.algorithms, "langs": cfg.langs, "case_id": case_id,
            "case_dir": dir.display().to_string(), "rehash": cfg.rehash, "evidence_ids": cfg.evidence_ids,
            "evidence_dirs": cfg.evidence_dirs.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "crosscheck": if cfg.crosscheck == CrossCheckMode::Auto { "auto" } else { "off" },
            "tool_overrides": cfg.tool_overrides.iter().map(|(k, v)| (k.clone(), json!(v.display().to_string()))).collect::<serde_json::Map<_, _>>(),
            "jurisdiction": cfg.jurisdiction, "tsa_url": cfg.tsa_url,
            "sign_cert": cfg.sign_cert.as_ref().map(|p| p.display().to_string()),
            "out_dir": cfg.out_dir.display().to_string(),
        }),
    )
    .map_err(io)?;
    match (&target.link, &target.not_extended) {
        (Some((case, _, run_rel, seq, head)), _) => {
            log.record(
                "case_linked",
                None,
                json!({"case_id": case.case_id, "case_dir": case.dir.display().to_string(), "role": cfg.case_role.name(),
                       "run_dir": run_rel, "case_created": false, "case_log_seq_at_start": seq,
                       "case_log_head_at_start": head, "registry_sha256": case::registry_digest(&case.dir),
                       "registry_items": case.items.len(), "jurisdiction": case.jurisdiction}),
            )
            .map_err(io)?;
        }
        (None, reason) => {
            log.record(
                "case_not_extended",
                None,
                json!({"case_id": case_id, "case_dir": dir.display().to_string(), "reason": reason}),
            )
            .map_err(io)?;
        }
    }
    for (action, details) in &cfg.preamble {
        log.record(action, None, details.clone()).map_err(io)?;
    }
    let env_json = report::pretty(&crate::env::describe(
        &cfg.tool_name,
        &cfg.tool_version,
        &cfg.frontend,
        &cfg.command_line,
    ));
    let (_, env_digest) =
        report::write_hashed(log_dir, "environment.json", &env_json, &cfg.algorithms)?;
    log.record("environment_recorded", Some("environment.json"), env_digest)
        .map_err(io)?;
    let signer = match &cfg.sign_cert {
        None => None,
        Some(p) => {
            match crate::trust::PdfSigner::load(p, cfg.sign_password.as_deref().unwrap_or("")) {
                Ok(s) => {
                    log.record(
                        "signing_certificate_loaded",
                        Some(&p.display().to_string()),
                        json!({"subject": s.subject, "certificate_sha256": s.fingerprint_sha256}),
                    )
                    .map_err(io)?;
                    Some(std::sync::Arc::new(s))
                }
                Err(e) => {
                    log.record("run_failed", None, json!({"reason": e}))
                        .map_err(io)?;
                    return Err(e);
                }
            }
        }
    };

    // Tools for the cross-check.
    let tools: Vec<ToolInfo> = match (&cfg.tools, cfg.crosscheck) {
        (_, CrossCheckMode::Off) => vec![],
        (Some(t), _) => t.clone(),
        (None, CrossCheckMode::Auto) => {
            tools::discover(&tools::DiscoverOptions::from_env(vec![]), &OsVerifier)
        }
    };
    if cfg.crosscheck == CrossCheckMode::Auto {
        log.record(
            "tools_inventoried",
            None,
            json!({"tools": tools.iter().map(|t| json!({"tool": t.tool, "version": t.version,
                "cli_exe": t.cli_exe.as_ref().map(|p| p.display().to_string()), "cli_sha256": t.cli_sha256,
                "cli_signature": t.cli_signature, "describe_source": t.describe_source})).collect::<Vec<_>>(),
                   "overrides": cfg.tool_overrides.keys().collect::<Vec<_>>()}),
        )
        .map_err(io)?;
    }

    // Plan the items.
    let mut plan: Vec<Plan> = vec![Plan::CaseLog];
    plan.extend(runs.iter().cloned().map(Plan::Run));
    let mut superseded: Vec<(String, String)> = Vec::new();
    if cfg.rehash {
        match &registry {
            Ok(items) => {
                for (i, it) in items.iter().enumerate() {
                    if !cfg.evidence_ids.is_empty() && !cfg.evidence_ids.contains(&it.evidence_id) {
                        continue;
                    }
                    if let Some(later) = items[i + 1..]
                        .iter()
                        .find(|o| case::same_path(&o.path, &it.path))
                    {
                        superseded.push((it.evidence_id.clone(), later.evidence_id.clone()));
                        continue;
                    }
                    plan.push(Plan::Evidence(it.clone()));
                }
            }
            Err(e) => {
                log.record("error", None, json!({"stage": "registry", "message": e}))
                    .map_err(io)?;
            }
        }
    }
    for (old, new) in &superseded {
        log.record(
            "evidence_superseded",
            None,
            json!({"evidence_id": old, "superseded_by": new}),
        )
        .map_err(io)?;
    }
    let size_of = |p: &Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    let mut items: Vec<Item> = Vec::with_capacity(plan.len());
    for (n, p) in plan.iter().enumerate() {
        let index = n as u64 + 1;
        let mut it = match p {
            Plan::CaseLog => Item::new(index, ItemKind::CaseLog, CASE_LOG, dir.join(CASE_LOG)),
            Plan::Run(r) => {
                let mut it = Item::new(
                    index,
                    ItemKind::Run,
                    r.rel.clone(),
                    r.log_dir(dir).join("audit.jsonl"),
                );
                it.tool = Some(r.tool.clone());
                it.run_id = Some(r.run_id.clone());
                it
            }
            Plan::Evidence(e) => {
                let name = e
                    .path
                    .rsplit(['/', '\\'])
                    .next()
                    .unwrap_or(&e.path)
                    .to_string();
                let path =
                    checks::locate(e, &cfg.evidence_dirs).unwrap_or_else(|| PathBuf::from(&e.path));
                let mut it = Item::new(
                    index,
                    ItemKind::Evidence,
                    format!("{} {}", e.evidence_id, name),
                    path,
                );
                it.evidence_id = Some(e.evidence_id.clone());
                it.intake_utc = Some(e.registered_utc.clone());
                it
            }
        };
        it.size = match p {
            Plan::CaseLog => case_log_bytes.map(|b| b.len() as u64).unwrap_or(0),
            _ => size_of(&it.path),
        };
        items.push(it);
    }
    let total_items = items.len() as u64;
    let total_bytes: u64 = items.iter().map(|i| i.size).sum();
    log.record(
        "inputs_resolved",
        None,
        json!({"items": total_items, "bytes": total_bytes, "runs": runs.len(),
               "evidence": items.iter().filter(|i| i.kind == ItemKind::Evidence).count()}),
    )
    .map_err(io)?;
    sink(&Event::RunStarted {
        run_id: run_id.to_string(),
        tool: cfg.tool_name.clone(),
        version: cfg.tool_version.clone(),
        frontend: cfg.frontend.clone(),
        algorithms: cfg.algorithms.clone(),
        langs: cfg.langs.clone(),
        total_items,
        total_bytes,
    });

    let mut tally = Tally {
        registered: registry.as_ref().map(|r| r.len() as u64).unwrap_or(0),
        ..Default::default()
    };
    let mut bytes_before = 0u64;
    let mut errors = 0u64;
    let mut cancelled = false;
    let mut last_progress = Instant::now() - PROGRESS_EVERY;
    let mut done: Vec<Item> = Vec::with_capacity(items.len());
    for (mut it, p) in items.into_iter().zip(plan.iter()) {
        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }
        let label = it.label.clone();
        sink(&Event::ItemStarted {
            index: it.index,
            path: it.path.display().to_string(),
            size: it.size,
        });
        it.audit_first_seq = log
            .record("item_started", Some(&label), json!({"index": it.index, "kind": it.kind, "path": it.path.display().to_string(), "size": it.size}))
            .map_err(io)?;

        // Digests: the case log as read at the start; other files streamed (progress + cancel per chunk).
        let algos: Vec<HashAlgo> = match p {
            Plan::Evidence(e) => {
                // At most two digests per read (product rule): first an algorithm the registry holds, so the
                // comparison is always possible (one the examiner selected if there is one), then the examiner's
                // other selections, so the hash register (hashes.csv) has the selected columns filled.
                let in_registry = |a: &HashAlgo| e.hashes.contains_key(a.name());
                let mut a: Vec<HashAlgo> = Vec::new();
                if let Some(x) = cfg.algorithms.iter().find(|x| in_registry(x)) {
                    a.push(*x);
                } else if let Some(x) = HashAlgo::ALL.into_iter().find(|x| in_registry(x)) {
                    a.push(x);
                }
                if !a.is_empty() {
                    for x in &cfg.algorithms {
                        if a.len() < HashAlgo::MAX_SELECTED && !a.contains(x) {
                            a.push(*x);
                        }
                    }
                }
                a
            }
            _ => cfg.algorithms.clone(),
        };
        let mut read_error = None;
        if let (Plan::CaseLog, Some(b)) = (p, case_log_bytes) {
            it.hashes = cfg
                .algorithms
                .iter()
                .map(|a| (*a, hash_bytes(b, *a)))
                .collect();
        } else if it.path.is_file() && !algos.is_empty() {
            let index = it.index;
            let mut on_chunk = |n: u64| {
                if last_progress.elapsed() >= PROGRESS_EVERY {
                    last_progress = Instant::now();
                    let elapsed = started.elapsed().as_millis() as u64;
                    sink(&Event::Progress {
                        done: index - 1,
                        total: total_items,
                        bytes_done: bytes_before + n,
                        bytes_total: total_bytes,
                        elapsed_ms: elapsed,
                        eta_ms: eta_ms(elapsed, bytes_before + n, total_bytes),
                    });
                }
                !cancel.load(Ordering::Relaxed)
            };
            // File::open is read-only: nothing in the case is ever opened for writing.
            match std::fs::File::open(&it.path).and_then(|f| hash_reader(f, &algos, &mut on_chunk))
            {
                Ok(Some(o)) => {
                    it.size = o.bytes;
                    it.hashes = o.digests;
                }
                Ok(None) => {
                    log.record("item_cancelled", Some(&label), json!({"index": it.index}))
                        .map_err(io)?;
                    cancelled = true;
                    break;
                }
                Err(e) => read_error = Some(e.to_string()),
            }
        }
        if !it.hashes.is_empty() {
            let hashes: BTreeMap<String, String> = it
                .hashes
                .iter()
                .map(|(a, h)| (a.name().to_string(), h.clone()))
                .collect();
            log.record(
                "item_hashed",
                Some(&label),
                json!({"index": it.index, "bytes_read": it.size, "hashes": hashes}),
            )
            .map_err(io)?;
            sink(&Event::ItemHashed {
                index: it.index,
                path: it.path.display().to_string(),
                hashes,
            });
        }

        match p {
            Plan::CaseLog => {
                checks::check_case_log(dir, case_entries, &mut it);
            }
            Plan::Run(r) => {
                checks::check_run(dir, case_id, r, &mut it);
                tally.runs += 1;
                if it.findings.iter().any(|f| f.code == fnd::RUN_LOG_BROKEN) {
                    tally.runs_broken += 1;
                } else if it.findings.iter().any(|f| f.code == fnd::RUN_LOG_INTACT) {
                    tally.runs_intact += 1;
                }
                if it
                    .findings
                    .iter()
                    .any(|f| f.code == fnd::RUN_NOT_IN_CASE_LOG)
                {
                    tally.runs_not_in_case_log += 1;
                }
                if it.findings.iter().any(|f| f.code == fnd::REVIEW_LOG_BROKEN) {
                    tally.reviews_broken += 1;
                }
                if cfg.crosscheck == CrossCheckMode::Auto {
                    let x = crosscheck(cfg, &tools, r, &mut it, &mut log)?;
                    match x.outcome.as_str() {
                        "agrees" => tally.crosscheck_agreed += 1,
                        "disagrees" => tally.crosscheck_disagreed += 1,
                        "unavailable" => tally.crosscheck_unavailable += 1,
                        _ => {}
                    }
                    it.crosscheck = Some(x);
                }
            }
            Plan::Evidence(e) => {
                tally.evidence_checked += 1;
                it.fact("fact_registered_path", e.path.clone());
                if let Some(err) = &read_error {
                    errors += 1;
                    it.error = Some(err.clone());
                    checks::missing_evidence(e, &format!("cannot be read ({err})"), &mut it);
                    tally.evidence_missing += 1;
                } else if it.hashes.is_empty() {
                    let reason = if algos.is_empty() {
                        "the registry holds no supported algorithm for it".to_string()
                    } else if cfg.evidence_dirs.is_empty() {
                        "not found at its registered path".to_string()
                    } else {
                        "not found at its registered path nor in the --evidence-dir folders"
                            .to_string()
                    };
                    checks::missing_evidence(e, &reason, &mut it);
                    tally.evidence_missing += 1;
                } else {
                    it.fact("fact_located_at", it.path.display().to_string());
                    let digests = it.hashes.clone();
                    if checks::compare_evidence(e, &digests, &mut it) {
                        tally.evidence_matched += 1;
                    } else {
                        tally.evidence_mismatched += 1;
                    }
                }
            }
        }
        if let (Some(err), false) = (&read_error, matches!(p, Plan::Evidence(_))) {
            errors += 1;
            it.error = Some(err.clone());
            it.fact("fact_problem", format!("cannot be read: {err}"));
        }
        let codes: Vec<String> = it.findings.iter().map(|f| f.code.clone()).collect();
        it.audit_last_seq = log
            .record(
                "item_verified",
                Some(&label),
                json!({"index": it.index, "kind": it.kind, "findings": it.findings, "verdict": it.verdict,
                       "facts": it.facts.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(), "status": it.status()}),
            )
            .map_err(io)?;
        sink(&Event::ItemFinished {
            index: it.index,
            path: it.path.display().to_string(),
            status: it.status().into(),
            findings: codes,
        });
        bytes_before += it.size;
        let elapsed = started.elapsed().as_millis() as u64;
        sink(&Event::Progress {
            done: it.index,
            total: total_items,
            bytes_done: bytes_before,
            bytes_total: total_bytes,
            elapsed_ms: elapsed,
            eta_ms: eta_ms(elapsed, bytes_before, total_bytes),
        });
        done.push(it);
    }
    let results = done;
    if cancelled {
        log.record(
            "run_cancelled",
            None,
            json!({"processed": results.len(), "of": total_items}),
        )
        .map_err(io)?;
        sink(&Event::Cancelled {
            done: results.len() as u64,
            elapsed_ms: started.elapsed().as_millis() as u64,
        });
    }

    // hashes.csv: the hash register of every file the hub read.
    let mut csv = format!(
        "index,path,size,{},status,error\n",
        cfg.algorithms
            .iter()
            .map(|a| a.name())
            .collect::<Vec<_>>()
            .join(",")
    );
    for r in &results {
        let hashes: Vec<String> = cfg
            .algorithms
            .iter()
            .map(|a| {
                r.hashes
                    .iter()
                    .find(|(x, _)| x == a)
                    .map(|(_, h)| h.clone())
                    .unwrap_or_default()
            })
            .collect();
        csv.push_str(&format!(
            "{},{},{},{},{},{}\n",
            r.index,
            csv_field(&r.path.display().to_string()),
            r.size,
            hashes.join(","),
            r.status(),
            csv_field(r.error.as_deref().unwrap_or(""))
        ));
    }
    let (_, csv_digest) =
        report::write_hashed(log_dir, "hashes.csv", csv.as_bytes(), &cfg.algorithms)?;
    log.record("hash_register_written", Some("hashes.csv"), csv_digest)
        .map_err(io)?;

    // Reports.
    let case_info = CaseInfo {
        case_id: case_id.to_string(),
        role: cfg.case_role.name().into(),
        dir: dir.display().to_string(),
        linked: target.link.is_some(),
        tally,
    };
    let mut info = RunInfo {
        tool_name: cfg.tool_name.clone(),
        tool_version: cfg.tool_version.clone(),
        run_id: run_id.to_string(),
        case_id: Some(case_id.to_string()),
        actor: cfg.actor.clone(),
        frontend: cfg.frontend.clone(),
        algorithms: cfg.algorithms.clone(),
        langs: cfg.langs.clone(),
        started_utc,
        finished_utc: utc_now(),
        elapsed_ms: started.elapsed().as_millis() as u64,
        cancelled,
        jurisdiction: cfg.jurisdiction.clone(),
        signer,
        timestamp: json!({"status": "off"}),
        case: Some(case_info),
    };
    let log_dir_s = log_dir.display().to_string();
    for r in &results {
        let audit = AuditRef {
            head: log.head().to_string(),
            entries: log.entries(),
            log_dir: log_dir_s.clone(),
        };
        let d = report_dir.join("items").join(r.folder());
        let files = report::write_item_reports(&d, &info, r, &audit)?;
        log.record(
            "item_reports_written",
            Some(&r.label),
            json!({"folder": format!("items/{}", r.folder()), "files": files}),
        )
        .map_err(io)?;
    }
    if !results.is_empty() {
        sink(&Event::ReportWritten {
            kind: "items".into(),
            path: report_dir.join("items").display().to_string(),
        });
    }
    let totals = RunTotals {
        items: results.len() as u64,
        bytes: results.iter().map(|r| r.size).sum(),
        errors,
    };
    if let Some(url) = &cfg.tsa_url {
        match crate::trust::timestamp_head(log_dir, log.entries(), log.head(), url) {
            Ok(ts) => {
                log.record("timestamp_obtained", Some(&ts.file), ts.to_json())
                    .map_err(io)?;
                let mut v = ts.to_json();
                v["status"] = json!("ok");
                info.timestamp = v;
            }
            Err(e) => {
                log.record("timestamp_pending", None, json!({"tsa": url, "reason": e, "covers_seq": log.entries(), "head": log.head()}))
                    .map_err(io)?;
                info.timestamp = json!({"status": "pending", "tsa": url, "reason": e});
            }
        }
        sink(&Event::Timestamp {
            status: info.timestamp["status"].as_str().unwrap_or_default().into(),
            tsa: url.clone(),
            gen_time: info.timestamp["gen_time"].as_str().map(String::from),
            reason: info.timestamp["reason"].as_str().map(String::from),
        });
    }
    let audit = AuditRef {
        head: log.head().to_string(),
        entries: log.entries(),
        log_dir: log_dir_s,
    };
    let files = report::write_statistics(report_dir, &info, &results, &totals, &audit)?;
    log.record("statistics_report_written", None, json!({"files": files}))
        .map_err(io)?;
    sink(&Event::ReportWritten {
        kind: "statistics".into(),
        path: report_dir
            .join(format!("statistics.{}.html", cfg.langs[0]))
            .display()
            .to_string(),
    });

    let mut sev: BTreeMap<Severity, u64> = BTreeMap::new();
    let mut codes: Vec<String> = Vec::new();
    for f in results.iter().flat_map(|r| &r.findings) {
        *sev.entry(f.severity).or_default() += 1;
        if !codes.contains(&f.code) {
            codes.push(f.code.clone());
        }
    }
    codes.sort();
    let get = |s: Severity| sev.get(&s).copied().unwrap_or(0);
    let summary = RunSummary {
        run_id: run_id.to_string(),
        items: totals.items,
        bytes: totals.bytes,
        errors,
        elapsed_ms: started.elapsed().as_millis() as u64,
        high: get(Severity::High),
        medium: get(Severity::Medium),
        low: get(Severity::Low),
        info: get(Severity::Info),
        cancelled,
        report_dir: report_dir.clone(),
        log_dir: log_dir.clone(),
        audit_head: String::new(),
        timestamp: info.timestamp.clone(),
        case: info.case.clone(),
        codes,
    };
    log.record("run_finished", None, json!({"items": summary.items, "bytes": summary.bytes, "errors": errors,
        "elapsed_ms": summary.elapsed_ms, "high": summary.high, "medium": summary.medium, "low": summary.low,
        "info": summary.info, "cancelled": cancelled, "codes": summary.codes}))
        .map_err(io)?;
    sink(&Event::RunFinished {
        items: summary.items,
        bytes: summary.bytes,
        errors,
        elapsed_ms: summary.elapsed_ms,
        high: summary.high,
        medium: summary.medium,
        low: summary.low,
        info: summary.info,
        report_dir: report_dir.display().to_string(),
        log_dir: log_dir.display().to_string(),
        cancelled,
    });
    Ok(RunSummary {
        audit_head: log.head().to_string(),
        ..summary
    })
}

/// Asks the run's own tool for its verify-log verdict and compares it with the hub's.
fn crosscheck(
    cfg: &RunConfig,
    tools: &[ToolInfo],
    run: &RunRef,
    it: &mut Item,
    log: &mut AuditLog,
) -> Result<CrossCheck, String> {
    let io = |e: std::io::Error| format!("audit log write failed: {}", e);
    let mut x = CrossCheck {
        tool: run.tool.clone(),
        exe: None,
        exe_sha256: None,
        outcome: "unavailable".into(),
        exit_code: None,
        reason: None,
    };
    let unavailable = |it: &mut Item, x: &mut CrossCheck, reason: String| {
        it.findings.push(
            Finding::of(fnd::CROSSCHECK_UNAVAILABLE)
                .with("tool", run.tool.clone())
                .with("run", run.rel.clone())
                .with("reason", reason.clone()),
        );
        x.reason = Some(reason);
    };
    let hub = it.verdict.unwrap_or(Verdict::NotVerifiable);
    if run.tool == cfg.tool_name {
        x.outcome = "skipped".into();
        x.reason = Some("a run of RV Hub itself: the hub's verdict is the tool's".into());
        it.fact("fact_crosscheck", "skipped (RV Hub's own run)");
        return Ok(x);
    }
    let exe = if let Some(p) = cfg.tool_overrides.get(&run.tool) {
        Some(p.clone())
    } else {
        let found: Vec<&ToolInfo> = tools
            .iter()
            .filter(|t| t.tool == run.tool && t.cli_exe.is_some())
            .collect();
        match found.iter().find(|t| t.cli_signature.is_rakvor()) {
            Some(t) => t.cli_exe.clone(),
            None => {
                let why = match found.first() {
                    None => format!("{} is not installed on this workstation", run.tool),
                    Some(t) => format!(
                        "{} is not Rakvor-signed ({})",
                        run.tool,
                        t.cli_signature.key()
                    ),
                };
                unavailable(it, &mut x, why.clone());
                it.fact("fact_crosscheck", format!("not done: {why}"));
                log.record(
                    "crosscheck",
                    Some(&run.rel),
                    json!({"tool": run.tool, "outcome": "unavailable", "reason": why}),
                )
                .map_err(io)?;
                return Ok(x);
            }
        }
    };
    let exe = exe.unwrap_or_default();
    x.exe = Some(exe.display().to_string());
    x.exe_sha256 = tools::sha256_of(&exe);
    if hub == Verdict::NotVerifiable {
        let why = "the run's log folder is missing: nothing to verify".to_string();
        unavailable(it, &mut x, why.clone());
        it.fact("fact_crosscheck", format!("not done: {why}"));
        log.record(
            "crosscheck",
            Some(&run.rel),
            json!({"tool": run.tool, "exe": x.exe, "outcome": "unavailable", "reason": why}),
        )
        .map_err(io)?;
        return Ok(x);
    }
    let log_dir = run.log_dir(&cfg.case_dir);
    let args = [
        std::ffi::OsString::from("verify-log"),
        log_dir.clone().into_os_string(),
    ];
    let out = crate::proc::run(&exe, &args, cfg.crosscheck_timeout);
    let (tool_verdict, reason) = match &out {
        Err(e) => (None, Some(format!("cannot start {}: {e}", exe.display()))),
        Ok(o) if o.timed_out => (
            None,
            Some(format!(
                "no answer within {} s",
                cfg.crosscheck_timeout.as_secs()
            )),
        ),
        Ok(o) => match o.code {
            Some(0) => (Some(Verdict::Intact), None),
            Some(3) => (Some(Verdict::Broken), None),
            c => (
                None,
                Some(format!(
                    "verify-log exited with {}",
                    c.map(|c| c.to_string())
                        .unwrap_or_else(|| "a signal".into())
                )),
            ),
        },
    };
    let output = out
        .as_ref()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .take(20)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    x.exit_code = out.as_ref().ok().and_then(|o| o.code);
    match tool_verdict {
        None => {
            let why = reason.unwrap_or_default();
            unavailable(it, &mut x, why.clone());
            it.fact("fact_crosscheck", format!("not done: {why}"));
        }
        Some(tv) if tv == hub => {
            x.outcome = "agrees".into();
            it.fact(
                "fact_crosscheck",
                format!(
                    "{} verify-log: {} (exit {}), same as RV Hub",
                    run.tool,
                    checks::verdict_word(tv),
                    x.exit_code.unwrap_or(-1)
                ),
            );
        }
        // Older verify-log implementations (rv-pdfauth, rv-imgauth) check the chain, the timestamp tokens and the
        // review log, but not truncation against the case log: their verdict is compared at that level.
        Some(tv) if Some(tv) == it.chain_verdict => {
            x.outcome = "agrees".into();
            x.reason = Some("same verdict at chain level; this tool's verify-log does not check truncation against the case log".into());
            it.fact(
                "fact_crosscheck",
                format!(
                    "{} verify-log: {} (exit {}), same as RV Hub's chain-level verdict (RV Hub, with the truncation check against the case log: {}); this tool's verify-log does not check truncation against the case log",
                    run.tool, checks::verdict_word(tv), x.exit_code.unwrap_or(-1), checks::verdict_word(hub)
                ),
            );
        }
        Some(tv) => {
            x.outcome = "disagrees".into();
            it.findings.push(
                Finding::of(fnd::TOOL_VERIFY_DISAGREES)
                    .with("tool", run.tool.clone())
                    .with("run", run.rel.clone())
                    .with("hub", checks::verdict_word(hub))
                    .with("tool_verdict", checks::verdict_word(tv))
                    .with(
                        "exit_code",
                        x.exit_code.map(|c| c.to_string()).unwrap_or_default(),
                    ),
            );
            it.fact(
                "fact_crosscheck",
                format!(
                    "{} verify-log: {} (exit {}), RV Hub: {}",
                    run.tool,
                    checks::verdict_word(tv),
                    x.exit_code.unwrap_or(-1),
                    checks::verdict_word(hub)
                ),
            );
        }
    }
    log.record(
        "crosscheck",
        Some(&run.rel),
        json!({"tool": run.tool, "exe": x.exe, "exe_sha256": x.exe_sha256, "args": ["verify-log", log_dir.display().to_string()],
               "exit_code": x.exit_code, "outcome": x.outcome, "reason": x.reason, "hub_verdict": hub,
               "hub_chain_verdict": it.chain_verdict,
               "output": output, "override": cfg.tool_overrides.contains_key(&run.tool)}),
    )
    .map_err(io)?;
    Ok(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_copy(dir: &Path) -> PathBuf {
        fn copy(from: &Path, to: &Path) {
            std::fs::create_dir_all(to).unwrap();
            for e in std::fs::read_dir(from).unwrap() {
                let e = e.unwrap();
                if e.path().is_dir() {
                    copy(&e.path(), &to.join(e.file_name()));
                } else {
                    std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
                }
            }
        }
        let case = dir.join("case");
        copy(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample/case"),
            &case,
        );
        case
    }

    fn cfg(case: &Path, out: &Path) -> RunConfig {
        RunConfig {
            case_dir: case.to_path_buf(),
            crosscheck: CrossCheckMode::Off,
            actor: "tester".into(),
            frontend: "test".into(),
            out_dir: out.to_path_buf(),
            ..Default::default()
        }
    }

    fn case_log(case: &Path) -> Vec<Value> {
        checks::read_entries(&case.join(CASE_LOG))
    }

    #[test]
    fn verify_links_its_run_and_a_cancel_still_closes_it() {
        let d = tempfile::tempdir().unwrap();
        let case = sample_copy(d.path());
        let mut events = vec![];
        let s = run(
            &cfg(&case, &d.path().join("out")),
            &mut |e| events.push(e.clone()),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!((s.high, s.items), (0, 5));
        assert_eq!(s.codes, ["RUN_LOG_INTACT"]);
        assert!(s.log_dir.starts_with(case.join("runs/rv-hub")));
        assert!(matches!(
            events.first(),
            Some(Event::RunStarted { total_items: 5, .. })
        ));
        assert!(matches!(events.last(), Some(Event::RunFinished { .. })));
        let last = case_log(&case).pop().unwrap();
        assert_eq!(
            (last["action"].as_str(), last["details"]["status"].as_str()),
            (Some("run_finished"), Some("completed"))
        );
        assert!(case::verify_case(&case).problems.is_empty());
        let s = run(
            &cfg(&case, &d.path().join("out")),
            &mut |_| {},
            &AtomicBool::new(true),
        )
        .unwrap();
        assert!(s.cancelled && s.items == 0);
        assert_eq!(
            case_log(&case).pop().unwrap()["details"]["status"],
            "cancelled"
        );
        assert!(case::verify_case(&case).problems.is_empty());
    }

    #[test]
    fn a_broken_case_log_is_never_extended() {
        let d = tempfile::tempdir().unwrap();
        let case = sample_copy(d.path());
        let lp = case.join(CASE_LOG);
        let text = std::fs::read_to_string(&lp).unwrap();
        let broken = text.replacen("\"actor\":\"Examiner PDF\"", "\"actor\":\"Mallory\"", 1);
        assert_ne!(broken, text);
        std::fs::write(&lp, &broken).unwrap();
        let out = d.path().join("out");
        let s = run(&cfg(&case, &out), &mut |_| {}, &AtomicBool::new(false)).unwrap();
        assert!(s.codes.contains(&"CASE_LOG_BROKEN".to_string()) && s.high > 0);
        assert!(s.log_dir.starts_with(out.join("logs")));
        assert!(
            !case.join("runs/rv-hub").exists(),
            "no run folder in a broken case"
        );
        assert_eq!(std::fs::read_to_string(&lp).unwrap(), broken);
        let audit = std::fs::read_to_string(s.log_dir.join("audit.jsonl")).unwrap();
        assert!(audit.contains("\"case_not_extended\""));
        assert!(!s.case.unwrap().linked);
    }

    #[test]
    fn preflight_errors_are_usage_errors() {
        let d = tempfile::tempdir().unwrap();
        let mut c = cfg(d.path(), d.path());
        assert_eq!(preflight(&c).unwrap_err().kind, CaseErrorKind::Usage);
        let case = sample_copy(d.path());
        c.case_dir = case;
        assert_eq!(preflight(&c).unwrap().0, "SAMPLE-1");
        c.evidence_ids = vec!["E0099".into()];
        assert!(preflight(&c).unwrap_err().message.contains("E0099"));
        c.evidence_ids = vec![];
        c.case_id = Some("OTHER".into());
        assert_eq!(preflight(&c).unwrap_err().exit_code(), 2);
    }
}
