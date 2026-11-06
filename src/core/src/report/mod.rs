//! Reports: one statistics report per verification run, and per verified item (the case log, each run folder,
//! each re-hashed evidence file) a technical report, a customer summary and a custody form, each in JSON
//! (language-neutral, schema-versioned), HTML and PDF (one file per selected language).
//!
//! HTML and PDF are rendered from the same view model (`*_context`), so they never disagree.

pub mod pdf;

use crate::findings::{Finding, LIMITATIONS, Severity};
use crate::hash::{HashAlgo, hash_bytes};
use crate::i18n::{Catalog, catalog};
use crate::time::human_duration;
use minijinja::Environment;
use pdf::Block;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const SCHEMA_STATISTICS: &str = "rakvor.statistics/1";
pub const SCHEMA_TECHNICAL: &str = "rakvor.item-technical/1";
pub const SCHEMA_SUMMARY: &str = "rakvor.item-summary/1";
pub const SCHEMA_CUSTODY: &str = "rakvor.item-custody/1";
const BLANK_TRANSFER_ROWS: usize = 6;

/// Custody form language per jurisdiction; an English copy is always added.
pub fn custody_langs(jurisdiction: &str) -> Vec<String> {
    let main = if jurisdiction == "fr" { "fr" } else { "es" };
    vec![main.to_string(), "en".to_string()]
}

#[derive(Clone)]
pub struct RunInfo {
    pub tool_name: String,
    pub tool_version: String,
    pub run_id: String,
    pub case_id: Option<String>,
    pub actor: String,
    pub frontend: String,
    pub algorithms: Vec<HashAlgo>,
    pub langs: Vec<String>,
    pub started_utc: String,
    pub finished_utc: String,
    pub elapsed_ms: u64,
    pub cancelled: bool,
    /// "co" (Colombia, Fiscalía) or "fr" (France, scellés)
    pub jurisdiction: String,
    pub signer: Option<std::sync::Arc<crate::trust::PdfSigner>>,
    /// {"status": "ok"|"pending"|"off", ...}
    pub timestamp: Value,
    /// The verified case folder.
    pub case: Option<CaseInfo>,
}

/// What a whole-case verification counted.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Tally {
    /// Items in the registry.
    pub registered: u64,
    pub runs: u64,
    pub runs_intact: u64,
    pub runs_broken: u64,
    pub runs_not_in_case_log: u64,
    pub reviews_broken: u64,
    pub evidence_checked: u64,
    pub evidence_matched: u64,
    pub evidence_mismatched: u64,
    pub evidence_missing: u64,
    pub crosscheck_agreed: u64,
    pub crosscheck_disagreed: u64,
    pub crosscheck_unavailable: u64,
}

impl Tally {
    /// (i18n label key, value) rows for the reports.
    pub fn rows(&self) -> Vec<(&'static str, u64)> {
        vec![
            ("registered", self.registered),
            ("runs", self.runs),
            ("runs_intact", self.runs_intact),
            ("runs_broken", self.runs_broken),
            ("runs_not_in_case_log", self.runs_not_in_case_log),
            ("reviews_broken", self.reviews_broken),
            ("evidence_checked", self.evidence_checked),
            ("evidence_matched", self.evidence_matched),
            ("evidence_mismatched", self.evidence_mismatched),
            ("evidence_missing", self.evidence_missing),
            ("crosscheck_agreed", self.crosscheck_agreed),
            ("crosscheck_disagreed", self.crosscheck_disagreed),
            ("crosscheck_unavailable", self.crosscheck_unavailable),
        ]
    }
}

#[derive(Clone, Debug)]
pub struct CaseInfo {
    pub case_id: String,
    /// The case role of this tool ("analysis").
    pub role: String,
    pub dir: String,
    /// True when this run is linked in the case log (false: the case log is broken and was not extended).
    pub linked: bool,
    pub tally: Tally,
}

impl CaseInfo {
    pub fn to_json(&self) -> Value {
        let t = &self.tally;
        json!({"case_id": self.case_id, "role": self.role, "case_dir": self.dir, "linked": self.linked,
               "counts": {"registered": t.registered, "added": 0, "verified": t.evidence_matched,
                          "mismatched": t.evidence_mismatched, "unregistered": 0},
               "verification": t})
    }
}

/// What a verified item is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    /// case-log.jsonl (with case.json and the registry digest).
    CaseLog,
    /// One run folder runs/<tool>/<RUN-ID>.
    Run,
    /// One registered evidence file, re-hashed (--rehash).
    Evidence,
}

impl ItemKind {
    pub fn key(&self) -> &'static str {
        match self {
            ItemKind::CaseLog => "case_log",
            ItemKind::Run => "run",
            ItemKind::Evidence => "evidence",
        }
    }
}

/// The hub's verdict on a run's logs, with the same rules as `<tool> verify-log` (compared in the cross-check).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Intact,
    Broken,
    /// Nothing to verify (the log folder is missing).
    NotVerifiable,
}

/// Result of asking the run's own tool (`<cli> verify-log <run>/logs`).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CrossCheck {
    pub tool: String,
    pub exe: Option<String>,
    pub exe_sha256: Option<String>,
    /// "agrees" | "disagrees" | "unavailable" | "skipped"
    pub outcome: String,
    pub exit_code: Option<i32>,
    pub reason: Option<String>,
}

/// One verified item (the items model of `rv-hub verify`).
#[derive(Clone, Debug)]
pub struct Item {
    pub index: u64,
    pub kind: ItemKind,
    /// "case-log.jsonl" | "runs/<tool>/<RUN-ID>" | "E0002 contrato.pdf"
    pub label: String,
    /// The file that was read and hashed (case-log.jsonl, the run's logs/audit.jsonl, the evidence file).
    pub path: PathBuf,
    pub size: u64,
    pub hashes: Vec<(HashAlgo, String)>,
    pub tool: Option<String>,
    pub run_id: Option<String>,
    pub evidence_id: Option<String>,
    pub intake_utc: Option<String>,
    /// (i18n label key, value): what the checks established, shown in the technical report.
    pub facts: Vec<(String, String)>,
    pub findings: Vec<Finding>,
    pub error: Option<String>,
    /// The full verify-log verdict (chain, timestamps, review log, truncation against the timestamp and the case
    /// log), as `verify::verify_log` gives it.
    pub verdict: Option<Verdict>,
    /// The chain-level verdict (chain, timestamp tokens, review log; no truncation check): what the older
    /// verify-log of rv-pdfauth / rv-imgauth checks.
    pub chain_verdict: Option<Verdict>,
    pub crosscheck: Option<CrossCheck>,
    pub audit_first_seq: u64,
    pub audit_last_seq: u64,
}

impl Item {
    pub fn new(index: u64, kind: ItemKind, label: impl Into<String>, path: PathBuf) -> Item {
        Item {
            index,
            kind,
            label: label.into(),
            path,
            size: 0,
            hashes: vec![],
            tool: None,
            run_id: None,
            evidence_id: None,
            intake_utc: None,
            facts: vec![],
            findings: vec![],
            error: None,
            verdict: None,
            chain_verdict: None,
            crosscheck: None,
            audit_first_seq: 0,
            audit_last_seq: 0,
        }
    }

    pub fn fact(&mut self, key: &str, value: impl Into<String>) {
        self.facts.push((key.to_string(), value.into()));
    }

    /// The label shown as the item's name.
    pub fn file_name(&self) -> String {
        self.label.clone()
    }

    /// ok = nothing above informational; attention = medium/low; problem = high.
    pub fn status(&self) -> &'static str {
        match self.findings.iter().map(|f| f.severity).max() {
            Some(Severity::High) => "problem",
            Some(Severity::Medium) | Some(Severity::Low) => "attention",
            _ => "ok",
        }
    }

    pub fn has_high(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::High)
    }

    /// Folder name for this item's reports: "00002-run-rv-pdfauth-<RUN-ID>" (sanitised, max 60 chars).
    pub fn folder(&self) -> String {
        let name = match self.kind {
            ItemKind::CaseLog => "case-log".to_string(),
            ItemKind::Run => format!(
                "run-{}-{}",
                self.tool.as_deref().unwrap_or("x"),
                self.run_id.as_deref().unwrap_or("x")
            ),
            ItemKind::Evidence => self.label.replace(' ', "-"),
        };
        let clean: String = name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') {
                    c
                } else {
                    '_'
                }
            })
            .take(60)
            .collect();
        format!("{:05}-{}", self.index, clean)
    }
}

pub struct AuditRef {
    pub head: String,
    pub entries: u64,
    pub log_dir: String,
}

pub struct RunTotals {
    pub items: u64,
    pub bytes: u64,
    pub errors: u64,
}

fn env() -> &'static Environment<'static> {
    static E: OnceLock<Environment<'static>> = OnceLock::new();
    E.get_or_init(|| {
        let mut e = Environment::new();
        e.add_template(
            "statistics.html",
            include_str!("../../../../templates/statistics.html"),
        )
        .expect("template");
        e.add_template(
            "technical.html",
            include_str!("../../../../templates/technical.html"),
        )
        .expect("template");
        e.add_template(
            "summary.html",
            include_str!("../../../../templates/summary.html"),
        )
        .expect("template");
        e.add_template(
            "custody.html",
            include_str!("../../../../templates/custody.html"),
        )
        .expect("template");
        e
    })
}

const CSS: &str = include_str!("../../../../templates/report.css");
const LOGO_SVG: &str = include_str!("../../../../templates/rv-mark.svg");

pub fn render_html(template: &str, ctx: &Value) -> Result<String, String> {
    env()
        .get_template(template)
        .and_then(|t| t.render(minijinja::value::Serde(ctx)))
        .map_err(|e| format!("template {}: {}", template, e))
}

fn finding_view(c: &Catalog, f: &Finding) -> Value {
    let (title, shows, dnp) = c.finding(&f.code, &f.params);
    json!({"code": f.code, "severity": f.severity.key(), "severity_label": c.severity(f.severity.key()), "title": title, "shows": shows, "does_not_prove": dnp})
}

fn run_view(c: &Catalog, run: &RunInfo) -> Value {
    json!({
        "run_id": run.run_id, "case_id": run.case_id, "actor": run.actor, "frontend": run.frontend,
        "started_utc": run.started_utc, "finished_utc": run.finished_utc,
        "duration_text": human_duration(run.elapsed_ms),
        "algorithms_text": run.algorithms.iter().map(|a| a.name()).collect::<Vec<_>>().join(" + "),
        "cancelled": run.cancelled,
        "lang": c.lang,
    })
}

fn base(c: &Catalog, run: &RunInfo) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("lang".into(), json!(c.lang));
    m.insert("t".into(), c.labels().clone());
    m.insert("css".into(), json!(CSS));
    m.insert(
        "tool".into(),
        json!({"name": run.tool_name, "version": run.tool_version}),
    );
    m.insert("run".into(), run_view(c, run));
    m.insert(
        "limitations".into(),
        json!(
            LIMITATIONS
                .iter()
                .map(|l| c.limitation(l))
                .collect::<Vec<_>>()
        ),
    );
    m.insert("brand".into(), c.brand().clone());
    m.insert("logo_svg".into(), json!(LOGO_SVG));
    m.insert(
        "signature".into(),
        json!({"signed": run.signer.is_some(), "by": run.signer.as_ref().map(|s| s.subject.clone()).unwrap_or_default(),
               "certificate_sha256": run.signer.as_ref().map(|s| s.fingerprint_sha256.clone()).unwrap_or_default()}),
    );
    let mut ts = run.timestamp.clone();
    if !ts.is_object() {
        ts = json!({"status": "off"});
    }
    let label = c.label(&format!(
        "timestamp_{}",
        ts["status"].as_str().unwrap_or("off")
    ));
    ts["status_label"] = json!(label);
    m.insert("timestamp".into(), ts);
    m
}

fn throughput(bytes: u64, ms: u64) -> String {
    if ms == 0 {
        return "-".into();
    }
    let per_s = bytes as f64 * 1000.0 / ms as f64;
    if per_s >= 1048576.0 {
        format!("{:.1} MiB/s", per_s / 1048576.0)
    } else {
        format!("{:.1} KiB/s", per_s / 1024.0)
    }
}

/// Keeps reports readable at scale: the first `max` names, then "… (+N)".
pub fn capped_list(names: &[String], max: usize) -> String {
    if names.len() <= max {
        names.join(", ")
    } else {
        format!(
            "{}, \u{2026} (+{})",
            names[..max].join(", "),
            names.len() - max
        )
    }
}

fn kind_label(c: &Catalog, k: ItemKind) -> String {
    c.label(&format!("kind_{}", k.key()))
}

fn case_view(c: &Catalog, run: &RunInfo) -> Value {
    run.case
        .as_ref()
        .map(|ci| {
            let rows: Vec<Value> = ci
                .tally
                .rows()
                .into_iter()
                .map(|(k, n)| json!({"label": c.label(k), "value": n}))
                .collect();
            json!({"case_id": ci.case_id, "role": ci.role, "dir": ci.dir, "linked": ci.linked,
                   "linked_text": c.label(if ci.linked { "case_linked_yes" } else { "case_linked_no" }), "rows": rows})
        })
        .unwrap_or(Value::Null)
}

pub fn statistics_context(
    lang: &str,
    run: &RunInfo,
    items: &[Item],
    totals: &RunTotals,
    audit: &AuditRef,
) -> Value {
    let c = catalog(lang);
    let mut m = base(c, run);
    let mut sev: BTreeMap<Severity, u64> = BTreeMap::new();
    let mut codes: BTreeMap<String, u64> = BTreeMap::new();
    let mut kinds: BTreeMap<ItemKind, u64> = BTreeMap::new();
    for it in items {
        for f in &it.findings {
            *sev.entry(f.severity).or_default() += 1;
            *codes.entry(f.code.clone()).or_default() += 1;
        }
        *kinds.entry(it.kind).or_default() += 1;
    }
    let severity_rows: Vec<Value> = [Severity::High, Severity::Medium, Severity::Low, Severity::Info]
        .iter()
        .map(|s| json!({"key": s.key(), "label": c.severity(s.key()), "count": sev.get(s).copied().unwrap_or(0)}))
        .collect();
    let code_rows: Vec<Value> = codes.iter().map(|(code, n)| json!({"code": code, "title": c.finding(code, &BTreeMap::new()).0, "count": n})).collect();
    let type_rows: Vec<Value> = kinds
        .iter()
        .map(|(k, n)| json!({"name": kind_label(c, *k), "count": n}))
        .collect();
    let item_rows: Vec<Value> = items
        .iter()
        .map(|it| {
            json!({"index": it.index, "file_name": it.file_name(), "kind": kind_label(c, it.kind), "size": it.size,
                   "finding_count": it.findings.len(), "evidence_id": it.evidence_id,
                   "status": it.status(), "status_label": c.label(&format!("status_{}", it.status())),
                   "link": format!("items/{}/technical.{}.html", it.folder(), lang)})
        })
        .collect();
    m.insert("totals".into(), json!({"items": totals.items, "bytes": totals.bytes, "errors": totals.errors, "throughput_text": throughput(totals.bytes, run.elapsed_ms)}));
    m.insert("severity_rows".into(), json!(severity_rows));
    m.insert("code_rows".into(), json!(code_rows));
    m.insert("type_rows".into(), json!(type_rows));
    m.insert("item_rows".into(), json!(item_rows));
    m.insert("case".into(), case_view(c, run));
    m.insert(
        "audit".into(),
        json!({"head": audit.head, "entries": audit.entries, "log_dir": audit.log_dir}),
    );
    Value::Object(m)
}

fn item_view(c: &Catalog, it: &Item) -> Value {
    let status = it.status();
    let (alg, hash) = it
        .hashes
        .first()
        .map(|(a, h)| (a.name().to_string(), h.clone()))
        .unwrap_or_else(|| ("-".into(), c.label("none")));
    let facts: Vec<Value> = it
        .facts
        .iter()
        .map(|(k, v)| json!({"label": c.label(k), "value": v}))
        .collect();
    json!({
        "index": it.index, "file_name": it.file_name(), "path": it.path.display().to_string(), "size": it.size,
        "kind": it.kind.key(), "detected_text": kind_label(c, it.kind), "facts": facts,
        "status": status, "status_label": c.label(&format!("status_{}", status)),
        "summary_text": c.label(&format!("summary_{}", status)), "next_text": c.label(&format!("next_{}", status)),
        "primary_algorithm": alg, "primary_hash": hash,
        "audit_first_seq": it.audit_first_seq, "audit_last_seq": it.audit_last_seq,
        "evidence_id": it.evidence_id, "intake_utc": it.intake_utc,
    })
}

pub fn item_context(lang: &str, run: &RunInfo, it: &Item, audit: &AuditRef) -> Value {
    let c = catalog(lang);
    let mut m = base(c, run);
    m.insert("item".into(), item_view(c, it));
    m.insert("case".into(), case_view(c, run));
    m.insert(
        "hash_rows".into(),
        json!(
            it.hashes
                .iter()
                .map(|(a, h)| json!({"algorithm": a.name(), "value": h}))
                .collect::<Vec<_>>()
        ),
    );
    m.insert(
        "findings".into(),
        json!(
            it.findings
                .iter()
                .map(|f| finding_view(c, f))
                .collect::<Vec<_>>()
        ),
    );
    m.insert(
        "audit".into(),
        json!({"head": audit.head, "entries": audit.entries, "log_dir": audit.log_dir}),
    );
    Value::Object(m)
}

// ---------- JSON (language-neutral; texts included for each selected language) ----------

fn findings_json(it: &Item, langs: &[String]) -> Value {
    json!(
        it.findings
            .iter()
            .map(|f| {
                let texts: BTreeMap<String, Value> = langs
                    .iter()
                    .map(|l| {
                        let (title, shows, dnp) = catalog(l).finding(&f.code, &f.params);
                        (
                            l.clone(),
                            json!({"title": title, "shows": shows, "does_not_prove": dnp}),
                        )
                    })
                    .collect();
                json!({"code": f.code, "severity": f.severity, "params": f.params, "text": texts})
            })
            .collect::<Vec<_>>()
    )
}

fn run_json(run: &RunInfo) -> Value {
    json!({"run_id": run.run_id, "case_id": run.case_id, "actor": run.actor, "frontend": run.frontend,
           "algorithms": run.algorithms, "langs": run.langs, "started_utc": run.started_utc,
           "finished_utc": run.finished_utc, "elapsed_ms": run.elapsed_ms, "cancelled": run.cancelled,
           "jurisdiction": run.jurisdiction, "pdf_signed_by": run.signer.as_ref().map(|s| s.subject.clone()),
           "pdf_signer_certificate_sha256": run.signer.as_ref().map(|s| s.fingerprint_sha256.clone())})
}

fn facts_json(it: &Item) -> Value {
    json!(
        it.facts
            .iter()
            .map(|(k, v)| json!({"key": k, "value": v}))
            .collect::<Vec<_>>()
    )
}

pub fn statistics_json(
    run: &RunInfo,
    items: &[Item],
    totals: &RunTotals,
    audit: &AuditRef,
) -> Value {
    let mut sev: BTreeMap<&str, u64> = ["high", "medium", "low", "info"]
        .iter()
        .map(|k| (*k, 0))
        .collect();
    let mut codes: BTreeMap<String, u64> = BTreeMap::new();
    let mut status: BTreeMap<&str, u64> = BTreeMap::new();
    let mut kinds: BTreeMap<&str, u64> = BTreeMap::new();
    for it in items {
        for f in &it.findings {
            *sev.entry(f.severity.key()).or_default() += 1;
            *codes.entry(f.code.clone()).or_default() += 1;
        }
        *status.entry(it.status()).or_default() += 1;
        *kinds.entry(it.kind.key()).or_default() += 1;
    }
    json!({
        "schema": SCHEMA_STATISTICS,
        "tool": {"name": run.tool_name, "version": run.tool_version},
        "run": run_json(run),
        "totals": {"items": totals.items, "bytes": totals.bytes, "errors": totals.errors},
        "findings_by_severity": sev, "findings_by_code": codes, "items_by_status": status,
        // Same keys as the tools' statistics.json; for the hub the "type" of an item is its kind.
        "items_by_type": kinds, "duplicate_groups": [],
        "case": run.case.as_ref().map(|c| c.to_json()),
        "items": items.iter().map(|it| json!({"index": it.index, "kind": it.kind, "label": it.label,
              "evidence_id": it.evidence_id, "tool": it.tool, "run_id": it.run_id,
              "path": it.path.display().to_string(), "size": it.size, "status": it.status(), "verdict": it.verdict,
              "crosscheck": it.crosscheck.as_ref().map(|x| x.outcome.clone()),
              "findings": it.findings.iter().map(|f| f.code.clone()).collect::<Vec<_>>(), "report_folder": format!("items/{}", it.folder())})).collect::<Vec<_>>(),
        "limitations": LIMITATIONS,
        "audit": {"head": audit.head, "entries": audit.entries, "log_dir": audit.log_dir},
        "timestamp": if run.timestamp.is_object() { run.timestamp.clone() } else { json!({"status": "off"}) },
    })
}

/// How an item relates to the case registry, in the shared vocabulary (schemas/item-technical.schema.json):
/// "verified" / "mismatch" for a re-hashed evidence file, null otherwise (logs, evidence not found).
fn registry_status(it: &Item) -> Option<&'static str> {
    if it.kind != ItemKind::Evidence
        || it
            .findings
            .iter()
            .any(|f| f.code == crate::findings::EVIDENCE_MISSING)
    {
        return None;
    }
    if it
        .findings
        .iter()
        .any(|f| f.code == crate::findings::EVIDENCE_REHASH_MISMATCH)
    {
        Some("mismatch")
    } else {
        Some("verified")
    }
}

pub fn technical_json(run: &RunInfo, it: &Item) -> Value {
    json!({
        "schema": SCHEMA_TECHNICAL,
        "tool": {"name": run.tool_name, "version": run.tool_version},
        "run": run_json(run),
        "item": {"index": it.index, "kind": it.kind, "label": it.label, "evidence_id": it.evidence_id,
                 "tool": it.tool, "run_id": it.run_id, "path": it.path.display().to_string(), "file_name": it.file_name(),
                 "size": it.size, "status": it.status(), "verdict": it.verdict, "error": it.error},
        "facts": facts_json(it),
        "crosscheck": it.crosscheck,
        "case": run.case.as_ref().map(|c| json!({"case_id": c.case_id, "role": c.role, "case_dir": c.dir,
                 "status": registry_status(it), "intake_utc": it.intake_utc})),
        "hashes": it.hashes.iter().map(|(a, h)| (a.name().to_string(), json!(h))).collect::<serde_json::Map<_, _>>(),
        "findings": findings_json(it, &run.langs),
        "limitations": LIMITATIONS,
        "audit": {"first_seq": it.audit_first_seq, "last_seq": it.audit_last_seq},
    })
}

pub fn summary_json(run: &RunInfo, it: &Item) -> Value {
    let texts: BTreeMap<String, Value> = run
        .langs
        .iter()
        .map(|l| {
            let c = catalog(l);
            (l.clone(), json!({"status": c.label(&format!("status_{}", it.status())), "summary": c.label(&format!("summary_{}", it.status())), "next_step": c.label(&format!("next_{}", it.status()))}))
        })
        .collect();
    json!({
        "schema": SCHEMA_SUMMARY,
        "run_id": run.run_id, "case_id": run.case_id,
        "item": {"index": it.index, "kind": it.kind, "evidence_id": it.evidence_id, "file_name": it.file_name()},
        "status": it.status(),
        "fingerprint": it.hashes.first().map(|(a, h)| json!({"algorithm": a.name(), "value": h})),
        "findings": findings_json(it, &run.langs),
        "text": texts,
    })
}

// ---------- PDF (built from the same view model as HTML) ----------

fn s(v: &Value, path: &str) -> String {
    let mut cur = v;
    for p in path.split('.') {
        cur = &cur[p];
    }
    match cur {
        Value::String(x) => x.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn arr<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v[key].as_array().map(|a| a.as_slice()).unwrap_or(&[])
}

fn header(ctx: &Value, title_key: &str, subtitle: String) -> Vec<Block> {
    vec![
        Block::Title(s(ctx, &format!("t.{}", title_key))),
        Block::Subtitle(subtitle),
    ]
}

fn signature_row(ctx: &Value) -> (String, String) {
    let t = |k: &str| s(ctx, &format!("t.{}", k));
    let v = if ctx["signature"]["signed"].as_bool() == Some(true) {
        format!(
            "{} {} ({} {})",
            t("signed_by"),
            s(ctx, "signature.by"),
            t("certificate_sha256"),
            s(ctx, "signature.certificate_sha256")
        )
    } else {
        t("not_signed")
    };
    (t("signature"), v)
}

/// Renders blocks with the Rakvor band, footer and tagline; signs when the run has a certificate.
fn finish(ctx: &Value, title: &str, blocks: &[Block], run: &RunInfo) -> Result<Vec<u8>, String> {
    let footer = format!(
        "{} {} {} \u{00B7} {}",
        s(ctx, "t.generated_by"),
        s(ctx, "tool.name"),
        s(ctx, "tool.version"),
        s(ctx, "run.run_id")
    );
    let producer = format!("{} {}", s(ctx, "tool.name"), s(ctx, "tool.version"));
    let (page, of, descriptor, tagline) = (
        s(ctx, "t.page"),
        s(ctx, "t.of"),
        s(ctx, "brand.descriptor"),
        s(ctx, "brand.tagline"),
    );
    let meta = pdf::Meta {
        title,
        footer: &footer,
        page_word: &page,
        of_word: &of,
        producer: &producer,
        descriptor: &descriptor,
        tagline: &tagline,
    };
    match &run.signer {
        Some(signer) => {
            let f = |data: &[u8]| signer.sign_detached(data);
            pdf::render(blocks, &meta, Some(&f))
        }
        None => pdf::render(blocks, &meta, None),
    }
}

pub fn statistics_pdf(ctx: &Value, run: &RunInfo) -> Result<Vec<u8>, String> {
    let t = |k: &str| s(ctx, &format!("t.{}", k));
    let mut b = header(
        ctx,
        "title_statistics",
        format!("{}: {}", t("run_id"), s(ctx, "run.run_id")),
    );
    if ctx["run"]["cancelled"].as_bool() == Some(true) {
        b.push(Block::Note(t("cancelled_note")));
    }
    let mut kv = vec![(
        t("tool"),
        format!("{} {}", s(ctx, "tool.name"), s(ctx, "tool.version")),
    )];
    if !s(ctx, "run.case_id").is_empty() {
        kv.push((t("case"), s(ctx, "run.case_id")));
    }
    for (k, p) in [
        ("actor", "run.actor"),
        ("started", "run.started_utc"),
        ("finished", "run.finished_utc"),
        ("duration", "run.duration_text"),
        ("frontend", "run.frontend"),
        ("algorithms", "run.algorithms_text"),
        ("items", "totals.items"),
        ("bytes", "totals.bytes"),
        ("errors", "totals.errors"),
        ("throughput", "totals.throughput_text"),
    ] {
        kv.push((t(k), s(ctx, p)));
    }
    b.push(Block::Kv(kv));
    b.push(Block::Heading(t("findings_by_severity")));
    b.push(Block::Kv(
        arr(ctx, "severity_rows")
            .iter()
            .map(|r| (s(r, "label"), s(r, "count")))
            .collect(),
    ));
    b.push(Block::Heading(t("findings_by_code")));
    let codes = arr(ctx, "code_rows");
    if codes.is_empty() {
        b.push(Block::Para(t("none")))
    } else {
        b.push(Block::Kv(
            codes
                .iter()
                .map(|r| (s(r, "title"), s(r, "count")))
                .collect(),
        ))
    }
    b.push(Block::Heading(t("by_type")));
    b.push(Block::Kv(
        arr(ctx, "type_rows")
            .iter()
            .map(|r| (s(r, "name"), s(r, "count")))
            .collect(),
    ));
    if ctx["case"].is_object() {
        b.push(Block::Heading(t("case_verification")));
        let mut rows = vec![
            (t("case"), s(ctx, "case.case_id")),
            (t("case_dir"), s(ctx, "case.dir")),
            (t("case_linked"), s(ctx, "case.linked_text")),
        ];
        for r in arr(&ctx["case"], "rows") {
            rows.push((s(r, "label"), s(r, "value")));
        }
        b.push(Block::Kv(rows));
    }
    b.push(Block::Heading(t("items")));
    b.push(Block::Kv(
        arr(ctx, "item_rows")
            .iter()
            .map(|r| {
                (
                    format!(
                        "#{}  {}  ({})",
                        s(r, "index"),
                        s(r, "file_name"),
                        s(r, "kind")
                    ),
                    format!(
                        "{} \u{00B7} {} {} \u{00B7} {} {}",
                        s(r, "status_label"),
                        s(r, "size"),
                        t("bytes").to_lowercase(),
                        s(r, "finding_count"),
                        t("findings").to_lowercase()
                    ),
                )
            })
            .collect(),
    ));
    b.push(Block::Heading(t("limitations")));
    for l in arr(ctx, "limitations") {
        b.push(Block::Bullet(l.as_str().unwrap_or_default().into()));
    }
    b.push(Block::Heading(t("timestamp")));
    let mut ts_rows = vec![(t("status"), s(ctx, "timestamp.status_label"))];
    if !s(ctx, "timestamp.tsa").is_empty() {
        ts_rows.push((t("tsa"), s(ctx, "timestamp.tsa")));
    }
    if !s(ctx, "timestamp.gen_time").is_empty() {
        ts_rows.push((t("gen_time"), s(ctx, "timestamp.gen_time")));
        ts_rows.push((t("covers"), format!("#{}", s(ctx, "timestamp.covers_seq"))));
        ts_rows.push((t("audit_head"), s(ctx, "timestamp.head")));
    }
    ts_rows.push(signature_row(ctx));
    b.push(Block::Kv(ts_rows));
    b.push(Block::Heading(t("audit")));
    b.push(Block::Kv(vec![
        (t("audit_head"), s(ctx, "audit.head")),
        (t("audit_entries"), s(ctx, "audit.entries")),
        (t("log_dir"), s(ctx, "audit.log_dir")),
    ]));
    finish(ctx, &t("title_statistics"), &b, run)
}

pub fn technical_pdf(ctx: &Value, run: &RunInfo) -> Result<Vec<u8>, String> {
    let t = |k: &str| s(ctx, &format!("t.{}", k));
    let mut b = header(
        ctx,
        "title_technical",
        format!(
            "{} #{} \u{00B7} {} \u{00B7} {}: {}",
            t("item"),
            s(ctx, "item.index"),
            s(ctx, "item.file_name"),
            t("run_id"),
            s(ctx, "run.run_id")
        ),
    );
    let mut rows = vec![
        (t("path"), s(ctx, "item.path")),
        (t("size"), s(ctx, "item.size")),
        (t("kind"), s(ctx, "item.detected_text")),
        (t("status"), s(ctx, "item.status_label")),
    ];
    for f in arr(&ctx["item"], "facts") {
        rows.push((s(f, "label"), s(f, "value")));
    }
    if ctx["case"].is_object() {
        rows.push((t("case"), s(ctx, "case.case_id")));
        rows.push((
            t("evidence_id"),
            if s(ctx, "item.evidence_id").is_empty() {
                t("none")
            } else {
                s(ctx, "item.evidence_id")
            },
        ));
        if !s(ctx, "item.intake_utc").is_empty() {
            rows.push((t("intake_date"), s(ctx, "item.intake_utc")));
        }
    }
    b.push(Block::Kv(rows));
    b.push(Block::Heading(t("hashes")));
    b.push(Block::Kv(
        arr(ctx, "hash_rows")
            .iter()
            .map(|h| (s(h, "algorithm"), s(h, "value")))
            .collect(),
    ));
    b.push(Block::Heading(t("findings")));
    let f = arr(ctx, "findings");
    if f.is_empty() {
        b.push(Block::Para(t("none")));
    }
    for x in f {
        b.push(Block::Finding {
            badge: s(x, "severity_label"),
            title: format!("{}  ({})", s(x, "title"), s(x, "code")),
            rows: vec![
                (t("shows"), s(x, "shows")),
                (t("does_not_prove"), s(x, "does_not_prove")),
            ],
        });
    }
    b.push(Block::Heading(t("method")));
    b.push(Block::Para(t("method_text")));
    b.push(Block::Heading(t("audit")));
    b.push(Block::Kv(vec![
        (
            t("audit_entries"),
            format!(
                "#{} \u{2013} #{}",
                s(ctx, "item.audit_first_seq"),
                s(ctx, "item.audit_last_seq")
            ),
        ),
        (t("log_dir"), s(ctx, "audit.log_dir")),
        signature_row(ctx),
    ]));
    b.push(Block::Heading(t("limitations")));
    for l in arr(ctx, "limitations") {
        b.push(Block::Bullet(l.as_str().unwrap_or_default().into()));
    }
    finish(ctx, &t("title_technical"), &b, run)
}

pub fn summary_pdf(ctx: &Value, run: &RunInfo) -> Result<Vec<u8>, String> {
    let t = |k: &str| s(ctx, &format!("t.{}", k));
    let mut sub = s(ctx, "item.file_name");
    if !s(ctx, "item.evidence_id").is_empty() {
        sub = format!(
            "{} \u{00B7} {}: {}",
            sub,
            t("evidence_id"),
            s(ctx, "item.evidence_id")
        );
    }
    if !s(ctx, "run.case_id").is_empty() {
        sub = format!("{} \u{00B7} {}: {}", sub, t("case"), s(ctx, "run.case_id"));
    }
    let mut b = header(ctx, "title_summary", sub);
    b.push(Block::Status(s(ctx, "item.status_label")));
    b.push(Block::Para(s(ctx, "item.summary_text")));
    b.push(Block::Heading(t("what_we_did")));
    b.push(Block::Para(t("method_text")));
    b.push(Block::Heading(t("what_we_found")));
    let f = arr(ctx, "findings");
    if f.is_empty() {
        b.push(Block::Para(t("none")));
    }
    for x in f {
        b.push(Block::Bullet(format!(
            "{}. {}",
            s(x, "title"),
            s(x, "shows")
        )));
    }
    b.push(Block::Heading(t("fingerprint")));
    b.push(Block::Para(t("fingerprint_text")));
    b.push(Block::Kv(vec![(
        s(ctx, "item.primary_algorithm"),
        s(ctx, "item.primary_hash"),
    )]));
    b.push(Block::Heading(t("next_steps")));
    b.push(Block::Para(s(ctx, "item.next_text")));
    finish(ctx, &t("title_summary"), &b, run)
}

// ---------- Chain-of-custody form (one per item; jurisdiction language + English) ----------

pub fn custody_context(lang: &str, run: &RunInfo, it: &Item, audit: &AuditRef) -> Value {
    let mut ctx = item_context(lang, run, it, audit);
    let c = catalog(lang);
    let j = if run.jurisdiction == "fr" { "fr" } else { "co" };
    let mut cu = c.custody().clone();
    let get = |k: &str| c.custody()[k].as_str().unwrap_or(k).to_string();
    let mut params = BTreeMap::new();
    for (k, v) in [
        ("tool", run.tool_name.clone()),
        ("version", run.tool_version.clone()),
        ("run_id", run.run_id.clone()),
        ("start", run.started_utc.clone()),
        ("end", run.finished_utc.clone()),
        ("first", it.audit_first_seq.to_string()),
        ("last", it.audit_last_seq.to_string()),
    ] {
        params.insert(k.to_string(), v);
    }
    cu["title"] = json!(get(&format!("title_{}", j)));
    cu["basis"] = json!(get(&format!("basis_{}", j)));
    cu["case_label"] = json!(get(&format!("case_{}", j)));
    cu["evidence_id_label"] = json!(get(&format!("evidence_id_{}", j)));
    cu["evidence_id"] = json!(custody_evidence_id(run, it));
    cu["intake_utc"] = json!(it.intake_utc);
    cu["jurisdiction_label"] = json!(c.ui(&format!("jur_{}", j)));
    cu["operation_text"] = json!(crate::i18n::fill(&get("operation_text"), &params));
    cu["blank_rows"] = json!((0..BLANK_TRANSFER_ROWS).collect::<Vec<_>>());
    ctx["custody"] = cu;
    ctx
}

/// The case registry id (E0001…) when the run is linked to a case, else "<RUN-ID>-<NNNNN>".
fn custody_evidence_id(run: &RunInfo, it: &Item) -> String {
    it.evidence_id
        .clone()
        .unwrap_or_else(|| format!("{}-{:05}", run.run_id, it.index))
}

pub fn custody_json(run: &RunInfo, it: &Item) -> Value {
    json!({
        "schema": SCHEMA_CUSTODY,
        "jurisdiction": run.jurisdiction,
        "run_id": run.run_id, "case_id": run.case_id,
        "evidence_id": custody_evidence_id(run, it),
        "intake_utc": it.intake_utc,
        "item": {"index": it.index, "path": it.path.display().to_string(), "file_name": it.file_name(), "size": it.size},
        "hashes": it.hashes.iter().map(|(a, h)| (a.name().to_string(), json!(h))).collect::<serde_json::Map<_, _>>(),
        "examiner": run.actor,
        "operations": [{"tool": run.tool_name, "version": run.tool_version, "start_utc": run.started_utc, "end_utc": run.finished_utc,
                        "audit_first_seq": it.audit_first_seq, "audit_last_seq": it.audit_last_seq}],
        "transfers": [],
    })
}

pub fn custody_pdf(ctx: &Value, run: &RunInfo) -> Result<Vec<u8>, String> {
    let c = |k: &str| s(ctx, &format!("custody.{}", k));
    let t = |k: &str| s(ctx, &format!("t.{}", k));
    let mut b = vec![
        Block::Title(c("title")),
        Block::Subtitle(format!(
            "{}: {} \u{00B7} {}: {}",
            t("jurisdiction"),
            c("jurisdiction_label"),
            t("run_id"),
            s(ctx, "run.run_id")
        )),
        Block::Note(c("basis")),
        Block::Kv(vec![
            (c("case_label"), s(ctx, "run.case_id")),
            (c("evidence_id_label"), c("evidence_id")),
            (
                c("description"),
                format!(
                    "{} \u{00B7} {} bytes \u{00B7} {}",
                    s(ctx, "item.file_name"),
                    s(ctx, "item.size"),
                    s(ctx, "item.detected_text")
                ),
            ),
            (c("location"), s(ctx, "item.path")),
        ]),
        Block::Heading(c("integrity")),
        Block::Kv(
            arr(ctx, "hash_rows")
                .iter()
                .map(|h| (s(h, "algorithm"), s(h, "value")))
                .collect(),
        ),
        Block::Heading(c("operations")),
        Block::Para(c("operation_text")),
        Block::Kv(vec![(c("examiner"), s(ctx, "run.actor"))]),
        Block::Heading(c("transfers")),
        Block::Grid {
            header: vec![
                c("date_time"),
                c("delivered_by"),
                c("received_by"),
                c("purpose"),
                c("condition"),
            ],
            widths: vec![80.0, 120.0, 120.0, 80.0, 95.0],
            rows: BLANK_TRANSFER_ROWS,
            row_h: 30.0,
        },
        Block::Heading(c("observations")),
        Block::Grid {
            header: vec![String::new()],
            widths: vec![495.0],
            rows: 2,
            row_h: 30.0,
        },
        Block::SignLines(vec![
            format!(
                "{}: {} \u{2014} {}",
                c("examiner"),
                s(ctx, "run.actor"),
                c("signature_line")
            ),
            format!("{} \u{2014} {}", c("received_by"), c("signature_line")),
        ]),
    ];
    if let Some(Block::Kv(rows)) = b.get_mut(3) {
        if s(ctx, "run.case_id").is_empty() {
            rows[0].1 = String::new();
        }
        if !c("intake_utc").is_empty() {
            rows.insert(2, (c("intake_date"), c("intake_utc")));
        }
    }
    finish(ctx, &c("title"), &b, run)
}

// ---------- Writing ----------

/// Writes bytes and returns (file name, digests) for the audit log.
pub fn write_hashed(
    dir: &Path,
    name: &str,
    data: &[u8],
    algos: &[HashAlgo],
) -> Result<(String, Value), String> {
    let p = dir.join(name);
    std::fs::write(&p, data).map_err(|e| format!("cannot write {}: {}", p.display(), e))?;
    let digests: serde_json::Map<String, Value> = algos
        .iter()
        .map(|a| (a.name().to_string(), json!(hash_bytes(data, *a))))
        .collect();
    Ok((name.to_string(), Value::Object(digests)))
}

pub fn pretty(v: &Value) -> Vec<u8> {
    let mut s = serde_json::to_string_pretty(v).expect("serializable");
    s.push('\n');
    s.into_bytes()
}

/// Writes the six (or more, with several languages) report files of one item. Returns {file: digests}.
pub fn write_item_reports(
    dir: &Path,
    run: &RunInfo,
    it: &Item,
    audit: &AuditRef,
) -> Result<serde_json::Map<String, Value>, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {}", dir.display(), e))?;
    let algos = &run.algorithms;
    let mut files = serde_json::Map::new();
    let mut put = |r: Result<(String, Value), String>| -> Result<(), String> {
        let (n, d) = r?;
        files.insert(n, d);
        Ok(())
    };
    put(write_hashed(
        dir,
        "technical.json",
        &pretty(&technical_json(run, it)),
        algos,
    ))?;
    put(write_hashed(
        dir,
        "summary.json",
        &pretty(&summary_json(run, it)),
        algos,
    ))?;
    for lang in &run.langs {
        let ctx = item_context(lang, run, it, audit);
        put(write_hashed(
            dir,
            &format!("technical.{}.html", lang),
            render_html("technical.html", &ctx)?.as_bytes(),
            algos,
        ))?;
        put(write_hashed(
            dir,
            &format!("summary.{}.html", lang),
            render_html("summary.html", &ctx)?.as_bytes(),
            algos,
        ))?;
        put(write_hashed(
            dir,
            &format!("technical.{}.pdf", lang),
            &technical_pdf(&ctx, run)?,
            algos,
        ))?;
        put(write_hashed(
            dir,
            &format!("summary.{}.pdf", lang),
            &summary_pdf(&ctx, run)?,
            algos,
        ))?;
    }
    put(write_hashed(
        dir,
        "custody.json",
        &pretty(&custody_json(run, it)),
        algos,
    ))?;
    for lang in custody_langs(&run.jurisdiction) {
        let ctx = custody_context(&lang, run, it, audit);
        put(write_hashed(
            dir,
            &format!("custody.{}.html", lang),
            render_html("custody.html", &ctx)?.as_bytes(),
            algos,
        ))?;
        put(write_hashed(
            dir,
            &format!("custody.{}.pdf", lang),
            &custody_pdf(&ctx, run)?,
            algos,
        ))?;
    }
    Ok(files)
}

pub fn write_statistics(
    dir: &Path,
    run: &RunInfo,
    items: &[Item],
    totals: &RunTotals,
    audit: &AuditRef,
) -> Result<serde_json::Map<String, Value>, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {}", dir.display(), e))?;
    let algos = &run.algorithms;
    let mut files = serde_json::Map::new();
    let (n, d) = write_hashed(
        dir,
        "statistics.json",
        &pretty(&statistics_json(run, items, totals, audit)),
        algos,
    )?;
    files.insert(n, d);
    for lang in &run.langs {
        let ctx = statistics_context(lang, run, items, totals, audit);
        let (n, d) = write_hashed(
            dir,
            &format!("statistics.{}.html", lang),
            render_html("statistics.html", &ctx)?.as_bytes(),
            algos,
        )?;
        files.insert(n, d);
        let (n, d) = write_hashed(
            dir,
            &format!("statistics.{}.pdf", lang),
            &statistics_pdf(&ctx, run)?,
            algos,
        )?;
        files.insert(n, d);
    }
    Ok(files)
}
