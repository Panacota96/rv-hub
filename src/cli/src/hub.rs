//! `rv-hub tools`, `rv-hub case`, `rv-hub launch` and `rv-hub describe`: thin renderers over the frozen core
//! (`tools::discover`, `signature`, `case_view::read_case`, `suggest::suggest`, `launch::launch_with`, `session`).
//! Wording comes from the `cli` section of `i18n/{en,es,fr}.json`; JSON output is language-neutral apart from
//! the `reason` text of each suggestion (the `reason_key` is stable).

use rv_hub_core::case_view::{CaseView, RunStatus, TimestampStatus};
use rv_hub_core::launch::{LaunchError, Spawner, launch_with};
use rv_hub_core::session::Session;
use rv_hub_core::signature::{SignatureStatus, SignatureVerifier, rakvor_root_sha256};
use rv_hub_core::suggest::{Action, Suggestion};
use rv_hub_core::tools::{DescribeSource, Source, ToolInfo};
use rv_hub_core::{TOOL_NAME, TOOL_VERSION, i18n, tools};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const EXIT_OK: u8 = 0;
pub const EXIT_ERROR: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_FINDINGS: u8 = 3;

/// `rv-hub tools --json` (schemas/hub-tools.schema.json).
pub const SCHEMA_HUB_TOOLS: &str = "rakvor.hub-tools/1";
/// `rv-hub case --json` (schemas/hub-case.schema.json).
pub const SCHEMA_HUB_CASE: &str = "rakvor.hub-case/1";

/// Where a command prints: standard output and standard error (buffers in tests).
pub struct Out<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

impl Out<'_> {
    fn line(&mut self, s: &str) {
        let _ = writeln!(self.out, "{s}");
    }
    fn eline(&mut self, s: &str) {
        let _ = writeln!(self.err, "{s}");
    }
}

/// CLI wording (`cli` section) in `lang`, with `%{name}` placeholders filled.
pub fn tr(lang: &str, key: &str, params: &[(&str, String)]) -> String {
    let p: BTreeMap<String, String> = params
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect();
    i18n::fill(&i18n::catalog(lang).text("cli", key), &p)
}

fn t(lang: &str, key: &str) -> String {
    tr(lang, key, &[])
}

/// True when the signature can be checked on this system (Authenticode: Windows only).
pub fn signature_check_available() -> bool {
    cfg!(windows)
}

/// A signature that makes `tools` exit 3: signed under another root, or a signature that does not verify.
pub fn is_bad_signature(s: &SignatureStatus) -> bool {
    matches!(
        s,
        SignatureStatus::SignedOtherRoot { .. } | SignatureStatus::Invalid { .. }
    )
}

fn source_key(s: &Source) -> &'static str {
    match s {
        Source::Registry { .. } => "registry",
        Source::LocalPrograms => "local_programs",
        Source::Path => "path",
        Source::UserFolder => "user_folder",
    }
}

fn sig_label(lang: &str, s: &SignatureStatus) -> String {
    t(lang, &format!("sig_{}", s.key()))
}

/// The executables of a tool that exist, with their signature: ("cli"|"gui", path, status).
fn exes(t: &ToolInfo) -> Vec<(&'static str, &PathBuf, &SignatureStatus)> {
    let mut v = Vec::new();
    if let Some(p) = &t.cli_exe {
        v.push(("cli", p, &t.cli_signature));
    }
    if let Some(p) = &t.gui_exe {
        v.push(("gui", p, &t.gui_signature));
    }
    v
}

/// One signature label for a tool: the common status, or "cli: …, gui: …" when they differ.
fn tool_sig_label(lang: &str, tool: &ToolInfo) -> String {
    let e = exes(tool);
    match e.as_slice() {
        [] => t(lang, "sig_not_checked"),
        [(_, _, s)] => sig_label(lang, s),
        [(_, _, a), (_, _, b)] if a.key() == b.key() => sig_label(lang, a),
        _ => e
            .iter()
            .map(|(k, _, s)| format!("{k}: {}", sig_label(lang, s)))
            .collect::<Vec<_>>()
            .join(", "),
    }
}

fn table(rows: &[Vec<String>]) -> Vec<String> {
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..cols)
        .map(|c| {
            rows.iter()
                .filter_map(|r| r.get(c))
                .map(|s| s.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    rows.iter()
        .map(|r| {
            let mut line = String::new();
            for (i, cell) in r.iter().enumerate() {
                if i + 1 == r.len() {
                    line.push_str(cell);
                } else {
                    let pad = widths[i].saturating_sub(cell.chars().count());
                    line.push_str(cell);
                    line.push_str(&" ".repeat(pad + 2));
                }
            }
            line.trim_end().to_string()
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------------------------
// tools

pub struct ToolsArgs {
    pub json: bool,
    pub check_signatures: bool,
    pub lang: String,
}

fn signature_json(s: &SignatureStatus) -> Value {
    serde_json::to_value(s).unwrap_or(Value::Null)
}

fn exe_json(
    tool: &ToolInfo,
    exe: &Option<PathBuf>,
    sha: &Option<String>,
    s: &SignatureStatus,
) -> Value {
    match exe {
        None => Value::Null,
        Some(p) => json!({
            "path": p.display().to_string(),
            "sha256": sha,
            "signature": signature_json(s),
            "finding": s.finding(&tool.tool, p),
        }),
    }
}

/// The `rakvor.hub-tools/1` document.
pub fn tools_json(found: &[ToolInfo], session: Option<&Session>, exit_code: u8) -> Value {
    let mut counts: BTreeMap<&str, u64> = [
        "signed_rakvor",
        "signed_other_root",
        "invalid",
        "unsigned",
        "not_checked",
    ]
    .iter()
    .map(|k| (*k, 0))
    .collect();
    let mut list = Vec::new();
    for t in found {
        for (_, _, s) in exes(t) {
            *counts.entry(s.key()).or_default() += 1;
        }
        list.push(json!({
            "tool": t.tool,
            "title": t.title,
            "version": t.version,
            "role": t.describe.role,
            "main_verb": t.describe.main_verb,
            "dir": t.dir.display().to_string(),
            "sources": t.sources.iter().map(source_key).collect::<Vec<_>>(),
            "describe_source": t.describe_source,
            "describe_problem": t.describe_problem.as_ref().map(|p| p.to_string()),
            "cli": exe_json(t, &t.cli_exe, &t.cli_sha256, &t.cli_signature),
            "gui": exe_json(t, &t.gui_exe, &t.gui_sha256, &t.gui_signature),
            "findings": t.findings(),
            "warnings": t.warnings,
        }));
    }
    let not_installed: Vec<&str> = tools::KNOWN_TOOLS
        .iter()
        .copied()
        .filter(|k| !found.iter().any(|t| t.tool == *k))
        .collect();
    json!({
        "schema": SCHEMA_HUB_TOOLS,
        "hub": {"tool": TOOL_NAME, "version": TOOL_VERSION},
        "generated_utc": rv_hub_core::time::utc_now(),
        "signature_check": if signature_check_available() { "authenticode_rakvor_root" } else { "not_available" },
        "rakvor_root_sha256": rakvor_root_sha256(),
        "tools": list,
        "not_installed": not_installed,
        "signature_counts": counts,
        "session_log": session.map(|s| s.audit_path().display().to_string()),
        "exit_code": exit_code,
    })
}

/// `rv-hub tools`: the inventory table (or JSON), warnings for unsigned executables, exit 3 for a bad signature.
/// The call is recorded in the hub session log (`tools_listed`).
pub fn tools_cmd(
    a: &ToolsArgs,
    found: &[ToolInfo],
    user_folders: &[PathBuf],
    session: &mut Session,
    w: &mut Out,
) -> u8 {
    let lang = a.lang.as_str();
    let bad = found
        .iter()
        .any(|t| exes(t).iter().any(|(_, _, s)| is_bad_signature(s)));
    let code = if bad { EXIT_FINDINGS } else { EXIT_OK };

    let record = json!({
        "user_folders": user_folders.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "tools": found.iter().map(|t| json!({
            "tool": t.tool, "version": t.version, "dir": t.dir.display().to_string(),
            "cli_sha256": t.cli_sha256, "gui_sha256": t.gui_sha256,
            "cli_signature": t.cli_signature, "gui_signature": t.gui_signature,
            "describe_source": t.describe_source,
        })).collect::<Vec<_>>(),
        "exit_code": code,
    });
    if let Err(e) = session.record("tools_listed", record) {
        w.eline(&format!("error: {e}"));
        return EXIT_ERROR;
    }

    if a.json {
        let doc = tools_json(found, Some(session), code);
        w.line(&serde_json::to_string_pretty(&doc).unwrap_or_default());
    } else {
        let mut rows = vec![
            [
                "col_tool",
                "col_version",
                "col_source",
                "col_signature",
                "col_path",
            ]
            .iter()
            .map(|k| t(lang, k))
            .collect::<Vec<_>>(),
        ];
        for tool in found {
            let mut src: Vec<String> = tool
                .sources
                .iter()
                .map(|s| t(lang, &format!("src_{}", source_key(s))))
                .collect();
            if tool.describe_source == DescribeSource::Builtin {
                src.push(t(lang, "src_builtin"));
            }
            rows.push(vec![
                tool.tool.clone(),
                tool.version.clone().unwrap_or_else(|| t(lang, "unknown")),
                src.join("+"),
                tool_sig_label(lang, tool),
                tool.dir.display().to_string(),
            ]);
        }
        for k in tools::KNOWN_TOOLS {
            if !found.iter().any(|x| x.tool == k) {
                rows.push(vec![
                    k.to_string(),
                    t(lang, "none"),
                    t(lang, "src_builtin"),
                    t(lang, "sig_not_installed"),
                    t(lang, "none"),
                ]);
            }
        }
        for l in table(&rows) {
            w.line(&l);
        }
        w.line("");
        let check = if signature_check_available() {
            t(lang, "check_windows")
        } else {
            t(lang, "check_unavailable")
        };
        if found.is_empty() {
            w.line(&t(lang, "tools_none"));
        } else {
            w.line(&tr(
                lang,
                "tools_found",
                &[("n", found.len().to_string()), ("check", check)],
            ));
        }
        if a.check_signatures {
            w.line(&tr(lang, "sig_title", &[("root", rakvor_root_sha256())]));
            for tool in found {
                for (kind, p, s) in exes(tool) {
                    let detail = match s {
                        SignatureStatus::SignedOtherRoot { root_sha256 } => {
                            format!(" root {root_sha256}")
                        }
                        SignatureStatus::Invalid { reason }
                        | SignatureStatus::NotChecked { reason } => format!(" ({reason})"),
                        _ => String::new(),
                    };
                    let code = s
                        .finding(&tool.tool, p)
                        .map(|f| format!(" [{} {}]", f.code, f.severity.key()))
                        .unwrap_or_default();
                    w.line(&format!(
                        "  {} {kind}: {}{code}{detail}  {}",
                        tool.tool,
                        sig_label(lang, s),
                        p.display()
                    ));
                }
            }
        }
        w.line(&tr(
            lang,
            "session_log",
            &[("path", session.audit_path().display().to_string())],
        ));
    }
    for tool in found {
        for (_, p, s) in exes(tool) {
            let exe = p.display().to_string();
            match s {
                SignatureStatus::Unsigned => w.eline(&tr(
                    lang,
                    "warn_unsigned",
                    &[("tool", tool.tool.clone()), ("exe", exe)],
                )),
                s if is_bad_signature(s) => w.eline(&tr(
                    lang,
                    "err_bad_signature",
                    &[
                        ("tool", tool.tool.clone()),
                        ("status", sig_label(lang, s)),
                        ("exe", exe),
                    ],
                )),
                _ => {}
            }
        }
        for warning in &tool.warnings {
            w.eline(&tr(
                lang,
                "warn_tool",
                &[("tool", tool.tool.clone()), ("warning", warning.clone())],
            ));
        }
        if let (DescribeSource::Builtin, Some(p)) = (tool.describe_source, &tool.describe_problem) {
            if !a.json {
                w.eline(&tr(
                    lang,
                    "describe_builtin",
                    &[("tool", tool.tool.clone()), ("problem", p.to_string())],
                ));
            }
        }
    }
    code
}

// ---------------------------------------------------------------------------------------------------------------
// case

pub struct CaseArgs {
    pub case_dir: PathBuf,
    pub json: bool,
    pub lang: String,
}

fn run_status_key(s: RunStatus) -> &'static str {
    match s {
        RunStatus::Completed => "st_completed",
        RunStatus::Cancelled => "st_cancelled",
        RunStatus::Failed => "st_failed",
        RunStatus::Running => "st_running",
        RunStatus::NotInCaseLog => "st_not_in_case_log",
    }
}

fn ts_key(s: TimestampStatus) -> &'static str {
    match s {
        TimestampStatus::Obtained => "ts_obtained",
        TimestampStatus::Pending => "ts_pending",
        TimestampStatus::Off => "ts_off",
        TimestampStatus::Unknown => "ts_unknown",
    }
}

fn reason(lang: &str, s: &Suggestion) -> String {
    i18n::catalog(lang).text("suggest", &s.reason_key)
}

/// The `rakvor.hub-case/1` document.
pub fn case_json(v: &CaseView, suggestions: &[Suggestion], lang: &str) -> Value {
    json!({
        "schema": SCHEMA_HUB_CASE,
        "hub": {"tool": TOOL_NAME, "version": TOOL_VERSION},
        "generated_utc": rv_hub_core::time::utc_now(),
        "lang": lang,
        "case_dir": v.dir.display().to_string(),
        "case_id": v.case_id,
        "jurisdiction": v.jurisdiction,
        "created_utc": v.created_utc,
        "case_log_intact": v.case_log_intact,
        "evidence_count": v.evidence.len(),
        "evidence": v.evidence.iter().map(|e| json!({
            "evidence_id": e.evidence_id, "file_name": e.file_name, "path": e.path, "size": e.size,
            "hashes": e.hashes, "registered_utc": e.registered_utc, "registered_by_tool": e.registered_by_tool,
            "examined_by": e.examined_by, "superseded_by": e.superseded_by,
        })).collect::<Vec<_>>(),
        "runs": v.runs.iter().map(|r| json!({
            "tool": r.tool, "run_id": r.run_id, "run_dir": r.run_dir, "version": r.version,
            "status": r.status, "started_utc": r.started_utc, "finished_utc": r.finished_utc,
            "folder_present": r.folder_present, "evidence_ids": r.evidence_ids, "items": r.items,
            "severity": r.severity, "timestamp": r.timestamp,
        })).collect::<Vec<_>>(),
        "severity": v.severity,
        "timestamps": v.timestamps,
        "problems": v.problems,
        "suggestions": suggestions.iter().map(|s| json!({
            "tool": s.tool, "action": s.action, "reason_key": s.reason_key, "reason": reason(lang, s),
            "evidence_ids": s.evidence_ids, "run_dirs": s.run_dirs,
        })).collect::<Vec<_>>(),
    })
}

/// `rv-hub case`: the read-only dashboard summary. Reads the case through `case_view::read_case` and the
/// suggestions through `suggest::suggest`; never writes anything (not even the session log).
pub fn case_cmd(a: &CaseArgs, catalog: &[tools::Describe], w: &mut Out) -> u8 {
    let lang = a.lang.as_str();
    if !a.case_dir.is_dir() {
        w.eline(&tr(
            lang,
            "not_a_dir",
            &[("path", a.case_dir.display().to_string())],
        ));
        return EXIT_USAGE;
    }
    let view = rv_hub_core::case_view::read_case(&a.case_dir);
    let suggestions = rv_hub_core::suggest::suggest(&view, catalog);
    let code = if view.case_id.is_some() {
        EXIT_OK
    } else {
        EXIT_ERROR
    };
    if a.json {
        w.line(
            &serde_json::to_string_pretty(&case_json(&view, &suggestions, lang))
                .unwrap_or_default(),
        );
        return code;
    }
    let none = t(lang, "none");
    match &view.case_id {
        Some(id) => w.line(&tr(
            lang,
            "case_header",
            &[
                ("case_id", id.clone()),
                (
                    "jurisdiction",
                    match view.jurisdiction.as_deref() {
                        Some("co") => t(lang, "jur_co"),
                        Some("fr") => t(lang, "jur_fr"),
                        Some(o) => o.to_string(),
                        None => none.clone(),
                    },
                ),
                ("created", view.created_utc.clone().unwrap_or(none.clone())),
            ],
        )),
        None => w.line(&t(lang, "case_none")),
    }
    w.line(&format!("  {}", a.case_dir.display()));
    w.line(&tr(
        lang,
        "evidence_count",
        &[("n", view.evidence.len().to_string())],
    ));
    w.line(&t(
        lang,
        match view.case_log_intact {
            Some(true) => "case_log_intact",
            Some(false) => "case_log_broken",
            None => "case_log_none",
        },
    ));
    let sv = &view.severity;
    w.line(&tr(
        lang,
        "totals",
        &[
            ("high", sv.high.to_string()),
            ("medium", sv.medium.to_string()),
            ("low", sv.low.to_string()),
            ("info", sv.info.to_string()),
        ],
    ));
    w.line("");
    if view.runs.is_empty() {
        w.line(&t(lang, "runs_none"));
    } else {
        w.line(&t(lang, "runs_title"));
        let mut rows = vec![
            [
                "col_tool",
                "col_run_id",
                "col_time",
                "col_status",
                "col_findings",
                "col_timestamp",
            ]
            .iter()
            .map(|k| t(lang, k))
            .collect::<Vec<_>>(),
        ];
        for r in &view.runs {
            rows.push(vec![
                r.tool.clone(),
                r.run_id.clone(),
                r.started_utc.clone().unwrap_or(none.clone()),
                t(lang, run_status_key(r.status)),
                r.severity
                    .map(|s| format!("{}/{}/{}/{}", s.high, s.medium, s.low, s.info))
                    .unwrap_or(none.clone()),
                t(lang, ts_key(r.timestamp)),
            ]);
        }
        for l in table(&rows) {
            w.line(&format!("  {l}"));
        }
    }
    w.line("");
    if view.problems.is_empty() {
        w.line(&t(lang, "problems_none"));
    } else {
        w.line(&t(lang, "problems_title"));
        for p in &view.problems {
            w.line(&format!("  - {p}"));
        }
    }
    w.line("");
    w.line(&format!(
        "{}:",
        i18n::catalog(lang).text("suggest", "title")
    ));
    if suggestions.is_empty() {
        w.line(&format!("  {}", t(lang, "suggest_none")));
    }
    for s in &suggestions {
        let what = match s.action {
            Action::Launch => format!("rv-hub launch {}", s.tool),
            Action::Timestamp => format!("{} timestamp", s.tool),
        };
        let mut extra = Vec::new();
        if !s.evidence_ids.is_empty() {
            extra.push(tr(
                lang,
                "suggest_items",
                &[("ids", s.evidence_ids.join(", "))],
            ));
        }
        if !s.run_dirs.is_empty() {
            extra.push(tr(lang, "suggest_runs", &[("runs", s.run_dirs.join(", "))]));
        }
        let extra = if extra.is_empty() {
            String::new()
        } else {
            format!(" ({})", extra.join("; "))
        };
        w.line(&format!("  - {what}: {}{extra}", reason(lang, s)));
    }
    code
}

// ---------------------------------------------------------------------------------------------------------------
// launch

pub struct LaunchArgs {
    pub tool: String,
    pub case_dir: PathBuf,
    pub yes_untrusted: bool,
    pub lang: String,
}

/// The installation `launch` uses when a tool is found more than once: a Rakvor-signed GUI first, then by
/// source (registry, install folder, PATH, added folder), then by folder.
pub fn pick<'a>(found: &'a [ToolInfo], tool: &str) -> Option<&'a ToolInfo> {
    let mut c: Vec<&ToolInfo> = found
        .iter()
        .filter(|t| t.tool == tool && t.gui_exe.is_some())
        .collect();
    c.sort_by(|a, b| {
        (!a.gui_signature.is_rakvor(), a.sources.iter().min(), &a.dir).cmp(&(
            !b.gui_signature.is_rakvor(),
            b.sources.iter().min(),
            &b.dir,
        ))
    });
    c.first().copied()
}

/// `rv-hub launch`: starts the tool's GUI on the case through `launch::launch_with` and prints the pid.
/// A tool that is not Rakvor-signed is refused (exit 3) unless `yes_untrusted`; the refusal and the
/// confirmation are both recorded in the session log.
pub fn launch_cmd(
    a: &LaunchArgs,
    found: &[ToolInfo],
    session: &mut Session,
    verifier: &dyn SignatureVerifier,
    spawner: &dyn Spawner,
    w: &mut Out,
) -> u8 {
    let lang = a.lang.as_str();
    let known =
        tools::KNOWN_TOOLS.contains(&a.tool.as_str()) || found.iter().any(|t| t.tool == a.tool);
    if !known {
        w.eline(&tr(
            lang,
            "launch_unknown_tool",
            &[
                ("tool", a.tool.clone()),
                ("known", tools::KNOWN_TOOLS.join(", ")),
            ],
        ));
        return EXIT_USAGE;
    }
    let Some(tool) = pick(found, &a.tool) else {
        w.eline(&tr(lang, "launch_not_found", &[("tool", a.tool.clone())]));
        return EXIT_ERROR;
    };
    match launch_with(
        session,
        tool,
        &a.case_dir,
        a.yes_untrusted,
        verifier,
        spawner,
    ) {
        Ok(l) => {
            if !l.signature.is_rakvor() {
                w.eline(&tr(
                    lang,
                    "launch_untrusted",
                    &[
                        ("tool", l.tool.clone()),
                        ("status", sig_label(lang, &l.signature)),
                    ],
                ));
            }
            w.line(&tr(
                lang,
                "launch_ok",
                &[
                    ("tool", l.tool.clone()),
                    (
                        "version",
                        l.version.clone().unwrap_or_else(|| t(lang, "unknown")),
                    ),
                    ("pid", l.pid.to_string()),
                    ("case", l.case_dir.display().to_string()),
                ],
            ));
            w.line(&tr(
                lang,
                "launch_exe",
                &[
                    ("exe", l.exe.display().to_string()),
                    ("sha256", l.exe_sha256.clone()),
                    ("status", sig_label(lang, &l.signature)),
                ],
            ));
            w.line(&format!("pid {}", l.pid));
            w.line(&tr(
                lang,
                "session_log",
                &[("path", session.audit_path().display().to_string())],
            ));
            EXIT_OK
        }
        Err(e) => {
            let code = match &e {
                LaunchError::NeedsConfirmation(_) | LaunchError::Changed { .. } => EXIT_FINDINGS,
                LaunchError::NotACase(_) => EXIT_USAGE,
                LaunchError::MissingExe(_) | LaunchError::Spawn(_) | LaunchError::Audit(_) => {
                    EXIT_ERROR
                }
            };
            if code == EXIT_FINDINGS {
                // The core records confirmations and launches; a refusal is recorded here.
                let _ = session.record(
                    "tool_launch_refused",
                    json!({"tool": tool.tool, "version": tool.version,
                           "exe": tool.gui_exe.as_ref().map(|p| p.display().to_string()),
                           "case_dir": a.case_dir.display().to_string(), "reason": e.to_string()}),
                );
            }
            let key = match &e {
                LaunchError::NeedsConfirmation(_) => "launch_refused",
                LaunchError::Changed { .. } => "launch_changed",
                _ => "launch_error",
            };
            w.eline(&tr(lang, key, &[("reason", e.to_string())]));
            code
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// describe

/// The hub's self-description, in the same `rakvor.describe/1` schema as the tools
/// (schemas/describe.schema.json). The schema's role enum has no `hub`: the hub is recorded in the case log as
/// an analysis tool (`CASE_ROLE`), so its role is `analysis`. serde_json sorts the keys.
pub fn describe() -> Value {
    json!({
        "schema": tools::SCHEMA_DESCRIBE,
        "tool": TOOL_NAME,
        "title": "RV Hub",
        "version": TOOL_VERSION,
        "role": "analysis",
        "main_verb": "verify",
        // The hub's input is a case folder; the files it reads directly are the case's JSON documents and
        // JSON Lines logs (case.json, registry.json, case-log.jsonl, audit.jsonl, review.jsonl).
        "accepts": {"extensions": ["json", "jsonl"], "signatures": []},
        "case_formats": [rv_hub_core::case::SCHEMA_CASE],
        "log_formats": [tools::LOG_AUDIT],
        "cli_exe": format!("{TOOL_NAME}.exe"),
        "gui_exe": format!("{TOOL_NAME}-gui.exe"),
        "exit_codes": {
            "0": "Completed; no high-severity finding (the case verifies).",
            "1": "Runtime error (case log locked, output not writable, session log not writable, tool not installed, ...).",
            "2": "Usage error (unknown option, bad value, not a case folder, case of another case, unknown tool).",
            "3": "Completed with at least one high-severity finding, a tool with a bad signature, or a launch refused for an untrusted tool.",
            "130": "Cancelled with Ctrl+C; partial reports and the cancellation are in the audit log."
        }
    })
}

/// Hashes of every file under `dir` (relative path → SHA-256): used by tests and by `case` callers to prove
/// that nothing was written.
pub fn tree_sha256(dir: &Path) -> BTreeMap<String, String> {
    fn walk(base: &Path, d: &Path, out: &mut BTreeMap<String, String>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(base, &p, out);
            } else if let Some(h) = tools::sha256_of(&p) {
                let rel = p
                    .strip_prefix(base)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel, h);
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}
