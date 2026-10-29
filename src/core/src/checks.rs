//! The checks of `rv-hub verify` — the hub's domain logic. Every check reuses the verifier code the tools
//! themselves are built on (one lineage): `audit::verify` (hash chain), `case::verify_log_and_registry`
//! (case log, case.json, registry digest), `trust::verify_timestamps` (RFC 3161 tokens), `review::verify`
//! (rv-imgauth's review log: anchored to `run_finished`, chain intact) and `verify::verify_log` (the exact rules
//! of `<tool> verify-log`, whose verdict is compared with the tool's own in the cross-check).
//!
//! Each check fills one [`Item`]: findings (codes in `findings.rs`), facts for the technical report, and for a
//! run the verify-log [`Verdict`]. Nothing is written.

use crate::audit;
use crate::case::{self, CASE_LOG, RegistryItem};
use crate::findings::{self as f, Finding};
use crate::report::{Item, Verdict};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// A run of the case: announced in the case log, present on disk, or both.
#[derive(Clone, Debug, PartialEq)]
pub struct RunRef {
    pub tool: String,
    pub run_id: String,
    /// "runs/<tool>/<RUN-ID>"
    pub rel: String,
    /// The case-log `run_started` entry (None: not announced).
    pub started: Option<Value>,
    /// The case-log `run_finished` entry.
    pub finished: Option<Value>,
}

impl RunRef {
    pub fn log_dir(&self, case_dir: &Path) -> PathBuf {
        case_dir.join(&self.rel).join("logs")
    }
}

/// Every run of the case, in case-log order, then the run folders the case log does not announce.
/// `entries`: the case log as read at the start of the verification.
pub fn runs_of_case(dir: &Path, entries: &[Value]) -> Vec<RunRef> {
    let mut runs: Vec<RunRef> = Vec::new();
    for e in entries {
        let rid = e["run_id"].as_str().unwrap_or_default();
        match e["action"].as_str() {
            Some("run_started") => {
                let rel = e["details"]["run_dir"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let tool = e["details"]["tool"]
                    .as_str()
                    .map(String::from)
                    .or_else(|| rel.split('/').nth(1).map(String::from))
                    .unwrap_or_else(|| "?".into());
                runs.push(RunRef {
                    tool,
                    run_id: rid.to_string(),
                    rel,
                    started: Some(e.clone()),
                    finished: None,
                });
            }
            Some("run_finished") => {
                if let Some(r) = runs.iter_mut().rev().find(|r| r.run_id == rid) {
                    r.finished = Some(e.clone());
                }
            }
            _ => {}
        }
    }
    for (tool, run_id, rel) in crate::case_view::run_folders(dir) {
        if !runs.iter().any(|r| r.rel == rel) {
            runs.push(RunRef {
                tool,
                run_id,
                rel,
                started: None,
                finished: None,
            });
        }
    }
    runs
}

pub(crate) fn read_entries(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Case log, case.json and registry digest. Returns true when intact (the case may then be extended).
pub fn check_case_log(dir: &Path, entries: &[Value], item: &mut Item) -> bool {
    item.fact("fact_case_log_entries", entries.len().to_string());
    // The digests are of the case log as found; the file is append-only, so they cover its first `size` bytes.
    item.fact(
        "fact_as_found",
        format!("first {} bytes of {}", item.size, CASE_LOG),
    );
    let mut problems = match case::verify_log_and_registry(dir) {
        Ok(state) => {
            item.fact(
                "fact_registry_sha256",
                state.registry_sha256.unwrap_or_else(|| "-".into()),
            );
            vec![]
        }
        Err(p) => p,
    };
    // A run_finished without its run_started (verify-case's rule).
    let mut started = std::collections::BTreeSet::new();
    for e in entries {
        let rid = e["run_id"].as_str().unwrap_or_default();
        match e["action"].as_str() {
            Some("run_started") => {
                started.insert(rid.to_string());
            }
            Some("run_finished") if !started.contains(rid) => problems.push(format!(
                "{CASE_LOG}: run_finished for {rid} without run_started"
            )),
            _ => {}
        }
    }
    let intact = problems.is_empty();
    for p in problems {
        item.findings
            .push(Finding::of(f::CASE_LOG_BROKEN).with("problem", p));
    }
    intact
}

fn verdict_text(v: Verdict) -> &'static str {
    match v {
        Verdict::Intact => "intact",
        Verdict::Broken => "broken",
        Verdict::NotVerifiable => "not verifiable",
    }
}

pub fn verdict_word(v: Verdict) -> &'static str {
    verdict_text(v)
}

/// One run folder: its audit chain, links with the case log, timestamps, review log and unknown logs; sets the
/// item's verify-log verdict. `case_id`: the case's id (for the case_linked check).
pub fn check_run(dir: &Path, case_id: &str, run: &RunRef, item: &mut Item) {
    let log_dir = run.log_dir(dir);
    let audit_path = log_dir.join("audit.jsonl");
    let label = run.rel.clone();
    let broken = |p: String| {
        Finding::of(f::RUN_LOG_BROKEN)
            .with("run", label.clone())
            .with("problem", p)
    };
    item.fact("fact_tool", run.tool.clone());
    if let Some(v) = run
        .started
        .as_ref()
        .and_then(|s| s["details"]["version"].as_str())
    {
        item.fact("fact_version", v);
    }
    item.fact("fact_run_id", run.run_id.clone());
    item.fact("fact_run_dir", run.rel.clone());
    let status = run
        .finished
        .as_ref()
        .and_then(|e| e["details"]["status"].as_str().map(String::from))
        .unwrap_or_else(|| {
            if run.started.is_some() {
                "running or interrupted (no run_finished)"
            } else {
                "-"
            }
            .into()
        });
    item.fact("fact_run_status", status);
    item.fact(
        "fact_case_link",
        if run.started.is_some() {
            "run_started"
        } else {
            "none"
        },
    );
    let recorded_entries = run
        .finished
        .as_ref()
        .and_then(|e| e["details"]["audit_entries"].as_u64())
        .unwrap_or(0);

    if run.started.is_none() {
        item.findings
            .push(Finding::of(f::RUN_NOT_IN_CASE_LOG).with("run", label.clone()));
    }
    if !audit_path.is_file() {
        // A run that failed before writing any entry records audit_entries 0 (verify-case accepts that).
        if run.started.is_none() || run.finished.is_none() || recorded_entries > 0 {
            item.findings.push(broken(format!(
                "{} is missing",
                if log_dir.is_dir() {
                    "logs/audit.jsonl"
                } else {
                    "the run folder"
                }
            )));
        }
        item.verdict = Some(Verdict::NotVerifiable);
        item.chain_verdict = Some(Verdict::NotVerifiable);
        return;
    }

    let entries = read_entries(&audit_path);
    match audit::verify(&audit_path) {
        Ok(n) => item.fact("fact_entries", n.to_string()),
        Err(p) => {
            for x in p {
                item.findings.push(broken(format!("audit.jsonl {x}")));
            }
        }
    }
    if let Some(started) = &run.started {
        match entries.iter().find(|e| e["action"] == "case_linked") {
            Some(l) => {
                if l["details"]["case_id"].as_str() != Some(case_id) {
                    item.findings
                        .push(broken("case_linked names another case".into()));
                }
                if l["details"]["case_log_head_at_start"].as_str() != started["entry_hash"].as_str()
                {
                    item.findings.push(broken(
                        "case_linked does not point to its run_started entry in the case log"
                            .into(),
                    ));
                }
            }
            None => item
                .findings
                .push(broken("audit.jsonl has no case_linked entry".into())),
        }
        if let Some(fin) = &run.finished {
            if recorded_entries > 0 {
                let at = entries
                    .iter()
                    .find(|e| e["seq"].as_u64() == Some(recorded_entries));
                if at.and_then(|e| e["entry_hash"].as_str())
                    != fin["details"]["audit_head"].as_str()
                {
                    item.findings.push(broken(format!(
                        "the audit head recorded in the case log is not entry #{recorded_entries} of the run's audit.jsonl"
                    )));
                }
                for later in entries
                    .iter()
                    .filter(|e| e["seq"].as_u64().unwrap_or(0) > recorded_entries)
                {
                    if later["action"] != "timestamp_obtained" {
                        item.findings.push(broken(format!(
                            "audit entry #{} ({}) was appended after run_finished",
                            later["seq"],
                            later["action"].as_str().unwrap_or("?")
                        )));
                    }
                }
            }
        }
    }
    for p in crate::trust::verify_timestamps(&log_dir, &audit::heads(&audit_path)) {
        item.findings.push(broken(p));
    }
    let mut ts = "off";
    for e in &entries {
        match e["action"].as_str() {
            Some("timestamp_obtained") => ts = "obtained",
            Some("timestamp_pending") if ts != "obtained" => ts = "pending",
            _ => {}
        }
    }
    item.fact("fact_timestamp", ts);
    if ts == "pending" {
        item.findings
            .push(Finding::of(f::TIMESTAMP_PENDING).with("run", label.clone()));
    }
    match crate::review::verify(&log_dir) {
        Ok(None) => {}
        Ok(Some(n)) => item.fact("fact_review_entries", n.to_string()),
        Err(p) => item.findings.push(
            Finding::of(f::REVIEW_LOG_BROKEN)
                .with("run", label.clone())
                .with("problem", p.join("; ")),
        ),
    }
    let mut unknown: Vec<String> = std::fs::read_dir(&log_dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| {
                    n.ends_with(".jsonl") && n != "audit.jsonl" && n != crate::review::REVIEW_FILE
                })
                .collect()
        })
        .unwrap_or_default();
    unknown.sort();
    for u in unknown {
        item.findings.push(
            Finding::of(f::UNKNOWN_LOG_FORMAT)
                .with("run", label.clone())
                .with("file", format!("logs/{u}")),
        );
    }

    // The verify-log verdict: the same function `<tool> verify-log` runs (chain, timestamps, truncation against
    // the case log, review log).
    let verdict = match crate::verify::verify_log(&audit_path) {
        Ok(v) => {
            if !v.truncation.is_empty() {
                item.fact("fact_truncation", v.truncation.clone());
            }
            for w in &v.warnings {
                item.fact("fact_warning", w.clone());
            }
            if v.problems.is_empty() {
                Verdict::Intact
            } else {
                for p in &v.problems {
                    item.fact("fact_problem", p.clone());
                }
                Verdict::Broken
            }
        }
        Err(e) => {
            item.fact("fact_problem", e);
            Verdict::Broken
        }
    };
    item.fact("fact_verify_log", verdict_text(verdict));
    item.verdict = Some(verdict);
    // Chain level: what every tool's verify-log checks (the truncation check against the case log came later).
    let chain_ok = audit::verify(&audit_path).is_ok()
        && crate::trust::verify_timestamps(&log_dir, &audit::heads(&audit_path)).is_empty()
        && crate::review::verify(&log_dir).is_ok();
    item.chain_verdict = Some(if chain_ok {
        Verdict::Intact
    } else {
        Verdict::Broken
    });
    if !item.has_high() {
        let n = audit::verify(&audit_path).unwrap_or(0);
        item.findings.push(
            Finding::of(f::RUN_LOG_INTACT)
                .with("run", label)
                .with("entries", n.to_string()),
        );
    }
}

/// Where a registered evidence file is now: its registered path, else `<dir>/<file name>` for each folder given.
pub fn locate(item: &RegistryItem, evidence_dirs: &[PathBuf]) -> Option<PathBuf> {
    let p = PathBuf::from(&item.path);
    if p.is_file() {
        return Some(p);
    }
    let name = item
        .path
        .rsplit(['/', '\\'])
        .next()
        .filter(|n| !n.is_empty())?;
    evidence_dirs
        .iter()
        .map(|d| d.join(name))
        .find(|c| c.is_file())
}

/// Compares fresh digests with the registry entry (EVIDENCE_REHASH_MISMATCH on a difference).
pub fn compare_evidence(
    reg: &RegistryItem,
    digests: &[(crate::HashAlgo, String)],
    item: &mut Item,
) -> bool {
    item.fact(
        "fact_algorithms",
        digests
            .iter()
            .map(|(a, _)| a.name())
            .collect::<Vec<_>>()
            .join("+"),
    );
    match case::compare(&reg.hashes, digests) {
        case::Comparison::Match(_) => true,
        case::Comparison::Mismatch {
            algorithm,
            expected,
            actual,
        } => {
            item.findings.push(
                Finding::of(f::EVIDENCE_REHASH_MISMATCH)
                    .with("evidence_id", reg.evidence_id.clone())
                    .with("path", item.path.display().to_string())
                    .with("algorithm", algorithm)
                    .with("expected", expected)
                    .with("actual", actual),
            );
            false
        }
        case::Comparison::NoCommonAlgorithm => {
            item.fact("fact_problem", "no algorithm in common with the registry");
            false
        }
    }
}

pub fn missing_evidence(reg: &RegistryItem, reason: &str, item: &mut Item) {
    item.findings.push(
        Finding::of(f::EVIDENCE_MISSING)
            .with("evidence_id", reg.evidence_id.clone())
            .with("path", reg.path.clone())
            .with("reason", reason),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::ItemKind;
    use serde_json::json;

    fn sample() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample/case")
    }

    #[test]
    fn sample_case_runs_are_intact() {
        let dir = sample();
        let entries = read_entries(&dir.join(CASE_LOG));
        let mut cl = Item::new(1, ItemKind::CaseLog, CASE_LOG, dir.join(CASE_LOG));
        assert!(check_case_log(&dir, &entries, &mut cl), "{:?}", cl.findings);
        let runs = runs_of_case(&dir, &entries);
        assert_eq!(runs.len(), 4);
        for r in &runs {
            let mut it = Item::new(
                2,
                ItemKind::Run,
                r.rel.clone(),
                r.log_dir(&dir).join("audit.jsonl"),
            );
            check_run(&dir, "SAMPLE-1", r, &mut it);
            let codes: Vec<&str> = it.findings.iter().map(|f| f.code.as_str()).collect();
            assert_eq!(codes, ["RUN_LOG_INTACT"], "{} {:?}", r.rel, it.facts);
            assert_eq!(it.verdict, Some(Verdict::Intact));
        }
    }

    #[test]
    fn review_log_unknown_log_and_pending_timestamp() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path();
        let w = case::Writer {
            tool: "rv-imgauth".into(),
            version: "1".into(),
            run_id: "R1".into(),
            actor: "t".into(),
        };
        case::Case::open_or_create(dir, Some("C-1"), "co", &w).unwrap();
        let c = case::Case::open(dir).unwrap();
        let (_, head) = c
            .append(
                &w,
                "run_started",
                json!({"tool": "rv-imgauth", "run_dir": "runs/rv-imgauth/R1"}),
            )
            .unwrap();
        let logs = dir.join("runs/rv-imgauth/R1/logs");
        let mut log = audit::AuditLog::create(&logs, "R1", "t").unwrap();
        log.record("run_started", None, json!({})).unwrap();
        log.record(
            "case_linked",
            None,
            json!({"case_id": "C-1", "case_log_head_at_start": head}),
        )
        .unwrap();
        log.record("timestamp_pending", None, json!({})).unwrap();
        log.record("run_finished", None, json!({})).unwrap();
        c.append(
            &w,
            "run_finished",
            json!({"status": "completed", "audit_entries": 4, "audit_head": log.head()}),
        )
        .unwrap();
        crate::review::append(&logs, "Ana", "ui_map_viewed", json!({"map": "ela.png"})).unwrap();
        std::fs::write(logs.join("notes.jsonl"), "{}\n").unwrap();

        let entries = read_entries(&dir.join(CASE_LOG));
        let run = &runs_of_case(dir, &entries)[0];
        let mut it = Item::new(2, ItemKind::Run, run.rel.clone(), logs.join("audit.jsonl"));
        check_run(dir, "C-1", run, &mut it);
        let codes: Vec<&str> = it.findings.iter().map(|f| f.code.as_str()).collect();
        assert_eq!(
            codes,
            ["TIMESTAMP_PENDING", "UNKNOWN_LOG_FORMAT", "RUN_LOG_INTACT"]
        );
        assert!(
            it.facts
                .iter()
                .any(|(k, v)| k == "fact_review_entries" && v == "1")
        );

        // Re-anchored review log: broken; verify-log verdict broken too.
        let rp = logs.join("review.jsonl");
        let mut first: serde_json::Map<String, Value> =
            serde_json::from_str(std::fs::read_to_string(&rp).unwrap().trim()).unwrap();
        first.insert("anchor_hash".into(), json!("00".repeat(32)));
        first.insert("prev_entry_hash".into(), json!("00".repeat(32)));
        let h = audit::entry_hash(&first);
        first.insert("entry_hash".into(), json!(h));
        std::fs::write(&rp, format!("{}\n", Value::Object(first))).unwrap();
        let mut it = Item::new(2, ItemKind::Run, run.rel.clone(), logs.join("audit.jsonl"));
        check_run(dir, "C-1", run, &mut it);
        assert!(it.findings.iter().any(|f| f.code == "REVIEW_LOG_BROKEN"));
        assert!(!it.findings.iter().any(|f| f.code == "RUN_LOG_INTACT"));
        assert_eq!(it.verdict, Some(Verdict::Broken));
    }
}
