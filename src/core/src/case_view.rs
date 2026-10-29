//! Read-only model of a case folder for the dashboard: evidence rows (with the tools that examined each item),
//! run rows (status, findings by severity, timestamp status), severity totals and the case jurisdiction.
//!
//! Reads `case.json`, `evidence/registry.json`, `case-log.jsonl` and `runs/<tool>/<RUN>/` (`logs/audit.jsonl`,
//! `reports/statistics.json`). Nothing is written. Missing, extra or malformed files never panic: each problem is
//! a line in [`CaseView::problems`] and the rest of the view is still built. This is a summary, not a
//! verification: `run::run` (`rv-hub verify`) checks the chains.

use crate::case::{CASE_FILE, CASE_LOG, REGISTRY_JSON};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SeverityTotals {
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub info: u64,
}

impl SeverityTotals {
    fn add(&mut self, o: &SeverityTotals) {
        self.high += o.high;
        self.medium += o.medium;
        self.low += o.low;
        self.info += o.info;
    }
    fn from_json(v: &Value) -> Option<SeverityTotals> {
        let o = v.as_object()?;
        let g = |k: &str| o.get(k).and_then(Value::as_u64).unwrap_or(0);
        Some(SeverityTotals {
            high: g("high"),
            medium: g("medium"),
            low: g("low"),
            info: g("info"),
        })
    }
}

/// A run's trusted-timestamp state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampStatus {
    /// A token was obtained (at the end of the run or later with `timestamp`).
    Obtained,
    /// The TSA could not be reached; `timestamp` can still add one.
    Pending,
    /// No timestamp requested.
    Off,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Completed,
    Cancelled,
    Failed,
    /// run_started without run_finished (still running, or interrupted).
    Running,
    /// A run folder the case log never announced.
    NotInCaseLog,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RunRow {
    pub tool: String,
    pub run_id: String,
    /// "runs/<tool>/<RUN-ID>"
    pub run_dir: String,
    pub version: Option<String>,
    pub role: Option<String>,
    pub actor: Option<String>,
    pub started_utc: Option<String>,
    pub finished_utc: Option<String>,
    pub status: RunStatus,
    pub folder_present: bool,
    /// Evidence ids the run examined (statistics.json, else run_started, else what it registered).
    pub evidence_ids: Vec<String>,
    pub items: Option<u64>,
    /// From reports/statistics.json; None when it is missing or unreadable.
    pub severity: Option<SeverityTotals>,
    pub timestamp: TimestampStatus,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct EvidenceRow {
    pub evidence_id: String,
    pub path: String,
    pub file_name: String,
    pub size: u64,
    pub hashes: BTreeMap<String, String>,
    pub registered_utc: String,
    pub registered_by_tool: String,
    pub registered_by_run: String,
    /// Tools whose runs examined this item (the intake tool included), sorted.
    pub examined_by: Vec<String>,
    /// A later registration of the same path (content changed between intakes).
    pub superseded_by: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct CaseView {
    pub dir: PathBuf,
    pub case_id: Option<String>,
    /// "co" | "fr"
    pub jurisdiction: Option<String>,
    pub created_utc: Option<String>,
    pub evidence: Vec<EvidenceRow>,
    /// In case-log order, then run folders the case log does not announce.
    pub runs: Vec<RunRow>,
    /// Sum of every run's findings by severity.
    pub severity: SeverityTotals,
    /// Runs per timestamp status.
    pub timestamps: BTreeMap<String, u64>,
    /// Quick chain check of case-log.jsonl (None when there is none).
    pub case_log_intact: Option<bool>,
    pub problems: Vec<String>,
}

fn read_json(p: &Path, problems: &mut Vec<String>) -> Option<Value> {
    if !p.is_file() {
        return None;
    }
    match std::fs::read_to_string(p)
        .map_err(|e| e.to_string())
        .and_then(|t| {
            serde_json::from_str::<Value>(&t).map_err(|e| format!("not valid JSON ({e})"))
        }) {
        Ok(v) => Some(v),
        Err(e) => {
            problems.push(format!("{}: {}", p.display(), e));
            None
        }
    }
}

/// JSON Lines, skipping (and reporting) lines that are not JSON objects.
pub(crate) fn read_jsonl(p: &Path, problems: &mut Vec<String>) -> Vec<Value> {
    let Ok(text) = std::fs::read_to_string(p) else {
        return vec![];
    };
    let mut out = Vec::new();
    for (i, l) in text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
    {
        match serde_json::from_str::<Value>(l) {
            Ok(v) if v.is_object() => out.push(v),
            _ => problems.push(format!(
                "{}: line {} is not a JSON object",
                p.display(),
                i + 1
            )),
        }
    }
    out
}

fn s(v: &Value) -> Option<String> {
    v.as_str().map(String::from)
}

fn ids(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Run folders on disk: (tool, run id, "runs/<tool>/<RUN>").
pub(crate) fn run_folders(dir: &Path) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for t in std::fs::read_dir(dir.join("runs"))
        .into_iter()
        .flatten()
        .flatten()
    {
        if !t.path().is_dir() {
            continue;
        }
        let tool = t.file_name().to_string_lossy().into_owned();
        for r in std::fs::read_dir(t.path()).into_iter().flatten().flatten() {
            if r.path().is_dir() {
                let run = r.file_name().to_string_lossy().into_owned();
                out.push((tool.clone(), run.clone(), format!("runs/{tool}/{run}")));
            }
        }
    }
    out.sort();
    out
}

fn timestamp_of(audit: &[Value], recorded: Option<&str>) -> TimestampStatus {
    let mut state = match recorded {
        Some("ok") => TimestampStatus::Obtained,
        Some("pending") => TimestampStatus::Pending,
        Some("off") => TimestampStatus::Off,
        _ => TimestampStatus::Unknown,
    };
    for e in audit {
        match e["action"].as_str() {
            Some("timestamp_obtained") => state = TimestampStatus::Obtained,
            Some("timestamp_pending") if state != TimestampStatus::Obtained => {
                state = TimestampStatus::Pending
            }
            _ => {}
        }
    }
    if state == TimestampStatus::Unknown && !audit.is_empty() {
        state = TimestampStatus::Off;
    }
    state
}

/// Builds the dashboard model of `dir` (never fails; see [`CaseView::problems`]).
pub fn read_case(dir: &Path) -> CaseView {
    let mut v = CaseView {
        dir: dir.to_path_buf(),
        ..Default::default()
    };
    let p = &mut v.problems;
    match read_json(&dir.join(CASE_FILE), p) {
        Some(c) => {
            if c["schema"] != crate::case::SCHEMA_CASE {
                p.push(format!(
                    "{CASE_FILE}: schema {} is not {}",
                    c["schema"],
                    crate::case::SCHEMA_CASE
                ));
            }
            v.case_id = s(&c["case_id"]);
            v.jurisdiction = s(&c["jurisdiction"]);
            v.created_utc = s(&c["created_utc"]);
        }
        None if !dir.join(CASE_FILE).exists() => {
            p.push(format!("{CASE_FILE} is missing: not a case folder yet"))
        }
        None => {}
    }
    let log_path = dir.join(CASE_LOG);
    let log = read_jsonl(&log_path, p);
    if log_path.is_file() {
        v.case_log_intact = Some(crate::audit::verify(&log_path).is_ok());
    }

    // Runs announced in the case log.
    let mut rows: Vec<RunRow> = Vec::new();
    let mut registered: BTreeMap<String, Vec<String>> = BTreeMap::new(); // run id -> ids registered
    for e in &log {
        let rid = e["run_id"].as_str().unwrap_or_default().to_string();
        let d = &e["details"];
        match e["action"].as_str() {
            Some("run_started") => {
                let run_dir = d["run_dir"].as_str().unwrap_or_default().to_string();
                rows.push(RunRow {
                    tool: d["tool"].as_str().unwrap_or("?").to_string(),
                    run_id: rid.clone(),
                    folder_present: !run_dir.is_empty() && dir.join(&run_dir).is_dir(),
                    run_dir,
                    version: s(&d["version"]),
                    role: s(&d["role"]),
                    actor: s(&e["actor"]),
                    started_utc: s(&e["ts_utc"]),
                    finished_utc: None,
                    status: RunStatus::Running,
                    evidence_ids: ids(&d["evidence_ids"]),
                    items: None,
                    severity: None,
                    timestamp: TimestampStatus::Unknown,
                });
            }
            Some("run_finished") => {
                if let Some(r) = rows.iter_mut().rev().find(|r| r.run_id == rid) {
                    r.finished_utc = s(&e["ts_utc"]);
                    r.status = match d["status"].as_str() {
                        Some("completed") => RunStatus::Completed,
                        Some("cancelled") => RunStatus::Cancelled,
                        _ => RunStatus::Failed,
                    };
                    r.timestamp = timestamp_of(&[], d["timestamp_status"].as_str());
                    r.items = d["totals"]["items"].as_u64();
                } else {
                    p.push(format!(
                        "{CASE_LOG}: run_finished for {rid} without run_started"
                    ));
                }
            }
            Some("evidence_registered") => {
                registered
                    .entry(rid)
                    .or_default()
                    .extend(ids(&d["evidence_ids"]));
            }
            _ => {}
        }
    }
    for (tool, run, rel) in run_folders(dir) {
        if !rows.iter().any(|r| r.run_id == run && r.run_dir == rel) {
            rows.push(RunRow {
                tool,
                run_id: run,
                run_dir: rel,
                version: None,
                role: None,
                actor: None,
                started_utc: None,
                finished_utc: None,
                status: RunStatus::NotInCaseLog,
                folder_present: true,
                evidence_ids: vec![],
                items: None,
                severity: None,
                timestamp: TimestampStatus::Unknown,
            });
        }
    }
    for r in &mut rows {
        if !r.folder_present {
            if !r.run_dir.is_empty() {
                p.push(format!("{}: run folder is missing", r.run_dir));
            }
            continue;
        }
        let run_dir = dir.join(&r.run_dir);
        let audit = read_jsonl(&run_dir.join("logs").join("audit.jsonl"), p);
        let recorded = match r.timestamp {
            TimestampStatus::Obtained => Some("ok"),
            TimestampStatus::Pending => Some("pending"),
            TimestampStatus::Off => Some("off"),
            TimestampStatus::Unknown => None,
        };
        r.timestamp = timestamp_of(&audit, recorded);
        if r.version.is_none() {
            r.version = audit.first().and_then(|e| s(&e["details"]["version"]));
        }
        if let Some(st) = read_json(&run_dir.join("reports").join("statistics.json"), p) {
            r.severity = SeverityTotals::from_json(&st["findings_by_severity"]);
            if r.items.is_none() {
                r.items = st["totals"]["items"].as_u64();
            }
            let from_items: Vec<String> = st["items"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|i| i["evidence_id"].as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if !from_items.is_empty() {
                r.evidence_ids = from_items;
            }
        }
        if r.evidence_ids.is_empty() {
            if let Some(reg) = registered.get(&r.run_id) {
                r.evidence_ids = reg.clone();
            }
        }
        let mut seen = BTreeSet::new();
        r.evidence_ids.retain(|i| seen.insert(i.clone()));
    }
    for r in &rows {
        if let Some(sv) = &r.severity {
            v.severity.add(sv);
        }
        let key = serde_json::to_value(r.timestamp)
            .ok()
            .and_then(|k| k.as_str().map(String::from))
            .unwrap_or_default();
        *v.timestamps.entry(key).or_default() += 1;
    }

    // Evidence registry.
    if let Some(reg) = read_json(&dir.join(REGISTRY_JSON), p) {
        let items = reg["items"].as_array().cloned().unwrap_or_default();
        for (i, it) in items.iter().enumerate() {
            let Some(id) = it["evidence_id"].as_str() else {
                p.push(format!(
                    "{REGISTRY_JSON}: item {} has no evidence_id",
                    i + 1
                ));
                continue;
            };
            let path = it["path"].as_str().unwrap_or_default().to_string();
            let superseded_by = items[i + 1..]
                .iter()
                .find(|o| o["path"].as_str() == Some(path.as_str()))
                .and_then(|o| s(&o["evidence_id"]));
            let mut examined: BTreeSet<String> = rows
                .iter()
                .filter(|r| r.evidence_ids.iter().any(|e| e == id))
                .map(|r| r.tool.clone())
                .collect();
            if let Some(t) = it["registered_by"]["tool"].as_str() {
                examined.insert(t.to_string());
            }
            v.evidence.push(EvidenceRow {
                evidence_id: id.to_string(),
                file_name: path
                    .rsplit(['/', '\\'])
                    .next()
                    .unwrap_or(path.as_str())
                    .to_string(),
                path,
                size: it["size"].as_u64().unwrap_or(0),
                hashes: it["hashes"]
                    .as_object()
                    .map(|o| {
                        o.iter()
                            .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                            .collect()
                    })
                    .unwrap_or_default(),
                registered_utc: it["registered_utc"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                registered_by_tool: it["registered_by"]["tool"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                registered_by_run: it["registered_by"]["run_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                examined_by: examined.into_iter().collect(),
                superseded_by,
            });
        }
    }
    v.runs = rows;
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample_case() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample/case")
    }

    #[test]
    fn sample_case_dashboard() {
        let v = read_case(&sample_case());
        assert!(v.problems.is_empty(), "{:?}", v.problems);
        assert_eq!(v.case_id.as_deref(), Some("SAMPLE-1"));
        assert_eq!(v.jurisdiction.as_deref(), Some("co"));
        assert_eq!(v.case_log_intact, Some(true));
        assert_eq!(v.evidence.len(), 5);
        let tools: Vec<&str> = v.runs.iter().map(|r| r.tool.as_str()).collect();
        assert_eq!(tools, ["rv-hashinv", "rv-pdfauth", "rv-imgauth", "rv-rsmf"]);
        assert!(
            v.runs
                .iter()
                .all(|r| r.status == RunStatus::Completed && r.folder_present)
        );
        assert!(v.runs.iter().all(|r| r.timestamp == TimestampStatus::Off));
        assert_eq!(v.timestamps.get("off"), Some(&4));
        let pdf = v
            .evidence
            .iter()
            .find(|e| e.file_name == "contrato.pdf")
            .unwrap();
        assert_eq!(pdf.examined_by, ["rv-hashinv", "rv-pdfauth"]);
        let notes = v
            .evidence
            .iter()
            .find(|e| e.file_name == "notas.txt")
            .unwrap();
        assert_eq!(notes.examined_by, ["rv-hashinv"]);
        let total: u64 = v
            .runs
            .iter()
            .filter_map(|r| r.severity)
            .map(|s| s.info + s.low)
            .sum();
        assert_eq!(total, v.severity.info + v.severity.low);
    }

    #[test]
    fn missing_and_malformed_files_become_problems() {
        let d = tempfile::tempdir().unwrap();
        let v = read_case(d.path());
        assert!(
            v.problems[0].contains("not a case folder"),
            "{:?}",
            v.problems
        );
        std::fs::write(d.path().join(CASE_FILE), "{not json").unwrap();
        std::fs::write(d.path().join(CASE_LOG), "garbage\n").unwrap();
        std::fs::create_dir_all(d.path().join("runs/rv-x/R1/reports")).unwrap();
        std::fs::write(d.path().join("runs/rv-x/R1/reports/statistics.json"), "[").unwrap();
        std::fs::create_dir_all(d.path().join("evidence")).unwrap();
        std::fs::write(d.path().join(REGISTRY_JSON), r#"{"items":[{"path":"x"}]}"#).unwrap();
        let v = read_case(d.path());
        assert_eq!(v.case_log_intact, Some(false));
        assert_eq!(v.runs.len(), 1);
        assert_eq!(v.runs[0].status, RunStatus::NotInCaseLog);
        assert!(v.problems.len() >= 4, "{:?}", v.problems);
        assert!(v.evidence.is_empty());
    }
}
