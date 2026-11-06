//! The Case tab model, built from `case_view::read_case` and `suggest::suggest`. Read-only: nothing here writes
//! into the case folder (a test checks it).

use rv_hub_core::case_view::{CaseView, RunStatus, SeverityTotals, TimestampStatus, read_case};
use rv_hub_core::suggest::{Action, suggest};
use rv_hub_core::tools::{Describe, ToolInfo};
use std::path::Path;

#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceLine {
    pub id: String,
    pub file: String,
    pub size: String,
    /// Tools whose runs examined the item, comma-separated ("" when none).
    pub examined_by: String,
    pub superseded_by: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RunLine {
    pub tool: String,
    pub run_id: String,
    /// "2026-10-29 11:00:57Z" (start, else finish), "" when unknown.
    pub time: String,
    /// None when the run has no readable statistics.
    pub findings: Option<SeverityTotals>,
    /// i18n `ui` key: ts_obtained | ts_pending | ts_off | ts_unknown
    pub timestamp_key: &'static str,
    /// i18n `ui` key: st_completed | st_cancelled | st_failed | st_running | st_not_in_case_log
    pub status_key: &'static str,
    pub folder_present: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SuggestionLine {
    pub tool: String,
    pub action: Action,
    /// Key in the i18n `suggest` section.
    pub reason_key: String,
    pub evidence_ids: Vec<String>,
    pub run_dirs: Vec<String>,
    /// The installed tool to launch with one click (index into `HubState::tools`); None when not installed.
    pub tool_index: Option<usize>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CaseModel {
    pub view: CaseView,
    pub evidence: Vec<EvidenceLine>,
    pub runs: Vec<RunLine>,
    pub suggestions: Vec<SuggestionLine>,
    /// When the folder was read (UTC).
    pub read_utc: String,
    /// case.json is present.
    pub is_case: bool,
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut v = bytes as f64 / 1024.0;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS[u])
}

/// "2026-10-29T11:00:57.077Z" → "2026-10-29 11:00:57Z".
pub fn short_utc(t: &str) -> String {
    let t = t.replacen('T', " ", 1);
    match t.find('.') {
        Some(i) if t.ends_with('Z') => format!("{}Z", &t[..i]),
        _ => t,
    }
}

fn timestamp_key(t: TimestampStatus) -> &'static str {
    match t {
        TimestampStatus::Obtained => "ts_obtained",
        TimestampStatus::Pending => "ts_pending",
        TimestampStatus::Off => "ts_off",
        TimestampStatus::Unknown => "ts_unknown",
    }
}

fn status_key(s: RunStatus) -> &'static str {
    match s {
        RunStatus::Completed => "st_completed",
        RunStatus::Cancelled => "st_cancelled",
        RunStatus::Failed => "st_failed",
        RunStatus::Running => "st_running",
        RunStatus::NotInCaseLog => "st_not_in_case_log",
    }
}

impl CaseModel {
    /// Reads the case folder (never fails: problems are listed in `view.problems`).
    pub fn load(dir: &Path, tools: &[ToolInfo]) -> CaseModel {
        let view = read_case(dir);
        let catalog: Vec<Describe> = rv_hub_core::tools::catalog(tools);
        let suggestions = suggest(&view, &catalog)
            .into_iter()
            .map(|s| SuggestionLine {
                tool_index: launchable_index(tools, &s.tool),
                tool: s.tool,
                action: s.action,
                reason_key: s.reason_key,
                evidence_ids: s.evidence_ids,
                run_dirs: s.run_dirs,
            })
            .collect();
        CaseModel::from_view(view, suggestions)
    }

    fn from_view(view: CaseView, suggestions: Vec<SuggestionLine>) -> CaseModel {
        let evidence = view
            .evidence
            .iter()
            .map(|e| EvidenceLine {
                id: e.evidence_id.clone(),
                file: e.file_name.clone(),
                size: human_size(e.size),
                examined_by: e.examined_by.join(", "),
                superseded_by: e.superseded_by.clone(),
            })
            .collect();
        let runs = view
            .runs
            .iter()
            .map(|r| RunLine {
                tool: r.tool.clone(),
                run_id: r.run_id.clone(),
                time: r
                    .started_utc
                    .as_deref()
                    .or(r.finished_utc.as_deref())
                    .map(short_utc)
                    .unwrap_or_default(),
                findings: r.severity,
                timestamp_key: timestamp_key(r.timestamp),
                status_key: status_key(r.status),
                folder_present: r.folder_present,
            })
            .collect();
        let is_case = view.dir.join(rv_hub_core::case::CASE_FILE).is_file();
        CaseModel {
            view,
            evidence,
            runs,
            suggestions,
            read_utc: rv_hub_core::time::utc_now(),
            is_case,
        }
    }

    /// i18n `ui` key of the case-log quick check.
    pub fn case_log_key(&self) -> &'static str {
        match self.view.case_log_intact {
            Some(true) => "case_log_intact",
            Some(false) => "case_log_broken",
            None => "case_log_none",
        }
    }
}

/// The first installed tool with this name that has a GUI executable.
pub fn launchable_index(tools: &[ToolInfo], tool: &str) -> Option<usize> {
    tools
        .iter()
        .position(|t| t.tool == tool && t.gui_exe.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_times() {
        assert_eq!(human_size(354), "354 B");
        assert_eq!(human_size(1536), "1.5 KiB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(
            short_utc("2026-10-29T11:00:57.077Z"),
            "2026-10-29 11:00:57Z"
        );
        assert_eq!(short_utc("2026-10-29T11:00:57Z"), "2026-10-29 11:00:57Z");
    }
}
