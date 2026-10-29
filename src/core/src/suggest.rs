//! Next-step suggestions for a case (plan §1 table). Each suggestion carries a reason key worded in
//! `i18n/*.json` (section `suggest`), so the GUI and the CLI show it in the user's language.
//!
//! | Situation                                                        | Suggestion  | Reason key                    |
//! |------------------------------------------------------------------|-------------|-------------------------------|
//! | No case, or no registered evidence yet                           | rv-hashinv  | `no_case` / `no_evidence`     |
//! | Registered PDFs not yet analysed                                 | rv-pdfauth  | `pdf_not_analysed`            |
//! | Images (JPEG/HEIC/PNG/WebP, by signature) not yet analysed       | rv-imgauth  | `images_not_analysed`         |
//! | Chat exports (WhatsApp .txt, Telegram JSON/HTML, .msg, CSV) not converted | rv-rsmf | `chats_not_converted` |
//! | Any other described tool with matching, unexamined evidence      | that tool   | `not_examined`                |
//! | Runs whose trusted timestamp is pending                          | `timestamp` | `timestamp_pending`           |
//!
//! Matching uses each tool's `accepts` lists (from `describe --json`, or the built-in table): the extension, or
//! the file's first bytes. The file is opened read-only, and only when it exists at its registered path. A `.txt`
//! file is a chat export only when its first lines look like one (a date and time at the start of a line, the
//! WhatsApp export format); unreadable `.txt` files are matched by extension alone.

use crate::case_view::{CaseView, EvidenceRow, TimestampStatus};
use crate::tools::{Describe, ToolRole};
use serde::Serialize;
use std::io::Read;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Open the tool's GUI on the case (`launch`).
    Launch,
    /// Run `<tool> timestamp <run>/logs` for the listed runs.
    Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Suggestion {
    pub tool: String,
    pub action: Action,
    /// Key in the `suggest` section of i18n/*.json.
    pub reason_key: String,
    pub evidence_ids: Vec<String>,
    /// For `Timestamp`: "runs/<tool>/<RUN-ID>".
    pub run_dirs: Vec<String>,
}

const SNIFF: usize = 4096;

fn head(path: &Path, n: usize) -> Option<Vec<u8>> {
    let f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::with_capacity(n);
    f.take(n as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// A line that starts like a chat export line: `12/03/2026, 09:14 - …`, `[12.03.26, 09:14:05] …`, `2026-03-12 09:14`.
pub fn looks_like_chat(text: &[u8]) -> bool {
    let text = String::from_utf8_lossy(text);
    text.lines().take(20).any(|l| {
        let l = l.trim_start_matches('\u{feff}').trim_start_matches('[');
        let b = l.as_bytes();
        let mut i = 0;
        let mut groups = 0;
        // date: three groups of digits separated by / . or -
        while groups < 3 {
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i == start || i - start > 4 {
                return false;
            }
            groups += 1;
            if groups < 3 {
                if i < b.len() && matches!(b[i], b'/' | b'.' | b'-') {
                    i += 1;
                } else {
                    return false;
                }
            }
        }
        if i < b.len() && b[i] == b',' {
            i += 1;
        }
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        let h = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        (1..=2).contains(&(i - h))
            && i + 2 < b.len()
            && b[i] == b':'
            && b[i + 1].is_ascii_digit()
            && b[i + 2].is_ascii_digit()
    })
}

fn reason_for(tool: &str) -> &'static str {
    match tool {
        "rv-pdfauth" => "pdf_not_analysed",
        "rv-imgauth" => "images_not_analysed",
        "rv-rsmf" => "chats_not_converted",
        _ => "not_examined",
    }
}

/// True when `d` accepts the registered file (extension or content, see the module documentation).
pub fn accepts(d: &Describe, e: &EvidenceRow, head_bytes: Option<&[u8]>) -> bool {
    if let Some(h) = head_bytes {
        if d.accepts.matches_content(h) {
            return true;
        }
    }
    if !d.accepts.matches_extension(&e.file_name) {
        return false;
    }
    let is_txt = Path::new(&e.file_name)
        .extension()
        .is_some_and(|x| x.eq_ignore_ascii_case("txt"));
    match (is_txt && !d.accepts.any(), head_bytes) {
        (true, Some(h)) => looks_like_chat(h),
        _ => true,
    }
}

/// The suggestions for `view`, in the order of the table above. `catalog`: [`crate::tools::catalog`].
pub fn suggest(view: &CaseView, catalog: &[Describe]) -> Vec<Suggestion> {
    let mut out = Vec::new();
    let intake = catalog
        .iter()
        .find(|d| d.role == ToolRole::Intake)
        .map(|d| d.tool.clone())
        .unwrap_or_else(|| "rv-hashinv".into());
    if view.case_id.is_none() || view.evidence.is_empty() {
        out.push(Suggestion {
            tool: intake,
            action: Action::Launch,
            reason_key: if view.case_id.is_none() {
                "no_case"
            } else {
                "no_evidence"
            }
            .into(),
            evidence_ids: vec![],
            run_dirs: vec![],
        });
    }
    let want = catalog
        .iter()
        .map(|d| d.accepts.head_len())
        .max()
        .unwrap_or(0)
        .max(SNIFF);
    let heads: Vec<Option<Vec<u8>>> = view
        .evidence
        .iter()
        .map(|e| {
            let p = Path::new(&e.path);
            if p.is_file() { head(p, want) } else { None }
        })
        .collect();
    let mut tools: Vec<&Describe> = catalog
        .iter()
        .filter(|d| d.role != ToolRole::Intake && !d.accepts.any())
        .collect();
    let rank = |t: &str| {
        crate::tools::KNOWN_TOOLS
            .iter()
            .position(|k| *k == t)
            .unwrap_or(usize::MAX)
    };
    tools.sort_by_key(|d| (rank(&d.tool), d.tool.clone()));
    for d in tools {
        let ids: Vec<String> = view
            .evidence
            .iter()
            .zip(&heads)
            .filter(|(e, h)| {
                e.superseded_by.is_none()
                    && !e.examined_by.contains(&d.tool)
                    && accepts(d, e, h.as_deref())
            })
            .map(|(e, _)| e.evidence_id.clone())
            .collect();
        if !ids.is_empty() {
            out.push(Suggestion {
                tool: d.tool.clone(),
                action: Action::Launch,
                reason_key: reason_for(&d.tool).into(),
                evidence_ids: ids,
                run_dirs: vec![],
            });
        }
    }
    let mut pending: Vec<(String, Vec<String>)> = Vec::new();
    for r in view
        .runs
        .iter()
        .filter(|r| r.timestamp == TimestampStatus::Pending)
    {
        match pending.iter_mut().find(|(t, _)| *t == r.tool) {
            Some((_, v)) => v.push(r.run_dir.clone()),
            None => pending.push((r.tool.clone(), vec![r.run_dir.clone()])),
        }
    }
    for (tool, run_dirs) in pending {
        out.push(Suggestion {
            tool,
            action: Action::Timestamp,
            reason_key: "timestamp_pending".into(),
            evidence_ids: vec![],
            run_dirs,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case_view::{RunRow, RunStatus, read_case};
    use crate::tools::catalog;

    fn row(id: &str, path: &Path, examined: &[&str]) -> EvidenceRow {
        EvidenceRow {
            evidence_id: id.into(),
            path: path.display().to_string(),
            file_name: path.file_name().unwrap().to_string_lossy().into_owned(),
            size: 0,
            hashes: Default::default(),
            registered_utc: String::new(),
            registered_by_tool: "rv-hashinv".into(),
            registered_by_run: "R".into(),
            examined_by: examined.iter().map(|s| s.to_string()).collect(),
            superseded_by: None,
        }
    }

    #[test]
    fn chat_sniffing() {
        assert!(looks_like_chat(b"12/03/2026, 09:14 - Laura: hola\n"));
        assert!(looks_like_chat(
            "\u{feff}[12.03.26, 09:14:05] Ana: x".as_bytes()
        ));
        assert!(looks_like_chat(b"intro\n2026-03-12 09:14 x"));
        assert!(!looks_like_chat(b"Notas del examinador\nCaso SAMPLE-1."));
        assert!(!looks_like_chat(b"12/03/2026 sin hora"));
    }

    #[test]
    fn rules_follow_the_table() {
        let d = tempfile::tempdir().unwrap();
        let w = |n: &str, b: &[u8]| {
            let p = d.path().join(n);
            std::fs::write(&p, b).unwrap();
            p
        };
        let pdf = w("a.pdf", b"%PDF-1.4\n");
        let disguised = w("photo.dat", b"\xFF\xD8\xFF\xE0JFIF");
        let chat = w("chat.txt", b"12/03/2026, 09:14 - Ana: hola\n");
        let notes = w("notes.txt", b"just notes");
        let gone = d.path().join("gone.png");
        let cat = catalog(&[]);
        let mut v = CaseView {
            case_id: None,
            ..Default::default()
        };
        assert_eq!(suggest(&v, &cat)[0].reason_key, "no_case");
        v.case_id = Some("C".into());
        assert_eq!(suggest(&v, &cat)[0].tool, "rv-hashinv");
        v.evidence = vec![
            row("E0001", &pdf, &["rv-hashinv"]),
            row("E0002", &disguised, &["rv-hashinv"]),
            row("E0003", &chat, &["rv-hashinv"]),
            row("E0004", &notes, &["rv-hashinv"]),
            row("E0005", &gone, &["rv-hashinv"]),
            row("E0006", &pdf, &["rv-hashinv", "rv-pdfauth"]),
        ];
        v.runs = vec![RunRow {
            tool: "rv-pdfauth".into(),
            run_id: "R2".into(),
            run_dir: "runs/rv-pdfauth/R2".into(),
            version: None,
            role: None,
            actor: None,
            started_utc: None,
            finished_utc: None,
            status: RunStatus::Completed,
            folder_present: true,
            evidence_ids: vec![],
            items: None,
            severity: None,
            timestamp: TimestampStatus::Pending,
        }];
        let s = suggest(&v, &cat);
        let got: Vec<(&str, &str, Vec<&str>)> = s
            .iter()
            .map(|x| {
                (
                    x.tool.as_str(),
                    x.reason_key.as_str(),
                    x.evidence_ids.iter().map(|i| i.as_str()).collect(),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("rv-pdfauth", "pdf_not_analysed", vec!["E0001"]),
                ("rv-imgauth", "images_not_analysed", vec!["E0002", "E0005"]),
                ("rv-rsmf", "chats_not_converted", vec!["E0003"]),
                ("rv-pdfauth", "timestamp_pending", vec![]),
            ]
        );
        assert_eq!(s[3].action, Action::Timestamp);
        assert_eq!(s[3].run_dirs, ["runs/rv-pdfauth/R2"]);
    }

    #[test]
    fn sample_case_has_nothing_left_to_examine() {
        let v =
            read_case(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample/case"));
        // Registered paths are not on this machine: matching falls back to extensions (notas.txt is then a
        // possible chat export, since its content cannot be read).
        let s = suggest(&v, &catalog(&[]));
        assert!(s.iter().all(|x| x.action == Action::Launch), "{s:?}");
        assert!(s.iter().all(|x| x.tool == "rv-rsmf"), "{s:?}");
    }
}
