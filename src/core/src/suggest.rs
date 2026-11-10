//! Next-step suggestions for a case (plan §1 table). Each suggestion carries a reason key worded in
//! `i18n/*.json` (section `suggest`), so the GUI and the CLI show it in the user's language.
//!
//! | Situation                                                        | Suggestion  | Reason key                    |
//! |------------------------------------------------------------------|-------------|-------------------------------|
//! | No case, or no registered evidence yet                           | rv-hashinv  | `no_case` / `no_evidence`     |
//! | Registered PDFs not yet analysed                                 | rv-pdfauth  | `pdf_not_analysed`            |
//! | Images (JPEG/HEIC/PNG/WebP, by signature) not yet analysed       | rv-imgauth  | `images_not_analysed`         |
//! | Chat exports (WhatsApp .txt by content, Telegram JSON/HTML, .msg, CSV) not converted | rv-rsmf | `chats_not_converted` |
//! | Certificates, CRLs or timestamp tokens (.crt .cer .der .pem .p7b .p12 .crl .tsr .tst …, or DER / PEM content) not yet analysed | rv-certcheck | `certs_not_analysed` |
//! | Any other described tool with matching, unexamined evidence      | that tool   | `not_examined`                |
//! | Runs whose trusted timestamp is pending                          | `timestamp` | `timestamp_pending`           |
//!
//! Matching uses each tool's `accepts` lists (from `describe --json`, or the built-in table): the extension, or
//! the file's first bytes. The file is opened read-only, at its registered path or, when it is not there, by file
//! name in the `--evidence-dir` folders. A `.txt` file is a chat export only when one of its first 20 lines is a
//! WhatsApp line (`12/03/26, 09:14 - Name: …` or `[12/03/26 09:14:05] Name: …`); a `.txt` file that cannot be
//! read is not suggested. An item counts as examined by a tool only through a completed run of that tool
//! (`case_view`): a failed, cancelled or unfinished run does not.

use crate::case_view::{CaseView, EvidenceRow, TimestampStatus};
use crate::tools::{Describe, ToolRole};
use serde::Serialize;
use std::io::Read;
use std::path::{Path, PathBuf};

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

/// One line of a WhatsApp chat export, in either layout (any of `/ . -` between the date parts, 2- or 4-digit
/// year, optional seconds and AM/PM marker):
///
/// * Android: `12/03/26, 09:14 - Laura: hola`
/// * iOS: `[12/03/26 09:14:05] Laura: hola` (a comma after the date is accepted)
///
/// The sender and the `: ` after it are required, so a line that only starts with a date and a time (a note,
/// a log line) is not a chat line.
pub fn is_whatsapp_line(line: &str) -> bool {
    let l = line
        .trim_start_matches('\u{feff}')
        .trim_start_matches('\u{200e}');
    let (bracket, l) = match l.strip_prefix('[') {
        Some(rest) => (true, rest),
        None => (false, l),
    };
    let b = l.as_bytes();
    let mut i = 0;
    let digits = |i: &mut usize, min: usize, max: usize| {
        let start = *i;
        while *i < b.len() && b[*i].is_ascii_digit() {
            *i += 1;
        }
        (min..=max).contains(&(*i - start))
    };
    // date: d{1,2} sep d{1,2} sep d{2,4}
    if !digits(&mut i, 1, 2) {
        return false;
    }
    let sep = match b.get(i) {
        Some(c @ (b'/' | b'.' | b'-')) => *c,
        _ => return false,
    };
    i += 1;
    if !digits(&mut i, 1, 2) || b.get(i) != Some(&sep) {
        return false;
    }
    i += 1;
    let y = i;
    if !digits(&mut i, 2, 4) || i - y == 3 {
        return false;
    }
    if b.get(i) == Some(&b',') {
        i += 1;
    }
    let sp = i;
    while i < b.len() && b[i] == b' ' {
        i += 1;
    }
    if i == sp {
        return false;
    }
    // time: h{1,2}:mm(:ss)?
    if !digits(&mut i, 1, 2) || b.get(i) != Some(&b':') {
        return false;
    }
    i += 1;
    if !digits(&mut i, 2, 2) {
        return false;
    }
    if b.get(i) == Some(&b':') {
        i += 1;
        if !digits(&mut i, 2, 2) {
            return false;
        }
    }
    // The rest after the time: an optional AM/PM marker ("PM", "a. m.", with a normal or narrow space), then the
    // separator, the sender and ": ".
    let rest = &l[i..];
    let rest = rest.trim_start_matches([' ', '\u{202f}', '\u{a0}']);
    let marker_end = rest
        .find(|c: char| {
            !(c.is_alphabetic() || c == '.' || c == ' ' || c == '\u{a0}' || c == '\u{202f}')
        })
        .unwrap_or(rest.len());
    let marker = rest[..marker_end].trim_end();
    let rest = if marker.chars().filter(|c| c.is_alphabetic()).count() <= 2 {
        &rest[marker.len()..]
    } else {
        rest
    };
    let rest = rest.trim_start_matches([' ', '\u{202f}', '\u{a0}']);
    let message = if bracket {
        match rest.strip_prefix(']') {
            Some(m) => m.strip_prefix(' ').unwrap_or(m),
            None => return false,
        }
    } else {
        match rest.strip_prefix("- ") {
            Some(m) => m,
            None => return false,
        }
    };
    let message = message.trim_start_matches('\u{200e}');
    match message.find(": ") {
        Some(n) => n > 0 && n <= 100 && !message[..n].trim().is_empty(),
        None => false,
    }
}

/// True when one of the first 20 lines of `text` is a WhatsApp chat line ([`is_whatsapp_line`]).
pub fn looks_like_whatsapp(text: &[u8]) -> bool {
    String::from_utf8_lossy(text)
        .lines()
        .take(20)
        .any(is_whatsapp_line)
}

/// Where a registered file is now: its registered path when it is a file, else `<dir>/<file name>` for each
/// folder of `evidence_dirs` in order (the same lookup as `verify --evidence-dir`).
pub fn locate(e: &EvidenceRow, evidence_dirs: &[PathBuf]) -> Option<PathBuf> {
    let p = PathBuf::from(&e.path);
    if p.is_file() {
        return Some(p);
    }
    evidence_dirs
        .iter()
        .map(|d| d.join(&e.file_name))
        .find(|c| c.is_file())
}

fn reason_for(tool: &str) -> &'static str {
    match tool {
        "rv-pdfauth" => "pdf_not_analysed",
        "rv-imgauth" => "images_not_analysed",
        "rv-rsmf" => "chats_not_converted",
        "rv-certcheck" => "certs_not_analysed",
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
    // A .txt is a chat export only by its content: an unreadable one is not suggested.
    if is_txt && !d.accepts.any() {
        return head_bytes.is_some_and(looks_like_whatsapp);
    }
    true
}

/// The suggestions for `view`, in the order of the table above. `catalog`: [`crate::tools::catalog`]. Files are
/// read at their registered path only; see [`suggest_with`].
pub fn suggest(view: &CaseView, catalog: &[Describe]) -> Vec<Suggestion> {
    suggest_with(view, catalog, &[])
}

/// Like [`suggest`]; a registered file that is not at its registered path is looked for by file name in
/// `evidence_dirs` (`rv-hub case --evidence-dir`), in order.
pub fn suggest_with(
    view: &CaseView,
    catalog: &[Describe],
    evidence_dirs: &[PathBuf],
) -> Vec<Suggestion> {
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
        .map(|e| locate(e, evidence_dirs).and_then(|p| head(&p, want)))
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
    fn whatsapp_sniffing() {
        assert!(looks_like_whatsapp(b"12/03/2026, 09:14 - Laura: hola\n"));
        assert!(looks_like_whatsapp(b"12/03/26, 9:14 - Laura: hola\n"));
        assert!(looks_like_whatsapp(
            "\u{feff}[12.03.26, 09:14:05] Ana: x".as_bytes()
        ));
        assert!(looks_like_whatsapp(b"[12/03/26 09:14:05] Ana: x"));
        assert!(looks_like_whatsapp(
            "3/12/26, 9:14\u{202f}PM - Ana: x".as_bytes()
        ));
        assert!(looks_like_whatsapp(
            "12/03/26, 9:14 a.\u{a0}m. - Ana: x".as_bytes()
        ));
        assert!(looks_like_whatsapp(
            b"12/03/26, 09:13 - Messages are end-to-end encrypted.\n12/03/26, 09:14 - Ana: x"
        ));
        // A date and a time are not enough: the sender and ": " are required.
        assert!(!looks_like_whatsapp(b"intro\n2026-03-12 09:14 x"));
        assert!(!looks_like_whatsapp(
            b"12/03/2026, 09:14 - reunion con el cliente"
        ));
        assert!(!looks_like_whatsapp(
            b"Notas del examinador\nCaso SAMPLE-1."
        ));
        assert!(!looks_like_whatsapp(b"12/03/2026 sin hora"));
        assert!(!looks_like_whatsapp(b"[12/03/26 09:14:05 Ana: x"));
        assert!(!looks_like_whatsapp(b"12/03/202, 09:14 - Ana: x"));
    }

    #[test]
    fn evidence_dirs_are_searched_and_unreadable_txt_is_not_a_chat() {
        let d = tempfile::tempdir().unwrap();
        let moved = d.path().join("copies");
        std::fs::create_dir(&moved).unwrap();
        std::fs::write(moved.join("chat.txt"), b"12/03/26, 09:14 - Ana: hola\n").unwrap();
        std::fs::write(moved.join("notas.txt"), b"Notas del examinador\n").unwrap();
        let cat = catalog(&[]);
        let v = CaseView {
            case_id: Some("C".into()),
            evidence: vec![
                row("E0001", &d.path().join("gone/chat.txt"), &["rv-hashinv"]),
                row("E0002", &d.path().join("gone/notas.txt"), &["rv-hashinv"]),
            ],
            ..Default::default()
        };
        // Not at the registered path and no folder given: neither .txt can be read, neither is suggested.
        assert!(suggest(&v, &cat).is_empty());
        let s = suggest_with(&v, &cat, &[d.path().join("nowhere"), moved.clone()]);
        assert_eq!(s.len(), 1, "{s:?}");
        assert_eq!(
            (s[0].tool.as_str(), s[0].evidence_ids.clone()),
            ("rv-rsmf", vec!["E0001".to_string()])
        );
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
        let cert = w("server.crt", b"-----BEGIN CERTIFICATE-----\nMIIB\n");
        let token = w("token.bin", b"\x30\x82\x05\x00\x30\x03");
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
            row("E0007", &cert, &["rv-hashinv"]),
            row("E0008", &token, &["rv-hashinv"]),
            row("E0009", &cert, &["rv-hashinv", "rv-certcheck"]),
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
                ("rv-certcheck", "certs_not_analysed", vec!["E0007", "E0008"]),
                ("rv-pdfauth", "timestamp_pending", vec![]),
            ]
        );
        assert_eq!(s[4].action, Action::Timestamp);
        assert_eq!(s[4].run_dirs, ["runs/rv-pdfauth/R2"]);
    }

    #[test]
    fn sample_case_has_nothing_left_to_examine() {
        let v =
            read_case(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample/case"));
        // Registered paths are not on this machine: nothing is suggested (notas.txt cannot be read, so it is
        // not taken for a chat export).
        assert_eq!(suggest(&v, &catalog(&[])), vec![]);
        // With the evidence folder, the content is read: notas.txt is still not a chat export.
        let ev = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample/evidence");
        let s = suggest_with(&v, &catalog(&[]), &[ev]);
        assert!(s.iter().all(|x| x.tool != "rv-rsmf"), "{s:?}");
    }
}
