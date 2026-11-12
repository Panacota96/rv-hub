//! Next-step suggestions for a case (plan §1 table). Each suggestion carries a reason key worded in
//! `i18n/*.json` (section `suggest`), so the GUI and the CLI show it in the user's language.
//!
//! | Situation                                                        | Suggestion  | Reason key                    |
//! |------------------------------------------------------------------|-------------|-------------------------------|
//! | No case, or no registered evidence yet                           | rv-hashinv  | `no_case` / `no_evidence`     |
//! | Registered PDFs not yet analysed                                 | rv-pdfauth  | `pdf_not_analysed`            |
//! | Images (JPEG/HEIC/PNG/WebP, by signature) not yet analysed       | rv-imgauth  | `images_not_analysed`         |
//! | Chat exports (WhatsApp .txt by content, Telegram JSON/HTML, CSV, Teams .msg) not converted | rv-rsmf | `chats_not_converted` |
//! | Certificates, CRLs or timestamp tokens (.crt .cer .der .pem .p7b .p12 .crl .tsr .tst …, or DER / PEM content) not yet analysed | rv-certcheck | `certs_not_analysed` |
//! | Emails (.eml, or a header block with `From:` and `Date:`/`Message-ID:`; .mbox, or a first line `From <sender> <date>`; email .msg) not yet analysed | rv-mailauth | `mail_not_analysed` |
//! | .msg whose message class cannot be read, or is neither an email nor a Teams message | rv-rsmf and rv-mailauth | `msg_ambiguous` |
//! | Any other described tool with matching, unexamined evidence      | that tool   | `not_examined`                |
//! | Runs whose trusted timestamp is pending                          | `timestamp` | `timestamp_pending`           |
//!
//! Matching uses each tool's `accepts` lists (from `describe --json`, or the built-in table): the extension, or
//! the file's first bytes. The file is opened read-only, at its registered path or, when it is not there, by file
//! name in the `--evidence-dir` folders. A `.txt` file is a chat export only when one of its first 20 lines is a
//! WhatsApp line (`12/03/26, 09:14 - Name: …` or `[12/03/26 09:14:05] Name: …`); a `.txt` file that cannot be
//! read is not suggested. An item counts as examined by a tool only through a completed run of that tool
//! (`case_view`): a failed, cancelled or unfinished run does not.
//!
//! **Outlook `.msg`** (extension `.msg`, or compound-file content `D0 CF 11 E0 A1 B1 1A E1`) is accepted by both
//! rv-mailauth (email) and rv-rsmf (Teams messages exported by Microsoft Purview, one `.msg` per message). The
//! MAPI message class (PR_MESSAGE_CLASS, 0x001A) is read from the compound file with the `cfb` crate, read-only:
//!
//! ```mermaid
//! flowchart TD
//!     M[".msg or compound file"] --> C{"PR_MESSAGE_CLASS"}
//!     C -- "IPM.Note, IPM.Note.*" --> A["rv-mailauth: mail_not_analysed"]
//!     C -- "IPM.SkypeTeams.*" --> R["rv-rsmf: chats_not_converted"]
//!     C -- "another class" --> B["both: msg_ambiguous"]
//!     C -- "unreadable, .msg extension" --> B
//!     C -- "unreadable, other extension (.doc, .xls)" --> N["neither"]
//! ```
//!
//! An ambiguous `.msg` that either tool has already examined is not suggested again.

use crate::case_view::{CaseView, EvidenceRow, TimestampStatus};
use crate::tools::{Describe, SignatureSpec, ToolRole};
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
        MAIL_TOOL => "mail_not_analysed",
        _ => "not_examined",
    }
}

/// The email tool and the chat converter: both accept Outlook `.msg` files; the message class decides.
const MAIL_TOOL: &str = "rv-mailauth";
const CHAT_TOOL: &str = "rv-rsmf";
/// Reason key of a `.msg` whose class is unreadable or neither an email nor a Teams message (both tools).
pub const MSG_AMBIGUOUS: &str = "msg_ambiguous";
/// First bytes of every OLE compound file (CFB), hence of every Outlook `.msg`.
pub const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
/// Longest message class read (real classes are a few dozen characters).
const MAX_CLASS_BYTES: u64 = 1024;

/// What an Outlook `.msg` holds, from its MAPI message class (PR_MESSAGE_CLASS, property 0x001A).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MsgKind {
    /// `IPM.Note` and its sub-classes (`IPM.Note.SMIME`, …): an email, for rv-mailauth.
    Email,
    /// `IPM.SkypeTeams.*` (`IPM.SkypeTeams.Message`, `IPM.SkypeTeams.SystemMessage`: Teams messages exported
    /// by Microsoft Purview), for rv-rsmf.
    Teams,
    /// Another class (a meeting request, a contact, a task, …).
    Other(String),
    /// No class could be read: missing file, not a compound file, damaged, or no PR_MESSAGE_CLASS stream.
    Unreadable,
}

impl MsgKind {
    /// The kind of a message class. Classes compare case-insensitively ([MS-OXCMSG] 2.2.1.3).
    pub fn of_class(class: &str) -> MsgKind {
        let c = class.trim().to_ascii_lowercase();
        let under = |prefix: &str| {
            c == prefix
                || c.strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('.'))
        };
        if under("ipm.note") {
            MsgKind::Email
        } else if under("ipm.skypeteams") {
            MsgKind::Teams
        } else {
            MsgKind::Other(class.trim().to_string())
        }
    }
}

/// Reads PR_MESSAGE_CLASS from an Outlook `.msg` (stream `__substg1.0_001A001F`, UTF-16LE, or `…001E`, 8-bit).
/// The file is opened read-only; None when it is not a readable compound file or has no class.
pub fn read_message_class(path: &Path) -> Option<String> {
    let f = std::fs::File::open(path).ok()?;
    // A damaged compound file must never stop the case view: a panic in the parser counts as unreadable.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let mut cf = cfb::CompoundFile::open(f).ok()?;
        for (name, utf16) in [
            ("/__substg1.0_001A001F", true),
            ("/__substg1.0_001A001E", false),
        ] {
            if !cf.is_stream(name) {
                continue;
            }
            let mut buf = Vec::new();
            cf.open_stream(name)
                .ok()?
                .take(MAX_CLASS_BYTES)
                .read_to_end(&mut buf)
                .ok()?;
            let text = if utf16 {
                let units: Vec<u16> = buf
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&units)
            } else {
                buf.iter().map(|&b| b as char).collect()
            };
            let class = text.trim_matches(|c: char| c == '\0' || c.is_whitespace());
            if !class.is_empty() {
                return Some(class.to_string());
            }
        }
        None
    }))
    .ok()
    .flatten()
}

/// The kind of the `.msg` at `path` ([`MsgKind::Unreadable`] when there is no file or no class).
pub fn msg_kind(path: Option<&Path>) -> MsgKind {
    path.and_then(read_message_class)
        .map(|c| MsgKind::of_class(&c))
        .unwrap_or(MsgKind::Unreadable)
}

/// True when `text` starts with an RFC 5322 header block (a saved email without extension, or a `.txt`):
/// the first line is a header field, and the fields before the first blank line, malformed line or the end of
/// `text` include `From:` and `Date:` or `Message-ID:`. Folded lines (starting with a space or a tab) continue
/// a field.
pub fn looks_like_email(text: &[u8]) -> bool {
    let s = String::from_utf8_lossy(text);
    let (mut from, mut date, mut id) = (false, false, false);
    for (i, line) in s.lines().take(200).enumerate() {
        let line = if i == 0 {
            line.trim_start_matches('\u{feff}')
        } else {
            line
        };
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            if i == 0 {
                return false;
            }
            continue;
        }
        let name = match line.split_once(':') {
            Some((n, _)) if !n.is_empty() && n.bytes().all(|b| (33..=126).contains(&b)) => n,
            _ if i == 0 => return false,
            _ => break,
        };
        match name.to_ascii_lowercase().as_str() {
            "from" => from = true,
            "date" => date = true,
            "message-id" => id = true,
            _ => {}
        }
    }
    from && (date || id)
}

fn has_msg_extension(file_name: &str) -> bool {
    Path::new(file_name)
        .extension()
        .is_some_and(|x| x.eq_ignore_ascii_case("msg"))
}

/// The reason key under which `d` is suggested for a registered item, or None. `msg`: the item's message
/// kind when it is a `.msg` or a compound file (see the module documentation).
fn route(
    d: &Describe,
    e: &EvidenceRow,
    head_bytes: Option<&[u8]>,
    msg: Option<&MsgKind>,
) -> Option<&'static str> {
    if (d.tool == MAIL_TOOL || d.tool == CHAT_TOOL)
        && let Some(kind) = msg
    {
        return match kind {
            MsgKind::Email => (d.tool == MAIL_TOOL).then_some(reason_for(&d.tool)),
            MsgKind::Teams => (d.tool == CHAT_TOOL).then_some(reason_for(&d.tool)),
            MsgKind::Other(_) => Some(MSG_AMBIGUOUS),
            // A compound file without a class and without the .msg extension (a .doc, an .xls) is no message.
            MsgKind::Unreadable => has_msg_extension(&e.file_name).then_some(MSG_AMBIGUOUS),
        };
    }
    if d.tool == MAIL_TOOL {
        // By extension, by an email header block, or by an mbox separator line; the bare "From " signature
        // alone would also take a text note that starts with "From the …".
        let by_content = head_bytes.is_some_and(|h| {
            looks_like_email(h)
                || looks_like_mbox(h)
                || d.accepts.signatures.iter().any(|s| {
                    !matches!(s, SignatureSpec::Format { format, .. } if format == "mbox")
                        && s.matches(h)
                })
        });
        return (by_content || d.accepts.matches_extension(&e.file_name))
            .then(|| reason_for(&d.tool));
    }
    accepts(d, e, head_bytes).then(|| reason_for(&d.tool))
}

/// True when the first line of `text` is an mbox separator: `From <sender> <date>`, the date with a time
/// (`From ana@example.org Thu Oct 15 09:00:00 2026`).
pub fn looks_like_mbox(text: &[u8]) -> bool {
    let first = String::from_utf8_lossy(&text[..text.len().min(1024)])
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    let Some(rest) = first.strip_prefix("From ") else {
        return false;
    };
    let mut tokens = rest.split_whitespace();
    let sender_ok = tokens.next().is_some_and(|s| !s.ends_with(':'));
    let is_time = |t: &str| {
        let parts: Vec<&str> = t.split(':').collect();
        (2..=3).contains(&parts.len())
            && (1..=2).contains(&parts[0].len())
            && parts[1..].iter().all(|p| p.len() == 2)
            && parts.iter().all(|p| p.bytes().all(|b| b.is_ascii_digit()))
    };
    sender_ok && tokens.any(is_time)
}

/// True when `d` accepts the registered file (extension or content, see the module documentation).
pub fn accepts(d: &Describe, e: &EvidenceRow, head_bytes: Option<&[u8]>) -> bool {
    if let Some(h) = head_bytes
        && d.accepts.matches_content(h)
    {
        return true;
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
    let paths: Vec<Option<PathBuf>> = view
        .evidence
        .iter()
        .map(|e| locate(e, evidence_dirs))
        .collect();
    let heads: Vec<Option<Vec<u8>>> = paths
        .iter()
        .map(|p| p.as_deref().and_then(|p| head(p, want)))
        .collect();
    // The message class is read only for a .msg or a compound file, and only for items still open.
    let msgs: Vec<Option<MsgKind>> = view
        .evidence
        .iter()
        .zip(paths.iter().zip(&heads))
        .map(|(e, (p, h))| {
            let candidate = has_msg_extension(&e.file_name)
                || h.as_deref().is_some_and(|h| h.starts_with(&CFB_MAGIC));
            (candidate && e.superseded_by.is_none()).then(|| msg_kind(p.as_deref()))
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
        // (reason key, ids): the tool's own reason first, then the ambiguous .msg files.
        let mut groups: Vec<(&'static str, Vec<String>)> = Vec::new();
        for ((e, h), m) in view.evidence.iter().zip(&heads).zip(&msgs) {
            if e.superseded_by.is_some() {
                continue;
            }
            let Some(reason) = route(d, e, h.as_deref(), m.as_ref()) else {
                continue;
            };
            // An ambiguous .msg that either tool has examined is settled: the examiner chose.
            let examined = if reason == MSG_AMBIGUOUS {
                e.examined_by
                    .iter()
                    .any(|t| t == MAIL_TOOL || t == CHAT_TOOL)
            } else {
                e.examined_by.contains(&d.tool)
            };
            if examined {
                continue;
            }
            match groups.iter_mut().find(|(r, _)| *r == reason) {
                Some((_, ids)) => ids.push(e.evidence_id.clone()),
                None => groups.push((reason, vec![e.evidence_id.clone()])),
            }
        }
        groups.sort_by_key(|(r, _)| *r == MSG_AMBIGUOUS);
        for (reason, ids) in groups {
            out.push(Suggestion {
                tool: d.tool.clone(),
                action: Action::Launch,
                reason_key: reason.into(),
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

    /// A minimal synthetic Outlook `.msg` (compound file): the property table and, when given, PR_MESSAGE_CLASS
    /// as a UTF-16LE (`001F`) or 8-bit (`001E`) string stream.
    fn msg_bytes(class: Option<&str>, utf16: bool) -> Vec<u8> {
        use std::io::Write;
        let mut cf = cfb::CompoundFile::create(std::io::Cursor::new(Vec::new())).unwrap();
        cf.create_stream("/__properties_version1.0")
            .unwrap()
            .write_all(&[0u8; 32])
            .unwrap();
        if let Some(c) = class {
            let (name, bytes): (&str, Vec<u8>) = if utf16 {
                (
                    "/__substg1.0_001A001F",
                    c.encode_utf16().flat_map(|u| u.to_le_bytes()).collect(),
                )
            } else {
                ("/__substg1.0_001A001E", c.as_bytes().to_vec())
            };
            cf.create_stream(name).unwrap().write_all(&bytes).unwrap();
        }
        cf.create_stream("/__substg1.0_0037001F")
            .unwrap()
            .write_all(
                &"Synthetic subject"
                    .encode_utf16()
                    .flat_map(|u| u.to_le_bytes())
                    .collect::<Vec<u8>>(),
            )
            .unwrap();
        cf.flush().unwrap();
        cf.into_inner().into_inner()
    }

    #[test]
    fn message_classes_and_email_headers() {
        assert_eq!(MsgKind::of_class("IPM.Note"), MsgKind::Email);
        assert_eq!(
            MsgKind::of_class("ipm.note.SMIME.MultipartSigned"),
            MsgKind::Email
        );
        assert_eq!(MsgKind::of_class("IPM.SkypeTeams.Message"), MsgKind::Teams);
        assert_eq!(
            MsgKind::of_class("IPM.SkypeTeams.SystemMessage"),
            MsgKind::Teams
        );
        assert_eq!(
            MsgKind::of_class("IPM.Notebook"),
            MsgKind::Other("IPM.Notebook".into())
        );
        assert!(matches!(
            MsgKind::of_class("IPM.Appointment"),
            MsgKind::Other(_)
        ));
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("m.msg");
        std::fs::write(&p, msg_bytes(Some("IPM.Note\0"), true)).unwrap();
        assert_eq!(read_message_class(&p).as_deref(), Some("IPM.Note"));
        std::fs::write(&p, msg_bytes(Some("IPM.SkypeTeams.Message"), false)).unwrap();
        assert_eq!(msg_kind(Some(&p)), MsgKind::Teams);
        std::fs::write(&p, msg_bytes(None, true)).unwrap();
        assert_eq!(msg_kind(Some(&p)), MsgKind::Unreadable);
        std::fs::write(&p, &msg_bytes(Some("IPM.Note"), true)[..600]).unwrap();
        assert_eq!(msg_kind(Some(&p)), MsgKind::Unreadable);
        assert_eq!(
            msg_kind(Some(&d.path().join("gone.msg"))),
            MsgKind::Unreadable
        );
        assert_eq!(msg_kind(None), MsgKind::Unreadable);

        assert!(looks_like_email(
            b"Return-Path: <a@example.org>\r\nReceived: from mx.example.org\r\n\tby mx2.example.org\r\nFrom: Ana <ana@example.org>\r\nDate: Thu, 15 Oct 2026 09:00:00 +0000\r\n\r\nbody"
        ));
        assert!(looks_like_email(
            "\u{feff}Message-ID: <1@example.org>\nfrom: b@example.org\n".as_bytes()
        ));
        // From: alone, a header block that does not start the file, an mbox separator line: not an .eml.
        assert!(!looks_like_email(
            b"From: a@example.org\nSubject: x\n\nDate: y"
        ));
        assert!(!looks_like_email(b"Notes\nFrom: a@example.org\nDate: x\n"));
        assert!(!looks_like_email(
            b"From a@example.org Thu Oct 15 09:00:00 2026\nFrom: a@example.org\nDate: x\n"
        ));
        assert!(!looks_like_email(b""));
        assert!(looks_like_mbox(
            b"From ana@example.org Thu Oct 15 09:00:00 2026\nFrom: ana@example.org\n"
        ));
        assert!(looks_like_mbox(
            b"From MAILER-DAEMON Fri Jul  8 12:08 2026\n"
        ));
        assert!(!looks_like_mbox(b"From the examiner: nothing to report\n"));
        assert!(!looks_like_mbox(b"From: ana@example.org\n"));
    }

    /// Emails go to rv-mailauth; an Outlook .msg goes by its message class: email to rv-mailauth, Teams to
    /// rv-rsmf, unreadable or another class to both (`msg_ambiguous`). Every address is example.org.
    #[test]
    fn mail_and_msg_rules() {
        let d = tempfile::tempdir().unwrap();
        let w = |n: &str, b: &[u8]| {
            let p = d.path().join(n);
            std::fs::write(&p, b).unwrap();
            p
        };
        let eml = w("a.eml", b"just a body without headers");
        let headers = w(
            "saved-message",
            b"From: Ana <ana@example.org>\nTo: luis@example.org\nDate: Thu, 15 Oct 2026 09:00:00 +0000\nMessage-ID: <1@example.org>\n\nHola\n",
        );
        let mbox = w("box.mbox", b"");
        let mbox_content = w(
            "export.dat",
            b"From ana@example.org Thu Oct 15 09:00:00 2026\nFrom: ana@example.org\n\nx\n",
        );
        let email_msg = w("email.msg", &msg_bytes(Some("IPM.Note"), true));
        let teams_msg = w(
            "teams.msg",
            &msg_bytes(Some("IPM.SkypeTeams.Message"), true),
        );
        let broken_msg = w("broken.msg", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1truncated");
        let meeting_msg = w(
            "meeting.msg",
            &msg_bytes(Some("IPM.Schedule.Meeting.Request"), false),
        );
        let disguised_msg = w("item.bin", &msg_bytes(Some("IPM.Note"), true));
        let doc = w("report.doc", &msg_bytes(None, true));
        let notes = w("notes.txt", b"From the examiner: nothing to report\n");
        let gone = d.path().join("gone.msg");
        let cat = catalog(&[]);
        let v = CaseView {
            case_id: Some("C".into()),
            evidence: vec![
                row("E0001", &eml, &["rv-hashinv"]),
                row("E0002", &headers, &["rv-hashinv"]),
                row("E0003", &mbox, &["rv-hashinv"]),
                row("E0004", &mbox_content, &["rv-hashinv"]),
                row("E0005", &email_msg, &["rv-hashinv"]),
                row("E0006", &teams_msg, &["rv-hashinv"]),
                row("E0007", &broken_msg, &["rv-hashinv"]),
                row("E0008", &meeting_msg, &["rv-hashinv"]),
                row("E0009", &disguised_msg, &["rv-hashinv"]),
                row("E0010", &doc, &["rv-hashinv"]),
                row("E0011", &notes, &["rv-hashinv"]),
                row("E0012", &gone, &["rv-hashinv"]),
                // Already examined: the email by rv-mailauth, an ambiguous .msg by rv-rsmf.
                row("E0013", &email_msg, &["rv-hashinv", "rv-mailauth"]),
                row("E0014", &broken_msg, &["rv-hashinv", "rv-rsmf"]),
            ],
            ..Default::default()
        };
        let got: Vec<(String, String, Vec<String>)> = suggest(&v, &cat)
            .into_iter()
            .map(|s| (s.tool, s.reason_key, s.evidence_ids))
            .collect();
        let ids = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            got,
            vec![
                (
                    "rv-rsmf".into(),
                    "chats_not_converted".into(),
                    ids(&["E0006"])
                ),
                (
                    "rv-rsmf".into(),
                    "msg_ambiguous".into(),
                    ids(&["E0007", "E0008", "E0012"])
                ),
                (
                    "rv-mailauth".into(),
                    "mail_not_analysed".into(),
                    ids(&["E0001", "E0002", "E0003", "E0004", "E0005", "E0009"])
                ),
                (
                    "rv-mailauth".into(),
                    "msg_ambiguous".into(),
                    ids(&["E0007", "E0008", "E0012"])
                ),
            ]
        );
        // The .msg files are read in place: nothing was written next to them.
        assert_eq!(
            std::fs::read(&email_msg).unwrap(),
            msg_bytes(Some("IPM.Note"), true)
        );
    }

    /// A moved Teams .msg is found in --evidence-dir and its class read there.
    #[test]
    fn msg_class_is_read_in_the_evidence_dir() {
        let d = tempfile::tempdir().unwrap();
        let moved = d.path().join("copies");
        std::fs::create_dir(&moved).unwrap();
        std::fs::write(
            moved.join("teams.msg"),
            msg_bytes(Some("IPM.SkypeTeams.SystemMessage"), true),
        )
        .unwrap();
        let v = CaseView {
            case_id: Some("C".into()),
            evidence: vec![row(
                "E0001",
                &d.path().join("gone/teams.msg"),
                &["rv-hashinv"],
            )],
            ..Default::default()
        };
        let keys = |s: Vec<Suggestion>| {
            s.into_iter()
                .map(|s| (s.tool, s.reason_key))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            keys(suggest(&v, &catalog(&[]))),
            [
                ("rv-rsmf".to_string(), "msg_ambiguous".to_string()),
                ("rv-mailauth".to_string(), "msg_ambiguous".to_string())
            ]
        );
        assert_eq!(
            keys(suggest_with(&v, &catalog(&[]), &[moved])),
            [("rv-rsmf".to_string(), "chats_not_converted".to_string())]
        );
    }

    /// Every reason key the rules give is worded in English, Spanish and French.
    #[test]
    fn every_reason_key_is_translated() {
        let mut keys: Vec<&str> = crate::tools::KNOWN_TOOLS
            .iter()
            .map(|t| reason_for(t))
            .collect();
        keys.extend([
            "no_case",
            "no_evidence",
            "not_examined",
            "timestamp_pending",
            MSG_AMBIGUOUS,
        ]);
        for lang in ["en", "es", "fr"] {
            for k in &keys {
                let t = crate::i18n::catalog(lang).text("suggest", k);
                assert!(t != *k && !t.is_empty(), "{lang}: suggest.{k}");
            }
        }
        assert_eq!(reason_for("rv-mailauth"), "mail_not_analysed");
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
