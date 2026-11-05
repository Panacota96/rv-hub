//! `rv-hub tools`, `case` and `launch`: help contract, inventory with fake tools on PATH, a case summary that
//! never writes, and launch refusal / success. The Windows-only signature outcomes are driven through the
//! library (`rv_hub_cli::hub`) with the core's `StaticVerifier` and a recording `Spawner`.

use assert_cmd::Command;
use rv_hub_cli::hub::{self, Out};
use rv_hub_core::launch::Spawner;
use rv_hub_core::session::Session;
use rv_hub_core::signature::{SignatureStatus, StaticVerifier};
use rv_hub_core::tools::{DiscoverOptions, ToolInfo, discover};
use serde_json::Value;
use std::cell::RefCell;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let t = to.join(e.file_name());
        if e.path().is_dir() {
            copy_dir(&e.path(), &t);
        } else {
            std::fs::copy(e.path(), &t).unwrap();
        }
    }
}

fn sample_copy(tmp: &Path) -> PathBuf {
    let case = tmp.join("case");
    copy_dir(&root().join("examples/sample/case"), &case);
    case
}

/// The binary with a controlled environment: tools only from `path` (plus the system folders, which hold
/// no rv-* program), no Windows install folder, the hub data folder in `data`.
fn hub_bin(path: &Path, data: &Path) -> Command {
    let mut c = Command::cargo_bin("rv-hub").unwrap();
    c.env("PATH", format!("{}:/usr/bin:/bin", path.display()))
        .env_remove("LOCALAPPDATA")
        .env("RV_HUB_DATA_DIR", data)
        .env("RV_NO_TIMESTAMP", "1");
    c
}

#[cfg(unix)]
fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

const PDF_DESCRIBE: &str = r#"{"schema":"rakvor.describe/1","tool":"rv-pdfauth","title":"RV PDFAuth","version":"0.9.9",
"role":"analysis","main_verb":"analyze","accepts":{"extensions":["pdf"],"signatures":[{"format":"pdf","match":[{"offset":0,"hex":"255044462d"}]}]},
"case_formats":["rakvor.case/1"],"log_formats":["rakvor.audit/1"],"cli_exe":"rv-pdfauth.exe","gui_exe":"rv-pdfauth-gui.exe",
"exit_codes":{"0":"ok","1":"error","2":"usage","3":"findings","130":"cancelled"}}"#;

/// A folder with fake tools: rv-pdfauth answers `describe --json` (version 0.9.9) and has a GUI that records
/// its arguments in `marker`; rv-rsmf is an old version without `describe`.
#[cfg(unix)]
fn fake_tools(dir: &Path, marker: &Path) -> PathBuf {
    let bin = dir.join("fakebin");
    let json = dir.join("pdf-describe.json");
    std::fs::write(&json, PDF_DESCRIBE).unwrap();
    script(
        &bin,
        "rv-pdfauth",
        &format!(
            "if [ \"$1\" = describe ]; then cat '{}'; exit 0; fi\nexit 2",
            json.display()
        ),
    );
    script(
        &bin,
        "rv-pdfauth-gui",
        &format!("echo \"$@\" > '{}'", marker.display()),
    );
    script(
        &bin,
        "rv-rsmf",
        "echo \"error: unrecognized subcommand '$1'\" >&2; exit 2",
    );
    bin
}

fn python() -> Option<String> {
    let explicit = std::env::var("RV_TEST_PYTHON").ok();
    let py = explicit.clone().unwrap_or_else(|| "python3".into());
    let ok = std::process::Command::new(&py)
        .args(["-c", "import jsonschema"])
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        assert!(
            explicit.is_none(),
            "RV_TEST_PYTHON={py} has no jsonschema module (pip install jsonschema)"
        );
        eprintln!("skipped schema validation: no Python with jsonschema");
        return None;
    }
    Some(py)
}

/// Validates `doc` against `schemas/<schema>`; Ok(()) or the validator's message. Ok when no Python.
fn check_schema(schema: &str, doc: &str) -> Result<(), String> {
    let Some(py) = python() else { return Ok(()) };
    let mut child = std::process::Command::new(&py)
        .args([
            "-c",
            "import json,sys,jsonschema\n\
             s=json.load(open(sys.argv[1],encoding='utf-8'))\n\
             jsonschema.Draft202012Validator.check_schema(s)\n\
             try:\n  jsonschema.Draft202012Validator(s).validate(json.load(sys.stdin))\n\
             except jsonschema.ValidationError as e:\n  print(e.message); sys.exit(1)",
        ])
        .arg(root().join("schemas").join(schema))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(doc.as_bytes())
        .unwrap();
    let o = child.wait_with_output().unwrap();
    if o.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&o.stdout).into_owned())
    }
}

fn session_actions(data: &Path) -> Vec<(String, Value)> {
    let logs = data.join("logs");
    let mut out = Vec::new();
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&logs)
        .map(|d| d.map(|e| e.unwrap().path()).collect())
        .unwrap_or_default();
    dirs.sort();
    for d in dirs {
        let p = d.join("audit.jsonl");
        assert_eq!(
            rv_hub_core::audit::verify(&p).map(|_| ()),
            Ok(()),
            "session log chain {}",
            p.display()
        );
        for l in std::fs::read_to_string(&p).unwrap().lines() {
            let v: Value = serde_json::from_str(l).unwrap();
            out.push((
                v["action"].as_str().unwrap().to_string(),
                v["details"].clone(),
            ));
        }
    }
    out
}

// ------------------------------------------------------------------------------------------------- help

#[test]
fn every_hub_command_meets_the_help_contract() {
    for (cmd, flags) in [
        (
            "tools",
            &[
                "--json",
                "--check-signatures",
                "--add-folder",
                "--lang",
                "--actor",
            ][..],
        ),
        (
            "case",
            &["--case-dir", "--json", "--add-folder", "--lang"][..],
        ),
        (
            "launch",
            &[
                "<TOOL>",
                "--case-dir",
                "--yes-untrusted",
                "--add-folder",
                "--lang",
                "--actor",
            ][..],
        ),
        (
            "verify",
            &[
                "--crosscheck",
                "--tool-exe",
                "--evidence-dir",
                "--rehash",
                "--out",
            ][..],
        ),
    ] {
        let out = Command::cargo_bin("rv-hub")
            .unwrap()
            .args([cmd, "--help"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0));
        let text = String::from_utf8(out.stdout).unwrap();
        for section in [
            "DESCRIPTION:",
            "Usage:",
            "EXAMPLES:",
            "EXIT CODES:",
            "FILES WRITTEN:",
            "FORENSIC NOTES:",
        ] {
            assert!(text.contains(section), "{cmd}: missing {section}");
        }
        for f in flags {
            assert!(text.contains(f), "{cmd}: missing {f}");
        }
        assert!(
            text.matches("Default:").count() >= flags.len()
                && text.matches("Example:").count() >= flags.len(),
            "{cmd}: every option needs Default: and Example:"
        );
        for l in text.lines() {
            assert!(
                l.chars().count() <= 100,
                "{cmd}: line over 100 columns: {l}"
            );
        }
    }
    let verify = String::from_utf8(
        Command::cargo_bin("rv-hub")
            .unwrap()
            .args(["verify", "--help"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    for what in [
        "case-log.jsonl",
        "audit.jsonl",
        "review.jsonl",
        "run_finished",
        "timestamp",
        "--rehash",
        "auto|off",
        "<CASE>/runs/rv-hub/<RUN-ID>/",
        "integrity, not content",
        "never edits",
    ] {
        assert!(verify.contains(what), "verify --help lacks {what}");
    }
    let root_help = String::from_utf8(
        Command::cargo_bin("rv-hub")
            .unwrap()
            .arg("--help")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    for c in ["verify", "tools", "case", "launch"] {
        assert!(root_help.contains(c));
    }
}

// ------------------------------------------------------------------------------------------------ tools

#[cfg(unix)]
#[test]
fn tools_lists_fake_tools_on_path_and_records_the_call() {
    let d = tempfile::tempdir().unwrap();
    let bin = fake_tools(d.path(), &d.path().join("marker"));
    let data = d.path().join("hub");

    let out = hub_bin(&bin, &data).arg("tools").output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    let header = text.lines().next().unwrap();
    for col in ["TOOL", "VERSION", "SOURCE", "SIGNATURE", "PATH"] {
        assert!(header.contains(col), "{header}");
    }
    let pdf = text.lines().find(|l| l.starts_with("rv-pdfauth")).unwrap();
    assert!(pdf.contains("0.9.9") && pdf.contains("PATH"), "{pdf}");
    assert!(pdf.contains(&bin.display().to_string()), "{pdf}");
    let rsmf = text.lines().find(|l| l.starts_with("rv-rsmf")).unwrap();
    assert!(
        rsmf.contains("unknown") && rsmf.contains("builtin"),
        "{rsmf}"
    );
    let cert = text
        .lines()
        .find(|l| l.starts_with("rv-certcheck"))
        .unwrap();
    assert!(cert.contains("not installed"), "{cert}");
    assert!(text.contains("2 tool(s) found"), "{text}");

    // JSON, in Spanish (only the warnings are translated): rakvor.hub-tools/1.
    let out = hub_bin(&bin, &data)
        .args(["tools", "--json", "--lang", "es"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let doc = String::from_utf8(out.stdout).unwrap();
    check_schema("hub-tools.schema.json", &doc).unwrap();
    let v: Value = serde_json::from_str(&doc).unwrap();
    assert_eq!(v["schema"], "rakvor.hub-tools/1");
    assert_eq!(v["exit_code"], 0);
    let pdf = v["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["tool"] == "rv-pdfauth")
        .unwrap();
    assert_eq!(pdf["describe_source"], "describe");
    assert_eq!(pdf["sources"], serde_json::json!(["path"]));
    assert_eq!(pdf["gui"]["sha256"].as_str().unwrap().len(), 64);
    assert!(
        v["not_installed"]
            .as_array()
            .unwrap()
            .contains(&"rv-certcheck".into())
    );

    // Each call is in the hub session log (one session per call), never in a case.
    let actions = session_actions(&data);
    let listed: Vec<&Value> = actions
        .iter()
        .filter(|(a, _)| a == "tools_listed")
        .map(|(_, d)| d)
        .collect();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0]["tools"].as_array().unwrap().len(), 2);
    assert_eq!(listed[0]["exit_code"], 0);
}

#[cfg(unix)]
#[test]
fn tools_add_folder_is_scanned_with_subfolders() {
    let d = tempfile::tempdir().unwrap();
    let empty = d.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let usb = d.path().join("usb");
    std::fs::create_dir_all(&usb).unwrap();
    // usb/fakebin: a subfolder of the added folder.
    fake_tools(&usb, &d.path().join("m"));
    let out = hub_bin(&empty, &d.path().join("hub"))
        .args(["tools", "--add-folder"])
        .arg(&usb)
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(0));
    let pdf = text.lines().find(|l| l.starts_with("rv-pdfauth")).unwrap();
    assert!(pdf.contains("folder"), "{pdf}");
}

/// `verify --add-folder` searches that folder for the cross-check's tools, as `tools --add-folder` does. Here
/// (no Authenticode) the tool found there is not Rakvor-signed, so it is reported as found but not asked.
#[cfg(unix)]
#[test]
fn verify_add_folder_is_used_for_the_crosscheck() {
    let d = tempfile::tempdir().unwrap();
    let empty = d.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let usb = d.path().join("usb");
    std::fs::create_dir_all(&usb).unwrap();
    fake_tools(&usb, &d.path().join("m"));
    let reason = |extra: &[&std::ffi::OsStr]| {
        let case = d.path().join(format!("case-{}", extra.len()));
        copy_dir(&root().join("examples/sample/case"), &case);
        let out = hub_bin(&empty, &d.path().join("hub"))
            .args(["verify", "--progress", "none", "--case-dir"])
            .arg(&case)
            .args(extra)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        let run = std::fs::read_dir(case.join("runs/rv-hub"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let audit = std::fs::read_to_string(run.join("logs/audit.jsonl")).unwrap();
        let entries: Vec<Value> = audit
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let started = entries
            .iter()
            .find(|e| e["action"] == "run_started")
            .unwrap();
        let x = entries
            .iter()
            .find(|e| e["action"] == "crosscheck" && e["details"]["tool"] == "rv-pdfauth")
            .unwrap();
        (
            started["details"]["add_folders"].clone(),
            x["details"]["reason"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        )
    };
    let (folders, why) = reason(&[]);
    assert_eq!(folders, serde_json::json!([]));
    assert!(why.contains("is not installed"), "{why}");
    let (folders, why) = reason(&["--add-folder".as_ref(), usb.as_os_str()]);
    assert_eq!(folders, serde_json::json!([usb.display().to_string()]));
    assert!(why.contains("is not Rakvor-signed"), "{why}");
}

fn found_with(dir: &Path, status: SignatureStatus) -> Vec<ToolInfo> {
    discover(
        &DiscoverOptions {
            registry: vec![],
            local_programs: None,
            path_dirs: vec![],
            user_folders: vec![dir.to_path_buf()],
            describe_timeout: Duration::from_secs(5),
            describe_untrusted: false,
        },
        &StaticVerifier::always(status),
    )
}

fn run_tools(found: &[ToolInfo], data: &Path, json: bool) -> (u8, String, String) {
    let mut s = Session::start(data, "tester", "test", &[]).unwrap();
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let code = hub::tools_cmd(
        &hub::ToolsArgs {
            json,
            check_signatures: true,
            lang: "en".into(),
        },
        found,
        &[],
        &mut s,
        &mut Out {
            out: &mut o,
            err: &mut e,
        },
    );
    (
        code,
        String::from_utf8(o).unwrap(),
        String::from_utf8(e).unwrap(),
    )
}

#[cfg(unix)]
#[test]
fn tools_exit_codes_follow_the_signature_status() {
    let d = tempfile::tempdir().unwrap();
    let bin = fake_tools(d.path(), &d.path().join("marker"));
    let data = d.path().join("hub");

    // Other root and invalid: exit 3, an error line, the finding code in the details.
    for (status, code) in [
        (
            SignatureStatus::SignedOtherRoot {
                root_sha256: "ab".repeat(32),
            },
            "TOOL_SIGNED_OTHER_ROOT",
        ),
        (
            SignatureStatus::Invalid {
                reason: "file modified after signing".into(),
            },
            "TOOL_SIGNATURE_INVALID",
        ),
    ] {
        let found = found_with(&bin, status);
        // Not Rakvor-signed: describe is never run, the built-in table is used.
        assert!(
            found
                .iter()
                .all(|t| t.describe_source == rv_hub_core::tools::DescribeSource::Builtin)
        );
        let (exit, out, err) = run_tools(&found, &data, false);
        assert_eq!(exit, 3, "{out}{err}");
        assert!(out.contains(code), "{out}");
        assert!(err.contains("do not use this copy"), "{err}");
        let (exit, doc, _) = run_tools(&found, &data, true);
        assert_eq!(exit, 3);
        check_schema("hub-tools.schema.json", &doc).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&doc).unwrap()["exit_code"], 3);
    }

    // Unsigned: exit 0 with a warning line per executable.
    let found = found_with(&bin, SignatureStatus::Unsigned);
    let (exit, out, err) = run_tools(&found, &data, false);
    assert_eq!(exit, 0, "{out}{err}");
    assert!(out.contains("TOOL_UNSIGNED"));
    assert_eq!(
        err.lines()
            .filter(|l| l.starts_with("warning:") && l.contains("is not signed"))
            .count(),
        3,
        "{err}"
    );

    // Rakvor-signed: exit 0, no warning, describe used.
    let found = found_with(&bin, SignatureStatus::SignedRakvor);
    let (exit, out, err) = run_tools(&found, &data, false);
    assert_eq!(exit, 0);
    assert!(out.contains("signed (Rakvor)"), "{out}");
    assert!(!err.contains("warning: rv-pdfauth"), "{err}");
    let pdf = found.iter().find(|t| t.tool == "rv-pdfauth").unwrap();
    assert_eq!(pdf.version.as_deref(), Some("0.9.9"));
}

// ------------------------------------------------------------------------------------------------- case

#[test]
fn case_summary_never_writes_into_the_case() {
    let d = tempfile::tempdir().unwrap();
    let case = sample_copy(d.path());
    let empty = d.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let data = d.path().join("hub");
    let before = hub::tree_sha256(&case);
    assert!(before.len() > 10);

    let out = hub_bin(&empty, &data)
        .args(["case", "--case-dir"])
        .arg(&case)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Case SAMPLE-1"), "{text}");
    assert!(text.contains("jurisdiction: Colombia"), "{text}");
    assert!(text.contains("Evidence items: 5"), "{text}");
    assert!(text.contains("Case log: intact"), "{text}");
    for tool in ["rv-hashinv", "rv-pdfauth", "rv-imgauth", "rv-rsmf"] {
        assert!(
            text.lines()
                .any(|l| l.trim_start().starts_with(tool) && l.contains("completed")),
            "{tool}: {text}"
        );
    }
    assert!(text.contains("Problems: none"));
    assert!(text.contains("Suggested next steps:"));
    // The evidence is not at its registered paths here: notas.txt cannot be read, so it is not taken for a chat
    // export, and every other item has been examined.
    assert!(!text.contains("rv-hub launch rv-rsmf"), "{text}");
    assert!(text.contains("No suggestion"), "{text}");

    // French text, JSON with French reasons: still nothing written.
    let fr = hub_bin(&empty, &data)
        .args(["case", "--lang", "fr", "--case-dir"])
        .arg(&case)
        .output()
        .unwrap();
    let fr = String::from_utf8(fr.stdout).unwrap();
    assert!(
        fr.contains("Affaire SAMPLE-1") && fr.contains("juridiction : Colombie"),
        "{fr}"
    );
    // A copy where the rv-rsmf run failed: the chat it took is no longer "examined". It is suggested again only
    // when its content can be read (--evidence-dir) and is a WhatsApp export; notas.txt never is.
    let failed = d.path().join("failed");
    copy_dir(&case, &failed);
    let log = failed.join("case-log.jsonl");
    let text = std::fs::read_to_string(&log).unwrap();
    let text: String = text
        .lines()
        .map(|l| {
            if l.contains("\"run_finished\"") && l.contains("runs/rv-rsmf/") {
                l.replace("\"status\":\"completed\"", "\"status\":\"failed\"")
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(&log, text).unwrap();
    let without = hub_bin(&empty, &data)
        .args(["case", "--json", "--case-dir"])
        .arg(&failed)
        .output()
        .unwrap();
    let without: Value = serde_json::from_slice(&without.stdout).unwrap();
    assert_eq!(without["suggestions"], serde_json::json!([]), "{without:#}");
    let out = hub_bin(&empty, &data)
        .args(["case", "--json", "--lang", "fr", "--case-dir"])
        .arg(&failed)
        .arg("--evidence-dir")
        .arg(root().join("examples/sample/evidence"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let doc = String::from_utf8(out.stdout).unwrap();
    check_schema("hub-case.schema.json", &doc).unwrap();
    let v: Value = serde_json::from_str(&doc).unwrap();
    assert_eq!(v["schema"], "rakvor.hub-case/1");
    assert_eq!(v["case_id"], "SAMPLE-1");
    assert_eq!(v["evidence_count"], 5);
    assert_eq!(v["runs"].as_array().unwrap().len(), 4);
    assert_eq!(v["severity"]["info"], 6);
    assert_eq!(v["suggestions"].as_array().unwrap().len(), 1, "{v:#}");
    let s = &v["suggestions"][0];
    assert_eq!(s["reason_key"], "chats_not_converted");
    let chat_id = v["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["file_name"] == "whatsapp-chat.txt")
        .unwrap()["evidence_id"]
        .clone();
    assert_eq!(s["evidence_ids"], serde_json::json!([chat_id]));
    assert!(s["reason"].as_str().unwrap().contains("RSMF"));
    assert_ne!(
        s["reason"],
        rv_hub_core::i18n::catalog("en").text("suggest", "chats_not_converted")
    );

    assert_eq!(hub::tree_sha256(&case), before, "case was modified");
    assert!(!data.exists(), "`case` writes no session log either");
}

#[test]
fn case_exit_codes() {
    let d = tempfile::tempdir().unwrap();
    let empty = d.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let data = d.path().join("hub");
    hub_bin(&empty, &data)
        .args(["case", "--case-dir"])
        .arg(d.path().join("missing"))
        .assert()
        .code(2);
    // A folder without case.json: summary printed, exit 1, the intake tool suggested.
    let out = hub_bin(&empty, &data)
        .args(["case", "--case-dir"])
        .arg(&empty)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains("not a case yet") && text.contains("rv-hub launch rv-hashinv"),
        "{text}"
    );
    hub_bin(&empty, &data).arg("case").assert().code(2);
    assert!(std::fs::read_dir(&empty).unwrap().next().is_none());
}

#[test]
fn case_shows_problems_of_a_tampered_case_without_touching_it() {
    let d = tempfile::tempdir().unwrap();
    let case = sample_copy(d.path());
    // A run folder the case log never announced, and a broken case log line.
    std::fs::create_dir_all(case.join("runs/rv-pdfauth/20261101T000000Z-ffffff/logs")).unwrap();
    let log = case.join("case-log.jsonl");
    let mut text = std::fs::read_to_string(&log).unwrap();
    text = text.replacen("\"SAMPLE-1\"", "\"SAMPLE-X\"", 1);
    std::fs::write(&log, text).unwrap();
    let before = hub::tree_sha256(&case);
    let empty = d.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let out = hub_bin(&empty, &d.path().join("hub"))
        .args(["case", "--case-dir"])
        .arg(&case)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Case log: BROKEN"), "{text}");
    assert!(text.contains("NOT IN CASE LOG"), "{text}");
    assert_eq!(hub::tree_sha256(&case), before);
}

// ----------------------------------------------------------------------------------------------- launch

#[cfg(unix)]
#[test]
fn launch_refuses_an_untrusted_tool_and_starts_it_when_confirmed() {
    let d = tempfile::tempdir().unwrap();
    let marker = d.path().join("marker");
    let bin = fake_tools(d.path(), &marker);
    let case = sample_copy(d.path());
    let data = d.path().join("hub");
    let before = hub::tree_sha256(&case);

    // On Linux nothing is Rakvor-signed ("not checked"): refused, exit 3, nothing started.
    let out = hub_bin(&bin, &data)
        .args(["launch", "rv-pdfauth", "--case-dir"])
        .arg(&case)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(
        err.contains("refused") && err.contains("not_checked"),
        "{err}"
    );
    assert!(err.contains("--yes-untrusted"), "{err}");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!marker.exists(), "nothing may start without confirmation");
    let actions = session_actions(&data);
    assert!(actions.iter().any(|(a, _)| a == "tool_launch_refused"));
    assert!(!actions.iter().any(|(a, _)| a == "tool_launched"));

    // Confirmed: started with --case-dir, pid printed, both steps audited.
    let out = hub_bin(&bin, &data)
        .args([
            "launch",
            "rv-pdfauth",
            "--yes-untrusted",
            "--actor",
            "Ana",
            "--case-dir",
        ])
        .arg(&case)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    let pid: u32 = text
        .lines()
        .find_map(|l| l.strip_prefix("pid "))
        .expect("pid line")
        .parse()
        .unwrap();
    assert!(pid > 0);
    assert!(text.contains("Launched rv-pdfauth 0.9.9"), "{text}");
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("--yes-untrusted was given")
    );
    let want = format!(
        "--case-dir {}",
        rv_hub_core::case::normalize(&case).display()
    );
    let mut seen = String::new();
    for _ in 0..250 {
        seen = std::fs::read_to_string(&marker).unwrap_or_default();
        if seen.contains(&want) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(seen.contains(&want), "GUI got: {seen:?}");
    let actions = session_actions(&data);
    let names: Vec<&str> = actions.iter().map(|(a, _)| a.as_str()).collect();
    let i = names
        .iter()
        .position(|a| *a == "tool_untrusted_confirmed")
        .unwrap();
    assert_eq!(names[i + 1], "tool_launched");
    let launched = &actions[i + 1].1;
    assert_eq!(launched["pid"], pid);
    assert_eq!(launched["tool"], "rv-pdfauth");
    assert_eq!(launched["confirmed_untrusted"], true);

    // The hub wrote nothing into the case (the fake GUI does not either).
    assert_eq!(hub::tree_sha256(&case), before);
}

#[cfg(unix)]
#[test]
fn launch_usage_and_runtime_errors() {
    let d = tempfile::tempdir().unwrap();
    let bin = fake_tools(d.path(), &d.path().join("marker"));
    let case = sample_copy(d.path());
    let data = d.path().join("hub");
    // Unknown tool: usage error.
    hub_bin(&bin, &data)
        .args(["launch", "notepad", "--case-dir"])
        .arg(&case)
        .assert()
        .code(2);
    // Known but not installed (rv-rsmf has no GUI here, rv-imgauth is absent): exit 1.
    for t in ["rv-rsmf", "rv-imgauth"] {
        hub_bin(&bin, &data)
            .args(["launch", t, "--case-dir"])
            .arg(&case)
            .assert()
            .code(1)
            .stderr(predicates::str::contains("not installed"));
    }
    // Analysis tool on a folder that is not a case: usage error, before any signature question.
    let empty = d.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    hub_bin(&bin, &data)
        .args(["launch", "rv-pdfauth", "--yes-untrusted", "--case-dir"])
        .arg(&empty)
        .assert()
        .code(2);
    // --case-dir is required.
    hub_bin(&bin, &data)
        .args(["launch", "rv-pdfauth"])
        .assert()
        .code(2);
}

#[derive(Default)]
struct Recorder(RefCell<Vec<(PathBuf, Vec<OsString>)>>);

impl Spawner for Recorder {
    fn spawn_detached(&self, exe: &Path, args: &[OsString]) -> std::io::Result<u32> {
        self.0.borrow_mut().push((exe.to_path_buf(), args.to_vec()));
        Ok(31337)
    }
}

#[cfg(unix)]
#[test]
fn launch_of_a_rakvor_signed_tool_needs_no_confirmation() {
    let d = tempfile::tempdir().unwrap();
    let bin = fake_tools(d.path(), &d.path().join("marker"));
    let case = sample_copy(d.path());
    let rakvor = StaticVerifier::always(SignatureStatus::SignedRakvor);
    let found = found_with(&bin, SignatureStatus::SignedRakvor);
    let mut s = Session::start(&d.path().join("hub"), "tester", "test", &[]).unwrap();
    let rec = Recorder::default();
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let args = hub::LaunchArgs {
        tool: "rv-pdfauth".into(),
        case_dir: case.clone(),
        yes_untrusted: false,
        lang: "es".into(),
    };
    let code = hub::launch_cmd(
        &args,
        &found,
        &mut s,
        &rakvor,
        &rec,
        &mut Out {
            out: &mut o,
            err: &mut e,
        },
    );
    let out = String::from_utf8(o).unwrap();
    assert_eq!(code, 0, "{out}{}", String::from_utf8_lossy(&e));
    assert!(e.is_empty(), "no warning for a Rakvor-signed tool");
    assert!(
        out.contains("pid 31337") && out.contains("Iniciada rv-pdfauth"),
        "{out}"
    );
    let (exe, a) = rec.0.borrow()[0].clone();
    assert!(exe.ends_with("rv-pdfauth-gui"));
    assert_eq!(a[0], OsString::from("--case-dir"));

    // Same tool, another root: refused with exit 3, nothing spawned.
    let other = StaticVerifier::always(SignatureStatus::SignedOtherRoot {
        root_sha256: "cd".repeat(32),
    });
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let code = hub::launch_cmd(
        &args,
        &found,
        &mut s,
        &other,
        &rec,
        &mut Out {
            out: &mut o,
            err: &mut e,
        },
    );
    assert_eq!(code, 3);
    assert_eq!(rec.0.borrow().len(), 1);
    assert!(String::from_utf8(e).unwrap().contains("signed_other_root"));
}
