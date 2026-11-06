//! The hub's real discovery and launch flow with real Authenticode signatures (Windows only).
//!
//! The four fixtures of `tests/signing/make-fixtures.ps1` (see `src/core/src/signature/fixture_tests.rs` for the
//! variables) are installed as a fake `rv-pdfauth` (CLI and GUI) in one subfolder each of a folder given with
//! `--add-folder`. The binary uses the production pin (the bundled Rakvor root), so none of them is Rakvor-signed:
//! `tools` must exit 3 for other-root and invalid signatures, and `launch` must refuse every one of them (exit 3,
//! the program never starts) unless `--yes-untrusted` is given.
#![cfg(windows)]

use assert_cmd::Command;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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

fn sha256_hex(bytes: &[u8]) -> String {
    rv_hub_core::hash::hash_bytes(bytes, rv_hub_core::hash::HashAlgo::Sha256)
}

/// (variant folder name, fixture variable).
const VARIANTS: [(&str, &str); 4] = [
    ("testroot", "RV_SIGTEST_SIGNED"),
    ("unsigned", "RV_SIGTEST_UNSIGNED"),
    ("tampered", "RV_SIGTEST_TAMPERED"),
    ("other", "RV_SIGTEST_OTHER"),
];

struct Setup {
    _tmp: tempfile::TempDir,
    tools: PathBuf,
    empty: PathBuf,
    data: PathBuf,
    case: PathBuf,
    root_sha: String,
    other_root_sha: String,
}

fn setup() -> Option<Setup> {
    let vars = VARIANTS
        .iter()
        .map(|(_, v)| *v)
        .chain(["RV_SIGTEST_ROOT_DER", "RV_SIGTEST_OTHER_ROOT_DER"]);
    let missing: Vec<&str> = vars
        .filter(|v| std::env::var_os(v).is_none_or(|p| !Path::new(&p).is_file()))
        .collect();
    if !missing.is_empty() {
        assert!(
            std::env::var("RV_SIGTEST_REQUIRED").as_deref() != Ok("1"),
            "RV_SIGTEST_REQUIRED=1 but these fixtures are missing: {}",
            missing.join(", ")
        );
        eprintln!("skipped: Authenticode fixtures not provided");
        return None;
    }
    let tmp = tempfile::tempdir().unwrap();
    let tools = tmp.path().join("usb");
    for (dir, var) in VARIANTS {
        let src = PathBuf::from(std::env::var_os(var).unwrap());
        let d = tools.join(dir);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::copy(&src, d.join("rv-pdfauth.exe")).unwrap();
        std::fs::copy(&src, d.join("rv-pdfauth-gui.exe")).unwrap();
    }
    let empty = tmp.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let case = tmp.path().join("case");
    copy_dir(&root().join("examples/sample/case"), &case);
    let der = |v: &str| std::fs::read(std::env::var_os(v).unwrap()).unwrap();
    Some(Setup {
        data: tmp.path().join("hub"),
        root_sha: sha256_hex(&der("RV_SIGTEST_ROOT_DER")),
        other_root_sha: sha256_hex(&der("RV_SIGTEST_OTHER_ROOT_DER")),
        _tmp: tmp,
        tools,
        empty,
        case,
    })
}

/// The binary with tools only from the given `--add-folder` (PATH is an empty folder, no install folder).
fn hub(s: &Setup) -> Command {
    let mut c = Command::cargo_bin("rv-hub").unwrap();
    c.env("PATH", &s.empty)
        .env_remove("LOCALAPPDATA")
        .env("RV_HUB_DATA_DIR", &s.data)
        .env("RV_NO_TIMESTAMP", "1");
    c
}

fn tools_json(s: &Setup, folder: &Path) -> (i32, Value) {
    let out = hub(s)
        .args(["tools", "--json", "--add-folder"])
        .arg(folder)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let doc: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{e}: {text}\n{}", String::from_utf8_lossy(&out.stderr)));
    (out.status.code().unwrap(), doc)
}

#[test]
fn tools_json_reports_each_real_signature() {
    let Some(s) = setup() else { return };
    // (variant, status, finding, exit code of `tools` on that folder alone)
    let expected = [
        ("testroot", "signed_other_root", "TOOL_SIGNED_OTHER_ROOT", 3),
        ("unsigned", "unsigned", "TOOL_UNSIGNED", 0),
        ("tampered", "invalid", "TOOL_SIGNATURE_INVALID", 3),
        ("other", "signed_other_root", "TOOL_SIGNED_OTHER_ROOT", 3),
    ];
    for (dir, status, finding, code) in expected {
        let (exit, doc) = tools_json(&s, &s.tools.join(dir));
        assert_eq!(exit, code, "{dir}: {doc:#}");
        assert_eq!(doc["exit_code"], code, "{dir}");
        assert_eq!(doc["signature_check"], "authenticode_rakvor_root");
        let tools = doc["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1, "{dir}: {doc:#}");
        let t = &tools[0];
        assert_eq!(t["tool"], "rv-pdfauth");
        // Not Rakvor-signed: describe is never run.
        assert_eq!(t["describe_source"], "builtin", "{dir}");
        for exe in ["cli", "gui"] {
            assert_eq!(t[exe]["signature"]["status"], status, "{dir} {exe}: {t:#}");
            assert_eq!(t[exe]["finding"]["code"], finding, "{dir} {exe}");
        }
        match dir {
            "testroot" => assert_eq!(t["cli"]["signature"]["root_sha256"], s.root_sha),
            "other" => assert_eq!(t["cli"]["signature"]["root_sha256"], s.other_root_sha),
            "tampered" => assert!(
                t["cli"]["signature"]["reason"]
                    .as_str()
                    .unwrap()
                    .contains("0x80096010"),
                "{t:#}"
            ),
            _ => {}
        }
    }

    // All four at once (subfolders of the added folder): exit 3, counts per executable.
    let (exit, doc) = tools_json(&s, &s.tools);
    assert_eq!(exit, 3, "{doc:#}");
    assert_eq!(doc["tools"].as_array().unwrap().len(), 4);
    let counts = &doc["signature_counts"];
    assert_eq!(counts["signed_rakvor"], 0, "{counts}");
    assert_eq!(counts["signed_other_root"], 4, "{counts}");
    assert_eq!(counts["invalid"], 2, "{counts}");
    assert_eq!(counts["unsigned"], 2, "{counts}");
    assert_eq!(counts["not_checked"], 0, "{counts}");
}

fn launch(s: &Setup, dir: &str, yes_untrusted: bool) -> std::process::Output {
    let mut c = hub(s);
    c.args(["launch", "rv-pdfauth", "--case-dir"])
        .arg(&s.case)
        .arg("--add-folder")
        .arg(s.tools.join(dir));
    if yes_untrusted {
        c.arg("--yes-untrusted");
    }
    c.output().unwrap()
}

/// Waits a little for the detached fixture to write its marker.
fn marker_after(path: &Path, wait: Duration) -> Option<String> {
    let start = Instant::now();
    loop {
        if let Ok(t) = std::fs::read_to_string(path) {
            return Some(t);
        }
        if start.elapsed() > wait {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn launch_refuses_every_tool_that_is_not_rakvor_signed() {
    let Some(s) = setup() else { return };
    for (dir, _) in VARIANTS {
        let out = launch(&s, dir, false);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(3), "{dir}: {err}");
        assert!(
            marker_after(
                &s.tools.join(dir).join("launched.txt"),
                Duration::from_secs(2)
            )
            .is_none(),
            "{dir}: the refused tool was started"
        );
    }

    // The flow is real: with the confirmation the unsigned fixture is started, on the case.
    let out = launch(&s, "unsigned", true);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let args = marker_after(
        &s.tools.join("unsigned").join("launched.txt"),
        Duration::from_secs(20),
    )
    .expect("the confirmed tool was not started");
    assert!(args.starts_with("--case-dir\n"), "{args}");
}
