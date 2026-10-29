//! End-to-end tests of the rv-hub binary: the contract every Rakvor CLI must meet.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn bin() -> Command {
    let mut c = Command::cargo_bin("rv-hub").unwrap();
    c.env("RV_NO_TIMESTAMP", "1"); // offline by default; trust_* tests use a local test TSA
    c
}

/// The fake TSA process, killed when dropped, so a failing assertion cannot leave it running. An orphaned
/// server keeps the test's inherited stderr open: under `cargo test | tee` (CI) the step then never ends.
struct TsaServer(std::process::Child);

impl Drop for TsaServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Starts tests/fake_tsa.py (needs Python with pyhanko). Returns None to skip when unavailable.
fn test_pki(dir: &Path) -> Option<(TsaServer, String)> {
    let py = std::env::var("RV_TEST_PYTHON").unwrap_or_else(|_| "python3".into());
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fake_tsa.py");
    let ok = std::process::Command::new(&py)
        .args(["-c", "import pyhanko"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!(
            "skipping trust test: {} has no pyhanko (pip install pyhanko)",
            py
        );
        return None;
    }
    let mut server = TsaServer(
        std::process::Command::new(&py)
            .arg(&script)
            .arg("serve")
            .arg(dir)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .ok()?,
    );
    let mut line = String::new();
    use std::io::BufRead;
    std::io::BufReader::new(server.0.stdout.take()?)
        .read_line(&mut line)
        .ok()?;
    Some((server, line.trim().to_string()))
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sample_case() -> PathBuf {
    root().join("examples/sample/case")
}

fn sample_evidence() -> PathBuf {
    root().join("examples/sample/evidence")
}

fn only_dir(p: &Path) -> PathBuf {
    let mut d: Vec<PathBuf> = std::fs::read_dir(p)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(d.len(), 1, "{:?}", d);
    d.pop().unwrap()
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

/// A fresh copy of the sample case (the committed one is never written to).
fn sample_copy(tmp: &Path) -> PathBuf {
    let case = tmp.join("case");
    copy_dir(&sample_case(), &case);
    case
}

fn verify(case: &Path) -> Command {
    let mut c = bin();
    c.arg("verify")
        .arg("--case-dir")
        .arg(case)
        .args(["--actor", "ci", "--progress", "none"]);
    c
}

/// The hub's run folders in a case.
fn hub_runs(case: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(case.join("runs/rv-hub"))
        .map(|d| d.map(|e| e.unwrap().path()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

fn statistics(report_dir: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(report_dir.join("statistics.json")).unwrap())
        .unwrap()
}

fn codes(stats: &Value) -> BTreeMap<String, u64> {
    stats["findings_by_code"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_u64().unwrap()))
        .collect()
}

fn python() -> String {
    std::env::var("RV_TEST_PYTHON").unwrap_or_else(|_| "python3".into())
}

/// SHA-256 of every file under `dir` (relative path → digest), skipping `skip` (relative prefixes).
fn tree_digests(dir: &Path, skip: &[&str]) -> BTreeMap<String, String> {
    fn walk(base: &Path, d: &Path, skip: &[&str], out: &mut BTreeMap<String, String>) {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            let rel = p
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if skip
                .iter()
                .any(|s| rel == *s || rel.starts_with(&format!("{s}/")))
            {
                continue;
            }
            if p.is_dir() {
                walk(base, &p, skip, out);
            } else {
                let b = std::fs::read(&p).unwrap();
                out.insert(
                    rel,
                    rv_hub_core::hash::hash_bytes(&b, rv_hub_core::HashAlgo::Sha256),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, skip, &mut out);
    out
}

#[test]
fn help_has_every_required_section() {
    let out = bin().args(["verify", "--help"]).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    for section in [
        "DESCRIPTION:",
        "Options:",
        "EXAMPLES:",
        "EXIT CODES:",
        "FILES WRITTEN:",
        "FORENSIC NOTES:",
    ] {
        assert!(text.contains(section), "missing {}", section);
    }
    for flag in [
        "--case-dir",
        "--rehash",
        "--evidence",
        "--evidence-dir",
        "--crosscheck",
        "--tool-exe",
        "--hash",
        "--out",
        "--lang",
        "--actor",
        "--case",
        "--progress",
        "--jurisdiction",
        "--tsa-url",
        "--no-timestamp",
        "--sign-cert",
    ] {
        assert!(text.contains(flag), "missing {}", flag);
    }
    assert!(
        text.matches("Default:").count() >= 17,
        "each option needs a Default: line"
    );
    assert!(
        text.matches("Example:").count() >= 17,
        "each option needs an Example: line"
    );
}

#[test]
fn usage_errors_exit_2() {
    let tmp = tempfile::tempdir().unwrap();
    let case = sample_copy(tmp.path());
    bin().arg("verify").assert().code(2);
    verify(&case)
        .args(["--hash", "md5,sha1,sha256"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("at most 2"));
    verify(&case).args(["--hash", "crc32"]).assert().code(2);
    verify(&case).args(["--lang", "de"]).assert().code(2);
    verify(&case)
        .args(["--case", "OTHER-CASE"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("belongs to case SAMPLE-1"));
    verify(&case)
        .args(["-E", "E0042"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("E0042"));
    verify(&case)
        .args(["--tool-exe", "nonsense"])
        .assert()
        .code(2);
    verify(tmp.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not a case folder"));
    assert!(
        hub_runs(&case).is_empty(),
        "nothing is written on a usage error"
    );
}

#[test]
fn sample_case_verifies_and_the_hub_writes_only_its_run_and_the_case_log_tail() {
    let tmp = tempfile::tempdir().unwrap();
    let case = sample_copy(tmp.path());
    let log_before = std::fs::read(case.join("case-log.jsonl")).unwrap();
    let before = tree_digests(&case, &["case-log.jsonl"]);
    let o = verify(&case)
        .args(["--rehash", "--evidence-dir"])
        .arg(sample_evidence())
        .args([
            "--crosscheck",
            "off",
            "--hash",
            "sha256,md5",
            "--lang",
            "all",
        ])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&o.stdout);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}{}",
        text,
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(text.contains("codes: RUN_LOG_INTACT"), "{}", text);

    // Nothing but the hub's own run folder and the case-log tail changed.
    assert_eq!(
        tree_digests(&case, &["case-log.jsonl", "runs/rv-hub"]),
        before
    );
    let log_after = std::fs::read(case.join("case-log.jsonl")).unwrap();
    assert!(
        log_after.starts_with(&log_before),
        "the case log is only appended to"
    );
    let tail: Vec<Value> = String::from_utf8_lossy(&log_after[log_before.len()..])
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let actions: Vec<&str> = tail.iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert_eq!(actions, ["run_started", "run_finished"]);
    assert_eq!(tail[0]["details"]["role"], "analysis");
    assert_eq!(tail[0]["details"]["tool"], "rv-hub");
    assert!(!case.join("case-log.lock").exists());

    // The run folder: logs, one report folder per item, statistics in three languages.
    let run = only_dir(&case.join("runs/rv-hub"));
    let (logs, reports) = (run.join("logs"), run.join("reports"));
    for f in ["audit.jsonl", "audit.log", "hashes.csv", "environment.json"] {
        assert!(logs.join(f).is_file(), "{}", f);
    }
    let stats = statistics(&reports);
    assert_eq!(
        stats["totals"]["items"], 10,
        "case log + 4 runs + 5 evidence files"
    );
    assert_eq!(stats["case"]["verification"]["evidence_matched"], 5);
    assert_eq!(stats["case"]["verification"]["runs_intact"], 4);
    assert_eq!(stats["case"]["linked"], true);
    let rows = std::fs::read_to_string(logs.join("hashes.csv"))
        .unwrap()
        .lines()
        .count()
        - 1;
    let items: Vec<PathBuf> = std::fs::read_dir(reports.join("items"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(items.len(), rows);
    for l in ["en", "es", "fr"] {
        for ext in ["html", "pdf"] {
            assert!(reports.join(format!("statistics.{l}.{ext}")).is_file());
        }
    }
    for d in &items {
        for f in [
            "technical.json",
            "summary.json",
            "custody.json",
            "technical.fr.pdf",
            "custody.es.pdf",
            "custody.en.html",
        ] {
            assert!(d.join(f).is_file(), "{} in {}", f, d.display());
        }
    }
    assert_ne!(
        std::fs::read_to_string(reports.join("statistics.es.html")).unwrap(),
        std::fs::read_to_string(reports.join("statistics.en.html")).unwrap()
    );
    // The hub's log verifies (anchored by the case log), with the hub and with the template's independent oracle.
    bin()
        .arg("verify-log")
        .arg(&logs)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("anchored by the case log"));
    // The case log is registered as found (its first N bytes): the hub appends run_finished afterwards, so the
    // oracle's re-hash of the current file differs for that row only.
    if let Ok(o) = std::process::Command::new(python())
        .arg(root().join("tests/verify_chain.py"))
        .arg(&logs)
        .output()
    {
        let out = String::from_utf8_lossy(&o.stdout);
        assert!(out.contains("chain: intact"), "{}", out);
        let bad: Vec<&str> = out
            .lines()
            .filter(|l| l.contains(" != recorded "))
            .collect();
        assert!(bad.iter().all(|l| l.contains("case-log.jsonl")), "{}", out);
    }
    if std::process::Command::new(python())
        .args(["-c", "import jsonschema"])
        .status()
        .is_ok_and(|s| s.success())
    {
        let o = std::process::Command::new(python())
            .arg(root().join("tests/validate_reports.py"))
            .arg(&case)
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
    }
    // The whole case, with the hub's run in it, still verifies with verify-case and with a second verify.
    bin()
        .arg("verify-case")
        .arg(&case)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("5 runs verified"));
    verify(&case).args(["--crosscheck", "off"]).assert().code(0);
    let stats = statistics(&hub_runs(&case)[1].join("reports"));
    assert_eq!(
        codes(&stats).get("RUN_LOG_INTACT"),
        Some(&5),
        "the first hub run is verified too"
    );

    // Tampering with the hub's own log is detected.
    let p = logs.join("audit.jsonl");
    let t = std::fs::read_to_string(&p).unwrap();
    std::fs::write(
        &p,
        t.replacen("\"actor\":\"ci\"", "\"actor\":\"mallory\"", 1),
    )
    .unwrap();
    bin()
        .arg("verify-log")
        .arg(&p)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("BROKEN"));
}

/// Writes the tampered variants (tests/samples/make_tampered.py, Python standard library only).
fn variants(tmp: &Path) -> Option<BTreeMap<String, PathBuf>> {
    let o = std::process::Command::new(python())
        .arg(root().join("tests/samples/make_tampered.py"))
        .arg(tmp)
        .output()
        .ok()?;
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let m: BTreeMap<String, String> = serde_json::from_slice(&o.stdout).unwrap();
    Some(m.into_iter().map(|(k, v)| (k, PathBuf::from(v))).collect())
}

fn expected() -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(root().join("examples/sample/expected_findings.json")).unwrap(),
    )
    .unwrap()
}

/// Runs verify on a variant; returns (exit code, statistics.json).
fn verify_variant(dir: &Path, args: &[String], extra: &[std::ffi::OsString]) -> (i32, Value) {
    let case = dir.join("case");
    let out = dir.join("out");
    let before = hub_runs(&case).len();
    let o = verify(&case)
        .arg("--evidence-dir")
        .arg(dir.join("evidence"))
        .arg("-o")
        .arg(&out)
        .args(args)
        .args(extra)
        .output()
        .unwrap();
    let code = o.status.code().unwrap();
    let after = hub_runs(&case);
    let report = if after.len() > before {
        after.last().unwrap().join("reports")
    } else {
        only_dir(&out.join("reports"))
    };
    (code, statistics(&report))
}

#[test]
fn tampered_variants_give_exactly_their_codes() {
    let tmp = tempfile::tempdir().unwrap();
    let Some(vs) = variants(tmp.path()) else {
        eprintln!(
            "skipping: {} cannot run tests/samples/make_tampered.py",
            python()
        );
        return;
    };
    let exp = expected();
    let want = exp["variants"].as_object().unwrap();
    assert_eq!(want.len(), vs.len(), "every variant has expected findings");
    for (name, dir) in &vs {
        let w = &want[name];
        let args: Vec<String> = w["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap().to_string())
            .collect();
        let mut args = args;
        args.extend(["--crosscheck".to_string(), "off".to_string()]);
        let case_log = std::fs::read(dir.join("case/case-log.jsonl")).unwrap();
        let (code, stats) = verify_variant(dir, &args, &[]);
        let want_codes: BTreeMap<String, u64> = w["codes"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_u64().unwrap()))
            .collect();
        assert_eq!(
            code,
            w["exit"].as_i64().unwrap() as i32,
            "{name}: exit code"
        );
        assert_eq!(codes(&stats), want_codes, "{name}: finding codes");
        if name == "case_log_line_edited" {
            // A broken case log is never extended: the report went to --out, the case log is unchanged.
            assert_eq!(stats["case"]["linked"], false);
            assert_eq!(
                std::fs::read(dir.join("case/case-log.jsonl")).unwrap(),
                case_log
            );
        }
    }
}

/// The four tools' own CLIs, as snapshotted by tests/samples/make_case.sh (gitignored; absent in CI).
fn snapshot_tools() -> Option<Vec<(String, PathBuf)>> {
    let bin = root().join("tests/samples/bin");
    let tools: Vec<(String, PathBuf)> = ["rv-hashinv", "rv-pdfauth", "rv-imgauth", "rv-rsmf"]
        .iter()
        .map(|t| {
            (
                t.to_string(),
                bin.join(format!("{t}{}", std::env::consts::EXE_SUFFIX)),
            )
        })
        .collect();
    tools.iter().all(|(_, p)| p.is_file()).then_some(tools)
}

#[test]
fn crosscheck_with_the_tools_own_verify_log_agrees_on_every_variant() {
    let Some(tools) = snapshot_tools() else {
        eprintln!(
            "skipping cross-check test: tests/samples/bin has no snapshot of the four tools (see tests/samples/make_case.sh)"
        );
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let Some(vs) = variants(tmp.path()) else {
        eprintln!(
            "skipping: {} cannot run tests/samples/make_tampered.py",
            python()
        );
        return;
    };
    let mut extra: Vec<std::ffi::OsString> = vec!["--crosscheck".into(), "auto".into()];
    for (t, p) in &tools {
        extra.push("--tool-exe".into());
        extra.push(format!("{}={}", t, p.display()).into());
    }
    let exp = expected();
    for (name, dir) in &vs {
        let w = &exp["variants"][name];
        let args: Vec<String> = w["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap().to_string())
            .collect();
        let (code, stats) = verify_variant(dir, &args, &extra);
        let mut got = codes(&stats);
        assert_eq!(
            got.remove("TOOL_VERIFY_DISAGREES"),
            None,
            "{name}: a tool disagrees with the hub: {stats:#}"
        );
        // A deleted run folder cannot be cross-checked; everything else must have the tool's verdict.
        let unavailable = got.remove("CROSSCHECK_UNAVAILABLE").unwrap_or(0);
        assert_eq!(
            unavailable,
            if name == "run_folder_deleted" { 1 } else { 0 },
            "{name}"
        );
        let want_codes: BTreeMap<String, u64> = w["codes"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_u64().unwrap()))
            .collect();
        assert_eq!(got, want_codes, "{name}");
        assert_eq!(code, w["exit"].as_i64().unwrap() as i32, "{name}");
        let runs: Vec<&Value> = stats["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["kind"] == "run")
            .collect();
        for r in runs {
            let want = if r["verdict"] == "not_verifiable" {
                "unavailable"
            } else {
                "agrees"
            };
            assert_eq!(r["crosscheck"], want, "{name}: {r}");
        }
        assert_eq!(stats["case"]["verification"]["crosscheck_disagreed"], 0);
    }
}

#[cfg(unix)]
#[test]
fn a_tool_that_disagrees_is_a_high_finding() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let Some(vs) = variants(tmp.path()) else {
        return;
    };
    // A "tool" whose verify-log always says intact, on a case whose rv-pdfauth log was edited.
    let fake = tmp.path().join("rv-pdfauth");
    std::fs::write(&fake, "#!/bin/sh\necho \"OK  chain intact\"\nexit 0\n").unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let extra: Vec<std::ffi::OsString> = vec![
        "--crosscheck".into(),
        "auto".into(),
        "--tool-exe".into(),
        format!("rv-pdfauth={}", fake.display()).into(),
    ];
    let (code, stats) = verify_variant(&vs["run_audit_entry_edited"], &[], &extra);
    assert_eq!(code, 3);
    let c = codes(&stats);
    assert_eq!(c.get("TOOL_VERIFY_DISAGREES"), Some(&1), "{c:?}");
    // The other three tools are not installed here: their cross-check is reported as not done.
    assert_eq!(c.get("CROSSCHECK_UNAVAILABLE"), Some(&3), "{c:?}");
    assert_eq!(stats["case"]["verification"]["crosscheck_disagreed"], 1);
}

#[test]
fn jsonl_progress_is_one_event_per_line_with_elapsed_time() {
    let tmp = tempfile::tempdir().unwrap();
    let case = sample_copy(tmp.path());
    let o = bin()
        .args([
            "verify",
            "--crosscheck",
            "off",
            "--rehash",
            "--progress",
            "jsonl",
            "--case-dir",
        ])
        .arg(&case)
        .arg("--evidence-dir")
        .arg(sample_evidence())
        .output()
        .unwrap();
    let text = String::from_utf8(o.stdout).unwrap();
    let events: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).expect("valid JSON line"))
        .collect();
    assert_eq!(events.first().unwrap()["event"], "run_started");
    assert_eq!(events.last().unwrap()["event"], "run_finished");
    let elapsed: Vec<u64> = events
        .iter()
        .filter(|e| e["event"] == "progress")
        .map(|e| e["elapsed_ms"].as_u64().unwrap())
        .collect();
    assert!(
        !elapsed.is_empty() && elapsed.windows(2).all(|w| w[0] <= w[1]),
        "elapsed_ms must be monotonic"
    );
}

/// examples/sample/run.sh compares the hub's hash register with expected_hashes.csv and fails on a difference.
#[test]
#[cfg(unix)]
fn sample_script_compares_the_hash_register() {
    let script = root().join("examples/sample/run.sh");
    let exe = env!("CARGO_BIN_EXE_rv-hub");
    let out = tempfile::tempdir().unwrap();
    let o = std::process::Command::new("sh")
        .arg(&script)
        .arg(exe)
        .env("RV_NO_TIMESTAMP", "1")
        .env("RV_SAMPLE_OUT", out.path())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(
        o.status.success(),
        "{}{}",
        text,
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(
        text.contains("hashes.csv matches expected_hashes.csv (5 files"),
        "{}",
        text
    );
}

#[test]
fn timestamp_of_a_missing_log_exits_3() {
    let d = tempfile::tempdir().unwrap();
    bin()
        .arg("timestamp")
        .arg(d.path())
        .assert()
        .code(3)
        .stderr(predicate::str::contains("no audit log at"));
}

#[test]
fn self_test_passes() {
    bin()
        .arg("self-test")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("FAIL").not());
}

#[test]
fn usage_doc_matches_help() {
    let generated = bin().arg("docs-cli").output().unwrap().stdout;
    let doc = root().join("docs/usage-cli.md");
    let committed = std::fs::read(&doc).unwrap_or_default();
    assert!(
        committed == generated,
        "docs/usage-cli.md is out of date: run `cargo run -p rv-hub-cli -- docs-cli > docs/usage-cli.md`"
    );
}

#[test]
fn trust_timestamp_and_signed_reports_with_test_pki() {
    let pki = tempfile::tempdir().unwrap();
    let Some((tsa, url)) = test_pki(pki.path()) else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let case = sample_copy(tmp.path());
    bin()
        .env_remove("RV_NO_TIMESTAMP")
        .env("NO_PROXY", "127.0.0.1")
        .env("RV_SIGN_PASSWORD", "test")
        .args([
            "verify",
            "--crosscheck",
            "off",
            "--progress",
            "none",
            "--tsa-url",
            &url,
            "--case-dir",
        ])
        .arg(&case)
        .arg("--sign-cert")
        .arg(pki.path().join("examiner.p12"))
        .assert()
        .code(0)
        .stdout(predicate::str::contains("timestamp: ok"));
    let run = only_dir(&case.join("runs/rv-hub"));
    let logs = run.join("logs");
    bin()
        .arg("verify-log")
        .arg(&logs)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("covers entry"));
    // The case jurisdiction (co) decides the custody form: Spanish + English.
    let item = run
        .join("reports/items")
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    for f in ["custody.json", "custody.es.pdf", "custody.en.pdf"] {
        assert!(item.join(f).is_file(), "{}", f);
    }
    let py = python();
    let v = std::process::Command::new(&py)
        .arg(root().join("tests/validate_pdf_signature.py"))
        .arg(run.join("reports"))
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&v.stdout);
    assert!(v.status.success(), "pyHanko validation failed:\n{}", report);
    for l in report
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
    {
        assert_eq!(
            (&l["intact"], &l["valid"]),
            (&true.into(), &true.into()),
            "{}",
            l
        );
    }
    // A second verification sees the timestamp of the first and checks its token.
    verify(&case).args(["--crosscheck", "off"]).assert().code(0);
    let tsr = std::fs::read_dir(&logs)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "tsr"))
        .unwrap();
    let mut b = std::fs::read(&tsr).unwrap();
    let last = b.len() - 1;
    b[last] ^= 0xff;
    std::fs::write(&tsr, b).unwrap();
    verify(&case)
        .args(["--crosscheck", "off"])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("RUN_LOG_BROKEN"));
    drop(tsa);
}

/// Cross-profile check without the other repository: a case folder written by the other profile
/// (tests/golden/case-by-<profile>.zip.b64, made by tests/golden/regenerate.py) verifies here, and tampering with it is
/// still detected. Unpacked with tests/golden/unpack.py (RV_TEST_PYTHON), like the other Python-based oracles.
#[test]
fn golden_case_from_the_other_profile_verifies() {
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden");
    let mut archives: Vec<PathBuf> = std::fs::read_dir(&golden)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.path())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    archives.retain(|p| p.to_string_lossy().ends_with(".zip.b64"));
    archives.sort();
    let py = std::env::var("RV_TEST_PYTHON").unwrap_or_else(|_| "python3".into());
    for archive in archives {
        let tmp = tempfile::tempdir().unwrap();
        let unzip = std::process::Command::new(&py)
            .arg(golden.join("unpack.py"))
            .arg(&archive)
            .arg(tmp.path())
            .status();
        if !unzip.is_ok_and(|s| s.success()) {
            eprintln!(
                "skipping golden case test: {} cannot unpack {}",
                py,
                archive.display()
            );
            return;
        }
        let case = tmp.path().join("CASE-GOLDEN");
        bin()
            .arg("verify-case")
            .arg(&case)
            .assert()
            .code(0)
            .stdout(predicate::str::contains(
                "3 registered items, 1 runs verified",
            ));
        let logs = only_dir(&only_dir(&case.join("runs"))).join("logs");
        bin()
            .arg("verify-log")
            .arg(&logs)
            .assert()
            .code(0)
            .stdout(
                predicate::str::contains("covers entry #").and(
                    predicate::str::is_match(
                        r"truncation: the final entry #\d+ is anchored by the case log \(run_finished\)",
                    )
                    .unwrap(),
                ),
            );
        let audit = logs.join("audit.jsonl");
        let full = std::fs::read(&audit).unwrap();
        let cut = full[..full.len() - 1]
            .iter()
            .rposition(|&b| b == b'\n')
            .unwrap()
            + 1;
        std::fs::write(&audit, &full[..cut]).unwrap();
        bin()
            .arg("verify-log")
            .arg(&logs)
            .assert()
            .code(3)
            .stdout(predicate::str::contains("truncated: the case log records"));
        bin().arg("verify-case").arg(&case).assert().code(3);
        std::fs::write(&audit, &full).unwrap();
        let reg = case.join("evidence/registry.json");
        let text = std::fs::read_to_string(&reg).unwrap();
        std::fs::write(&reg, text.replacen("\"size\": ", "\"size\": 1", 1)).unwrap();
        bin()
            .arg("verify-case")
            .arg(&case)
            .assert()
            .code(3)
            .stdout(predicate::str::contains("registry.json"));
    }
}

/// CI and release build with the toolchain pinned in rust-toolchain.toml (never a floating `stable`).
#[test]
fn workflows_use_the_pinned_toolchain() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pin = std::fs::read_to_string(root.join("rust-toolchain.toml")).unwrap();
    let channel = pin
        .lines()
        .find_map(|l| l.trim().strip_prefix("channel = "))
        .unwrap()
        .trim_matches('"');
    assert!(
        channel.split('.').count() == 3 && channel.split('.').all(|p| p.parse::<u32>().is_ok()),
        "rust-toolchain.toml must pin an exact x.y.z version, not {}",
        channel
    );
    for wf in ["ci.yml", "release.yml"] {
        let text = std::fs::read_to_string(root.join(".github/workflows").join(wf)).unwrap();
        assert!(!text.contains("rust-toolchain@stable"), "{}", wf);
        assert!(text.contains("rustup toolchain install"), "{}", wf);
    }
}
