//! `describe --json`: RV Hub describes itself with the same schema as the tools (rakvor.describe/1). Same test
//! as in every Rakvor tool; only the constants differ. The schema's role enum has no `hub`: the hub is an
//! analysis tool in the case log.

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

const TOOL: &str = "rv-hub";
const TITLE: &str = "RV Hub";
const ROLE: &str = "analysis";
const MAIN_VERB: &str = "verify";
const LOG_FORMATS: &[&str] = &["rakvor.audit/1"];

fn root() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

fn describe_text() -> String {
    let out = Command::cargo_bin(TOOL)
        .unwrap()
        .args(["describe", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{:?}", out);
    assert!(out.stderr.is_empty());
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn describe_prints_the_hub_contract() {
    let text = describe_text();
    let v: Value = serde_json::from_str(&text).unwrap();
    assert!(text.starts_with("{\n  \"") && text.ends_with("}\n"));
    let top: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("  \"").and_then(|l| l.split('"').next()))
        .collect();
    let mut sorted = top.clone();
    sorted.sort();
    assert_eq!(top, sorted, "top-level keys are sorted");
    assert_eq!(v["schema"], "rakvor.describe/1");
    assert_eq!(v["tool"], TOOL);
    assert_eq!(v["title"], TITLE);
    let version = std::fs::read_to_string(root().join("version.txt")).unwrap();
    assert_eq!(v["version"], version.trim());
    assert_eq!(v["role"], ROLE);
    assert_eq!(v["role"], rv_hub_core::CASE_ROLE.name());
    assert_eq!(v["main_verb"], MAIN_VERB);
    assert_eq!(v["case_formats"], serde_json::json!(["rakvor.case/1"]));
    assert_eq!(v["log_formats"], serde_json::json!(LOG_FORMATS));
    assert_eq!(v["cli_exe"], format!("{}.exe", TOOL));
    assert_eq!(v["gui_exe"], format!("{}-gui.exe", TOOL));
    Command::cargo_bin(TOOL)
        .unwrap()
        .args([MAIN_VERB, "--help"])
        .assert()
        .code(0);
    let codes: Vec<&String> = v["exit_codes"].as_object().unwrap().keys().collect();
    assert_eq!(codes, ["0", "1", "130", "2", "3"]);
    // The core's own describe parser (what the hub applies to the tools) accepts it too.
    assert!(rv_hub_core::tools::parse_describe(text.as_bytes()).is_ok());
}

#[test]
fn describe_is_hidden_from_the_command_list_but_documented() {
    let out = Command::cargo_bin(TOOL)
        .unwrap()
        .arg("--help")
        .output()
        .unwrap();
    let help = String::from_utf8(out.stdout).unwrap();
    assert!(
        !help.contains("describe") && !help.contains("docs-cli"),
        "{help}"
    );
    let cli_doc = std::fs::read_to_string(root().join("docs/usage-cli.md")).unwrap();
    assert!(cli_doc.contains(&format!("## {} describe", TOOL)));
    let usage = std::fs::read_to_string(root().join("docs/usage.md")).unwrap();
    assert!(usage.contains("describe --json") && usage.contains("--case-dir"));
}

/// Validated against schemas/describe.schema.json (the same file as in every tool repository) with Python's
/// jsonschema; mandatory when RV_TEST_PYTHON is set (CI).
#[test]
fn describe_output_matches_the_schema() {
    let text = describe_text();
    let schema_path = root().join("schemas/describe.schema.json");
    let schema: Value = serde_json::from_slice(&std::fs::read(&schema_path).unwrap()).unwrap();
    // The role enum: `hub` is not a role, so the hub says `analysis`.
    let roles = &schema["properties"]["role"]["enum"];
    assert!(!roles.as_array().unwrap().contains(&"hub".into()));
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap())
        .collect();
    let v: Value = serde_json::from_str(&text).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    let mut want = required.clone();
    keys.sort();
    want.sort();
    assert_eq!(keys, want);

    let explicit = std::env::var("RV_TEST_PYTHON").ok();
    let py = explicit.clone().unwrap_or_else(|| "python3".into());
    let has = std::process::Command::new(&py)
        .args(["-c", "import jsonschema"])
        .status()
        .is_ok_and(|s| s.success());
    if !has {
        assert!(explicit.is_none(), "RV_TEST_PYTHON={py} has no jsonschema");
        eprintln!("skipped: no Python with jsonschema");
        return;
    }
    let check = |doc: &str| {
        let mut child = std::process::Command::new(&py)
            .args([
                "-c",
                "import json,sys,jsonschema\n\
                 s=json.load(open(sys.argv[1],encoding='utf-8'))\n\
                 jsonschema.Draft202012Validator.check_schema(s)\n\
                 try:\n  jsonschema.Draft202012Validator(s).validate(json.load(sys.stdin))\n\
                 except jsonschema.ValidationError as e:\n  print(e.message); sys.exit(1)",
            ])
            .arg(&schema_path)
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
        (
            o.status.success(),
            String::from_utf8_lossy(&o.stdout).to_string(),
        )
    };
    let (ok, msg) = check(&text);
    assert!(ok, "describe output does not match the schema: {msg}");
    let mut bad = v.clone();
    bad["role"] = "hub".into();
    assert!(!check(&bad.to_string()).0, "the schema forbids role hub");
    let mut bad = v;
    bad["extra"] = 1.into();
    assert!(!check(&bad.to_string()).0);
}
