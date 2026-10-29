//! Launching a tool's GUI on a case folder: `<gui_exe> --case-dir CASE`, detached, audited in the hub's
//! session log (`tool_launched`: tool, version, exe SHA-256, signature status, case, pid).
//!
//! Rules: the executable must exist; it is hashed and its signature checked again at launch (it may have been
//! replaced since discovery); anything other than `SignedRakvor` needs `confirm_untrusted = true`, and that
//! confirmation is itself audited (`tool_untrusted_confirmed`) before the process starts.

use crate::session::Session;
use crate::signature::{OsVerifier, SignatureStatus, SignatureVerifier};
use crate::tools::{ToolInfo, ToolRole};
use serde_json::json;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// A started tool.
#[derive(Clone, Debug, PartialEq)]
pub struct Launched {
    pub tool: String,
    pub version: Option<String>,
    pub exe: PathBuf,
    pub exe_sha256: String,
    pub signature: SignatureStatus,
    pub case_dir: PathBuf,
    pub pid: u32,
    /// Sequence number of `tool_launched` in the session log.
    pub audit_seq: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum LaunchError {
    /// The tool has no GUI executable, or it is not there any more.
    MissingExe(String),
    /// Not Rakvor-signed: call again with `confirm_untrusted = true` after asking the user.
    NeedsConfirmation(SignatureStatus),
    /// The executable differs from the one inventoried (hash changed): discover again.
    Changed {
        expected: String,
        actual: String,
    },
    /// The case folder is not usable for this tool.
    NotACase(String),
    Spawn(String),
    Audit(String),
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LaunchError::MissingExe(s) => write!(f, "{s}"),
            LaunchError::NeedsConfirmation(s) => write!(
                f,
                "the executable is not Rakvor-signed ({}): confirm to launch it anyway",
                s.key()
            ),
            LaunchError::Changed { expected, actual } => write!(
                f,
                "the executable changed since it was inventoried (SHA-256 {expected} → {actual}): refresh the tool list"
            ),
            LaunchError::NotACase(s) | LaunchError::Spawn(s) | LaunchError::Audit(s) => {
                write!(f, "{s}")
            }
        }
    }
}

/// Starts a process without waiting for it. Returns its pid.
pub trait Spawner {
    fn spawn_detached(&self, exe: &Path, args: &[OsString]) -> std::io::Result<u32>;
}

/// The real spawner: no console, own process group, stdio closed; the hub never waits for the tool.
#[derive(Clone, Copy, Debug, Default)]
pub struct DetachedSpawner;

impl Spawner for DetachedSpawner {
    fn spawn_detached(&self, exe: &Path, args: &[OsString]) -> std::io::Result<u32> {
        let mut c = Command::new(exe);
        c.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(dir) = exe.parent() {
            c.current_dir(dir);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const DETACHED_PROCESS: u32 = 0x0000_0008;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
            c.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            c.process_group(0);
        }
        let mut child = c.spawn()?;
        let pid = child.id();
        // Reap it when it exits (no zombie on Unix); the hub never blocks on it.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(pid)
    }
}

/// `launch_with` with the operating system's signature check and the detached spawner.
pub fn launch(
    session: &mut Session,
    tool: &ToolInfo,
    case_dir: &Path,
    confirm_untrusted: bool,
) -> Result<Launched, LaunchError> {
    launch_with(
        session,
        tool,
        case_dir,
        confirm_untrusted,
        &OsVerifier,
        &DetachedSpawner,
    )
}

pub fn launch_with(
    session: &mut Session,
    tool: &ToolInfo,
    case_dir: &Path,
    confirm_untrusted: bool,
    verifier: &dyn SignatureVerifier,
    spawner: &dyn Spawner,
) -> Result<Launched, LaunchError> {
    let audit = |e: String| LaunchError::Audit(e);
    let Some(exe) = tool.gui_exe.clone() else {
        return Err(LaunchError::MissingExe(format!(
            "{} has no GUI executable",
            tool.tool
        )));
    };
    if !exe.is_file() {
        return Err(LaunchError::MissingExe(format!(
            "{} is missing: {}",
            tool.tool,
            exe.display()
        )));
    }
    let case_dir = crate::case::normalize(case_dir);
    if case_dir.is_file() {
        return Err(LaunchError::NotACase(format!(
            "{} is a file, not a folder",
            case_dir.display()
        )));
    }
    let has_case = case_dir.join(crate::case::CASE_FILE).is_file();
    // Only the intake tool creates a case (case.json); the hub never does.
    if !has_case && tool.describe.role != ToolRole::Intake {
        return Err(LaunchError::NotACase(format!(
            "{} is not a case folder yet (no case.json): open it with the intake tool first",
            case_dir.display()
        )));
    }
    let actual = crate::tools::sha256_of(&exe)
        .ok_or_else(|| LaunchError::MissingExe(format!("cannot read {}", exe.display())))?;
    if let Some(expected) = &tool.gui_sha256 {
        if !expected.eq_ignore_ascii_case(&actual) {
            return Err(LaunchError::Changed {
                expected: expected.clone(),
                actual,
            });
        }
    }
    let signature = verifier.verify(&exe);
    let details = |extra: serde_json::Value| {
        let mut v = json!({"tool": tool.tool, "version": tool.version, "exe": exe.display().to_string(),
                           "exe_sha256": actual, "signature": signature, "case_dir": case_dir.display().to_string()});
        if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
            o.extend(e.clone());
        }
        v
    };
    if !signature.is_rakvor() {
        if !confirm_untrusted {
            return Err(LaunchError::NeedsConfirmation(signature));
        }
        session
            .record(
                "tool_untrusted_confirmed",
                details(json!({"actor": session.actor})),
            )
            .map_err(audit)?;
    }
    let args: Vec<OsString> = vec!["--case-dir".into(), case_dir.clone().into_os_string()];
    let pid = match spawner.spawn_detached(&exe, &args) {
        Ok(p) => p,
        Err(e) => {
            session
                .record(
                    "tool_launch_failed",
                    details(json!({"error": e.to_string()})),
                )
                .map_err(audit)?;
            return Err(LaunchError::Spawn(format!(
                "cannot start {}: {}",
                exe.display(),
                e
            )));
        }
    };
    let audit_seq = session
        .record(
            "tool_launched",
            details(
                json!({"pid": pid, "args": ["--case-dir", case_dir.display().to_string()],
                           "confirmed_untrusted": !signature.is_rakvor()}),
            ),
        )
        .map_err(audit)?;
    Ok(Launched {
        tool: tool.tool.clone(),
        version: tool.version.clone(),
        exe,
        exe_sha256: actual,
        signature,
        case_dir,
        pid,
        audit_seq,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::StaticVerifier;
    use crate::tools::{DescribeSource, builtin};
    use std::cell::RefCell;

    #[derive(Default)]
    struct Recorder(RefCell<Vec<(PathBuf, Vec<OsString>)>>);
    impl Spawner for Recorder {
        fn spawn_detached(&self, exe: &Path, args: &[OsString]) -> std::io::Result<u32> {
            self.0.borrow_mut().push((exe.to_path_buf(), args.to_vec()));
            Ok(4242)
        }
    }

    fn tool(dir: &Path, name: &str) -> ToolInfo {
        let gui = dir.join(format!("{name}-gui"));
        std::fs::write(&gui, b"gui binary").unwrap();
        ToolInfo {
            tool: name.into(),
            title: "T".into(),
            dir: dir.into(),
            cli_exe: None,
            gui_exe: Some(gui.clone()),
            cli_sha256: None,
            gui_sha256: crate::tools::sha256_of(&gui),
            sources: vec![],
            version: Some("1.2.3".into()),
            describe: builtin(name).unwrap(),
            describe_source: DescribeSource::Builtin,
            describe_problem: None,
            cli_signature: SignatureStatus::Unsigned,
            gui_signature: SignatureStatus::Unsigned,
            warnings: vec![],
        }
    }

    fn entries(s: &Session) -> Vec<serde_json::Value> {
        std::fs::read_to_string(s.audit_path())
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn launch_rules_and_audit() {
        let d = tempfile::tempdir().unwrap();
        let case = d.path().join("case");
        std::fs::create_dir_all(&case).unwrap();
        let mut s = Session::start(&d.path().join("hub"), "Ana", "test", &[]).unwrap();
        let t = tool(d.path(), "rv-pdfauth");
        let rec = Recorder::default();
        let rakvor = StaticVerifier::always(SignatureStatus::SignedRakvor);
        let unsigned = StaticVerifier::always(SignatureStatus::Unsigned);

        // Analysis tool on a folder without case.json: refused.
        assert!(matches!(
            launch_with(&mut s, &t, &case, false, &rakvor, &rec),
            Err(LaunchError::NotACase(_))
        ));
        std::fs::write(case.join("case.json"), "{}").unwrap();
        // Unsigned: confirmation needed, nothing started, nothing logged.
        assert_eq!(
            launch_with(&mut s, &t, &case, false, &unsigned, &rec),
            Err(LaunchError::NeedsConfirmation(SignatureStatus::Unsigned))
        );
        assert!(rec.0.borrow().is_empty());
        // Confirmed: audited, then launched with --case-dir.
        let l = launch_with(&mut s, &t, &case, true, &unsigned, &rec).unwrap();
        assert_eq!(l.pid, 4242);
        let (exe, args) = rec.0.borrow()[0].clone();
        assert_eq!(exe, t.gui_exe.clone().unwrap());
        assert_eq!(
            args,
            vec![
                OsString::from("--case-dir"),
                crate::case::normalize(&case).into_os_string()
            ]
        );
        let e = entries(&s);
        let actions: Vec<&str> = e.iter().map(|x| x["action"].as_str().unwrap()).collect();
        assert_eq!(&actions[2..], ["tool_untrusted_confirmed", "tool_launched"]);
        let last = &e[3]["details"];
        assert_eq!(last["tool"], "rv-pdfauth");
        assert_eq!(last["version"], "1.2.3");
        assert_eq!(last["pid"], 4242);
        assert_eq!(last["signature"]["status"], "unsigned");
        assert_eq!(last["exe_sha256"].as_str(), t.gui_sha256.as_deref());
        assert_eq!(last["confirmed_untrusted"], true);
        assert_eq!(l.audit_seq, 4);
        // Rakvor-signed: no confirmation entry.
        launch_with(&mut s, &t, &case, false, &rakvor, &rec).unwrap();
        assert_eq!(
            entries(&s).last().unwrap()["details"]["confirmed_untrusted"],
            false
        );
        assert_eq!(crate::audit::verify(&s.audit_path()), Ok(5));

        // Replaced executable: refused. Missing executable: refused.
        std::fs::write(t.gui_exe.as_ref().unwrap(), b"other binary").unwrap();
        assert!(matches!(
            launch_with(&mut s, &t, &case, true, &rakvor, &rec),
            Err(LaunchError::Changed { .. })
        ));
        std::fs::remove_file(t.gui_exe.as_ref().unwrap()).unwrap();
        assert!(matches!(
            launch_with(&mut s, &t, &case, true, &rakvor, &rec),
            Err(LaunchError::MissingExe(_))
        ));

        // The intake tool may open a folder that is not a case yet (it creates case.json).
        let h = tool(d.path(), "rv-hashinv");
        let new_case = d.path().join("new-case");
        assert!(launch_with(&mut s, &h, &new_case, false, &rakvor, &rec).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn detached_spawner_starts_a_real_process() {
        let d = tempfile::tempdir().unwrap();
        let marker = d.path().join("ran");
        let script = d.path().join("gui.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\necho \"$@\" > '{}'\n", marker.display()),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let pid = DetachedSpawner
            .spawn_detached(&script, &["--case-dir".into(), "/x".into()])
            .unwrap();
        assert!(pid > 0);
        for _ in 0..200 {
            if std::fs::read_to_string(&marker).is_ok_and(|s| s.contains("--case-dir /x")) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("the detached process did not run");
    }
}
