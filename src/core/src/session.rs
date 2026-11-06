//! The hub's own audit log: one hash-chained "session" log per hub process (same chain rule as every run's
//! audit.jsonl), in the hub's data folder. It records what the hub did outside a case run: tools launched,
//! untrusted tools confirmed, folders added. Case folders are never written here.
//!
//! ```text
//! Windows: %LOCALAPPDATA%\Rakvor\RV Hub\logs\<SESSION-ID>\audit.jsonl|audit.log|environment.json
//! Linux:   $XDG_DATA_HOME/rakvor/rv-hub/logs/<SESSION-ID>/…   (default ~/.local/share)
//! Override: RV_HUB_DATA_DIR=<dir>  (tests, portable use)
//! ```

use crate::audit::AuditLog;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub const DATA_DIR_ENV: &str = "RV_HUB_DATA_DIR";

/// The hub's data folder (see the module documentation). None when no home folder is known.
pub fn data_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os(DATA_DIR_ENV).filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(d));
    }
    if cfg!(windows) {
        return std::env::var_os("LOCALAPPDATA")
            .map(|d| PathBuf::from(d).join("Rakvor").join("RV Hub"));
    }
    std::env::var_os("XDG_DATA_HOME")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share")))
        .map(|d| d.join("rakvor").join("rv-hub"))
}

/// A hub session: its audit log is created on start and appended to by every audited action.
pub struct Session {
    pub id: String,
    pub dir: PathBuf,
    pub actor: String,
    log: AuditLog,
}

impl Session {
    /// Starts a session under `<data_dir>/logs/<SESSION-ID>/` (records `session_started` and the environment).
    pub fn start(
        data_dir: &Path,
        actor: &str,
        frontend: &str,
        command_line: &[String],
    ) -> Result<Session, String> {
        let id = crate::run::new_run_id();
        let dir = data_dir.join("logs").join(&id);
        let mut log = AuditLog::create(&dir, &id, actor).map_err(|e| {
            format!(
                "cannot create the hub session log in {}: {}",
                dir.display(),
                e
            )
        })?;
        let env = crate::env::describe(
            crate::TOOL_NAME,
            crate::TOOL_VERSION,
            frontend,
            command_line,
        );
        let bytes = crate::report::pretty(&env);
        let (_, digest) = crate::report::write_hashed(
            &dir,
            "environment.json",
            &bytes,
            &[crate::HashAlgo::Sha256],
        )?;
        let io = |e: std::io::Error| format!("session log write failed: {e}");
        log.record(
            "session_started",
            None,
            json!({"tool": crate::TOOL_NAME, "version": crate::TOOL_VERSION, "frontend": frontend}),
        )
        .map_err(io)?;
        log.record("environment_recorded", Some("environment.json"), digest)
            .map_err(io)?;
        Ok(Session {
            id,
            dir,
            actor: actor.to_string(),
            log,
        })
    }

    /// Starts a session in [`data_dir`].
    pub fn start_default(
        actor: &str,
        frontend: &str,
        command_line: &[String],
    ) -> Result<Session, String> {
        let d = data_dir().ok_or("no data folder for the hub (set RV_HUB_DATA_DIR)")?;
        Session::start(&d, actor, frontend, command_line)
    }

    /// Appends one audited action; returns its sequence number.
    pub fn record(&mut self, action: &str, details: Value) -> Result<u64, String> {
        self.log
            .record(action, None, details)
            .map_err(|e| format!("session log write failed: {e}"))
    }

    pub fn entries(&self) -> u64 {
        self.log.entries()
    }

    pub fn audit_path(&self) -> PathBuf {
        self.dir.join("audit.jsonl")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_log_is_a_verifiable_chain() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Session::start(d.path(), "tester", "test", &["rv-hub".into()]).unwrap();
        assert_eq!(
            s.record("ui_folder_added", json!({"folder": "E:\\tools"}))
                .unwrap(),
            3
        );
        assert!(s.dir.starts_with(d.path().join("logs")));
        assert_eq!(crate::audit::verify(&s.audit_path()), Ok(3));
        assert!(s.dir.join("environment.json").is_file());
    }
}
