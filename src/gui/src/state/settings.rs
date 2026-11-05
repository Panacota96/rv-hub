//! The hub's settings: portable tool folders the user added, recent cases and the interface language.
//!
//! Saved as `settings.json` in the hub data folder (`rv_hub_core::session::data_dir`). When that folder cannot be
//! written (read-only profile, locked-down VM), the next candidate is tried (a folder in the temp directory);
//! when none can be written, the settings stay in memory for this session and the window says so. Loading takes
//! the first candidate that holds a readable file, so a fallback copy is found again on the next start.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const SETTINGS_FILE: &str = "settings.json";
pub const SETTINGS_SCHEMA: &str = "rakvor.hub-settings/1";
/// How many recent cases are remembered.
pub const MAX_RECENT: usize = 8;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default = "schema")]
    pub schema: String,
    /// Folders scanned for portable tools (e.g. unzipped releases on a USB stick).
    #[serde(default)]
    pub user_folders: Vec<PathBuf>,
    /// Most recent first.
    #[serde(default)]
    pub recent_cases: Vec<PathBuf>,
    /// "en" | "es" | "fr"
    #[serde(default)]
    pub ui_lang: Option<String>,
}

fn schema() -> String {
    SETTINGS_SCHEMA.into()
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            schema: schema(),
            user_folders: vec![],
            recent_cases: vec![],
            ui_lang: None,
        }
    }
}

/// Where settings (and the session log) go, in order: the hub data folder, then a temp-directory fallback.
pub fn default_dirs() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = rv_hub_core::session::data_dir().into_iter().collect();
    let fallback = std::env::temp_dir().join("rakvor-rv-hub");
    if !v.contains(&fallback) {
        v.push(fallback);
    }
    v
}

impl Settings {
    /// The first readable settings file among `dirs` (and where it was), else defaults. A file that is not valid
    /// JSON is reported and skipped.
    pub fn load(dirs: &[PathBuf]) -> (Settings, Option<PathBuf>, Vec<String>) {
        let mut problems = vec![];
        for d in dirs {
            let p = d.join(SETTINGS_FILE);
            let Ok(text) = std::fs::read_to_string(&p) else {
                continue;
            };
            match serde_json::from_str::<Settings>(&text) {
                Ok(mut s) => {
                    s.normalise();
                    return (s, Some(p), problems);
                }
                Err(e) => problems.push(format!("{}: {}", p.display(), e)),
            }
        }
        (Settings::default(), None, problems)
    }

    /// Writes to the first of `dirs` that accepts it (temporary file, then rename). Returns the file written.
    pub fn save(&self, dirs: &[PathBuf]) -> Result<PathBuf, String> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        let mut errors = vec![];
        for d in dirs {
            match write_atomic(d, &bytes) {
                Ok(p) => return Ok(p),
                Err(e) => errors.push(format!("{}: {}", d.display(), e)),
            }
        }
        if errors.is_empty() {
            errors.push("no settings folder".into());
        }
        Err(errors.join("; "))
    }

    /// Adds a case to the front of the recent list (no duplicates, at most [`MAX_RECENT`]).
    pub fn add_recent(&mut self, case: &Path) {
        let case = case.to_path_buf();
        self.recent_cases.retain(|c| *c != case);
        self.recent_cases.insert(0, case);
        self.recent_cases.truncate(MAX_RECENT);
    }

    /// False when the folder is already listed.
    pub fn add_folder(&mut self, folder: &Path) -> bool {
        if self.user_folders.iter().any(|f| f == folder) {
            return false;
        }
        self.user_folders.push(folder.to_path_buf());
        true
    }

    fn normalise(&mut self) {
        self.schema = schema();
        if let Some(l) = &self.ui_lang {
            if !rv_hub_core::i18n::LANGS.contains(&l.as_str()) {
                self.ui_lang = None;
            }
        }
        let mut seen = vec![];
        self.recent_cases.retain(|c| {
            let new = !seen.contains(c);
            seen.push(c.clone());
            new
        });
        self.recent_cases.truncate(MAX_RECENT);
    }
}

fn write_atomic(dir: &Path, bytes: &[u8]) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let target = dir.join(SETTINGS_FILE);
    let tmp = dir.join(format!("{SETTINGS_FILE}.{}.tmp", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    match std::fs::rename(&tmp, &target) {
        Ok(()) => Ok(target),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip_and_fallback() {
        let d = tempfile::tempdir().unwrap();
        let (primary, fallback) = (d.path().join("data"), d.path().join("fallback"));
        let dirs = vec![primary.clone(), fallback.clone()];
        let (s, from, problems) = Settings::load(&dirs);
        assert_eq!(s, Settings::default());
        assert!(from.is_none() && problems.is_empty());

        let mut s = Settings::default();
        assert!(s.add_folder(Path::new("E:\\rakvor-portable")));
        assert!(!s.add_folder(Path::new("E:\\rakvor-portable")), "no duplicate");
        for i in 0..10 {
            s.add_recent(Path::new(&format!("C:\\cases\\{i}")));
        }
        s.add_recent(Path::new("C:\\cases\\3"));
        assert_eq!(s.recent_cases.len(), MAX_RECENT);
        assert_eq!(s.recent_cases[0], PathBuf::from("C:\\cases\\3"));
        s.ui_lang = Some("es".into());
        assert_eq!(s.save(&dirs).unwrap(), primary.join(SETTINGS_FILE));
        let (back, from, _) = Settings::load(&dirs);
        assert_eq!(back, s);
        assert_eq!(from, Some(primary.join(SETTINGS_FILE)));

        // Primary unwritable (a file where the folder should be): the fallback is used, and found again.
        let blocked = d.path().join("blocked");
        std::fs::write(&blocked, b"not a folder").unwrap();
        let dirs = vec![blocked.clone(), fallback.clone()];
        assert_eq!(s.save(&dirs).unwrap(), fallback.join(SETTINGS_FILE));
        assert_eq!(Settings::load(&dirs).0, s);
        // Nothing writable: an error, never a panic.
        assert!(s.save(std::slice::from_ref(&blocked)).is_err());
        assert!(Settings::default().save(&[]).is_err());
    }

    #[test]
    fn a_damaged_settings_file_is_reported_and_skipped() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(SETTINGS_FILE), b"{not json").unwrap();
        let (s, from, problems) = Settings::load(&[d.path().to_path_buf()]);
        assert_eq!(s, Settings::default());
        assert!(from.is_none());
        assert_eq!(problems.len(), 1);
        std::fs::write(
            d.path().join(SETTINGS_FILE),
            br#"{"ui_lang":"de","recent_cases":["a","a","b"]}"#,
        )
        .unwrap();
        let (s, _, _) = Settings::load(&[d.path().to_path_buf()]);
        assert_eq!(s.ui_lang, None, "unknown language dropped");
        assert_eq!(s.recent_cases, vec![PathBuf::from("a"), PathBuf::from("b")]);
        assert!(s.user_folders.is_empty());
    }
}
