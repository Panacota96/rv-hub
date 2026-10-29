//! Everything the window shows and every rule it enforces, without any drawing code.
//! Kept separate from `app.rs` so it can be unit-tested headless (CI has no display).
//!
//! Core-engineer stage: the window offers the main verb (whole-case verification) only; the GUI stage adds the
//! Tools and Case tabs on top of `rv_hub_core::{tools, case_view, suggest, launch}`.

use rv_hub_core::{
    CrossCheckMode, Event, HashAlgo, RunConfig, TOOL_NAME, TOOL_VERSION, hash, i18n,
    time::human_duration,
};
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq)]
pub enum Phase {
    Idle,
    Running,
    Finished,
    Cancelled,
    Failed(String),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Progress {
    pub done: u64,
    pub total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub elapsed_ms: u64,
    pub eta_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Outcome {
    pub items: u64,
    pub errors: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub info: u64,
    pub report: PathBuf,
    pub log_dir: PathBuf,
}

pub const LANG_CHOICES: [(&str, &str); 4] = [
    ("en", "English"),
    ("es", "Español"),
    ("fr", "Français"),
    ("all", "All three (EN + ES + FR)"),
];

#[derive(Clone, Debug)]
pub struct GuiState {
    /// Also re-hash the registered evidence (`--rehash`).
    pub rehash: bool,
    /// Where the evidence copies are now (`--evidence-dir`), when not at their registered paths.
    pub evidence_dir: String,
    /// Ask each run's own tool to verify its logs (`--crosscheck auto`).
    pub crosscheck: bool,
    pub selected: Vec<HashAlgo>,
    pub lang: String,
    pub out_dir: String,
    pub actor: String,
    pub case_id: String,
    pub phase: Phase,
    pub progress: Progress,
    pub current_item: String,
    pub warnings: Vec<String>,
    pub outcome: Option<Outcome>,
    /// User actions recorded before the run; handed to the core as audit preamble entries.
    pub ui_actions: Vec<(String, Value)>,
    /// Interface language (en/es/fr), independent from the report language.
    pub ui_lang: String,
    pub jurisdiction: String,
    pub timestamp: bool,
    pub tsa_url: String,
    pub sign_cert: String,
    /// Kept in memory only; never logged.
    pub sign_password: String,
    /// The case folder to verify (required); the run is written to `<case>/runs/rv-hub/<RUN-ID>`.
    pub case_dir: String,
    /// Finding codes of the last finished verification.
    pub codes: Vec<String>,
}

impl Default for GuiState {
    fn default() -> Self {
        GuiState {
            rehash: false,
            evidence_dir: String::new(),
            crosscheck: true,
            selected: vec![HashAlgo::Sha256],
            lang: "en".into(),
            out_dir: "rakvor-out".into(),
            actor: rv_hub_core::env::os_user(),
            case_id: String::new(),
            phase: Phase::Idle,
            progress: Progress::default(),
            current_item: String::new(),
            warnings: vec![],
            outcome: None,
            ui_actions: vec![],
            ui_lang: "en".into(),
            jurisdiction: "co".into(),
            timestamp: true,
            tsa_url: rv_hub_core::trust::DEFAULT_TSA.into(),
            sign_cert: String::new(),
            sign_password: String::new(),
            case_dir: String::new(),
            codes: vec![],
        }
    }
}

impl GuiState {
    /// Records a user action with the time it happened (written to the audit log when the run starts).
    fn note(&mut self, action: &str, mut details: Value) {
        if let Some(o) = details.as_object_mut() {
            o.insert("at_utc".into(), json!(rv_hub_core::time::utc_now()));
        }
        self.ui_actions.push((action.to_string(), details));
    }

    pub fn is_running(&self) -> bool {
        self.phase == Phase::Running
    }

    /// A checkbox is clickable if it can be unticked (more than one ticked) or ticked (fewer than two ticked).
    pub fn can_toggle(&self, a: HashAlgo) -> bool {
        if self.selected.contains(&a) {
            self.selected.len() > 1
        } else {
            self.selected.len() < HashAlgo::MAX_SELECTED
        }
    }

    pub fn toggle_algo(&mut self, a: HashAlgo) -> Result<(), String> {
        if !self.can_toggle(a) {
            return Err(if self.selected.contains(&a) {
                "At least one hash algorithm is required.".into()
            } else {
                format!(
                    "At most {} hash algorithms can be selected.",
                    HashAlgo::MAX_SELECTED
                )
            });
        }
        if let Some(i) = self.selected.iter().position(|x| *x == a) {
            self.selected.remove(i);
        } else {
            self.selected.push(a);
        }
        self.note(
            "ui_hash_selection_changed",
            json!({"algorithms": self.selected}),
        );
        Ok(())
    }

    pub fn set_lang(&mut self, l: &str) {
        if self.lang != l {
            self.lang = l.to_string();
            self.note("ui_language_changed", json!({"lang": l}));
        }
    }

    pub fn set_rehash(&mut self, on: bool) {
        if self.rehash != on {
            self.rehash = on;
            self.note("ui_rehash_changed", json!({"rehash": on}));
        }
    }

    pub fn set_crosscheck(&mut self, on: bool) {
        if self.crosscheck != on {
            self.crosscheck = on;
            self.note(
                "ui_crosscheck_changed",
                json!({"crosscheck": if on { "auto" } else { "off" }}),
            );
        }
    }

    pub fn set_evidence_dir(&mut self, path: &str) {
        let path = path.trim().trim_matches('"').to_string();
        if self.evidence_dir != path {
            self.evidence_dir = path.clone();
            self.note(
                "ui_evidence_dir_changed",
                json!({"path": if path.is_empty() { Value::Null } else { json!(path) }}),
            );
        }
    }

    /// GUI text in the interface language.
    pub fn tr(&self, key: &str) -> String {
        i18n::catalog(&self.ui_lang).ui(key)
    }

    pub fn set_ui_lang(&mut self, l: &str) {
        if self.ui_lang != l && ["en", "es", "fr"].contains(&l) {
            self.ui_lang = l.to_string();
            self.note("ui_interface_language_changed", json!({"ui_lang": l}));
        }
    }

    pub fn set_jurisdiction(&mut self, j: &str) {
        if self.jurisdiction != j && (j == "co" || j == "fr") {
            self.jurisdiction = j.to_string();
            self.note("ui_jurisdiction_changed", json!({"jurisdiction": j}));
        }
    }

    pub fn set_timestamp(&mut self, on: bool, url: &str) {
        let url = url.trim().to_string();
        if self.timestamp != on || self.tsa_url != url {
            self.timestamp = on;
            self.tsa_url = url.clone();
            self.note(
                "ui_timestamp_changed",
                json!({"enabled": on, "tsa_url": url}),
            );
        }
    }

    pub fn set_sign_cert(&mut self, path: &str) {
        let path = path.trim().trim_matches('"').to_string();
        if self.sign_cert != path {
            self.sign_cert = path.clone();
            self.note(
                "ui_signing_certificate_changed",
                json!({"path": if path.is_empty() { Value::Null } else { json!(path) }}),
            );
        }
    }

    /// Rule: the run is always written to `<case>/runs/rv-hub/<RUN-ID>` (or to the output folder when the case log
    /// is broken and must not be extended).
    pub fn set_case_dir(&mut self, path: &str) {
        let path = path.trim().trim_matches('"').to_string();
        if self.case_dir != path {
            self.case_dir = path.clone();
            self.note(
                "ui_case_dir_changed",
                json!({"path": if path.is_empty() { Value::Null } else { json!(path) }}),
            );
        }
    }

    /// Where the run will be written.
    pub fn out_dir_display(&self) -> String {
        if self.case_dir.trim().is_empty() {
            "\u{2014}".into()
        } else {
            PathBuf::from(self.case_dir.trim())
                .join("runs")
                .join(TOOL_NAME)
                .join("<RUN-ID>")
                .display()
                .to_string()
        }
    }

    pub fn can_start(&self) -> bool {
        !self.is_running() && !self.case_dir.trim().is_empty()
    }

    /// Builds the run configuration; the recorded UI actions become audit preamble entries.
    pub fn to_config(&self) -> Result<RunConfig, String> {
        if self.case_dir.trim().is_empty() {
            return Err("Choose the case folder to verify.".into());
        }
        hash::validate_selection(&self.selected)?;
        let langs = i18n::parse_langs(&self.lang)?;
        if !self.sign_cert.is_empty() && !std::path::Path::new(&self.sign_cert).is_file() {
            return Err(format!("Signing certificate not found: {}", self.sign_cert));
        }
        let case_id = Some(self.case_id.trim().to_string()).filter(|s| !s.is_empty());
        let mut preamble = self.ui_actions.clone();
        preamble.push(("ui_start_clicked".into(), json!({"algorithms": self.selected, "lang": self.lang, "rehash": self.rehash,
            "crosscheck": self.crosscheck, "evidence_dir": self.evidence_dir, "jurisdiction": self.jurisdiction,
            "timestamp": self.timestamp, "pdf_signing": !self.sign_cert.is_empty(), "case_dir": self.case_dir.trim(),
            "at_utc": rv_hub_core::time::utc_now()})));
        let settings = vec![
            format!("{} (gui) verify", TOOL_NAME),
            format!("case_dir={}", self.case_dir.trim()),
            format!("rehash={}", self.rehash),
            format!(
                "evidence_dir={}",
                if self.evidence_dir.is_empty() {
                    "none"
                } else {
                    self.evidence_dir.as_str()
                }
            ),
            format!(
                "crosscheck={}",
                if self.crosscheck { "auto" } else { "off" }
            ),
            format!(
                "hash={}",
                self.selected
                    .iter()
                    .map(|a| a.name())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            format!("lang={}", self.lang),
            format!("out={}", self.out_dir.trim()),
            format!("jurisdiction={}", self.jurisdiction),
            format!(
                "tsa={}",
                if self.timestamp {
                    self.tsa_url.as_str()
                } else {
                    "off"
                }
            ),
            format!(
                "sign_cert={}",
                if self.sign_cert.is_empty() {
                    "none"
                } else {
                    self.sign_cert.as_str()
                }
            ),
        ];
        let cfg = RunConfig {
            case_dir: PathBuf::from(self.case_dir.trim()),
            rehash: self.rehash,
            evidence_dirs: if self.evidence_dir.trim().is_empty() {
                vec![]
            } else {
                vec![PathBuf::from(self.evidence_dir.trim())]
            },
            crosscheck: if self.crosscheck {
                CrossCheckMode::Auto
            } else {
                CrossCheckMode::Off
            },
            algorithms: self.selected.clone(),
            out_dir: PathBuf::from(self.out_dir.trim()),
            langs,
            actor: if self.actor.trim().is_empty() {
                rv_hub_core::env::os_user()
            } else {
                self.actor.trim().to_string()
            },
            case_id,
            frontend: "gui".into(),
            preamble,
            command_line: settings,
            tool_name: TOOL_NAME.into(),
            tool_version: TOOL_VERSION.into(),
            jurisdiction: self.jurisdiction.clone(),
            tsa_url: if self.timestamp {
                Some(self.tsa_url.clone())
            } else {
                None
            },
            sign_cert: if self.sign_cert.is_empty() {
                None
            } else {
                Some(PathBuf::from(&self.sign_cert))
            },
            sign_password: if self.sign_password.is_empty() {
                None
            } else {
                Some(self.sign_password.clone())
            },
            ..Default::default()
        };
        rv_hub_core::run::preflight(&cfg).map_err(|e| e.message)?;
        Ok(cfg)
    }

    pub fn start(&mut self) {
        self.phase = Phase::Running;
        self.progress = Progress::default();
        self.current_item.clear();
        self.warnings.clear();
        self.outcome = None;
        self.codes.clear();
        // Recorded actions now belong to this run's audit log.
        self.ui_actions.clear();
    }

    pub fn apply(&mut self, e: &Event) {
        match e {
            Event::RunStarted {
                total_items,
                total_bytes,
                ..
            } => {
                self.progress.total = *total_items;
                self.progress.bytes_total = *total_bytes;
            }
            Event::ItemStarted { path, .. } => self.current_item = path.clone(),
            Event::ItemFinished { findings, .. } => {
                for f in findings {
                    if !self.codes.contains(f) {
                        self.codes.push(f.clone());
                    }
                }
                self.codes.sort();
            }
            Event::Progress {
                done,
                total,
                bytes_done,
                bytes_total,
                elapsed_ms,
                eta_ms,
            } => {
                self.progress = Progress {
                    done: *done,
                    total: *total,
                    bytes_done: *bytes_done,
                    bytes_total: *bytes_total,
                    elapsed_ms: *elapsed_ms,
                    eta_ms: *eta_ms,
                };
            }
            Event::Error { path, message } => {
                self.warnings
                    .push(format!("{}: {}", path.as_deref().unwrap_or("-"), message))
            }
            Event::RunFinished {
                items,
                errors,
                high,
                medium,
                low,
                info,
                report_dir,
                log_dir,
                cancelled,
                elapsed_ms,
                ..
            } => {
                self.progress.elapsed_ms = *elapsed_ms;
                self.progress.eta_ms = None;
                let lang = if self.lang == "all" {
                    "en".to_string()
                } else {
                    self.lang.clone()
                };
                self.outcome = Some(Outcome {
                    items: *items,
                    errors: *errors,
                    high: *high,
                    medium: *medium,
                    low: *low,
                    info: *info,
                    report: PathBuf::from(report_dir).join(format!("statistics.{}.html", lang)),
                    log_dir: PathBuf::from(log_dir),
                });
                self.phase = if *cancelled {
                    Phase::Cancelled
                } else {
                    Phase::Finished
                };
                self.current_item.clear();
            }
            _ => {}
        }
    }

    pub fn fail(&mut self, msg: String) {
        self.phase = Phase::Failed(msg);
    }

    /// 0.0..=1.0, by bytes (or by files when every file is empty).
    pub fn fraction(&self) -> f32 {
        let p = &self.progress;
        if p.bytes_total > 0 {
            (p.bytes_done as f64 / p.bytes_total as f64).clamp(0.0, 1.0) as f32
        } else if p.total > 0 {
            (p.done as f64 / p.total as f64) as f32
        } else if matches!(self.phase, Phase::Finished) {
            1.0
        } else {
            0.0
        }
    }

    /// `live_elapsed_ms` is measured by the window clock so the timer keeps moving between events.
    pub fn timing_text(&self, live_elapsed_ms: Option<u64>) -> String {
        let elapsed = live_elapsed_ms
            .unwrap_or(self.progress.elapsed_ms)
            .max(self.progress.elapsed_ms);
        let eta = match self.progress.eta_ms {
            Some(ms) if self.is_running() => human_duration(ms),
            _ => "\u{2014}".into(),
        };
        format!(
            "{}: {}   \u{00B7}   {}: {}",
            self.tr("elapsed"),
            human_duration(elapsed),
            self.tr("remaining"),
            eta
        )
    }

    pub fn progress_text(&self) -> String {
        format!(
            "{} / {} {}  \u{00B7}  {:.0}%",
            self.progress.done,
            self.progress.total,
            self.tr("files"),
            self.fraction() * 100.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_most_two_and_at_least_one_algorithm() {
        let mut s = GuiState::default();
        assert_eq!(s.selected, vec![HashAlgo::Sha256]);
        assert!(
            !s.can_toggle(HashAlgo::Sha256),
            "cannot untick the last one"
        );
        assert!(s.toggle_algo(HashAlgo::Sha256).is_err());
        s.toggle_algo(HashAlgo::Md5).unwrap();
        assert!(
            !s.can_toggle(HashAlgo::Blake3),
            "third checkbox is disabled"
        );
        assert!(s.toggle_algo(HashAlgo::Blake3).is_err());
        assert!(s.can_toggle(HashAlgo::Sha256));
        s.toggle_algo(HashAlgo::Sha256).unwrap();
        assert_eq!(s.selected, vec![HashAlgo::Md5]);
    }

    fn sample_copy(tag: &str) -> PathBuf {
        fn copy(from: &std::path::Path, to: &std::path::Path) {
            std::fs::create_dir_all(to).unwrap();
            for e in std::fs::read_dir(from).unwrap() {
                let e = e.unwrap();
                if e.path().is_dir() {
                    copy(&e.path(), &to.join(e.file_name()));
                } else {
                    std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
                }
            }
        }
        let tmp = std::env::temp_dir().join(format!("rv-hub-gui-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        copy(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample/case"),
            &tmp.join("case"),
        );
        tmp
    }

    #[test]
    fn settings_changes_become_audit_preamble() {
        let tmp = sample_copy("pre");
        let mut s = GuiState::default();
        assert!(
            !s.can_start() && s.to_config().is_err(),
            "no case folder yet"
        );
        s.set_case_dir(&format!("\"{}\"", tmp.join("case").display()));
        s.toggle_algo(HashAlgo::Blake3).unwrap();
        s.set_lang("es");
        s.set_rehash(true);
        s.set_crosscheck(false);
        s.set_evidence_dir("E:\\copies");
        let cfg = s.to_config().unwrap();
        assert_eq!(cfg.case_dir, tmp.join("case"));
        assert!(cfg.rehash && cfg.crosscheck == CrossCheckMode::Off);
        assert_eq!(cfg.evidence_dirs, vec![PathBuf::from("E:\\copies")]);
        assert_eq!(cfg.frontend, "gui");
        let actions: Vec<&str> = cfg.preamble.iter().map(|(a, _)| a.as_str()).collect();
        assert_eq!(
            actions,
            vec![
                "ui_case_dir_changed",
                "ui_hash_selection_changed",
                "ui_language_changed",
                "ui_rehash_changed",
                "ui_crosscheck_changed",
                "ui_evidence_dir_changed",
                "ui_start_clicked"
            ]
        );
        s.start();
        assert!(s.ui_actions.is_empty());
        s.case_id = "OTHER".into();
        assert!(
            s.to_config()
                .unwrap_err()
                .contains("belongs to case SAMPLE-1")
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn events_drive_progress_and_outcome() {
        let mut s = GuiState::default();
        s.start();
        s.apply(&Event::RunStarted {
            run_id: "R".into(),
            tool: "t".into(),
            version: "v".into(),
            frontend: "gui".into(),
            algorithms: vec![HashAlgo::Sha256],
            langs: vec!["en".into()],
            total_items: 4,
            total_bytes: 400,
        });
        s.apply(&Event::Progress {
            done: 1,
            total: 4,
            bytes_done: 100,
            bytes_total: 400,
            elapsed_ms: 2000,
            eta_ms: Some(6000),
        });
        assert!((s.fraction() - 0.25).abs() < 1e-6);
        assert!(s.timing_text(Some(2500)).contains("6.0 s"));
        assert!(s.progress_text().starts_with("1 / 4"));
        s.apply(&Event::ItemFinished {
            index: 2,
            path: "x".into(),
            status: "problem".into(),
            findings: vec!["RUN_LOG_BROKEN".into()],
        });
        s.apply(&Event::RunFinished {
            items: 4,
            bytes: 400,
            errors: 0,
            elapsed_ms: 8000,
            high: 1,
            medium: 0,
            low: 0,
            info: 0,
            report_dir: "out/reports/R".into(),
            log_dir: "out/logs/R".into(),
            cancelled: false,
        });
        assert_eq!(s.phase, Phase::Finished);
        assert_eq!(s.codes, ["RUN_LOG_BROKEN"]);
        assert_eq!(
            s.outcome.as_ref().unwrap().report,
            PathBuf::from("out/reports/R/statistics.en.html")
        );
    }

    #[test]
    fn interface_language_and_trust_settings_are_audited() {
        let tmp = sample_copy("trust");
        let mut s = GuiState::default();
        s.set_ui_lang("fr");
        assert_eq!(s.tr("start"), "Lancer la vérification");
        s.set_ui_lang("es");
        assert_eq!(s.tr("start"), "Iniciar verificación");
        s.set_jurisdiction("fr");
        s.set_timestamp(false, "http://tsa.example");
        s.set_sign_cert("missing.p12");
        s.set_case_dir(&tmp.join("case").display().to_string());
        assert!(s.to_config().is_err(), "missing certificate refused");
        s.set_sign_cert("");
        let cfg = s.to_config().unwrap();
        assert_eq!(cfg.jurisdiction, "fr");
        assert!(cfg.tsa_url.is_none());
        let actions: Vec<&str> = cfg.preamble.iter().map(|(a, _)| a.as_str()).collect();
        assert!(
            actions.contains(&"ui_interface_language_changed")
                && actions.contains(&"ui_timestamp_changed")
        );
        assert!(
            cfg.preamble
                .iter()
                .all(|(_, d)| !d.to_string().contains("password"))
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_real_verification_from_gui_settings_is_audited() {
        let tmp = sample_copy("run");
        let mut s = GuiState {
            timestamp: false, // tests stay offline
            crosscheck: false,
            ..Default::default()
        };
        s.set_case_dir(&tmp.join("case").display().to_string());
        assert!(
            s.out_dir_display().contains("rv-hub") && s.out_dir_display().ends_with("<RUN-ID>")
        );
        let cfg = s.to_config().unwrap();
        s.start();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let summary = rv_hub_core::run(&cfg, &mut |e| s.apply(e), &cancel).unwrap();
        assert_eq!(s.phase, Phase::Finished);
        assert_eq!(s.codes, ["RUN_LOG_INTACT"]);
        assert!(summary.log_dir.starts_with(tmp.join("case/runs/rv-hub")));
        let log = std::fs::read_to_string(summary.log_dir.join("audit.jsonl")).unwrap();
        assert!(
            log.contains("\"ui_case_dir_changed\"")
                && log.contains("\"ui_start_clicked\"")
                && log.contains("\"frontend\":\"gui\"")
                && log.contains("\"case_linked\"")
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
