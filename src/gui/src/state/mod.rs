//! Everything the window shows and every rule it enforces, without any drawing code. Kept separate from `app.rs`
//! so it can be unit-tested headless (CI has no display).
//!
//! [`HubState`] holds the three tabs (Tools, Case, Verify), the hub settings and the hub session log. Every user
//! action goes through [`HubState::audit`]: a `ui_*` entry with `at_utc`, written to the session log
//! (`rv_hub_core::session`) and kept in [`HubState::audit_trail`]. Verify-tab options are also handed to the
//! verification run as its audit preamble, as in every Rakvor tool.

pub mod case;
pub mod settings;
pub mod tools;
pub mod verify;

pub use case::{CaseModel, EvidenceLine, RunLine, SuggestionLine};
pub use settings::Settings;
pub use tools::{Badge, Tone, ToolCard};
pub use verify::{GuiState, ItemLine, LANG_CHOICES, Outcome, Phase, Progress};

use rv_hub_core::launch::{self, LaunchError, Launched, Spawner};
use rv_hub_core::session::Session;
use rv_hub_core::signature::{SignatureStatus, SignatureVerifier};
use rv_hub_core::suggest::Action;
use rv_hub_core::tools::{DiscoverOptions, ToolInfo, ToolRole};
use rv_hub_core::{RunConfig, i18n};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Tools,
    Case,
    Verify,
}

impl Tab {
    pub const ALL: [Tab; 3] = [Tab::Tools, Tab::Case, Tab::Verify];

    pub fn key(self) -> &'static str {
        match self {
            Tab::Tools => "tab_tools",
            Tab::Case => "tab_case",
            Tab::Verify => "tab_verify",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Tab::Tools => "tools",
            Tab::Case => "case",
            Tab::Verify => "verify",
        }
    }
}

/// What a launch opens the tool on.
#[derive(Clone, Debug, PartialEq)]
pub enum LaunchTarget {
    Case(PathBuf),
    /// No case is open: the tool opens without one (asked first).
    NoCase,
}

/// A launch waiting for the user's confirmation (no case open, and/or not Rakvor-signed).
#[derive(Clone, Debug, PartialEq)]
pub struct PendingLaunch {
    pub tool_index: usize,
    pub tool: String,
    pub target: LaunchTarget,
    /// Set when the executable is not Rakvor-signed: the risk is stated and the confirmation audited.
    pub untrusted: Option<SignatureStatus>,
    /// "tools" | "suggestion" | "create_case"
    pub origin: String,
}

impl PendingLaunch {
    /// i18n `ui` key of the risk for an untrusted executable.
    pub fn risk_key(&self) -> Option<&'static str> {
        self.untrusted
            .as_ref()
            .and_then(|s| Badge::of(s).risk_key())
    }
}

/// What a launch request led to.
#[derive(Clone, Debug, PartialEq)]
pub enum LaunchStep {
    /// The confirmation dialog is open ([`HubState::pending`]).
    AskFirst,
    Started(Launched),
    Refused(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Notice {
    pub tone: Tone,
    pub text: String,
}

/// The signature check and process starter a launch uses (the OS ones in the window, fakes in tests).
pub struct LaunchEnv<'a> {
    pub verifier: &'a dyn SignatureVerifier,
    pub spawner: &'a dyn Spawner,
}

pub struct HubState {
    pub tab: Tab,
    /// Interface language (en/es/fr); the Verify tab's report language is separate.
    pub ui_lang: String,
    pub settings: Settings,
    /// Candidate folders for the settings (and the session log), in order of preference.
    pub data_dirs: Vec<PathBuf>,
    /// Where the settings were last read or written; None when they live in memory only.
    pub settings_path: Option<PathBuf>,
    /// The last discovery result.
    pub tools: Vec<ToolInfo>,
    pub cards: Vec<ToolCard>,
    /// A discovery has completed at least once.
    pub discovered: bool,
    pub discovering: bool,
    pub case: Option<CaseModel>,
    pub verify: GuiState,
    pub pending: Option<PendingLaunch>,
    pub notice: Option<Notice>,
    /// The hub session log (None when no folder could hold it: launching is then refused).
    pub session: Option<Session>,
    /// Every audited `ui_*` action of this window, in order (also in the session log when there is one).
    pub audit_trail: Vec<(String, Value)>,
    /// How many of `verify.ui_actions` were already copied to the session log.
    verify_flushed: usize,
}

impl HubState {
    /// Loads the settings from `data_dirs` (first readable) and starts the session log in the first folder that
    /// accepts it.
    pub fn new(data_dirs: Vec<PathBuf>, actor: &str) -> HubState {
        let (settings, settings_path, problems) = Settings::load(&data_dirs);
        let mut session_errors = vec![];
        let mut session = None;
        for d in &data_dirs {
            match Session::start(
                d,
                actor,
                "gui",
                &[format!("{} (gui)", rv_hub_core::TOOL_NAME)],
            ) {
                Ok(s) => {
                    session = Some(s);
                    break;
                }
                Err(e) => session_errors.push(e),
            }
        }
        let ui_lang = settings.ui_lang.clone().unwrap_or_else(|| "en".into());
        let verify = GuiState {
            ui_lang: ui_lang.clone(),
            actor: actor.to_string(),
            ..Default::default()
        };
        let mut s = HubState {
            tab: Tab::Tools,
            ui_lang,
            settings,
            data_dirs,
            settings_path,
            tools: vec![],
            cards: tools::cards(&[]),
            discovered: false,
            discovering: false,
            case: None,
            verify,
            pending: None,
            notice: None,
            session,
            audit_trail: vec![],
            verify_flushed: 0,
        };
        if s.session.is_none() {
            let err = session_errors.join("; ");
            s.warn(s.trf("session_unavailable", &[("error", &err)]));
        }
        for p in problems {
            s.warn(p);
        }
        s
    }

    /// The window's state: the hub data folder, then a temp-directory fallback; the OS user as actor.
    pub fn start_default() -> HubState {
        HubState::new(settings::default_dirs(), &rv_hub_core::env::os_user())
    }

    // ---- audit, language, notices -------------------------------------------------------------------------

    /// Records one user action (`ui_*`), with `at_utc`, in the session log and in [`HubState::audit_trail`].
    pub fn audit(&mut self, action: &str, details: Value) {
        let mut details = if details.is_object() {
            details
        } else {
            json!({ "value": details })
        };
        if let Some(o) = details.as_object_mut() {
            o.insert("at_utc".into(), json!(rv_hub_core::time::utc_now()));
        }
        if let Some(s) = self.session.as_mut() {
            if let Err(e) = s.record(action, details.clone()) {
                self.notice = Some(Notice {
                    tone: Tone::Red,
                    text: e,
                });
            }
        }
        self.audit_trail.push((action.to_string(), details));
    }

    /// The actions recorded so far (names only), for tests and the screenshot example.
    pub fn audited_actions(&self) -> Vec<&str> {
        self.audit_trail.iter().map(|(a, _)| a.as_str()).collect()
    }

    /// Copies the Verify tab's newly recorded option changes to the session log (they also stay in the
    /// verification run's preamble). Called by the window every frame.
    pub fn sync_verify_audit(&mut self) {
        let new: Vec<(String, Value)> = self
            .verify
            .ui_actions
            .iter()
            .skip(self.verify_flushed)
            .cloned()
            .collect();
        self.verify_flushed = self.verify.ui_actions.len();
        for (a, d) in new {
            // Already stamped with at_utc by the Verify state.
            if let Some(s) = self.session.as_mut() {
                let _ = s.record(&a, d.clone());
            }
            self.audit_trail.push((a, d));
        }
    }

    pub fn tr(&self, key: &str) -> String {
        i18n::catalog(&self.ui_lang).ui(key)
    }

    /// `tr` with `%{name}` placeholders filled.
    pub fn trf(&self, key: &str, params: &[(&str, &str)]) -> String {
        let p: BTreeMap<String, String> = params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        i18n::fill(&self.tr(key), &p)
    }

    pub fn suggestion_text(&self, s: &SuggestionLine) -> String {
        let mut t = i18n::catalog(&self.ui_lang).text("suggest", &s.reason_key);
        if !s.evidence_ids.is_empty() {
            t = format!("{t} ({})", s.evidence_ids.join(", "));
        } else if !s.run_dirs.is_empty() {
            t = format!("{t} ({})", s.run_dirs.join(", "));
        }
        t
    }

    pub fn set_ui_lang(&mut self, l: &str) {
        if self.ui_lang == l || !i18n::LANGS.contains(&l) {
            return;
        }
        self.ui_lang = l.to_string();
        self.verify.ui_lang = l.to_string();
        self.audit("ui_interface_language_changed", json!({"ui_lang": l}));
        self.settings.ui_lang = Some(l.to_string());
        self.save_settings();
    }

    pub fn set_tab(&mut self, t: Tab) {
        if self.tab != t {
            self.tab = t;
            self.audit("ui_tab_selected", json!({"tab": t.name()}));
        }
    }

    fn say(&mut self, tone: Tone, text: String) {
        self.notice = Some(Notice { tone, text });
    }

    fn warn(&mut self, text: String) {
        self.say(Tone::Amber, text);
    }

    pub fn dismiss_notice(&mut self) {
        self.notice = None;
    }

    fn save_settings(&mut self) {
        match self.settings.save(&self.data_dirs) {
            Ok(p) => {
                if self.data_dirs.first().is_some_and(|d| !p.starts_with(d)) {
                    let shown = p.display().to_string();
                    self.warn(self.trf("settings_fallback", &[("path", &shown)]));
                }
                self.settings_path = Some(p);
            }
            Err(e) => {
                self.settings_path = None;
                self.warn(self.trf("settings_unsaved", &[("error", &e)]));
            }
        }
    }

    // ---- Tools tab ----------------------------------------------------------------------------------------

    /// What the next discovery looks at (this workstation + the added folders).
    pub fn discover_options(&self) -> DiscoverOptions {
        DiscoverOptions::from_env(self.settings.user_folders.clone())
    }

    /// The user asked for a new discovery (Refresh); the window then runs it off the UI thread.
    pub fn request_refresh_tools(&mut self) {
        self.audit("ui_tools_refreshed", json!({}));
        self.discovering = true;
    }

    /// A discovery result arrived: rebuild the cards (and the open case's suggestions) and record the inventory.
    pub fn apply_discovery(&mut self, tools: Vec<ToolInfo>) {
        let inventory: Vec<Value> = tools
            .iter()
            .map(|t| {
                json!({"tool": t.tool, "version": t.version, "dir": t.dir.display().to_string(),
                            "signature": tools::card_signature(t).key()})
            })
            .collect();
        self.cards = tools::cards(&tools);
        self.tools = tools;
        self.discovered = true;
        self.discovering = false;
        self.pending = None;
        self.audit("ui_tools_listed", json!({"tools": inventory}));
        if let Some(c) = &self.case {
            let dir = c.view.dir.clone();
            self.case = Some(CaseModel::load(&dir, &self.tools));
        }
    }

    /// Adds a portable folder (saved in the settings). True when a new discovery should run.
    pub fn add_folder(&mut self, text: &str) -> bool {
        let text = text.trim().trim_matches('"');
        if text.is_empty() {
            return false;
        }
        let p = PathBuf::from(text);
        if !p.is_dir() {
            self.warn(self.trf("folder_not_found", &[("path", text)]));
            return false;
        }
        if !self.settings.add_folder(&p) {
            self.warn(self.trf("folder_already_added", &[("path", text)]));
            return false;
        }
        self.audit("ui_folder_added", json!({"folder": text}));
        self.save_settings();
        self.discovering = true;
        true
    }

    pub fn remove_folder(&mut self, index: usize) -> bool {
        if index >= self.settings.user_folders.len() {
            return false;
        }
        let f = self.settings.user_folders.remove(index);
        self.audit(
            "ui_folder_removed",
            json!({"folder": f.display().to_string()}),
        );
        self.save_settings();
        self.discovering = true;
        true
    }

    // ---- launching ----------------------------------------------------------------------------------------

    fn case_dir(&self) -> Option<PathBuf> {
        self.case.as_ref().map(|c| c.view.dir.clone())
    }

    /// Launch clicked on a tool card or a suggestion. With a case open, the tool opens on it; without one it
    /// opens with no case, asked first. Anything but Rakvor-signed is asked first too, stating the risk.
    pub fn request_launch(
        &mut self,
        tool_index: usize,
        origin: &str,
        env: &LaunchEnv,
    ) -> LaunchStep {
        let target = match self.case_dir() {
            Some(d) => LaunchTarget::Case(d),
            None => LaunchTarget::NoCase,
        };
        self.request_launch_on(tool_index, origin, target, env)
    }

    fn request_launch_on(
        &mut self,
        tool_index: usize,
        origin: &str,
        target: LaunchTarget,
        env: &LaunchEnv,
    ) -> LaunchStep {
        let Some(t) = self.tools.get(tool_index) else {
            return LaunchStep::Refused(self.tr("not_installed"));
        };
        let tool = t.tool.clone();
        let status = tools::card_signature(t).clone();
        let case_text = match &target {
            LaunchTarget::Case(d) => json!(d.display().to_string()),
            LaunchTarget::NoCase => Value::Null,
        };
        self.audit(
            "ui_launch_clicked",
            json!({"tool": tool, "origin": origin, "case_dir": case_text, "signature": status.key()}),
        );
        let p = PendingLaunch {
            tool_index,
            tool,
            target,
            untrusted: (!status.is_rakvor()).then_some(status),
            origin: origin.into(),
        };
        if p.untrusted.is_some() || p.target == LaunchTarget::NoCase {
            self.pending = Some(p);
            return LaunchStep::AskFirst;
        }
        self.perform(p, env)
    }

    /// The user confirmed the dialog: the confirmations are audited, then the tool starts.
    pub fn confirm_pending(&mut self, env: &LaunchEnv) -> LaunchStep {
        let Some(p) = self.pending.take() else {
            return LaunchStep::Refused(String::new());
        };
        if p.target == LaunchTarget::NoCase {
            self.audit(
                "ui_launch_without_case_confirmed",
                json!({"tool": p.tool, "origin": p.origin}),
            );
        }
        if let Some(s) = &p.untrusted {
            let exe = self
                .tools
                .get(p.tool_index)
                .and_then(|t| t.gui_exe.as_ref())
                .map(|e| e.display().to_string());
            self.audit(
                "ui_launch_untrusted_confirmed",
                json!({"tool": p.tool, "exe": exe, "signature": s, "risk": p.risk_key(), "origin": p.origin}),
            );
        }
        self.perform(p, env)
    }

    pub fn cancel_pending(&mut self) {
        if let Some(p) = self.pending.take() {
            self.audit(
                "ui_launch_cancelled",
                json!({"tool": p.tool, "origin": p.origin}),
            );
        }
    }

    fn perform(&mut self, p: PendingLaunch, env: &LaunchEnv) -> LaunchStep {
        let Some(tool) = self.tools.get(p.tool_index).cloned() else {
            return LaunchStep::Refused(self.tr("not_installed"));
        };
        let confirmed = p.untrusted.is_some();
        let Some(session) = self.session.as_mut() else {
            let msg = self.tr("launch_needs_session");
            self.say(Tone::Red, msg.clone());
            return LaunchStep::Refused(msg);
        };
        let result = match &p.target {
            LaunchTarget::Case(d) => {
                launch::launch_with(session, &tool, d, confirmed, env.verifier, env.spawner)
            }
            LaunchTarget::NoCase => launch::launch_without_case_with(
                session,
                &tool,
                confirmed,
                env.verifier,
                env.spawner,
            ),
        };
        match result {
            Ok(l) => {
                let pid = l.pid.to_string();
                self.say(
                    Tone::Green,
                    self.trf("launched", &[("tool", &tool.title), ("pid", &pid)]),
                );
                if p.origin == "create_case" {
                    if let LaunchTarget::Case(d) = &p.target {
                        self.load_case(d);
                    }
                }
                LaunchStep::Started(l)
            }
            // The signature changed since discovery: ask, stating the new status.
            Err(LaunchError::NeedsConfirmation(s)) => {
                self.pending = Some(PendingLaunch {
                    untrusted: Some(s),
                    ..p
                });
                LaunchStep::AskFirst
            }
            Err(e) => {
                let err = e.to_string();
                self.audit("ui_launch_failed", json!({"tool": tool.tool, "error": err}));
                let msg = self.trf("launch_failed", &[("tool", &tool.title), ("error", &err)]);
                self.say(Tone::Red, msg.clone());
                LaunchStep::Refused(msg)
            }
        }
    }

    // ---- Case tab -----------------------------------------------------------------------------------------

    /// Opens a case folder (read-only). Remembered in the recent cases when it holds case.json.
    pub fn open_case(&mut self, text: &str) -> bool {
        let text = text.trim().trim_matches('"');
        if text.is_empty() {
            return false;
        }
        let dir = PathBuf::from(text);
        if !dir.is_dir() {
            self.warn(self.trf("case_not_folder", &[("path", text)]));
            return false;
        }
        self.audit("ui_case_opened", json!({"case_dir": text}));
        self.load_case(&dir);
        true
    }

    fn load_case(&mut self, dir: &Path) {
        let model = CaseModel::load(dir, &self.tools);
        if model.is_case {
            self.settings.add_recent(dir);
            self.save_settings();
        }
        // The Verify tab follows the open case (its own field can still be changed).
        self.verify.case_dir = dir.display().to_string();
        self.case = Some(model);
    }

    /// Re-reads the open case. `by_user`: the Refresh button (audited); otherwise the window regained focus.
    pub fn refresh_case(&mut self, by_user: bool) {
        let Some(dir) = self.case_dir() else { return };
        if by_user {
            self.audit(
                "ui_case_refreshed",
                json!({"case_dir": dir.display().to_string()}),
            );
        }
        self.case = Some(CaseModel::load(&dir, &self.tools));
    }

    pub fn close_case(&mut self) {
        if let Some(dir) = self.case_dir() {
            self.audit(
                "ui_case_closed",
                json!({"case_dir": dir.display().to_string()}),
            );
            self.case = None;
        }
    }

    /// Create case: rv-hashinv (the intake tool) opens on an empty folder and creates case.json there. The hub
    /// never writes case.json itself.
    pub fn request_create_case(&mut self, text: &str, env: &LaunchEnv) -> LaunchStep {
        let text = text.trim().trim_matches('"').to_string();
        let refuse = |s: &mut HubState, key: &str| {
            let m = s.trf(key, &[("path", &text)]);
            s.warn(m.clone());
            LaunchStep::Refused(m)
        };
        if text.is_empty() {
            return refuse(self, "create_err_empty");
        }
        let dir = PathBuf::from(&text);
        if dir.is_file() {
            return refuse(self, "create_err_file");
        }
        if dir.join(rv_hub_core::case::CASE_FILE).is_file() {
            return refuse(self, "create_err_is_case");
        }
        if dir.is_dir()
            && std::fs::read_dir(&dir)
                .map(|mut r| r.next().is_some())
                .unwrap_or(true)
        {
            return refuse(self, "create_err_not_empty");
        }
        let Some(intake) = self
            .tools
            .iter()
            .position(|t| t.describe.role == ToolRole::Intake && t.gui_exe.is_some())
        else {
            return refuse(self, "create_err_no_intake");
        };
        self.audit("ui_create_case_clicked", json!({"case_dir": text}));
        self.request_launch_on(intake, "create_case", LaunchTarget::Case(dir), env)
    }

    /// One-click launch of a suggestion's tool.
    pub fn launch_suggestion(&mut self, index: usize, env: &LaunchEnv) -> LaunchStep {
        let Some(s) = self
            .case
            .as_ref()
            .and_then(|c| c.suggestions.get(index))
            .cloned()
        else {
            return LaunchStep::Refused(String::new());
        };
        let Some(t) = s.tool_index else {
            let m = self.trf("suggest_not_installed", &[("tool", &s.tool)]);
            self.warn(m.clone());
            return LaunchStep::Refused(m);
        };
        let origin = match s.action {
            Action::Launch => "suggestion",
            Action::Timestamp => "suggestion_timestamp",
        };
        self.request_launch(t, origin, env)
    }

    // ---- Verify tab ---------------------------------------------------------------------------------------

    /// The verification run's configuration: the Verify options (their changes become the run's audit
    /// preamble) plus the tools already discovered here, so the cross-check does not discover them again.
    pub fn verify_config(&mut self) -> Result<RunConfig, String> {
        self.sync_verify_audit();
        let mut cfg = self.verify.to_config()?;
        if self.discovered {
            cfg.tools = Some(self.tools.clone());
        }
        self.audit(
            "ui_verify_started",
            json!({"case_dir": cfg.case_dir.display().to_string(), "rehash": cfg.rehash,
                   "crosscheck": cfg.crosscheck == rv_hub_core::CrossCheckMode::Auto,
                   "algorithms": cfg.algorithms, "langs": cfg.langs}),
        );
        Ok(cfg)
    }

    /// The run started: the Verify actions now belong to its audit log.
    pub fn verify_started(&mut self) {
        self.verify.start();
        self.verify_flushed = 0;
    }

    /// A verification finished: the case view shows the new rv-hub run.
    pub fn verify_finished(&mut self) {
        if self.case.is_some() {
            self.refresh_case(false);
        }
    }

    /// Open report clicked: the report to open (audited).
    pub fn report_to_open(&mut self) -> Option<PathBuf> {
        let p = self.verify.outcome.as_ref()?.report.clone();
        self.audit("ui_report_opened", json!({"path": p.display().to_string()}));
        Some(p)
    }

    /// Open run folder clicked: `runs/rv-hub/<RUN-ID>` (audited).
    pub fn run_folder_to_open(&mut self) -> Option<PathBuf> {
        let logs = self.verify.outcome.as_ref()?.log_dir.clone();
        let p = logs.parent().map(Path::to_path_buf).unwrap_or(logs);
        self.audit(
            "ui_run_folder_opened",
            json!({"path": p.display().to_string()}),
        );
        Some(p)
    }

    pub fn cancel_verify_clicked(&mut self) {
        self.audit("ui_cancel_clicked", json!({}));
    }
}

/// The `ui` keys this window uses beyond the template's (checked in every language by a test).
pub const UI_KEYS: &[&str] = &[
    "tab_tools",
    "tab_case",
    "tab_verify",
    "tools_title",
    "tools_help",
    "badge_rakvor",
    "badge_unsigned",
    "badge_other_root",
    "badge_invalid",
    "badge_not_checked",
    "risk_unsigned",
    "risk_other_root",
    "risk_invalid",
    "risk_not_checked",
    "version",
    "version_unknown",
    "source",
    "src_registry",
    "src_local",
    "src_path",
    "src_user",
    "install_path",
    "launch",
    "launch_tip_case",
    "launch_tip_no_case",
    "not_installed",
    "builtin_describe",
    "folders_title",
    "add_folder",
    "add_folder_hint",
    "add",
    "remove",
    "refresh",
    "discovering",
    "confirm_title",
    "confirm_no_case",
    "confirm_untrusted",
    "confirm_recorded",
    "confirm_go",
    "confirm_go_untrusted",
    "launched",
    "launch_failed",
    "launch_needs_session",
    "session_unavailable",
    "settings_unsaved",
    "settings_fallback",
    "folder_not_found",
    "folder_already_added",
    "case_title",
    "case_open",
    "case_open_hint",
    "case_close",
    "recent",
    "create_case",
    "create_case_help",
    "create_hint",
    "create_err_empty",
    "create_err_file",
    "create_err_is_case",
    "create_err_not_empty",
    "create_err_no_intake",
    "case_not_folder",
    "no_case_open",
    "not_a_case_yet",
    "case_id",
    "created",
    "read_only_note",
    "read_at",
    "evidence_title",
    "evidence_none",
    "col_id",
    "col_file",
    "col_size",
    "col_examined",
    "superseded",
    "runs_title",
    "runs_none",
    "col_tool",
    "col_run",
    "col_time",
    "col_findings",
    "col_timestamp",
    "col_status",
    "ts_obtained",
    "ts_pending",
    "ts_off",
    "ts_unknown",
    "st_completed",
    "st_cancelled",
    "st_failed",
    "st_running",
    "st_not_in_case_log",
    "totals_title",
    "problems_title",
    "no_problems",
    "case_log_intact",
    "case_log_broken",
    "case_log_none",
    "no_suggestions",
    "launch_suggested",
    "suggest_timestamp_hint",
    "suggest_not_installed",
    "results_title",
    "results_none",
    "col_item",
    "col_kind",
    "col_verdict",
    "kind_case_log",
    "kind_run",
    "kind_evidence",
    "verdict_ok",
    "verdict_attention",
    "verdict_problem",
    "verdict_running",
    "open_run_folder",
];

/// Fake tools for tests and the screenshot example (no real executables are run).
#[doc(hidden)]
pub mod testing {
    use rv_hub_core::signature::SignatureStatus;
    use rv_hub_core::tools::{
        Accepts, Describe, DescribeSource, Source, ToolInfo, ToolRole, builtin,
    };
    use std::path::Path;

    /// A discovered tool under `dir/<tool>/` with small fake executables written there.
    pub fn fake_tool(dir: &Path, tool: &str, status: SignatureStatus) -> ToolInfo {
        let d = dir.join(tool);
        std::fs::create_dir_all(&d).unwrap();
        let (cli, gui) = (
            d.join(format!("{tool}.exe")),
            d.join(format!("{tool}-gui.exe")),
        );
        std::fs::write(&cli, format!("{tool} cli")).unwrap();
        std::fs::write(&gui, format!("{tool} gui")).unwrap();
        let mut t = preview_tool(&d, tool, status, "1.0.0", Source::UserFolder);
        t.cli_sha256 = rv_hub_core::tools::sha256_of(&cli);
        t.gui_sha256 = rv_hub_core::tools::sha256_of(&gui);
        t
    }

    /// What `rv-certcheck describe --json` reports (used until the core's built-in table knows the tool).
    pub fn certcheck_describe(tool: &str) -> Describe {
        let mut d = builtin("rv-pdfauth").expect("known tool");
        d.tool = tool.into();
        d.title = "RV CertCheck".into();
        d.version = Some("0.2.0".into());
        d.role = ToolRole::Analysis;
        d.main_verb = "check".into();
        d.accepts = Accepts {
            extensions: [
                "cer", "crt", "pem", "der", "p7b", "p7c", "crl", "tsr", "tst",
            ]
            .iter()
            .map(|e| e.to_string())
            .collect(),
            signatures: vec![],
        };
        d.cli_exe = format!("{tool}.exe");
        d.gui_exe = format!("{tool}-gui.exe");
        d
    }

    /// The five Rakvor tools as discovered on a workstation (no files on disk): screenshots and tests.
    /// `root` is shown as is (e.g. a Windows path on any platform): the folders are `<root>\\<title>`.
    pub fn five_tools(root: &str) -> Vec<ToolInfo> {
        let p = |t: &str| std::path::PathBuf::from(format!("{root}\\{t}"));
        let reg = |id: &str| Source::Registry { app_id: id.into() };
        let mut v = vec![
            preview_tool(
                &p("RV HashInv"),
                "rv-hashinv",
                SignatureStatus::SignedRakvor,
                "0.3.1",
                reg("{RV-HASHINV}"),
            ),
            preview_tool(
                &p("RV PDFAuth"),
                "rv-pdfauth",
                SignatureStatus::SignedRakvor,
                "0.4.0",
                reg("{RV-PDFAUTH}"),
            ),
            preview_tool(
                &p("RV ImgAuth"),
                "rv-imgauth",
                SignatureStatus::Unsigned,
                "0.2.2",
                Source::UserFolder,
            ),
            preview_tool(
                &p("RV RSMF"),
                "rv-rsmf",
                SignatureStatus::NotChecked {
                    reason: "not Windows: Authenticode signatures are checked on Windows only"
                        .into(),
                },
                "0.5.0",
                Source::LocalPrograms,
            ),
            preview_tool(
                &p("RV CertCheck"),
                "rv-certcheck",
                SignatureStatus::SignedRakvor,
                "0.2.0",
                Source::LocalPrograms,
            ),
        ];
        v.sort_by(|a, b| a.tool.cmp(&b.tool));
        v
    }

    /// A tool as discovery would report it, without any file on disk (screenshots).
    pub fn preview_tool(
        dir: &Path,
        tool: &str,
        status: SignatureStatus,
        version: &str,
        source: Source,
    ) -> ToolInfo {
        let describe = builtin(tool).unwrap_or_else(|| certcheck_describe(tool));
        ToolInfo {
            tool: tool.into(),
            title: describe.title.clone(),
            dir: dir.to_path_buf(),
            cli_exe: Some(dir.join(format!("{tool}.exe"))),
            gui_exe: Some(dir.join(format!("{tool}-gui.exe"))),
            cli_sha256: None,
            gui_sha256: None,
            sources: vec![source],
            version: Some(version.into()),
            describe,
            describe_source: DescribeSource::Describe,
            describe_problem: None,
            cli_signature: status.clone(),
            gui_signature: status,
            warnings: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::fake_tool;
    use super::*;
    use rv_hub_core::signature::StaticVerifier;
    use std::cell::RefCell;
    use std::ffi::OsString;

    #[derive(Default)]
    struct Recorder(RefCell<Vec<(PathBuf, Vec<OsString>)>>);
    impl Spawner for Recorder {
        fn spawn_detached(&self, exe: &Path, args: &[OsString]) -> std::io::Result<u32> {
            self.0.borrow_mut().push((exe.to_path_buf(), args.to_vec()));
            Ok(777)
        }
    }

    fn copy_dir(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for e in std::fs::read_dir(from).unwrap() {
            let e = e.unwrap();
            if e.path().is_dir() {
                copy_dir(&e.path(), &to.join(e.file_name()));
            } else {
                std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
            }
        }
    }

    fn sample_case(root: &Path) -> PathBuf {
        let case = root.join("case");
        copy_dir(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample/case"),
            &case,
        );
        case
    }

    /// Every file under `dir` with its bytes.
    fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut out = BTreeMap::new();
        fn walk(d: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for e in std::fs::read_dir(d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    walk(&p, out);
                } else {
                    out.insert(p.clone(), std::fs::read(&p).unwrap());
                }
            }
        }
        walk(dir, &mut out);
        out
    }

    fn hub(root: &Path) -> HubState {
        HubState::new(vec![root.join("hub-data")], "Examiner Test")
    }

    fn session_actions(s: &HubState) -> Vec<String> {
        std::fs::read_to_string(s.session.as_ref().unwrap().audit_path())
            .unwrap()
            .lines()
            .map(|l| {
                serde_json::from_str::<Value>(l).unwrap()["action"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn untrusted_launch_is_confirmed_and_audited() {
        let d = tempfile::tempdir().unwrap();
        let case = sample_case(d.path());
        let mut s = hub(d.path());
        s.apply_discovery(vec![fake_tool(
            d.path(),
            "rv-pdfauth",
            SignatureStatus::Unsigned,
        )]);
        assert!(s.open_case(&case.display().to_string()));
        let rec = Recorder::default();
        let v = StaticVerifier::always(SignatureStatus::Unsigned);
        let env = LaunchEnv {
            verifier: &v,
            spawner: &rec,
        };
        // Unsigned: the dialog opens, nothing starts.
        assert_eq!(s.request_launch(0, "tools", &env), LaunchStep::AskFirst);
        let p = s.pending.clone().unwrap();
        assert_eq!(p.risk_key(), Some("risk_unsigned"));
        assert!(rec.0.borrow().is_empty());
        // Cancel: audited, nothing starts.
        s.cancel_pending();
        assert!(s.pending.is_none() && rec.0.borrow().is_empty());
        assert_eq!(s.audited_actions().last(), Some(&"ui_launch_cancelled"));
        // Again, confirmed: audited before the core's own entries, then started.
        assert_eq!(s.request_launch(0, "tools", &env), LaunchStep::AskFirst);
        let LaunchStep::Started(l) = s.confirm_pending(&env) else {
            panic!("not started")
        };
        assert_eq!(l.pid, 777);
        let (_, details) = s
            .audit_trail
            .iter()
            .find(|(a, _)| a == "ui_launch_untrusted_confirmed")
            .unwrap();
        assert_eq!(details["tool"], "rv-pdfauth");
        assert_eq!(details["signature"]["status"], "unsigned");
        assert_eq!(details["risk"], "risk_unsigned");
        assert!(details["at_utc"].as_str().unwrap().ends_with('Z'));
        let log = session_actions(&s);
        let tail: Vec<&str> = log.iter().rev().take(4).rev().map(String::as_str).collect();
        assert_eq!(
            tail,
            [
                "ui_launch_clicked",
                "ui_launch_untrusted_confirmed",
                "tool_untrusted_confirmed",
                "tool_launched"
            ]
        );
        assert_eq!(
            rv_hub_core::audit::verify(&s.session.as_ref().unwrap().audit_path()),
            Ok(log.len() as u64)
        );
        assert!(s.notice.as_ref().unwrap().text.contains("777"));
    }

    #[test]
    fn launch_builds_the_case_dir_command_line() {
        let d = tempfile::tempdir().unwrap();
        let case = sample_case(d.path());
        let mut s = hub(d.path());
        s.apply_discovery(vec![fake_tool(
            d.path(),
            "rv-imgauth",
            SignatureStatus::SignedRakvor,
        )]);
        let rec = Recorder::default();
        let v = StaticVerifier::always(SignatureStatus::SignedRakvor);
        let env = LaunchEnv {
            verifier: &v,
            spawner: &rec,
        };
        // No case open: asked first, then started with no arguments.
        assert_eq!(s.request_launch(0, "tools", &env), LaunchStep::AskFirst);
        assert_eq!(s.pending.as_ref().unwrap().target, LaunchTarget::NoCase);
        assert!(s.pending.as_ref().unwrap().untrusted.is_none());
        assert!(matches!(s.confirm_pending(&env), LaunchStep::Started(_)));
        assert!(rec.0.borrow()[0].1.is_empty());
        assert!(
            s.audited_actions()
                .contains(&"ui_launch_without_case_confirmed")
        );
        // Case open + Rakvor-signed: started at once with --case-dir CASE.
        s.open_case(&case.display().to_string());
        assert!(matches!(
            s.request_launch(0, "tools", &env),
            LaunchStep::Started(_)
        ));
        let (exe, args) = rec.0.borrow()[1].clone();
        assert_eq!(exe, s.tools[0].gui_exe.clone().unwrap());
        assert_eq!(
            args,
            vec![
                OsString::from("--case-dir"),
                rv_hub_core::case::normalize(&case).into_os_string()
            ]
        );
        assert!(
            !s.audited_actions()
                .contains(&"ui_launch_untrusted_confirmed")
        );
        // Signature changed since discovery: the core refuses, the dialog opens with the new status.
        let bad = StaticVerifier::always(SignatureStatus::Invalid {
            reason: "tampered".into(),
        });
        let env2 = LaunchEnv {
            verifier: &bad,
            spawner: &rec,
        };
        assert_eq!(s.request_launch(0, "tools", &env2), LaunchStep::AskFirst);
        assert_eq!(s.pending.as_ref().unwrap().risk_key(), Some("risk_invalid"));
        assert_eq!(rec.0.borrow().len(), 2);
    }

    #[test]
    fn create_case_launches_the_intake_tool_on_an_empty_folder() {
        let d = tempfile::tempdir().unwrap();
        let mut s = hub(d.path());
        let rec = Recorder::default();
        let v = StaticVerifier::always(SignatureStatus::SignedRakvor);
        let env = LaunchEnv {
            verifier: &v,
            spawner: &rec,
        };
        let new_case = d.path().join("CASE-2026-014");
        let text = new_case.display().to_string();
        // No intake tool installed.
        assert!(matches!(
            s.request_create_case(&text, &env),
            LaunchStep::Refused(_)
        ));
        s.apply_discovery(vec![fake_tool(
            d.path(),
            "rv-hashinv",
            SignatureStatus::SignedRakvor,
        )]);
        // Not empty, already a case, a file: refused.
        let full = d.path().join("full");
        std::fs::create_dir_all(&full).unwrap();
        std::fs::write(full.join("x"), b"x").unwrap();
        assert!(matches!(
            s.request_create_case(&full.display().to_string(), &env),
            LaunchStep::Refused(_)
        ));
        let existing = sample_case(d.path());
        assert!(matches!(
            s.request_create_case(&existing.display().to_string(), &env),
            LaunchStep::Refused(_)
        ));
        assert!(rec.0.borrow().is_empty());
        // A new (not yet existing) folder: rv-hashinv opens on it; the hub writes nothing there.
        assert!(matches!(
            s.request_create_case(&text, &env),
            LaunchStep::Started(_)
        ));
        let (exe, args) = rec.0.borrow()[0].clone();
        assert!(exe.ends_with("rv-hashinv-gui.exe"));
        assert_eq!(args[0], OsString::from("--case-dir"));
        assert_eq!(
            args[1],
            rv_hub_core::case::normalize(&new_case).into_os_string()
        );
        assert!(!new_case.exists(), "the hub never creates the case");
        assert!(s.case.as_ref().is_some_and(|c| !c.is_case));
        assert!(s.audited_actions().contains(&"ui_create_case_clicked"));
        assert!(s.settings.recent_cases.is_empty(), "not a case yet");
    }

    #[test]
    fn case_tab_model_from_the_sample_case_writes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let case = sample_case(d.path());
        let before = snapshot(&case);
        let mut s = hub(d.path());
        s.apply_discovery(vec![
            fake_tool(d.path(), "rv-hashinv", SignatureStatus::SignedRakvor),
            fake_tool(d.path(), "rv-pdfauth", SignatureStatus::SignedRakvor),
        ]);
        assert!(s.open_case(&case.display().to_string()));
        s.refresh_case(true);
        s.refresh_case(false);
        let c = s.case.clone().unwrap();
        assert!(c.is_case);
        assert_eq!(c.view.case_id.as_deref(), Some("SAMPLE-1"));
        assert_eq!(c.view.jurisdiction.as_deref(), Some("co"));
        assert_eq!(c.evidence.len(), c.view.evidence.len());
        assert!(c.evidence.len() >= 5);
        let e1 = &c.evidence[0];
        assert_eq!((e1.id.as_str(), e1.file.as_str()), ("E0001", "captura.png"));
        assert_eq!(e1.size, "354 B");
        assert!(e1.examined_by.contains("rv-hashinv") && e1.examined_by.contains("rv-imgauth"));
        let tools: Vec<&str> = c.runs.iter().map(|r| r.tool.as_str()).collect();
        for t in ["rv-hashinv", "rv-pdfauth", "rv-imgauth", "rv-rsmf"] {
            assert!(tools.contains(&t), "{t} run listed");
        }
        assert!(c.runs.iter().all(|r| r.status_key == "st_completed"));
        assert!(c.runs.iter().all(|r| r.time.starts_with("2026-10-29 ")));
        assert!(c.runs.iter().all(|r| r.findings.is_some()));
        assert_eq!(c.case_log_key(), "case_log_intact");
        assert_eq!(s.verify.case_dir, case.display().to_string());
        assert_eq!(s.settings.recent_cases, vec![case.clone()]);
        let actions = s.audited_actions();
        assert!(actions.contains(&"ui_case_opened") && actions.contains(&"ui_case_refreshed"));
        assert_eq!(
            actions
                .iter()
                .filter(|a| **a == "ui_case_refreshed")
                .count(),
            1,
            "a focus refresh is not a user action"
        );
        assert_eq!(snapshot(&case), before, "nothing written into the case");
    }

    #[test]
    fn suggestions_render_with_reason_and_launch() {
        let d = tempfile::tempdir().unwrap();
        let case = sample_case(d.path());
        // Drop the rv-pdfauth run from a copy of the view: the PDF becomes "not analysed".
        let mut view = rv_hub_core::case_view::read_case(&case);
        for e in &mut view.evidence {
            e.examined_by.retain(|t| t != "rv-pdfauth");
        }
        let tools = vec![fake_tool(
            d.path(),
            "rv-pdfauth",
            SignatureStatus::SignedRakvor,
        )];
        let catalog = rv_hub_core::tools::catalog(&tools);
        let sug = rv_hub_core::suggest::suggest(&view, &catalog);
        let pdf = sug.iter().find(|s| s.tool == "rv-pdfauth").unwrap();
        assert_eq!(pdf.reason_key, "pdf_not_analysed");

        let mut s = hub(d.path());
        s.apply_discovery(tools);
        let line = SuggestionLine {
            tool: pdf.tool.clone(),
            action: pdf.action,
            reason_key: pdf.reason_key.clone(),
            evidence_ids: pdf.evidence_ids.clone(),
            run_dirs: vec![],
            tool_index: case::launchable_index(&s.tools, "rv-pdfauth"),
        };
        assert_eq!(line.tool_index, Some(0));
        let en = s.suggestion_text(&line);
        assert!(
            en.starts_with("Registered PDF files") && en.contains("E0002"),
            "{en}"
        );
        s.set_ui_lang("fr");
        assert_ne!(s.suggestion_text(&line), en);
        assert!(s.suggestion_text(&line).contains("E0002"));

        // One-click launch from the open case's suggestions.
        s.open_case(&case.display().to_string());
        let model = s.case.as_mut().unwrap();
        model.suggestions = vec![
            line.clone(),
            SuggestionLine {
                tool: "rv-rsmf".into(),
                tool_index: None,
                ..line
            },
        ];
        let rec = Recorder::default();
        let v = StaticVerifier::always(SignatureStatus::SignedRakvor);
        let env = LaunchEnv {
            verifier: &v,
            spawner: &rec,
        };
        assert!(matches!(
            s.launch_suggestion(0, &env),
            LaunchStep::Started(_)
        ));
        assert_eq!(rec.0.borrow()[0].1[0], OsString::from("--case-dir"));
        let (_, d0) = s
            .audit_trail
            .iter()
            .rev()
            .find(|(a, _)| a == "ui_launch_clicked")
            .unwrap();
        assert_eq!(d0["origin"], "suggestion");
        // Not installed: refused with a message, nothing started.
        assert!(matches!(
            s.launch_suggestion(1, &env),
            LaunchStep::Refused(_)
        ));
        assert_eq!(rec.0.borrow().len(), 1);

        // The real sample (every tool already ran): suggestions come from the core and keep their reason keys.
        s.refresh_case(true);
        for sl in &s.case.as_ref().unwrap().suggestions {
            assert!(!s.suggestion_text(sl).is_empty());
        }
    }

    #[test]
    fn verify_options_map_to_the_run_config() {
        let d = tempfile::tempdir().unwrap();
        let case = sample_case(d.path());
        let mut s = hub(d.path());
        let tools = vec![fake_tool(
            d.path(),
            "rv-hashinv",
            SignatureStatus::SignedRakvor,
        )];
        s.apply_discovery(tools.clone());
        s.open_case(&case.display().to_string());
        s.verify.set_rehash(true);
        s.verify.set_evidence_dir("E:\\copies");
        s.verify.set_crosscheck(false);
        s.verify.toggle_algo(rv_hub_core::HashAlgo::Blake3).unwrap();
        s.verify.set_lang("all");
        s.verify.set_jurisdiction("fr");
        s.verify.set_timestamp(false, "http://tsa.example");
        let cfg = s.verify_config().unwrap();
        assert_eq!(cfg.case_dir, case);
        assert!(cfg.rehash);
        assert_eq!(cfg.evidence_dirs, vec![PathBuf::from("E:\\copies")]);
        assert_eq!(cfg.crosscheck, rv_hub_core::CrossCheckMode::Off);
        assert_eq!(
            cfg.algorithms,
            vec![rv_hub_core::HashAlgo::Sha256, rv_hub_core::HashAlgo::Blake3]
        );
        assert_eq!(cfg.langs, vec!["en", "es", "fr"]);
        assert_eq!(cfg.jurisdiction, "fr");
        assert!(cfg.tsa_url.is_none());
        assert_eq!(cfg.frontend, "gui");
        assert_eq!(cfg.tools.as_ref().map(|t| t.len()), Some(1));
        assert_eq!(cfg.actor, "Examiner Test");
        // The option changes are in the run's preamble and in the hub session log.
        let pre: Vec<&str> = cfg.preamble.iter().map(|(a, _)| a.as_str()).collect();
        assert!(pre.contains(&"ui_rehash_changed") && pre.contains(&"ui_start_clicked"));
        let log = session_actions(&s);
        for a in [
            "ui_rehash_changed",
            "ui_crosscheck_changed",
            "ui_hash_selection_changed",
            "ui_verify_started",
        ] {
            assert!(log.iter().any(|x| x == a), "{a} in the session log");
        }
        // Sync is idempotent: no duplicates.
        s.sync_verify_audit();
        assert_eq!(
            session_actions(&s)
                .iter()
                .filter(|a| *a == "ui_rehash_changed")
                .count(),
            1
        );
        // Run it for real (offline, no cross-check) and check the results table and the case refresh.
        s.verify.set_rehash(false);
        let cfg = s.verify_config().unwrap();
        s.verify_started();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let v = &mut s.verify;
        rv_hub_core::run(&cfg, &mut |e| v.apply(e), &cancel).unwrap();
        s.verify_finished();
        let items = &s.verify.items;
        assert_eq!(items[0].kind, rv_hub_core::report::ItemKind::CaseLog);
        assert!(
            items
                .iter()
                .filter(|i| i.kind == rv_hub_core::report::ItemKind::Run)
                .count()
                >= 4
        );
        assert!(items.iter().all(|i| i.status == "ok"), "{items:?}");
        assert!(items.iter().any(|i| i.label.starts_with("rv-pdfauth / ")));
        assert!(
            s.case
                .as_ref()
                .unwrap()
                .runs
                .iter()
                .any(|r| r.tool == "rv-hub"),
            "the verification run appears in the case view"
        );
        let rf = s.run_folder_to_open().unwrap();
        assert!(rf.starts_with(case.join("runs/rv-hub")) && !rf.ends_with("logs"));
        assert!(
            s.report_to_open()
                .unwrap()
                .to_string_lossy()
                .ends_with(".html")
        );
    }

    #[test]
    fn settings_are_saved_on_change_and_reloaded() {
        let d = tempfile::tempdir().unwrap();
        let portable = d.path().join("usb");
        std::fs::create_dir_all(&portable).unwrap();
        let case = sample_case(d.path());
        {
            let mut s = hub(d.path());
            assert!(s.add_folder(&format!("\"{}\"", portable.display())));
            assert!(
                !s.add_folder(&portable.display().to_string()),
                "already added"
            );
            assert!(!s.add_folder(&d.path().join("missing").display().to_string()));
            s.set_ui_lang("es");
            s.open_case(&case.display().to_string());
            assert!(s.settings_path.is_some());
            assert_eq!(s.discover_options().user_folders, vec![portable.clone()]);
        }
        let mut s = hub(d.path());
        assert_eq!(s.settings.user_folders, vec![portable.clone()]);
        assert_eq!(s.settings.recent_cases, vec![case]);
        assert_eq!(s.ui_lang, "es");
        assert_eq!(s.verify.ui_lang, "es");
        assert!(s.remove_folder(0));
        assert!(hub(d.path()).settings.user_folders.is_empty());
    }

    #[test]
    fn unwritable_data_folder_falls_back() {
        let d = tempfile::tempdir().unwrap();
        let blocked = d.path().join("blocked");
        std::fs::write(&blocked, b"file").unwrap();
        let fallback = d.path().join("fallback");
        let mut s = HubState::new(vec![blocked.clone(), fallback.clone()], "x");
        assert!(s.session.as_ref().unwrap().dir.starts_with(&fallback));
        s.set_ui_lang("fr");
        assert!(s.settings_path.as_ref().unwrap().starts_with(&fallback));
        assert_eq!(s.notice.as_ref().unwrap().tone, Tone::Amber);
        // Nothing writable: no session (launching refused, with a message), settings in memory.
        let mut s = HubState::new(vec![blocked], "x");
        assert!(s.session.is_none() && s.notice.is_some());
        s.set_ui_lang("es");
        assert!(s.settings_path.is_none());
        s.apply_discovery(vec![fake_tool(
            d.path(),
            "rv-hashinv",
            SignatureStatus::SignedRakvor,
        )]);
        s.case = None;
        let rec = Recorder::default();
        let v = StaticVerifier::always(SignatureStatus::SignedRakvor);
        let env = LaunchEnv {
            verifier: &v,
            spawner: &rec,
        };
        s.request_launch(0, "tools", &env);
        assert!(matches!(s.confirm_pending(&env), LaunchStep::Refused(_)));
        assert!(rec.0.borrow().is_empty());
        assert_eq!(s.audited_actions()[0], "ui_interface_language_changed");
    }

    #[test]
    fn tabs_and_language_are_audited() {
        let d = tempfile::tempdir().unwrap();
        let mut s = hub(d.path());
        s.set_tab(Tab::Case);
        s.set_tab(Tab::Case);
        s.set_ui_lang("de");
        s.set_ui_lang("fr");
        assert_eq!(s.tr("tab_case"), "Dossier");
        assert_eq!(
            s.audited_actions(),
            ["ui_tab_selected", "ui_interface_language_changed"]
        );
        assert!(s.audit_trail.iter().all(|(_, d)| d["at_utc"].is_string()));
    }

    #[test]
    fn every_ui_key_exists_in_every_language() {
        fn ui_keys(lang: &str) -> Vec<String> {
            let text = match lang {
                "en" => include_str!("../../../../i18n/en.json"),
                "es" => include_str!("../../../../i18n/es.json"),
                _ => include_str!("../../../../i18n/fr.json"),
            };
            let v: Value = serde_json::from_str(text).unwrap();
            let mut k: Vec<String> = v["ui"].as_object().unwrap().keys().cloned().collect();
            k.sort();
            k
        }
        let en = ui_keys("en");
        assert_eq!(en, ui_keys("es"), "es ui keys differ from en");
        assert_eq!(en, ui_keys("fr"), "fr ui keys differ from en");
        for l in ["en", "es", "fr"] {
            let c = i18n::catalog(l);
            for k in UI_KEYS {
                assert!(en.iter().any(|e| e == k), "{k} missing in {l}");
                assert_ne!(c.ui(k), *k, "{k} not worded in {l}");
            }
            for b in [
                Badge::SignedRakvor,
                Badge::Unsigned,
                Badge::OtherRoot,
                Badge::Invalid,
                Badge::NotChecked,
            ] {
                assert!(UI_KEYS.contains(&b.label_key()));
                if let Some(r) = b.risk_key() {
                    assert!(UI_KEYS.contains(&r));
                }
            }
        }
        // Placeholders survive translation.
        for l in ["en", "es", "fr"] {
            let c = i18n::catalog(l);
            assert!(c.ui("launched").contains("%{tool}") && c.ui("launched").contains("%{pid}"));
            assert!(c.ui("confirm_untrusted").contains("%{tool}"));
        }
    }
}
