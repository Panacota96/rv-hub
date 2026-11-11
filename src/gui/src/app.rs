//! The window. Drawing only: rules live in `state`, work lives in the core (discovery and verification on worker
//! threads). Rakvor dark theme; three tabs (Tools, Case, Verify); interface language EN/ES/FR switchable at any
//! time (texts from i18n "ui").

use crate::state::{
    Badge, CaseModel, HubState, LaunchEnv, LaunchTarget, Phase, Tab, Tone, ToolCard,
};
use eframe::egui;
use rv_hub_core::launch::{DetachedSpawner, Spawner};
use rv_hub_core::report::ItemKind;
use rv_hub_core::signature::{OsVerifier, SignatureStatus, SignatureVerifier};
use rv_hub_core::suggest::Action;
use rv_hub_core::tools::ToolInfo;
use rv_hub_core::{Event, HashAlgo, RunConfig, RunSummary, TOOL_VERSION};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

// Rakvor palette
const NIGHT: egui::Color32 = egui::Color32::from_rgb(0x0D, 0x11, 0x17);
const NIGHT2: egui::Color32 = egui::Color32::from_rgb(0x1A, 0x1F, 0x26);
const EDGE: egui::Color32 = egui::Color32::from_rgb(0x2B, 0x32, 0x40);
const BLUE: egui::Color32 = egui::Color32::from_rgb(0x2A, 0x5C, 0xFF);
const VIOLET: egui::Color32 = egui::Color32::from_rgb(0x6B, 0x00, 0xFF);
const CYAN: egui::Color32 = egui::Color32::from_rgb(0x00, 0xE5, 0xFF);
const MIST: egui::Color32 = egui::Color32::from_rgb(0xE6, 0xE6, 0xE6);
const GREEN: egui::Color32 = egui::Color32::from_rgb(0x3F, 0xB9, 0x50);
const AMBER: egui::Color32 = egui::Color32::from_rgb(0xFF, 0xB0, 0x40);
const RED: egui::Color32 = egui::Color32::from_rgb(0xFF, 0x6B, 0x6B);
const GREY: egui::Color32 = egui::Color32::from_rgb(0x8B, 0x94, 0x9E);
const UI_LANGS: [(&str, &str); 3] = [("en", "English"), ("es", "Español"), ("fr", "Français")];

fn tone_color(t: Tone) -> egui::Color32 {
    match t {
        Tone::Green => GREEN,
        Tone::Amber => AMBER,
        Tone::Red => RED,
        Tone::Grey => GREY,
    }
}

enum Msg {
    Event(Event),
    Done(Box<Result<RunSummary, rv_hub_core::case::CaseError>>),
}

pub struct HubApp {
    state: HubState,
    verifier: Box<dyn SignatureVerifier>,
    spawner: Box<dyn Spawner>,
    rx: Option<Receiver<Msg>>,
    discover_rx: Option<Receiver<Vec<ToolInfo>>>,
    cancel: Arc<AtomicBool>,
    started: Option<Instant>,
    themed: bool,
    /// The window had the focus in the last frame (the case view is re-read when it comes back).
    focused: bool,
    /// Text being typed; applied (and audited) on Enter or a button.
    case_entry: String,
    create_entry: String,
    folder_entry: String,
    verify_case_entry: String,
    case_evidence_entry: String,
    verify_evidence_entry: String,
    tsa_ca_entry: String,
}

/// Applies the Rakvor dark theme.
pub fn apply_theme(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = NIGHT;
    v.window_fill = NIGHT2;
    v.extreme_bg_color = NIGHT2; // text fields
    v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, EDGE);
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, EDGE);
    v.faint_bg_color = egui::Color32::from_rgb(0x14, 0x19, 0x20);
    v.override_text_color = Some(MIST);
    v.selection.bg_fill = BLUE;
    v.hyperlink_color = CYAN;
    v.widgets.inactive.bg_fill = NIGHT2;
    v.widgets.inactive.weak_bg_fill = NIGHT2;
    v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, CYAN);
    v.widgets.active.bg_fill = BLUE;
    ctx.set_visuals(v);
}

impl HubApp {
    /// The real window: settings and session log in the hub data folder, OS signature check, detached spawner.
    pub fn new() -> Self {
        Self::from_parts(
            HubState::start_default(),
            Box::new(OsVerifier),
            Box::new(DetachedSpawner),
        )
    }

    /// A window over an existing state (headless rendering, e.g. the documentation screenshots). No discovery
    /// is started when the state already holds one.
    pub fn from_parts(
        state: HubState,
        verifier: Box<dyn SignatureVerifier>,
        spawner: Box<dyn Spawner>,
    ) -> Self {
        let case_entry = state
            .case
            .as_ref()
            .map(|c| c.view.dir.display().to_string())
            .unwrap_or_default();
        let verify_case_entry = state.verify.case_dir.clone();
        let case_evidence_entry = state.verify.evidence_dir.clone();
        let verify_evidence_entry = state.verify.evidence_dir.clone();
        let tsa_ca_entry = state.verify.tsa_ca.clone();
        let mut app = HubApp {
            state,
            verifier,
            spawner,
            rx: None,
            discover_rx: None,
            cancel: Arc::new(AtomicBool::new(false)),
            started: None,
            themed: false,
            focused: true,
            case_entry,
            create_entry: String::new(),
            folder_entry: String::new(),
            verify_case_entry,
            case_evidence_entry,
            verify_evidence_entry,
            tsa_ca_entry,
        };
        if !app.state.discovered {
            app.state.discovering = true;
        }
        app
    }

    /// `--case-dir DIR` (or a folder given to the executable) opens that case.
    pub fn with_args(args: impl IntoIterator<Item = std::ffi::OsString>) -> Self {
        let mut app = Self::new();
        let args: Vec<std::ffi::OsString> = args.into_iter().collect();
        let dir = match args.iter().position(|a| a == "--case-dir") {
            Some(i) => args.get(i + 1).cloned(),
            None => args.first().cloned(),
        };
        if let Some(d) = dir {
            let text = PathBuf::from(d).display().to_string();
            app.state.audit(
                "ui_case_dir_from_launcher",
                serde_json::json!({"path": text}),
            );
            if app.state.open_case(&text) {
                app.state.set_tab(Tab::Case);
            }
            app.sync_entries();
        }
        app
    }

    pub fn state(&self) -> &HubState {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut HubState {
        &mut self.state
    }

    fn sync_entries(&mut self) {
        if let Some(c) = &self.state.case {
            self.case_entry = c.view.dir.display().to_string();
        }
        self.verify_case_entry = self.state.verify.case_dir.clone();
        self.case_evidence_entry = self.state.verify.evidence_dir.clone();
        self.verify_evidence_entry = self.state.verify.evidence_dir.clone();
        self.tsa_ca_entry = self.state.verify.tsa_ca.clone();
    }

    /// Applies (and so audits) text still being edited in the option fields. Called before the tab changes and
    /// before a verification starts: a field that is no longer drawn never sees its focus loss.
    fn commit_entries(&mut self) {
        let norm = |t: &str| t.trim().trim_matches('"').to_string();
        let v = &self.state.verify;
        let (case_ev, verify_ev, tsa) = (
            norm(&self.case_evidence_entry),
            norm(&self.verify_evidence_entry),
            norm(&self.tsa_ca_entry),
        );
        if case_ev != v.evidence_dir {
            self.state.set_evidence_dir(&case_ev);
        } else if verify_ev != v.evidence_dir {
            self.state.verify.set_evidence_dir(&verify_ev);
        }
        if tsa != self.state.verify.tsa_ca {
            self.state.verify.set_tsa_ca(&tsa);
        }
        self.sync_option_entries();
    }

    /// The option fields show the state again (after a commit, or a refused value).
    fn sync_option_entries(&mut self) {
        self.case_evidence_entry = self.state.verify.evidence_dir.clone();
        self.verify_evidence_entry = self.state.verify.evidence_dir.clone();
        self.tsa_ca_entry = self.state.verify.tsa_ca.clone();
    }

    // ---- workers ------------------------------------------------------------------------------------------

    fn start_discovery(&mut self, ctx: &egui::Context) {
        let opts = self.state.discover_options();
        let (tx, rx) = channel();
        self.discover_rx = Some(rx);
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let tools = rv_hub_core::tools::discover(&opts, &OsVerifier);
            let _ = tx.send(tools);
            repaint.request_repaint();
        });
    }

    fn poll_discovery(&mut self, ctx: &egui::Context) {
        if self.state.discovering && self.discover_rx.is_none() {
            self.start_discovery(ctx);
        }
        let Some(rx) = &self.discover_rx else { return };
        if let Ok(tools) = rx.try_recv() {
            self.discover_rx = None;
            self.state.apply_discovery(tools);
        }
    }

    fn start_verify(&mut self, ctx: &egui::Context) {
        self.commit_entries();
        let cfg: RunConfig = match self.state.verify_config() {
            Ok(c) => c,
            Err(e) => {
                self.state.notice = Some(crate::state::Notice {
                    tone: Tone::Amber,
                    text: e,
                });
                return;
            }
        };
        self.state.notice = None;
        self.state.verify_started();
        self.cancel.store(false, Ordering::SeqCst);
        self.started = Some(Instant::now());
        let (tx, rx) = channel();
        self.rx = Some(rx);
        let cancel = self.cancel.clone();
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let tx2 = tx.clone();
            let r2 = repaint.clone();
            let mut sink = move |e: &Event| {
                let _ = tx2.send(Msg::Event(e.clone()));
                r2.request_repaint();
            };
            let result = rv_hub_core::run(&cfg, &mut sink, &cancel);
            let _ = tx.send(Msg::Done(Box::new(result)));
            repaint.request_repaint();
        });
    }

    fn drain(&mut self) {
        let Some(rx) = &self.rx else { return };
        let mut finished = false;
        while let Ok(m) = rx.try_recv() {
            match m {
                Msg::Event(e) => {
                    if let Event::Timestamp { status, reason, .. } = &e
                        && status != "ok"
                    {
                        self.state
                            .verify
                            .warnings
                            .push(format!("timestamp: {}", reason.as_deref().unwrap_or("-")));
                    }
                    self.state.verify.apply(&e)
                }
                Msg::Done(r) => {
                    if let Err(e) = *r {
                        self.state.verify.fail(e.message);
                    }
                    finished = true;
                }
            }
        }
        if finished {
            self.rx = None;
            self.started = None;
            self.state.verify_finished();
        }
    }

    fn launch_tool(&mut self, index: usize, origin: &str) {
        let env = LaunchEnv {
            verifier: &*self.verifier,
            spawner: &*self.spawner,
        };
        self.state.request_launch(index, origin, &env);
    }

    // ---- common chrome ------------------------------------------------------------------------------------

    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(egui::vec2(38.0, 38.0), egui::Sense::hover());
            ui.painter().rect(
                rect,
                8.0,
                NIGHT2,
                egui::Stroke::new(2.0, BLUE),
                egui::StrokeKind::Inside,
            );
            ui.painter().text(
                rect.center() - egui::vec2(0.0, 3.0),
                egui::Align2::CENTER_CENTER,
                "RV",
                egui::FontId::proportional(16.0),
                MIST,
            );
            ui.painter().line_segment(
                [
                    rect.center() + egui::vec2(-8.0, 10.0),
                    rect.center() + egui::vec2(8.0, 10.0),
                ],
                egui::Stroke::new(2.0, CYAN),
            );
            ui.vertical(|ui| {
                ui.label(
                    egui::RichText::new("R A K V O R  ·  RV Hub")
                        .strong()
                        .size(16.0),
                );
                let desc = rv_hub_core::i18n::catalog(&self.state.ui_lang).brand()["descriptor"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                ui.label(egui::RichText::new(desc).color(CYAN).size(10.0));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let current = UI_LANGS
                    .iter()
                    .find(|(k, _)| *k == self.state.ui_lang)
                    .map(|(_, v)| *v)
                    .unwrap_or("English");
                let mut chosen = None;
                egui::ComboBox::from_id_salt("ui-lang")
                    .selected_text(current)
                    .show_ui(ui, |ui| {
                        for (k, v) in UI_LANGS {
                            if ui.selectable_label(self.state.ui_lang == k, v).clicked() {
                                chosen = Some(k);
                            }
                        }
                    });
                if let Some(k) = chosen {
                    self.state.set_ui_lang(k);
                }
                ui.label(self.state.tr("ui_lang"));
                ui.weak(format!("v{}", TOOL_VERSION));
            });
        });
        let (r, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 3.0), egui::Sense::hover());
        let third = r.width() / 3.0;
        for (i, c) in [BLUE, VIOLET, CYAN].iter().enumerate() {
            ui.painter().rect_filled(
                egui::Rect::from_min_size(
                    r.min + egui::vec2(third * i as f32, 0.0),
                    egui::vec2(third, 3.0),
                ),
                0.0,
                *c,
            );
        }
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            for t in Tab::ALL {
                let on = self.state.tab == t;
                let text = egui::RichText::new(self.state.tr(t.key())).size(15.0);
                let text = if on { text.strong().color(CYAN) } else { text };
                let b = egui::Button::new(text)
                    .fill(if on { NIGHT2 } else { NIGHT })
                    .stroke(egui::Stroke::new(1.0, if on { CYAN } else { EDGE }))
                    .min_size(egui::vec2(110.0, 28.0));
                if ui.add(b).clicked() {
                    self.commit_entries();
                    self.state.set_tab(t);
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.weak(self.state.tr("audit_note"));
            });
        });
        if let Some(n) = self.state.notice.clone() {
            ui.horizontal(|ui| {
                ui.colored_label(tone_color(n.tone), &n.text);
                if ui.small_button("✕").clicked() {
                    self.state.dismiss_notice();
                }
            });
        }
        ui.separator();
    }

    fn section_title(ui: &mut egui::Ui, text: String) {
        ui.add_space(6.0);
        ui.label(egui::RichText::new(text).color(CYAN).strong().size(15.0));
    }

    fn pill(ui: &mut egui::Ui, text: &str, color: egui::Color32) -> egui::Response {
        egui::Frame::new()
            .fill(color.gamma_multiply(0.18))
            .stroke(egui::Stroke::new(1.0, color))
            .corner_radius(10.0)
            .inner_margin(egui::Margin::symmetric(8, 2))
            .show(ui, |ui| {
                ui.label(egui::RichText::new(text).color(color).size(12.0).strong());
            })
            .response
    }

    fn card_frame() -> egui::Frame {
        egui::Frame::new()
            .fill(NIGHT2)
            .stroke(egui::Stroke::new(1.0, EDGE))
            .corner_radius(8.0)
            .inner_margin(egui::Margin::same(12))
    }

    // ---- Tools tab ----------------------------------------------------------------------------------------

    fn tools_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            Self::section_title(ui, self.state.tr("tools_title"));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_enabled_ui(!self.state.discovering, |ui| {
                    if ui.button(self.state.tr("refresh")).clicked() {
                        self.state.request_refresh_tools();
                    }
                });
                if self.state.discovering {
                    ui.spinner();
                    ui.weak(self.state.tr("discovering"));
                }
            });
        });
        ui.weak(self.state.tr("tools_help"));
        match &self.state.case {
            Some(c) => ui.label(format!(
                "{}: {}",
                self.state.tr("launch_tip_case"),
                c.view.dir.display()
            )),
            None => ui.weak(self.state.tr("launch_tip_no_case")),
        };
        ui.add_space(6.0);
        let cards = self.state.cards.clone();
        let per_row = if ui.available_width() > 900.0 { 2 } else { 1 };
        for row in cards.chunks(per_row) {
            ui.columns(per_row, |cols| {
                for (col, card) in cols.iter_mut().zip(row) {
                    self.tool_card(col, card);
                }
            });
            ui.add_space(8.0);
        }
        self.folders_section(ui);
    }

    fn tool_card(&mut self, ui: &mut egui::Ui, c: &ToolCard) {
        let tr = |k: &str| self.state.tr(k);
        let mut launch = false;
        ui.scope(|ui| {
            if !c.installed {
                ui.multiply_opacity(0.45);
            }
            Self::card_frame().show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&c.title).strong().size(17.0));
                    ui.weak(&c.tool);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if c.installed {
                            let r = Self::pill(
                                ui,
                                &tr(c.badge.label_key()),
                                tone_color(c.badge.tone()),
                            );
                            let detail = match &c.signature {
                                SignatureStatus::SignedOtherRoot { root_sha256 } => {
                                    format!("root SHA-256 {root_sha256}")
                                }
                                SignatureStatus::Invalid { reason }
                                | SignatureStatus::NotChecked { reason } => reason.clone(),
                                _ => String::new(),
                            };
                            if !detail.is_empty() {
                                r.on_hover_text(detail);
                            }
                        } else {
                            Self::pill(ui, &tr("not_installed"), GREY);
                        }
                    });
                });
                if c.installed {
                    let sources: Vec<String> = c.sources.iter().map(|k| tr(k)).collect();
                    ui.label(format!(
                        "{}: {}   ·   {}: {}",
                        tr("version"),
                        c.version.clone().unwrap_or_else(|| tr("version_unknown")),
                        tr("source"),
                        sources.join(", ")
                    ));
                    ui.label(
                        egui::RichText::new(format!("{}: {}", tr("install_path"), c.path))
                            .weak()
                            .monospace()
                            .size(11.5),
                    );
                    if c.builtin_describe {
                        ui.weak(tr("builtin_describe"));
                    }
                    for w in &c.warnings {
                        ui.colored_label(AMBER, w);
                    }
                } else {
                    ui.label(tr("not_installed"));
                    ui.add_space(14.0);
                }
                ui.add_space(4.0);
                let tip = if self.state.case.is_some() {
                    tr("launch_tip_case")
                } else {
                    tr("launch_tip_no_case")
                };
                let fill = if c.badge == Badge::SignedRakvor {
                    BLUE
                } else {
                    NIGHT
                };
                let b = egui::Button::new(
                    egui::RichText::new(tr("launch"))
                        .strong()
                        .color(egui::Color32::WHITE),
                )
                .fill(fill)
                .min_size(egui::vec2(96.0, 26.0));
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(c.can_launch(), b)
                        .on_hover_text(tip)
                        .clicked()
                    {
                        launch = true;
                    }
                });
            });
        });
        if launch && let Some(i) = c.tool_index {
            self.launch_tool(i, "tools");
        }
    }

    fn folders_section(&mut self, ui: &mut egui::Ui) {
        Self::section_title(ui, self.state.tr("folders_title"));
        let mut remove = None;
        for (i, f) in self.state.settings.user_folders.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.monospace(f.display().to_string());
                if ui.small_button(self.state.tr("remove")).clicked() {
                    remove = Some(i);
                }
            });
        }
        if let Some(i) = remove {
            self.state.remove_folder(i);
        }
        ui.horizontal(|ui| {
            ui.label(self.state.tr("add_folder"));
            let r = ui.add(
                egui::TextEdit::singleline(&mut self.folder_entry)
                    .hint_text(self.state.tr("add_folder_hint"))
                    .desired_width(320.0),
            );
            let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            #[cfg(windows)]
            if ui.button(self.state.tr("browse")).clicked()
                && let Some(d) = rfd::FileDialog::new().pick_folder()
            {
                self.folder_entry = d.display().to_string();
            }
            if ui.button(self.state.tr("add")).clicked() || enter {
                let text = self.folder_entry.clone();
                if self.state.add_folder(&text) {
                    self.folder_entry.clear();
                }
            }
        });
    }

    // ---- confirmation dialog ------------------------------------------------------------------------------

    fn confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(p) = self.state.pending.clone() else {
            return;
        };
        let title = self
            .state
            .tools
            .get(p.tool_index)
            .map(|t| t.title.clone())
            .unwrap_or(p.tool.clone());
        let mut go = false;
        let mut cancel = false;
        let resp = egui::Modal::new(egui::Id::unique("confirm-launch")).show(ctx, |ui| {
            ui.set_max_width(520.0);
            ui.label(
                egui::RichText::new(self.state.tr("confirm_title"))
                    .strong()
                    .size(17.0)
                    .color(CYAN),
            );
            ui.add_space(6.0);
            if let Some(s) = &p.untrusted {
                let b = Badge::of(s);
                let status = self.state.tr(b.label_key());
                Self::pill(ui, &status, tone_color(b.tone()));
                ui.label(
                    egui::RichText::new(self.state.trf(
                        "confirm_untrusted",
                        &[("tool", &title), ("status", &status)],
                    ))
                    .strong(),
                );
                if let Some(k) = p.risk_key() {
                    ui.colored_label(tone_color(b.tone()), self.state.tr(k));
                }
                if let Some(exe) = self
                    .state
                    .tools
                    .get(p.tool_index)
                    .and_then(|t| t.gui_exe.as_ref())
                {
                    ui.weak(exe.display().to_string());
                }
            }
            match &p.target {
                LaunchTarget::NoCase => {
                    ui.label(self.state.trf("confirm_no_case", &[("tool", &title)]));
                }
                LaunchTarget::Case(d) => {
                    ui.label(format!("--case-dir {}", d.display()));
                }
            }
            ui.weak(self.state.tr("confirm_recorded"));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let label = if p.untrusted.is_some() {
                    self.state.tr("confirm_go_untrusted")
                } else {
                    self.state.tr("confirm_go")
                };
                let fill = if p.untrusted.is_some() {
                    RED.gamma_multiply(0.6)
                } else {
                    BLUE
                };
                if ui
                    .add(egui::Button::new(egui::RichText::new(label).strong()).fill(fill))
                    .clicked()
                {
                    go = true;
                }
                if ui.button(self.state.tr("cancel")).clicked() {
                    cancel = true;
                }
            });
        });
        if resp.should_close() && !go {
            cancel = true;
        }
        if go {
            let env = LaunchEnv {
                verifier: &*self.verifier,
                spawner: &*self.spawner,
            };
            self.state.confirm_pending(&env);
            self.sync_entries();
        } else if cancel {
            self.state.cancel_pending();
        }
    }

    // ---- Case tab -----------------------------------------------------------------------------------------

    fn case_tab(&mut self, ui: &mut egui::Ui) {
        Self::section_title(ui, self.state.tr("case_title"));
        ui.horizontal(|ui| {
            let r = ui.add(
                egui::TextEdit::singleline(&mut self.case_entry)
                    .hint_text(self.state.tr("case_open_hint"))
                    .desired_width(380.0),
            );
            let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            #[cfg(windows)]
            if ui.button(self.state.tr("browse")).clicked()
                && let Some(d) = rfd::FileDialog::new().pick_folder()
            {
                self.case_entry = d.display().to_string();
                let t = self.case_entry.clone();
                self.state.open_case(&t);
            }
            if ui.button(self.state.tr("case_open")).clicked() || enter {
                let t = self.case_entry.clone();
                self.state.open_case(&t);
                self.sync_entries();
            }
            if self.state.case.is_some() {
                if ui.button(self.state.tr("refresh")).clicked() {
                    self.state.refresh_case(true);
                }
                if ui.button(self.state.tr("case_close")).clicked() {
                    self.state.close_case();
                }
            }
            let recent = self.state.settings.recent_cases.clone();
            if !recent.is_empty() {
                let mut chosen = None;
                egui::ComboBox::from_id_salt("recent")
                    .selected_text(self.state.tr("recent"))
                    .show_ui(ui, |ui| {
                        for r in &recent {
                            if ui
                                .selectable_label(false, r.display().to_string())
                                .clicked()
                            {
                                chosen = Some(r.clone());
                            }
                        }
                    });
                if let Some(r) = chosen {
                    self.state.open_case(&r.display().to_string());
                    self.sync_entries();
                }
            }
        });
        // A folder dropped on the window is opened as the case.
        let dropped: Option<PathBuf> = ui.ctx().input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .find(|p| p.is_dir())
        });
        if let Some(d) = dropped {
            self.state.open_case(&d.display().to_string());
            self.sync_entries();
        }
        ui.horizontal(|ui| {
            ui.label(self.state.tr("create_case"));
            ui.add(
                egui::TextEdit::singleline(&mut self.create_entry)
                    .hint_text(self.state.tr("create_hint"))
                    .desired_width(300.0),
            );
            #[cfg(windows)]
            if ui.button(self.state.tr("browse")).clicked()
                && let Some(d) = rfd::FileDialog::new().pick_folder()
            {
                self.create_entry = d.display().to_string();
            }
            if ui.button(self.state.tr("create_case")).clicked() {
                let env = LaunchEnv {
                    verifier: &*self.verifier,
                    spawner: &*self.spawner,
                };
                let t = self.create_entry.clone();
                self.state.request_create_case(&t, &env);
                self.sync_entries();
            }
        })
        .response
        .on_hover_text(self.state.tr("create_case_help"));
        ui.weak(self.state.tr("create_case_help"));
        ui.separator();
        let Some(c) = self.state.case.clone() else {
            ui.label(self.state.tr("no_case_open"));
            return;
        };
        self.case_header(ui, &c);
        let tr = |k: &str| self.state.tr(k);
        Self::section_title(ui, tr("evidence_title"));
        if c.evidence.is_empty() {
            ui.weak(tr("evidence_none"));
        } else {
            egui::Grid::new("evidence")
                .striped(true)
                .num_columns(4)
                .spacing([18.0, 4.0])
                .show(ui, |ui| {
                    for h in ["col_id", "col_file", "col_size", "col_examined"] {
                        ui.label(egui::RichText::new(tr(h)).strong());
                    }
                    ui.end_row();
                    for e in &c.evidence {
                        ui.monospace(&e.id);
                        match &e.superseded_by {
                            Some(s) => ui.label(format!(
                                "{}  ({})",
                                e.file,
                                self.state.trf("superseded", &[("id", s)])
                            )),
                            None => ui.label(&e.file),
                        };
                        ui.label(&e.size);
                        ui.label(&e.examined_by);
                        ui.end_row();
                    }
                });
        }
        Self::section_title(ui, tr("runs_title"));
        if c.runs.is_empty() {
            ui.weak(tr("runs_none"));
        } else {
            egui::Grid::new("runs")
                .striped(true)
                .num_columns(6)
                .spacing([18.0, 4.0])
                .show(ui, |ui| {
                    for h in [
                        "col_tool",
                        "col_run",
                        "col_time",
                        "col_findings",
                        "col_timestamp",
                        "col_status",
                    ] {
                        ui.label(egui::RichText::new(tr(h)).strong());
                    }
                    ui.end_row();
                    for r in &c.runs {
                        ui.label(&r.tool);
                        ui.monospace(&r.run_id);
                        ui.label(&r.time);
                        match &r.findings {
                            Some(s) => {
                                ui.horizontal(|ui| {
                                    ui.colored_label(
                                        if s.high > 0 { RED } else { GREY },
                                        s.high.to_string(),
                                    );
                                    ui.label("/");
                                    ui.colored_label(
                                        if s.medium > 0 { AMBER } else { GREY },
                                        s.medium.to_string(),
                                    );
                                    ui.label("/");
                                    ui.colored_label(GREY, s.low.to_string());
                                    ui.label("/");
                                    ui.colored_label(GREY, s.info.to_string());
                                });
                            }
                            None => {
                                ui.weak("—");
                            }
                        }
                        let ts = match r.timestamp_key {
                            "ts_obtained" => GREEN,
                            "ts_pending" => AMBER,
                            _ => GREY,
                        };
                        ui.colored_label(ts, tr(r.timestamp_key));
                        let st = match r.status_key {
                            "st_completed" => MIST,
                            "st_running" | "st_cancelled" => AMBER,
                            _ => RED,
                        };
                        ui.colored_label(st, tr(r.status_key));
                        ui.end_row();
                    }
                });
        }
        Self::section_title(ui, tr("totals_title"));
        ui.horizontal(|ui| {
            let cat = rv_hub_core::i18n::catalog(&self.state.ui_lang);
            let s = c.view.severity;
            for (k, n, col) in [
                ("high", s.high, RED),
                ("medium", s.medium, AMBER),
                ("low", s.low, CYAN),
                ("info", s.info, GREY),
            ] {
                Self::pill(
                    ui,
                    &format!("{}  {}", cat.severity(k), n),
                    if n > 0 { col } else { GREY },
                );
            }
        });
        Self::section_title(ui, tr("problems_title"));
        if c.view.problems.is_empty() {
            ui.weak(tr("no_problems"));
        } else {
            for p in &c.view.problems {
                ui.colored_label(AMBER, format!("• {p}"));
            }
        }
        self.evidence_dir_row(ui);
        self.suggestions(ui, &c);
    }

    /// Where the evidence copies are now: the suggestions read a file's content there when it is not at its
    /// registered path (`rv-hub case --evidence-dir`); the same value is the Verify tab's re-hash folder.
    fn evidence_dir_row(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(self.state.tr("evidence_dir"));
            let hint = self.state.tr("case_evidence_dir_hint");
            let r = ui.add(
                egui::TextEdit::singleline(&mut self.case_evidence_entry)
                    .hint_text(hint)
                    .desired_width(300.0),
            );
            if !r.has_focus() && !r.lost_focus() {
                self.case_evidence_entry = self.state.verify.evidence_dir.clone();
            }
            if r.lost_focus() {
                let entry = self.case_evidence_entry.clone();
                self.state.set_evidence_dir(&entry);
                self.sync_option_entries();
            }
            #[cfg(windows)]
            if ui.button(self.state.tr("browse")).clicked()
                && let Some(p) = rfd::FileDialog::new().pick_folder()
            {
                self.state.set_evidence_dir(&p.display().to_string());
                self.sync_option_entries();
            }
        });
    }

    fn case_header(&self, ui: &mut egui::Ui, c: &CaseModel) {
        let tr = |k: &str| self.state.tr(k);
        Self::card_frame().show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            if !c.is_case {
                ui.colored_label(AMBER, tr("not_a_case_yet"));
            }
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!(
                        "{}  {}",
                        tr("case_id"),
                        c.view.case_id.clone().unwrap_or_else(|| "—".into())
                    ))
                    .strong()
                    .size(18.0),
                );
                let jur = match c.view.jurisdiction.as_deref() {
                    Some("fr") => tr("jur_fr"),
                    Some("co") => tr("jur_co"),
                    Some(o) => o.to_string(),
                    None => "—".into(),
                };
                Self::pill(ui, &jur, CYAN);
                let (key, col) = (
                    c.case_log_key(),
                    match c.view.case_log_intact {
                        Some(true) => GREEN,
                        Some(false) => RED,
                        None => GREY,
                    },
                );
                Self::pill(ui, &tr(key), col);
            });
            ui.label(
                egui::RichText::new(c.view.dir.display().to_string())
                    .monospace()
                    .weak(),
            );
            ui.weak(format!(
                "{}: {}   ·   {}: {}   ·   {}",
                tr("created"),
                c.view
                    .created_utc
                    .as_deref()
                    .map(crate::state::case::short_utc)
                    .unwrap_or_else(|| "—".into()),
                tr("read_at"),
                crate::state::case::short_utc(&c.read_utc),
                tr("read_only_note")
            ));
        });
    }

    fn suggestions(&mut self, ui: &mut egui::Ui, c: &CaseModel) {
        let title = rv_hub_core::i18n::catalog(&self.state.ui_lang).text("suggest", "title");
        Self::section_title(ui, title);
        if c.suggestions.is_empty() {
            ui.weak(self.state.tr("no_suggestions"));
            return;
        }
        let mut launch = None;
        for (i, s) in c.suggestions.iter().enumerate() {
            Self::card_frame().show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("»").color(CYAN).strong());
                    ui.label(self.state.suggestion_text(s));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let title = self
                            .state
                            .tools
                            .get(s.tool_index.unwrap_or(usize::MAX))
                            .map(|t| t.title.clone())
                            .unwrap_or(s.tool.clone());
                        if s.tool_index.is_some() {
                            let b = egui::Button::new(
                                egui::RichText::new(
                                    self.state.trf("launch_suggested", &[("tool", &title)]),
                                )
                                .strong()
                                .color(egui::Color32::WHITE),
                            )
                            .fill(BLUE);
                            if ui.add(b).clicked() {
                                launch = Some(i);
                            }
                        } else {
                            ui.weak(
                                self.state
                                    .trf("suggest_not_installed", &[("tool", &s.tool)]),
                            );
                        }
                    });
                });
                if s.action == Action::Timestamp {
                    ui.weak(self.state.tr("suggest_timestamp_hint"));
                }
            });
            ui.add_space(4.0);
        }
        if let Some(i) = launch {
            let env = LaunchEnv {
                verifier: &*self.verifier,
                spawner: &*self.spawner,
            };
            self.state.launch_suggestion(i, &env);
        }
    }

    // ---- Verify tab ---------------------------------------------------------------------------------------

    fn verify_tab(&mut self, ui: &mut egui::Ui) {
        let enabled = !self.state.verify.is_running();
        self.verify_case_section(ui, enabled);
        ui.columns(2, |cols| {
            self.hashing_section(&mut cols[0], enabled);
            self.report_section(&mut cols[0], enabled);
            self.trust_section(&mut cols[1], enabled);
        });
        self.run_section(ui);
        self.results_section(ui);
    }

    fn verify_case_section(&mut self, ui: &mut egui::Ui, enabled: bool) {
        Self::section_title(ui, self.state.tr("evidence"));
        ui.label(self.state.tr("evidence_help"));
        ui.add_enabled_ui(enabled, |ui| {
            ui.horizontal(|ui| {
                ui.label(self.state.tr("case_dir"));
                let hint = self.state.tr("case_dir_hint");
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.verify_case_entry)
                        .hint_text(hint)
                        .desired_width(380.0),
                );
                // Follows the open case unless the user is typing here.
                if !r.has_focus() && !r.lost_focus() {
                    self.verify_case_entry = self.state.verify.case_dir.clone();
                }
                if r.lost_focus() {
                    let entry = self.verify_case_entry.clone();
                    self.state.verify.set_case_dir(&entry);
                }
                #[cfg(windows)]
                if ui.button(self.state.tr("browse")).clicked()
                    && let Some(d) = rfd::FileDialog::new().pick_folder()
                {
                    self.verify_case_entry = d.display().to_string();
                    let entry = self.verify_case_entry.clone();
                    self.state.verify.set_case_dir(&entry);
                }
            });
            let mut rehash = self.state.verify.rehash;
            if ui.checkbox(&mut rehash, self.state.tr("rehash")).changed() {
                self.state.verify.set_rehash(rehash);
            }
            ui.add_enabled_ui(self.state.verify.rehash, |ui| {
                ui.horizontal(|ui| {
                    ui.label(self.state.tr("evidence_dir"));
                    let hint = self.state.tr("evidence_dir_hint");
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut self.verify_evidence_entry)
                            .hint_text(hint)
                            .desired_width(300.0),
                    );
                    if !r.has_focus() && !r.lost_focus() {
                        self.verify_evidence_entry = self.state.verify.evidence_dir.clone();
                    }
                    if r.lost_focus() {
                        let entry = self.verify_evidence_entry.clone();
                        self.state.verify.set_evidence_dir(&entry);
                        self.sync_option_entries();
                    }
                    #[cfg(windows)]
                    if ui.button(self.state.tr("browse")).clicked()
                        && let Some(p) = rfd::FileDialog::new().pick_folder()
                    {
                        self.state.verify.set_evidence_dir(&p.display().to_string());
                        self.sync_option_entries();
                    }
                });
            });
            let mut x = self.state.verify.crosscheck;
            if ui.checkbox(&mut x, self.state.tr("crosscheck")).changed() {
                self.state.verify.set_crosscheck(x);
            }
            ui.horizontal(|ui| {
                ui.label(self.state.tr("tsa_ca"));
                let hint = self.state.tr("tsa_ca_hint");
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.tsa_ca_entry)
                        .hint_text(hint)
                        .desired_width(300.0),
                );
                if !r.has_focus() && !r.lost_focus() {
                    self.tsa_ca_entry = self.state.verify.tsa_ca.clone();
                }
                if r.lost_focus() {
                    let entry = self.tsa_ca_entry.clone();
                    self.state.verify.set_tsa_ca(&entry);
                    self.sync_option_entries();
                }
                #[cfg(windows)]
                if ui.button(self.state.tr("browse")).clicked()
                    && let Some(p) = rfd::FileDialog::new()
                        .add_filter("CA bundle", &["pem", "crt", "cer", "der"])
                        .pick_file()
                {
                    self.state.verify.set_tsa_ca(&p.display().to_string());
                    self.sync_option_entries();
                }
            });
        });
    }

    fn hashing_section(&mut self, ui: &mut egui::Ui, enabled: bool) {
        Self::section_title(ui, self.state.tr("hashes"));
        let v = &mut self.state.verify;
        let mut err = None;
        ui.add_enabled_ui(enabled, |ui| {
            ui.horizontal_wrapped(|ui| {
                for a in HashAlgo::ALL {
                    let mut on = v.selected.contains(&a);
                    let tip = if v.can_toggle(a) {
                        String::new()
                    } else if on {
                        v.tr("hash_tip_one")
                    } else {
                        v.tr("hash_tip_two")
                    };
                    let r = ui.add_enabled(v.can_toggle(a), egui::Checkbox::new(&mut on, a.name()));
                    let r = if tip.is_empty() {
                        r
                    } else {
                        r.on_disabled_hover_text(tip)
                    };
                    if r.changed()
                        && let Err(e) = v.toggle_algo(a)
                    {
                        err = Some(e);
                    }
                }
            });
        });
        if let Some(e) = err {
            self.state.notice = Some(crate::state::Notice {
                tone: Tone::Amber,
                text: e,
            });
        }
    }

    fn report_section(&mut self, ui: &mut egui::Ui, enabled: bool) {
        Self::section_title(ui, self.state.tr("reports"));
        let v = &mut self.state.verify;
        let tr = |k: &str| v.tr(k);
        let (l_lang, l_exam, l_case, l_hint, l_all, l_broken) = (
            tr("report_lang"),
            tr("examiner"),
            tr("case"),
            tr("case_hint"),
            tr("lang_all"),
            tr("out_dir_broken"),
        );
        ui.add_enabled_ui(enabled, |ui| {
            egui::Grid::new("report-grid")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label(l_lang);
                    let choices = [
                        ("en", "English".to_string()),
                        ("es", "Español".to_string()),
                        ("fr", "Français".to_string()),
                        ("all", l_all),
                    ];
                    let current = choices
                        .iter()
                        .find(|(k, _)| *k == v.lang)
                        .map(|(_, t)| t.clone())
                        .unwrap_or_default();
                    let mut chosen = None;
                    egui::ComboBox::from_id_salt("lang")
                        .selected_text(current)
                        .show_ui(ui, |ui| {
                            for (k, t) in &choices {
                                if ui.selectable_label(v.lang == *k, t).clicked() {
                                    chosen = Some(*k);
                                }
                            }
                        });
                    if let Some(k) = chosen {
                        v.set_lang(k);
                    }
                    ui.end_row();
                    ui.label(l_broken);
                    ui.add(egui::TextEdit::singleline(&mut v.out_dir).desired_width(220.0));
                    ui.end_row();
                    ui.label(l_exam);
                    ui.add(egui::TextEdit::singleline(&mut v.actor).desired_width(220.0));
                    ui.end_row();
                    ui.label(l_case);
                    ui.add(
                        egui::TextEdit::singleline(&mut v.case_id)
                            .hint_text(l_hint)
                            .desired_width(220.0),
                    );
                    ui.end_row();
                });
        });
    }

    fn trust_section(&mut self, ui: &mut egui::Ui, enabled: bool) {
        Self::section_title(ui, self.state.tr("trust"));
        let v = &mut self.state.verify;
        let tr = |k: &str| v.tr(k);
        let (l_jur, l_co, l_fr, l_tsa, l_cert, l_pass, l_browse) = (
            tr("jurisdiction"),
            tr("jur_co"),
            tr("jur_fr"),
            tr("tsa"),
            tr("sign_cert"),
            tr("sign_pass"),
            tr("browse"),
        );
        ui.add_enabled_ui(enabled, |ui| {
            egui::Grid::new("trust-grid")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label(l_jur);
                    let current = if v.jurisdiction == "fr" {
                        l_fr.clone()
                    } else {
                        l_co.clone()
                    };
                    let mut chosen = None;
                    egui::ComboBox::from_id_salt("jur")
                        .selected_text(current)
                        .show_ui(ui, |ui| {
                            if ui.selectable_label(v.jurisdiction == "co", &l_co).clicked() {
                                chosen = Some("co");
                            }
                            if ui.selectable_label(v.jurisdiction == "fr", &l_fr).clicked() {
                                chosen = Some("fr");
                            }
                        });
                    if let Some(j) = chosen {
                        v.set_jurisdiction(j);
                    }
                    ui.end_row();
                    ui.label(l_tsa);
                    ui.horizontal(|ui| {
                        let mut on = v.timestamp;
                        let mut url = v.tsa_url.clone();
                        let c = ui.checkbox(&mut on, "");
                        let t = ui.add_enabled(
                            on,
                            egui::TextEdit::singleline(&mut url).desired_width(220.0),
                        );
                        if c.changed() || t.lost_focus() {
                            v.set_timestamp(on, &url);
                        } else {
                            v.tsa_url = url;
                        }
                    });
                    ui.end_row();
                    ui.label(l_cert);
                    ui.horizontal(|ui| {
                        let mut path = v.sign_cert.clone();
                        let r = ui.add(egui::TextEdit::singleline(&mut path).desired_width(220.0));
                        if r.lost_focus() || r.changed() {
                            v.set_sign_cert(&path);
                        }
                        #[cfg(windows)]
                        if ui.button(&l_browse).clicked()
                            && let Some(f) = rfd::FileDialog::new()
                                .add_filter("PKCS#12", &["p12", "pfx"])
                                .pick_file()
                        {
                            v.set_sign_cert(&f.display().to_string());
                        }
                        let _ = &l_browse;
                    });
                    ui.end_row();
                    ui.label(l_pass);
                    ui.add(
                        egui::TextEdit::singleline(&mut v.sign_password)
                            .password(true)
                            .desired_width(220.0),
                    );
                    ui.end_row();
                });
        });
    }

    fn run_section(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if self.state.verify.is_running() {
                if ui.button(self.state.tr("cancel")).clicked() {
                    self.cancel.store(true, Ordering::SeqCst);
                    self.state.cancel_verify_clicked();
                    self.state.notice = Some(crate::state::Notice {
                        tone: Tone::Amber,
                        text: self.state.tr("cancelling"),
                    });
                }
            } else {
                let start = egui::Button::new(
                    egui::RichText::new(self.state.tr("start"))
                        .strong()
                        .color(egui::Color32::WHITE),
                )
                .fill(BLUE)
                .min_size(egui::vec2(160.0, 28.0));
                if ui
                    .add_enabled(self.state.verify.can_start(), start)
                    .clicked()
                {
                    let ctx = ui.ctx().clone();
                    self.start_verify(&ctx);
                }
            }
            ui.weak(self.state.verify.out_dir_display());
        });
        ui.add_space(6.0);
        let v = &self.state.verify;
        ui.add(
            egui::ProgressBar::new(v.fraction())
                .text(v.progress_text())
                .fill(BLUE)
                .animate(v.is_running()),
        );
        let live = self.started.map(|s| s.elapsed().as_millis() as u64);
        ui.label(v.timing_text(live));
        if !v.current_item.is_empty() {
            ui.weak(format!("{}: {}", v.tr("now"), v.current_item));
        }
        let mut open_report = false;
        let mut open_run = false;
        match &v.phase {
            Phase::Failed(e) => {
                ui.colored_label(RED, format!("{}: {}", v.tr("failed"), e));
            }
            Phase::Finished | Phase::Cancelled => {
                if let Some(o) = v.outcome.clone() {
                    let title = if v.phase == Phase::Cancelled {
                        v.tr("cancelled")
                    } else {
                        v.tr("done")
                    };
                    ui.label(egui::RichText::new(title).color(CYAN).strong());
                    ui.label(format!(
                        "{} {} · {} {} · {}: {} / {} / {} / {}",
                        o.items,
                        v.tr("files"),
                        o.errors,
                        v.tr("errors"),
                        v.tr("findings"),
                        o.high,
                        o.medium,
                        o.low,
                        o.info
                    ));
                    if !v.codes.is_empty() {
                        ui.label(format!("{}: {}", v.tr("codes"), v.codes.join(", ")));
                    }
                    ui.horizontal(|ui| {
                        open_report = ui.button(v.tr("open_report")).clicked();
                        open_run = ui.button(v.tr("open_run_folder")).clicked();
                    });
                }
            }
            _ => {}
        }
        if !v.warnings.is_empty() {
            egui::CollapsingHeader::new(format!("{} ({})", v.tr("warnings"), v.warnings.len()))
                .show(ui, |ui| {
                    for w in &v.warnings {
                        ui.label(w);
                    }
                });
        }
        if open_report && let Some(p) = self.state.report_to_open() {
            open_path(&p);
        }
        if open_run && let Some(p) = self.state.run_folder_to_open() {
            open_path(&p);
        }
    }

    fn results_section(&mut self, ui: &mut egui::Ui) {
        let tr = |k: &str| self.state.tr(k);
        Self::section_title(ui, tr("results_title"));
        let items = &self.state.verify.items;
        if items.is_empty() {
            ui.weak(tr("results_none"));
            return;
        }
        egui::Grid::new("results")
            .striped(true)
            .num_columns(5)
            .spacing([18.0, 4.0])
            .show(ui, |ui| {
                for h in ["#", "col_kind", "col_item", "col_verdict", "findings"] {
                    let t = if h == "#" { "#".to_string() } else { tr(h) };
                    ui.label(egui::RichText::new(t).strong());
                }
                ui.end_row();
                for i in items {
                    ui.weak(i.index.to_string());
                    ui.label(tr(match i.kind {
                        ItemKind::CaseLog => "kind_case_log",
                        ItemKind::Run => "kind_run",
                        ItemKind::Evidence => "kind_evidence",
                    }));
                    ui.label(&i.label);
                    let (k, c) = match i.status.as_str() {
                        "ok" => ("verdict_ok", GREEN),
                        "attention" => ("verdict_attention", AMBER),
                        "problem" => ("verdict_problem", RED),
                        _ => ("verdict_running", GREY),
                    };
                    ui.colored_label(c, tr(k));
                    ui.label(i.findings.join(", "));
                    ui.end_row();
                }
            });
    }

    /// Draws one frame into the root `ui` (what eframe calls every frame).
    pub fn draw(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if !self.themed {
            apply_theme(&ctx);
            self.themed = true;
        }
        self.poll_discovery(&ctx);
        self.drain();
        self.state.sync_verify_audit();
        // The case view is re-read when the window regains the focus (a tool may have added a run).
        let focused = ctx.input(|i| i.focused);
        if focused && !self.focused {
            self.state.refresh_case(false);
        }
        self.focused = focused;
        if self.state.verify.is_running() || self.state.discovering {
            // Keep the elapsed timer moving even when no event arrives (large files).
            ctx.request_repaint_after(Duration::from_millis(200));
        }
        egui::CentralPanel::default().show(ui, |ui| {
            self.header(ui);
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| match self.state.tab {
                    Tab::Tools => self.tools_tab(ui),
                    Tab::Case => self.case_tab(ui),
                    Tab::Verify => self.verify_tab(ui),
                });
        });
        self.confirm_dialog(&ctx);
    }
}

impl Default for HubApp {
    fn default() -> Self {
        Self::new()
    }
}

fn open_path(p: &Path) {
    #[cfg(windows)]
    let _ = std::process::Command::new("explorer").arg(p).spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(p).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(p).spawn();
}

impl eframe::App for HubApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rv_hub_core::signature::StaticVerifier;

    fn app(root: &Path) -> HubApp {
        let mut state = HubState::new(vec![root.join("hub-data")], "Examiner Test");
        state.apply_discovery(vec![]);
        HubApp::from_parts(
            state,
            Box::new(StaticVerifier::always(SignatureStatus::Unsigned)),
            Box::new(DetachedSpawner),
        )
    }

    fn verify_actions(a: &HubApp) -> Vec<String> {
        a.state
            .verify
            .ui_actions
            .iter()
            .map(|(x, _)| x.clone())
            .collect()
    }

    /// A field that is no longer drawn never sees its focus loss: switching tabs (or starting) applies it.
    #[test]
    fn edits_still_in_a_field_are_applied_and_audited_before_the_tab_changes() {
        let d = tempfile::tempdir().unwrap();
        let copies = d.path().join("copies");
        std::fs::create_dir(&copies).unwrap();
        let mut a = app(d.path());

        a.tsa_ca_entry = "C:\\certs\\tsa-roots.pem".into();
        a.commit_entries();
        assert_eq!(a.state.verify.tsa_ca, "C:\\certs\\tsa-roots.pem");
        a.tsa_ca_entry.clear();
        a.commit_entries();
        assert!(
            a.state.verify.tsa_ca.is_empty(),
            "clearing the field is applied too"
        );
        assert_eq!(
            verify_actions(&a)
                .iter()
                .filter(|x| *x == "ui_tsa_ca_changed")
                .count(),
            2,
            "every change of the trust roots is audited"
        );

        a.verify_evidence_entry = format!("\"{}\"", copies.display());
        a.commit_entries();
        assert_eq!(a.state.verify.evidence_dir, copies.display().to_string());
        assert!(verify_actions(&a).contains(&"ui_evidence_dir_changed".to_string()));
        assert_eq!(
            a.case_evidence_entry,
            copies.display().to_string(),
            "the Case tab shows the new value"
        );

        // Nothing pending: committing again changes and records nothing.
        let n = a.state.verify.ui_actions.len();
        a.commit_entries();
        assert_eq!(a.state.verify.ui_actions.len(), n);
    }

    #[test]
    fn case_tab_evidence_edit_is_applied_and_a_stale_buffer_never_reverts_it() {
        let d = tempfile::tempdir().unwrap();
        let (one, two) = (d.path().join("one"), d.path().join("two"));
        std::fs::create_dir(&one).unwrap();
        std::fs::create_dir(&two).unwrap();
        let mut a = app(d.path());
        a.case_evidence_entry = one.display().to_string();
        a.commit_entries();
        assert_eq!(a.state.verify.evidence_dir, one.display().to_string());
        assert!(
            a.state
                .audit_trail
                .iter()
                .any(|(x, _)| x == "ui_case_evidence_dir_changed")
        );
        // The Verify tab changes it (focus loss there resyncs every buffer) ...
        a.verify_evidence_entry = two.display().to_string();
        a.commit_entries();
        // ... and a later commit does not bring back the Case tab's earlier text.
        a.commit_entries();
        assert_eq!(a.state.verify.evidence_dir, two.display().to_string());
        assert_eq!(a.case_evidence_entry, two.display().to_string());
        // A folder that does not exist is refused and the field shows the current value again.
        a.case_evidence_entry = d.path().join("nowhere").display().to_string();
        a.commit_entries();
        assert_eq!(a.state.verify.evidence_dir, two.display().to_string());
        assert_eq!(a.case_evidence_entry, two.display().to_string());
    }
}
