//! The Tools tab model: one card per discovered tool (plus a dimmed card for each known tool that is not
//! installed) and the signature badge of each.

use rv_hub_core::signature::SignatureStatus;
use rv_hub_core::tools::{DescribeSource, KNOWN_TOOLS, Source, ToolInfo, builtin};

/// The colour family of a badge or a notice (the window maps it to the Rakvor palette).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Green,
    Amber,
    Red,
    Grey,
}

/// The signature badge of a card: one per [`SignatureStatus`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Badge {
    SignedRakvor,
    Unsigned,
    OtherRoot,
    Invalid,
    NotChecked,
}

impl Badge {
    pub fn of(s: &SignatureStatus) -> Badge {
        match s {
            SignatureStatus::SignedRakvor => Badge::SignedRakvor,
            SignatureStatus::Unsigned => Badge::Unsigned,
            SignatureStatus::SignedOtherRoot { .. } => Badge::OtherRoot,
            SignatureStatus::Invalid { .. } => Badge::Invalid,
            SignatureStatus::NotChecked { .. } => Badge::NotChecked,
        }
    }

    /// Green Rakvor-signed, amber unsigned, red other root or invalid, grey not checked.
    pub fn tone(self) -> Tone {
        match self {
            Badge::SignedRakvor => Tone::Green,
            Badge::Unsigned => Tone::Amber,
            Badge::OtherRoot | Badge::Invalid => Tone::Red,
            Badge::NotChecked => Tone::Grey,
        }
    }

    /// i18n `ui` key of the badge text.
    pub fn label_key(self) -> &'static str {
        match self {
            Badge::SignedRakvor => "badge_rakvor",
            Badge::Unsigned => "badge_unsigned",
            Badge::OtherRoot => "badge_other_root",
            Badge::Invalid => "badge_invalid",
            Badge::NotChecked => "badge_not_checked",
        }
    }

    /// i18n `ui` key of the risk stated before an untrusted launch (None: no confirmation needed).
    pub fn risk_key(self) -> Option<&'static str> {
        match self {
            Badge::SignedRakvor => None,
            Badge::Unsigned => Some("risk_unsigned"),
            Badge::OtherRoot => Some("risk_other_root"),
            Badge::Invalid => Some("risk_invalid"),
            Badge::NotChecked => Some("risk_not_checked"),
        }
    }

    /// Anything but Rakvor-signed is confirmed by the user first.
    pub fn needs_confirmation(self) -> bool {
        self != Badge::SignedRakvor
    }
}

/// i18n `ui` key of a discovery source.
pub fn source_key(s: &Source) -> &'static str {
    match s {
        Source::Registry { .. } => "src_registry",
        Source::LocalPrograms => "src_local",
        Source::Path => "src_path",
        Source::UserFolder => "src_user",
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ToolCard {
    pub tool: String,
    pub title: String,
    pub version: Option<String>,
    /// i18n keys of the sources, in discovery order.
    pub sources: Vec<&'static str>,
    pub badge: Badge,
    /// The status as checked (reason, other root's thumbprint), for the tooltip and the confirmation.
    pub signature: SignatureStatus,
    /// Folder holding the executables ("" when not installed).
    pub path: String,
    pub gui_exe: Option<String>,
    pub installed: bool,
    /// Index into [`super::HubState::tools`]; None for a "not installed" card.
    pub tool_index: Option<usize>,
    /// The description came from the built-in table (no `describe --json`).
    pub builtin_describe: bool,
    pub warnings: Vec<String>,
}

impl ToolCard {
    /// A GUI executable to launch exists.
    pub fn can_launch(&self) -> bool {
        self.installed && self.gui_exe.is_some()
    }
}

/// The signature that matters for the card: the GUI executable's (what Launch starts), else the CLI's.
pub fn card_signature(t: &ToolInfo) -> &SignatureStatus {
    if t.gui_exe.is_some() {
        &t.gui_signature
    } else {
        &t.cli_signature
    }
}

/// Cards for a discovery result: every discovered tool (sorted as discovered), then a dimmed card for each known
/// tool that was not found.
pub fn cards(tools: &[ToolInfo]) -> Vec<ToolCard> {
    let mut out: Vec<ToolCard> = tools
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let signature = card_signature(t).clone();
            ToolCard {
                tool: t.tool.clone(),
                title: t.title.clone(),
                version: t.version.clone(),
                sources: t.sources.iter().map(source_key).collect(),
                badge: Badge::of(&signature),
                signature,
                path: t.dir.display().to_string(),
                gui_exe: t.gui_exe.as_ref().map(|p| p.display().to_string()),
                installed: true,
                tool_index: Some(i),
                builtin_describe: t.describe_source == DescribeSource::Builtin,
                warnings: t.warnings.clone(),
            }
        })
        .collect();
    for k in KNOWN_TOOLS {
        if !tools.iter().any(|t| t.tool == k) {
            let title = builtin(k).map(|d| d.title).unwrap_or_else(|| k.to_string());
            out.push(ToolCard {
                tool: k.into(),
                title,
                version: None,
                sources: vec![],
                badge: Badge::NotChecked,
                signature: SignatureStatus::NotChecked {
                    reason: "not installed".into(),
                },
                path: String::new(),
                gui_exe: None,
                installed: false,
                tool_index: None,
                builtin_describe: true,
                warnings: vec![],
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::testing::fake_tool;

    #[test]
    fn badge_mapping_for_all_five_statuses() {
        let cases = [
            (
                SignatureStatus::SignedRakvor,
                Badge::SignedRakvor,
                Tone::Green,
                false,
            ),
            (
                SignatureStatus::Unsigned,
                Badge::Unsigned,
                Tone::Amber,
                true,
            ),
            (
                SignatureStatus::SignedOtherRoot {
                    root_sha256: "ab".into(),
                },
                Badge::OtherRoot,
                Tone::Red,
                true,
            ),
            (
                SignatureStatus::Invalid {
                    reason: "tampered".into(),
                },
                Badge::Invalid,
                Tone::Red,
                true,
            ),
            (
                SignatureStatus::NotChecked {
                    reason: "not Windows".into(),
                },
                Badge::NotChecked,
                Tone::Grey,
                true,
            ),
        ];
        let mut keys = vec![];
        for (status, badge, tone, confirm) in cases {
            let b = Badge::of(&status);
            assert_eq!(b, badge, "{status:?}");
            assert_eq!(b.tone(), tone);
            assert_eq!(b.needs_confirmation(), confirm);
            assert_eq!(b.risk_key().is_some(), confirm);
            keys.push(b.label_key());
        }
        keys.dedup();
        assert_eq!(keys.len(), 5, "one label per status");
    }

    #[test]
    fn tool_cards_from_a_fake_discovery() {
        let d = tempfile::tempdir().unwrap();
        let tools = vec![
            fake_tool(d.path(), "rv-certcheck", SignatureStatus::SignedRakvor),
            fake_tool(d.path(), "rv-hashinv", SignatureStatus::SignedRakvor),
            fake_tool(d.path(), "rv-pdfauth", SignatureStatus::Unsigned),
        ];
        let c = cards(&tools);
        // Every discovered tool, then every other known tool (not hard-coded: the core's table).
        assert!(KNOWN_TOOLS.contains(&"rv-certcheck"));
        assert_eq!(c.len(), KNOWN_TOOLS.len());
        assert_eq!(c[0].tool, "rv-certcheck");
        assert_eq!(c[0].title, "RV CertCheck");
        assert!(c[0].can_launch());
        let c: Vec<ToolCard> = c[1..].to_vec();
        assert_eq!(c[0].tool, "rv-hashinv");
        assert_eq!(c[0].badge, Badge::SignedRakvor);
        assert_eq!(c[0].version.as_deref(), Some("1.0.0"));
        assert_eq!(c[0].sources, vec!["src_user"]);
        assert_eq!(c[0].tool_index, Some(1));
        assert!(c[0].can_launch() && c[0].path.starts_with(&d.path().display().to_string()));
        assert_eq!(c[1].badge, Badge::Unsigned);
        let missing: Vec<&str> = c[2..].iter().map(|c| c.tool.as_str()).collect();
        assert!(
            missing.starts_with(&["rv-imgauth", "rv-rsmf"]),
            "{missing:?}"
        );
        assert!(c[2..].iter().all(|c| !c.installed && !c.can_launch()));
        assert_eq!(c[2].title, "RV ImgAuth");
        // Nothing found: four dimmed cards.
        assert!(cards(&[]).iter().all(|c| !c.installed));
    }
}
