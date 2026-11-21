//! RV Hub's release check of every Rakvor tool: the shared [`crate::update`] check, run for each known tool and the hub
//! itself in parallel (one HTTPS GET of each tool's public latest-release page, with the hub's User-Agent). Notify
//! only: nothing is downloaded. The off switch ([`update::disabled`]) turns it off, as it does for every tool.
//!
//! ```text
//! KNOWN_TOOLS + rv-hub ──► one thread per tool: update::latest_version(tool, "rv-hub/<ver>")
//!                       ──► Latest { tool → Ok(X.Y.Z) | Err(reason) }
//! installed version (ToolInfo.version) + Latest ──► status(): available / up_to_date / failed / unknown
//! ```
//!
//! `rv-hub tools --check-updates` prints it (JSON `updates`); the desktop app checks once at start-up and on Refresh,
//! and shows it on every tool card.

use crate::tools::KNOWN_TOOLS;
use crate::update::{self, Check};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::mpsc::{Receiver, TryRecvError};

/// The latest released version of each checked tool (`Err`: why it could not be checked).
pub type Latest = BTreeMap<String, Result<String, String>>;

/// The tools whose latest release the hub checks: every known tool, then the hub itself.
pub fn checked_tools() -> Vec<&'static str> {
    KNOWN_TOOLS
        .iter()
        .copied()
        .chain(std::iter::once(crate::TOOL_NAME))
        .collect()
}

/// Checks every tool of [`checked_tools`] in parallel. None when the check is turned off (nothing is contacted).
pub fn latest_all() -> Option<Latest> {
    if update::disabled() {
        return None;
    }
    let agent = update::user_agent();
    let jobs: Vec<_> = checked_tools()
        .into_iter()
        .map(|t| {
            let a = agent.clone();
            (t, std::thread::spawn(move || update::latest_version(t, &a)))
        })
        .collect();
    Some(
        jobs.into_iter()
            .map(|(t, h)| {
                let r = h
                    .join()
                    .unwrap_or_else(|_| Err("the check stopped".to_string()));
                (t.to_string(), r)
            })
            .collect(),
    )
}

/// The status of one tool from its installed version and the check. None when the tool's installed version is
/// unknown (not installed, or a version the hub could not read): the card then shows the latest release only.
pub fn status(tool: &str, installed: Option<&str>, latest: &Latest) -> Option<Check> {
    let v = installed?;
    Some(match latest.get(tool)? {
        Ok(l) => update::compare(v, l, tool),
        Err(reason) => Check::Failed {
            current: v.to_string(),
            reason: reason.clone(),
        },
    })
}

/// The `updates` object of `rv-hub tools --check-updates --json`: per tool its installed and latest version and
/// status (`available`, `up_to_date`, `failed`, or `not_installed` / `unknown_version`).
pub fn json(
    installed: &BTreeMap<String, Option<String>>,
    latest: Option<&Latest>,
) -> serde_json::Value {
    let Some(latest) = latest else {
        return serde_json::json!({"checked": false, "disabled": true, "tools": {}});
    };
    let tools: serde_json::Map<String, serde_json::Value> = checked_tools()
        .into_iter()
        .map(|t| {
            let inst = installed.get(t).cloned().flatten();
            let l = latest.get(t);
            let mut v = serde_json::json!({
                "installed": inst,
                "latest": l.and_then(|r| r.as_ref().ok()),
                "release_page": update::latest_page(t),
            });
            match status(t, inst.as_deref(), latest) {
                Some(c) => {
                    v["status"] = c.status().into();
                    if let Check::Available { url, .. } = &c {
                        v["url"] = url.as_str().into();
                    }
                    if let Check::Failed { reason, .. } = &c {
                        v["reason"] = reason.as_str().into();
                    }
                }
                None => {
                    v["status"] = if installed.contains_key(t) {
                        "unknown_version"
                    } else {
                        "not_installed"
                    }
                    .into();
                    if let Some(Err(r)) = l {
                        v["reason"] = r.as_str().into();
                    }
                }
            }
            (t.to_string(), v)
        })
        .collect();
    serde_json::json!({"checked": true, "disabled": false, "tools": tools})
}

/// A running check (its channel) and its result once it arrived (`Some(None)`: the check is turned off).
type Running = (Option<Receiver<Option<Latest>>>, Option<Option<Latest>>);

/// The desktop app's check of every tool (restarted by Refresh). None while none was started.
static ALL: Mutex<Option<Running>> = Mutex::new(None);

/// Starts (or restarts) the desktop app's check of every tool on a thread.
pub fn start_all() {
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("rv-hub-release-check".into())
        .spawn(move || {
            let _ = tx.send(latest_all());
        })
        .is_ok();
    if let Ok(mut g) = ALL.lock() {
        *g = Some(if spawned {
            (Some(rx), None)
        } else {
            (None, Some(None))
        });
    }
}

/// The desktop app's check: None when not started; `Some(None)` while it runs; `Some(Some(latest))` once finished
/// (`latest` None when the check is turned off).
pub fn all_result() -> Option<Option<Option<Latest>>> {
    let mut g = ALL.lock().ok()?;
    let (rx, result) = g.as_mut()?;
    if result.is_none()
        && let Some(r) = rx
    {
        match r.try_recv() {
            Ok(v) => *result = Some(v),
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => *result = Some(None),
        }
    }
    Some(result.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn latest() -> Latest {
        [
            ("rv-timeline", Ok("0.3.0".to_string())),
            ("rv-hashinv", Ok("0.5.1".to_string())),
            (
                "rv-avauth",
                Err("cannot reach github.com: timeout".to_string()),
            ),
        ]
        .into_iter()
        .map(|(t, r)| (t.to_string(), r))
        .collect()
    }

    #[test]
    fn every_known_tool_and_the_hub_are_checked() {
        let t = checked_tools();
        assert_eq!(t.len(), KNOWN_TOOLS.len() + 1);
        assert_eq!(t.last(), Some(&"rv-hub"));
        assert!(t.contains(&"rv-avauth") && t.contains(&"rv-report"));
    }

    #[test]
    fn statuses() {
        let l = latest();
        assert_eq!(
            status("rv-timeline", Some("0.2.3"), &l).map(|c| c.status()),
            Some("available")
        );
        assert_eq!(
            status("rv-hashinv", Some("0.5.1"), &l).map(|c| c.status()),
            Some("up_to_date")
        );
        assert_eq!(
            status("rv-avauth", Some("0.2.0"), &l).map(|c| c.status()),
            Some("failed")
        );
        assert_eq!(status("rv-timeline", None, &l), None);
        let installed: BTreeMap<String, Option<String>> = [
            ("rv-timeline".to_string(), Some("0.2.3".to_string())),
            ("rv-hashinv".to_string(), None),
        ]
        .into_iter()
        .collect();
        let j = json(&installed, Some(&l));
        assert_eq!(j["checked"], true);
        let tl = &j["tools"]["rv-timeline"];
        assert_eq!(
            (
                tl["status"].as_str(),
                tl["latest"].as_str(),
                tl["installed"].as_str()
            ),
            (Some("available"), Some("0.3.0"), Some("0.2.3"))
        );
        assert_eq!(
            tl["url"],
            "https://github.com/Panacota96/rv-timeline/releases/tag/v0.3.0"
        );
        assert_eq!(j["tools"]["rv-hashinv"]["status"], "unknown_version");
        assert_eq!(j["tools"]["rv-pdfauth"]["status"], "not_installed");
        assert_eq!(j["tools"]["rv-avauth"]["status"], "not_installed");
        assert!(
            j["tools"]["rv-avauth"]["reason"]
                .as_str()
                .unwrap()
                .contains("timeout")
        );
        let off = json(&installed, None);
        assert_eq!(
            (off["checked"].as_bool(), off["disabled"].as_bool()),
            (Some(false), Some(true))
        );
    }
}
