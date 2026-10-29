//! Tool discovery: which Rakvor tools are on this workstation, what they say about themselves
//! (`<tool> describe --json`, schema `rakvor.describe/1`), the SHA-256 of each executable and its signature.
//!
//! Sources, in this order (an executable found by several sources is listed once, with every source):
//! 1. the uninstall registry keys `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\{AppId}_is1` of the
//!    known AppIds ([`APP_IDS`], Windows only): `InstallLocation`, `DisplayVersion`;
//! 2. `%LOCALAPPDATA%\Programs\Rakvor\*\rv-*.exe` (the per-user install folder of every Rakvor installer);
//! 3. `PATH` (the four known tools only: nothing else named `rv-*` is ever executed);
//! 4. folders the user added (portable zips, a USB stick): the folder and its direct subfolders.
//!
//! `describe --json` runs with a time limit, and only for executables that are Rakvor-signed (or where the
//! signature cannot be checked, i.e. not Windows): an executable signed by someone else is never run by the hub.
//! When `describe` is absent (tool versions before it), fails, or reports another schema, the built-in table of
//! the four tools is used and the inventory says so (`describe_source: builtin`, version unknown).

use crate::hash::{HashAlgo, hash_reader};
use crate::signature::{SignatureStatus, SignatureVerifier};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const SCHEMA_DESCRIBE: &str = "rakvor.describe/1";
/// Log chains a tool may declare in `log_formats`.
pub const LOG_AUDIT: &str = "rakvor.audit/1";
pub const LOG_REVIEW: &str = "rakvor.review/1";
/// The four tools RV Hub coordinates (CLI names without extension).
pub const KNOWN_TOOLS: [&str; 4] = ["rv-hashinv", "rv-pdfauth", "rv-imgauth", "rv-rsmf"];
pub const DEFAULT_DESCRIBE_TIMEOUT: Duration = Duration::from_secs(10);

/// An Inno Setup AppId of a Rakvor tool and what it is known to install.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownAppId {
    pub app_id: &'static str,
    /// The tool it belongs to; None for an AppId shared by mistake (the installed folder tells which tool).
    pub tool: Option<&'static str>,
    /// Warning attached to tools found under this key.
    pub warning: Option<&'static str>,
}

/// Uninstall keys read on Windows (the `_is1` suffix is added by Inno Setup).
///
/// `{B2454915-…}` is rv-pdfauth's AppId; rv-imgauth 0.2.0 reused it by mistake (inherited from the port), so the
/// key names whichever of the two was installed last: the tool is identified by the executables in its
/// InstallLocation, and a warning is attached. `{04A0C3C3-…}` is rv-imgauth's corrected AppId (plan §0.3, from
/// 0.2.1). Tools installed under any other key are still found in `%LOCALAPPDATA%\Programs\Rakvor`.
pub const APP_IDS: [KnownAppId; 4] = [
    KnownAppId {
        app_id: "{6D3F3B0E-5B7A-4B2C-9E61-2A1C7D4E9F10}",
        tool: Some("rv-hashinv"),
        warning: None,
    },
    KnownAppId {
        app_id: "{B2454915-B966-44CD-9C5B-5413F38185AE}",
        tool: None,
        warning: Some(
            "installed under the AppId shared by RV PDFAuth and RV ImgAuth 0.2.0: if you installed RV ImgAuth 0.2.0 \
             after RV PDFAuth, reinstall RV PDFAuth",
        ),
    },
    KnownAppId {
        app_id: "{7E0DA535-8638-4E9D-8680-ED046DCA9F45}",
        tool: Some("rv-rsmf"),
        warning: None,
    },
    KnownAppId {
        app_id: "{04A0C3C3-4929-42ED-81F7-93DB361940C8}",
        tool: Some("rv-imgauth"),
        warning: None,
    },
];

/// What a tool does in a case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolRole {
    Intake,
    Analysis,
    Conversion,
}

/// One part of a content signature: these bytes (hex) at this offset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MagicPart {
    pub offset: u64,
    pub hex: String,
}

/// A content signature in `accepts.signatures`: `"*"` (any content) or every part matching.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignatureSpec {
    Format {
        format: String,
        #[serde(rename = "match")]
        parts: Vec<MagicPart>,
    },
    Any(String),
}

impl SignatureSpec {
    pub fn matches(&self, head: &[u8]) -> bool {
        match self {
            SignatureSpec::Any(s) => s == "*",
            SignatureSpec::Format { parts, .. } => {
                !parts.is_empty()
                    && parts.iter().all(|p| {
                        let Some(want) = decode_hex(&p.hex) else {
                            return false;
                        };
                        let start = p.offset as usize;
                        head.len() >= start + want.len()
                            && head[start..start + want.len()] == want[..]
                    })
            }
        }
    }

    /// Bytes needed at the start of a file to test this signature.
    pub fn span(&self) -> usize {
        match self {
            SignatureSpec::Any(_) => 0,
            SignatureSpec::Format { parts, .. } => parts
                .iter()
                .map(|p| p.offset as usize + p.hex.len() / 2)
                .max()
                .unwrap_or(0),
        }
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Inputs a tool handles: a file is a candidate when its extension is listed or its first bytes match.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accepts {
    pub extensions: Vec<String>,
    pub signatures: Vec<SignatureSpec>,
}

impl Accepts {
    /// `"*"` in either list: the tool takes any file (the intake tool).
    pub fn any(&self) -> bool {
        self.extensions.iter().any(|e| e == "*")
            || self
                .signatures
                .iter()
                .any(|s| matches!(s, SignatureSpec::Any(x) if x == "*"))
    }

    pub fn matches_extension(&self, file_name: &str) -> bool {
        let ext = Path::new(file_name)
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase());
        self.extensions
            .iter()
            .any(|e| e == "*" || Some(e.as_str()) == ext.as_deref())
    }

    pub fn matches_content(&self, head: &[u8]) -> bool {
        self.signatures.iter().any(|s| s.matches(head))
    }

    /// Bytes to read from a file to test every signature.
    pub fn head_len(&self) -> usize {
        self.signatures.iter().map(|s| s.span()).max().unwrap_or(0)
    }
}

/// `describe --json` (schema `rakvor.describe/1`). Unknown extra fields are kept in `extra`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Describe {
    pub schema: String,
    pub tool: String,
    pub title: String,
    /// None only in the built-in table (version unknown).
    pub version: Option<String>,
    pub role: ToolRole,
    pub main_verb: String,
    pub accepts: Accepts,
    pub case_formats: Vec<String>,
    pub log_formats: Vec<String>,
    pub cli_exe: String,
    pub gui_exe: String,
    pub exit_codes: BTreeMap<String, String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Why a `describe --json` answer was not used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", content = "detail", rename_all = "snake_case")]
pub enum DescribeProblem {
    /// Not run: the executable is not Rakvor-signed (or there is no CLI).
    NotRun(String),
    /// The command failed, timed out or is unknown (tool versions before `describe`).
    Failed(String),
    NotJson(String),
    /// Another schema than `rakvor.describe/1`: refused.
    UnknownSchema(String),
    /// The right schema, but a required field is missing or has the wrong type.
    Invalid(String),
}

impl std::fmt::Display for DescribeProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DescribeProblem::NotRun(s) => write!(f, "describe not run: {s}"),
            DescribeProblem::Failed(s) => write!(f, "describe failed: {s}"),
            DescribeProblem::NotJson(s) => write!(f, "describe output is not JSON: {s}"),
            DescribeProblem::UnknownSchema(s) => {
                write!(
                    f,
                    "describe reports schema {s}; only {SCHEMA_DESCRIBE} is read"
                )
            }
            DescribeProblem::Invalid(s) => write!(f, "describe output is invalid: {s}"),
        }
    }
}

/// Parses and checks a `describe --json` answer.
pub fn parse_describe(bytes: &[u8]) -> Result<Describe, DescribeProblem> {
    let v: Value =
        serde_json::from_slice(bytes).map_err(|e| DescribeProblem::NotJson(e.to_string()))?;
    match v.get("schema").and_then(Value::as_str) {
        Some(SCHEMA_DESCRIBE) => {}
        Some(other) => return Err(DescribeProblem::UnknownSchema(other.to_string())),
        None => return Err(DescribeProblem::UnknownSchema("(none)".into())),
    }
    let d: Describe =
        serde_json::from_value(v).map_err(|e| DescribeProblem::Invalid(e.to_string()))?;
    if d.version.as_deref().is_none_or(str::is_empty) {
        return Err(DescribeProblem::Invalid("missing field `version`".into()));
    }
    if !d.tool.starts_with("rv-") {
        return Err(DescribeProblem::Invalid(format!(
            "tool `{}` is not an rv-* name",
            d.tool
        )));
    }
    if !d.log_formats.iter().any(|l| l == LOG_AUDIT) {
        return Err(DescribeProblem::Invalid(format!(
            "log_formats lacks {LOG_AUDIT}"
        )));
    }
    Ok(d)
}

fn sig(format: &str, parts: &[(u64, &str)]) -> SignatureSpec {
    SignatureSpec::Format {
        format: format.into(),
        parts: parts
            .iter()
            .map(|(o, h)| MagicPart {
                offset: *o,
                hex: (*h).into(),
            })
            .collect(),
    }
}

/// The built-in description of a known tool (used when `describe --json` is not available). Version unknown.
pub fn builtin(tool: &str) -> Option<Describe> {
    let (title, role, verb, ext, sigs, logs): (
        &str,
        ToolRole,
        &str,
        &[&str],
        Vec<SignatureSpec>,
        &[&str],
    ) = match tool {
        "rv-hashinv" => (
            "RV HashInv",
            ToolRole::Intake,
            "scan",
            &["*"],
            vec![SignatureSpec::Any("*".into())],
            &[LOG_AUDIT],
        ),
        "rv-pdfauth" => (
            "RV PDFAuth",
            ToolRole::Analysis,
            "analyze",
            &["pdf"],
            vec![sig("pdf", &[(0, "255044462d")])],
            &[LOG_AUDIT],
        ),
        "rv-imgauth" => (
            "RV ImgAuth",
            ToolRole::Analysis,
            "analyze",
            &["jpg", "jpeg", "jpe", "jfif", "png", "heic", "heif", "webp"],
            vec![
                sig("jpeg", &[(0, "ffd8ff")]),
                sig("png", &[(0, "89504e470d0a1a0a")]),
                sig("webp", &[(0, "52494646"), (8, "57454250")]),
                sig("heic", &[(4, "6674797068656963")]),
                sig("heic", &[(4, "6674797068656978")]),
                sig("heif", &[(4, "667479706d696631")]),
            ],
            &[LOG_AUDIT, LOG_REVIEW],
        ),
        "rv-rsmf" => (
            "RV RSMF",
            ToolRole::Conversion,
            "convert",
            &["txt", "json", "html", "htm", "msg", "csv"],
            vec![sig("msg", &[(0, "d0cf11e0a1b11ae1")])],
            &[LOG_AUDIT],
        ),
        _ => return None,
    };
    let exit_codes = [
        ("0", "Completed; no high-severity finding."),
        ("1", "Runtime error."),
        ("2", "Usage error."),
        ("3", "Completed with at least one high-severity finding, or the case folder fails verification."),
        ("130", "Cancelled."),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    Some(Describe {
        schema: SCHEMA_DESCRIBE.into(),
        tool: tool.into(),
        title: title.into(),
        version: None,
        role,
        main_verb: verb.into(),
        accepts: Accepts {
            extensions: ext.iter().map(|e| e.to_string()).collect(),
            signatures: sigs,
        },
        case_formats: vec![crate::case::SCHEMA_CASE.into()],
        log_formats: logs.iter().map(|l| l.to_string()).collect(),
        cli_exe: format!("{tool}.exe"),
        gui_exe: format!("{tool}-gui.exe"),
        exit_codes,
        extra: Default::default(),
    })
}

/// Where an executable was found.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum Source {
    Registry { app_id: String },
    LocalPrograms,
    Path,
    UserFolder,
}

/// Where the [`ToolInfo::describe`] data came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DescribeSource {
    /// The executable's own `describe --json`.
    Describe,
    /// The built-in table (version unknown).
    Builtin,
}

/// One installed (or portable) tool.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ToolInfo {
    /// CLI name without extension, e.g. "rv-pdfauth".
    pub tool: String,
    pub title: String,
    /// Folder holding the executables.
    pub dir: PathBuf,
    pub cli_exe: Option<PathBuf>,
    pub gui_exe: Option<PathBuf>,
    pub cli_sha256: Option<String>,
    pub gui_sha256: Option<String>,
    pub sources: Vec<Source>,
    /// From describe, else the registry's DisplayVersion, else unknown.
    pub version: Option<String>,
    pub describe: Describe,
    pub describe_source: DescribeSource,
    pub describe_problem: Option<DescribeProblem>,
    pub cli_signature: SignatureStatus,
    pub gui_signature: SignatureStatus,
    pub warnings: Vec<String>,
}

impl ToolInfo {
    /// The inventory findings (TOOL_SIGNED_RAKVOR, TOOL_UNSIGNED, …) of both executables.
    pub fn findings(&self) -> Vec<crate::findings::Finding> {
        [
            (&self.cli_exe, &self.cli_signature),
            (&self.gui_exe, &self.gui_signature),
        ]
        .into_iter()
        .filter_map(|(exe, s)| exe.as_ref().and_then(|e| s.finding(&self.tool, e)))
        .collect()
    }
}

/// A Rakvor tool's uninstall entry (Windows registry).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryEntry {
    pub app_id: String,
    pub install_location: PathBuf,
    pub display_version: Option<String>,
}

/// Everything discovery looks at. [`DiscoverOptions::from_env`] fills it from this workstation; tests build it
/// by hand.
#[derive(Clone, Debug)]
pub struct DiscoverOptions {
    pub registry: Vec<RegistryEntry>,
    /// `%LOCALAPPDATA%\Programs\Rakvor` (its subfolders are scanned).
    pub local_programs: Option<PathBuf>,
    pub path_dirs: Vec<PathBuf>,
    pub user_folders: Vec<PathBuf>,
    pub describe_timeout: Duration,
    /// Also run `describe` on executables that are signed by another root, unsigned or invalid (default: no).
    pub describe_untrusted: bool,
}

impl DiscoverOptions {
    pub fn from_env(user_folders: Vec<PathBuf>) -> DiscoverOptions {
        DiscoverOptions {
            registry: read_uninstall_registry(),
            local_programs: std::env::var_os("LOCALAPPDATA")
                .map(|d| PathBuf::from(d).join("Programs").join("Rakvor")),
            path_dirs: std::env::var_os("PATH")
                .map(|p| std::env::split_paths(&p).collect())
                .unwrap_or_default(),
            user_folders,
            describe_timeout: DEFAULT_DESCRIBE_TIMEOUT,
            describe_untrusted: false,
        }
    }
}

/// Reads the uninstall keys of [`APP_IDS`] (HKCU, Inno Setup per-user installs).
#[cfg(windows)]
pub fn read_uninstall_registry() -> Vec<RegistryEntry> {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    APP_IDS
        .iter()
        .filter_map(|k| {
            let key = hkcu
                .open_subkey(format!(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{}_is1",
                    k.app_id
                ))
                .ok()?;
            let loc: String = key.get_value("InstallLocation").ok()?;
            Some(RegistryEntry {
                app_id: k.app_id.to_string(),
                install_location: PathBuf::from(loc),
                display_version: key.get_value::<String, _>("DisplayVersion").ok(),
            })
        })
        .collect()
}

/// No uninstall registry outside Windows.
#[cfg(not(windows))]
pub fn read_uninstall_registry() -> Vec<RegistryEntry> {
    vec![]
}

/// `rv-x` / `rv-x-gui` → ("rv-x", is_gui) for an executable file name of this platform.
fn tool_of(file_name: &str) -> Option<(String, bool)> {
    let stem = if std::env::consts::EXE_SUFFIX.is_empty() {
        file_name
    } else {
        let lower = file_name.to_ascii_lowercase();
        let suffix = std::env::consts::EXE_SUFFIX;
        if !lower.ends_with(suffix) {
            return None;
        }
        &file_name[..file_name.len() - suffix.len()]
    };
    let stem = stem.to_ascii_lowercase();
    if !stem.starts_with("rv-") || stem.contains('.') {
        return None;
    }
    let (tool, gui) = match stem.strip_suffix("-gui") {
        Some(t) => (t.to_string(), true),
        None => (stem.clone(), false),
    };
    (tool.len() > 3 && tool != crate::TOOL_NAME).then_some((tool, gui))
}

#[derive(Default)]
struct Found {
    cli: Option<PathBuf>,
    gui: Option<PathBuf>,
    sources: Vec<Source>,
    registry_version: Option<String>,
    warnings: Vec<String>,
}

fn scan_dir(
    dir: &Path,
    source: &Source,
    known_only: bool,
    found: &mut BTreeMap<(PathBuf, String), Found>,
) -> Vec<String> {
    let mut tools = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return tools;
    };
    let dir_n = crate::case::normalize(dir);
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some((tool, gui)) = tool_of(&name) else {
            continue;
        };
        if known_only && !KNOWN_TOOLS.contains(&tool.as_str()) {
            continue;
        }
        let path = e.path();
        if !path.is_file() {
            continue;
        }
        let f = found.entry((dir_n.clone(), tool.clone())).or_default();
        if gui {
            f.gui = Some(dir_n.join(&name));
        } else {
            f.cli = Some(dir_n.join(&name));
        }
        if !f.sources.contains(source) {
            f.sources.push(source.clone());
        }
        tools.push(tool);
    }
    tools
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// SHA-256 of a file (streamed), None when it cannot be read.
pub fn sha256_of(p: &Path) -> Option<String> {
    let f = std::fs::File::open(p).ok()?;
    hash_reader(f, &[HashAlgo::Sha256], |_| true)
        .ok()
        .flatten()
        .and_then(|o| o.digests.into_iter().next().map(|(_, h)| h))
}

/// Runs `<cli> describe --json` with a time limit and parses it.
pub fn describe(cli: &Path, timeout: Duration) -> Result<Describe, DescribeProblem> {
    let out = crate::proc::run(cli, &["describe", "--json"], timeout)
        .map_err(|e| DescribeProblem::Failed(format!("cannot start {}: {}", cli.display(), e)))?;
    if out.timed_out {
        return Err(DescribeProblem::Failed(format!(
            "no answer within {} s",
            timeout.as_secs()
        )));
    }
    if out.code != Some(0) {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(DescribeProblem::Failed(format!(
            "exit {} ({})",
            out.code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into()),
            err.lines().next().unwrap_or("").trim()
        )));
    }
    parse_describe(&out.stdout)
}

/// Finds every Rakvor tool (see the module documentation for the sources and rules).
pub fn discover(opts: &DiscoverOptions, verifier: &dyn SignatureVerifier) -> Vec<ToolInfo> {
    let mut found: BTreeMap<(PathBuf, String), Found> = BTreeMap::new();
    for r in &opts.registry {
        let source = Source::Registry {
            app_id: r.app_id.clone(),
        };
        let known = APP_IDS
            .iter()
            .find(|k| k.app_id.eq_ignore_ascii_case(&r.app_id));
        for tool in scan_dir(&r.install_location, &source, false, &mut found) {
            let key = (crate::case::normalize(&r.install_location), tool.clone());
            if let Some(f) = found.get_mut(&key) {
                f.registry_version = r.display_version.clone();
                if let Some(w) = known.and_then(|k| k.warning) {
                    if !f.warnings.iter().any(|x| x == w) {
                        f.warnings.push(w.to_string());
                    }
                }
                if let Some(expected) = known.and_then(|k| k.tool) {
                    if expected != tool {
                        f.warnings.push(format!(
                            "found under the uninstall key of {expected} ({})",
                            r.app_id
                        ));
                    }
                }
            }
        }
    }
    if let Some(lp) = &opts.local_programs {
        for d in subdirs(lp) {
            scan_dir(&d, &Source::LocalPrograms, false, &mut found);
        }
    }
    for d in &opts.path_dirs {
        scan_dir(d, &Source::Path, true, &mut found);
    }
    for u in &opts.user_folders {
        scan_dir(u, &Source::UserFolder, false, &mut found);
        for d in subdirs(u) {
            scan_dir(&d, &Source::UserFolder, false, &mut found);
        }
    }

    let mut out = Vec::new();
    for ((dir, tool), f) in found {
        let check = |p: &Option<PathBuf>| match p {
            Some(p) => verifier.verify(p),
            None => SignatureStatus::NotChecked {
                reason: "no executable".into(),
            },
        };
        let (cli_signature, gui_signature) = (check(&f.cli), check(&f.gui));
        let runnable = |s: &SignatureStatus| {
            opts.describe_untrusted
                || matches!(
                    s,
                    SignatureStatus::SignedRakvor | SignatureStatus::NotChecked { .. }
                )
        };
        let described = match &f.cli {
            None => Err(DescribeProblem::NotRun("no command-line executable".into())),
            Some(_) if !runnable(&cli_signature) => Err(DescribeProblem::NotRun(format!(
                "the executable is not Rakvor-signed ({})",
                cli_signature.key()
            ))),
            Some(cli) => describe(cli, opts.describe_timeout).and_then(|d| {
                if d.tool == tool {
                    Ok(d)
                } else {
                    Err(DescribeProblem::Invalid(format!(
                        "the executable {} describes itself as {}",
                        cli.display(),
                        d.tool
                    )))
                }
            }),
        };
        let (describe, describe_source, describe_problem) = match described {
            Ok(d) => (d, DescribeSource::Describe, None),
            Err(p) => match builtin(&tool) {
                Some(b) => (b, DescribeSource::Builtin, Some(p)),
                // An unknown rv-* program without a valid describe is not a Rakvor tool: not listed.
                None => continue,
            },
        };
        let version = describe.version.clone().or(f.registry_version.clone());
        out.push(ToolInfo {
            title: describe.title.clone(),
            tool,
            dir,
            cli_sha256: f.cli.as_deref().and_then(sha256_of),
            gui_sha256: f.gui.as_deref().and_then(sha256_of),
            cli_exe: f.cli,
            gui_exe: f.gui,
            sources: f.sources,
            version,
            describe,
            describe_source,
            describe_problem,
            cli_signature,
            gui_signature,
            warnings: f.warnings,
        });
    }
    out.sort_by(|a, b| (&a.tool, &a.dir).cmp(&(&b.tool, &b.dir)));
    out
}

/// What every known tool accepts: the discovered tools' descriptions, completed by the built-in table.
pub fn catalog(tools: &[ToolInfo]) -> Vec<Describe> {
    let mut out: Vec<Describe> = Vec::new();
    for t in tools {
        if !out.iter().any(|d| d.tool == t.tool) {
            out.push(t.describe.clone());
        }
    }
    for k in KNOWN_TOOLS {
        if !out.iter().any(|d| d.tool == k) {
            out.extend(builtin(k));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::StaticVerifier;

    const PDF_DESCRIBE: &str = r#"{"schema":"rakvor.describe/1","tool":"rv-pdfauth","title":"RV PDFAuth","version":"0.4.0",
      "role":"analysis","main_verb":"analyze","accepts":{"extensions":["pdf"],"signatures":[{"format":"pdf","match":[{"offset":0,"hex":"255044462d"}]}]},
      "case_formats":["rakvor.case/1"],"log_formats":["rakvor.audit/1"],"cli_exe":"rv-pdfauth.exe","gui_exe":"rv-pdfauth-gui.exe",
      "exit_codes":{"0":"a","1":"b","2":"c","3":"d","130":"e"},"future_field":{"x":1}}"#;

    #[test]
    fn describe_is_parsed_with_extra_fields_and_other_schemas_are_refused() {
        let d = parse_describe(PDF_DESCRIBE.as_bytes()).unwrap();
        assert_eq!(
            (d.tool.as_str(), d.version.as_deref()),
            ("rv-pdfauth", Some("0.4.0"))
        );
        assert_eq!(d.extra["future_field"]["x"], 1);
        assert!(d.accepts.matches_content(b"%PDF-1.7"));
        assert!(!d.accepts.matches_content(b"%PDX-1.7"));
        assert!(d.accepts.matches_extension("A.PDF"));
        let other = PDF_DESCRIBE.replace("rakvor.describe/1", "rakvor.describe/2");
        assert_eq!(
            parse_describe(other.as_bytes()),
            Err(DescribeProblem::UnknownSchema("rakvor.describe/2".into()))
        );
        let missing = PDF_DESCRIBE.replace(r#""main_verb":"analyze","#, "");
        assert!(matches!(
            parse_describe(missing.as_bytes()),
            Err(DescribeProblem::Invalid(_))
        ));
        assert!(matches!(
            parse_describe(b"usage: ..."),
            Err(DescribeProblem::NotJson(_))
        ));
    }

    #[test]
    fn builtin_table_matches_by_extension_and_signature() {
        let img = builtin("rv-imgauth").unwrap();
        assert!(img.accepts.matches_content(b"\xFF\xD8\xFF\xE0"));
        assert!(img.accepts.matches_content(b"RIFF\0\0\0\0WEBPVP8 "));
        assert!(img.accepts.matches_content(b"\0\0\0\x18ftypheic"));
        assert!(!img.accepts.matches_content(b"RIFF\0\0\0\0AVI "));
        assert!(img.accepts.head_len() >= 12);
        assert!(builtin("rv-hashinv").unwrap().accepts.any());
        assert!(!builtin("rv-rsmf").unwrap().accepts.any());
        assert!(builtin("rv-other").is_none());
        assert_eq!(catalog(&[]).len(), 4);
        assert_eq!(img.version, None);
    }

    #[test]
    fn executable_names() {
        let s = std::env::consts::EXE_SUFFIX;
        assert_eq!(
            tool_of(&format!("rv-pdfauth{s}")),
            Some(("rv-pdfauth".into(), false))
        );
        assert_eq!(
            tool_of(&format!("rv-pdfauth-gui{s}")),
            Some(("rv-pdfauth".into(), true))
        );
        assert_eq!(tool_of(&format!("rv-hub{s}")), None);
        assert_eq!(tool_of("readme.txt"), None);
        assert_eq!(tool_of(&format!("rv-{s}")), None);
    }

    #[cfg(unix)]
    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[cfg(unix)]
    #[test]
    fn discovery_merges_sources_runs_describe_and_falls_back_to_builtin() {
        let d = tempfile::tempdir().unwrap();
        let lp = d.path().join("Programs/Rakvor");
        let pdf_dir = lp.join("RV PDFAuth");
        let img_dir = d.path().join("usb/rv-imgauth-0.2.0");
        std::fs::create_dir_all(&pdf_dir).unwrap();
        std::fs::create_dir_all(&img_dir).unwrap();
        let json = d.path().join("pdf.json");
        std::fs::write(&json, PDF_DESCRIBE).unwrap();
        script(&pdf_dir, "rv-pdfauth", &format!("cat '{}'", json.display()));
        script(&pdf_dir, "rv-pdfauth-gui", "exit 0");
        // An old version without describe: clap prints an error and exits 2.
        script(
            &img_dir,
            "rv-imgauth",
            "echo \"error: unrecognized subcommand 'describe'\" >&2; exit 2",
        );
        script(&img_dir, "rv-imgauth-gui", "exit 0");
        // Unknown rv-* program without describe: ignored. A hanging describe: timed out.
        script(&img_dir, "rv-unknown", "exit 2");
        let rsmf_dir = d.path().join("slow");
        std::fs::create_dir_all(&rsmf_dir).unwrap();
        script(&rsmf_dir, "rv-rsmf", "sleep 5");
        let opts = DiscoverOptions {
            registry: vec![RegistryEntry {
                app_id: APP_IDS[1].app_id.into(),
                install_location: pdf_dir.clone(),
                display_version: Some("0.4.0".into()),
            }],
            local_programs: Some(lp.clone()),
            // PATH: the same folder again (merged) and a folder with the slow tool.
            path_dirs: vec![pdf_dir.clone(), rsmf_dir.clone()],
            user_folders: vec![d.path().join("usb")],
            describe_timeout: Duration::from_millis(500),
            describe_untrusted: false,
        };
        let tools = discover(
            &opts,
            &StaticVerifier::always(SignatureStatus::NotChecked {
                reason: "test".into(),
            }),
        );
        let names: Vec<&str> = tools.iter().map(|t| t.tool.as_str()).collect();
        assert_eq!(names, ["rv-imgauth", "rv-pdfauth", "rv-rsmf"], "{tools:#?}");
        let pdf = &tools[1];
        assert_eq!(pdf.describe_source, DescribeSource::Describe);
        assert_eq!(pdf.version.as_deref(), Some("0.4.0"));
        assert_eq!(pdf.sources.len(), 3, "{:?}", pdf.sources);
        assert!(pdf.gui_exe.as_ref().unwrap().ends_with("rv-pdfauth-gui"));
        assert_eq!(pdf.cli_sha256.as_ref().unwrap().len(), 64);
        assert!(pdf.warnings[0].contains("reinstall RV PDFAuth"));
        let img = &tools[0];
        assert_eq!(
            (img.describe_source, img.version.as_deref()),
            (DescribeSource::Builtin, None)
        );
        assert!(
            matches!(&img.describe_problem, Some(DescribeProblem::Failed(m)) if m.contains("exit 2"))
        );
        assert_eq!(img.sources, vec![Source::UserFolder]);
        let rsmf = &tools[2];
        assert!(
            matches!(&rsmf.describe_problem, Some(DescribeProblem::Failed(m)) if m.contains("no answer"))
        );
        assert!(rsmf.gui_exe.is_none());

        // An executable signed under another root is never run.
        let other = StaticVerifier::always(SignatureStatus::SignedOtherRoot {
            root_sha256: "00".into(),
        });
        let tools = discover(&opts, &other);
        let pdf = tools.iter().find(|t| t.tool == "rv-pdfauth").unwrap();
        assert!(matches!(
            &pdf.describe_problem,
            Some(DescribeProblem::NotRun(_))
        ));
        assert_eq!(pdf.findings()[0].code, "TOOL_SIGNED_OTHER_ROOT");
    }
}
