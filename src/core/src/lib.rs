//! RV Hub core library: the main app of the four Rakvor DFIR tools (rv-hashinv, rv-pdfauth, rv-imgauth,
//! rv-rsmf). The core does all the work and never prints: front-ends (CLI, GUI) call it and render what it
//! returns, or the [`events::Event`] stream of [`run::run`].
//!
//! Public API (frozen for the CLI and GUI; see docs/architecture.md):
//!
//! | Module | What |
//! |---|---|
//! | [`tools`] | discovery of installed / portable tools, `describe --json` (`rakvor.describe/1`), built-in table |
//! | [`signature`] | [`signature::SignatureVerifier`]: Authenticode + Rakvor root (Windows), statuses → findings |
//! | [`launch`] | `<gui_exe> --case-dir CASE`, detached, audited in the hub's [`session`] log |
//! | [`case_view`] | read-only dashboard model of a case folder |
//! | [`suggest`] | next-step rules with i18n reason keys |
//! | [`run`] | the main verb `verify`: whole-case verification, cross-check, reports |
//!
//! Unsafe code: forbidden, except in `signature/windows.rs` (Win32 FFI), compiled on Windows only. `forbid`
//! cannot be relaxed by a module, so on Windows the crate is `deny(unsafe_code)` and that one module allows it.
#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, deny(unsafe_code))]

pub mod audit;
pub mod case;
pub mod case_view;
pub mod checks;
pub mod env;
pub mod events;
pub mod findings;
pub mod hash;
pub mod i18n;
pub mod launch;
pub mod proc;
pub mod report;
pub mod review;
pub mod run;
pub mod session;
pub mod signature;
pub mod suggest;
pub mod time;
pub mod tools;
pub mod trust;
pub mod verify;

pub use case::CaseRole;
pub use events::Event;
pub use hash::HashAlgo;
pub use run::{CrossCheckMode, RunConfig, RunSummary, run};

pub const TOOL_NAME: &str = "rv-hub";
/// Product version = version.txt (bumped by release-please). The crate versions in Cargo.toml stay fixed so a
/// release never changes Cargo.lock (CI builds with --locked).
pub const TOOL_VERSION: &str = env!("RV_VERSION");

/// This tool's place in a shared case folder (see docs/case-folder.md). RV Hub is an ANALYSIS tool in the case
/// log (its verification runs are recorded like any analysis run), but its main verb `verify` takes no evidence
/// input: it verifies the case folder itself. Kept in step with `case_role` in .forge.json.
pub const CASE_ROLE: CaseRole = CaseRole::Analysis;
