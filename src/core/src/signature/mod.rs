//! Code-signature check of the tools RV Hub launches or asks to cross-check.
//!
//! On Windows ([`OsVerifier`]): `WinVerifyTrust` (Authenticode, `WINTRUST_ACTION_GENERIC_VERIFY_V2`, no UI, no
//! network), then the signer's certificate chain built by the trust provider (`CertGetCertificateChain`); the SHA-256
//! thumbprint of the chain's root must equal the Rakvor root bundled at build time
//! (`packaging/signing/rakvor-code-signing-root.cer`). Elsewhere the result is [`SignatureStatus::NotChecked`].
//!
//! The decision logic ([`trust_outcome`], [`classify`]) is plain Rust and unit-tested on every platform; only the
//! FFI calls live in `windows.rs` (the one module allowed to use `unsafe`).

use crate::findings::{self, Finding};
use crate::hash::{HashAlgo, hash_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[cfg(windows)]
mod windows;

/// The Rakvor code-signing root, as shipped in the repository.
pub const RAKVOR_ROOT_DER: &[u8] =
    include_bytes!("../../../../packaging/signing/rakvor-code-signing-root.cer");

/// SHA-256 thumbprint (lower-case hex) of [`RAKVOR_ROOT_DER`].
pub fn rakvor_root_sha256() -> String {
    hash_bytes(RAKVOR_ROOT_DER, HashAlgo::Sha256)
}

/// What the signature check found for one executable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SignatureStatus {
    /// Valid Authenticode signature whose chain ends at the bundled Rakvor root.
    SignedRakvor,
    /// Valid signature, but the chain ends at another root (thumbprint given).
    SignedOtherRoot { root_sha256: String },
    /// A signature is present but does not verify (file modified after signing, revoked, expired, ...).
    Invalid { reason: String },
    /// No Authenticode signature (e.g. a developer build).
    Unsigned,
    /// The check was not done (not Windows, file missing, ...).
    NotChecked { reason: String },
}

impl SignatureStatus {
    /// Stable key: signed_rakvor | signed_other_root | invalid | unsigned | not_checked.
    pub fn key(&self) -> &'static str {
        match self {
            SignatureStatus::SignedRakvor => "signed_rakvor",
            SignatureStatus::SignedOtherRoot { .. } => "signed_other_root",
            SignatureStatus::Invalid { .. } => "invalid",
            SignatureStatus::Unsigned => "unsigned",
            SignatureStatus::NotChecked { .. } => "not_checked",
        }
    }

    pub fn is_rakvor(&self) -> bool {
        matches!(self, SignatureStatus::SignedRakvor)
    }

    /// The tool-inventory finding for this status (plan §1 table). None for `NotChecked`: the reports say so in
    /// the `SIGNATURE_CHECK_WINDOWS_ONLY` limitation instead.
    pub fn finding(&self, tool: &str, exe: &Path) -> Option<Finding> {
        let f = |code: &str| {
            Finding::of(code)
                .with("tool", tool)
                .with("exe", exe.display().to_string())
        };
        match self {
            SignatureStatus::SignedRakvor => Some(f(findings::TOOL_SIGNED_RAKVOR)),
            SignatureStatus::SignedOtherRoot { root_sha256 } => {
                Some(f(findings::TOOL_SIGNED_OTHER_ROOT).with("root_sha256", root_sha256.clone()))
            }
            SignatureStatus::Invalid { reason } => {
                Some(f(findings::TOOL_SIGNATURE_INVALID).with("reason", reason.clone()))
            }
            SignatureStatus::Unsigned => Some(f(findings::TOOL_UNSIGNED)),
            SignatureStatus::NotChecked { .. } => None,
        }
    }
}

/// Checks the signature of an executable. Implementations: [`OsVerifier`] (the real one) and
/// [`StaticVerifier`] (tests, previews).
pub trait SignatureVerifier: Send + Sync {
    fn verify(&self, exe: &Path) -> SignatureStatus;
}

/// The operating system's check: Authenticode + Rakvor root on Windows, `NotChecked` elsewhere.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsVerifier;

impl SignatureVerifier for OsVerifier {
    fn verify(&self, exe: &Path) -> SignatureStatus {
        if !exe.is_file() {
            return SignatureStatus::NotChecked {
                reason: format!("{} is not a file", exe.display()),
            };
        }
        verify_os(exe)
    }
}

#[cfg(windows)]
fn verify_os(exe: &Path) -> SignatureStatus {
    let (hresult, root_der) = windows::verify_file(exe);
    let root = root_der.map(|der| hash_bytes(&der, HashAlgo::Sha256));
    classify(
        trust_outcome(hresult),
        root.as_deref(),
        &rakvor_root_sha256(),
    )
}

#[cfg(not(windows))]
fn verify_os(_exe: &Path) -> SignatureStatus {
    SignatureStatus::NotChecked {
        reason: "not Windows: Authenticode signatures are checked on Windows only".into(),
    }
}

/// A fixed answer per path (default for any other path): for tests and for front-ends previewing statuses.
#[derive(Clone, Debug)]
pub struct StaticVerifier {
    pub default: SignatureStatus,
    pub by_path: BTreeMap<PathBuf, SignatureStatus>,
}

impl StaticVerifier {
    pub fn always(status: SignatureStatus) -> StaticVerifier {
        StaticVerifier {
            default: status,
            by_path: BTreeMap::new(),
        }
    }
}

impl SignatureVerifier for StaticVerifier {
    fn verify(&self, exe: &Path) -> SignatureStatus {
        self.by_path
            .get(exe)
            .cloned()
            .unwrap_or_else(|| self.default.clone())
    }
}

/// WinVerifyTrust's answer, reduced to what the decision needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustOutcome {
    /// S_OK: signature valid and the chain ends at a root trusted by Windows.
    Trusted,
    /// Signature valid, chain built, but its root is not in the Windows trust store (CERT_E_UNTRUSTEDROOT,
    /// CERT_E_UNTRUSTEDTESTROOT): expected for the private Rakvor root unless it was installed.
    UntrustedRoot,
    /// The file carries no Authenticode signature.
    NoSignature,
    /// Any other error (HRESULT).
    Failed(i32),
}

const TRUST_E_PROVIDER_UNKNOWN: u32 = 0x800B_0001;
const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800B_0003;
const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
const CERT_E_EXPIRED: u32 = 0x800B_0101;
const CERT_E_UNTRUSTEDROOT: u32 = 0x800B_0109;
const CERT_E_CHAINING: u32 = 0x800B_010A;
const CERT_E_REVOKED: u32 = 0x800B_010C;
const CERT_E_UNTRUSTEDTESTROOT: u32 = 0x800B_010D;
const TRUST_E_EXPLICIT_DISTRUST: u32 = 0x800B_0111;
const TRUST_E_CERT_SIGNATURE: u32 = 0x8009_6004;
const TRUST_E_BAD_DIGEST: u32 = 0x8009_6010;
const CRYPT_E_SECURITY_SETTINGS: u32 = 0x8009_2026;

/// Maps a WinVerifyTrust return value (HRESULT as i32) to a [`TrustOutcome`].
pub fn trust_outcome(hresult: i32) -> TrustOutcome {
    match hresult as u32 {
        0 => TrustOutcome::Trusted,
        CERT_E_UNTRUSTEDROOT | CERT_E_UNTRUSTEDTESTROOT => TrustOutcome::UntrustedRoot,
        TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => {
            TrustOutcome::NoSignature
        }
        _ => TrustOutcome::Failed(hresult),
    }
}

/// Plain-language reason for a failed WinVerifyTrust (English; the code is always included).
pub fn describe_hresult(hresult: i32) -> String {
    let what = match hresult as u32 {
        TRUST_E_BAD_DIGEST => "the file was modified after it was signed (digest mismatch)",
        TRUST_E_CERT_SIGNATURE => "the certificate signature does not verify",
        TRUST_E_EXPLICIT_DISTRUST => "the signing certificate is explicitly distrusted",
        CERT_E_EXPIRED => {
            "the signing certificate has expired and the signature has no valid timestamp"
        }
        CERT_E_REVOKED => "the signing certificate was revoked",
        CERT_E_CHAINING => "the certificate chain could not be built",
        CRYPT_E_SECURITY_SETTINGS => "blocked by the local security policy",
        _ => "the signature does not verify",
    };
    format!("{} (WinVerifyTrust 0x{:08X})", what, hresult as u32)
}

/// The decision: WinVerifyTrust's outcome plus the SHA-256 of the signer chain's root certificate.
pub fn classify(
    outcome: TrustOutcome,
    chain_root_sha256: Option<&str>,
    rakvor_root_sha256: &str,
) -> SignatureStatus {
    match outcome {
        TrustOutcome::NoSignature => SignatureStatus::Unsigned,
        TrustOutcome::Failed(hr) => SignatureStatus::Invalid {
            reason: describe_hresult(hr),
        },
        TrustOutcome::Trusted | TrustOutcome::UntrustedRoot => match chain_root_sha256 {
            None => SignatureStatus::Invalid {
                reason: "the signer's certificate chain is not available".into(),
            },
            Some(r) if r.eq_ignore_ascii_case(rakvor_root_sha256) => SignatureStatus::SignedRakvor,
            Some(r) => SignatureStatus::SignedOtherRoot {
                root_sha256: r.to_ascii_lowercase(),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_root_is_the_rakvor_root() {
        assert_eq!(
            rakvor_root_sha256(),
            "dc9ba1a2fcd4f0633c5214b7cceb25bed8f3f7d9ebaf111590250cbcaa83df60"
        );
    }

    #[test]
    fn decision_table() {
        let rk = rakvor_root_sha256();
        let other = "ab".repeat(32);
        assert_eq!(
            classify(trust_outcome(0), Some(&rk.to_uppercase()), &rk),
            SignatureStatus::SignedRakvor
        );
        // Private root not installed in Windows: still Rakvor when the chain ends at the bundled root.
        assert_eq!(
            classify(trust_outcome(CERT_E_UNTRUSTEDROOT as i32), Some(&rk), &rk),
            SignatureStatus::SignedRakvor
        );
        assert_eq!(
            classify(trust_outcome(0), Some(&other), &rk),
            SignatureStatus::SignedOtherRoot {
                root_sha256: other.clone()
            }
        );
        assert_eq!(
            classify(trust_outcome(TRUST_E_NOSIGNATURE as i32), None, &rk),
            SignatureStatus::Unsigned
        );
        match classify(trust_outcome(TRUST_E_BAD_DIGEST as i32), Some(&rk), &rk) {
            SignatureStatus::Invalid { reason } => {
                assert!(
                    reason.contains("modified after it was signed")
                        && reason.contains("0x80096010")
                )
            }
            s => panic!("{s:?}"),
        }
        assert!(matches!(
            classify(TrustOutcome::Trusted, None, &rk),
            SignatureStatus::Invalid { .. }
        ));
    }

    #[test]
    fn statuses_map_to_inventory_findings() {
        let exe = Path::new("rv-x.exe");
        let code = |s: SignatureStatus| s.finding("rv-x", exe).map(|f| (f.code, f.severity));
        use crate::findings::Severity::*;
        assert_eq!(
            code(SignatureStatus::SignedRakvor),
            Some(("TOOL_SIGNED_RAKVOR".into(), Info))
        );
        assert_eq!(
            code(SignatureStatus::SignedOtherRoot {
                root_sha256: "00".into()
            }),
            Some(("TOOL_SIGNED_OTHER_ROOT".into(), High))
        );
        assert_eq!(
            code(SignatureStatus::Invalid { reason: "x".into() }),
            Some(("TOOL_SIGNATURE_INVALID".into(), High))
        );
        assert_eq!(
            code(SignatureStatus::Unsigned),
            Some(("TOOL_UNSIGNED".into(), Medium))
        );
        assert_eq!(
            code(SignatureStatus::NotChecked { reason: "x".into() }),
            None
        );
        let j = serde_json::to_value(SignatureStatus::Invalid { reason: "r".into() }).unwrap();
        assert_eq!(j, serde_json::json!({"status": "invalid", "reason": "r"}));
    }

    #[test]
    fn os_verifier_off_windows_and_on_missing_files() {
        let d = tempfile::tempdir().unwrap();
        assert!(matches!(
            OsVerifier.verify(&d.path().join("missing.exe")),
            SignatureStatus::NotChecked { .. }
        ));
        #[cfg(not(windows))]
        {
            let f = d.path().join("a.exe");
            std::fs::write(&f, b"MZ").unwrap();
            assert!(matches!(
                OsVerifier.verify(&f),
                SignatureStatus::NotChecked { reason } if reason.contains("not Windows")
            ));
        }
    }
}
