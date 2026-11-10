//! The Authenticode check against real signed executables (Windows only).
//!
//! CI builds the fixtures at run time with `tests/signing/make-fixtures.ps1` (throwaway roots, nothing secret
//! committed) and passes their paths in `RV_SIGTEST_*` environment variables:
//!
//! | Variable | Content |
//! | --- | --- |
//! | `RV_SIGTEST_SIGNED` | exe signed by the CI test root's leaf (root trusted in Windows) |
//! | `RV_SIGTEST_UNSIGNED` | the same exe, unsigned |
//! | `RV_SIGTEST_TAMPERED` | the signed exe with one byte of its body changed |
//! | `RV_SIGTEST_OTHER` | exe signed by an unrelated root's leaf (also trusted in Windows) |
//! | `RV_SIGTEST_EMBEDDED` | exe signed by a third root that is *not* installed in Windows; the root is embedded in the signature |
//! | `RV_SIGTEST_ROOT_DER`, `RV_SIGTEST_OTHER_ROOT_DER`, `RV_SIGTEST_EMBEDDED_ROOT_DER` | the three roots (DER files) |
//!
//! Without the variables the tests are skipped, unless `RV_SIGTEST_REQUIRED=1` (set in CI), where a missing
//! fixture is a failure: the job cannot go green without running them.

use super::windows::verify_file;
use super::*;
use std::path::PathBuf;

struct Fixtures {
    signed: PathBuf,
    unsigned: PathBuf,
    tampered: PathBuf,
    other: PathBuf,
    embedded: PathBuf,
    root_der: Vec<u8>,
    other_root_der: Vec<u8>,
    embedded_root_der: Vec<u8>,
}

fn var(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

fn fixtures() -> Option<Fixtures> {
    let names = [
        "RV_SIGTEST_SIGNED",
        "RV_SIGTEST_UNSIGNED",
        "RV_SIGTEST_TAMPERED",
        "RV_SIGTEST_OTHER",
        "RV_SIGTEST_EMBEDDED",
        "RV_SIGTEST_ROOT_DER",
        "RV_SIGTEST_OTHER_ROOT_DER",
        "RV_SIGTEST_EMBEDDED_ROOT_DER",
    ];
    let missing: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| var(n).is_none_or(|p| !p.is_file()))
        .collect();
    if !missing.is_empty() {
        let required = std::env::var("RV_SIGTEST_REQUIRED").is_ok_and(|v| v == "1");
        assert!(
            !required,
            "RV_SIGTEST_REQUIRED=1 but these fixtures are missing: {}",
            missing.join(", ")
        );
        // Skipped (the core never prints; CI makes the skip impossible with RV_SIGTEST_REQUIRED=1).
        return None;
    }
    let p = |n: &str| var(n).unwrap();
    let der = |n: &str| std::fs::read(p(n)).unwrap();
    Some(Fixtures {
        signed: p("RV_SIGTEST_SIGNED"),
        unsigned: p("RV_SIGTEST_UNSIGNED"),
        tampered: p("RV_SIGTEST_TAMPERED"),
        other: p("RV_SIGTEST_OTHER"),
        embedded: p("RV_SIGTEST_EMBEDDED"),
        root_der: der("RV_SIGTEST_ROOT_DER"),
        other_root_der: der("RV_SIGTEST_OTHER_ROOT_DER"),
        embedded_root_der: der("RV_SIGTEST_EMBEDDED_ROOT_DER"),
    })
}

fn sha(der: &[u8]) -> String {
    hash_bytes(der, HashAlgo::Sha256)
}

/// The raw WinVerifyTrust result, for assertion messages.
fn raw(exe: &Path) -> String {
    let (hr, root) = verify_file(exe);
    format!(
        "WinVerifyTrust 0x{:08X}, chain root {}",
        hr as u32,
        root.map(|d| sha(&d)).unwrap_or_else(|| "none".into())
    )
}

fn finding_code(s: &SignatureStatus, exe: &Path) -> Option<String> {
    s.finding("rv-pdfauth", exe).map(|f| f.code)
}

#[test]
fn test_root_signed_is_rakvor_when_its_root_is_pinned() {
    let Some(f) = fixtures() else { return };
    let v = PinnedRootVerifier::with_root_der(&f.root_der);
    let s = v.verify(&f.signed);
    assert_eq!(s, SignatureStatus::SignedRakvor, "{}", raw(&f.signed));
    assert_eq!(
        finding_code(&s, &f.signed).as_deref(),
        Some("TOOL_SIGNED_RAKVOR")
    );
    // Root trusted by Windows: WinVerifyTrust itself succeeds and the chain ends at the test root.
    let (hr, root) = verify_file(&f.signed);
    assert_eq!(hr, 0, "{}", raw(&f.signed));
    assert_eq!(root.map(|d| sha(&d)), Some(sha(&f.root_der)));
}

#[test]
fn unsigned_is_unsigned() {
    let Some(f) = fixtures() else { return };
    for s in [
        PinnedRootVerifier::with_root_der(&f.root_der).verify(&f.unsigned),
        OsVerifier.verify(&f.unsigned),
    ] {
        assert_eq!(s, SignatureStatus::Unsigned, "{}", raw(&f.unsigned));
        assert_eq!(
            finding_code(&s, &f.unsigned).as_deref(),
            Some("TOOL_UNSIGNED")
        );
    }
}

#[test]
fn tampered_is_invalid() {
    let Some(f) = fixtures() else { return };
    for s in [
        PinnedRootVerifier::with_root_der(&f.root_der).verify(&f.tampered),
        OsVerifier.verify(&f.tampered),
    ] {
        match &s {
            SignatureStatus::Invalid { reason } => assert!(
                reason.contains("modified after it was signed") && reason.contains("0x80096010"),
                "{reason} / {}",
                raw(&f.tampered)
            ),
            other => panic!("{other:?} / {}", raw(&f.tampered)),
        }
        assert_eq!(
            finding_code(&s, &f.tampered).as_deref(),
            Some("TOOL_SIGNATURE_INVALID")
        );
    }
}

#[test]
fn other_root_is_signed_other_root_with_its_thumbprint() {
    let Some(f) = fixtures() else { return };
    let expected = SignatureStatus::SignedOtherRoot {
        root_sha256: sha(&f.other_root_der),
    };
    for s in [
        PinnedRootVerifier::with_root_der(&f.root_der).verify(&f.other),
        OsVerifier.verify(&f.other),
    ] {
        assert_eq!(s, expected, "{}", raw(&f.other));
        let finding = s.finding("rv-pdfauth", &f.other).unwrap();
        assert_eq!(finding.code, "TOOL_SIGNED_OTHER_ROOT");
        assert_eq!(
            finding.params.get("root_sha256"),
            Some(&sha(&f.other_root_der))
        );
    }
}

/// Production pin: the bundled Rakvor root is not the CI test root, so a test-root signature is "another root".
#[test]
fn default_pin_rejects_the_test_root() {
    let Some(f) = fixtures() else { return };
    assert_ne!(sha(&f.root_der), rakvor_root_sha256());
    assert_eq!(
        OsVerifier.verify(&f.signed),
        SignatureStatus::SignedOtherRoot {
            root_sha256: sha(&f.root_der)
        },
        "{}",
        raw(&f.signed)
    );
}

/// The case of a workstation where the private Rakvor root is not installed: WinVerifyTrust answers
/// CERT_E_UNTRUSTEDROOT, the chain ends at the root embedded in the signature, and the pin decides.
#[test]
fn root_not_installed_but_embedded_is_decided_by_the_pin() {
    let Some(f) = fixtures() else { return };
    let (hr, root) = verify_file(&f.embedded);
    assert_eq!(hr as u32, 0x800B_0109, "{}", raw(&f.embedded));
    assert_eq!(root.map(|d| sha(&d)), Some(sha(&f.embedded_root_der)));
    assert_eq!(
        PinnedRootVerifier::with_root_der(&f.embedded_root_der).verify(&f.embedded),
        SignatureStatus::SignedRakvor
    );
    assert_eq!(
        OsVerifier.verify(&f.embedded),
        SignatureStatus::SignedOtherRoot {
            root_sha256: sha(&f.embedded_root_der)
        }
    );
}
