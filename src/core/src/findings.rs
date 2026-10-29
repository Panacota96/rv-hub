//! Findings: a stable code (worded in `i18n/*.json`: title / shows / does_not_prove), a severity and named
//! parameters. This file is the single list of the codes RV Hub can emit and their severities.

use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn key(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

/// One finding: a stable code, a severity and named parameters (filled into the i18n wording).
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub params: BTreeMap<String, String>,
}

impl Finding {
    /// A finding with the severity of `code` in [`CODES`] (Info for an unknown code, which tests forbid).
    pub fn of(code: &str) -> Finding {
        Finding {
            code: code.into(),
            severity: severity_of(code).unwrap_or(Severity::Info),
            params: BTreeMap::new(),
        }
    }
    pub fn with(mut self, k: &str, v: impl Into<String>) -> Finding {
        self.params.insert(k.into(), v.into());
        self
    }
}

// Whole-case verification (`rv-hub verify`).
pub const CASE_LOG_BROKEN: &str = "CASE_LOG_BROKEN";
pub const RUN_LOG_BROKEN: &str = "RUN_LOG_BROKEN";
pub const REVIEW_LOG_BROKEN: &str = "REVIEW_LOG_BROKEN";
pub const RUN_NOT_IN_CASE_LOG: &str = "RUN_NOT_IN_CASE_LOG";
pub const TOOL_VERIFY_DISAGREES: &str = "TOOL_VERIFY_DISAGREES";
pub const EVIDENCE_REHASH_MISMATCH: &str = "EVIDENCE_REHASH_MISMATCH";
pub const EVIDENCE_MISSING: &str = "EVIDENCE_MISSING";
pub const UNKNOWN_LOG_FORMAT: &str = "UNKNOWN_LOG_FORMAT";
pub const TIMESTAMP_PENDING: &str = "TIMESTAMP_PENDING";
pub const CROSSCHECK_UNAVAILABLE: &str = "CROSSCHECK_UNAVAILABLE";
pub const RUN_LOG_INTACT: &str = "RUN_LOG_INTACT";
// Tool inventory (`signature::finding`).
pub const TOOL_SIGNED_RAKVOR: &str = "TOOL_SIGNED_RAKVOR";
pub const TOOL_SIGNED_OTHER_ROOT: &str = "TOOL_SIGNED_OTHER_ROOT";
pub const TOOL_SIGNATURE_INVALID: &str = "TOOL_SIGNATURE_INVALID";
pub const TOOL_UNSIGNED: &str = "TOOL_UNSIGNED";

/// Every code RV Hub emits, with its severity (plan §1 "New finding codes" + the tool inventory table).
pub const CODES: [(&str, Severity); 15] = [
    (CASE_LOG_BROKEN, Severity::High),
    (RUN_LOG_BROKEN, Severity::High),
    (REVIEW_LOG_BROKEN, Severity::High),
    (RUN_NOT_IN_CASE_LOG, Severity::High),
    (TOOL_VERIFY_DISAGREES, Severity::High),
    (EVIDENCE_REHASH_MISMATCH, Severity::High),
    (EVIDENCE_MISSING, Severity::High),
    (UNKNOWN_LOG_FORMAT, Severity::Medium),
    (TIMESTAMP_PENDING, Severity::Low),
    (CROSSCHECK_UNAVAILABLE, Severity::Info),
    (RUN_LOG_INTACT, Severity::Info),
    (TOOL_SIGNED_RAKVOR, Severity::Info),
    (TOOL_SIGNED_OTHER_ROOT, Severity::High),
    (TOOL_SIGNATURE_INVALID, Severity::High),
    (TOOL_UNSIGNED, Severity::Medium),
];

pub fn severity_of(code: &str) -> Option<Severity> {
    CODES.iter().find(|(c, _)| *c == code).map(|(_, s)| *s)
}

/// Run-level limitations, printed in every report (what a verification cannot tell you).
pub const LIMITATIONS: [&str; 4] = [
    "VERIFICATION_PROVES_INTEGRITY_NOT_CONTENT",
    "SIGNATURE_CHECK_WINDOWS_ONLY",
    "CROSSCHECK_NEEDS_INSTALLED_TOOLS",
    "TIMESTAMP_PROVES_EXISTENCE_ONLY",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_is_worded_in_every_language() {
        for lang in crate::i18n::LANGS {
            let c = crate::i18n::catalog(lang);
            for (code, _) in CODES {
                assert!(c.has_finding(code), "{lang}: {code} has no wording");
            }
            for l in LIMITATIONS {
                assert_ne!(c.limitation(l), l, "{lang}: limitation {l} has no wording");
            }
        }
        assert_eq!(Finding::of(RUN_LOG_BROKEN).severity, Severity::High);
        assert_eq!(Finding::of(TIMESTAMP_PENDING).severity, Severity::Low);
        assert_eq!(severity_of("NOPE"), None);
    }
}
