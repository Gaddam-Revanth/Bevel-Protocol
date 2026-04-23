//! Bevel Protocol — Security Audit Library
//! Shared types: Finding, Severity, Status.

pub mod crypto_audit;
pub mod onion_audit;
pub mod protocol_audit;
pub mod adversarial;
pub mod bns_audit;

use std::fmt;

/// Severity rating for each security finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (label, color) = match self {
            Severity::Critical => ("CRITICAL", "\x1b[1;31m"),
            Severity::High     => ("HIGH    ", "\x1b[31m"),
            Severity::Medium   => ("MEDIUM  ", "\x1b[33m"),
            Severity::Low      => ("LOW     ", "\x1b[36m"),
            Severity::Info     => ("INFO    ", "\x1b[32m"),
        };
        write!(f, "{}[{}]\x1b[0m", color, label.trim_end())
    }
}

/// Whether the test confirmed a vulnerability, passed clean, or found a known placeholder.
#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    /// Vulnerability confirmed by automated test.
    Confirmed,
    /// Test passed — no vulnerability detected.
    Passed,
    /// Known design limitation / documented placeholder (not yet mitigated).
    KnownLimitation,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::Confirmed        => write!(f, "\x1b[1;31m[VULN ]\x1b[0m"),
            Status::Passed           => write!(f, "\x1b[32m[PASS ]\x1b[0m"),
            Status::KnownLimitation  => write!(f, "\x1b[33m[KNOWN]\x1b[0m"),
        }
    }
}

/// A single security finding produced by an audit test.
pub struct Finding {
    pub id:             &'static str,
    pub title:          &'static str,
    pub severity:       Severity,
    pub description:    String,
    pub status:         Status,
    pub recommendation: &'static str,
}
