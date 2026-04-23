//! bevel-audit — Security Audit Runner
//!
//! Runs all audit modules and prints a structured vulnerability report.

use bevel_audit::adversarial;
use bevel_audit::crypto_audit;
use bevel_audit::onion_audit;
use bevel_audit::protocol_audit;
use bevel_audit::{Finding, Severity, Status};

fn main() {
    print_banner();

    let mut all_findings: Vec<Finding> = Vec::new();

    println!("\x1b[1;34m══ [1/5] Cryptographic Primitive Audit\x1b[0m");
    let mut crypto = crypto_audit::run();
    print_section_results(&crypto);
    all_findings.append(&mut crypto);

    println!("\n\x1b[1;34m══ [2/5] Onion Routing Security Audit\x1b[0m");
    let mut onion = onion_audit::run();
    print_section_results(&onion);
    all_findings.append(&mut onion);

    println!("\n\x1b[1;34m══ [3/5] Protocol & Metadata Audit\x1b[0m");
    let mut proto = protocol_audit::run();
    print_section_results(&proto);
    all_findings.append(&mut proto);

    println!("\n\x1b[1;34m══ [4/5] Adversarial & Fuzzing Audit\x1b[0m");
    let mut adv = adversarial::run();
    print_section_results(&adv);
    all_findings.append(&mut adv);

    println!("\n\x1b[1;34m══ [5/5] Bevel Name Service (BNS) Audit\x1b[0m");
    let mut bns = bevel_audit::bns_audit::run();
    print_section_results(&bns);
    all_findings.append(&mut bns);

    print_summary(&all_findings);
}

fn print_banner() {
    println!("\x1b[1;35m");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║          BEVEL PROTOCOL — SECURITY AUDIT REPORT             ║");
    println!("║          Automated Vulnerability & Hardening Analysis        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("\x1b[0m");
    println!("  Auditing: bevel-crypto · bevel-onion · bevel-protocol · bevel-p2p");
    println!("  Scope: Cryptography · Anonymity · Protocol Integrity · Adversarial Inputs");
    println!();
}

fn print_section_results(findings: &[Finding]) {
    for f in findings {
        println!(
            "  {} {} \x1b[1m{}\x1b[0m  ({})",
            f.status, f.severity, f.id, f.title
        );
        println!("       → {}", f.description);
        if f.status != Status::Passed {
            println!("       \x1b[33m⚑  Fix: {}\x1b[0m", f.recommendation);
        }
        println!();
    }
}

fn print_summary(findings: &[Finding]) {
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical && f.status == Status::Confirmed)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High && f.status == Status::Confirmed)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium && f.status == Status::Confirmed)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == Severity::Low && f.status == Status::Confirmed)
        .count();
    let known = findings
        .iter()
        .filter(|f| f.status == Status::KnownLimitation)
        .count();
    let passed = findings
        .iter()
        .filter(|f| f.status == Status::Passed)
        .count();
    let total = findings.len();

    println!("\x1b[1;35m");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                    AUDIT SUMMARY                            ║");
    println!("╚══════════════════════════════════════════════════════════════╝\x1b[0m");
    println!("  Total checks run : {}", total);
    println!("  \x1b[32mPassed\x1b[0m           : {}", passed);
    println!("  \x1b[33mKnown limitations: {}\x1b[0m", known);
    println!("  \x1b[1;31mCRITICAL vulns   : {}\x1b[0m", critical);
    println!("  \x1b[31mHIGH vulns       : {}\x1b[0m", high);
    println!("  \x1b[33mMEDIUM vulns     : {}\x1b[0m", medium);
    println!("  \x1b[36mLOW vulns        : {}\x1b[0m", low);

    let confirmed = critical + high + medium + low;
    if confirmed == 0 {
        println!("\n  \x1b[1;32m✅ No confirmed vulnerabilities — protocol is hardened.\x1b[0m\n");
    } else {
        println!("\n  \x1b[1;31m⚠  {} confirmed vulnerabilit{} require attention before production deployment.\x1b[0m\n",
            confirmed, if confirmed == 1 { "y" } else { "ies" });
    }
}
