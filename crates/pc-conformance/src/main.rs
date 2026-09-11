//! `pc-conformance`: run the MCP conformance suite and print a report. Exits
//! non-zero if any case fails, so `just conformance` gates CI.

use std::process::ExitCode;

fn main() -> ExitCode {
    let report = pc_conformance::run();
    println!(
        "MCP conformance: {}/{} checks passed\n",
        report.passed_count(),
        report.cases.len()
    );
    for case in &report.cases {
        let mark = if case.passed { "ok  " } else { "FAIL" };
        let detail = if case.detail.is_empty() {
            String::new()
        } else {
            format!("  ({})", case.detail)
        };
        println!("  [{mark}] {}{detail}", case.name);
    }
    if report.all_passed() {
        println!("\nconformant");
        ExitCode::SUCCESS
    } else {
        println!("\nNON-CONFORMANT");
        ExitCode::FAILURE
    }
}
