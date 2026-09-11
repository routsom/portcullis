//! MCP spec conformance suite.
//!
//! A set of runnable checks that assert the gateway's protocol layer behaves per
//! the MCP spec across every supported revision (CLAUDE.md §7). The suite is a
//! library so it can be run from a test, the `pc-conformance` binary, and (in
//! future) against third-party gateways.

use pc_proto_mcp::version::{self, NegotiationOutcome};
use pc_proto_mcp::{Message, ProtocolVersion, SUPPORTED_VERSIONS};

/// The outcome of one conformance check.
#[derive(Clone, Debug)]
pub struct CaseResult {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// A full conformance run.
#[derive(Clone, Debug, Default)]
pub struct Report {
    pub cases: Vec<CaseResult>,
}

impl Report {
    fn check(&mut self, name: impl Into<String>, passed: bool, detail: impl Into<String>) {
        self.cases.push(CaseResult {
            name: name.into(),
            passed,
            detail: detail.into(),
        });
    }

    /// Whether every case passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.cases.iter().all(|c| c.passed)
    }

    #[must_use]
    pub fn passed_count(&self) -> usize {
        self.cases.iter().filter(|c| c.passed).count()
    }
}

/// Run the full suite and return a report.
#[must_use]
pub fn run() -> Report {
    let mut r = Report::default();

    // 1. Every supported revision negotiates to itself.
    for rev in SUPPORTED_VERSIONS {
        let v = ProtocolVersion::new(*rev);
        let outcome = version::negotiate(&v);
        let ok = matches!(&outcome, NegotiationOutcome::Agreed(agreed) if agreed == &v);
        r.check(
            format!("negotiate/{rev}/agrees"),
            ok,
            format!("{outcome:?}"),
        );
    }

    // 2. An unknown future revision downgrades to the latest, never errors.
    let future = ProtocolVersion::new("2999-12-31");
    let outcome = version::negotiate(&future);
    let ok = matches!(
        &outcome,
        NegotiationOutcome::Downgraded { offered, .. } if offered == &version::latest()
    );
    r.check("negotiate/unknown/downgrades", ok, format!("{outcome:?}"));

    // 3. Frame classification: request, notification, response.
    r.check(
        "frame/request",
        matches!(
            Message::parse(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
            Ok(Message::Request(_))
        ),
        "request with id+method",
    );
    r.check(
        "frame/notification",
        matches!(
            Message::parse(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            Ok(Message::Notification(_))
        ),
        "method without id",
    );
    r.check(
        "frame/response",
        matches!(
            Message::parse(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
            Ok(Message::Response(_))
        ),
        "id with result",
    );

    // 4. Wrong jsonrpc version is rejected.
    r.check(
        "frame/bad-version-rejected",
        Message::parse(br#"{"jsonrpc":"1.0","id":1,"method":"x"}"#).is_err(),
        "jsonrpc must be 2.0",
    );

    // 5. Roundtrip preserves method and id.
    let roundtrip = Message::parse(br#"{"jsonrpc":"2.0","id":7,"method":"tools/call"}"#)
        .and_then(|m| m.to_bytes())
        .and_then(|b| Message::parse(&b))
        .is_ok_and(|m| m.method() == Some("tools/call"));
    r.check("frame/roundtrip", roundtrip, "method survives re-serialize");

    // 6. initialize protocolVersion is extracted for each supported revision.
    for rev in SUPPORTED_VERSIONS {
        let frame = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"{rev}","capabilities":{{}}}}}}"#
        );
        let extracted = match Message::parse(frame.as_bytes()) {
            Ok(Message::Request(req)) => {
                req.initialize_protocol_version() == Some(ProtocolVersion::new(*rev))
            }
            _ => false,
        };
        r.check(format!("initialize/{rev}/version-extracted"), extracted, "");
    }

    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_suite_passes() {
        let report = run();
        assert!(
            report.all_passed(),
            "failures: {:?}",
            report
                .cases
                .iter()
                .filter(|c| !c.passed)
                .collect::<Vec<_>>()
        );
        // Sanity: the suite actually ran a meaningful number of checks.
        assert!(report.cases.len() >= 10);
    }
}
