//! Per-tenant usage and cost accounting.
//!
//! Metrics are on by default and exported locally only (Directive #8): nothing
//! leaves the process. Counts are kept per tenant so usage/cost is a first-class,
//! tenant-attributable metric (CLAUDE.md §5 row #18), and rendered in Prometheus
//! text format for a local scraper.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Mutex;

/// The outcome of a request, for accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Allowed,
    Denied,
    UpstreamError,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counters {
    allowed: u64,
    denied: u64,
    upstream_errors: u64,
}

/// A tenant-keyed metrics registry.
#[derive(Debug, Default)]
pub struct Metrics {
    by_tenant: Mutex<BTreeMap<String, Counters>>,
}

impl Metrics {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one request outcome for `tenant`.
    pub fn record(&self, tenant: &str, outcome: Outcome) {
        let mut map = self.by_tenant.lock().expect("metrics lock poisoned");
        let c = map.entry(tenant.to_string()).or_default();
        match outcome {
            Outcome::Allowed => c.allowed += 1,
            Outcome::Denied => c.denied += 1,
            Outcome::UpstreamError => c.upstream_errors += 1,
        }
    }

    /// Total requests counted for a tenant (diagnostics/tests).
    #[must_use]
    pub fn total(&self, tenant: &str) -> u64 {
        self.by_tenant
            .lock()
            .expect("metrics lock poisoned")
            .get(tenant)
            .map_or(0, |c| c.allowed + c.denied + c.upstream_errors)
    }

    /// Render all counters in Prometheus text exposition format.
    #[must_use]
    pub fn to_prometheus(&self) -> String {
        let map = self.by_tenant.lock().expect("metrics lock poisoned");
        let mut out = String::new();
        out.push_str("# HELP portcullis_requests_total Requests handled, by tenant and outcome.\n");
        out.push_str("# TYPE portcullis_requests_total counter\n");
        for (tenant, c) in map.iter() {
            for (outcome, value) in [
                ("allowed", c.allowed),
                ("denied", c.denied),
                ("upstream_error", c.upstream_errors),
            ] {
                let _ = writeln!(
                    out,
                    "portcullis_requests_total{{tenant=\"{}\",outcome=\"{outcome}\"}} {value}",
                    escape(tenant)
                );
            }
        }
        out
    }
}

/// Escape a Prometheus label value.
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_are_per_tenant_and_per_outcome() {
        let m = Metrics::new();
        m.record("acme", Outcome::Allowed);
        m.record("acme", Outcome::Allowed);
        m.record("acme", Outcome::Denied);
        m.record("globex", Outcome::UpstreamError);

        assert_eq!(m.total("acme"), 3);
        assert_eq!(m.total("globex"), 1);
        assert_eq!(m.total("unknown"), 0);
    }

    #[test]
    fn prometheus_output_contains_labeled_series() {
        let m = Metrics::new();
        m.record("acme", Outcome::Allowed);
        let text = m.to_prometheus();
        assert!(text.contains("# TYPE portcullis_requests_total counter"));
        assert!(text.contains("portcullis_requests_total{tenant=\"acme\",outcome=\"allowed\"} 1"));
    }
}
