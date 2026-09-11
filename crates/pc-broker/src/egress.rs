//! Egress allowlisting.
//!
//! Outbound destinations are **fail-closed by default**: nothing is reachable
//! unless a rule allows it (CLAUDE.md §5 row #13). Rules support exact hosts,
//! wildcard domains, and CIDR ranges. Cloud metadata endpoints (IMDS) are
//! blackholed **unconditionally** - no rule and no `--observe` mode can permit
//! them (§5 row #14).
//!
//! `--observe` mode never opens the gate; it still denies, but records the
//! minimal rule that *would* have allowed the traffic, so an operator can adopt
//! real-world rules from a diff instead of hand-editing blind.

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

use crate::error::BrokerError;

/// A destination the gateway (or a runner, via the broker) wants to reach.
#[derive(Clone, Debug, Default)]
pub struct Destination {
    pub host: Option<String>,
    pub ip: Option<IpAddr>,
}

impl Destination {
    #[must_use]
    pub fn host(host: impl Into<String>) -> Self {
        Self {
            host: Some(host.into()),
            ip: None,
        }
    }

    #[must_use]
    pub fn ip(ip: IpAddr) -> Self {
        Self {
            host: None,
            ip: Some(ip),
        }
    }
}

/// A single egress allow rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressRule {
    /// Matches one exact host, e.g. `api.github.com`.
    ExactHost(String),
    /// Matches a domain and all its subdomains, e.g. base `github.com` matches
    /// `github.com` and `api.github.com`.
    WildcardHost(String),
    /// Matches any IP inside a CIDR range.
    Cidr(IpNet),
}

impl EgressRule {
    /// Parse a rule from its config string form:
    /// `example.com`, `*.example.com`, or `10.0.0.0/8`.
    pub fn parse(s: &str) -> Result<Self, BrokerError> {
        let s = s.trim();
        if let Some(base) = s.strip_prefix("*.") {
            if base.is_empty() {
                return Err(BrokerError::EgressRule(s.to_string()));
            }
            return Ok(EgressRule::WildcardHost(base.to_ascii_lowercase()));
        }
        if s.contains('/') {
            return IpNet::from_str(s)
                .map(EgressRule::Cidr)
                .map_err(|_| BrokerError::EgressRule(s.to_string()));
        }
        if s.is_empty() {
            return Err(BrokerError::EgressRule(s.to_string()));
        }
        Ok(EgressRule::ExactHost(s.to_ascii_lowercase()))
    }

    fn matches(&self, dest: &Destination) -> bool {
        match self {
            EgressRule::ExactHost(h) => dest
                .host
                .as_deref()
                .is_some_and(|dh| dh.eq_ignore_ascii_case(h)),
            EgressRule::WildcardHost(base) => dest.host.as_deref().is_some_and(|dh| {
                let dh = dh.to_ascii_lowercase();
                dh == *base || dh.ends_with(&format!(".{base}"))
            }),
            EgressRule::Cidr(net) => dest.ip.is_some_and(|ip| net.contains(&ip)),
        }
    }
}

/// The outcome of an egress check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressDecision {
    Allow,
    Deny {
        /// True if denied because the destination is a metadata endpoint.
        imds: bool,
        /// In `--observe` mode, the minimal rule that would have allowed this.
        proposal: Option<EgressRule>,
    },
}

impl EgressDecision {
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, EgressDecision::Allow)
    }
}

/// Cloud metadata endpoints that are blackholed unconditionally.
const IMDS_HOSTS: &[&str] = &["metadata.google.internal", "metadata.goog"];

fn is_imds(dest: &Destination) -> bool {
    // Link-local IMDS addresses used by AWS/GCP/Azure/OpenStack.
    const IMDS_V4: [u8; 4] = [169, 254, 169, 254];
    if let Some(ip) = dest.ip {
        match ip {
            IpAddr::V4(v4) if v4.octets() == IMDS_V4 => return true,
            // AWS IPv6 IMDS: fd00:ec2::254
            IpAddr::V6(v6) if v6.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254] => {
                return true;
            }
            _ => {}
        }
    }
    if let Some(host) = dest.host.as_deref() {
        let host = host.to_ascii_lowercase();
        if IMDS_HOSTS.iter().any(|h| host == *h) {
            return true;
        }
    }
    false
}

/// A compiled egress policy.
#[derive(Clone, Debug)]
pub struct EgressPolicy {
    rules: Vec<EgressRule>,
    observe: bool,
}

impl EgressPolicy {
    /// Build a policy from rules. `observe` records deny proposals but never
    /// opens the gate.
    #[must_use]
    pub fn new(rules: Vec<EgressRule>, observe: bool) -> Self {
        Self { rules, observe }
    }

    /// Parse rules from their string forms (config).
    pub fn from_strings(rules: &[String], observe: bool) -> Result<Self, BrokerError> {
        let rules = rules
            .iter()
            .map(|s| EgressRule::parse(s))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::new(rules, observe))
    }

    /// Evaluate a destination. IMDS is always denied; otherwise a rule must
    /// match; otherwise fail closed (with a proposal in observe mode).
    #[must_use]
    pub fn evaluate(&self, dest: &Destination) -> EgressDecision {
        if is_imds(dest) {
            return EgressDecision::Deny {
                imds: true,
                proposal: None,
            };
        }
        if self.rules.iter().any(|r| r.matches(dest)) {
            return EgressDecision::Allow;
        }
        EgressDecision::Deny {
            imds: false,
            proposal: if self.observe {
                dest.host
                    .as_deref()
                    .map(|h| EgressRule::ExactHost(h.to_ascii_lowercase()))
            } else {
                None
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> EgressPolicy {
        EgressPolicy::new(
            vec![
                EgressRule::ExactHost("api.github.com".into()),
                EgressRule::WildcardHost("example.com".into()),
                EgressRule::Cidr("10.0.0.0/8".parse().unwrap()),
            ],
            false,
        )
    }

    #[test]
    fn exact_host_allowed() {
        assert!(
            policy()
                .evaluate(&Destination::host("api.github.com"))
                .is_allowed()
        );
    }

    #[test]
    fn wildcard_matches_domain_and_subdomains() {
        assert!(
            policy()
                .evaluate(&Destination::host("example.com"))
                .is_allowed()
        );
        assert!(
            policy()
                .evaluate(&Destination::host("api.example.com"))
                .is_allowed()
        );
        assert!(
            !policy()
                .evaluate(&Destination::host("notexample.com"))
                .is_allowed()
        );
    }

    #[test]
    fn cidr_matches_inside_range() {
        assert!(
            policy()
                .evaluate(&Destination::ip("10.1.2.3".parse().unwrap()))
                .is_allowed()
        );
        assert!(
            !policy()
                .evaluate(&Destination::ip("11.0.0.1".parse().unwrap()))
                .is_allowed()
        );
    }

    #[test]
    fn unlisted_destination_fails_closed() {
        assert!(
            !policy()
                .evaluate(&Destination::host("evil.example.net"))
                .is_allowed()
        );
    }

    #[test]
    fn imds_is_blackholed_even_if_a_rule_would_match() {
        let permissive = EgressPolicy::new(
            vec![EgressRule::Cidr("169.254.0.0/16".parse().unwrap())],
            false,
        );
        let d = permissive.evaluate(&Destination::ip("169.254.169.254".parse().unwrap()));
        assert_eq!(
            d,
            EgressDecision::Deny {
                imds: true,
                proposal: None
            }
        );
    }

    #[test]
    fn imds_hostnames_blocked() {
        assert!(
            !policy()
                .evaluate(&Destination::host("metadata.google.internal"))
                .is_allowed()
        );
    }

    #[test]
    fn observe_mode_denies_but_proposes() {
        let observing = EgressPolicy::new(vec![], true);
        let d = observing.evaluate(&Destination::host("newapi.saas.com"));
        assert_eq!(
            d,
            EgressDecision::Deny {
                imds: false,
                proposal: Some(EgressRule::ExactHost("newapi.saas.com".into()))
            }
        );
    }

    #[test]
    fn rule_parsing_covers_all_forms() {
        assert_eq!(
            EgressRule::parse("api.x.com").unwrap(),
            EgressRule::ExactHost("api.x.com".into())
        );
        assert_eq!(
            EgressRule::parse("*.x.com").unwrap(),
            EgressRule::WildcardHost("x.com".into())
        );
        assert!(matches!(
            EgressRule::parse("10.0.0.0/8").unwrap(),
            EgressRule::Cidr(_)
        ));
        assert!(EgressRule::parse("*.").is_err());
    }
}
