//! The rule engine: ordered RBAC/ABAC rules, fail-closed, with explanations.

use std::collections::BTreeMap;

use pc_core::{ArgShapeHash, CapabilityId, Decision, DenyReason, Digest, Principal, TenantId};
use serde::{Deserialize, Serialize};

use crate::cache::DecisionCache;
use crate::glob;

/// Whether a matching rule permits or forbids the call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}

/// Comparison used by an attribute predicate (ABAC).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttrOp {
    Eq,
    Ne,
    In,
}

/// An attribute-based condition, e.g. `env in [prod, staging]`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttrPredicate {
    pub key: String,
    pub op: AttrOp,
    pub values: Vec<String>,
}

impl AttrPredicate {
    fn is_satisfied(&self, attributes: &BTreeMap<String, String>) -> bool {
        let actual = attributes.get(&self.key);
        match self.op {
            AttrOp::Eq => actual.is_some_and(|a| self.values.first().is_some_and(|v| v == a)),
            AttrOp::Ne => actual.is_none_or(|a| self.values.first().is_none_or(|v| v != a)),
            AttrOp::In => actual.is_some_and(|a| self.values.iter().any(|v| v == a)),
        }
    }
}

/// The conditions under which a rule applies. Every specified condition must
/// hold (logical AND); an unset condition matches anything.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Matcher {
    /// Restrict to these tenants (None = any).
    pub tenants: Option<Vec<String>>,
    /// Restrict to these principal ids (None = any).
    pub principals: Option<Vec<String>>,
    /// RBAC: the subject must hold at least one of these roles (None = any).
    pub roles_any: Option<Vec<String>>,
    /// Capability id globs; empty = any capability.
    pub capabilities: Vec<String>,
    /// Deny/allow only up to this delegation-chain depth (ABAC over the chain).
    pub max_chain_depth: Option<usize>,
    /// Attribute predicates (ABAC).
    pub attributes: Vec<AttrPredicate>,
}

impl Matcher {
    fn matches(&self, req: &PolicyRequest<'_>) -> bool {
        if let Some(tenants) = &self.tenants
            && !tenants.iter().any(|t| t == req.tenant.as_str())
        {
            return false;
        }
        if let Some(principals) = &self.principals
            && !principals.iter().any(|p| p == req.principal.id.as_str())
        {
            return false;
        }
        if let Some(roles) = &self.roles_any
            && !roles.iter().any(|r| req.roles.iter().any(|sr| sr == r))
        {
            return false;
        }
        if !self.capabilities.is_empty()
            && !self
                .capabilities
                .iter()
                .any(|g| glob::matches(g, req.capability.as_str()))
        {
            return false;
        }
        if let Some(max) = self.max_chain_depth
            && req.chain_depth > max
        {
            return false;
        }
        if !self
            .attributes
            .iter()
            .all(|p| p.is_satisfied(req.attributes))
        {
            return false;
        }
        true
    }
}

/// A single policy rule, evaluated in order.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub effect: Effect,
    #[serde(default)]
    pub matcher: Matcher,
    /// Human-readable reason surfaced in explanations and audit.
    #[serde(default)]
    pub reason: String,
}

/// The subject and object of an authorization question.
#[derive(Clone, Copy, Debug)]
pub struct PolicyRequest<'a> {
    pub tenant: &'a TenantId,
    pub principal: &'a Principal,
    pub roles: &'a [String],
    pub attributes: &'a BTreeMap<String, String>,
    pub capability: &'a CapabilityId,
    pub chain_depth: usize,
    pub arg_shape: ArgShapeHash,
}

/// A decision together with why it was reached - for the audit log and
/// `portcullis policy test`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Explained {
    pub decision: Decision,
    pub matched_rule: Option<String>,
    pub reason: String,
}

/// The policy engine: ordered rules plus a decision cache. Fail-closed - if no
/// rule matches, the default is deny.
#[derive(Debug)]
pub struct PolicyEngine {
    rules: Vec<Rule>,
    cache: DecisionCache<Explained>,
    /// Bumped whenever rules are replaced so cached decisions are invalidated.
    epoch: u64,
}

impl PolicyEngine {
    /// Build an engine with a bounded decision cache.
    #[must_use]
    pub fn new(rules: Vec<Rule>, cache_capacity: usize) -> Self {
        Self {
            rules,
            cache: DecisionCache::new(cache_capacity),
            epoch: 0,
        }
    }

    /// Replace the rule set and invalidate the cache.
    pub fn reload(&mut self, rules: Vec<Rule>) {
        self.rules = rules;
        self.cache.clear();
        self.epoch += 1;
    }

    /// Evaluate without touching the cache. Deterministic and pure.
    #[must_use]
    pub fn explain(&self, req: &PolicyRequest<'_>) -> Explained {
        for rule in &self.rules {
            if rule.matcher.matches(req) {
                let reason = if rule.reason.is_empty() {
                    format!("matched rule {}", rule.id)
                } else {
                    rule.reason.clone()
                };
                let decision = match rule.effect {
                    Effect::Allow => Decision::Allow,
                    Effect::Deny => Decision::Deny(DenyReason::PolicyDenied(reason.clone())),
                };
                return Explained {
                    decision,
                    matched_rule: Some(rule.id.clone()),
                    reason,
                };
            }
        }
        Explained {
            decision: Decision::default_deny(),
            matched_rule: None,
            reason: "no matching rule (default deny)".to_string(),
        }
    }

    /// Evaluate, consulting and populating the decision cache. The cache key
    /// includes a hash of the subject's roles and attributes, so a cached result
    /// is never reused for a subject whose authorization inputs differ
    /// (CLAUDE.md §5 row #1).
    #[must_use]
    pub fn decide(&mut self, req: &PolicyRequest<'_>) -> Explained {
        let key = cache_key(self.epoch, req);
        if let Some(cached) = self.cache.get(&key) {
            return cached;
        }
        let explained = self.explain(req);
        self.cache.put(key, explained.clone());
        explained
    }

    #[must_use]
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }
}

/// Build a cache key that fully captures the authorization inputs.
fn cache_key(epoch: u64, req: &PolicyRequest<'_>) -> String {
    // Canonical subject fingerprint over roles + attributes so identical
    // decisions collapse and differing subjects never collide.
    let mut subject = String::new();
    let mut roles: Vec<&str> = req.roles.iter().map(String::as_str).collect();
    roles.sort_unstable();
    subject.push_str(&roles.join(","));
    subject.push('|');
    for (k, v) in req.attributes {
        subject.push_str(k);
        subject.push('=');
        subject.push_str(v);
        subject.push(';');
    }
    let subject_hash = Digest::of(subject.as_bytes());
    format!(
        "{epoch}|{}|{}|{}|{}|{}",
        req.tenant.as_str(),
        req.principal.id.as_str(),
        req.capability.as_str(),
        req.chain_depth,
        format_args!("{}|{}", req.arg_shape, subject_hash)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_core::{PrincipalId, PrincipalKind};

    fn principal(id: &str) -> Principal {
        Principal::new(PrincipalId::new(id), PrincipalKind::Pat)
    }

    fn req<'a>(
        tenant: &'a TenantId,
        principal: &'a Principal,
        roles: &'a [String],
        attrs: &'a BTreeMap<String, String>,
        cap: &'a CapabilityId,
    ) -> PolicyRequest<'a> {
        PolicyRequest {
            tenant,
            principal,
            roles,
            attributes: attrs,
            capability: cap,
            chain_depth: 1,
            arg_shape: ArgShapeHash::new(Digest::of(b"{}")),
        }
    }

    #[test]
    fn default_is_deny_when_no_rules() {
        let engine = PolicyEngine::new(vec![], 16);
        let (t, p, cap) = (
            TenantId::new("acme").unwrap(),
            principal("a"),
            CapabilityId::new("echo"),
        );
        let attrs = BTreeMap::new();
        let out = engine.explain(&req(&t, &p, &[], &attrs, &cap));
        assert!(!out.decision.is_allowed());
        assert_eq!(out.matched_rule, None);
    }

    #[test]
    fn rbac_allows_role_and_denies_others() {
        let rules = vec![Rule {
            id: "writers-can-write".into(),
            effect: Effect::Allow,
            matcher: Matcher {
                roles_any: Some(vec!["writer".into()]),
                capabilities: vec!["github.*".into()],
                ..Default::default()
            },
            reason: "writers may call github tools".into(),
        }];
        let engine = PolicyEngine::new(rules, 16);
        let (t, p) = (TenantId::new("acme").unwrap(), principal("a"));
        let cap = CapabilityId::new("github.create_issue");
        let attrs = BTreeMap::new();

        let writer_roles = vec!["writer".to_string()];
        assert!(
            engine
                .explain(&req(&t, &p, &writer_roles, &attrs, &cap))
                .decision
                .is_allowed()
        );

        let reader_roles = vec!["reader".to_string()];
        assert!(
            !engine
                .explain(&req(&t, &p, &reader_roles, &attrs, &cap))
                .decision
                .is_allowed()
        );
    }

    #[test]
    fn abac_attribute_and_chain_depth() {
        let rules = vec![Rule {
            id: "prod-shallow-only".into(),
            effect: Effect::Allow,
            matcher: Matcher {
                attributes: vec![AttrPredicate {
                    key: "env".into(),
                    op: AttrOp::In,
                    values: vec!["prod".into(), "staging".into()],
                }],
                max_chain_depth: Some(2),
                ..Default::default()
            },
            reason: String::new(),
        }];
        let engine = PolicyEngine::new(rules, 16);
        let (t, p, cap) = (
            TenantId::new("acme").unwrap(),
            principal("a"),
            CapabilityId::new("x"),
        );
        let mut attrs = BTreeMap::new();
        attrs.insert("env".to_string(), "prod".to_string());

        let mut r = req(&t, &p, &[], &attrs, &cap);
        assert!(engine.explain(&r).decision.is_allowed());

        // Too-deep delegation chain no longer matches -> default deny.
        r.chain_depth = 5;
        assert!(!engine.explain(&r).decision.is_allowed());
    }

    #[test]
    fn first_matching_rule_wins() {
        let rules = vec![
            Rule {
                id: "deny-delete".into(),
                effect: Effect::Deny,
                matcher: Matcher {
                    capabilities: vec!["*.delete".into()],
                    ..Default::default()
                },
                reason: "deletes are forbidden".into(),
            },
            Rule {
                id: "allow-all".into(),
                effect: Effect::Allow,
                matcher: Matcher::default(),
                reason: String::new(),
            },
        ];
        let engine = PolicyEngine::new(rules, 16);
        let (t, p) = (TenantId::new("acme").unwrap(), principal("a"));
        let attrs = BTreeMap::new();

        let del = CapabilityId::new("files.delete");
        let out = engine.explain(&req(&t, &p, &[], &attrs, &del));
        assert!(!out.decision.is_allowed());
        assert_eq!(out.matched_rule.as_deref(), Some("deny-delete"));

        let read = CapabilityId::new("files.read");
        assert!(
            engine
                .explain(&req(&t, &p, &[], &attrs, &read))
                .decision
                .is_allowed()
        );
    }

    #[test]
    fn cache_returns_same_decision_and_reload_invalidates() {
        let allow = vec![Rule {
            id: "allow".into(),
            effect: Effect::Allow,
            matcher: Matcher::default(),
            reason: String::new(),
        }];
        let mut engine = PolicyEngine::new(allow, 16);
        let (t, p, cap) = (
            TenantId::new("acme").unwrap(),
            principal("a"),
            CapabilityId::new("echo"),
        );
        let attrs = BTreeMap::new();
        assert!(
            engine
                .decide(&req(&t, &p, &[], &attrs, &cap))
                .decision
                .is_allowed()
        );
        assert_eq!(engine.cache_len(), 1);
        // Cache hit path.
        assert!(
            engine
                .decide(&req(&t, &p, &[], &attrs, &cap))
                .decision
                .is_allowed()
        );
        assert_eq!(engine.cache_len(), 1);

        // Reload to deny-all; cache invalidated, new decision observed.
        engine.reload(vec![]);
        assert!(
            !engine
                .decide(&req(&t, &p, &[], &attrs, &cap))
                .decision
                .is_allowed()
        );
    }
}
