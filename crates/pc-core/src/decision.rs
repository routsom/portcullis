//! The outcome of authorizing an [`Invocation`](crate::Invocation).
//!
//! The policy engine itself is a later milestone (M2); this type exists from M0
//! so the decision *path* is in place and the default is explicit. Fail-closed
//! is the rule: anything that is not an explicit `Allow` denies.

use serde::{Deserialize, Serialize};

/// Why a call was denied. Kept as a small, stable enum plus a free-form detail
/// so audit and the CLI can render a reason without leaking argument data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", content = "detail", rename_all = "snake_case")]
pub enum DenyReason {
    /// No policy rule permitted the call (the default outcome).
    NoMatchingRule,
    /// The capability is not approved or has drifted from its pinned hash.
    CapabilityNotInvocable,
    /// A limit (rate, concurrency, size, budget) was exceeded.
    LimitExceeded(String),
    /// Denied by an explicit policy rule.
    PolicyDenied(String),
}

/// The authorization outcome for an invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny(DenyReason),
}

impl Decision {
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    /// The fail-closed default: deny because nothing explicitly allowed the call.
    #[must_use]
    pub fn default_deny() -> Self {
        Decision::Deny(DenyReason::NoMatchingRule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_deny_when_nothing_matches() {
        assert!(!Decision::default_deny().is_allowed());
    }

    #[test]
    fn allow_is_allowed() {
        assert!(Decision::Allow.is_allowed());
    }
}
