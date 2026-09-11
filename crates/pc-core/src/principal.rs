//! Principals and delegation chains.
//!
//! A [`Principal`] is intentionally opaque: OIDC, mTLS, PAT, and SPIFFE are all
//! adapters that resolve to the same type (CLAUDE.md §7). Nothing in the core
//! assumes a single human at the top of a call chain, so every invocation
//! carries a [`DelegationChain`] and policy can later reason over its depth and
//! origin.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Opaque identifier for a principal. The string is meaningful only to the
/// identity adapter that produced it; the core never parses it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrincipalId(String);

impl PrincipalId {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The identity scheme that vouched for a principal. This is a hint for policy
/// and audit; it is deliberately an open-ended set so new adapters do not
/// require a core change.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PrincipalKind {
    /// A personal access token / pre-shared bearer token (the M0 scheme).
    Pat,
    /// `OpenID` Connect.
    Oidc,
    /// Mutual TLS client certificate.
    Mtls,
    /// SPIFFE workload identity.
    Spiffe,
    /// A non-human service identity not covered above.
    Service,
}

/// A single identity in a call chain.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Principal {
    pub id: PrincipalId,
    pub kind: PrincipalKind,
}

impl Principal {
    #[must_use]
    pub fn new(id: PrincipalId, kind: PrincipalKind) -> Self {
        Self { id, kind }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind_tag(), self.id)
    }
}

impl Principal {
    fn kind_tag(&self) -> &'static str {
        match self.kind {
            PrincipalKind::Pat => "pat",
            PrincipalKind::Oidc => "oidc",
            PrincipalKind::Mtls => "mtls",
            PrincipalKind::Spiffe => "spiffe",
            PrincipalKind::Service => "service",
        }
    }
}

/// A non-empty, ordered chain of principals: the origin is first, the most
/// recent delegate is last. Agents calling agents extend this chain, and policy
/// can reason over its depth and origin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<Principal>", into = "Vec<Principal>")]
pub struct DelegationChain {
    // Invariant: never empty. Enforced by the constructor and `TryFrom`.
    principals: Vec<Principal>,
}

/// Error constructing a [`DelegationChain`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DelegationChainError {
    #[error("a delegation chain must contain at least one principal")]
    Empty,
}

impl DelegationChain {
    /// Start a chain from its origin principal.
    #[must_use]
    pub fn root(origin: Principal) -> Self {
        Self {
            principals: vec![origin],
        }
    }

    /// Build a chain from an ordered list (origin first). Rejects an empty list.
    pub fn from_vec(principals: Vec<Principal>) -> Result<Self, DelegationChainError> {
        if principals.is_empty() {
            return Err(DelegationChainError::Empty);
        }
        Ok(Self { principals })
    }

    /// Append a delegate, returning the extended chain.
    #[must_use]
    pub fn delegate_to(mut self, next: Principal) -> Self {
        self.principals.push(next);
        self
    }

    /// The principal that originated the call chain.
    #[must_use]
    pub fn origin(&self) -> &Principal {
        // Safe: the chain is never empty by construction.
        &self.principals[0]
    }

    /// The principal acting right now (the last delegate).
    #[must_use]
    pub fn current(&self) -> &Principal {
        &self.principals[self.principals.len() - 1]
    }

    /// Number of hops in the chain (1 == a direct, undelegated call).
    #[must_use]
    pub fn depth(&self) -> usize {
        self.principals.len()
    }

    #[must_use]
    pub fn principals(&self) -> &[Principal] {
        &self.principals
    }
}

impl TryFrom<Vec<Principal>> for DelegationChain {
    type Error = DelegationChainError;
    fn try_from(value: Vec<Principal>) -> Result<Self, Self::Error> {
        Self::from_vec(value)
    }
}

impl From<DelegationChain> for Vec<Principal> {
    fn from(chain: DelegationChain) -> Self {
        chain.principals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(id: &str) -> Principal {
        Principal::new(PrincipalId::new(id), PrincipalKind::Pat)
    }

    #[test]
    fn from_vec_rejects_empty_when_no_principals() {
        assert_eq!(
            DelegationChain::from_vec(vec![]),
            Err(DelegationChainError::Empty)
        );
    }

    #[test]
    fn origin_and_current_track_delegation_when_chain_grows() {
        let chain = DelegationChain::root(pat("human"))
            .delegate_to(pat("planner"))
            .delegate_to(pat("worker"));
        assert_eq!(chain.origin(), &pat("human"));
        assert_eq!(chain.current(), &pat("worker"));
        assert_eq!(chain.depth(), 3);
    }

    #[test]
    fn deserialize_rejects_empty_chain_when_json_array_is_empty() {
        assert!(serde_json::from_str::<DelegationChain>("[]").is_err());
    }
}
