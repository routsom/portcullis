//! Capabilities: the protocol-neutral unit of "a thing that can be invoked".
//!
//! A capability is whatever a protocol adapter exposes - an MCP tool, a REST
//! operation, a gRPC method. The core only cares that it has a stable identity
//! and a pinned [`ContentHash`] of its full definition, so that post-approval
//! redefinition (a "rug-pull") is detectable (CLAUDE.md §5 row #6).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash::ContentHash;

/// Stable, human-meaningful identifier for a capability (e.g. a tool name),
/// namespaced by the adapter that registered it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityId(String);

impl CapabilityId {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Approval lifecycle of a capability. Defaults to [`Unapproved`] because the
/// safe default is that nothing is invocable until an operator pins it
/// (CLAUDE.md §9).
///
/// [`Unapproved`]: CapabilityState::Unapproved
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    /// Seen but not yet approved for use. The safe default.
    #[default]
    Unapproved,
    /// Pinned and allowed. The pinned hash is held on the [`Capability`].
    Approved,
    /// Its definition drifted from the pinned hash; fails closed until an
    /// operator re-approves (CLAUDE.md §5 row #6).
    Quarantined,
}

/// A registered capability together with the hash its definition was pinned at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub id: CapabilityId,
    /// Hash of the full definition at registration/approval time.
    pub content_hash: ContentHash,
    pub state: CapabilityState,
}

impl Capability {
    /// Register a newly-seen capability. It starts [`Unapproved`].
    ///
    /// [`Unapproved`]: CapabilityState::Unapproved
    #[must_use]
    pub fn newly_seen(id: CapabilityId, content_hash: ContentHash) -> Self {
        Self {
            id,
            content_hash,
            state: CapabilityState::Unapproved,
        }
    }

    /// Whether a freshly observed definition hash still matches the pinned one.
    /// A mismatch is a rug-pull and must move the capability to
    /// [`Quarantined`](CapabilityState::Quarantined).
    #[must_use]
    pub fn matches(&self, observed: ContentHash) -> bool {
        self.content_hash == observed
    }

    /// Only an approved, un-drifted capability is invocable.
    #[must_use]
    pub fn is_invocable(&self) -> bool {
        matches!(self.state, CapabilityState::Approved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Digest;

    fn hash(bytes: &[u8]) -> ContentHash {
        ContentHash::new(Digest::of(bytes))
    }

    #[test]
    fn newly_seen_is_unapproved_and_not_invocable() {
        let cap = Capability::newly_seen(CapabilityId::new("fs.read"), hash(b"def"));
        assert_eq!(cap.state, CapabilityState::Unapproved);
        assert!(!cap.is_invocable());
    }

    #[test]
    fn matches_detects_drift_when_definition_changes() {
        let cap = Capability::newly_seen(CapabilityId::new("fs.read"), hash(b"def-v1"));
        assert!(cap.matches(hash(b"def-v1")));
        assert!(!cap.matches(hash(b"def-v2")));
    }
}
