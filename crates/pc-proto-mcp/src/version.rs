//! MCP protocol-version matrix and negotiation.
//!
//! We support the current revision plus the previous two (CLAUDE.md §7). The
//! pinned set and its rationale live in `SPEC_REVISIONS.md` next to this file;
//! that document and this array must stay in lock-step - the test
//! `supported_set_is_ordered_newest_first` guards the ordering invariant.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A dated MCP protocol revision, e.g. `2026-07-28`.
///
/// Stored as the raw revision string because the wire format is a date label,
/// not a semver. Comparison is lexicographic, which for `YYYY-MM-DD` labels is
/// also chronological - relied on by [`ProtocolVersion::is_at_least`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProtocolVersion(String);

impl ProtocolVersion {
    #[must_use]
    pub fn new(revision: impl Into<String>) -> Self {
        Self(revision.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Chronological ">=" over `YYYY-MM-DD` revision labels.
    #[must_use]
    pub fn is_at_least(&self, other: &ProtocolVersion) -> bool {
        self.0 >= other.0
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Supported revisions, newest first. Index 0 is the preferred/latest revision
/// the gateway speaks. Keep in sync with `SPEC_REVISIONS.md`.
pub const SUPPORTED_VERSIONS: &[&str] = &["2026-07-28", "2025-11-25", "2025-06-18"];

/// The result of negotiating a version against a client's request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NegotiationOutcome {
    /// The client's requested revision is supported; we echo it back.
    Agreed(ProtocolVersion),
    /// The client's requested revision is not supported; we offer our latest
    /// and let the client decide whether to proceed. This is a graceful
    /// downgrade, not an error (CLAUDE.md §7 "downgrade gracefully").
    Downgraded {
        requested: ProtocolVersion,
        offered: ProtocolVersion,
    },
}

impl NegotiationOutcome {
    /// The revision the gateway will actually speak for this session.
    #[must_use]
    pub fn effective(&self) -> &ProtocolVersion {
        match self {
            NegotiationOutcome::Agreed(v) | NegotiationOutcome::Downgraded { offered: v, .. } => v,
        }
    }
}

/// The latest revision the gateway speaks.
#[must_use]
pub fn latest() -> ProtocolVersion {
    // SUPPORTED_VERSIONS is a non-empty compile-time constant.
    ProtocolVersion::new(SUPPORTED_VERSIONS[0])
}

/// Whether `version` is in the supported set.
#[must_use]
pub fn is_supported(version: &ProtocolVersion) -> bool {
    SUPPORTED_VERSIONS.iter().any(|v| *v == version.as_str())
}

/// Negotiate the session revision from the client's `initialize.protocolVersion`.
#[must_use]
pub fn negotiate(requested: &ProtocolVersion) -> NegotiationOutcome {
    if is_supported(requested) {
        NegotiationOutcome::Agreed(requested.clone())
    } else {
        NegotiationOutcome::Downgraded {
            requested: requested.clone(),
            offered: latest(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_set_is_ordered_newest_first() {
        for pair in SUPPORTED_VERSIONS.windows(2) {
            assert!(
                pair[0] > pair[1],
                "{} should be newer than {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn negotiate_agrees_when_requested_is_supported() {
        let req = ProtocolVersion::new("2025-11-25");
        assert_eq!(negotiate(&req), NegotiationOutcome::Agreed(req.clone()));
        assert_eq!(negotiate(&req).effective(), &req);
    }

    #[test]
    fn negotiate_downgrades_when_requested_is_unknown() {
        let req = ProtocolVersion::new("2099-01-01");
        let outcome = negotiate(&req);
        assert_eq!(
            outcome,
            NegotiationOutcome::Downgraded {
                requested: req,
                offered: latest()
            }
        );
        assert_eq!(outcome.effective(), &latest());
    }

    #[test]
    fn is_at_least_is_chronological() {
        assert!(
            ProtocolVersion::new("2026-07-28").is_at_least(&ProtocolVersion::new("2025-06-18"))
        );
        assert!(
            !ProtocolVersion::new("2025-06-18").is_at_least(&ProtocolVersion::new("2026-07-28"))
        );
    }
}
