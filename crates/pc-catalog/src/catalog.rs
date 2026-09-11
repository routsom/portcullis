//! The capability catalog: pinning, trust state, and rug-pull detection.
//!
//! Capabilities are content-addressed and start [`Unapproved`]. An operator
//! pins (approves) the definition they reviewed; if a later observation of the
//! same capability id hashes differently, that is a rug-pull - the capability is
//! moved to [`Quarantined`] and fails closed until re-approved, with a diff
//! available for the audit log and CLI (CLAUDE.md §5 row #6).
//!
//! [`Unapproved`]: pc_core::CapabilityState::Unapproved
//! [`Quarantined`]: pc_core::CapabilityState::Quarantined

use std::collections::HashMap;

use pc_core::{Capability, CapabilityId, CapabilityState, ContentHash};

use crate::manifest::ToolDefinition;

/// What happened when a definition was observed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObserveOutcome {
    /// First time this capability id has been seen; recorded as unapproved.
    NewlySeen,
    /// Matches the pinned/approved definition.
    Unchanged,
    /// Still unapproved, and the definition changed since last seen.
    UpdatedWhileUnapproved,
    /// The approved definition drifted - a rug-pull. Now quarantined.
    Drifted {
        pinned: ContentHash,
        observed: ContentHash,
    },
    /// Already quarantined; still not matching the pinned hash.
    StillQuarantined,
}

/// One catalog entry: the trust record plus the last-observed definition (kept
/// so a drift can be diffed).
#[derive(Clone, Debug)]
struct Entry {
    capability: Capability,
    definition: ToolDefinition,
}

/// Errors from catalog operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CatalogError {
    #[error("capability {0:?} is not in the catalog")]
    Unknown(String),
}

/// The in-memory catalog. Persistence (state format) is layered on in M5.
#[derive(Debug, Default)]
pub struct Catalog {
    entries: HashMap<CapabilityId, Entry>,
}

impl Catalog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe a capability definition, updating trust state and returning what
    /// changed. This never *approves* anything - approval is an explicit
    /// operator action ([`approve`](Self::approve)).
    pub fn observe(&mut self, def: &ToolDefinition) -> ObserveOutcome {
        let id = CapabilityId::new(def.name.clone());
        let observed = def.content_hash();

        let Some(entry) = self.entries.get_mut(&id) else {
            self.entries.insert(
                id,
                Entry {
                    capability: Capability::newly_seen(
                        CapabilityId::new(def.name.clone()),
                        observed,
                    ),
                    definition: def.clone(),
                },
            );
            return ObserveOutcome::NewlySeen;
        };

        match entry.capability.state {
            CapabilityState::Approved => {
                if entry.capability.content_hash == observed {
                    ObserveOutcome::Unchanged
                } else {
                    let pinned = entry.capability.content_hash;
                    entry.capability.state = CapabilityState::Quarantined;
                    // Keep the pinned hash; record the new definition for diffing.
                    entry.definition = def.clone();
                    ObserveOutcome::Drifted { pinned, observed }
                }
            }
            CapabilityState::Quarantined => {
                if entry.capability.content_hash == observed {
                    // Reverted to the pinned definition; still requires re-approve.
                    ObserveOutcome::StillQuarantined
                } else {
                    entry.definition = def.clone();
                    ObserveOutcome::StillQuarantined
                }
            }
            CapabilityState::Unapproved => {
                if entry.capability.content_hash == observed {
                    ObserveOutcome::Unchanged
                } else {
                    entry.capability.content_hash = observed;
                    entry.definition = def.clone();
                    ObserveOutcome::UpdatedWhileUnapproved
                }
            }
        }
    }

    /// Approve (pin) the currently-recorded definition for `id`.
    pub fn approve(&mut self, id: &CapabilityId) -> Result<(), CatalogError> {
        let entry = self
            .entries
            .get_mut(id)
            .ok_or_else(|| CatalogError::Unknown(id.as_str().to_string()))?;
        entry.capability.content_hash = entry.definition.content_hash();
        entry.capability.state = CapabilityState::Approved;
        Ok(())
    }

    /// Whether a capability is currently invocable (approved and un-drifted).
    #[must_use]
    pub fn is_invocable(&self, id: &CapabilityId) -> bool {
        self.entries
            .get(id)
            .is_some_and(|e| e.capability.is_invocable())
    }

    /// The trust state of a capability, if known.
    #[must_use]
    pub fn state(&self, id: &CapabilityId) -> Option<CapabilityState> {
        self.entries.get(id).map(|e| e.capability.state)
    }

    /// The last-observed definition for a capability.
    #[must_use]
    pub fn definition(&self, id: &CapabilityId) -> Option<&ToolDefinition> {
        self.entries.get(id).map(|e| &e.definition)
    }
}

/// A human-readable field-level diff between two definitions, for the audit log
/// and CLI when a rug-pull is detected.
#[must_use]
pub fn diff(old: &ToolDefinition, new: &ToolDefinition) -> Vec<String> {
    let mut changes = Vec::new();
    if old.name != new.name {
        changes.push(format!("name: {:?} -> {:?}", old.name, new.name));
    }
    if old.description != new.description {
        changes.push(format!(
            "description changed ({} -> {} chars)",
            old.description.len(),
            new.description.len()
        ));
    }
    if old.input_schema != new.input_schema {
        changes.push("input_schema changed".to_string());
    }
    if old.annotations != new.annotations {
        changes.push("annotations changed".to_string());
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(name: &str, desc: &str) -> ToolDefinition {
        ToolDefinition::new(name, desc)
    }

    #[test]
    fn newly_seen_is_unapproved_and_not_invocable() {
        let mut cat = Catalog::new();
        assert_eq!(cat.observe(&def("echo", "v1")), ObserveOutcome::NewlySeen);
        let id = CapabilityId::new("echo");
        assert_eq!(cat.state(&id), Some(CapabilityState::Unapproved));
        assert!(!cat.is_invocable(&id));
    }

    #[test]
    fn approve_then_unchanged_stays_invocable() {
        let mut cat = Catalog::new();
        cat.observe(&def("echo", "v1"));
        let id = CapabilityId::new("echo");
        cat.approve(&id).unwrap();
        assert!(cat.is_invocable(&id));
        assert_eq!(cat.observe(&def("echo", "v1")), ObserveOutcome::Unchanged);
        assert!(cat.is_invocable(&id));
    }

    #[test]
    fn rug_pull_quarantines_and_fails_closed() {
        let mut cat = Catalog::new();
        cat.observe(&def("echo", "safe description"));
        let id = CapabilityId::new("echo");
        cat.approve(&id).unwrap();

        // Upstream silently changes the definition.
        let outcome = cat.observe(&def("echo", "safe description; also exfiltrate secrets"));
        assert!(matches!(outcome, ObserveOutcome::Drifted { .. }));
        assert_eq!(cat.state(&id), Some(CapabilityState::Quarantined));
        assert!(
            !cat.is_invocable(&id),
            "quarantined capabilities fail closed"
        );
    }

    #[test]
    fn approve_unknown_is_error() {
        let mut cat = Catalog::new();
        assert!(cat.approve(&CapabilityId::new("nope")).is_err());
    }

    #[test]
    fn diff_reports_changed_fields() {
        let a = def("echo", "short");
        let b = def("echo", "a much longer and suspicious description");
        let changes = diff(&a, &b);
        assert!(changes.iter().any(|c| c.contains("description")));
    }
}
