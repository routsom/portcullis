//! Tenancy.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Identifies a tenant - the top-level isolation boundary.
///
/// Tenant is a required parameter everywhere, never an optional wrapper
/// (CLAUDE.md Directive #9). Constructing one requires a non-empty id so a
/// "default"/empty tenant can never silently appear.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TenantId(String);

/// Error returned when a [`TenantId`] cannot be constructed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TenantIdError {
    #[error("tenant id must not be empty")]
    Empty,
}

impl TenantId {
    /// Create a tenant id, rejecting the empty string.
    pub fn new(id: impl Into<String>) -> Result<Self, TenantIdError> {
        let id = id.into();
        if id.is_empty() {
            return Err(TenantIdError::Empty);
        }
        Ok(Self(id))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TenantId {
    type Error = TenantIdError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<TenantId> for String {
    fn from(value: TenantId) -> Self {
        value.0
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_empty_when_id_is_blank() {
        assert_eq!(TenantId::new(""), Err(TenantIdError::Empty));
    }

    #[test]
    fn deserialize_rejects_empty_when_json_is_empty_string() {
        let err = serde_json::from_str::<TenantId>("\"\"");
        assert!(err.is_err());
    }

    #[test]
    fn roundtrips_through_json_when_id_is_valid() {
        let t = TenantId::new("acme").unwrap();
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"acme\"");
        assert_eq!(serde_json::from_str::<TenantId>(&json).unwrap(), t);
    }
}
