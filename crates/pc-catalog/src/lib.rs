//! portcullis catalog: capability provenance and trust.
//!
//! Three concerns, all fail-closed:
//! - [`manifest`] - content-addressing of the full tool definition.
//! - [`catalog`] - pinning, trust state, and rug-pull detection (a drifted
//!   definition is quarantined until re-approved).
//! - [`poison`] - scoring tool descriptions for prompt-injection / poisoning
//!   signals; high scores require explicit approval.
//!
//! The catalog speaks `pc-core` domain types and knows nothing of MCP; a
//! protocol adapter maps its tool list into [`manifest::ToolDefinition`]s.

pub mod catalog;
pub mod manifest;
pub mod poison;

pub use catalog::{Catalog, CatalogError, ObserveOutcome, diff};
pub use manifest::{ToolDefinition, canonical_json};
pub use poison::{Finding, FindingKind, HIGH_RISK_THRESHOLD, PoisonReport, scan};
