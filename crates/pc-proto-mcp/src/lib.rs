//! MCP wire codec and version negotiation.
//!
//! This is the *only* crate that knows MCP is JSON-RPC over a dated protocol
//! revision. The core (`pc-core`) stays protocol-neutral; a future protocol is a
//! new `pc-proto-*` crate, not a change here (CLAUDE.md §7, Directive #10).
//!
//! Two responsibilities:
//! - [`frame`]: parse/serialize JSON-RPC 2.0 messages while keeping `params`,
//!   `result`, and `error` as un-deserialized raw JSON, so the edge can route on
//!   method and id without paying to deserialize payloads it only relays
//!   (CLAUDE.md §5 row #1).
//! - [`version`]: the supported revision matrix and graceful-downgrade
//!   negotiation performed during `initialize`.

pub mod frame;
pub mod version;

pub use frame::{Id, Message, MessageError, Notification, Request, Response};
pub use version::{NegotiationOutcome, ProtocolVersion, SUPPORTED_VERSIONS};
