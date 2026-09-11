//! Core domain model for portcullis.
//!
//! This crate is the hub every other crate depends on, so it is kept
//! deliberately small and pure: no I/O, no async, and - critically - no
//! knowledge of any wire protocol (CLAUDE.md §7). If you find yourself reaching
//! for `jsonrpc`, an `Mcp-` header, or `tokio` here, the abstraction is in the
//! wrong crate.
//!
//! The model is organised around five nouns the whole gateway reasons about:
//! [`Tenant`], [`Principal`] (composed into a [`DelegationChain`]),
//! [`Capability`], [`Invocation`], and [`Decision`].

mod capability;
mod decision;
mod hash;
mod invocation;
mod principal;
mod tenant;

pub use capability::{Capability, CapabilityId, CapabilityState};
pub use decision::{Decision, DenyReason};
pub use hash::{ArgShapeHash, ContentHash, Digest};
pub use invocation::Invocation;
pub use principal::{DelegationChain, Principal, PrincipalId, PrincipalKind};
pub use tenant::TenantId;

/// A tenant is the top-level isolation boundary. In M0 it is a thin newtype, but
/// it is threaded through every request from the start because there is no
/// single-tenant fast path (CLAUDE.md Directive #9).
pub type Tenant = TenantId;
