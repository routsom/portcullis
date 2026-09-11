//! portcullis policy engine.
//!
//! Ordered RBAC/ABAC rules evaluated against a [`PolicyRequest`], producing an
//! [`Explained`] decision (the answer plus the rule and reason, for audit and
//! `portcullis policy test`). Evaluation is pure, in-process, and **fail-closed**:
//! if no rule matches, the default is deny (CLAUDE.md §2).
//!
//! A bounded [`cache::DecisionCache`] keyed on the full authorization inputs
//! keeps repeated decisions off the critical path so policy evaluation fits the
//! latency budget (§5 row #1, §6).
//!
//! The engine is protocol-agnostic: it speaks only `pc-core` domain types, never
//! MCP.

pub mod cache;
pub mod engine;
pub mod glob;

pub use engine::{
    AttrOp, AttrPredicate, Effect, Explained, Matcher, PolicyEngine, PolicyRequest, Rule,
};
