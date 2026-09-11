//! OpenAPI 3 → capability adapter.
//!
//! An OpenAPI document is translated **once, at load time**, into a table of
//! invocable capabilities - each operation becomes a tool with a derived name, a
//! description, a merged JSON Schema for its arguments, and an [`HttpBinding`]
//! describing how to build the upstream request. Nothing is interpreted per
//! request, which is how the gateway stays inside the latency budget where
//! other gateways spend 100-300 ms translating on the hot path (CLAUDE.md §5
//! row #10).
//!
//! Only a safe, common subset of OpenAPI is supported; unsupported constructs
//! are skipped with a diagnostic rather than guessed at.

mod spec;
mod translate;

pub use spec::OpenApiDoc;
pub use translate::{Capability, HttpBinding, ParamLocation, TranslateError, translate};
