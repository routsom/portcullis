//! Edge error types.
//!
//! Errors carry enough context to identify the request without leaking secrets
//! or user data (CLAUDE.md §11): no token values, no argument contents, no
//! upstream response bodies are ever placed in an error message.

use pc_proto_mcp::MessageError;

/// Errors surfaced while handling a client request.
#[derive(Debug, thiserror::Error)]
pub enum EdgeError {
    #[error("authentication required")]
    Unauthenticated,
    #[error("forbidden: request origin or host not allowed")]
    ForbiddenOrigin,
    #[error("no upstream named {0:?} is configured")]
    UnknownUpstream(String),
    #[error("malformed request frame")]
    BadFrame(#[from] MessageError),
    #[error("upstream request failed")]
    Upstream(#[source] reqwest::Error),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("i/o error")]
    Io(#[from] std::io::Error),
}

/// Result alias for edge operations.
pub type Result<T> = std::result::Result<T, EdgeError>;
