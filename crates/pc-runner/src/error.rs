//! Runner error types.

/// Errors from sandboxed execution.
#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    /// The current platform has no isolation backend (e.g. macOS). The runner
    /// fails closed rather than executing without a sandbox.
    #[error("sandboxed execution is not supported on this platform")]
    Unsupported,

    /// The spec is invalid (empty argv, relative rootfs, …).
    #[error("invalid sandbox spec: {0}")]
    InvalidSpec(String),

    /// Setting up isolation (namespaces, seccomp, landlock, mounts) failed.
    #[error("failed to establish isolation: {0}")]
    Isolation(String),

    /// Spawning or waiting on the child failed.
    #[error("failed to run sandboxed process")]
    Spawn(#[source] std::io::Error),
}

/// Result alias for runner operations.
pub type Result<T> = std::result::Result<T, RunnerError>;
