//! portcullis runner: one sandboxed process per invocation.
//!
//! The runner is where tool logic actually executes - never in the edge
//! (Directive #1). Each invocation runs in its own process with an unprivileged
//! uid, no ambient host credentials, no network route to cloud metadata or the
//! broker, a read-only root, a landlock filesystem ruleset, and a seccomp
//! syscall filter.
//!
//! Isolation is Linux-specific kernel machinery (user/mount/net namespaces,
//! seccomp-BPF, landlock). On platforms without it (e.g. macOS) the runner
//! reports [`RunnerError::Unsupported`] and **fails closed** - it never executes
//! a tool without a sandbox.
//!
//! ## Verification status
//!
//! The cross-platform API, spec validation, and the unsupported backend are
//! covered by tests that run everywhere. The Linux backend
//! ([`isolate`], `cfg(target_os = "linux")`) is compiled and exercised only in
//! Linux CI plus the red-team suite; it is **not** certified by tests on a
//! non-Linux host. See `docs/adr/0005-runner-isolation.md`.

pub mod error;
pub mod isolate;
pub mod spec;

pub use error::{Result, RunnerError};
pub use spec::{IsolationProfile, NetworkMode, RunOutcome, SandboxSpec, SeccompMode};

/// A backend that runs a [`SandboxSpec`] to completion under isolation.
pub trait Runner: Send + Sync + std::fmt::Debug {
    /// Run the spec, returning its outcome. Implementations must validate the
    /// spec and fail closed if isolation cannot be established.
    fn run(&self, spec: &SandboxSpec) -> Result<RunOutcome>;
}

/// The isolation backend for the current platform. On Linux this is the real
/// sandbox; elsewhere it fails closed with [`RunnerError::Unsupported`].
#[must_use]
pub fn default_runner() -> Box<dyn Runner> {
    isolate::default_runner()
}

/// Whether sandboxed execution is available on this platform.
#[must_use]
pub fn sandbox_available() -> bool {
    isolate::AVAILABLE
}
