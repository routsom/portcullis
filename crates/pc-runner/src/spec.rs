//! Sandbox specification - the cross-platform description of *what* to run and
//! *how* isolated it must be. This type is platform-neutral; backends interpret
//! it (or reject it) per platform.

use std::path::PathBuf;

/// Network exposure for a sandboxed process.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NetworkMode {
    /// No network at all: an empty network namespace. Cloud metadata (IMDS) is
    /// unreachable by construction, not by a config flag (CLAUDE.md §5 row #14).
    #[default]
    None,
    /// Loopback only. Still no route to IMDS or the broker.
    LoopbackOnly,
}

/// How syscall filtering is applied.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SeccompMode {
    /// No syscall filter (not recommended; the runner warns).
    Disabled,
    /// Apply the seccomp-BPF profile at this path (a seccompiler JSON profile).
    /// Kept as operator-owned data so the allowlist is reviewable and testable,
    /// not hardcoded guesswork.
    #[default]
    Default,
    /// Apply a specific profile file.
    Profile(PathBuf),
}

/// The isolation posture. `Default` is the safe posture: no network, unprivileged
/// user, no-new-privileges, seccomp on, landlock on.
#[derive(Clone, Debug)]
pub struct IsolationProfile {
    pub network: NetworkMode,
    /// Container-side uid/gid the process runs as (mapped from the host euid via
    /// a user namespace).
    pub uid: u32,
    pub gid: u32,
    /// Set `PR_SET_NO_NEW_PRIVS` so the child cannot gain privileges via setuid.
    pub no_new_privileges: bool,
    pub seccomp: SeccompMode,
    /// Restrict filesystem access with landlock to the spec's declared paths.
    pub landlock: bool,
}

impl Default for IsolationProfile {
    fn default() -> Self {
        Self {
            network: NetworkMode::None,
            uid: 65_534, // "nobody"
            gid: 65_534,
            no_new_privileges: true,
            seccomp: SeccompMode::Default,
            landlock: true,
        }
    }
}

/// A fully-specified sandboxed invocation.
///
/// The program and arguments are an explicit `argv`, never a shell command
/// string (Directive #6): there is no shell, so there is nothing to inject into.
#[derive(Clone, Debug)]
pub struct SandboxSpec {
    /// `argv[0]` is the program; the rest are arguments. Never a command line.
    pub argv: Vec<String>,
    /// The complete environment. Only these variables are passed; the host
    /// environment is not inherited (no ambient credentials).
    pub env: Vec<(String, String)>,
    /// Working directory inside the sandbox.
    pub working_dir: PathBuf,
    /// Read-only root filesystem, if a dedicated rootfs is used.
    pub rootfs: Option<PathBuf>,
    /// Paths exposed read-only (in addition to a read-only root).
    pub read_only_paths: Vec<PathBuf>,
    /// Paths exposed read-write (e.g. a per-invocation scratch dir).
    pub read_write_paths: Vec<PathBuf>,
    pub isolation: IsolationProfile,
}

impl SandboxSpec {
    /// Build a spec for `program` with `args`, with the safe default isolation.
    pub fn command<I, S>(program: impl Into<String>, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut argv = vec![program.into()];
        argv.extend(arguments.into_iter().map(Into::into));
        Self {
            argv,
            env: Vec::new(),
            working_dir: PathBuf::from("/"),
            rootfs: None,
            read_only_paths: Vec::new(),
            read_write_paths: Vec::new(),
            isolation: IsolationProfile::default(),
        }
    }

    /// Validate structural invariants that hold on every platform.
    pub fn validate(&self) -> Result<(), crate::error::RunnerError> {
        use crate::error::RunnerError;
        if self.argv.is_empty() || self.argv[0].is_empty() {
            return Err(RunnerError::InvalidSpec("argv must not be empty".into()));
        }
        if let Some(root) = &self.rootfs
            && !root.is_absolute()
        {
            return Err(RunnerError::InvalidSpec(
                "rootfs must be an absolute path".into(),
            ));
        }
        if !self.working_dir.is_absolute() {
            return Err(RunnerError::InvalidSpec(
                "working_dir must be absolute".into(),
            ));
        }
        Ok(())
    }
}

/// The result of running a sandboxed process to completion.
#[derive(Clone, Debug)]
pub struct RunOutcome {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_builds_argv_with_program_first() {
        let spec = SandboxSpec::command("/bin/echo", ["hello", "world"]);
        assert_eq!(spec.argv, vec!["/bin/echo", "hello", "world"]);
    }

    #[test]
    fn default_isolation_is_the_safe_posture() {
        let iso = IsolationProfile::default();
        assert_eq!(iso.network, NetworkMode::None);
        assert!(iso.no_new_privileges);
        assert!(iso.landlock);
        assert_eq!(iso.seccomp, SeccompMode::Default);
    }

    #[test]
    fn validate_rejects_empty_argv() {
        let mut spec = SandboxSpec::command("/bin/true", Vec::<String>::new());
        spec.argv.clear();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn validate_rejects_relative_working_dir() {
        let mut spec = SandboxSpec::command("/bin/true", Vec::<String>::new());
        spec.working_dir = PathBuf::from("relative");
        assert!(spec.validate().is_err());
    }

    #[test]
    fn validate_accepts_well_formed_spec() {
        let spec = SandboxSpec::command("/bin/true", Vec::<String>::new());
        assert!(spec.validate().is_ok());
    }
}
