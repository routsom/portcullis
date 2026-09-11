//! Linux sandbox supervisor.
//!
//! Spawns one process per invocation inside fresh user/mount/net/uts/ipc
//! namespaces, with mapped-unprivileged ids, a read-only root, a landlock
//! filesystem ruleset, no-new-privileges, and (optionally) a seccomp filter -
//! all established in the child before `exec`. The empty network namespace makes
//! cloud metadata and the broker unreachable by construction.
//!
//! Verification status: CI-gated (see `crate` docs / ADR-0005).

use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::Runner;
use crate::error::{Result, RunnerError};
use crate::spec::{RunOutcome, SandboxSpec};

use super::sys;

/// The Linux isolation backend.
#[derive(Debug, Default)]
pub struct LinuxRunner;

impl LinuxRunner {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Runner for LinuxRunner {
    fn run(&self, spec: &SandboxSpec) -> Result<RunOutcome> {
        spec.validate()?;

        let mut cmd = Command::new(&spec.argv[0]);
        cmd.args(&spec.argv[1..]);
        // Never inherit the host environment - no ambient credentials.
        cmd.env_clear();
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        cmd.current_dir(&spec.working_dir);

        // Capture only what the child needs, since the closure must be `Send`
        // and outlive this frame.
        let iso = spec.isolation.clone();
        let read_only = spec.read_only_paths.clone();
        let read_write = spec.read_write_paths.clone();

        // SAFETY: `pre_exec` runs in the forked child after `fork` and before
        // `exec`. The closure performs isolation setup (unshare, /proc writes,
        // prctl, mount, landlock, seccomp) and returns `io::Error` on any
        // failure, which aborts the exec so the process never runs unsandboxed.
        // It does not rely on parent heap state beyond the moved, owned captures.
        #[allow(unsafe_code)]
        unsafe {
            cmd.pre_exec(move || {
                sys::enter_namespaces(iso.network)?;
                sys::map_ids(iso.uid, iso.gid)?;
                sys::make_filesystem_readonly()?;
                if iso.landlock {
                    sys::apply_landlock(&read_only, &read_write)?;
                }
                if iso.no_new_privileges {
                    sys::set_no_new_privileges()?;
                }
                // seccomp last: once installed it constrains everything after.
                sys::apply_seccomp(&iso.seccomp)?;
                Ok(())
            });
        }

        let output = cmd.output().map_err(RunnerError::Spawn)?;
        Ok(RunOutcome {
            exit_code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}
