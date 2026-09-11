//! Confined syscall layer for the Linux sandbox.
//!
//! This is the only place `pc-runner` performs low-level isolation calls. Most
//! are safe `nix`/`landlock` wrappers; any raw `unsafe` carries a
//! `// SAFETY:` note (CLAUDE.md §4). Functions here run inside the forked child
//! before `exec`, so they avoid the heap invariants of the parent and return an
//! `io::Error` on failure, which aborts the exec and fails the run closed.
//!
//! Verification status: compiled and exercised only in Linux CI and the
//! red-team suite (`tests/redteam/`), never on a non-Linux host.

use std::io;

use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};

use crate::spec::{NetworkMode, SeccompMode};

fn errno_to_io(e: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

/// Enter fresh namespaces. A new, empty network namespace means there is no
/// route to cloud metadata (169.254.169.254) or the broker: IMDS is blackholed
/// by construction, not by a flag (CLAUDE.md §5 row #14).
pub fn enter_namespaces(_network: NetworkMode) -> io::Result<()> {
    let flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWNET
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWIPC;
    unshare(flags).map_err(errno_to_io)
    // NetworkMode::LoopbackOnly (bringing `lo` up inside the netns) is a
    // follow-up; today both modes yield a network with no usable route, which is
    // the safe direction.
}

/// Map the sandbox uid/gid to the host's effective ids via the user namespace,
/// enabling rootless isolation with no real privilege.
pub fn map_ids(uid: u32, gid: u32) -> io::Result<()> {
    let euid = nix::unistd::geteuid().as_raw();
    let egid = nix::unistd::getegid().as_raw();
    // Must deny setgroups before writing gid_map in a user namespace.
    std::fs::write("/proc/self/setgroups", "deny")?;
    std::fs::write("/proc/self/uid_map", format!("{uid} {euid} 1"))?;
    std::fs::write("/proc/self/gid_map", format!("{gid} {egid} 1"))?;
    Ok(())
}

/// Set `PR_SET_NO_NEW_PRIVS` so the child cannot escalate via setuid binaries.
pub fn set_no_new_privileges() -> io::Result<()> {
    nix::sys::prctl::set_no_new_privs().map_err(errno_to_io)
}

/// Make mount propagation private and remount the root filesystem read-only.
pub fn make_filesystem_readonly() -> io::Result<()> {
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(errno_to_io)?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .map_err(errno_to_io)
}

/// Restrict filesystem access with landlock to only the declared paths.
/// Unlisted paths become inaccessible even though the mount is present.
// `ro`/`rw` are the conventional names for read vs read-write access sets.
#[allow(clippy::similar_names)]
pub fn apply_landlock(
    read_only: &[std::path::PathBuf],
    read_write: &[std::path::PathBuf],
) -> io::Result<()> {
    use landlock::{
        ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    };

    let abi = ABI::V2;
    let ro = AccessFs::from_read(abi);
    let rw = AccessFs::from_all(abi);

    let mut created = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(io::Error::other)?
        .create()
        .map_err(io::Error::other)?;

    // `from_read`/`from_all` yield `BitFlags<AccessFs>`; `PathBeneath::new`
    // accepts anything `Into<BitFlags<AccessFs>>`, so type inference carries it.
    for path in read_only {
        let fd = PathFd::new(path).map_err(io::Error::other)?;
        created = created
            .add_rule(PathBeneath::new(fd, ro))
            .map_err(io::Error::other)?;
    }
    for path in read_write {
        let fd = PathFd::new(path).map_err(io::Error::other)?;
        created = created
            .add_rule(PathBeneath::new(fd, rw))
            .map_err(io::Error::other)?;
    }

    created.restrict_self().map_err(io::Error::other)?;
    Ok(())
}

/// Apply a seccomp-BPF syscall filter.
///
/// Seccomp enforcement is developed and validated against the real-kernel
/// red-team harness (see ADR-0005) and is intentionally **not installed yet**;
/// namespaces + landlock provide the load-bearing containment in the interim.
/// [`SeccompMode`] stays part of the spec so a reviewed filter can be wired in
/// here without changing any caller.
// Keeps the uniform `io::Result` syscall-helper signature so the real filter
// wires in (and can fail) without touching the `pre_exec` call site.
#[allow(clippy::unnecessary_wraps)]
pub fn apply_seccomp(_mode: &SeccompMode) -> io::Result<()> {
    Ok(())
}
