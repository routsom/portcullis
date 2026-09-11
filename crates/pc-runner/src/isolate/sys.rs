//! Confined syscall layer for the Linux sandbox.
//!
//! This is the only place `pc-runner` performs low-level isolation calls. Most
//! are safe `nix`/`landlock`/`seccompiler` wrappers; any raw `unsafe` carries a
//! `// SAFETY:` note (CLAUDE.md §4). Functions here run inside the forked child
//! before `exec`, so they avoid the heap invariants of the parent and return an
//! `io::Error` on failure, which aborts the exec and fails the run closed.
//!
//! Verification status: compiled and exercised only in Linux CI and the
//! red-team suite (`tests/redteam/`), never on a non-Linux host.

use std::io;
use std::path::Path;

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

    for path in read_only {
        created = add_path(created, path, ro)?;
    }
    for path in read_write {
        created = add_path(created, path, rw)?;
    }

    created.restrict_self().map_err(io::Error::other)?;
    Ok(())
}

fn add_path<R>(ruleset: R, path: &Path, access: landlock::AccessFs) -> io::Result<R>
where
    R: landlock::RulesetCreatedAttr,
{
    use landlock::{PathBeneath, PathFd};
    let fd = PathFd::new(path).map_err(io::Error::other)?;
    ruleset
        .add_rule(PathBeneath::new(fd, access))
        .map_err(io::Error::other)
}

/// Apply a seccomp-BPF syscall filter.
///
/// `Default`/`Disabled` install no filter (the operator is expected to supply a
/// reviewed profile via `Profile`); `Profile` compiles a seccompiler JSON
/// profile and applies its `default` thread filter. Keeping the allowlist as
/// operator-owned data avoids shipping an untested hardcoded filter that would
/// silently break most programs.
pub fn apply_seccomp(mode: &SeccompMode) -> io::Result<()> {
    match mode {
        SeccompMode::Disabled | SeccompMode::Default => Ok(()),
        SeccompMode::Profile(path) => {
            let json = std::fs::read_to_string(path)?;
            let arch = std::env::consts::ARCH;
            let target = seccompiler::TargetArch::try_from(arch)
                .map_err(|_| io::Error::other(format!("unsupported seccomp arch {arch}")))?;
            let mut filters = seccompiler::compile_from_json(json.as_bytes(), target)
                .map_err(io::Error::other)?;
            let program = filters
                .remove("default")
                .ok_or_else(|| io::Error::other("seccomp profile missing `default` filter"))?;
            seccompiler::apply_filter(&program).map_err(io::Error::other)
        }
    }
}
