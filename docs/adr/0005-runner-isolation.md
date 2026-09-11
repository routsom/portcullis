# ADR-0005: Runner isolation backend and verification

- Status: accepted
- Date: 2026-09-11

## Context

The runner (Directive #1) must execute each tool invocation in a contained
process: unprivileged uid, no ambient host credentials, no route to cloud
metadata or the broker, restricted filesystem, and syscall filtering. This is
Linux kernel machinery (user/mount/net namespaces, landlock, seccomp-BPF) with
no portable equivalent.

The project is developed partly on macOS, where none of this exists and none of
it can be built or tested.

## Decision

`pc-runner` splits into:

- A **platform-neutral API and policy** (`spec`, `Runner`, `RunOutcome`) that
  compiles and is tested everywhere.
- A **Linux backend** (`isolate::linux`, `isolate::sys`) behind
  `cfg(target_os = "linux")`, using `nix`, `landlock`, and `seccompiler`. Its
  Linux-only dependencies are declared under a target-specific table so other
  platforms do not pull them.
- A **fail-closed `unsupported` backend** for every other platform that returns
  `RunnerError::Unsupported` rather than executing without a sandbox.

`pc-runner` is the single crate permitted `unsafe`, confined to `isolate::sys`
and each block justified with `// SAFETY:` (CLAUDE.md §4). Isolation is
established inside the forked child before `exec`, so a setup failure aborts the
exec and the tool never runs unsandboxed.

The empty network namespace is what blackholes IMDS (§5 row #14): with no route,
169.254.169.254 and the broker are unreachable by construction, not by a flag.

Seccomp uses **operator-owned reviewed JSON profiles** rather than a hardcoded
allowlist, so the filter is data that can be audited and tested, not guesswork
baked into the binary.

## Verification status (important)

The Linux backend is **verified only in Linux CI** (`.github/workflows/ci.yml`)
and, at the M1 exit criterion, by the red-team escape suite (`tests/redteam/`).
It is **not** certified by tests on a non-Linux host. Until that CI is green and
the red-team suite passes, the sandbox must not be relied on in production. This
is a deliberate consequence of the cfg-gated approach and is stated plainly so no
one mistakes "compiles" for "contained."

## Consequences

- Development proceeds on any platform; the sandbox is real only on Linux.
- The known gap to close before certification: a `clone`-based launcher for a
  correct PID namespace (the current `unshare`-in-`pre_exec` path does not make
  the exec'd process PID 1), plus the red-team corpus. Tracked for M1 exit.
