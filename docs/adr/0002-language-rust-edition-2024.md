# ADR-0002: Rust, edition 2024

- Status: accepted
- Date: 2026-09-11

## Context

Directive #4 makes added latency a hard budget (p99 ≤ 5 ms of gateway overhead),
and Directive #1 requires strong process-level isolation of execution. The
per-request memory/CPU overhead and a non-recoverable GC pause in the hot path
are exactly what kill gateway latency budgets, so a garbage-collected runtime is
disqualified for the data path (this is Directive #4 made concrete, not a
preference). §5 row #20 also calls out interpreted-runtime overhead as a prior
failure.

## Decision

The gateway is written in **Rust, edition 2024**, MSRV pinned in
`rust-toolchain.toml` and bumped deliberately in its own commit.

`#![forbid(unsafe_code)]` applies to every crate (enforced via
`[workspace.lints]`). The sole future exception is `pc-runner`'s syscall layer
(`pc-runner::isolate::sys`), which does not exist in M0; when it lands, every
`unsafe` block there must carry a `// SAFETY:` justification.

Error handling: `thiserror` in libraries, `anyhow` only in `pc-cli` and tests.
No `unwrap`/`expect` outside tests and startup. Clippy pedantic is on with a
short, justified allow-list at the workspace root.

## Consequences

- No GC pauses on the data path; predictable tail latency.
- `forbid(unsafe_code)` means some ergonomic APIs (e.g. `std::env::set_var`,
  which is `unsafe` in edition 2024) are unavailable; callers restructure
  instead (e.g. the launcher sets env vars for the benchmark).
- Edition 2024 requires rustc ≥ 1.85.
