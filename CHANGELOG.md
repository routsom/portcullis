# Changelog

All notable, user-visible changes are recorded here, written for an operator
(CLAUDE.md §13). This project follows semantic versioning; the public surfaces
are the CLI, the config schema, the WIT plugin interface, the audit log format,
the HTTP admin API, and the on-disk state format (§8).

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added - M1–M6

- **Contain (M1)**: an encrypted-at-rest secret **broker** (`pc-broker`) with
  short-lived scoped credential tokens; a fail-closed **egress allowlist** (exact
  / wildcard / CIDR) with an **unconditional IMDS blackhole**; and a **Linux
  sandbox** (`pc-runner`: user/mount/net namespaces, seccomp, landlock, read-only
  root, no-new-privileges). The sandbox is Linux-only and **verified in CI**, not
  on non-Linux hosts; on those it fails closed. See `docs/adr/0004`, `docs/adr/0005`.
- **Decide (M2)**: a fail-closed **RBAC/ABAC policy engine** (`pc-policy`) with a
  decision cache; **rate limiting** (429) and per-upstream **circuit breakers**
  (503); and an append-only, hash-chained, optionally-signed **audit log**
  (`pc-audit`). All enforced in the live request path (`deny → 403/429/503`), with
  the passthrough fast path preserved.
- **Trust (M3)**: content-addressed capability **manifests** with **rug-pull
  quarantine**, and a **tool-poisoning scanner** with a corpus and the
  `portcullis catalog scan` command.
- **Translate (M4)**: load-time **OpenAPI → capability** translation
  (`pc-proto-openapi`), a **capability facade** (`find` / `find_and_invoke`) with
  honest **token accounting**, and `portcullis translate openapi`.
- **Operate (M5)**: per-tenant **metrics** at `/metrics` (local export only),
  **versioned state with forward migrations** (`pc-state`), and **active-active
  HA** — stateless session tokens verify on any node sharing the key.
- **Endure (M6)**: a frozen **WIT plugin ABI** (`wit/portcullis.wit`) and an MCP
  **conformance suite** (`pc-conformance`, `just conformance`).
- **Docs**: an mdBook documentation site under `docs/book`, a token report, and a
  GitHub Actions CI workflow (Linux + macOS).

### Deferred (tracked)

gRPC adapter, sigstore provenance, live catalog ingest on the edge, OTLP exporter,
the WASM component *host* runtime, and the cargo-public-api baseline. The Linux
sandbox's red-team certification and an independent security review gate
production use.

### Added - M0 "Skeleton"

- **`portcullis` binary** with three subcommands:
  - `serve --config <file>` - run the gateway. Supports `--strict-config` to
    treat unknown config keys as errors (otherwise they warn and are ignored).
  - `doctor --config <file>` - diagnose config, upstream connectivity, clock
    skew, and sandbox availability in one command; exits non-zero on a failing
    check.
  - `config explain --config <file>` - print the effective configuration with
    the provenance (default / file / env) of notable values.
- **Transports**: Streamable HTTP and stdio for clients. HTTP upstreams are
  proxied with streaming relay and connection pooling.
- **Authentication is mandatory on every transport** - there is no `--no-auth`.
  M0 ships pre-shared bearer tokens (PATs); token values are read from
  environment variables named in the config, never stored inline.
- **DNS-rebinding hardening** on the HTTP listener: `Host` and `Origin`
  allow-lists and `Sec-Fetch-Site` enforcement, checked before authentication.
- **Stateless sessions**: signed session tokens carry their own routing hint and
  resumption cursor, so any node can serve any request (no session affinity).
  Configure a shared `session.secret_env` for multi-node deployments.
- **MCP protocol negotiation** across revisions `2026-07-28`, `2025-11-25`, and
  `2025-06-18`, with graceful downgrade for unknown client versions.
- **Example config** at `examples/portcullis.toml`, validated in CI.
- **CI gate** (`just check`): formatting, pedantic clippy, `cargo deny`, tests,
  and directive-enforcing checks (`deny-imports`, `check-licensing`,
  `dep-graph`, `api-diff`). Reference latency benchmark via `just bench`.

### Security

- The gateway executes no tool logic and cannot spawn a process; the edge crate
  is verifiably free of process-spawning imports (`xtask deny-imports`).
- Everything is Apache-2.0; no capability is gated on a license
  (`xtask check-licensing`).

### Known limitations (planned for later milestones)

- No sandboxed execution, secret brokering, egress control, or IMDS blackhole
  yet (M1). In M0 the edge connects to upstream MCP servers over HTTP only; it
  does not spawn stdio upstreams (see `docs/adr/0003-m0-upstream-over-http.md`).
- No policy evaluation, rate/size limits, circuit breakers, or hash-chained
  audit yet (M2). Once authenticated, requests are allowed.
