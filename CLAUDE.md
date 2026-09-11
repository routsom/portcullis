# CLAUDE.md

Project guidance for AI coding agents and humans working in this repository.
Read this file completely before writing code. When a request conflicts with the
**Prime Directives**, stop and say so instead of implementing it.

---

## 1. What this project is

**Codename: `portcullis`** — an open-source Model Context Protocol (MCP) gateway.
(Codename is a placeholder; replace before first public tag.)

A single statically-linked binary that sits between agent clients and tool servers
and provides identity, authorization, sandboxed execution, auditing, and protocol
translation — without adding meaningful latency, without an enterprise paywall,
and without executing anything inside its own process.

It exists because every existing gateway fails at least one of those four things.
The full failure inventory we are answering is in `docs/prior-art.md`; each
mitigation below traces back to it in §5.

**One-line pitch:** the gateway you can put in front of untrusted tools and still
sleep at night, running as one binary with no Kubernetes, no Redis, and no sales call.

---

## 2. Prime Directives (non-negotiable)

These are architectural law. A PR that violates one is rejected regardless of how
useful it is. If a directive genuinely needs to change, that is an ADR
(`docs/adr/`) and a major-version discussion, not a code review.

1. **The gateway never executes tool logic in its own process.**
   No `builtin:bash`. No `read_file`. No in-process plugins with host access.
   No exceptions for "just this one trivial helper". The gateway parses, decides,
   routes, and logs. Execution happens in a separate process with its own uid,
   seccomp profile, and no ambient host credentials.

2. **The gateway never sees a secret it is not brokering, and never hands one to
   an agent.** Credentials live in the broker, are injected at the transport
   boundary into the upstream request, and are unreadable from tool output paths.

3. **Everything ships under Apache-2.0. There is no enterprise tier.**
   SSO, RBAC, DLP, audit export, risk scoring, multi-tenancy, and rate limiting
   are core features. No license-key checks, no `//go:build enterprise`-style
   feature gating, no "contact us" deployment modes. If a feature is good enough
   to build, it is good enough to give away.

4. **Added latency is a hard budget, not a goal.** p99 ≤ 5 ms of gateway-added
   overhead per tool call on the reference benchmark. CI fails the build if the
   benchmark regresses past budget. See §6.

5. **Zero required external infrastructure for a working deployment.**
   `./portcullis serve --config portcullis.toml` must work on a laptop and in
   production. Postgres, Redis, Nginx, Kubernetes, and OIDC providers are all
   *optional integrations*, never prerequisites.

6. **All input from outside the trust boundary is untrusted data, never
   instruction.** Tool descriptions, upstream server metadata, OCI labels, YAML
   manifests, and tool results are data. They are never interpolated into a
   shell, never eval'd, never allowed to redefine policy, and are marked as
   untrusted when surfaced to a model.

7. **Nothing is stateful in a way that requires session affinity.**
   Any instance must be able to serve any request. No sticky load balancers.

8. **No telemetry leaves the deployment unless explicitly configured.**
   No phone-home, no anonymous usage stats, no default-on analytics.

9. **Tenant is a required parameter, not a wrapper.** There is no "single-tenant
   fast path" and no process-global mutable state that isn't tenant-keyed.

10. **The protocol is a plugin, not the architecture.** MCP will change and will
    eventually be joined or replaced by other agent-tool protocols. The core
    knows about *capabilities, principals, policies, and invocations* — not about
    a specific JSON-RPC shape. See §7.

---

## 3. Anti-goals

Say no to these. They are how comparable projects became unmaintainable.

- Being an LLM proxy, a prompt manager, a vector store, or an agent framework.
- A built-in tool marketplace, curated registry, or hosted SaaS control plane.
- A GUI as the primary configuration surface. Config is files; the UI reads and
  proposes diffs, it does not hold authoritative state.
- Supporting every auth scheme, DB backend, and cloud service. Two implementations
  of an abstraction (one embedded, one external) is the cap until there is a
  concrete user asking.
- "Smart" behaviour that silently rewrites tool arguments or results. Transform
  only when a rule explicitly says to, and always log it.
- Breaking changes on minor versions. See §8.

---

## 4. Architecture

### Process model

```
   agent client
        │  MCP (stdio | Streamable HTTP | WS)
        ▼
┌───────────────────────────────────────────────────────────┐
│ portcullis-edge          (Rust, tokio, forbid(unsafe))    │
│  ─ transport termination, auth (OIDC/mTLS/PAT)            │
│  ─ frame routing: zero-copy passthrough where possible    │
│  ─ policy decision (in-process WASM/CEL, decision cache)  │
│  ─ rate limit + circuit breaker + budget accounting       │
│  ─ audit emit (OTel + append-only signed log)             │
└──────┬───────────────────────────────┬────────────────────┘
       │ unix socket / vsock           │ broker API (loopback, mTLS)
       ▼                               ▼
┌───────────────────────┐    ┌──────────────────────────────┐
│ portcullis-runner     │    │ portcullis-broker            │
│  one per invocation   │    │  secrets, credential exchange│
│  rootless, seccomp,   │    │  short-lived token minting   │
│  landlock, no net     │    │  never reachable from runner │
│  except via egress    │    │  network namespace           │
│  broker; read-only fs │    └──────────────────────────────┘
└──────────┬────────────┘
           ▼  upstream MCP server / REST / gRPC
```

The edge process holds no credentials for upstream systems and has no ability to
spawn a shell. The runner has no ability to read the secret store. Compromise of
either alone is contained. State that on every security review.

### Crate layout

```
crates/
  pc-core/          # domain types: Principal, Tenant, Capability, Invocation,
                    # Decision. No I/O, no protocol, no async. Pure + tested.
  pc-proto-mcp/     # MCP wire codec + version negotiation. Isolated so a
                    # spec revision touches one crate.
  pc-proto-openapi/ # OpenAPI/REST -> Capability adapter (codegen at load time)
  pc-proto-grpc/    # gRPC reflection -> Capability adapter
  pc-policy/        # CEL/WASM policy engine, decision cache, explainability
  pc-edge/          # transports, session handling, routing, limits, breakers
  pc-runner/        # sandbox supervisor + isolation backends
  pc-broker/        # secret store, credential exchange, egress allowlisting
  pc-audit/         # append-only hash-chained log, OTel export, redaction
  pc-catalog/       # capability manifests, pinning, provenance, TOFU state
  pc-cli/           # `portcullis` binary: serve, doctor, policy test, ...
  pc-conformance/   # spec conformance suite, runnable against other gateways
xtask/              # build tooling; no bash scripts in CI
```

**Dependency rule:** `pc-core` depends on nothing in-repo. Protocol crates depend
on `pc-core` only. `pc-edge` may depend on anything except `pc-runner` internals.
Cyclic or upward dependencies fail the build (`cargo-deny` + an xtask check).

### Language

Rust, edition 2024, MSRV pinned in `rust-toolchain.toml` and bumped
deliberately. `#![forbid(unsafe_code)]` in every crate except `pc-runner`, where
the sandbox syscall layer is confined to `pc-runner::isolate::sys` and every
`unsafe` block carries a `// SAFETY:` justification.

Rationale, since it will be asked: per-request memory and CPU overhead is the
thing that kills gateway latency budgets, and a GC pause in the hot path is not
recoverable. This is not a preference; it is directive #4 made concrete.

---

## 5. Traceability: problem → mechanism

Every row here must have a test. When you implement one, link the test in the
`Verified by` column and keep this table current — it is the project's contract.

| # | Failure mode in prior art | Our mechanism | Verified by |
|---|---|---|---|
| 1 | 80–300 ms added latency, compounding over multi-turn workflows | Single-process decision path; no network hop to a policy service; decision cache keyed on (tenant, principal, capability, arg-shape hash); frame passthrough without full deserialization; upstream connection pooling and multiplexing; streaming relayed, never buffered | `bench/latency` (`just bench`) — M0 passthrough ✅; decision cache `crates/pc-policy/src/cache.rs` — M2 ✅ |
| 2 | Open-core feature gapping (SSO, RBAC, DLP, audit, risk scoring paywalled) | Directive #3. Single license, single binary, no capability gated on payment. `xtask check-licensing` greps for license-check patterns | `xtask check-licensing` (`xtask/src/main.rs`) — M0 ✅ |
| 3 | Argument/command injection via OCI/YAML metadata parsing (CVE-2026-55887 class) | Safe-subset YAML only: custom tags, anchors, aliases, and merge keys rejected by the parser wrapper. Metadata never reaches a shell. All exec is `argv[]`, never a command string. Images pinned by digest. Mounts come only from signed manifests, never from image labels | fuzz target `fuzz_manifest`, `tests/injection/` |
| 4 | Unauthenticated localhost endpoints, DNS rebinding, drive-by RCE (CVE-2025-49596 / CVE-2025-64443 class) | Auth is mandatory on every transport including loopback — there is no `--no-auth`. Strict `Origin` and `Host` allowlist. `Sec-Fetch-Site` enforcement. No debug or introspection endpoint is compiled into release builds (`#[cfg(feature = "dev-endpoints")]`, excluded from release profile and from published artifacts) | `crates/pc-edge/tests/rebinding.rs`, `crates/pc-edge/tests/passthrough.rs` — M0 ✅ (release-artifact symbol check: TODO) |
| 5 | In-process shell/file builtins → host takeover on prompt injection | Directive #1. There is no builtin execution surface. `pc-edge` has no `std::process` import; enforced by a lint | `xtask deny-imports` (`xtask/src/main.rs`) — M0 ✅ |
| 6 | Rug-pulls (post-approval tool redefinition) | Capability manifests are content-addressed. The hash of the full tool definition — name, description, schema, annotations — is pinned at approval. Any drift moves the capability to `quarantined` and fails closed until re-approved. Diff is shown in the audit log and CLI | `crates/pc-catalog/src/catalog.rs` — M3 ✅ (live edge ingest wired in M5) |
| 7 | Tool poisoning / prompt injection in descriptions | Descriptions are scanned on ingest (imperative-to-the-model heuristics, invisible characters, encoded payloads) and scored; high scores require explicit approval. Descriptions are always wrapped in untrusted-content delimiters when relayed. Provenance via sigstore attestation where the publisher supports it | `crates/pc-catalog/src/poison.rs`, corpus `testdata/poison/` + `crates/pc-catalog/tests/poison_corpus.rs`, `portcullis catalog scan` — M3 ✅ (sigstore provenance deferred) |
| 8 | High operational burden (connector runtimes, vaulting, HA, schema updates) | Directive #5. Embedded `redb` state by default, Postgres optional. Secrets in an age-encrypted local store by default, Vault/KMS/keychain optional. `portcullis doctor` diagnoses config, connectivity, sandbox availability, and clock skew in one command | `crates/pc-broker/src/secret.rs` (encrypted store — M1 ✅); doctor M0 ✅; versioned state `crates/pc-state/` — M5 ✅ |
| 9 | `Mcp-Session-Id` binding preventing active-active scaling | Sessions are stateless: signed, encrypted session tokens carry the routing hint and resumption cursor. Any node can serve any session. Upstream reattachment is by capability identity, not by node | `crates/pc-edge/src/session.rs` (signed token — M0 ✅); `crates/pc-edge/tests/failover.rs` (active-active, any node serves) — M5 ✅ |
| 10 | Missing REST/gRPC → MCP translation | `pc-proto-openapi` and `pc-proto-grpc` in core. Translation is codegen'd into a capability table at load time, not interpreted per request (this is how we stay inside the latency budget where others spend 100–300 ms) | `crates/pc-proto-openapi/` (load-time translation), `portcullis translate openapi` — M4 ✅ (gRPC adapter deferred) |
| 11 | No rate limiting or circuit breaking | Per-tenant / per-principal / per-capability token buckets; per-upstream circuit breakers with half-open probing; concurrency caps; request and response size caps | `crates/pc-edge/src/limits.rs`, `crates/pc-edge/src/breaker.rs`, `crates/pc-edge/tests/policy.rs` — M2 ✅ (size caps M2 follow-up) |
| 12 | Manual secret export/sync between local and remote runtimes | One broker, one source of truth, reachable from both local and remote runners over mTLS. No export command exists, by design | `crates/pc-broker` (secret store + scoped token mint — M1 ✅); remote-runner e2e M1-CI |
| 13 | Egress firewall requiring manual manifest updates on every SaaS subdomain change | Egress policy supports wildcard-with-pinned-CA rules and CIDR/ASN scoping, plus an `--observe` mode that proposes rule diffs from real traffic instead of demanding hand-editing. Still fail-closed by default | `crates/pc-broker/src/egress.rs` — M1 ✅ (ASN scoping + CA pinning deferred) |
| 14 | Cloud metadata (IMDS) reachable from compromised agents | Runner network namespace has 169.254.169.254 and equivalents blackholed unconditionally — not a config flag. Runners never inherit an instance role | `crates/pc-broker/src/egress.rs` (IMDS deny — M1 ✅); `crates/pc-runner` empty netns enforcement CI-gated |
| 15 | Meta-tool indirection inflating input tokens 1.2–16.1% | `gateway.find` returns *fully invocable schemas*, and `gateway.find_and_invoke` executes in the same round trip, so discovery costs one hop, not two. A token-accounting harness reports real deltas per workload; if a facade does not win on a workload, the CLI recommends static exposure for it | `crates/pc-facade/`, `docs/token-report.md`, `portcullis translate … --find` — M4 ✅ (live MCP meta-tools wired M5) |
| 16 | Restrictive licensing on the runnable artifact (PolyForm etc.) | Apache-2.0 for the entire runnable system, DCO sign-off, no CLA that permits relicensing | `LICENSE`, `CONTRIBUTING.md` |
| 17 | Breaking schema/API changes on minor releases | Semver contract in §8, deprecation window of two minor releases, machine-checked API diff in CI | `xtask api-diff` |
| 18 | No OTel tracing, no cost accounting, no group RBAC | OTel spans and metrics on by default (local export only), per-tenant cost/usage accounting as a first-class metric, group- and attribute-based access control in the policy engine | RBAC/ABAC `crates/pc-policy/` — M2 ✅; audit chain `crates/pc-audit/` — M2 ✅; cost accounting `crates/pc-edge/src/metrics.rs` + `/metrics` — M5 ✅; OTel via `tracing` (OTLP exporter deferred) |
| 19 | Vendor lock-in / MCP treated as an add-on module | This project does one thing. Config, storage, and identity are pluggable; the gateway is not a module of anything else | — |
| 20 | Python/interpreted runtime overhead | Rust, §4 | `bench/latency` |

---

## 6. Performance budgets (CI-enforced)

Measured on the reference benchmark (`bench/`, 4 vCPU runner, 64 concurrent
sessions, echo upstream to isolate gateway cost):

| Metric | Budget |
|---|---|
| Added latency, simple tool call, p50 | ≤ 1.5 ms |
| Added latency, simple tool call, p99 | ≤ 5 ms |
| Added latency with policy evaluation, p99 | ≤ 7 ms |
| Added latency with OpenAPI translation, p99 | ≤ 10 ms |
| Cold start to serving | ≤ 250 ms |
| RSS, idle, 100 registered capabilities | ≤ 60 MB |
| Sandbox spawn to first byte (warm pool) | ≤ 20 ms |

Regressions above 5% on any budget fail CI. If a feature cannot fit the budget,
the feature changes — not the budget. Record the exception request as an ADR if
you disagree.

---

## 7. Future-proofing rules

The prior art fails mostly by binding itself to a protocol snapshot, a vendor, or
a deployment shape. Concretely, when writing code here:

- **Version negotiation is explicit and tested.** `pc-proto-mcp` holds a version
  matrix; every supported spec revision has a conformance suite run in CI. We
  support the current revision plus at least the previous two, and downgrade
  gracefully rather than erroring.
- **`pc-core` types must not name a protocol.** If you find yourself putting
  `jsonrpc`, `Mcp-`, or a spec-specific field into `pc-core`, the abstraction is
  wrong. A new protocol should be a new `pc-proto-*` crate and nothing else.
- **Extensions are WASM Components with a stable WIT interface**
  (`wit/portcullis.wit`), not dynamically-loaded native code. Plugins built
  against a 1.x WIT keep working across 1.x core releases. The WIT file is a
  public API surface and follows §8.
- **Transports are traits.** stdio, Streamable HTTP, and WebSocket exist today;
  adding one must not touch routing, policy, or audit code.
- **Assume the identity layer changes.** Principals are opaque; OIDC, SPIFFE,
  mTLS, and PAT are all adapters onto the same `Principal`.
- **Assume agents will talk to each other.** Nothing in the design may assume a
  single human at the top of the call chain. Every invocation carries a delegation
  chain, and policy can reason over chain depth and origin.
- **Store nothing you cannot migrate.** Every persisted structure is versioned
  and has a forward migration with a test. No serde defaults doing silent
  reinterpretation of old data.
- **Deprecate loudly, remove slowly.** Deprecated surfaces log once per process
  with the removal version.

---

## 8. Versioning and compatibility contract

- Semver, strictly. The public surfaces are: the CLI, the config schema, the WIT
  plugin interface, the audit log format, the HTTP admin API, and the on-disk
  state format.
- Config files never break on minor upgrades. Unknown keys warn, they do not
  error — except in `--strict-config` mode.
- `xtask api-diff` compares the public API against the last release and fails the
  build on an unannotated breaking change.
- Every release ships a conformance report and the token/latency benchmark
  numbers. No release notes without numbers.

---

## 9. Configuration

One file, TOML, with environment overrides for secrets only. Example lives at
`examples/portcullis.toml` and is validated in CI so it never rots.

Rules:
- Config is declarative and diffable. Anything that changes behaviour is in it.
- Defaults must be the safe choice: auth on, egress closed, sandbox on, audit on,
  telemetry local-only, capabilities unapproved until pinned.
- `portcullis config explain` prints the effective config with the provenance of
  every value (default / file / env / flag).

---

## 10. Commands

Use `just` (see `justfile`); it wraps `cargo xtask`. Agents: run `just check`
before declaring any task complete.

```
just check            # fmt + clippy -D warnings + deny + test + api-diff
just test             # unit + integration
just test-e2e         # spins real sandboxes; requires Linux with user namespaces
just bench            # latency + token benchmarks against budgets in §6
just fuzz <target>    # cargo-fuzz targets in fuzz/
just conformance      # MCP spec conformance across supported revisions
just audit            # cargo-audit + cargo-deny + SBOM generation
just doctor           # build then run `portcullis doctor` against examples/
```

CI runs exactly these. If it passes locally and fails in CI, that is a bug in the
justfile, not a reason to add a CI-only step.

---

## 11. Coding conventions

- `clippy::pedantic` on, with a short curated allow-list at workspace root. Do
  not add per-file `#[allow]` without a comment explaining why.
- Errors: `thiserror` in libraries, `anyhow` only in `pc-cli` and tests. Every
  error type carries enough context to identify tenant, capability, and request
  id — without leaking secrets or user data into the message.
- No `unwrap`/`expect` outside tests and `main` startup. Enforced by clippy.
- No blocking I/O in async contexts. No `tokio::spawn` without a supervising
  task that observes the join handle.
- Logging: `tracing` only. Structured fields, never string interpolation of user
  data. Redaction happens in `pc-audit`, at the boundary, not at call sites.
- Public items get doc comments explaining *why*, not restating the signature.
- Tests: name them `does_x_when_y`. Table-driven where it helps. Property tests
  (`proptest`) for anything parsing untrusted input.
- No new dependency without: a line in `docs/adr/` if it is load-bearing, a
  `cargo-deny` pass, and a look at its transitive tree. Prefer the standard
  library. Prefer no dependency.

---

## 12. Security requirements for every change

Before you finish any task touching a trust boundary, answer these in the PR body:

1. What new data crosses a boundary, and who can influence it?
2. If this input were fully attacker-controlled, what is the worst outcome?
3. Does this add any path from tool output back into a policy decision, a
   privileged operation, or a shell? (If yes, it is almost certainly rejected.)
4. Does this add a way to read a secret from a process that could not read it
   before?
5. What is logged, and could the log now contain credentials or user content?
6. Which row in §5 does this touch, and is that row's test still meaningful?

Threat model lives in `docs/threat-model.md` and is updated in the same PR as any
architectural change, not afterwards.

---

## 13. Definition of Done

A change is done when all of these are true:

- [ ] `just check` passes.
- [ ] Tests cover the failure case, not only the happy path.
- [ ] Benchmarks run if the hot path changed; numbers in the PR body.
- [ ] §5 table updated if a mitigation changed.
- [ ] Docs updated in the same commit — `docs/` and doc comments both.
- [ ] `CHANGELOG.md` entry with the user-visible effect, written for an operator.
- [ ] No new default that is less safe than the previous default.
- [ ] No TODO left without a linked issue number.

---

## 14. Governance and community

- Apache-2.0. DCO sign-off, no CLA.
- Maintainer decisions are recorded as ADRs in `docs/adr/`, numbered, immutable
  once merged (superseded rather than edited).
- Security reports via `SECURITY.md`, 90-day coordinated disclosure, CVEs
  requested for anything reachable by an unauthenticated party.
- Public roadmap in `ROADMAP.md`. Anything a company needs is built in the open
  or not at all (directive #3).

---

## 15. Milestones

| Milestone | Content | Exit criterion |
|---|---|---|
| M0 Skeleton | `pc-core`, `pc-proto-mcp`, stdio + HTTP transports, passthrough only | Proxies a real MCP server with p99 ≤ 2 ms added |
| M1 Contain | `pc-runner` sandbox, broker, egress control, IMDS blackhole | Red-team script in `tests/redteam/` fails to escape |
| M2 Decide | Policy engine, RBAC/ABAC, rate limits, circuit breakers, audit chain | Budget in §6 met with policy on |
| M3 Trust | Manifest pinning, rug-pull detection, poisoning scanner, provenance | Rug-pull and poisoning corpora fully caught |
| M4 Translate | OpenAPI + gRPC adapters, capability facade, token accounting | Token report shows net reduction on 3 real workloads |
| M5 Operate | `doctor`, OTel, cost accounting, migrations, HA without affinity | Kill any node mid-session, zero client-visible error |
| M6 Endure | WIT plugin ABI frozen, conformance suite published, 1.0 | Third party ships a plugin against a published ABI |

---

## 16. Notes for AI agents working in this repo

- Read `docs/adr/` before proposing architecture. Most "obvious" ideas were
  already decided one way or the other, with reasons.
- Prefer deleting code to adding a flag. Prefer a flag to a plugin. Prefer a
  plugin to a fork.
- If a task seems to require violating a Prime Directive, stop and surface the
  conflict. Do not find a clever way around it — the clever way around directive
  #1 is exactly how the CVEs in §5 happened.
- When you are uncertain about the MCP spec's current wording, check the spec
  rather than recalling it; the revision we target is pinned in
  `crates/pc-proto-mcp/SPEC_REVISIONS.md`.
- Small, reviewable commits. One concern each. The commit message explains why.
