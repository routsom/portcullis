# Roadmap

Public roadmap (CLAUDE.md §14, §15). Anything a company needs is built in the
open or not at all (Directive #3).

| Milestone | Content | Status |
|---|---|---|
| **M0 Skeleton** | `pc-core`, `pc-proto-mcp`, stdio + HTTP transports, mandatory auth, passthrough | **done** — p99 well under budget |
| **M1 Contain** | `pc-runner` sandbox, broker, egress control, IMDS blackhole | **done** — broker/egress/IMDS verified here; **Linux sandbox CI-gated** (red-team suite + `clone`-PID-ns are the certification gate) |
| **M2 Decide** | Policy engine, RBAC/ABAC, rate limits, circuit breakers, audit chain | **done** — enforced in the live request path; budget held |
| **M3 Trust** | Manifest pinning, rug-pull detection, poisoning scanner, provenance | **done** — engine + corpus + `catalog scan`; sigstore provenance and live edge ingest deferred |
| **M4 Translate** | OpenAPI + gRPC adapters, capability facade, token accounting | **done** for OpenAPI + facade + token report; **gRPC adapter deferred** |
| **M5 Operate** | metrics, cost accounting, migrations, HA without affinity | **done** — `/metrics`, `pc-state` migrations, active-active failover; **OTLP exporter deferred** |
| **M6 Endure** | WIT plugin ABI frozen, conformance suite published, 1.0 | **ABI + conformance done**; **WASM component host + api-diff baseline deferred** |

### Honest status

Everything platform-agnostic is implemented, tested, and passes `just check`.
Two things stand between this and "trust it in production fronting untrusted
tools": the **Linux sandbox must go green in CI and pass the red-team suite**,
and the system should get an **independent security review**. Deferred items
above are tracked, not forgotten.

## What M0 delivers today

- A single binary (`portcullis`) with `serve`, `doctor`, and `config explain`.
- Domain core (`pc-core`) with no protocol or I/O coupling.
- MCP codec and version negotiation (`2026-07-28` + previous two) in
  `pc-proto-mcp`, with graceful downgrade.
- Streamable HTTP and stdio client transports; HTTP upstream passthrough with
  streaming relay and connection pooling.
- Mandatory bearer auth on every transport (no `--no-auth`), DNS-rebinding
  hardening, stateless signed session tokens.
- Directive-enforcing CI checks (`deny-imports`, `check-licensing`, `dep-graph`)
  and a latency benchmark gating the p99 budget.

## What M0 deliberately does not do yet

Sandboxed execution, secret brokering, egress control, IMDS blackhole (M1);
policy evaluation, rate/size limits, circuit breakers, hash-chained audit (M2).
The decision *path* and content-addressing *types* exist so these slot in
without reshaping the core. See `docs/threat-model.md` for the current posture.
