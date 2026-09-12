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

## Beyond 1.0 — the open platform

All Apache-2.0 (Directive #3): anything a company needs is built in the open, or
not at all. These are capabilities, not a paid tier.

**Observability & response**

- **Web console** — read-only-by-default UI over live traffic, the audit trail,
  metrics, and the capability catalog. Proposes config diffs; never authoritative.
- **Anomaly detection** — behavioural baselines per (tenant, principal,
  capability) that flag volume spikes, new destinations, arg-shape drift,
  off-hours access, and spend anomalies.
- **Alerting** — Slack / PagerDuty / Opsgenie / webhook routes on policy denials,
  circuit trips, rug-pull/poisoning hits, budget breaches, audit-chain
  verification failures, and sandbox escape attempts.
- **Fleet kill switch** — one command (or one tap) pauses tool execution across
  every gateway in the org, instantly.
- **Session forensics & replay** — reconstruct what a principal did and what a
  compromised tool *could* have reached, from the signed audit chain.

**Governance & scale**

- **Policy-as-code / GitOps** — versioned policy bundles with staging, canary,
  diff review, rollback; `policy test` against recorded traffic.
- **Approval workflows** — human-in-the-loop gates for high-risk capabilities and
  rug-pull re-approvals, fully audited.
- **Cost & usage analytics** — per-team accounting, budgets, chargeback.
- **SIEM & OpenTelemetry export** — signed audit chain + metrics to Splunk,
  Datadog, Elastic, S3, and OTel, with tamper-evident chain proofs.
- **Open threat-intel format** — a signature format for poisoned tools and
  known-bad MCP servers, publishable and consumable by anyone.

## portcullis Cloud — the business model

The gateway is, and always will be, Apache-2.0 with **no feature paywall**. We
monetize the way durable open source does — **hosting, operations, curated data,
and people** — never by locking capabilities (Directive #3, §14).

- **Managed gateway** — zero-ops hosted portcullis with SLAs, managed upgrades,
  multi-region, autoscaling; bring-your-own-cloud keeps data in your account.
- **Managed threat feed** — continuously curated, signed signatures for poisoned
  tools and known-bad MCP servers, plus hosted prompt-injection models. Format
  and consumer are open; the curation is the service.
- **Compliance pack** — one-click SOC 2 / ISO 27001 evidence, tamper-proof audit
  archival with legal hold, auditor-ready reports.
- **Red-team-as-a-service** — scheduled real-kernel escape attempts against your
  sandbox, with findings and regression tracking.
- **Fleet control plane** — centralized policy, secret rotation, and capability
  approvals across many gateways/teams, with SSO/SCIM and org RBAC.
- **Support & response** — 24/7 incident response, advisories ahead of public
  disclosure, architecture review.

Security controls are never the upsell: if it keeps you safe, it's in the binary,
for free. The Cloud sells the operational burden you'd rather not carry.
