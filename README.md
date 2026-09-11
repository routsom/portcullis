<div align="center">

<img src="docs/assets/banner.svg" alt="portcullis — lower the gate on untrusted tools" width="760">

<h3>Lower the gate on untrusted tools.</h3>

The open-source MCP gateway you can put in front of untrusted tools — and still
sleep at night. One statically-linked binary. No Kubernetes, no Redis, no sales
call.

[![CI](https://github.com/routsom/portcullis/actions/workflows/ci.yml/badge.svg)](https://github.com/routsom/portcullis/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust edition 2024](https://img.shields.io/badge/rust-edition%202024-orange.svg)](rust-toolchain.toml)
[![Added latency p99 ≤ 5ms](https://img.shields.io/badge/added%20latency-p99%20%E2%89%A4%205ms-brightgreen.svg)](#performance)
[![Prime Directives: 10](https://img.shields.io/badge/prime%20directives-10-8A2BE2.svg)](CLAUDE.md#2-prime-directives-non-negotiable)

</div>

---

portcullis sits between agent clients and tool servers and provides **identity,
authorization, sandboxed execution, auditing, and protocol translation** —
without adding meaningful latency, without an enterprise paywall, and **without
ever executing tool logic in its own process**.

Every existing gateway fails at least one of those, gates them behind a licence,
or adds latency that compounds across multi-turn agent workflows. portcullis
answers each failure with a mechanism backed by a test (see the
[traceability table](CLAUDE.md#5-traceability-problem--mechanism)).

## Why portcullis

- 🛡️ **Nothing executes in the gateway.** The edge parses, decides, routes, and
  logs. Tools run in a separate sandboxed process (uid, seccomp, landlock, no
  network, no ambient credentials). A prompt injection can't turn the gateway
  into a shell — there is none.
- 🆓 **All Apache-2.0, no enterprise tier.** SSO, RBAC, DLP, audit, rate limiting,
  and multi-tenancy are core features. A build-time check *enforces* no licence
  gating.
- ⚡ **Latency is a hard budget.** p99 ≤ 5 ms of gateway overhead, gated in CI.
  The passthrough path never fully deserializes payloads.
- 🧩 **Zero required infra.** `portcullis serve --config portcullis.toml` runs on
  a laptop and in production. Postgres, Redis, Vault, OIDC are optional.

## Feature matrix

| | Capability |
|---|---|
| **Transport** | stdio + Streamable HTTP; mandatory auth (no `--no-auth`); DNS-rebinding hardening; HTTP-upstream passthrough with streaming relay |
| **Contain** | encrypted secret broker (Argon2id + XChaCha20-Poly1305); short-lived scoped credential tokens; fail-closed egress allowlist; **IMDS blackhole**; Linux sandbox (namespaces/seccomp/landlock, CI-verified) |
| **Decide** | ordered RBAC/ABAC policy engine + decision cache; token-bucket rate limits; per-upstream circuit breakers; **hash-chained signed audit log** |
| **Trust** | content-addressed manifests; rug-pull quarantine; tool-poisoning scanner with corpus |
| **Translate** | OpenAPI → capability table (load-time); capability facade with honest token accounting |
| **Operate** | per-tenant metrics (`/metrics`); versioned state + forward migrations; active-active HA (no session affinity) |
| **Endure** | frozen [WIT plugin ABI](wit/portcullis.wit); MCP conformance suite across supported revisions |

## Quick start

```sh
# 1. Build
cargo build --release

# 2. Provide secrets (config stores env var *names*, never values)
export PORTCULLIS_TOKEN_AGENT="$(openssl rand -hex 32)"
export PORTCULLIS_SESSION_SECRET="$(openssl rand -hex 32)"

# 3. Diagnose config, connectivity, sandbox, clock skew
./target/release/portcullis doctor --config examples/portcullis.toml

# 4. Run (expects an MCP server on http://127.0.0.1:9090/mcp)
./target/release/portcullis serve --config examples/portcullis.toml
```

Call it like any Streamable HTTP MCP endpoint:

```sh
curl -s http://127.0.0.1:8080/mcp \
  -H "authorization: Bearer $PORTCULLIS_TOKEN_AGENT" \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{}}}'
```

## The CLI

```sh
portcullis serve      --config portcullis.toml   # run the gateway
portcullis doctor     --config portcullis.toml   # health checks
portcullis config explain --config portcullis.toml   # effective config + provenance
portcullis catalog scan   --file tools.json      # scan an MCP tool list for poisoning
portcullis translate openapi --file api.json --find "get a pet"   # OpenAPI → tools + token report
```

## Architecture

```text
 agent client ──(MCP: stdio | HTTP)──▶ portcullis-edge ──(HTTP)──▶ upstream MCP server
                                        auth · origin checks · policy · limits ·
                                        breakers · audit · metrics · relay
                                          │ loopback mTLS        │ one process/call
                                          ▼                       ▼
                                     portcullis-broker      portcullis-runner (Linux)
                                     secrets · tokens ·     userns/seccomp/landlock ·
                                     egress                 no net · no host creds
```

The edge holds no upstream credentials and cannot spawn a process (enforced by a
build check). The runner cannot read the secret store. Compromise of either
alone is contained. Full design in [`docs/book`](docs/book) and
[`CLAUDE.md`](CLAUDE.md).

## Performance

Reference benchmark (echo upstream, isolates gateway cost), on a laptop:

| Metric | Budget | Measured |
|---|---|---|
| Added latency, simple call, p99 | ≤ 5 ms | **~0.4–0.9 ms** |

`just bench` gates this in CI.

## Security

portcullis is security-critical infrastructure. The Linux sandbox is verified on
a real kernel in CI (not on a developer's macOS laptop), and — like any gateway
fronting untrusted tools — should pass an independent security review before
production use. The [security model](docs/book/src/security/model.md) states
plainly what is enforced and what is not yet. Report vulnerabilities privately
per [`SECURITY.md`](SECURITY.md).

## Development

```sh
just check        # fmt + clippy -D warnings + cargo-deny + tests + directive checks
just test         # tests only
just bench        # latency benchmark against the budget
just conformance  # MCP spec conformance suite
just docs         # build the mdBook documentation site
just doctor       # build + run doctor against the example config
```

## Documentation

- 📖 [Documentation site](docs/book) (mdBook) — getting started, architecture,
  security, operations, extending
- 🗺️ [Roadmap & milestones](ROADMAP.md)
- 🔒 [Threat model](docs/threat-model.md) · [Prior art](docs/prior-art.md)
- 🧾 [Architecture Decision Records](docs/adr)
- 🧮 [Token report](docs/token-report.md)

## Contributing

Apache-2.0 with DCO sign-off, no CLA. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
Anything a company needs is built in the open or not at all.

## License

[Apache-2.0](LICENSE).
