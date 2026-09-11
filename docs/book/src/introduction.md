<img class="pc-hero" src="./img/banner.svg" alt="portcullis — lower the gate on untrusted tools">

# Introduction

> The MCP gateway you can put in front of untrusted tools and still sleep at
> night — one statically-linked binary, no Kubernetes, no Redis, no sales call.

**portcullis** sits between agent clients and tool servers and provides identity,
authorization, sandboxed execution, auditing, and protocol translation —
without adding meaningful latency, without an enterprise paywall, and **without
ever executing tool logic in its own process**.

It exists because every existing gateway fails at least one of those four
things, or gates them behind a licence, or adds latency that compounds across a
multi-turn agent workflow. The full failure inventory is in
[prior art](https://github.com/routsom/portcullis/blob/main/docs/prior-art.md);
every mechanism traces back to it.

## Why it's different

- **Nothing executes in the gateway.** The edge parses, decides, routes, and
  logs. Tools run in a separate, sandboxed process with their own uid, seccomp
  profile, landlock ruleset, and no ambient host credentials. A prompt injection
  cannot turn the gateway into a shell — there is no shell to turn it into.
- **Everything is Apache-2.0.** SSO, RBAC, DLP, audit, rate limiting, and
  multi-tenancy are core features, not a paid tier. There are no licence-key
  checks, and a build-time check enforces it.
- **Latency is a hard budget, not a goal.** p99 ≤ 5 ms of gateway-added overhead,
  gated in CI. The passthrough path does not fully deserialize payloads.
- **Zero required infrastructure.** `portcullis serve --config portcullis.toml`
  works on a laptop and in production. Postgres, Redis, Vault, and OIDC providers
  are optional integrations, never prerequisites.

## What's here today

portcullis is built milestone by milestone (see the [roadmap](./project/roadmap.md)).
Implemented and tested:

| Area | What you get |
|------|--------------|
| Transport & routing | stdio + Streamable HTTP, mandatory auth, DNS-rebinding hardening, HTTP-upstream passthrough with streaming relay |
| Contain | encrypted secret broker, short-lived credential tokens, fail-closed egress allowlist with IMDS blackhole, Linux sandbox (CI-verified) |
| Decide | RBAC/ABAC policy engine + decision cache, token-bucket rate limits, per-upstream circuit breakers, hash-chained signed audit log |
| Trust | content-addressed manifests, rug-pull quarantine, tool-poisoning scanner |
| Translate | OpenAPI → capability table, capability facade with token accounting |
| Operate | per-tenant metrics (`/metrics`), versioned state + migrations, active-active HA |
| Endure | frozen WIT plugin ABI, MCP conformance suite |

## A note on trust

portcullis is security-critical infrastructure. The Linux sandbox is verified in
CI on a real kernel, not on a developer's macOS laptop, and — like any gateway
that fronts untrusted tools — it should pass an independent security review
before you rely on it in production. The [security model](./security/model.md)
states plainly what is enforced and what is not yet.

Start with [Install & first run](./getting-started/install.md).
