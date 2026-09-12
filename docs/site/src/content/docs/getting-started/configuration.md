---
title: "Configuration reference"
---

Config is one TOML file, declarative and diffable. Unknown keys warn and are
ignored (they error under `--strict-config`). Print the effective config with the
provenance of every value:

```sh
portcullis config explain --config portcullis.toml
```

```text
# provenance
config file       = portcullis.toml (flag)
telemetry.log_level = "info" (file)
server.http.bind  = "127.0.0.1:8080" (file)
server.http.path  = "/mcp" (file)
server.http.allowed_origins = ["http://127.0.0.1:8080"] (file)
upstream[echo]       = "http://127.0.0.1:9090/mcp" (file)
auth principal "agent-1" <- env PORTCULLIS_TOKEN_AGENT (set (redacted))
session secret    <- env PORTCULLIS_SESSION_SECRET (MISSING)
```

Every value shows its provenance (`default` / `file` / `env` / `flag`), and
secret *values* are never printed - only whether the named env var is set.

The annotated, CI-validated example lives at
[`examples/portcullis.toml`](https://github.com/routsom/portcullis/blob/main/examples/portcullis.toml).
Key sections:

| Section | Purpose |
|---------|---------|
| `[server.http]` / `[server.stdio]` | client-facing listeners; at least one required |
| `[[auth.tokens]]` | PAT principals (token value from `token_env`), plus `roles` and `attributes` for policy |
| `[session]` | shared HMAC key (`secret_env`) for active-active; ephemeral if unset |
| `[[upstream]]` | named HTTP MCP upstreams |
| `[policy]` | ordered RBAC/ABAC rules + decision-cache size |
| `[rate_limit]` | per-(tenant, principal, capability) token bucket |
| `[circuit_breaker]` | per-upstream failure threshold + cooldown |
| `[audit]` | hash-chained JSONL path, optional signing key |
| `[telemetry]` | log level (local export only) |

Defaults are the safe choice: auth on, origins closed, telemetry local, sandbox
on, capabilities unapproved until pinned.

## Worked example: policy in action

The shipped example gives the `agent-1` principal the `reader` role and these
rules (first match wins; no match denies):

```toml
[[policy.rules]]
id = "deny-destructive"
effect = "deny"
reason = "destructive tools require an approved change ticket"
matcher = { capabilities = ["*.delete", "*.destroy"] }

[[policy.rules]]
id = "readers-read-only"
effect = "allow"
matcher = { roles_any = ["reader", "writer"], capabilities = ["*.read", "*.list", "tools/list", "initialize"] }

[[policy.rules]]
id = "writers-write"
effect = "allow"
matcher = { roles_any = ["writer"] }
```

Running the [first-server walkthrough](./first-server.md) against this config,
as `agent-1`:

```text
tools/list                  -> HTTP 200   (readers-read-only allows it)
tools/call { name: echo }   -> HTTP 403   (no rule allows it -> default deny)
tools/call { name: files.delete } -> HTTP 403   (deny-destructive)
```

A denied call never reaches the upstream; the client gets:

```json
{ "error": "denied by policy" }
```

## Worked example: the audit trail

With `[audit]` configured, every decision is appended to a **hash-chained** log -
each entry commits to the previous entry's hash, so tampering is detectable
(add `secret_env` to also HMAC-sign it). The three calls above produce:

```json
{"seq":0,"ts":1789219569,"event":{"request_id":"id-1","tenant":"default","principal":"agent-1","capability":"tools/list","method":"tools/list","decision":"allow"},"prev":"0000…0000","hash":"fe52dd5c…","sig":""}
{"seq":1,"ts":1789219569,"event":{"request_id":"id-2","tenant":"default","principal":"agent-1","capability":"echo","method":"tools/call","decision":"deny:no matching rule (default deny)"},"prev":"fe52dd5c…","hash":"05db43e8…","sig":""}
{"seq":2,"ts":1789219569,"event":{"request_id":"id-3","tenant":"default","principal":"agent-1","capability":"files.delete","method":"tools/call","decision":"deny:destructive tools require an approved change ticket"},"prev":"05db43e8…","hash":"c1aa1b35…","sig":""}
```

Note each `prev` equals the previous entry's `hash`: reorder, edit, or delete any
line and the chain no longer verifies. See [Auditing](../operations/audit.md).
