# Configuration reference

Config is one TOML file, declarative and diffable. Unknown keys warn and are
ignored (they error under `--strict-config`). Print the effective config with the
provenance of every value:

```sh
portcullis config explain --config portcullis.toml
```

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
