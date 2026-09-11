# Architecture

```
 agent client
      │  MCP (stdio | Streamable HTTP)
      ▼
┌──────────────────────────────────────────────┐
│ portcullis-edge  (Rust, tokio, forbid unsafe) │
│  auth · origin checks · policy · limits ·     │
│  breakers · audit · routing · relay           │
└──────┬──────────────────────────┬─────────────┘
       │ (loopback, mTLS)          │ HTTP
       ▼                           ▼
┌───────────────┐          upstream MCP server
│ portcullis-   │
│ broker        │   ┌──────────────────────────┐
│ secrets ·     │   │ portcullis-runner (Linux) │
│ tokens ·      │   │ one process per call ·    │
│ egress        │   │ userns/seccomp/landlock · │
└───────────────┘   │ no net, no host creds     │
                    └──────────────────────────┘
```

The edge holds no upstream credentials and cannot spawn a process (enforced by
the `deny-imports` check). The runner cannot read the secret store. Compromise of
either alone is contained.

## Crates

`pc-core` (pure domain types) · `pc-proto-mcp` (codec + version negotiation) ·
`pc-edge` (transports, auth, policy wiring, limits, breakers, metrics) ·
`pc-broker` (secrets, tokens, egress) · `pc-runner` (sandbox) ·
`pc-policy` (RBAC/ABAC + cache) · `pc-audit` (hash-chained log) ·
`pc-catalog` (manifests, rug-pull, poisoning) · `pc-proto-openapi` (translation) ·
`pc-facade` (find/invoke + tokens) · `pc-state` (versioned persistence) ·
`pc-conformance` (spec suite) · `pc-cli` (the binary).

`pc-core` depends on nothing in-repo; the dependency graph is acyclic and checked
in CI. The protocol is a plugin, not the architecture: `pc-core` names no wire
format.
