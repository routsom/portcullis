# Prior art and the failure inventory

portcullis exists because every MCP gateway we surveyed fails at least one of
four things: identity/authorization, sandboxed execution, auditing, or protocol
translation - or it gates those behind a paywall, or it adds latency that
compounds across multi-turn agent workflows.

This document is the failure inventory that the traceability table in
`CLAUDE.md` §5 answers row-by-row. Each failure mode below maps to a mechanism
and a test in that table.

## Latency

- **80-300 ms added latency per call**, typically from a network hop to an
  external policy service and from fully deserializing every frame. Over a
  multi-turn workflow this compounds into seconds.
  → single-process decision path, decision cache, frame passthrough without full
  deserialization, streaming relay (never buffer). §5 row #1.

## Commercial model

- **Open-core feature gapping.** SSO, RBAC, DLP, audit export, and risk scoring
  are routinely behind an enterprise tier or a "contact us" deployment.
  → single Apache-2.0 binary, no capability gated on payment. §5 rows #2, #16.

## Injection and untrusted metadata

- **Argument/command injection via OCI labels or YAML manifest parsing**
  (CVE-2026-55887 class): unsafe YAML features (anchors, merge keys, custom
  tags) and metadata flowing into a shell.
  → safe-subset parsing, `argv[]`-only exec, digest-pinned images. §5 row #3.
- **Tool poisoning / prompt injection in tool descriptions**: descriptions that
  instruct the model, hide payloads in invisible characters, or carry encoded
  instructions.
  → ingest-time scanning and scoring, untrusted-content delimiters, provenance.
  §5 row #7.
- **Rug-pulls**: a tool's definition changes after approval.
  → content-addressed manifests; drift quarantines the capability. §5 row #6.

## Network exposure

- **Unauthenticated localhost endpoints and DNS rebinding** (CVE-2025-49596 /
  CVE-2025-64443 class): a gateway listening on loopback with no auth, reachable
  from a victim's browser via rebinding.
  → mandatory auth on every transport (no `--no-auth`), strict Origin/Host
  allowlist, `Sec-Fetch-Site` enforcement, no dev endpoints in release. §5 row
  #4.
- **In-process shell/file builtins**: a gateway that can itself execute tools is
  one prompt injection away from host takeover.
  → the gateway never executes tool logic; no `std::process` in the edge.
  Directive #1, §5 row #5.
- **Cloud metadata (IMDS) reachable from a compromised tool**.
  → runner network namespace blackholes 169.254.169.254 unconditionally. §5 row
  #14.

## Scaling and operations

- **`Mcp-Session-Id` binding that prevents active-active scaling.**
  → stateless signed session tokens; any node serves any request. §5 row #9.
- **High operational burden**: connector runtimes, external vaults, HA stores,
  and manual schema updates as prerequisites.
  → embedded state and secret store by default; `portcullis doctor`. §5 row #8.
- **Manual secret export/sync** between local and remote runtimes.
  → one broker reachable from both over mTLS; no export command. §5 row #12.
- **Egress firewalls that demand manual manifest edits** on every SaaS subdomain
  change.
  → wildcard-with-pinned-CA and CIDR/ASN rules, `--observe` mode. §5 row #13.

## Protocol and portability

- **Missing REST/gRPC → MCP translation**, or translation interpreted per
  request at 100-300 ms cost.
  → OpenAPI/gRPC adapters codegen a capability table at load time. §5 rows #10,
  #15.
- **Vendor lock-in / MCP treated as an add-on module**, and **interpreted-runtime
  overhead** (Python).
  → this project does one thing, in Rust. §5 rows #19, #20.

## Governance

- **Restrictive licensing on the runnable artifact** (PolyForm and similar).
  → Apache-2.0 for the entire runnable system, DCO, no relicensing CLA. §5 row
  #16.
- **Breaking schema/API changes on minor releases.**
  → strict semver, machine-checked API diff, two-release deprecation window. §5
  row #17.
- **No OTel tracing, cost accounting, or group RBAC.**
  → on by default (local export), per-tenant accounting, ABAC. §5 row #18.
