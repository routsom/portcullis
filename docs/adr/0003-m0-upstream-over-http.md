# ADR-0003: M0 connects to upstreams over HTTP only

- Status: accepted
- Date: 2026-09-11

## Context

Directive #1 forbids the gateway from executing tool logic in its own process,
and §5 row #5 makes that mechanical: `pc-edge` must contain **no process-spawning
import** (`std::process`, `tokio::process`, …), enforced by `xtask deny-imports`.

Many MCP servers today are launched as stdio child processes. Spawning such a
child is precisely a `std::process` call, which the edge is not allowed to make.
The component that legitimately spawns and isolates child processes is the
`pc-runner` sandbox supervisor - which is M1, not M0.

## Decision

In **M0**, the edge connects to upstream MCP servers over **Streamable HTTP
only**. Client-facing transports remain both **stdio and HTTP**; only the
*upstream* side is HTTP-restricted.

Spawning and supervising stdio upstreams becomes `pc-runner`'s responsibility in
M1; the edge will then reach the runner over a socket, still without a
process-spawning import of its own.

The reference benchmark already uses an HTTP "echo upstream" (§6), so this
decision also keeps M0 measurable against the latency budget.

## Consequences

- M0 can proxy any HTTP-reachable MCP server today, with connection pooling and
  streaming relay, inside the latency budget.
- stdio-only upstreams are not supported until M1. This is a capability gap, not
  a safety gap: it exists specifically to preserve Directive #1.
- `pc-edge` stays provably free of an execution surface, which `xtask
  deny-imports` verifies on every build.
