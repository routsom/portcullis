# MCP spec revisions supported by `pc-proto-mcp`

This file is the authoritative record of which Model Context Protocol revisions
the gateway speaks. It must stay in lock-step with `SUPPORTED_VERSIONS` in
`src/version.rs` (the test `supported_set_is_ordered_newest_first` guards the
ordering).

Policy (CLAUDE.md §7): support the **current** revision plus at least the
**previous two**, and **downgrade gracefully** rather than erroring when a client
requests something outside the set.

## Supported set (newest first)

| Revision     | Status    | Notes |
|--------------|-----------|-------|
| `2026-07-28` | preferred | Current. Introduced a stateless protocol core and header-based routing, which align with Directive #7 (no session affinity) and §5 row #9. |
| `2025-11-25` | supported | Previous stable release. |
| `2025-06-18` | supported | Two revisions back. |

## Negotiation

During `initialize`, the client proposes a `protocolVersion`:

- in the supported set → **agree** (echo it back);
- otherwise → **downgrade**: offer `2026-07-28` (our latest) and let the client
  decide whether to continue. This is never an error.

See `NegotiationOutcome` in `src/version.rs`.

## Revisions known but not supported

`2024-11-05` and `2025-03-26` predate the supported window. Requests naming them
are handled by the downgrade path (we offer our latest).

## Changing this set

Dropping or adding a revision is a change to a public surface (CLAUDE.md §8).
Update the table, `SUPPORTED_VERSIONS`, the conformance matrix, and the
CHANGELOG in the same commit.
