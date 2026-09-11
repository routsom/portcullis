# Capabilities, principals & decisions

`pc-core` is the protocol-neutral hub every crate reasons about:

- **Tenant** — the top-level isolation boundary; a required parameter everywhere.
- **Principal** — an opaque identity. OIDC, mTLS, PAT, and SPIFFE are adapters
  onto the same type. Principals compose into a **delegation chain** (origin
  first, current delegate last), so policy can reason over chain depth and origin
  — nothing assumes a single human at the top.
- **Capability** — a protocol-neutral "thing that can be invoked", pinned by the
  **content hash** of its full definition. Drift from the pinned hash quarantines
  it (rug-pull defence).
- **Invocation** — who is calling what, in which tenant, with what argument
  *shape* (a hash of keys/types, never values).
- **Decision** — the fail-closed outcome: anything not explicitly allowed is
  denied.

None of these name a wire protocol. A new protocol is a new `pc-proto-*` crate,
not a change to the core.
