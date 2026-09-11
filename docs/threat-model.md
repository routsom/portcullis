# Threat model

This document is updated in the same PR as any architectural change (CLAUDE.md
§12), not afterwards. It reflects the **M0 "Skeleton"** surface: transports,
authentication, origin hardening, stateless sessions, and HTTP passthrough. The
runner, broker, policy engine, and audit chain (M1-M2) extend - and will extend
this model.

## Assets

- Upstream credentials (not present in M0: the edge brokers none yet - Directive
  #2; the broker arrives in M1).
- The session signing key.
- The authorization decision path and its integrity.
- The audit trail (plain structured tracing in M0; hash-chained in M2).

## Trust boundaries

```
 client ── (untrusted) ──> edge ── (trusted intra-process) ──> upstream (HTTP)
```

- **Client → edge**: fully untrusted. Every byte is attacker-influenceable: the
  JSON-RPC frame, all headers, the bearer token.
- **Edge → upstream**: the edge initiates an outbound HTTP call to a configured
  URL. Upstream *responses* are untrusted data and are relayed, never
  interpreted as instructions (Directive #6).

## Principals and entry points (M0)

| Entry point            | Auth                         | Notes |
|------------------------|------------------------------|-------|
| HTTP `POST {path}`     | mandatory bearer (PAT)       | Origin/Host/Sec-Fetch-Site checked first. |
| stdio                  | configured principal binding | Local pipe; bound to an explicit principal, not anonymous. |

There is no unauthenticated path and no `--no-auth` (§5 row #4).

## Threats and mitigations (M0)

1. **DNS rebinding / drive-by** (CVE-2025-49596 / -64443 class). A victim
   browser is pointed at the loopback listener.
   - *Mitigation*: `Host` must be allow-listed (defaults to the bind address); a
     present `Origin` must be allow-listed (empty allowlist rejects all
     cross-origin); `Sec-Fetch-Site: cross-site` is rejected. The check runs
     before auth and before the body is parsed. Verified by
     `crates/pc-edge/tests/rebinding.rs`.

2. **Host takeover via prompt injection → in-process execution.**
   - *Mitigation*: the edge cannot execute anything. No `std::process` import,
     enforced by `xtask deny-imports`. Directive #1, §5 row #5.

3. **Credential theft from the gateway process.**
   - *M0 posture*: the edge holds no upstream credentials. It forwards the
     client's frame to a configured URL. The broker (M1) will inject credentials
     at the transport boundary, unreadable from tool-output paths.

4. **Token leakage via timing or logs.**
   - *Mitigation*: bearer tokens are compared in constant time
     (`subtle::ConstantTimeEq`); error messages never include token values;
     logging uses structured fields, never interpolated user data.

5. **Session pinning / forged session tokens.**
   - *Mitigation*: session tokens are HMAC-signed and verified in constant time;
     tampering or a wrong key is rejected. Tokens carry no secret, so signing
     (integrity) suffices in M0; an AEAD is the upgrade path if sensitive data is
     ever added. Verified by `crates/pc-edge/src/session.rs` tests.

6. **Malformed/oversized frames.**
   - *Mitigation*: parsing never panics on arbitrary input (property-tested in
     `crates/pc-proto-mcp/tests/parse_fuzz.rs`); a bad frame yields a typed 400.
   - *Gap (tracked for M2)*: request/response **size caps** and rate limiting are
     not yet enforced (§5 row #11). Until then, deploy behind a reverse proxy
     that bounds body size if exposed beyond localhost.

7. **Information disclosure via debug endpoints.**
   - *Mitigation*: dev/introspection endpoints compile only under the
     `dev-endpoints` feature and are excluded from release builds. §5 row #4.

## Residual risks / explicitly out of scope for M0

- No sandboxed execution (M1): do not point M0 at untrusted upstreams you would
  not already trust over plain HTTP.
- No policy engine (M2): the decision is allow-all once authenticated. The
  decision *path* exists and is fail-closed-shaped, but authorization rules are
  not yet evaluated.
- No hash-chained audit (M2), no egress control (M1), no IMDS blackhole (M1).

## Security questions to answer for every change (CLAUDE.md §12)

1. What new data crosses a boundary, and who can influence it?
2. If this input were fully attacker-controlled, what is the worst outcome?
3. Does this add a path from tool output into a decision, a privileged
   operation, or a shell?
4. Does this let a process read a secret it could not read before?
5. What is logged, and could it now contain credentials or user content?
6. Which §5 row does this touch, and is that row's test still meaningful?
