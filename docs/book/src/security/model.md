# Security model

portcullis is meant to sit in front of *untrusted* tools. This page states what
is enforced today and what is not yet, so you never mistake "compiles" for
"contained."

## Enforced

- **Mandatory auth on every transport.** There is no `--no-auth`. Tokens are
  compared in constant time; they never appear in logs or errors.
- **DNS-rebinding / drive-by defence.** `Host` must be allow-listed, a present
  `Origin` must be allow-listed, and `Sec-Fetch-Site: cross-site` is rejected —
  before the body is parsed and before auth.
- **No in-process execution.** `pc-edge` contains no process-spawning import,
  enforced by `xtask deny-imports`.
- **Fail-closed authorization.** No matching policy rule ⇒ deny.
- **Secret handling.** Secrets live in the broker (Argon2id + XChaCha20-Poly1305
  at rest), are zeroized in memory, and are injected at the upstream transport
  boundary — never exposed to tool output.
- **Egress allowlist + IMDS blackhole.** Outbound is fail-closed; cloud metadata
  (169.254.169.254 and friends) is blocked unconditionally.
- **Tamper-evident audit.** Hash-chained, optionally HMAC-signed; opening a
  tampered log fails closed.

## Verified in CI, not on macOS

The Linux sandbox (`pc-runner`: user/mount/net namespaces, seccomp, landlock) is
compiled and exercised only in Linux CI plus the red-team suite. Until that CI is
green and reviewed, treat the sandbox as unproven on your host. See
[Sandboxing](./sandbox.md).

## Not yet (roadmap)

Request/response size caps, sigstore provenance, and the WASM plugin *host*
runtime are on the roadmap. Before fronting genuinely untrusted tools in
production, get an independent security review — that is what "production
security gateway" means industry-wide.
