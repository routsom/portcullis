# ADR-0004: Broker default secret store

- Status: accepted
- Date: 2026-09-11

## Context

Directive #5 requires zero required external infrastructure: secrets must work on
a laptop with no Vault/KMS. `CLAUDE.md` §5 row #8 describes the default as an
"age-encrypted local store." We need encryption-at-rest for the broker's secrets
with a small, auditable dependency footprint that `cargo deny` accepts cleanly.

## Decision

The default [`SecretStore`](../../crates/pc-broker/src/secret.rs) is an encrypted
local file using **RustCrypto primitives directly**:

- **Argon2id** derives a 32-byte key from an operator passphrase (OWASP
  interactive parameters, stored in the file header).
- **XChaCha20-Poly1305** seals the secret map, with the file header (magic + KDF
  params + salt) bound as AEAD associated data so parameters cannot be swapped
  undetected.
- Writes are atomic (temp file + rename); keys and plaintext are zeroized on
  drop; wrong passphrase and tampering are indistinguishable failures.

This is functionally equivalent to `age`'s passphrase mode (scrypt/ChaCha) but
with a smaller, single-ecosystem dependency tree.

The `age` file format, Vault, cloud KMS, and OS keychains are **optional
integrations** layered on the `SecretStore` trait later - not defaults.

## Consequences

- No external vault is required for a working deployment.
- We own a small amount of crypto-assembly code; it is covered by roundtrip,
  wrong-passphrase, and tamper-detection tests, and the primitives are
  well-reviewed RustCrypto crates.
- This is a deliberate, documented deviation from the literal "age" wording in
  §5 row #8; the threat model (passphrase → KDF → AEAD) is unchanged.
