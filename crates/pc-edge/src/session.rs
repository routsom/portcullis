//! Stateless session tokens.
//!
//! MCP's `Mcp-Session-Id` traditionally pins a client to one node, which blocks
//! active-active scaling (CLAUDE.md §5 row #9). Instead we mint a signed token
//! that *carries* its own routing hint and resumption cursor, so any node
//! holding the shared signing key can serve any request - no session affinity,
//! no shared session store (Directive #7).
//!
//! The token contains no secret, so HMAC signing (integrity) is sufficient in
//! M0; if sensitive data is ever placed in it, switch to an AEAD. The wire form
//! is `hex(payload).hex(tag)`.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// The claims carried inside a session token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionClaims {
    /// Tenant the session belongs to.
    pub tenant: String,
    /// Principal id the session was established for.
    pub principal: String,
    /// Routing hint: which upstream this session is attached to.
    pub upstream: String,
    /// Negotiated protocol revision.
    pub protocol: String,
    /// Opaque resumption cursor (empty until streaming resumption is used).
    #[serde(default)]
    pub cursor: String,
}

/// Signs and verifies session tokens with a shared HMAC key.
#[derive(Clone)]
pub struct SessionSigner {
    key: Vec<u8>,
}

impl std::fmt::Debug for SessionSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the key.
        f.debug_struct("SessionSigner").finish_non_exhaustive()
    }
}

/// Why a token failed to verify. Deliberately opaque to the caller/attacker.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid session token")]
pub struct InvalidToken;

impl SessionSigner {
    /// Create a signer from raw key bytes (e.g. from a configured env var).
    #[must_use]
    pub fn from_key(key: impl Into<Vec<u8>>) -> Self {
        Self { key: key.into() }
    }

    /// Generate an ephemeral random key. Suitable for a single node only: other
    /// nodes will not be able to verify these tokens, so a cluster must share a
    /// configured key (CLAUDE.md §5 row #9). Callers should log a warning.
    #[must_use]
    pub fn ephemeral() -> Self {
        let mut key = [0u8; 32];
        // getrandom draws from the OS CSPRNG; on failure we cannot safely mint
        // tokens, so panic at startup rather than sign with a weak key.
        getrandom::getrandom(&mut key).expect("OS randomness unavailable at startup");
        Self { key: key.to_vec() }
    }

    /// Mint a signed token for the given claims.
    #[must_use]
    pub fn mint(&self, claims: &SessionClaims) -> String {
        // serde_json on our own struct cannot fail.
        let payload = serde_json::to_vec(claims).expect("claims serialize");
        let tag = self.tag(&payload);
        format!("{}.{}", hex::encode(&payload), hex::encode(tag))
    }

    /// Verify a token and return its claims, or [`InvalidToken`].
    pub fn verify(&self, token: &str) -> Result<SessionClaims, InvalidToken> {
        let (payload_hex, tag_hex) = token.split_once('.').ok_or(InvalidToken)?;
        let payload = hex::decode(payload_hex).map_err(|_| InvalidToken)?;
        let presented_tag = hex::decode(tag_hex).map_err(|_| InvalidToken)?;
        let expected_tag = self.tag(&payload);
        if expected_tag.len() != presented_tag.len()
            || !bool::from(expected_tag.ct_eq(&presented_tag))
        {
            return Err(InvalidToken);
        }
        serde_json::from_slice(&payload).map_err(|_| InvalidToken)
    }

    fn tag(&self, payload: &[u8]) -> Vec<u8> {
        // Hmac accepts keys of any length; construction cannot fail here.
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac accepts any key length");
        mac.update(payload);
        mac.finalize().into_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> SessionClaims {
        SessionClaims {
            tenant: "acme".into(),
            principal: "bot".into(),
            upstream: "default".into(),
            protocol: "2026-07-28".into(),
            cursor: String::new(),
        }
    }

    #[test]
    fn mint_then_verify_roundtrips() {
        let s = SessionSigner::from_key(*b"0123456789abcdef0123456789abcdef");
        let token = s.mint(&claims());
        assert_eq!(s.verify(&token).unwrap(), claims());
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let s = SessionSigner::from_key(*b"0123456789abcdef0123456789abcdef");
        let token = s.mint(&claims());
        let mut bytes = token.into_bytes();
        bytes[0] ^= 0x01; // flip a byte in the payload hex
        let tampered = String::from_utf8(bytes).unwrap();
        assert_eq!(s.verify(&tampered), Err(InvalidToken));
    }

    #[test]
    fn verify_rejects_token_from_other_key() {
        let a = SessionSigner::from_key(*b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let b = SessionSigner::from_key(*b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let token = a.mint(&claims());
        assert_eq!(b.verify(&token), Err(InvalidToken));
    }

    #[test]
    fn verify_rejects_garbage() {
        let s = SessionSigner::ephemeral();
        assert!(s.verify("not-a-token").is_err());
        assert!(s.verify("deadbeef").is_err());
    }
}
