//! Short-lived, scoped credential tokens.
//!
//! Credential exchange (CLAUDE.md §5 row #12): rather than handing a long-lived
//! upstream secret to anything downstream, the broker mints a **short-lived,
//! scoped, signed** token bound to a (tenant, principal, capability, upstream)
//! and an expiry. The token carries no secret, so HMAC signing is sufficient;
//! verification is constant-time and checks the expiry against a caller-supplied
//! clock (so it is deterministically testable).

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// What a minted token is allowed to do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenScope {
    pub tenant: String,
    pub principal: String,
    pub capability: String,
    pub upstream: String,
}

/// The signed claims: scope plus validity window (Unix seconds).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenClaims {
    pub scope: TokenScope,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Why a token was rejected. Opaque to callers/attackers.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("invalid credential token")]
    Invalid,
    #[error("credential token expired")]
    Expired,
}

/// Mints and verifies scoped credential tokens with a shared HMAC key.
#[derive(Clone)]
pub struct TokenMinter {
    key: Vec<u8>,
}

impl std::fmt::Debug for TokenMinter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenMinter").finish_non_exhaustive()
    }
}

impl TokenMinter {
    /// Create a minter from raw key bytes.
    #[must_use]
    pub fn from_key(key: impl Into<Vec<u8>>) -> Self {
        Self { key: key.into() }
    }

    /// Mint a token valid for `ttl_secs` from `now_unix`.
    #[must_use]
    pub fn mint(&self, scope: TokenScope, now_unix: u64, ttl_secs: u64) -> String {
        let claims = TokenClaims {
            scope,
            issued_at: now_unix,
            expires_at: now_unix.saturating_add(ttl_secs),
        };
        let payload = serde_json::to_vec(&claims).expect("claims serialize");
        let tag = self.tag(&payload);
        format!("{}.{}", hex::encode(&payload), hex::encode(tag))
    }

    /// Verify signature and expiry against `now_unix`, returning the claims.
    pub fn verify(&self, token: &str, now_unix: u64) -> Result<TokenClaims, TokenError> {
        let (payload_hex, tag_hex) = token.split_once('.').ok_or(TokenError::Invalid)?;
        let payload = hex::decode(payload_hex).map_err(|_| TokenError::Invalid)?;
        let presented = hex::decode(tag_hex).map_err(|_| TokenError::Invalid)?;
        let expected = self.tag(&payload);
        if expected.len() != presented.len() || !bool::from(expected.ct_eq(&presented)) {
            return Err(TokenError::Invalid);
        }
        let claims: TokenClaims =
            serde_json::from_slice(&payload).map_err(|_| TokenError::Invalid)?;
        if now_unix >= claims.expires_at {
            return Err(TokenError::Expired);
        }
        Ok(claims)
    }

    fn tag(&self, payload: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac accepts any key length");
        mac.update(payload);
        mac.finalize().into_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> TokenScope {
        TokenScope {
            tenant: "acme".into(),
            principal: "agent-1".into(),
            capability: "github.create_issue".into(),
            upstream: "github".into(),
        }
    }

    fn minter() -> TokenMinter {
        TokenMinter::from_key(*b"0123456789abcdef0123456789abcdef")
    }

    #[test]
    fn mint_then_verify_returns_scope() {
        let m = minter();
        let token = m.mint(scope(), 1000, 60);
        let claims = m.verify(&token, 1030).unwrap();
        assert_eq!(claims.scope, scope());
    }

    #[test]
    fn expired_token_is_rejected() {
        let m = minter();
        let token = m.mint(scope(), 1000, 60);
        assert_eq!(m.verify(&token, 1060), Err(TokenError::Expired));
        assert_eq!(m.verify(&token, 5000), Err(TokenError::Expired));
    }

    #[test]
    fn tampered_or_foreign_token_is_rejected() {
        let m = minter();
        let token = m.mint(scope(), 1000, 60);
        let mut bytes = token.into_bytes();
        bytes[0] ^= 0x01;
        assert_eq!(
            m.verify(&String::from_utf8(bytes).unwrap(), 1010),
            Err(TokenError::Invalid)
        );

        let other = TokenMinter::from_key(*b"ffffffffffffffffffffffffffffffff");
        let token = m.mint(scope(), 1000, 60);
        assert_eq!(other.verify(&token, 1010), Err(TokenError::Invalid));
    }
}
