//! Authentication: resolving a presented credential to a principal and tenant.
//!
//! Auth is mandatory on every transport, including loopback; there is no
//! `--no-auth` and no anonymous path (CLAUDE.md §5 row #4). M0 ships pre-shared
//! bearer tokens (PATs); OIDC/mTLS/SPIFFE are future adapters that resolve to
//! the same [`AuthContext`].

use pc_core::{Principal, PrincipalId, PrincipalKind, TenantId};
use subtle::ConstantTimeEq;

use crate::config::AuthConfig;
use crate::error::EdgeError;

/// The identity and routing context established for a request.
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub tenant: TenantId,
    pub principal: Principal,
    /// Name of the upstream this principal's calls route to.
    pub upstream: String,
    /// RBAC roles for policy evaluation.
    pub roles: Vec<String>,
    /// ABAC attributes for policy evaluation.
    pub attributes: std::collections::BTreeMap<String, String>,
}

/// Resolves bearer tokens to contexts. Token values are held only in memory and
/// compared in constant time so a comparison cannot leak them via timing.
#[derive(Debug)]
pub struct Authenticator {
    // Keyed by a hash of the token is unnecessary for M0; we compare in constant
    // time against each configured token. The map is keyed by the principal id
    // only for diagnostics; lookup is a linear constant-time scan.
    tokens: Vec<TokenEntry>,
}

#[derive(Debug)]
struct TokenEntry {
    secret: Vec<u8>,
    context: AuthContext,
}

impl Authenticator {
    /// Build from config, reading each token's value from its named env var.
    ///
    /// Fails if a referenced env var is missing or a tenant id is invalid -
    /// failing closed is preferable to starting with a principal that can never
    /// authenticate.
    pub fn from_config(cfg: &AuthConfig) -> Result<Self, EdgeError> {
        let mut tokens = Vec::with_capacity(cfg.tokens.len());
        for t in &cfg.tokens {
            let secret = std::env::var(&t.token_env).map_err(|_| {
                EdgeError::Config(format!("auth token env var {:?} is not set", t.token_env))
            })?;
            if secret.is_empty() {
                return Err(EdgeError::Config(format!(
                    "auth token env var {:?} is empty",
                    t.token_env
                )));
            }
            let tenant = TenantId::new(t.tenant.clone())
                .map_err(|e| EdgeError::Config(format!("invalid tenant: {e}")))?;
            tokens.push(TokenEntry {
                secret: secret.into_bytes(),
                context: AuthContext {
                    tenant,
                    principal: Principal::new(
                        PrincipalId::new(t.principal.clone()),
                        PrincipalKind::Pat,
                    ),
                    upstream: t.upstream.clone(),
                    roles: t.roles.clone(),
                    attributes: t.attributes.clone(),
                },
            });
        }
        Ok(Self { tokens })
    }

    /// Construct directly (used for stdio's configured principal and in tests).
    #[must_use]
    pub fn with_static_context(token: &str, context: AuthContext) -> Self {
        Self {
            tokens: vec![TokenEntry {
                secret: token.as_bytes().to_vec(),
                context,
            }],
        }
    }

    /// Resolve a presented bearer token. Scans every entry in constant time so
    /// the number of comparisons does not depend on which token matched.
    pub fn authenticate(&self, presented: &str) -> Result<AuthContext, EdgeError> {
        let presented = presented.as_bytes();
        let mut matched: Option<&AuthContext> = None;
        for entry in &self.tokens {
            // ConstantTimeEq over equal-length slices; differing lengths can
            // never match, which is not itself secret.
            let eq =
                entry.secret.len() == presented.len() && bool::from(entry.secret.ct_eq(presented));
            if eq {
                matched = Some(&entry.context);
            }
        }
        matched.cloned().ok_or(EdgeError::Unauthenticated)
    }

    /// Parse a bearer token from an `Authorization: Bearer <token>` header value.
    #[must_use]
    pub fn parse_bearer(header: &str) -> Option<&str> {
        let rest = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))?;
        let token = rest.trim();
        if token.is_empty() { None } else { Some(token) }
    }

    /// Number of registered principals (diagnostics).
    #[must_use]
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> AuthContext {
        AuthContext {
            tenant: TenantId::new("acme").unwrap(),
            principal: Principal::new(PrincipalId::new("bot"), PrincipalKind::Pat),
            upstream: "default".to_string(),
            roles: Vec::new(),
            attributes: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn authenticate_accepts_correct_token() {
        let a = Authenticator::with_static_context("s3cr3t", ctx());
        let resolved = a.authenticate("s3cr3t").unwrap();
        assert_eq!(resolved.tenant.as_str(), "acme");
    }

    #[test]
    fn authenticate_rejects_wrong_token() {
        let a = Authenticator::with_static_context("s3cr3t", ctx());
        assert!(matches!(
            a.authenticate("nope"),
            Err(EdgeError::Unauthenticated)
        ));
    }

    #[test]
    fn authenticate_rejects_empty_token() {
        let a = Authenticator::with_static_context("s3cr3t", ctx());
        assert!(a.authenticate("").is_err());
    }

    #[test]
    fn parse_bearer_extracts_token_when_well_formed() {
        assert_eq!(Authenticator::parse_bearer("Bearer abc"), Some("abc"));
        assert_eq!(Authenticator::parse_bearer("bearer abc"), Some("abc"));
        assert_eq!(Authenticator::parse_bearer("Basic abc"), None);
        assert_eq!(Authenticator::parse_bearer("Bearer   "), None);
    }
}
