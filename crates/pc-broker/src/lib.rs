//! portcullis broker: the single source of truth for secrets and egress.
//!
//! The broker holds upstream credentials and mints short-lived scoped tokens. It
//! is architecturally unreachable from the runner's network namespace
//! (Directive #2, §5 row #12): the runner never asks the broker for a secret;
//! the broker injects credentials at the transport boundary of the *edge's*
//! upstream request, where tool output cannot read them.
//!
//! Responsibilities:
//! - [`secret`] - encrypted-at-rest secret storage ([`SecretStore`]).
//! - [`token`] - short-lived scoped credential tokens ([`TokenMinter`]).
//! - [`egress`] - fail-closed outbound allowlisting with IMDS blackhole.

pub mod egress;
pub mod error;
pub mod secret;
pub mod token;

pub use egress::{Destination, EgressDecision, EgressPolicy, EgressRule};
pub use error::{BrokerError, Result};
pub use secret::{EncryptedFileStore, MemoryStore, SecretStore, SecretValue};
pub use token::{TokenClaims, TokenError, TokenMinter, TokenScope};

/// How to inject a stored credential into an upstream request. The secret is
/// resolved at call time and attached at the transport boundary; it is never
/// exposed to the client or to tool output.
#[derive(Clone, Debug)]
pub struct InjectionRule {
    /// The upstream this rule applies to.
    pub upstream: String,
    /// The header to set on the upstream request, e.g. `authorization`.
    pub header: String,
    /// The name of the secret whose value becomes the header value.
    pub secret: String,
    /// Optional prefix, e.g. `Bearer ` for `authorization`.
    pub value_prefix: String,
}

/// A resolved credential ready to attach to one upstream request.
pub struct Injection {
    pub header: String,
    pub value: SecretValue,
}

impl std::fmt::Debug for Injection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the value.
        f.debug_struct("Injection")
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

/// The broker.
pub struct Broker {
    store: Box<dyn SecretStore>,
    minter: TokenMinter,
    egress: EgressPolicy,
    injections: Vec<InjectionRule>,
}

impl std::fmt::Debug for Broker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Broker")
            .field("egress", &self.egress)
            .field("injection_upstreams", &self.injection_upstreams())
            .finish_non_exhaustive()
    }
}

impl Broker {
    #[must_use]
    pub fn new(
        store: Box<dyn SecretStore>,
        minter: TokenMinter,
        egress: EgressPolicy,
        injections: Vec<InjectionRule>,
    ) -> Self {
        Self {
            store,
            minter,
            egress,
            injections,
        }
    }

    /// Resolve the credential (if any) to inject for `upstream`. Returns the
    /// header name and secret value; the caller attaches it to the outbound
    /// request. Missing secrets are an error (fail closed - a rule that names a
    /// missing secret must not silently send an unauthenticated request).
    pub fn injection_for(&self, upstream: &str) -> Result<Option<Injection>> {
        let Some(rule) = self.injections.iter().find(|r| r.upstream == upstream) else {
            return Ok(None);
        };
        let secret = self.store.get(&rule.secret)?;
        let value = SecretValue::new(format!("{}{}", rule.value_prefix, secret.as_str()));
        Ok(Some(Injection {
            header: rule.header.clone(),
            value,
        }))
    }

    /// Check whether an outbound destination is permitted.
    #[must_use]
    pub fn check_egress(&self, dest: &Destination) -> EgressDecision {
        self.egress.evaluate(dest)
    }

    /// Mint a short-lived scoped credential token.
    #[must_use]
    pub fn mint_token(&self, scope: TokenScope, now_unix: u64, ttl_secs: u64) -> String {
        self.minter.mint(scope, now_unix, ttl_secs)
    }

    /// Verify a credential token against a clock.
    pub fn verify_token(
        &self,
        token: &str,
        now_unix: u64,
    ) -> std::result::Result<TokenClaims, TokenError> {
        self.minter.verify(token, now_unix)
    }

    fn injection_upstreams(&self) -> Vec<&str> {
        self.injections
            .iter()
            .map(|r| r.upstream.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn broker() -> Broker {
        let store = MemoryStore::new();
        store
            .put("github_pat", Zeroizing::new("ghp_secret".into()))
            .unwrap();
        Broker::new(
            Box::new(store),
            TokenMinter::from_key(*b"0123456789abcdef0123456789abcdef"),
            EgressPolicy::new(vec![EgressRule::ExactHost("api.github.com".into())], false),
            vec![InjectionRule {
                upstream: "github".into(),
                header: "authorization".into(),
                secret: "github_pat".into(),
                value_prefix: "Bearer ".into(),
            }],
        )
    }

    #[test]
    fn injection_resolves_secret_with_prefix() {
        let inj = broker().injection_for("github").unwrap().unwrap();
        assert_eq!(inj.header, "authorization");
        assert_eq!(inj.value.as_str(), "Bearer ghp_secret");
    }

    #[test]
    fn injection_is_none_for_unconfigured_upstream() {
        assert!(broker().injection_for("gitlab").unwrap().is_none());
    }

    #[test]
    fn injection_fails_closed_when_secret_missing() {
        let b = Broker::new(
            Box::new(MemoryStore::new()),
            TokenMinter::from_key(*b"0123456789abcdef0123456789abcdef"),
            EgressPolicy::new(vec![], false),
            vec![InjectionRule {
                upstream: "x".into(),
                header: "authorization".into(),
                secret: "absent".into(),
                value_prefix: String::new(),
            }],
        );
        assert!(matches!(
            b.injection_for("x"),
            Err(BrokerError::NotFound(_))
        ));
    }

    #[test]
    fn egress_and_tokens_are_reachable_through_broker() {
        let b = broker();
        assert!(
            b.check_egress(&Destination::host("api.github.com"))
                .is_allowed()
        );
        let scope = TokenScope {
            tenant: "t".into(),
            principal: "p".into(),
            capability: "c".into(),
            upstream: "github".into(),
        };
        let token = b.mint_token(scope.clone(), 1000, 60);
        assert_eq!(b.verify_token(&token, 1010).unwrap().scope, scope);
    }
}
