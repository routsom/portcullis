//! portcullis edge: transport termination, authentication, stateless sessions,
//! and passthrough routing to upstream MCP servers.
//!
//! Two invariants this crate exists to uphold:
//! - It never executes tool logic and cannot spawn a process. There is no
//!   `std::process` import here, enforced by `xtask deny-imports` (Directive #1,
//!   §5 row #5).
//! - It holds no upstream credentials; it only relays (Directive #2).

pub mod auth;
pub mod breaker;
pub mod config;
pub mod error;
pub mod gateway;
pub mod limits;
pub mod metrics;
pub mod security;
pub mod session;
pub mod transport;
pub mod upstream;

pub use config::GatewayConfig;
pub use error::{EdgeError, Result};
pub use gateway::Gateway;

use auth::{AuthContext, Authenticator};
use pc_core::{Principal, PrincipalId, PrincipalKind, TenantId};
use security::SecurityPolicy;
use session::SessionSigner;
use tokio::task::JoinSet;
use tracing::{info, warn};
use transport::Transport;
use transport::http::HttpTransport;
use transport::stdio::StdioTransport;
use upstream::UpstreamPool;

/// Assemble a [`Gateway`] from configuration, reading secret *values* from the
/// environment variables the config names (Directive #2).
pub fn build_gateway(config: &GatewayConfig) -> Result<Gateway> {
    let auth = Authenticator::from_config(&config.auth)?;
    let upstreams = UpstreamPool::from_config(&config.upstream)?;
    let sessions = build_session_signer(config)?;
    let mut gateway = Gateway::new(auth, upstreams, sessions);

    if let Some(policy) = &config.policy {
        gateway = gateway.with_policy(pc_policy::PolicyEngine::new(
            policy.rules.clone(),
            policy.cache_capacity,
        ));
    }
    if let Some(rl) = &config.rate_limit {
        gateway =
            gateway.with_rate_limiter(limits::RateLimiter::new(rl.capacity, rl.refill_per_sec));
    }
    if let Some(cb) = &config.circuit_breaker {
        gateway = gateway.with_breakers(breaker::CircuitBreakers::new(
            cb.failure_threshold,
            cb.cooldown_ms,
        ));
    }
    if let Some(audit) = &config.audit {
        let key = match &audit.secret_env {
            Some(var) => Some(
                std::env::var(var)
                    .map_err(|_| {
                        EdgeError::Config(format!("audit secret env var {var:?} is not set"))
                    })?
                    .into_bytes(),
            ),
            None => None,
        };
        let log = pc_audit::FileAuditLog::open(&audit.path, key).map_err(EdgeError::Io)?;
        gateway = gateway.with_audit(gateway::AuditSink::spawn(log));
    }
    Ok(gateway)
}

fn build_session_signer(config: &GatewayConfig) -> Result<SessionSigner> {
    let Some(var) = &config.session.secret_env else {
        warn!(
            "no session.secret_env configured; using an ephemeral signing key \
             (single-node only - configure a shared key for active-active)"
        );
        return Ok(SessionSigner::ephemeral());
    };
    let key = std::env::var(var)
        .map_err(|_| EdgeError::Config(format!("session secret env var {var:?} is not set")))?;
    if key.is_empty() {
        return Err(EdgeError::Config(format!(
            "session secret env var {var:?} is empty"
        )));
    }
    Ok(SessionSigner::from_key(key.into_bytes()))
}

/// Build, then run, every configured transport until one exits or errors.
///
/// At least one listener must be enabled. Each transport runs on a supervised
/// task whose result is observed (CLAUDE.md §11).
pub async fn serve(config: GatewayConfig) -> Result<()> {
    let gateway = build_gateway(&config)?;
    let mut set: JoinSet<Result<()>> = JoinSet::new();

    if let Some(http) = &config.server.http {
        if gateway.auth().is_empty() {
            warn!("http listener enabled with no auth tokens; all requests will be rejected");
        }
        let security = SecurityPolicy::new(
            http.allowed_origins.clone(),
            http.allowed_hosts.clone(),
            &http.bind,
        );
        let transport = HttpTransport::new(http.bind.clone(), http.path.clone(), security);
        let gw = gateway.clone();
        set.spawn(async move { transport.serve(gw).await });
    }

    if let Some(stdio) = &config.server.stdio {
        let ctx = stdio_context(stdio, &gateway)?;
        let transport = StdioTransport::new(ctx);
        let gw = gateway.clone();
        set.spawn(async move { transport.serve(gw).await });
    }

    if set.is_empty() {
        return Err(EdgeError::Config(
            "no transport enabled: configure [server.http] and/or [server.stdio]".to_string(),
        ));
    }

    info!(transports = set.len(), "portcullis edge serving");

    // Await the first task to finish; propagate its result. A clean exit of any
    // listener ends serving, and dropping `set` aborts the rest.
    match set.join_next().await {
        Some(Ok(Ok(()))) | None => Ok(()),
        Some(Ok(Err(e))) => Err(e),
        Some(Err(join_err)) => Err(EdgeError::Config(format!(
            "transport task panicked: {join_err}"
        ))),
    }
}

fn stdio_context(stdio: &config::StdioListenerConfig, gateway: &Gateway) -> Result<AuthContext> {
    if gateway.upstreams().url(&stdio.upstream).is_none() {
        return Err(EdgeError::UnknownUpstream(stdio.upstream.clone()));
    }
    let tenant = TenantId::new(stdio.tenant.clone())
        .map_err(|e| EdgeError::Config(format!("invalid stdio tenant: {e}")))?;
    Ok(AuthContext {
        tenant,
        principal: Principal::new(
            PrincipalId::new(stdio.principal.clone()),
            PrincipalKind::Pat,
        ),
        upstream: stdio.upstream.clone(),
        roles: stdio.roles.clone(),
        attributes: stdio.attributes.clone(),
    })
}
