//! Runtime configuration for the edge.
//!
//! This is the authoritative shape of the gateway's behaviour: everything that
//! changes how it runs lives here and is declarative and diffable (CLAUDE.md
//! §9). Secrets are never stored inline - token and key *values* are read from
//! named environment variables at load time (Directive #2, §9). The serde
//! `Default` impls encode the safe defaults: auth on, egress/origins closed,
//! telemetry local, capabilities unapproved.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level gateway configuration, typically parsed from `portcullis.toml`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GatewayConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub session: SessionConfig,
    #[serde(default)]
    pub upstream: Vec<UpstreamConfig>,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    /// Authorization policy (M2). Absent means allow-all once authenticated.
    #[serde(default)]
    pub policy: Option<PolicyConfig>,
    /// Per-(tenant, principal, capability) rate limiting (M2). Absent = off.
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    /// Per-upstream circuit breaking (M2). Absent = off.
    #[serde(default)]
    pub circuit_breaker: Option<BreakerConfig>,
    /// Hash-chained audit log (M2). Absent = structured tracing only.
    #[serde(default)]
    pub audit: Option<AuditConfig>,
}

/// Authorization policy: ordered RBAC/ABAC rules, evaluated fail-closed.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub rules: Vec<pc_policy::Rule>,
    /// Decision-cache capacity. 0 disables the cache.
    #[serde(default = "default_cache_capacity")]
    pub cache_capacity: usize,
}

fn default_cache_capacity() -> usize {
    4096
}

/// Token-bucket rate limit applied per (tenant, principal, capability).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Burst capacity (tokens).
    pub capacity: f64,
    /// Sustained refill rate (tokens per second).
    pub refill_per_sec: f64,
}

/// Circuit-breaker thresholds applied per upstream.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BreakerConfig {
    /// Consecutive failures before opening.
    pub failure_threshold: u32,
    /// How long to stay open before a half-open probe (milliseconds).
    pub cooldown_ms: u64,
}

/// Append-only, hash-chained audit log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Path to the JSONL audit file.
    pub path: PathBuf,
    /// Env var holding the HMAC signing key (unsigned if absent).
    #[serde(default)]
    pub secret_env: Option<String>,
}

/// Client-facing listeners.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub http: Option<HttpListenerConfig>,
    #[serde(default)]
    pub stdio: Option<StdioListenerConfig>,
}

/// Streamable HTTP listener.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpListenerConfig {
    /// Socket address to bind, e.g. `127.0.0.1:8080`.
    pub bind: String,
    /// Request path for the MCP endpoint.
    #[serde(default = "default_mcp_path")]
    pub path: String,
    /// Exact `Origin` values permitted (DNS-rebinding defence, §5 row #4).
    /// Empty means: reject all cross-origin requests (the safe default).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Exact `Host` header values permitted. Empty means: derive from `bind`.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

fn default_mcp_path() -> String {
    "/mcp".to_string()
}

/// stdio listener. Because stdio is a local pipe with no per-message
/// credential, the session is bound to an explicitly configured principal and
/// tenant - this is an authenticated binding set by the operator, not an
/// anonymous bypass (there is no `--no-auth`, §5 row #4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StdioListenerConfig {
    pub principal: String,
    pub tenant: String,
    /// Which configured upstream to route to.
    pub upstream: String,
    /// RBAC roles the bound principal holds.
    #[serde(default)]
    pub roles: Vec<String>,
    /// ABAC attributes for policy evaluation.
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

/// Pre-shared bearer-token (PAT) authentication. Each entry names the env var
/// holding the token value; the value itself is never written in config.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub tokens: Vec<TokenConfig>,
}

/// One principal's bearer token, sourced from an environment variable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenConfig {
    /// Environment variable holding the secret token value.
    pub token_env: String,
    pub principal: String,
    pub tenant: String,
    /// Which configured upstream this principal's calls route to.
    pub upstream: String,
    /// RBAC roles this principal holds.
    #[serde(default)]
    pub roles: Vec<String>,
    /// ABAC attributes for policy evaluation.
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

/// Stateless session-token signing. The key is read from an env var so every
/// node in a cluster can share it; if unset, an ephemeral per-process key is
/// generated and a warning is logged (single-node only - §5 row #9).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SessionConfig {
    #[serde(default)]
    pub secret_env: Option<String>,
}

/// A named upstream MCP server. In M0 the edge connects over HTTP only (it
/// cannot spawn a stdio server - Directive #1); stdio upstreams arrive with the
/// runner in M1. See `docs/adr/0003-m0-upstream-over-http.md`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub name: String,
    /// Full URL of the upstream MCP endpoint, e.g. `http://127.0.0.1:9090/mcp`.
    pub url: String,
}

/// Observability. On by default, local export only (Directive #8).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetryConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_no_open_listener() {
        let c = GatewayConfig::default();
        assert!(c.server.http.is_none());
        assert!(c.server.stdio.is_none());
        assert!(c.auth.tokens.is_empty());
    }

    #[test]
    fn unknown_keys_are_ignored_at_struct_level() {
        // Unknown keys must not break parsing (CLAUDE.md §8: they warn, they do
        // not error). Strictness is layered on in the CLI loader via
        // `serde_ignored`, not here.
        let parsed: GatewayConfig = toml::from_str("nonsense_key = true").unwrap();
        assert!(parsed.server.http.is_none());
    }

    #[test]
    fn http_listener_defaults_path_when_omitted() {
        let parsed: GatewayConfig =
            toml::from_str("[server.http]\nbind = \"127.0.0.1:8080\"\n").unwrap();
        assert_eq!(parsed.server.http.unwrap().path, "/mcp");
    }
}
