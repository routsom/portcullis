//! Upstream connection pool.
//!
//! The edge connects to upstream MCP servers over Streamable HTTP only. It
//! cannot spawn a process, so it never launches a stdio server itself
//! (Directive #1; see `docs/adr/0003-m0-upstream-over-http.md`). A single
//! [`reqwest::Client`] is shared across all requests, giving connection pooling
//! and HTTP/2 multiplexing for free, which the latency budget depends on
//! (CLAUDE.md §5 row #1).

use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;

use crate::config::UpstreamConfig;
use crate::error::EdgeError;

/// A pool of named upstream endpoints behind a shared HTTP client.
#[derive(Clone)]
pub struct UpstreamPool {
    client: reqwest::Client,
    endpoints: HashMap<String, String>,
}

impl std::fmt::Debug for UpstreamPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamPool")
            .field("endpoints", &self.endpoints.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl UpstreamPool {
    /// Build the pool from configured upstreams.
    pub fn from_config(upstreams: &[UpstreamConfig]) -> Result<Self, EdgeError> {
        let client = reqwest::Client::builder()
            // Pool idle connections so multi-turn workloads reuse them.
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .map_err(EdgeError::Upstream)?;
        let endpoints = upstreams
            .iter()
            .map(|u| (u.name.clone(), u.url.clone()))
            .collect();
        Ok(Self { client, endpoints })
    }

    /// The URL for a named upstream, if configured.
    #[must_use]
    pub fn url(&self, name: &str) -> Option<&str> {
        self.endpoints.get(name).map(String::as_str)
    }

    /// Forward a JSON-RPC frame to an upstream and return the raw response for
    /// the caller to relay. The body is sent verbatim; the response is *not*
    /// buffered here - callers stream it (CLAUDE.md §5 row #1 "streaming relayed,
    /// never buffered").
    pub async fn forward(
        &self,
        name: &str,
        body: Bytes,
        accept: Option<&str>,
    ) -> Result<reqwest::Response, EdgeError> {
        let url = self
            .url(name)
            .ok_or_else(|| EdgeError::UnknownUpstream(name.to_string()))?;
        let mut req = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        // Relay the client's Accept so the upstream can choose JSON vs SSE.
        if let Some(accept) = accept {
            req = req.header(reqwest::header::ACCEPT, accept);
        } else {
            req = req.header(
                reqwest::header::ACCEPT,
                "application/json, text/event-stream",
            );
        }
        req.send().await.map_err(EdgeError::Upstream)
    }

    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.endpoints.keys().map(String::as_str).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> UpstreamPool {
        UpstreamPool::from_config(&[UpstreamConfig {
            name: "default".into(),
            url: "http://127.0.0.1:9090/mcp".into(),
        }])
        .unwrap()
    }

    #[test]
    fn url_resolves_known_upstream() {
        assert_eq!(pool().url("default"), Some("http://127.0.0.1:9090/mcp"));
    }

    #[test]
    fn url_is_none_for_unknown_upstream() {
        assert_eq!(pool().url("missing"), None);
    }
}
