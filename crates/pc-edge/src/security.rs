//! HTTP request-origin hardening against DNS rebinding and drive-by RCE
//! (CLAUDE.md §5 row #4, the CVE-2025-49596 / CVE-2025-64443 class).
//!
//! A rebinding attack relies on a victim browser being pointed at the gateway's
//! loopback address; the browser always attaches `Origin` (and, in modern
//! browsers, `Sec-Fetch-Site`) and cannot forge the `Host`. We therefore:
//!
//! - require `Host` to be an explicitly allowed value;
//! - reject any present `Origin` that is not allow-listed (absent `Origin`, as
//!   from a non-browser MCP client, is permitted);
//! - reject `Sec-Fetch-Site: cross-site` outright.
//!
//! The safe default is an empty origin allow-list, which rejects every
//! cross-origin browser request.

use crate::error::EdgeError;

/// Effective, resolved allow-lists for one HTTP listener.
#[derive(Clone, Debug)]
pub struct SecurityPolicy {
    allowed_origins: Vec<String>,
    allowed_hosts: Vec<String>,
}

/// The subset of request headers relevant to the origin check.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestHeaders<'a> {
    pub host: Option<&'a str>,
    pub origin: Option<&'a str>,
    pub sec_fetch_site: Option<&'a str>,
}

impl SecurityPolicy {
    /// Build a policy. If `allowed_hosts` is empty, `bind` is used as the only
    /// permitted `Host`, so a misconfiguration fails closed rather than open.
    #[must_use]
    pub fn new(allowed_origins: Vec<String>, allowed_hosts: Vec<String>, bind: &str) -> Self {
        let allowed_hosts = if allowed_hosts.is_empty() {
            vec![bind.to_string()]
        } else {
            allowed_hosts
        };
        Self {
            allowed_origins,
            allowed_hosts,
        }
    }

    /// Check a request's headers. Returns [`EdgeError::ForbiddenOrigin`] on any
    /// violation; the error does not echo the offending value.
    pub fn check(&self, headers: RequestHeaders<'_>) -> Result<(), EdgeError> {
        // Host must be explicitly allowed.
        match headers.host {
            Some(host) if self.allowed_hosts.iter().any(|h| h == host) => {}
            _ => return Err(EdgeError::ForbiddenOrigin),
        }

        // A present Origin must be allow-listed. Absent Origin (non-browser
        // clients) is permitted.
        if let Some(origin) = headers.origin
            && !self.allowed_origins.iter().any(|o| o == origin)
        {
            return Err(EdgeError::ForbiddenOrigin);
        }

        // Reject explicit cross-site fetches.
        if matches!(headers.sec_fetch_site, Some("cross-site")) {
            return Err(EdgeError::ForbiddenOrigin);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SecurityPolicy {
        SecurityPolicy::new(
            vec!["http://localhost:8080".to_string()],
            vec!["localhost:8080".to_string(), "127.0.0.1:8080".to_string()],
            "127.0.0.1:8080",
        )
    }

    #[test]
    fn allows_non_browser_client_with_allowed_host() {
        let h = RequestHeaders {
            host: Some("127.0.0.1:8080"),
            origin: None,
            sec_fetch_site: None,
        };
        assert!(policy().check(h).is_ok());
    }

    #[test]
    fn allows_same_origin_browser_request() {
        let h = RequestHeaders {
            host: Some("localhost:8080"),
            origin: Some("http://localhost:8080"),
            sec_fetch_site: Some("same-origin"),
        };
        assert!(policy().check(h).is_ok());
    }

    #[test]
    fn rejects_rebinding_host() {
        let h = RequestHeaders {
            host: Some("attacker.example.com"),
            origin: None,
            sec_fetch_site: None,
        };
        assert!(policy().check(h).is_err());
    }

    #[test]
    fn rejects_unlisted_origin() {
        let h = RequestHeaders {
            host: Some("localhost:8080"),
            origin: Some("http://evil.example.com"),
            sec_fetch_site: None,
        };
        assert!(policy().check(h).is_err());
    }

    #[test]
    fn rejects_cross_site_fetch() {
        let h = RequestHeaders {
            host: Some("localhost:8080"),
            origin: Some("http://localhost:8080"),
            sec_fetch_site: Some("cross-site"),
        };
        assert!(policy().check(h).is_err());
    }

    #[test]
    fn rejects_missing_host() {
        let h = RequestHeaders::default();
        assert!(policy().check(h).is_err());
    }
}
