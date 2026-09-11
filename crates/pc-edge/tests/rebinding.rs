//! DNS-rebinding / drive-by defence, exercised end-to-end over HTTP
//! (CLAUDE.md §5 row #4, CVE-2025-49596 / CVE-2025-64443 class).
//!
//! The gateway derives its allowed `Host` from the bind address and rejects any
//! present `Origin` (the empty-allowlist safe default) and any cross-site fetch.

mod common;

#[tokio::test]
async fn authenticated_same_host_request_succeeds() {
    let h = common::start().await;
    let resp = h
        .client
        .post(&h.gateway_url)
        .bearer_auth(&h.token)
        .header("content-type", "application/json")
        .body(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.as_slice())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn forged_host_header_is_rejected() {
    let h = common::start().await;
    // A rebinding victim's browser would carry an attacker Host it cannot match.
    let resp = h
        .client
        .post(&h.gateway_url)
        .bearer_auth(&h.token)
        .header("host", "attacker.example.com")
        .header("content-type", "application/json")
        .body(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.as_slice())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn cross_origin_request_is_rejected() {
    let h = common::start().await;
    let resp = h
        .client
        .post(&h.gateway_url)
        .bearer_auth(&h.token)
        .header("origin", "http://evil.example.com")
        .header("content-type", "application/json")
        .body(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.as_slice())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn cross_site_fetch_is_rejected() {
    let h = common::start().await;
    let resp = h
        .client
        .post(&h.gateway_url)
        .bearer_auth(&h.token)
        .header("sec-fetch-site", "cross-site")
        .header("content-type", "application/json")
        .body(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.as_slice())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn origin_check_precedes_auth() {
    // A forbidden origin is rejected even without a valid token: the network
    // boundary is enforced before credentials are considered.
    let h = common::start().await;
    let resp = h
        .client
        .post(&h.gateway_url)
        .header("host", "attacker.example.com")
        .header("content-type", "application/json")
        .body(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.as_slice())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}
