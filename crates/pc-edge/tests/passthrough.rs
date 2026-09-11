//! End-to-end passthrough: a client drives `initialize` and `tools/call`
//! through the gateway to a real (echo) upstream, and authentication is proven
//! mandatory. Verifies the M0 exit behaviour (CLAUDE.md §15) and §5 row #4's
//! "there is no `--no-auth`".

mod common;

use serde_json::Value;

#[tokio::test]
async fn initialize_is_relayed_and_protocol_is_negotiated() {
    let h = common::start().await;
    let resp = h
        .client
        .post(&h.gateway_url)
        .bearer_auth(&h.token)
        .header("content-type", "application/json")
        .body(
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{}}}"#
                .as_slice(),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    // The gateway annotates the negotiated revision.
    assert_eq!(
        resp.headers()
            .get("x-portcullis-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("2026-07-28")
    );
    let bytes = resp.bytes().await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["id"], 1);
    assert_eq!(body["result"]["protocolVersion"], "2026-07-28");
}

#[tokio::test]
async fn unsupported_client_version_downgrades_not_errors() {
    let h = common::start().await;
    let resp = h
        .client
        .post(&h.gateway_url)
        .bearer_auth(&h.token)
        .header("content-type", "application/json")
        .body(
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01","capabilities":{}}}"#
                .as_slice(),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    // Graceful downgrade: the gateway offers its latest supported revision.
    assert_eq!(
        resp.headers()
            .get("x-portcullis-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("2026-07-28")
    );
}

#[tokio::test]
async fn tools_call_is_relayed_faithfully() {
    let h = common::start().await;
    let resp = h
        .client
        .post(&h.gateway_url)
        .bearer_auth(&h.token)
        .header("content-type", "application/json")
        .body(
            br#"{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}"#
                .as_slice(),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let bytes = resp.bytes().await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["id"], 42);
    assert_eq!(body["result"]["echoed_method"], "tools/call");
    // Arguments pass through untouched (the gateway does not rewrite payloads).
    assert_eq!(body["result"]["echoed_params"]["arguments"]["msg"], "hi");
}

#[tokio::test]
async fn request_without_token_is_rejected() {
    let h = common::start().await;
    let resp = h
        .client
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.as_slice())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(resp.headers().contains_key("www-authenticate"));
}

#[tokio::test]
async fn request_with_wrong_token_is_rejected() {
    let h = common::start().await;
    let resp = h
        .client
        .post(&h.gateway_url)
        .bearer_auth("not-the-token")
        .header("content-type", "application/json")
        .body(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.as_slice())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}
