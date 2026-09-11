//! Shared test harness: an in-process echo MCP upstream behind a real gateway
//! built from public `pc-edge` APIs (no env, no `unsafe`).

// Each integration-test binary uses only a subset of these helpers; the module
// is shared, so unused-in-one-binary is expected.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::routing::post;
use pc_core::{Principal, PrincipalId, PrincipalKind, TenantId};
use pc_edge::auth::{AuthContext, Authenticator};
use pc_edge::config::UpstreamConfig;
use pc_edge::gateway::Gateway;
use pc_edge::security::SecurityPolicy;
use pc_edge::session::SessionSigner;
use pc_edge::transport::Transport;
use pc_edge::transport::http::HttpTransport;
use pc_edge::upstream::UpstreamPool;

pub struct Harness {
    pub gateway_url: String,
    pub token: String,
    pub client: reqwest::Client,
}

/// Start an echo upstream and a default gateway in front of it.
pub async fn start() -> Harness {
    start_with(|g| g).await
}

/// Start like [`start`] but apply `customize` to the gateway (e.g. attach a
/// policy engine or rate limiter) before it serves.
pub async fn start_with(customize: impl FnOnce(Gateway) -> Gateway) -> Harness {
    let echo_addr = spawn_echo().await;
    let echo_url = format!("http://{echo_addr}/mcp");
    let token = "test-token".to_string();

    let ctx = AuthContext {
        tenant: TenantId::new("default").unwrap(),
        principal: Principal::new(PrincipalId::new("tester"), PrincipalKind::Pat),
        upstream: "echo".to_string(),
        roles: Vec::new(),
        attributes: std::collections::BTreeMap::new(),
    };
    let auth = Authenticator::with_static_context(&token, ctx);
    let upstreams = UpstreamPool::from_config(&[UpstreamConfig {
        name: "echo".to_string(),
        url: echo_url.clone(),
    }])
    .unwrap();
    let gateway = customize(Gateway::new(auth, upstreams, SessionSigner::ephemeral()));

    let gw_addr = reserve_port().await;
    let bind = gw_addr.to_string();
    // Empty origins + host derived from bind.
    let security = SecurityPolicy::new(Vec::new(), Vec::new(), &bind);
    let transport = HttpTransport::new(bind.clone(), "/mcp".to_string(), security);
    tokio::spawn(async move {
        let _ = transport.serve(gateway).await;
    });

    let client = reqwest::Client::new();
    let gateway_url = format!("http://{bind}/mcp");
    wait_ready(&client, &gateway_url, &token).await;

    Harness {
        gateway_url,
        token,
        client,
    }
}

/// Start `nodes` gateways in front of one shared echo upstream, all sharing the
/// same auth token and session signing key - i.e. an active-active cluster with
/// no session affinity. Any node can serve any request (CLAUDE.md §5 row #9).
pub async fn start_cluster(nodes: usize, session_key: &[u8]) -> Vec<Harness> {
    let echo_addr = spawn_echo().await;
    let echo_url = format!("http://{echo_addr}/mcp");
    let token = "test-token".to_string();

    let mut harnesses = Vec::new();
    for _ in 0..nodes {
        let ctx = AuthContext {
            tenant: TenantId::new("default").unwrap(),
            principal: Principal::new(PrincipalId::new("tester"), PrincipalKind::Pat),
            upstream: "echo".to_string(),
            roles: Vec::new(),
            attributes: std::collections::BTreeMap::new(),
        };
        let auth = Authenticator::with_static_context(&token, ctx);
        let upstreams = UpstreamPool::from_config(&[UpstreamConfig {
            name: "echo".to_string(),
            url: echo_url.clone(),
        }])
        .unwrap();
        // Every node shares the same signing key, so a session token minted by
        // one node verifies on any other.
        let gateway = Gateway::new(
            auth,
            upstreams,
            SessionSigner::from_key(session_key.to_vec()),
        );

        let gw_addr = reserve_port().await;
        let bind = gw_addr.to_string();
        let security = SecurityPolicy::new(Vec::new(), Vec::new(), &bind);
        let transport = HttpTransport::new(bind.clone(), "/mcp".to_string(), security);
        tokio::spawn(async move {
            let _ = transport.serve(gateway).await;
        });

        let client = reqwest::Client::new();
        let gateway_url = format!("http://{bind}/mcp");
        wait_ready(&client, &gateway_url, &token).await;
        harnesses.push(Harness {
            gateway_url,
            token: token.clone(),
            client,
        });
    }
    harnesses
}

async fn wait_ready(client: &reqwest::Client, url: &str, token: &str) {
    for _ in 0..100 {
        let r = client
            .post(url)
            .bearer_auth(token)
            .header("content-type", "application/json")
            .body(br#"{"jsonrpc":"2.0","id":0,"method":"ping"}"#.as_slice())
            .send()
            .await;
        if r.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("gateway did not become ready");
}

async fn spawn_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/mcp", post(echo_handler));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

/// Echoes back the request: the response `result` carries the method and the
/// verbatim params, so tests can assert faithful relay. For `initialize`, it
/// reflects the requested protocol version like a real server would.
async fn echo_handler(body: axum::body::Bytes) -> axum::response::Response {
    use axum::response::IntoResponse;
    let req: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = req
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let result = if method == "initialize" {
        let version = params
            .get("protocolVersion")
            .and_then(|v| v.as_str())
            .unwrap_or("2026-07-28");
        serde_json::json!({
            "protocolVersion": version,
            "serverInfo": {"name": "echo", "version": "0"},
            "capabilities": {}
        })
    } else {
        serde_json::json!({ "echoed_method": method, "echoed_params": params })
    };

    let resp = serde_json::json!({"jsonrpc":"2.0","id":id,"result":result});
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&resp).unwrap(),
    )
        .into_response()
}

async fn reserve_port() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}
