//! Reference latency benchmark (CLAUDE.md §6, §15).
//!
//! Measures the gateway's *added* overhead by comparing two paths against the
//! same echo upstream:
//!
//! - direct:  client -> echo (1 hop, the baseline)
//! - gateway: client -> portcullis -> echo (2 hops)
//!
//! Added latency = gateway - direct, which isolates the gateway's own cost as
//! §6 prescribes ("echo upstream to isolate gateway cost").
//!
//! Exit code is non-zero if the M0 exit budget (added p99 <= 2 ms) is missed,
//! so CI can gate on it.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::Router;
use axum::extract::State;
use axum::routing::post;
use pc_edge::GatewayConfig;
use pc_edge::config::{AuthConfig, HttpListenerConfig, ServerConfig, TokenConfig, UpstreamConfig};

const WARMUP: usize = 300;
const SAMPLES: usize = 3000;
const M0_ADDED_P99_BUDGET: Duration = Duration::from_millis(2);

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Echo upstream.
    let echo_addr = spawn_echo().await?;
    let echo_url = format!("http://{echo_addr}/mcp");

    // 2. Gateway in front of it. Pre-bind to reserve a port, then hand it over.
    // The token value is provided by the launcher (see the `bench` recipe) so
    // the binary needs no `unsafe` env mutation.
    let gw_addr = reserve_port().await?;
    let token = std::env::var("PORTCULLIS_BENCH_TOKEN")
        .context("set PORTCULLIS_BENCH_TOKEN before running the benchmark (see `just bench`)")?;
    let token = token.as_str();
    let config = gateway_config(&gw_addr.to_string(), &echo_url);
    tokio::spawn(async move {
        if let Err(e) = pc_edge::serve(config).await {
            eprintln!("gateway exited: {e}");
        }
    });

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(16)
        .build()?;
    wait_ready(&client, &format!("http://{gw_addr}/mcp"), token).await?;

    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hello"}}}"#;

    // 3. Measure both paths.
    let direct = measure(&client, &echo_url, None, body).await?;
    let gateway = measure(&client, &format!("http://{gw_addr}/mcp"), Some(token), body).await?;

    let d = summarize(direct);
    let g = summarize(gateway);
    let added_p50 = g.p50.saturating_sub(d.p50);
    let added_p99 = g.p99.saturating_sub(d.p99);

    println!("reference latency benchmark ({SAMPLES} samples)\n");
    println!("{:<18} {:>10} {:>10}", "path", "p50 (µs)", "p99 (µs)");
    println!(
        "{:<18} {:>10} {:>10}",
        "direct (echo)",
        d.p50.as_micros(),
        d.p99.as_micros()
    );
    println!(
        "{:<18} {:>10} {:>10}",
        "via portcullis",
        g.p50.as_micros(),
        g.p99.as_micros()
    );
    println!(
        "{:<18} {:>10} {:>10}",
        "added",
        added_p50.as_micros(),
        added_p99.as_micros()
    );
    println!(
        "\nM0 exit budget: added p99 <= {} µs",
        M0_ADDED_P99_BUDGET.as_micros()
    );

    if added_p99 > M0_ADDED_P99_BUDGET {
        println!("RESULT: OVER BUDGET");
        std::process::exit(1);
    }
    println!("RESULT: within budget");
    Ok(())
}

struct Stats {
    p50: Duration,
    p99: Duration,
}

fn summarize(mut samples: Vec<Duration>) -> Stats {
    samples.sort_unstable();
    // Integer percentile indexing avoids lossy float casts.
    let idx = |num: usize, den: usize| ((samples.len() * num) / den).min(samples.len() - 1);
    Stats {
        p50: samples[idx(1, 2)],
        p99: samples[idx(99, 100)],
    }
}

async fn measure(
    client: &reqwest::Client,
    url: &str,
    token: Option<&str>,
    body: &'static [u8],
) -> Result<Vec<Duration>> {
    // Warm up connection pool and upstream.
    for _ in 0..WARMUP {
        send(client, url, token, body).await?;
    }
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        send(client, url, token, body).await?;
        samples.push(start.elapsed());
    }
    Ok(samples)
}

async fn send(
    client: &reqwest::Client,
    url: &str,
    token: Option<&str>,
    body: &'static [u8],
) -> Result<()> {
    let mut req = client
        .post(url)
        .header("content-type", "application/json")
        .body(body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await.context("request failed")?;
    // Drain body so the connection is reusable.
    let _ = resp.bytes().await?;
    Ok(())
}

async fn wait_ready(client: &reqwest::Client, url: &str, token: &str) -> Result<()> {
    for _ in 0..100 {
        if send(
            client,
            url,
            Some(token),
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}",
        )
        .await
        .is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("gateway did not become ready")
}

fn gateway_config(bind: &str, upstream_url: &str) -> GatewayConfig {
    GatewayConfig {
        server: ServerConfig {
            http: Some(HttpListenerConfig {
                bind: bind.to_string(),
                path: "/mcp".to_string(),
                allowed_origins: Vec::new(),
                allowed_hosts: Vec::new(),
            }),
            stdio: None,
        },
        auth: AuthConfig {
            tokens: vec![TokenConfig {
                token_env: "PORTCULLIS_BENCH_TOKEN".to_string(),
                principal: "bench".to_string(),
                tenant: "default".to_string(),
                upstream: "echo".to_string(),
                roles: Vec::new(),
                attributes: std::collections::BTreeMap::new(),
            }],
        },
        session: pc_edge::config::SessionConfig::default(),
        upstream: vec![UpstreamConfig {
            name: "echo".to_string(),
            url: upstream_url.to_string(),
        }],
        telemetry: pc_edge::config::TelemetryConfig::default(),
        policy: None,
        rate_limit: None,
        circuit_breaker: None,
        audit: None,
    }
}

// --- echo upstream fixture -------------------------------------------------

#[derive(Clone)]
struct EchoState;

async fn spawn_echo() -> Result<std::net::SocketAddr> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = Router::new()
        .route("/mcp", post(echo_handler))
        .with_state(EchoState);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(addr)
}

async fn echo_handler(
    State(_): State<EchoState>,
    body: axum::body::Bytes,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    // Echo a minimal JSON-RPC-shaped result; the benchmark only needs a small,
    // realistic response, not a full MCP implementation.
    let id = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .unwrap_or(serde_json::Value::Null);
    let resp = serde_json::json!({"jsonrpc":"2.0","id":id,"result":{"ok":true}});
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&resp).unwrap_or_default(),
    )
        .into_response()
}

async fn reserve_port() -> Result<std::net::SocketAddr> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}
