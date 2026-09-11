//! Streamable HTTP transport.
//!
//! One POST endpoint terminates MCP over HTTP. Every request is authenticated
//! (no `--no-auth`), origin-checked (DNS-rebinding defence), routed to the
//! principal's upstream, and relayed - responses are streamed straight through,
//! never buffered (CLAUDE.md §5 rows #1, #4).

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use pc_proto_mcp::Message;
use tracing::{debug, info, warn};

use crate::auth::Authenticator;
use crate::error::Result;
use crate::gateway::{self, Gateway};
use crate::metrics::Outcome;
use crate::security::{RequestHeaders, SecurityPolicy};

use super::Transport;

/// Streamable HTTP listener configuration, resolved to a bindable form.
#[derive(Clone, Debug)]
pub struct HttpTransport {
    bind: String,
    path: String,
    security: SecurityPolicy,
}

impl HttpTransport {
    #[must_use]
    pub fn new(bind: String, path: String, security: SecurityPolicy) -> Self {
        Self {
            bind,
            path,
            security,
        }
    }
}

#[derive(Clone)]
struct AppState {
    gateway: Gateway,
    security: Arc<SecurityPolicy>,
}

impl Transport for HttpTransport {
    async fn serve(self, gateway: Gateway) -> Result<()> {
        let state = AppState {
            gateway,
            security: Arc::new(self.security),
        };
        let app = Router::new()
            .route(&self.path, post(handle))
            // Local-only metrics for a Prometheus scraper (Directive #8). Bind
            // the listener to a trusted interface if exposing metrics.
            .route("/metrics", get(metrics))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind(&self.bind).await?;
        info!(bind = %self.bind, path = %self.path, "http transport listening");
        axum::serve(listener, app)
            .await
            .map_err(crate::error::EdgeError::Io)?;
        Ok(())
    }
}

/// Prometheus metrics endpoint (local export only).
#[allow(clippy::unused_async)] // axum handler contract
async fn metrics(State(state): State<AppState>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.gateway.metrics().to_prometheus(),
    )
        .into_response()
}

/// Small JSON error body. Never contains token values or argument data.
fn error_response(status: StatusCode, message: &str) -> Response {
    (status, axum::Json(serde_json::json!({ "error": message }))).into_response()
}

#[allow(clippy::unused_async)] // handler signature is async by axum contract
async fn handle(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    // 1. Origin/Host/Sec-Fetch-Site hardening, before anything else looks at the
    //    body.
    let rh = RequestHeaders {
        host: header_str(&headers, header::HOST),
        origin: header_str(&headers, header::ORIGIN),
        sec_fetch_site: headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()),
    };
    if state.security.check(rh).is_err() {
        debug!("request rejected by origin/host policy");
        return error_response(StatusCode::FORBIDDEN, "forbidden");
    }

    // 2. Mandatory authentication.
    let Some(token) =
        header_str(&headers, header::AUTHORIZATION).and_then(Authenticator::parse_bearer)
    else {
        return unauthorized();
    };
    let Ok(ctx) = state.gateway.auth().authenticate(token) else {
        return unauthorized();
    };

    // 3. Parse just enough to route and negotiate; payload stays raw.
    let Ok(msg) = Message::parse(&body) else {
        return error_response(StatusCode::BAD_REQUEST, "malformed frame");
    };

    // 4. Version negotiation (initialize only).
    let negotiated = state.gateway.negotiate(&msg);
    if let Some(outcome) = &negotiated {
        debug!(effective = %outcome.effective(), "protocol negotiated");
    }

    let gw = &state.gateway;
    let method = msg.method().unwrap_or("<response>").to_string();
    // When no policy/limiter/breaker/audit is configured, skip capability and
    // arg-shape extraction entirely so the hot path stays at passthrough cost.
    let need = gw.enforcement_active() || gw.has_audit();
    let capability = if need { gw.capability_of(&msg) } else { None };
    let request_id = if need {
        request_id(&msg)
    } else {
        String::new()
    };
    let cap_ref = capability.as_ref();

    // 5-7. Rate limit, policy, and circuit breaker (fail-closed).
    if need && let Some(blocked) = enforce(gw, &ctx, &msg, &method, cap_ref, &request_id) {
        return blocked;
    }

    info!(
        tenant = %ctx.tenant,
        principal = %ctx.principal,
        upstream = %ctx.upstream,
        method = %method,
        "relaying call"
    );

    // 8. Relay to the principal's upstream and stream the response back.
    let accept = header_str(&headers, header::ACCEPT);
    match gw.upstreams().forward(&ctx.upstream, body, accept).await {
        Ok(resp) => {
            // Treat upstream 5xx as a breaker failure signal.
            let success = !resp.status().is_server_error();
            gw.breaker_record(&ctx.upstream, success);
            gw.record_outcome(
                ctx.tenant.as_str(),
                if success {
                    Outcome::Allowed
                } else {
                    Outcome::UpstreamError
                },
            );
            if gw.has_audit() {
                gw.audit(gateway::audit_event(
                    &request_id,
                    &ctx,
                    cap_ref,
                    &method,
                    "allow",
                ));
            }
            relay(resp, negotiated.as_ref())
        }
        Err(e) => {
            warn!(error = %e, "upstream request failed");
            gw.breaker_record(&ctx.upstream, false);
            gw.record_outcome(ctx.tenant.as_str(), Outcome::UpstreamError);
            if gw.has_audit() {
                gw.audit(gateway::audit_event(
                    &request_id,
                    &ctx,
                    cap_ref,
                    &method,
                    "deny:upstream_error",
                ));
            }
            error_response(StatusCode::BAD_GATEWAY, "upstream error")
        }
    }
}

/// Apply rate limiting, policy authorization, and the circuit breaker. Returns
/// `Some(response)` if the request is blocked (already audited), `None` to
/// proceed.
fn enforce(
    gw: &Gateway,
    ctx: &crate::auth::AuthContext,
    msg: &Message,
    method: &str,
    cap_ref: Option<&pc_core::CapabilityId>,
    request_id: &str,
) -> Option<Response> {
    // Rate limiting (per tenant/principal/capability).
    if let Some(cap) = cap_ref
        && !gw.rate_limit_allow(ctx, cap)
    {
        gw.audit(gateway::audit_event(
            request_id,
            ctx,
            cap_ref,
            method,
            "deny:rate_limited",
        ));
        gw.record_outcome(ctx.tenant.as_str(), Outcome::Denied);
        return Some(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded",
        ));
    }

    // Authorization (fail-closed policy; allow-all if unconfigured).
    if let Some(cap) = cap_ref {
        // Direct calls have a chain depth of 1; delegation parsing arrives later.
        let explained = gw.authorize(ctx, cap, 1, msg);
        if !explained.decision.is_allowed() {
            debug!(reason = %explained.reason, "denied by policy");
            gw.audit(gateway::audit_event(
                request_id,
                ctx,
                cap_ref,
                method,
                &format!("deny:{}", explained.reason),
            ));
            gw.record_outcome(ctx.tenant.as_str(), Outcome::Denied);
            return Some(error_response(StatusCode::FORBIDDEN, "denied by policy"));
        }
    }

    // Circuit breaker for the target upstream.
    if !gw.breaker_allow(&ctx.upstream) {
        gw.audit(gateway::audit_event(
            request_id,
            ctx,
            cap_ref,
            method,
            "deny:circuit_open",
        ));
        gw.record_outcome(ctx.tenant.as_str(), Outcome::Denied);
        return Some(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "upstream circuit open",
        ));
    }
    None
}

/// A stable-enough request id for correlation: the JSON-RPC id if present.
fn request_id(msg: &Message) -> String {
    match msg.id() {
        Some(pc_proto_mcp::Id::Number(n)) => format!("id-{n}"),
        Some(pc_proto_mcp::Id::String(s)) => s.clone(),
        None => format!("req-{}", gateway::now_ms()),
    }
}

/// Turn an upstream reqwest response into a streamed axum response, preserving
/// status and content-type and annotating the negotiated protocol revision.
fn relay(
    resp: reqwest::Response,
    negotiated: Option<&pc_proto_mcp::NegotiationOutcome>,
) -> Response {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();

    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type);
    if let Some(outcome) = negotiated {
        builder = builder.header("x-portcullis-protocol", outcome.effective().as_str());
    }
    // Stream upstream bytes straight through without buffering.
    let body = Body::from_stream(resp.bytes_stream());
    builder
        .body(body)
        .unwrap_or_else(|_| error_response(StatusCode::BAD_GATEWAY, "relay error"))
}

fn unauthorized() -> Response {
    // Advertise the scheme without hinting at valid tokens.
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        axum::Json(serde_json::json!({ "error": "authentication required" })),
    )
        .into_response()
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}
