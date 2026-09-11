//! The gateway core: the pieces every transport shares.
//!
//! A [`Gateway`] owns the authenticator, upstream pool, session signer, and -
//! from M2 - the policy engine, rate limiter, circuit breakers, and audit sink.
//! It holds **no upstream credentials** and cannot execute anything; it parses,
//! decides, routes, and logs (Directive #1).
//!
//! The decision path is fail-closed-shaped: the handler must consult
//! [`Gateway::authorize`], [`Gateway::rate_limit_allow`], and the circuit
//! breaker before relaying, and record the outcome to the audit chain.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use pc_audit::{AuditEvent, FileAuditLog};
use pc_core::{ArgShapeHash, CapabilityId, Decision, Digest};
use pc_policy::{Explained, PolicyEngine, PolicyRequest};
use pc_proto_mcp::{Message, NegotiationOutcome, ProtocolVersion, version};
use serde_json::Value;

use crate::auth::{AuthContext, Authenticator};
use crate::breaker::CircuitBreakers;
use crate::limits::RateLimiter;
use crate::metrics::{Metrics, Outcome};
use crate::session::SessionSigner;
use crate::upstream::UpstreamPool;

/// A background audit writer. The hot path only sends events over a channel; a
/// dedicated thread owns the file and appends to the hash chain, so audit I/O
/// never blocks request handling (keeping the §6 latency budget intact).
#[derive(Clone)]
pub struct AuditSink {
    tx: std::sync::mpsc::Sender<AuditEvent>,
}

impl std::fmt::Debug for AuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditSink").finish_non_exhaustive()
    }
}

impl AuditSink {
    /// Spawn the background writer around an opened audit log.
    #[must_use]
    pub fn spawn(mut log: FileAuditLog) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<AuditEvent>();
        std::thread::spawn(move || {
            while let Ok(event) = rx.recv() {
                if let Err(e) = log.append(event) {
                    tracing::error!(error = %e, "audit append failed");
                }
            }
        });
        Self { tx }
    }

    /// Record an event. Never blocks; a full/closed channel drops the event with
    /// a log line rather than stalling the request.
    pub fn record(&self, event: AuditEvent) {
        if self.tx.send(event).is_err() {
            tracing::error!("audit sink closed; event dropped");
        }
    }
}

/// Shared, cheaply-clonable handle to the gateway's collaborators.
#[derive(Clone, Debug)]
pub struct Gateway {
    auth: Arc<Authenticator>,
    upstreams: Arc<UpstreamPool>,
    sessions: Arc<SessionSigner>,
    policy: Option<Arc<Mutex<PolicyEngine>>>,
    limiter: Option<Arc<RateLimiter>>,
    breakers: Option<Arc<CircuitBreakers>>,
    audit: Option<AuditSink>,
    // Metrics are always on and local-only (Directive #8).
    metrics: Arc<Metrics>,
}

impl Gateway {
    #[must_use]
    pub fn new(auth: Authenticator, upstreams: UpstreamPool, sessions: SessionSigner) -> Self {
        Self {
            auth: Arc::new(auth),
            upstreams: Arc::new(upstreams),
            sessions: Arc::new(sessions),
            policy: None,
            limiter: None,
            breakers: None,
            audit: None,
            metrics: Arc::new(Metrics::new()),
        }
    }

    /// The per-tenant metrics registry (local export only).
    #[must_use]
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Record a request outcome for accounting.
    pub fn record_outcome(&self, tenant: &str, outcome: Outcome) {
        self.metrics.record(tenant, outcome);
    }

    #[must_use]
    pub fn with_policy(mut self, engine: PolicyEngine) -> Self {
        self.policy = Some(Arc::new(Mutex::new(engine)));
        self
    }

    #[must_use]
    pub fn with_rate_limiter(mut self, limiter: RateLimiter) -> Self {
        self.limiter = Some(Arc::new(limiter));
        self
    }

    #[must_use]
    pub fn with_breakers(mut self, breakers: CircuitBreakers) -> Self {
        self.breakers = Some(Arc::new(breakers));
        self
    }

    #[must_use]
    pub fn with_audit(mut self, sink: AuditSink) -> Self {
        self.audit = Some(sink);
        self
    }

    #[must_use]
    pub fn auth(&self) -> &Authenticator {
        &self.auth
    }

    #[must_use]
    pub fn upstreams(&self) -> &UpstreamPool {
        &self.upstreams
    }

    #[must_use]
    pub fn sessions(&self) -> &SessionSigner {
        &self.sessions
    }

    /// Perform protocol-version negotiation if this message is an `initialize`
    /// request. Returns `None` for every other message.
    #[must_use]
    pub fn negotiate(&self, msg: &Message) -> Option<NegotiationOutcome> {
        let Message::Request(req) = msg else {
            return None;
        };
        let requested = req.initialize_protocol_version()?;
        Some(version::negotiate(&requested))
    }

    /// The capability a message targets: the tool name for `tools/call`,
    /// otherwise the method. Responses have none.
    #[must_use]
    pub fn capability_of(&self, msg: &Message) -> Option<CapabilityId> {
        let method = msg.method()?;
        if method == "tools/call"
            && let Message::Request(req) = msg
            && let Some(params) = &req.params
            && let Ok(v) = serde_json::from_str::<Value>(params.get())
            && let Some(name) = v.get("name").and_then(Value::as_str)
        {
            return Some(CapabilityId::new(name));
        }
        Some(CapabilityId::new(method))
    }

    /// Whether any decision-path enforcement is configured. When false, the
    /// handler skips capability/arg-shape extraction entirely and the hot path
    /// stays at M0 passthrough cost.
    #[must_use]
    pub fn enforcement_active(&self) -> bool {
        self.policy.is_some() || self.limiter.is_some() || self.breakers.is_some()
    }

    /// The M2 authorization decision. With no policy configured this is
    /// allow-all (M0/M1 behaviour); with a policy it evaluates fail-closed and
    /// consults the decision cache. The argument shape is computed only when a
    /// policy is present, so unauthorized fast paths never pay for it.
    #[must_use]
    pub fn authorize(
        &self,
        ctx: &AuthContext,
        capability: &CapabilityId,
        chain_depth: usize,
        msg: &Message,
    ) -> Explained {
        let Some(policy) = &self.policy else {
            return Explained {
                decision: Decision::Allow,
                matched_rule: None,
                reason: "no policy configured (allow)".to_string(),
            };
        };
        let arg_shape = message_arg_shape(msg);
        let req = PolicyRequest {
            tenant: &ctx.tenant,
            principal: &ctx.principal,
            roles: &ctx.roles,
            attributes: &ctx.attributes,
            capability,
            chain_depth,
            arg_shape,
        };
        policy.lock().expect("policy lock poisoned").decide(&req)
    }

    /// Whether the rate limiter admits this (tenant, principal, capability). True
    /// when no limiter is configured.
    #[must_use]
    pub fn rate_limit_allow(&self, ctx: &AuthContext, capability: &CapabilityId) -> bool {
        let Some(limiter) = &self.limiter else {
            return true;
        };
        let key = format!(
            "{}|{}|{}",
            ctx.tenant.as_str(),
            ctx.principal.id.as_str(),
            capability.as_str()
        );
        limiter.allow(&key, now_ms())
    }

    /// Whether the circuit breaker admits a call to `upstream`.
    #[must_use]
    pub fn breaker_allow(&self, upstream: &str) -> bool {
        self.breakers
            .as_ref()
            .is_none_or(|b| b.allow(upstream, now_ms()))
    }

    /// Record the outcome of an upstream call for the circuit breaker.
    pub fn breaker_record(&self, upstream: &str, success: bool) {
        if let Some(b) = &self.breakers {
            b.record(upstream, success, now_ms());
        }
    }

    /// Emit an audit event if an audit sink is configured.
    pub fn audit(&self, event: AuditEvent) {
        if let Some(sink) = &self.audit {
            sink.record(event);
        }
    }

    #[must_use]
    pub fn has_audit(&self) -> bool {
        self.audit.is_some()
    }
}

/// Compute a hash of an argument object's *shape* - its keys and value types,
/// recursively - never its values. Used as part of the decision-cache key so
/// the cache neither depends on nor leaks argument contents (CLAUDE.md §5 row
/// #1).
#[must_use]
pub fn arg_shape_hash(params: &[u8]) -> ArgShapeHash {
    let skeleton = match serde_json::from_slice::<Value>(params) {
        Ok(value) => type_skeleton(&value),
        Err(_) => "invalid".to_string(),
    };
    ArgShapeHash::new(Digest::of(skeleton.as_bytes()))
}

/// The argument shape of a request message (for `tools/call`, its params).
#[must_use]
pub fn message_arg_shape(msg: &Message) -> ArgShapeHash {
    if let Message::Request(req) = msg
        && let Some(params) = &req.params
    {
        return arg_shape_hash(params.get().as_bytes());
    }
    arg_shape_hash(b"null")
}

fn type_skeleton(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(_) => "bool".to_string(),
        Value::Number(_) => "number".to_string(),
        Value::String(_) => "string".to_string(),
        Value::Array(items) => {
            let mut shapes: Vec<String> = items.iter().map(type_skeleton).collect();
            shapes.sort();
            shapes.dedup();
            format!("[{}]", shapes.join(","))
        }
        Value::Object(map) => {
            let mut entries: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{k}:{}", type_skeleton(v)))
                .collect();
            entries.sort();
            format!("{{{}}}", entries.join(","))
        }
    }
}

/// A monotonic-ish millisecond clock for limiter/breaker bookkeeping.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Current Unix seconds, for audit timestamps.
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Build an audit event from the request context and decision.
#[must_use]
pub fn audit_event(
    request_id: &str,
    ctx: &AuthContext,
    capability: Option<&CapabilityId>,
    method: &str,
    decision: &str,
) -> AuditEvent {
    AuditEvent {
        request_id: request_id.to_string(),
        tenant: ctx.tenant.as_str().to_string(),
        principal: ctx.principal.id.as_str().to_string(),
        capability: capability.map(|c| c.as_str().to_string()),
        method: method.to_string(),
        decision: decision.to_string(),
        detail: Value::Null,
    }
}

/// The negotiated version to advertise for a fresh session (diagnostics).
#[must_use]
pub fn default_protocol() -> ProtocolVersion {
    version::latest()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_core::TenantId;
    use std::collections::BTreeMap;

    #[test]
    fn arg_shape_ignores_values_but_not_structure() {
        let a = arg_shape_hash(br#"{"msg":"hello","count":1}"#);
        let b = arg_shape_hash(br#"{"msg":"totally different","count":999}"#);
        assert_eq!(a, b);
        let c = arg_shape_hash(br#"{"msg":"hello","count":"1"}"#);
        assert_ne!(a, c);
    }

    #[test]
    fn arg_shape_is_independent_of_key_order() {
        let a = arg_shape_hash(br#"{"a":1,"b":"x"}"#);
        let b = arg_shape_hash(br#"{"b":"y","a":2}"#);
        assert_eq!(a, b);
    }

    #[test]
    fn capability_of_uses_tool_name_for_tools_call() {
        let g = tiny_gateway();
        let msg = Message::parse(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"github.create_issue","arguments":{}}}"#,
        )
        .unwrap();
        assert_eq!(
            g.capability_of(&msg).unwrap().as_str(),
            "github.create_issue"
        );
    }

    #[test]
    fn capability_of_uses_method_otherwise() {
        let g = tiny_gateway();
        let msg = Message::parse(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).unwrap();
        assert_eq!(g.capability_of(&msg).unwrap().as_str(), "tools/list");
    }

    fn tiny_gateway() -> Gateway {
        use crate::auth::{AuthContext, Authenticator};
        use crate::session::SessionSigner;
        use crate::upstream::UpstreamPool;
        use pc_core::{Principal, PrincipalId, PrincipalKind};

        let ctx = AuthContext {
            tenant: TenantId::new("t").unwrap(),
            principal: Principal::new(PrincipalId::new("p"), PrincipalKind::Pat),
            upstream: "u".into(),
            roles: vec![],
            attributes: BTreeMap::new(),
        };
        Gateway::new(
            Authenticator::with_static_context("tok", ctx),
            UpstreamPool::from_config(&[]).unwrap(),
            SessionSigner::ephemeral(),
        )
    }
}
