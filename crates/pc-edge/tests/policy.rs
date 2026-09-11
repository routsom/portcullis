//! End-to-end enforcement of the M2 decision path: policy denial and rate
//! limiting are applied to live requests through the gateway (CLAUDE.md §5 rows
//! #11, §2 fail-closed).

mod common;

use pc_edge::limits::RateLimiter;
use pc_policy::{Effect, Matcher, PolicyEngine, Rule};

fn tools_call(id: u32, name: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}","arguments":{{}}}}}}"#
    )
}

#[tokio::test]
async fn policy_denies_forbidden_capability_but_allows_others() {
    // Deny anything matching `secret.*`; allow everything else.
    let rules = vec![
        Rule {
            id: "deny-secrets".into(),
            effect: Effect::Deny,
            matcher: Matcher {
                capabilities: vec!["secret.*".into()],
                ..Default::default()
            },
            reason: "secret tools are forbidden".into(),
        },
        Rule {
            id: "allow-rest".into(),
            effect: Effect::Allow,
            matcher: Matcher::default(),
            reason: String::new(),
        },
    ];
    let h = common::start_with(move |g| g.with_policy(PolicyEngine::new(rules, 64))).await;

    // Allowed capability relays (200).
    let ok = h
        .client
        .post(&h.gateway_url)
        .bearer_auth(&h.token)
        .header("content-type", "application/json")
        .body(tools_call(1, "public.echo"))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    // Forbidden capability is denied (403) before reaching the upstream.
    let denied = h
        .client
        .post(&h.gateway_url)
        .bearer_auth(&h.token)
        .header("content-type", "application/json")
        .body(tools_call(2, "secret.exfiltrate"))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
}

#[tokio::test]
async fn rate_limiter_returns_429_after_burst() {
    // Capacity 2, no refill: the third call in a burst is rejected.
    let h = common::start_with(|g| g.with_rate_limiter(RateLimiter::new(2.0, 0.0))).await;

    let call = || {
        h.client
            .post(&h.gateway_url)
            .bearer_auth(&h.token)
            .header("content-type", "application/json")
            .body(tools_call(1, "tool.a"))
            .send()
    };

    assert_eq!(call().await.unwrap().status(), 200);
    assert_eq!(call().await.unwrap().status(), 200);
    assert_eq!(call().await.unwrap().status(), 429);
}

#[tokio::test]
async fn no_policy_configured_allows_everything() {
    // The default harness attaches no policy: behaviour is allow-all once authed.
    let h = common::start().await;
    let resp = h
        .client
        .post(&h.gateway_url)
        .bearer_auth(&h.token)
        .header("content-type", "application/json")
        .body(tools_call(1, "anything.at.all"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}
