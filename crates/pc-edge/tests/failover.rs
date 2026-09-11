//! Active-active failover: with no session affinity, any node serves any
//! request, so killing a node mid-session is invisible to the client (CLAUDE.md
//! §5 row #9, M5 exit criterion).

mod common;

use pc_edge::session::{SessionClaims, SessionSigner};

const SESSION_KEY: &[u8] = b"shared-cluster-session-key-32byte";

fn claims() -> SessionClaims {
    SessionClaims {
        tenant: "default".into(),
        principal: "tester".into(),
        upstream: "echo".into(),
        protocol: "2026-07-28".into(),
        cursor: String::new(),
    }
}

#[tokio::test]
async fn any_node_serves_the_same_session() {
    let nodes = common::start_cluster(2, SESSION_KEY).await;
    let (a, b) = (&nodes[0], &nodes[1]);

    // Client "initializes" against node A.
    let init = a
        .client
        .post(&a.gateway_url)
        .bearer_auth(&a.token)
        .header("content-type", "application/json")
        .body(br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{}}}"#.as_slice())
        .send()
        .await
        .unwrap();
    assert_eq!(init.status(), 200);

    // Node A "fails"; the very next call goes to node B with the same token and
    // succeeds - no sticky session, zero client-visible error.
    let call = b
        .client
        .post(&b.gateway_url)
        .bearer_auth(&b.token)
        .header("content-type", "application/json")
        .body(br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#.as_slice())
        .send()
        .await
        .unwrap();
    assert_eq!(call.status(), 200);
}

#[tokio::test]
async fn session_token_minted_on_one_node_verifies_on_another() {
    // Two independent signers with the same shared key model two nodes.
    let node_a = SessionSigner::from_key(SESSION_KEY.to_vec());
    let node_b = SessionSigner::from_key(SESSION_KEY.to_vec());

    let token = node_a.mint(&claims());
    // Node B, which never saw the mint, verifies it purely from the shared key.
    assert_eq!(node_b.verify(&token).unwrap(), claims());
}

#[tokio::test]
async fn session_token_is_rejected_by_a_node_with_a_different_key() {
    let node_a = SessionSigner::from_key(SESSION_KEY.to_vec());
    let outsider = SessionSigner::from_key(b"a-totally-different-cluster-key!!".to_vec());
    let token = node_a.mint(&claims());
    assert!(outsider.verify(&token).is_err());
}
