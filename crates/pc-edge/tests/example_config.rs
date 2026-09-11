//! The shipped example config must always parse into `GatewayConfig`, so it
//! never rots (CLAUDE.md §9).

use pc_edge::GatewayConfig;

#[test]
fn example_config_parses() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/portcullis.toml"
    );
    let text = std::fs::read_to_string(path).expect("example config exists");
    let config: GatewayConfig = toml::from_str(&text).expect("example config parses");

    // Spot-check the M2 sections are wired through.
    assert!(config.policy.is_some(), "policy section present");
    assert!(config.rate_limit.is_some(), "rate_limit present");
    assert!(config.circuit_breaker.is_some(), "circuit_breaker present");
    assert!(config.audit.is_some(), "audit present");
    assert!(config.server.http.is_some(), "http listener present");
}
