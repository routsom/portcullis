//! `portcullis doctor`: diagnose config, connectivity, sandbox availability, and
//! clock skew in one command (CLAUDE.md §5 row #8).
//!
//! Checks are either `Ok`, `Warn` (non-fatal), or `Fail` (fatal). The command
//! exits non-zero only if a check fails.

use std::time::{Duration, SystemTime};

use pc_edge::GatewayConfig;
use reqwest::header;

use crate::config::Loaded;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Level {
    Ok,
    Warn,
    Fail,
}

struct Check {
    level: Level,
    name: &'static str,
    detail: String,
}

impl Check {
    fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            level: Level::Ok,
            name,
            detail: detail.into(),
        }
    }
    fn warn(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            level: Level::Warn,
            name,
            detail: detail.into(),
        }
    }
    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            level: Level::Fail,
            name,
            detail: detail.into(),
        }
    }
}

/// Run all checks. Returns `true` if healthy (no failures).
pub async fn run(loaded: &Loaded) -> bool {
    let cfg = &loaded.config;
    let mut checks = Vec::new();

    checks.push(Check::ok(
        "config",
        format!("parsed {}", loaded.path.display()),
    ));
    if !loaded.unknown_keys.is_empty() {
        checks.push(Check::warn(
            "config",
            format!("{} unknown key(s) ignored", loaded.unknown_keys.len()),
        ));
    }

    checks.push(transports_check(cfg));
    checks.push(auth_check(cfg));
    checks.extend(session_check(cfg));
    checks.extend(upstream_checks(cfg).await);
    checks.push(sandbox_check());

    let mut healthy = true;
    println!("portcullis doctor");
    for c in &checks {
        let (tag, marker) = match c.level {
            Level::Ok => ("OK  ", "✓"),
            Level::Warn => ("WARN", "!"),
            Level::Fail => {
                healthy = false;
                ("FAIL", "✗")
            }
        };
        println!("  {marker} [{tag}] {:<10} {}", c.name, c.detail);
    }
    println!(
        "\n{}",
        if healthy {
            "healthy (warnings are non-fatal)"
        } else {
            "unhealthy: fix FAIL items above"
        }
    );
    healthy
}

fn transports_check(cfg: &GatewayConfig) -> Check {
    match (&cfg.server.http, &cfg.server.stdio) {
        (None, None) => Check::fail(
            "transport",
            "no listener enabled; configure [server.http] and/or [server.stdio]",
        ),
        (http, stdio) => {
            let mut enabled = Vec::new();
            if http.is_some() {
                enabled.push("http");
            }
            if stdio.is_some() {
                enabled.push("stdio");
            }
            Check::ok("transport", format!("enabled: {}", enabled.join(", ")))
        }
    }
}

fn auth_check(cfg: &GatewayConfig) -> Check {
    if cfg.server.http.is_some() && cfg.auth.tokens.is_empty() {
        return Check::warn(
            "auth",
            "http enabled with no tokens: every request will be rejected",
        );
    }
    let mut missing = Vec::new();
    for t in &cfg.auth.tokens {
        if std::env::var(&t.token_env).is_err() {
            missing.push(t.token_env.clone());
        }
    }
    if missing.is_empty() {
        Check::ok(
            "auth",
            format!("{} principal token(s) resolved", cfg.auth.tokens.len()),
        )
    } else {
        Check::fail(
            "auth",
            format!("token env var(s) not set: {}", missing.join(", ")),
        )
    }
}

fn session_check(cfg: &GatewayConfig) -> Vec<Check> {
    match &cfg.session.secret_env {
        Some(var) if std::env::var(var).is_ok() => {
            vec![Check::ok(
                "session",
                format!("shared signing key from {var}"),
            )]
        }
        Some(var) => vec![Check::fail(
            "session",
            format!("session.secret_env {var} is not set"),
        )],
        None => vec![Check::warn(
            "session",
            "ephemeral signing key (single-node only; set session.secret_env for HA)",
        )],
    }
}

async fn upstream_checks(cfg: &GatewayConfig) -> Vec<Check> {
    if cfg.upstream.is_empty() {
        return vec![Check::warn("upstream", "no upstreams configured")];
    }
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(c) => c,
        Err(e) => return vec![Check::warn("upstream", format!("client init failed: {e}"))],
    };

    let mut checks = Vec::new();
    for up in &cfg.upstream {
        // A reachable MCP endpoint need not answer GET with 200; any HTTP
        // response proves connectivity. Also sample the Date header for skew.
        match client.get(&up.url).send().await {
            Ok(resp) => {
                checks.push(Check::ok(
                    "upstream",
                    format!("{} reachable ({})", up.name, resp.status()),
                ));
                if let Some(skew) = clock_skew(&resp) {
                    let check = if skew > Duration::from_secs(5) {
                        Check::warn(
                            "clock",
                            format!("{} skew ~{}s vs upstream", up.name, skew.as_secs()),
                        )
                    } else {
                        Check::ok("clock", format!("skew ~{}s vs {}", skew.as_secs(), up.name))
                    };
                    checks.push(check);
                }
            }
            Err(_) => checks.push(Check::warn(
                "upstream",
                format!("{} not reachable at {}", up.name, up.url),
            )),
        }
    }
    checks
}

fn clock_skew(resp: &reqwest::Response) -> Option<Duration> {
    let date = resp.headers().get(header::DATE)?.to_str().ok()?;
    let upstream_time = httpdate::parse_http_date(date).ok()?;
    let now = SystemTime::now();
    now.duration_since(upstream_time)
        .or_else(|_| upstream_time.duration_since(now))
        .ok()
}

fn sandbox_check() -> Check {
    // The runner's isolation backends (namespaces, seccomp, landlock) are
    // Linux-only and arrive in M1. Report availability without failing.
    if cfg!(target_os = "linux") {
        Check::ok(
            "sandbox",
            "Linux host: isolation backends available (runner lands in M1)",
        )
    } else {
        Check::warn(
            "sandbox",
            "non-Linux host: sandboxed execution unavailable (M1 requires Linux namespaces)",
        )
    }
}
