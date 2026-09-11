//! Config loading and `config explain`.
//!
//! Loading is forward-compatible: unknown keys warn and are ignored, except
//! under `--strict-config` where they are an error (CLAUDE.md §8). `explain`
//! prints the effective config together with the provenance of each notable
//! value (default / file / env / flag), which §9 requires.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use pc_edge::GatewayConfig;
use tracing::warn;

/// A successfully loaded configuration, with the keys the parser ignored.
pub struct Loaded {
    pub config: GatewayConfig,
    pub path: PathBuf,
    pub source: PathSource,
    pub raw: toml::Value,
    pub unknown_keys: Vec<String>,
}

/// Where the config path came from - used for provenance reporting.
#[derive(Clone, Copy, Debug)]
pub enum PathSource {
    Flag,
    Default,
}

/// Load and parse the config file.
pub fn load(path: &Path, source: PathSource, strict: bool) -> anyhow::Result<Loaded> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file {}", path.display()))?;

    // Parse once for provenance inspection and once into the typed config,
    // collecting any keys the typed parse ignored.
    let raw: toml::Value =
        toml::from_str(&text).with_context(|| format!("parsing {} as TOML", path.display()))?;

    let de = toml::Deserializer::new(&text);
    let mut unknown_keys = Vec::new();
    let config: GatewayConfig =
        serde_ignored::deserialize(de, |p| unknown_keys.push(p.to_string()))
            .with_context(|| format!("interpreting {}", path.display()))?;

    if !unknown_keys.is_empty() {
        if strict {
            bail!(
                "unknown config keys under --strict-config: {}",
                unknown_keys.join(", ")
            );
        }
        for key in &unknown_keys {
            warn!(key = %key, "unknown config key ignored");
        }
    }

    Ok(Loaded {
        config,
        path: path.to_path_buf(),
        source,
        raw,
        unknown_keys,
    })
}

/// Print the effective configuration and the provenance of notable values.
pub fn explain(loaded: &Loaded) -> anyhow::Result<()> {
    let cfg = &loaded.config;

    println!("# effective configuration");
    // Secrets are never in the config (only env var *names*), so this is safe to
    // print verbatim.
    let rendered = toml::to_string_pretty(cfg).context("rendering effective config")?;
    println!("{rendered}");

    println!("# provenance");
    let path_src = match loaded.source {
        PathSource::Flag => "flag",
        PathSource::Default => "default",
    };
    println!("config file       = {} ({path_src})", loaded.path.display());

    let log_src = provenance(&loaded.raw, &["telemetry", "log_level"]);
    println!(
        "telemetry.log_level = {:?} ({log_src})",
        cfg.telemetry.log_level
    );

    if let Some(http) = &cfg.server.http {
        let path_prov = provenance(&loaded.raw, &["server", "http", "path"]);
        println!("server.http.bind  = {:?} (file)", http.bind);
        println!("server.http.path  = {:?} ({path_prov})", http.path);
        println!(
            "server.http.allowed_origins = {:?} ({})",
            http.allowed_origins,
            provenance(&loaded.raw, &["server", "http", "allowed_origins"])
        );
    }

    for up in &cfg.upstream {
        println!("upstream[{}]       = {:?} (file)", up.name, up.url);
    }

    // Secret provenance: report whether each named env var is present, never the
    // value.
    for token in &cfg.auth.tokens {
        let present = std::env::var(&token.token_env).is_ok();
        println!(
            "auth principal {:?} <- env {} ({})",
            token.principal,
            token.token_env,
            if present { "set (redacted)" } else { "MISSING" }
        );
    }
    match &cfg.session.secret_env {
        Some(var) => {
            let present = std::env::var(var).is_ok();
            println!(
                "session secret    <- env {var} ({})",
                if present { "set (redacted)" } else { "MISSING" }
            );
        }
        None => println!("session secret    = ephemeral (single-node only)"),
    }

    Ok(())
}

/// Report whether a dotted key was present in the file (`file`) or came from a
/// built-in default (`default`).
fn provenance(raw: &toml::Value, path: &[&str]) -> &'static str {
    let mut cursor = raw;
    for key in path {
        match cursor.get(key) {
            Some(next) => cursor = next,
            None => return "default",
        }
    }
    "file"
}
