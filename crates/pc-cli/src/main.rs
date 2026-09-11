//! The `portcullis` command-line interface.
//!
//! `anyhow` is permitted here (CLAUDE.md §11); library crates use typed errors.

mod catalog;
mod config;
mod doctor;
mod translate;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use config::PathSource;

const DEFAULT_CONFIG: &str = "portcullis.toml";

#[derive(Parser)]
#[command(
    name = "portcullis",
    version,
    about = "An MCP gateway you can put in front of untrusted tools."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the gateway.
    Serve(ConfigArgs),
    /// Diagnose config, connectivity, sandbox availability, and clock skew.
    Doctor(ConfigArgs),
    /// Inspect configuration.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Inspect capability manifests and scan tool descriptions.
    #[command(subcommand)]
    Catalog(CatalogCmd),
    /// Translate other protocols (OpenAPI) into a capability table.
    #[command(subcommand)]
    Translate(TranslateCmd),
}

#[derive(Subcommand)]
enum TranslateCmd {
    /// Translate an OpenAPI 3 document into a capability table.
    Openapi {
        /// Path to the OpenAPI JSON document.
        #[arg(short, long)]
        file: PathBuf,
        /// Optionally show what the facade would surface for this query.
        #[arg(long)]
        find: Option<String>,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Print the effective config with the provenance of every value.
    Explain(ConfigArgs),
}

#[derive(Subcommand)]
enum CatalogCmd {
    /// Scan an MCP tool list (JSON) for poisoning signals; exits non-zero if any
    /// tool is high-risk.
    Scan {
        /// Path to a JSON file: a tools array or a `tools/list` result object.
        #[arg(short, long)]
        file: PathBuf,
    },
}

#[derive(clap::Args)]
struct ConfigArgs {
    /// Path to the TOML config file.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Treat unknown config keys as errors.
    #[arg(long)]
    strict_config: bool,
}

impl ConfigArgs {
    fn resolve(&self) -> (PathBuf, PathSource) {
        match &self.config {
            Some(p) => (p.clone(), PathSource::Flag),
            None => (PathBuf::from(DEFAULT_CONFIG), PathSource::Default),
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            // Render the full error chain for operators.
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    match cli.command {
        Command::Serve(args) => serve(&args),
        Command::Doctor(args) => doctor_cmd(&args),
        Command::Config(ConfigCmd::Explain(args)) => {
            init_tracing("warn");
            let (path, source) = args.resolve();
            let loaded = config::load(&path, source, args.strict_config)?;
            config::explain(&loaded)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Catalog(CatalogCmd::Scan { file }) => {
            init_tracing("warn");
            let clean = catalog::scan_file(&file)?;
            Ok(if clean {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Command::Translate(TranslateCmd::Openapi { file, find }) => {
            init_tracing("warn");
            translate::openapi(&file, find.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn serve(args: &ConfigArgs) -> anyhow::Result<ExitCode> {
    let (path, source) = args.resolve();
    // Load before starting the runtime so a config error exits cleanly.
    let loaded = config::load(&path, source, args.strict_config)?;
    init_tracing(&loaded.config.telemetry.log_level);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    runtime.block_on(async move {
        pc_edge::serve(loaded.config)
            .await
            .context("gateway exited with an error")
    })?;
    Ok(ExitCode::SUCCESS)
}

fn doctor_cmd(args: &ConfigArgs) -> anyhow::Result<ExitCode> {
    init_tracing("warn");
    let (path, source) = args.resolve();
    let loaded = config::load(&path, source, args.strict_config)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    let healthy = runtime.block_on(doctor::run(&loaded));
    Ok(if healthy {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Initialise local-only structured logging. `RUST_LOG` overrides the config
/// level. No telemetry leaves the process (Directive #8).
fn init_tracing(default_level: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    // `try_init` so repeated calls in tests do not panic.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
