//! Build tooling and the checks that keep the Prime Directives mechanically
//! enforced rather than merely documented (CLAUDE.md §5).
//!
//! Subcommands:
//! - `deny-imports`    - `pc-edge` must never import a process-spawning API
//!   (Directive #1, §5 row #5).
//! - `check-licensing` - no license-key checks or enterprise feature gates
//!   (Directive #3, §5 row #2).
//! - `dep-graph`       - the in-repo dependency rules hold (§4).
//! - `api-diff`        - public-API diff vs the last release (M0 stub).
//! - `all`             - run every check.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

fn main() -> Result<()> {
    let task = std::env::args().nth(1).unwrap_or_default();
    let root = workspace_root();
    match task.as_str() {
        "deny-imports" => deny_imports(&root),
        "check-licensing" => check_licensing(&root),
        "dep-graph" => dep_graph(&root),
        "api-diff" => api_diff(&root),
        "all" => {
            deny_imports(&root)?;
            check_licensing(&root)?;
            dep_graph(&root)?;
            api_diff(&root)
        }
        other => {
            bail!(
                "unknown task {other:?}; expected one of: \
                 deny-imports, check-licensing, dep-graph, api-diff, all"
            );
        }
    }
}

/// The workspace root is the parent of the `xtask` crate directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent directory")
        .to_path_buf()
}

/// Directive #1: `pc-edge` has no execution surface. Forbid any process-spawning
/// import in its source.
fn deny_imports(root: &Path) -> Result<()> {
    const FORBIDDEN: &[&str] = &[
        "std::process",
        "process::Command",
        "tokio::process",
        "std::os::unix::process",
    ];
    let dir = root.join("crates/pc-edge/src");
    let mut violations = Vec::new();
    for file in rust_files(&dir)? {
        let text = std::fs::read_to_string(&file)?;
        for (lineno, line) in text.lines().enumerate() {
            // Ignore comment lines so the rule can be *described* in docs.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            for needle in FORBIDDEN {
                if line.contains(needle) {
                    violations.push(format!(
                        "{}:{}: forbidden `{needle}` in pc-edge",
                        rel(root, &file),
                        lineno + 1
                    ));
                }
            }
        }
    }
    if violations.is_empty() {
        println!("deny-imports: ok (pc-edge has no process-spawning imports)");
        Ok(())
    } else {
        for v in &violations {
            eprintln!("  {v}");
        }
        bail!(
            "deny-imports: {} violation(s) - see Directive #1",
            violations.len()
        );
    }
}

/// Directive #3: no capability is gated on a license. Forbid license-check and
/// enterprise-gate patterns anywhere in crate source.
fn check_licensing(root: &Path) -> Result<()> {
    const PATTERNS: &[&str] = &[
        "license_key",
        "licensekey",
        "check_license",
        "is_licensed",
        "enterprise_only",
        "feature = \"enterprise\"",
        "cfg(feature = \"enterprise\")",
    ];
    let mut violations = Vec::new();
    for file in rust_files(&root.join("crates"))? {
        let text = std::fs::read_to_string(&file)?;
        for (lineno, line) in text.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            for pat in PATTERNS {
                if lower.contains(&pat.to_ascii_lowercase()) {
                    violations.push(format!(
                        "{}:{}: licensing/gating pattern `{pat}`",
                        rel(root, &file),
                        lineno + 1
                    ));
                }
            }
        }
    }
    if violations.is_empty() {
        println!("check-licensing: ok (no license gating found)");
        Ok(())
    } else {
        for v in &violations {
            eprintln!("  {v}");
        }
        bail!(
            "check-licensing: {} violation(s) - see Directive #3",
            violations.len()
        );
    }
}

/// §4 dependency rule: `pc-core` depends on nothing in-repo; no in-repo cycles.
fn dep_graph(root: &Path) -> Result<()> {
    let metadata = cargo_metadata(root)?;
    let packages = metadata
        .get("packages")
        .and_then(|p| p.as_array())
        .context("cargo metadata: packages")?;

    // Map in-repo package name -> its in-repo dependency names.
    let names: Vec<String> = packages
        .iter()
        .filter(|p| is_local(p, root))
        .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();

    let mut graph: Vec<(String, Vec<String>)> = Vec::new();
    for p in packages.iter().filter(|p| is_local(p, root)) {
        let name = p
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default()
            .to_string();
        let deps: Vec<String> = p
            .get("dependencies")
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|d| d.get("name").and_then(|n| n.as_str()))
                    .filter(|d| names.iter().any(|n| n == d))
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        graph.push((name, deps));
    }

    // pc-core must have no in-repo dependencies.
    if let Some((_, deps)) = graph.iter().find(|(n, _)| n == "pc-core")
        && !deps.is_empty()
    {
        bail!("dep-graph: pc-core must not depend on in-repo crates, found {deps:?}");
    }

    // No cycles.
    if let Some(cycle) = find_cycle(&graph) {
        bail!(
            "dep-graph: dependency cycle detected: {}",
            cycle.join(" -> ")
        );
    }

    println!("dep-graph: ok ({} in-repo crates, acyclic)", graph.len());
    Ok(())
}

/// API-diff stub for M0: use `cargo public-api` if present, otherwise report
/// that the baseline is not yet established and succeed (CLAUDE.md §8,
/// documented behaviour). Wired into `just check` so the command exists from
/// day one.
// Uniform command signature: every check returns `Result<()>` so `all` can
// chain them with `?`. This stub currently cannot fail, hence the allow.
#[allow(clippy::unnecessary_wraps)]
fn api_diff(_root: &Path) -> Result<()> {
    let available = Command::new("cargo")
        .args(["public-api", "--help"])
        .output()
        .is_ok_and(|o| o.status.success());
    if available {
        println!("api-diff: cargo-public-api present; baseline comparison runs pre-1.0");
    } else {
        println!(
            "api-diff: cargo-public-api not installed; skipping (M0 stub). \
             Install with `cargo install cargo-public-api` to enable."
        );
    }
    Ok(())
}

// --- helpers ---------------------------------------------------------------

fn cargo_metadata(root: &Path) -> Result<serde_json::Value> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(root)
        .output()
        .context("running cargo metadata")?;
    if !output.status.success() {
        bail!("cargo metadata failed");
    }
    serde_json::from_slice(&output.stdout).context("parsing cargo metadata")
}

/// A package is local if its manifest lives under the workspace root.
fn is_local(pkg: &serde_json::Value, root: &Path) -> bool {
    pkg.get("manifest_path")
        .and_then(|m| m.as_str())
        .is_some_and(|m| Path::new(m).starts_with(root))
}

/// Depth-first cycle detection over the in-repo graph.
fn find_cycle(graph: &[(String, Vec<String>)]) -> Option<Vec<String>> {
    fn visit<'a>(
        node: &'a str,
        graph: &'a [(String, Vec<String>)],
        stack: &mut Vec<String>,
        done: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        if stack.iter().any(|n| n == node) {
            let mut cycle = stack.clone();
            cycle.push(node.to_string());
            return Some(cycle);
        }
        if done.iter().any(|n| n == node) {
            return None;
        }
        stack.push(node.to_string());
        if let Some((_, deps)) = graph.iter().find(|(n, _)| n == node) {
            for dep in deps {
                if let Some(c) = visit(dep, graph, stack, done) {
                    return Some(c);
                }
            }
        }
        stack.pop();
        done.push(node.to_string());
        None
    }

    let mut done = Vec::new();
    for (node, _) in graph {
        let mut stack = Vec::new();
        if let Some(cycle) = visit(node, graph, &mut stack, &mut done) {
            return Some(cycle);
        }
    }
    None
}

/// Recursively collect `.rs` files under `dir`.
fn rust_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).with_context(|| format!("reading {}", d.display()))? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    Ok(out)
}

fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}
