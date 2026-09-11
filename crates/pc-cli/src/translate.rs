//! `portcullis translate openapi`: turn an OpenAPI spec into a capability table
//! and optionally show facade token savings (CLAUDE.md §5 rows #10, #15).

use std::path::Path;

use anyhow::Context;
use pc_facade::Facade;
use pc_proto_openapi::{OpenApiDoc, translate};

/// Translate `file` and print the capability table. If `find` is set, also show
/// what the facade would surface for that query and the token comparison.
pub fn openapi(file: &Path, find: Option<&str>) -> anyhow::Result<()> {
    let json =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let doc =
        OpenApiDoc::from_json(&json).with_context(|| format!("parsing {}", file.display()))?;
    let caps = translate(&doc).context("translating OpenAPI document")?;

    println!("translated {} operation(s):\n", caps.len());
    for cap in &caps {
        let args = cap.definition.input_schema["properties"]
            .as_object()
            .map_or(0, serde_json::Map::len);
        println!(
            "  {:<28} {:<6} {:<24} {} arg(s)",
            cap.definition.name, cap.binding.method, cap.binding.path_template, args
        );
    }

    let facade = Facade::new(caps.iter().map(|c| c.definition.clone()).collect());
    if let Some(query) = find {
        println!("\nfacade.find({query:?}):");
        for hit in facade.find(query, 5) {
            println!("  [{:>2}] {}", hit.score, hit.tool.name);
        }
        let cmp = facade.token_comparison(query, 5);
        println!(
            "\ntokens: static={} facade={} saved={} ({:.0}% reduction) -> {}",
            cmp.static_tokens,
            cmp.facade_tokens,
            cmp.saved(),
            cmp.reduction_pct(),
            if cmp.facade_wins() {
                "facade recommended"
            } else {
                "static exposure recommended"
            }
        );
    }
    Ok(())
}
