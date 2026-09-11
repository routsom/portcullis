//! `portcullis catalog scan`: scan an MCP tool list for poisoning signals and
//! print each tool's content hash (CLAUDE.md §5 rows #6, #7).

use std::path::Path;

use anyhow::{Context, bail};
use pc_catalog::{ToolDefinition, scan};
use serde::Deserialize;

/// Accepts either a raw array of tool definitions or an MCP `tools/list` result
/// object of the form `{ "tools": [ ... ] }`.
#[derive(Deserialize)]
#[serde(untagged)]
enum ToolsInput {
    Wrapped { tools: Vec<ToolDefinition> },
    Bare(Vec<ToolDefinition>),
}

impl ToolsInput {
    fn into_tools(self) -> Vec<ToolDefinition> {
        match self {
            ToolsInput::Wrapped { tools } | ToolsInput::Bare(tools) => tools,
        }
    }
}

/// Scan the tools in `file`. Returns `true` if all are clean (below the
/// high-risk threshold), `false` if any is high-risk.
pub fn scan_file(file: &Path) -> anyhow::Result<bool> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let input: ToolsInput =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", file.display()))?;
    let tools = input.into_tools();
    if tools.is_empty() {
        bail!("no tools found in {}", file.display());
    }

    let mut all_clean = true;
    println!("catalog scan: {} tool(s)\n", tools.len());
    for tool in &tools {
        let report = scan(&tool.description);
        let hash = tool.content_hash();
        let marker = if report.is_high_risk() {
            all_clean = false;
            "HIGH-RISK"
        } else if report.score > 0 {
            "review"
        } else {
            "ok"
        };
        println!(
            "  [{marker:<9}] {:<32} score={:<3} hash={}",
            tool.name,
            report.score,
            &hash.to_hex()[..16]
        );
        for finding in &report.findings {
            println!(
                "      - {:?}: {} (+{})",
                finding.kind, finding.detail, finding.weight
            );
        }
    }
    println!(
        "\n{}",
        if all_clean {
            "all tools below the high-risk threshold"
        } else {
            "one or more tools are HIGH-RISK: explicit approval required before use"
        }
    );
    Ok(all_clean)
}
