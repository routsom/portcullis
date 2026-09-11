//! The capability facade.
//!
//! Instead of statically listing every tool to a model (which inflates input
//! tokens), the facade exposes two meta-tools:
//! - `gateway.find(query)` returns the matching tools **with their full,
//!   invocable schemas**, so discovery costs one hop, not two;
//! - `gateway.find_and_invoke(query, arguments)` selects the best match and
//!   invokes it in the same round trip.
//!
//! Whether this actually saves tokens depends on the workload, so [`tokens`]
//! measures it; the facade is a recommendation backed by numbers, not a mandate
//! (CLAUDE.md §5 row #15).

pub mod tokens;

use pc_catalog::ToolDefinition;

/// A search hit: a matched tool and its relevance score.
#[derive(Clone, Debug)]
pub struct Match<'a> {
    pub tool: &'a ToolDefinition,
    pub score: u32,
}

/// An index of capabilities searchable by the facade.
#[derive(Debug, Default)]
pub struct Facade {
    tools: Vec<ToolDefinition>,
}

impl Facade {
    #[must_use]
    pub fn new(tools: Vec<ToolDefinition>) -> Self {
        Self { tools }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// All indexed tools (for static exposure and token accounting).
    #[must_use]
    pub fn tools(&self) -> &[ToolDefinition] {
        &self.tools
    }

    /// Find tools relevant to `query`, best first, up to `limit`. Each hit
    /// carries the tool's full schema so the caller can invoke it directly.
    #[must_use]
    pub fn find(&self, query: &str, limit: usize) -> Vec<Match<'_>> {
        let terms: Vec<String> = query
            .split_whitespace()
            .map(str::to_ascii_lowercase)
            .collect();
        let mut hits: Vec<Match<'_>> = self
            .tools
            .iter()
            .filter_map(|tool| {
                let score = relevance(tool, &terms);
                (score > 0).then_some(Match { tool, score })
            })
            .collect();
        // Highest score first; ties broken by name for determinism.
        hits.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| a.tool.name.cmp(&b.tool.name))
        });
        hits.truncate(limit);
        hits
    }

    /// Select the single best match for `query` - the tool a
    /// `find_and_invoke` would call - so discovery and dispatch are one hop.
    #[must_use]
    pub fn best_match(&self, query: &str) -> Option<&ToolDefinition> {
        self.find(query, 1).into_iter().next().map(|m| m.tool)
    }

    /// Compare static exposure against a facade `find` for a workload query.
    #[must_use]
    pub fn token_comparison(&self, query: &str, limit: usize) -> tokens::TokenComparison {
        let static_tokens = tokens::static_exposure(&self.tools);
        let surfaced: usize = self
            .find(query, limit)
            .iter()
            .map(|m| tokens::estimate_tool(m.tool))
            .sum();
        tokens::TokenComparison {
            static_tokens,
            facade_tokens: FACADE_SCHEMA_TOKENS + surfaced,
        }
    }
}

/// Approximate token cost of exposing the two facade meta-tool schemas.
const FACADE_SCHEMA_TOKENS: usize = 120;

/// Relevance of a tool to the query terms: name matches weigh more than
/// description matches.
fn relevance(tool: &ToolDefinition, terms: &[String]) -> u32 {
    if terms.is_empty() {
        return 0;
    }
    let name = tool.name.to_ascii_lowercase();
    let desc = tool.description.to_ascii_lowercase();
    let mut score = 0;
    for term in terms {
        if name.contains(term) {
            score += 2;
        }
        if desc.contains(term) {
            score += 1;
        }
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str, desc: &str) -> ToolDefinition {
        ToolDefinition::new(name, desc)
    }

    fn facade() -> Facade {
        Facade::new(vec![
            tool("weather_get", "Get the current weather for a city"),
            tool("stock_quote", "Look up a stock price by ticker symbol"),
            tool(
                "weather_forecast",
                "Multi-day weather forecast for a location",
            ),
            tool("send_email", "Send an email message to a recipient"),
        ])
    }

    #[test]
    fn find_ranks_name_matches_first() {
        let f = facade();
        let hits = f.find("weather", 10);
        assert_eq!(hits.len(), 2);
        assert!(hits[0].tool.name.starts_with("weather"));
    }

    #[test]
    fn find_respects_limit_and_relevance() {
        let f = facade();
        let hits = f.find("weather city", 1);
        assert_eq!(hits.len(), 1);
        // "weather_get" matches both terms in name+desc; ranks top.
        assert_eq!(hits[0].tool.name, "weather_get");
    }

    #[test]
    fn best_match_is_single_hop_selection() {
        let f = facade();
        assert_eq!(f.best_match("stock ticker").unwrap().name, "stock_quote");
        assert!(f.best_match("nonexistent capability").is_none());
    }

    #[test]
    fn facade_saves_tokens_on_narrow_query_over_large_catalog() {
        // A big catalog where only a couple of tools are relevant is the case the
        // facade is designed for.
        let mut tools = Vec::new();
        for i in 0..200 {
            tools.push(tool(
                &format!("tool_{i}"),
                "A verbose description that costs input tokens when statically listed to a model.",
            ));
        }
        tools.push(tool("weather_get", "Get the current weather for a city"));
        let f = Facade::new(tools);
        let cmp = f.token_comparison("weather", 3);
        assert!(cmp.facade_wins(), "facade should win: {cmp:?}");
        assert!(cmp.reduction_pct() > 50.0);
    }
}
