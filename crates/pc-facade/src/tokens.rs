//! Token accounting for the facade.
//!
//! Meta-tool indirection is only worth it if it actually reduces input tokens
//! (CLAUDE.md §5 row #15). This module estimates token counts so the CLI and the
//! token report can show real deltas per workload; if a facade does not win on a
//! workload, the tooling recommends static exposure instead.
//!
//! The estimate is a portable heuristic (~4 characters per token) rather than a
//! model-specific tokenizer; it is used for *relative* comparisons, which are
//! stable under this approximation.

use pc_catalog::ToolDefinition;

/// Estimate the token count of a string (~4 chars/token, rounded up).
#[must_use]
pub fn estimate_str(s: &str) -> usize {
    s.len().div_ceil(4)
}

/// Estimate the tokens needed to expose a single tool definition to a model
/// (its JSON serialization).
#[must_use]
pub fn estimate_tool(tool: &ToolDefinition) -> usize {
    let json = serde_json::to_string(tool).unwrap_or_default();
    estimate_str(&json)
}

/// Estimate the tokens to statically expose every tool up front.
#[must_use]
pub fn static_exposure(tools: &[ToolDefinition]) -> usize {
    tools.iter().map(estimate_tool).sum()
}

/// A comparison of static exposure vs a facade result for one workload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenComparison {
    /// Tokens to list every tool up front.
    pub static_tokens: usize,
    /// Tokens for the facade tool schema plus the tools it surfaced.
    pub facade_tokens: usize,
}

impl TokenComparison {
    /// Tokens saved by the facade (0 if the facade is not cheaper).
    #[must_use]
    pub fn saved(&self) -> usize {
        self.static_tokens.saturating_sub(self.facade_tokens)
    }

    /// Percentage reduction (0.0 if the facade is not cheaper).
    #[must_use]
    pub fn reduction_pct(&self) -> f64 {
        if self.static_tokens == 0 || self.facade_tokens >= self.static_tokens {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)] // token counts are small
        let pct = (self.saved() as f64 / self.static_tokens as f64) * 100.0;
        pct
    }

    /// Whether the facade wins on this workload.
    #[must_use]
    pub fn facade_wins(&self) -> bool {
        self.facade_tokens < self.static_tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_scales_with_length() {
        assert_eq!(estimate_str(""), 0);
        assert_eq!(estimate_str("abcd"), 1);
        assert_eq!(estimate_str("abcde"), 2);
    }

    #[test]
    fn comparison_reports_savings() {
        let c = TokenComparison {
            static_tokens: 1000,
            facade_tokens: 250,
        };
        assert_eq!(c.saved(), 750);
        assert!((c.reduction_pct() - 75.0).abs() < 0.001);
        assert!(c.facade_wins());
    }

    #[test]
    fn no_savings_when_facade_larger() {
        let c = TokenComparison {
            static_tokens: 100,
            facade_tokens: 300,
        };
        assert_eq!(c.saved(), 0);
        assert!(c.reduction_pct().abs() < 1e-9);
        assert!(!c.facade_wins());
    }
}
