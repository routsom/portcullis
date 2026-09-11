//! A tiny glob matcher for capability ids (e.g. `github.*`, `*.read`).
//!
//! Only `*` is special, matching any run of characters (including none). This is
//! deliberately minimal: capability matching must be predictable and fast, not a
//! full regex engine.

/// Returns whether `pattern` (with `*` wildcards) matches `text`.
#[must_use]
pub fn matches(pattern: &str, text: &str) -> bool {
    // Classic two-pointer glob match with backtracking on the last `*`.
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn literal_matches_exactly() {
        assert!(matches("github.create_issue", "github.create_issue"));
        assert!(!matches("github.create_issue", "github.delete_issue"));
    }

    #[test]
    fn star_matches_prefix_namespace() {
        assert!(matches("github.*", "github.create_issue"));
        assert!(matches("github.*", "github."));
        assert!(!matches("github.*", "gitlab.create_issue"));
    }

    #[test]
    fn star_matches_suffix_and_middle() {
        assert!(matches("*.read", "files.read"));
        assert!(matches("a*z", "abcz"));
        assert!(matches("*", "anything"));
        assert!(matches("*", ""));
    }

    #[test]
    fn multiple_stars() {
        assert!(matches("*.*.read", "svc.files.read"));
        assert!(!matches("*.*.read", "files.read"));
    }
}
