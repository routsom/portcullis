//! Redaction at the boundary.
//!
//! Redaction happens here, in `pc-audit`, not at call sites (CLAUDE.md §11): a
//! caller logs a structured value and the audit layer masks any field whose key
//! is marked sensitive, recursively. This keeps the "never log a secret" rule in
//! one auditable place instead of scattered across the codebase.

use serde_json::Value;

/// The mask substituted for a redacted value.
pub const MASK: &str = "***REDACTED***";

/// Recursively replace the values of any object field whose (lower-cased) key is
/// in `sensitive` with [`MASK`]. Array elements are traversed; scalars are left
/// as-is unless their key matched at the parent object.
pub fn redact(value: &mut Value, sensitive: &[&str]) {
    match value {
        Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                if sensitive.iter().any(|s| key.eq_ignore_ascii_case(s)) {
                    *val = Value::String(MASK.to_string());
                } else {
                    redact(val, sensitive);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact(item, sensitive);
            }
        }
        _ => {}
    }
}

/// The default sensitive key set. Extend via config as new fields appear.
pub const DEFAULT_SENSITIVE: &[&str] = &[
    "authorization",
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "cookie",
    "set-cookie",
];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn masks_sensitive_keys_case_insensitively() {
        let mut v = json!({"Authorization": "Bearer abc", "user": "alice"});
        redact(&mut v, DEFAULT_SENSITIVE);
        assert_eq!(v["Authorization"], MASK);
        assert_eq!(v["user"], "alice");
    }

    #[test]
    fn masks_nested_and_in_arrays() {
        let mut v = json!({
            "items": [{"token": "t1"}, {"token": "t2"}],
            "meta": {"secret": "s", "ok": true}
        });
        redact(&mut v, DEFAULT_SENSITIVE);
        assert_eq!(v["items"][0]["token"], MASK);
        assert_eq!(v["items"][1]["token"], MASK);
        assert_eq!(v["meta"]["secret"], MASK);
        assert_eq!(v["meta"]["ok"], true);
    }

    #[test]
    fn leaves_non_sensitive_untouched() {
        let mut v = json!({"a": 1, "b": [1, 2, 3], "c": {"d": "e"}});
        let before = v.clone();
        redact(&mut v, DEFAULT_SENSITIVE);
        assert_eq!(v, before);
    }
}
