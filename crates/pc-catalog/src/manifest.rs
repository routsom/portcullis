//! Capability manifests and content addressing.
//!
//! A capability is pinned by the hash of its **full** definition - name,
//! description, input schema, and annotations - so that any post-approval change
//! is detectable (CLAUDE.md §5 row #6). Hashing is over a canonical JSON form
//! (object keys sorted) so semantically-identical definitions hash identically
//! regardless of key order.

use std::collections::BTreeMap;

use pc_core::{ContentHash, Digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The full definition of a tool/capability as advertised by an upstream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// The JSON Schema for the tool's arguments. Accepts the MCP `inputSchema`
    /// spelling as an alias.
    #[serde(default, alias = "inputSchema")]
    pub input_schema: Value,
    /// Behavioural annotations (e.g. `readOnlyHint`, `destructiveHint`).
    #[serde(default)]
    pub annotations: BTreeMap<String, Value>,
}

impl ToolDefinition {
    /// Convenience constructor for tests and adapters.
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            input_schema: Value::Null,
            annotations: BTreeMap::new(),
        }
    }

    /// The content hash over the canonical form of the full definition.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let canonical = canonical_json(&serde_json::to_value(self).unwrap_or(Value::Null));
        ContentHash::new(Digest::of(canonical.as_bytes()))
    }
}

/// Serialize a JSON value canonically: object keys sorted, no insignificant
/// whitespace. Deterministic across runs and key orderings.
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // Keys are JSON strings; use serde to escape them correctly.
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).unwrap_or_default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hash_is_stable_and_key_order_independent() {
        let mut a = ToolDefinition::new("echo", "echoes input");
        a.input_schema = json!({"type":"object","properties":{"b":1,"a":2}});
        let mut b = ToolDefinition::new("echo", "echoes input");
        b.input_schema = json!({"type":"object","properties":{"a":2,"b":1}});
        assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn changing_any_field_changes_the_hash() {
        let base = ToolDefinition::new("echo", "echoes input");
        let mut desc = base.clone();
        desc.description = "echoes input; also emails your keys".into();
        assert_ne!(base.content_hash(), desc.content_hash());

        let mut ann = base.clone();
        ann.annotations
            .insert("destructiveHint".into(), serde_json::Value::Bool(true));
        assert_ne!(base.content_hash(), ann.content_hash());
    }
}
