//! Load-time translation of OpenAPI operations into capabilities.

use pc_catalog::ToolDefinition;
use serde_json::{Map, Value, json};

use crate::spec::{OpenApiDoc, Operation, SUPPORTED_METHODS};

/// Where an argument is placed when building the upstream HTTP request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamLocation {
    Path,
    Query,
    Header,
}

/// How to build the upstream HTTP request for a translated operation.
#[derive(Clone, Debug)]
pub struct HttpBinding {
    /// Upper-case HTTP method, e.g. `GET`.
    pub method: String,
    /// Path template with `{param}` placeholders, e.g. `/pets/{petId}`.
    pub path_template: String,
    /// Named parameters and where each goes.
    pub params: Vec<(String, ParamLocation)>,
    /// Whether the operation takes a JSON request body (argument key `body`).
    pub has_body: bool,
}

/// A translated capability: its tool definition (for the catalog, policy, and
/// poison scanning) plus the binding used to invoke it.
#[derive(Clone, Debug)]
pub struct Capability {
    pub definition: ToolDefinition,
    pub binding: HttpBinding,
}

/// Errors from translation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TranslateError {
    #[error("OpenAPI document declares no supported operations")]
    Empty,
}

/// Translate an OpenAPI document into a capability table. Unsupported HTTP
/// methods are skipped. Fails only if nothing translatable remains.
pub fn translate(doc: &OpenApiDoc) -> Result<Vec<Capability>, TranslateError> {
    let mut caps = Vec::new();
    for (path, item) in &doc.paths {
        for (method, op) in &item.operations {
            let method_lc = method.to_ascii_lowercase();
            if !SUPPORTED_METHODS.contains(&method_lc.as_str()) {
                continue;
            }
            caps.push(translate_op(path, &method_lc, op));
        }
    }
    if caps.is_empty() {
        return Err(TranslateError::Empty);
    }
    Ok(caps)
}

fn translate_op(path: &str, method: &str, op: &Operation) -> Capability {
    let name = op
        .operation_id
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| derive_name(method, path));

    let description = match (op.summary.trim(), op.description.trim()) {
        ("", "") => format!("{} {path}", method.to_ascii_uppercase()),
        (s, "") => s.to_string(),
        ("", d) => d.to_string(),
        (s, d) => format!("{s}\n\n{d}"),
    };

    // Build the argument JSON Schema and the binding side-by-side.
    let mut properties = Map::new();
    let mut required = Vec::new();
    let mut params = Vec::new();

    for p in &op.parameters {
        let location = match p.location.as_str() {
            "path" => ParamLocation::Path,
            "query" => ParamLocation::Query,
            "header" => ParamLocation::Header,
            _ => continue, // cookie params etc. are not supported
        };
        let schema = if p.schema.is_null() {
            json!({ "description": p.description })
        } else {
            p.schema.clone()
        };
        properties.insert(p.name.clone(), schema);
        // Path parameters are always required by construction.
        if p.required || location == ParamLocation::Path {
            required.push(Value::String(p.name.clone()));
        }
        params.push((p.name.clone(), location));
    }

    let has_body = op
        .request_body
        .as_ref()
        .is_some_and(|b| b.content.contains_key("application/json"));
    if has_body {
        let body = op
            .request_body
            .as_ref()
            .and_then(|b| b.content.get("application/json").map(|m| m.schema.clone()));
        properties.insert("body".to_string(), body.unwrap_or(Value::Null));
        if op.request_body.as_ref().is_some_and(|b| b.required) {
            required.push(Value::String("body".to_string()));
        }
    }

    let input_schema = json!({
        "type": "object",
        "properties": Value::Object(properties),
        "required": Value::Array(required),
    });

    let mut definition = ToolDefinition {
        name,
        description,
        input_schema,
        annotations: std::collections::BTreeMap::new(),
    };
    definition
        .annotations
        .insert("x-http-method".into(), json!(method.to_ascii_uppercase()));
    definition
        .annotations
        .insert("x-http-path".into(), json!(path));

    Capability {
        definition,
        binding: HttpBinding {
            method: method.to_ascii_uppercase(),
            path_template: path.to_string(),
            params,
            has_body,
        },
    }
}

/// Derive a tool name from method + path when no `operationId` is given, e.g.
/// `GET /pets/{petId}` -> `get_pets_petId`.
fn derive_name(method: &str, path: &str) -> String {
    let mut name = String::from(method);
    let mut prev_us = false;
    for ch in path.chars() {
        if ch.is_ascii_alphanumeric() {
            name.push(ch);
            prev_us = false;
        } else if !prev_us {
            name.push('_');
            prev_us = true;
        }
    }
    name.trim_end_matches('_').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PETSTORE: &str = r#"{
      "openapi":"3.0.0",
      "info":{"title":"Petstore","version":"1.0"},
      "paths":{
        "/pets":{
          "get":{"operationId":"listPets","summary":"List pets",
                 "parameters":[{"name":"limit","in":"query","required":false,"schema":{"type":"integer"}}]},
          "post":{"operationId":"createPet","summary":"Create a pet",
                  "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object"}}}}}
        },
        "/pets/{petId}":{
          "get":{"summary":"Get a pet",
                 "parameters":[{"name":"petId","in":"path","required":true,"schema":{"type":"string"}}]},
          "trace":{"summary":"unsupported"}
        }
      }
    }"#;

    fn caps() -> Vec<Capability> {
        let doc = OpenApiDoc::from_json(PETSTORE).unwrap();
        translate(&doc).unwrap()
    }

    #[test]
    fn translates_each_supported_operation() {
        let caps = caps();
        let names: Vec<&str> = caps.iter().map(|c| c.definition.name.as_str()).collect();
        assert!(names.contains(&"listPets"));
        assert!(names.contains(&"createPet"));
        // TRACE is unsupported and skipped; the get on /pets/{petId} is derived.
        assert!(names.contains(&"get_pets_petId"));
        assert_eq!(caps.len(), 3);
    }

    #[test]
    fn path_params_are_required_and_bound() {
        let caps = caps();
        let get_pet = caps
            .iter()
            .find(|c| c.definition.name == "get_pets_petId")
            .unwrap();
        assert_eq!(get_pet.binding.method, "GET");
        assert_eq!(
            get_pet.binding.params,
            vec![("petId".to_string(), ParamLocation::Path)]
        );
        let required = &get_pet.definition.input_schema["required"];
        assert_eq!(required[0], "petId");
    }

    #[test]
    fn request_body_becomes_a_body_argument() {
        let caps = caps();
        let create = caps
            .iter()
            .find(|c| c.definition.name == "createPet")
            .unwrap();
        assert!(create.binding.has_body);
        assert!(create.definition.input_schema["properties"]["body"].is_object());
        assert_eq!(create.definition.input_schema["required"][0], "body");
    }

    #[test]
    fn empty_document_is_an_error() {
        let doc = OpenApiDoc::from_json(r#"{"openapi":"3.0.0","paths":{}}"#).unwrap();
        assert!(matches!(translate(&doc), Err(TranslateError::Empty)));
    }
}
