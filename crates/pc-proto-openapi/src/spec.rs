//! A serde model of the OpenAPI 3 subset we translate.
//!
//! Deliberately partial: only the fields the translator needs. Unknown fields
//! are ignored so real-world specs (which carry much more) still parse.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

/// A parsed OpenAPI document.
#[derive(Debug, Deserialize)]
pub struct OpenApiDoc {
    #[serde(default)]
    pub info: Info,
    /// Path templates -> operations by HTTP method.
    #[serde(default)]
    pub paths: BTreeMap<String, PathItem>,
}

impl OpenApiDoc {
    /// Parse a document from JSON.
    ///
    /// # Errors
    /// Returns a `serde_json::Error` if the JSON is not a valid OpenAPI subset.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct Info {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub version: String,
}

/// The operations available at one path, keyed by lower-case HTTP method.
#[derive(Debug, Default, Deserialize)]
pub struct PathItem {
    #[serde(flatten)]
    pub operations: BTreeMap<String, Operation>,
}

#[derive(Debug, Deserialize)]
pub struct Operation {
    // `operation_id` mirrors OpenAPI's `operationId`; the name is the spec's.
    #[allow(clippy::struct_field_names)]
    #[serde(rename = "operationId", default)]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub parameters: Vec<Parameter>,
    #[serde(rename = "requestBody", default)]
    pub request_body: Option<RequestBody>,
}

#[derive(Debug, Deserialize)]
pub struct Parameter {
    pub name: String,
    #[serde(rename = "in")]
    pub location: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub description: String,
    #[serde(default = "null_schema")]
    pub schema: Value,
}

#[derive(Debug, Deserialize)]
pub struct RequestBody {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub content: BTreeMap<String, MediaType>,
}

#[derive(Debug, Deserialize)]
pub struct MediaType {
    #[serde(default = "null_schema")]
    pub schema: Value,
}

fn null_schema() -> Value {
    Value::Null
}

/// The HTTP methods we translate (others are skipped).
pub const SUPPORTED_METHODS: &[&str] = &["get", "post", "put", "patch", "delete"];
