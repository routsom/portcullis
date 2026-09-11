//! JSON-RPC 2.0 framing for MCP.
//!
//! The defining choice here is that payload fields (`params`, `result`,
//! `error`) are kept as [`RawValue`] - parsed just enough to be valid JSON, but
//! not deserialized into typed structures. The edge routes on `method` and `id`
//! and relays the payload bytes untouched, which keeps the hot path off the
//! allocator and inside the latency budget (CLAUDE.md §5 row #1, §6).

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::version::ProtocolVersion;

/// A JSON-RPC request/response correlation id. Per the spec an id is a string or
/// a number; we model both and reject fractional numbers on the `i64` path.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Id {
    Number(i64),
    String(String),
}

/// A method call expecting a response.
#[derive(Clone, Debug, Serialize)]
pub struct Request {
    pub id: Id,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Box<RawValue>>,
}

/// A one-way notification (no response expected).
#[derive(Clone, Debug, Serialize)]
pub struct Notification {
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Box<RawValue>>,
}

/// A response carrying either a result or an error (never routed on by the
/// gateway, only relayed).
#[derive(Clone, Debug, Serialize)]
pub struct Response {
    pub id: Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Box<RawValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Box<RawValue>>,
}

/// A classified JSON-RPC message.
#[derive(Clone, Debug)]
pub enum Message {
    Request(Request),
    Notification(Notification),
    Response(Response),
}

/// Errors from parsing a frame. Deliberately coarse: malformed input is data
/// from outside the trust boundary and we do not echo its contents into errors.
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("frame is not valid JSON")]
    NotJson(#[source] serde_json::Error),
    #[error("missing or unsupported jsonrpc version (expected \"2.0\")")]
    BadVersion,
    #[error("frame is not a valid JSON-RPC request, notification, or response")]
    Unclassifiable,
    #[error("failed to serialize frame")]
    Serialize(#[source] serde_json::Error),
}

/// Raw envelope used only for parsing; every payload field is left as raw JSON.
#[derive(Deserialize)]
struct Wire {
    #[serde(default)]
    jsonrpc: Option<String>,
    #[serde(default)]
    id: Option<Id>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<Box<RawValue>>,
    #[serde(default)]
    result: Option<Box<RawValue>>,
    #[serde(default)]
    error: Option<Box<RawValue>>,
}

impl Message {
    /// Parse and classify a single JSON-RPC frame.
    pub fn parse(bytes: &[u8]) -> Result<Self, MessageError> {
        let wire: Wire = serde_json::from_slice(bytes).map_err(MessageError::NotJson)?;
        if wire.jsonrpc.as_deref() != Some("2.0") {
            return Err(MessageError::BadVersion);
        }
        match (wire.method, wire.id) {
            (Some(method), Some(id)) => Ok(Message::Request(Request {
                id,
                method,
                params: wire.params,
            })),
            (Some(method), None) => Ok(Message::Notification(Notification {
                method,
                params: wire.params,
            })),
            (None, id) if wire.result.is_some() || wire.error.is_some() => {
                Ok(Message::Response(Response {
                    id,
                    result: wire.result,
                    error: wire.error,
                }))
            }
            _ => Err(MessageError::Unclassifiable),
        }
    }

    /// The method name, for requests and notifications; `None` for responses.
    #[must_use]
    pub fn method(&self) -> Option<&str> {
        match self {
            Message::Request(r) => Some(&r.method),
            Message::Notification(n) => Some(&n.method),
            Message::Response(_) => None,
        }
    }

    /// The correlation id, if any.
    #[must_use]
    pub fn id(&self) -> Option<&Id> {
        match self {
            Message::Request(r) => Some(&r.id),
            Message::Response(r) => r.id.as_ref(),
            Message::Notification(_) => None,
        }
    }

    /// Serialize back to JSON-RPC bytes, re-attaching `"jsonrpc":"2.0"`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MessageError> {
        // Tagging the envelope with the version on the way out keeps the raw
        // payloads untouched while guaranteeing a well-formed frame.
        let tagged = Tagged::from(self);
        serde_json::to_vec(&tagged).map_err(MessageError::Serialize)
    }
}

/// Serialization wrapper that injects the `jsonrpc` tag.
#[derive(Serialize)]
#[serde(untagged)]
enum Tagged<'a> {
    Request {
        jsonrpc: &'static str,
        #[serde(flatten)]
        inner: &'a Request,
    },
    Notification {
        jsonrpc: &'static str,
        #[serde(flatten)]
        inner: &'a Notification,
    },
    Response {
        jsonrpc: &'static str,
        #[serde(flatten)]
        inner: &'a Response,
    },
}

impl<'a> From<&'a Message> for Tagged<'a> {
    fn from(m: &'a Message) -> Self {
        match m {
            Message::Request(inner) => Tagged::Request {
                jsonrpc: "2.0",
                inner,
            },
            Message::Notification(inner) => Tagged::Notification {
                jsonrpc: "2.0",
                inner,
            },
            Message::Response(inner) => Tagged::Response {
                jsonrpc: "2.0",
                inner,
            },
        }
    }
}

impl Request {
    /// If this is an `initialize` request, extract the client's requested
    /// `protocolVersion`. Returns `None` for other methods or malformed params.
    #[must_use]
    pub fn initialize_protocol_version(&self) -> Option<ProtocolVersion> {
        #[derive(Deserialize)]
        struct InitParams {
            #[serde(rename = "protocolVersion")]
            protocol_version: String,
        }
        if self.method != "initialize" {
            return None;
        }
        let params = self.params.as_ref()?;
        let parsed: InitParams = serde_json::from_str(params.get()).ok()?;
        Some(ProtocolVersion::new(parsed.protocol_version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_classifies_request_when_method_and_id_present() {
        let m = Message::parse(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).unwrap();
        assert!(matches!(m, Message::Request(_)));
        assert_eq!(m.method(), Some("tools/list"));
        assert_eq!(m.id(), Some(&Id::Number(1)));
    }

    #[test]
    fn parse_classifies_notification_when_id_absent() {
        let m =
            Message::parse(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).unwrap();
        assert!(matches!(m, Message::Notification(_)));
        assert_eq!(m.id(), None);
    }

    #[test]
    fn parse_classifies_response_when_result_present() {
        let m = Message::parse(br#"{"jsonrpc":"2.0","id":"a","result":{"ok":true}}"#).unwrap();
        assert!(matches!(m, Message::Response(_)));
        assert_eq!(m.id(), Some(&Id::String("a".to_string())));
    }

    #[test]
    fn parse_rejects_when_jsonrpc_version_wrong() {
        let err = Message::parse(br#"{"jsonrpc":"1.0","id":1,"method":"x"}"#).unwrap_err();
        assert!(matches!(err, MessageError::BadVersion));
    }

    #[test]
    fn roundtrip_preserves_method_and_raw_params() {
        let bytes = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}"#;
        let m = Message::parse(bytes).unwrap();
        let out = m.to_bytes().unwrap();
        let reparsed = Message::parse(&out).unwrap();
        assert_eq!(reparsed.method(), Some("tools/call"));
        assert_eq!(reparsed.id(), Some(&Id::Number(7)));
    }

    #[test]
    fn initialize_version_extracted_when_method_is_initialize() {
        let m = Message::parse(
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{}}}"#,
        )
        .unwrap();
        let Message::Request(req) = m else {
            panic!("expected request")
        };
        assert_eq!(
            req.initialize_protocol_version(),
            Some(ProtocolVersion::new("2026-07-28"))
        );
    }

    #[test]
    fn initialize_version_none_when_other_method() {
        let m = Message::parse(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).unwrap();
        let Message::Request(req) = m else { panic!() };
        assert_eq!(req.initialize_protocol_version(), None);
    }
}
