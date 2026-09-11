//! Property tests for frame parsing. Frames arrive from outside the trust
//! boundary, so the parser must never panic on arbitrary input (CLAUDE.md §6,
//! §11) - it either classifies a valid message or returns a typed error.

use pc_proto_mcp::Message;
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = Message::parse(&bytes);
    }

    #[test]
    fn parse_never_panics_on_arbitrary_text(s in ".{0,512}") {
        let _ = Message::parse(s.as_bytes());
    }

    #[test]
    fn well_formed_requests_roundtrip(id in 0i64..1_000_000, method in "[a-z]{1,16}/[a-z]{1,16}") {
        let frame = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}"}}"#);
        let msg = Message::parse(frame.as_bytes()).expect("valid request parses");
        prop_assert_eq!(msg.method(), Some(method.as_str()));
        // Re-serializing and re-parsing preserves the classification.
        let out = msg.to_bytes().unwrap();
        let reparsed = Message::parse(&out).unwrap();
        prop_assert_eq!(reparsed.method(), Some(method.as_str()));
    }
}
