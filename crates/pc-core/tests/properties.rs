//! Property tests for the core types. Anything that parses or round-trips
//! untrusted input gets a property test (CLAUDE.md §11).

use pc_core::{Digest, TenantId};
use proptest::prelude::*;

proptest! {
    #[test]
    fn tenant_id_accepts_any_non_empty_string(s in "\\PC{1,64}") {
        let t = TenantId::new(s.clone()).expect("non-empty id is valid");
        prop_assert_eq!(t.as_str(), s);
    }

    #[test]
    fn tenant_id_json_roundtrips(s in "\\PC{1,64}") {
        let t = TenantId::new(s).unwrap();
        let json = serde_json::to_string(&t).unwrap();
        let back: TenantId = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(t, back);
    }

    #[test]
    fn digest_is_deterministic_and_hex_is_64_chars(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let a = Digest::of(&bytes);
        let b = Digest::of(&bytes);
        prop_assert_eq!(a, b);
        prop_assert_eq!(a.to_hex().len(), 64);
        prop_assert_eq!(Digest::from_bytes(*a.as_bytes()), a);
    }
}
