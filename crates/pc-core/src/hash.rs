//! Content-addressing primitives.
//!
//! portcullis pins things by the hash of their full definition so that later
//! drift is detectable (the rug-pull defence, CLAUDE.md §5 row #6). The concrete
//! hashing lives here; *what* gets hashed (e.g. the canonical bytes of a tool
//! definition, or the shape of a JSON argument object) is decided by protocol
//! crates, which must not leak their wire formats into this crate.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A 256-bit BLAKE3 digest.
///
/// This is the raw primitive; prefer the semantic newtypes [`ContentHash`] and
/// [`ArgShapeHash`] at API boundaries so the meaning of a digest is not lost.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest([u8; 32]);

impl Digest {
    /// Hash `bytes` with BLAKE3.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(blake3::hash(bytes).into())
    }

    /// Construct from a raw digest produced elsewhere (e.g. read from disk).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lower-case hex rendering, used in logs, the CLI, and the audit trail.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Short prefix keeps logs readable; full value is available via `to_hex`.
        write!(f, "Digest({}…)", &self.to_hex()[..12])
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

macro_rules! semantic_digest {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Digest);

        impl $name {
            #[must_use]
            pub const fn new(digest: Digest) -> Self {
                Self(digest)
            }

            #[must_use]
            pub const fn digest(&self) -> &Digest {
                &self.0
            }

            #[must_use]
            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

semantic_digest! {
    /// The pinned hash of a capability's full definition - name, description,
    /// schema, annotations. A change to any of these changes this hash and moves
    /// the capability to [`CapabilityState::Quarantined`](crate::CapabilityState).
    ContentHash
}

semantic_digest! {
    /// The hash of an invocation's argument *shape* (keys and types), not its
    /// values. Used as part of the decision-cache key (CLAUDE.md §5 row #1) so
    /// that caching never depends on, or leaks, argument contents.
    ArgShapeHash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_of_is_stable_and_distinct() {
        assert_eq!(Digest::of(b"portcullis"), Digest::of(b"portcullis"));
        assert_ne!(Digest::of(b"a"), Digest::of(b"b"));
    }

    #[test]
    fn hex_roundtrips_through_bytes() {
        let d = Digest::of(b"payload");
        assert_eq!(Digest::from_bytes(*d.as_bytes()), d);
        assert_eq!(d.to_hex().len(), 64);
    }

    #[test]
    fn debug_is_truncated_but_display_is_full() {
        let d = Digest::of(b"x");
        assert!(format!("{d:?}").len() < d.to_string().len());
    }
}
