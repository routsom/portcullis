//! The hash-chained, optionally-signed audit record.
//!
//! Each entry commits to the previous entry's hash, so any modification,
//! reordering, or deletion of history is detectable (CLAUDE.md §5, §8 "the audit
//! log format is a public surface"). When a signing key is configured, each hash
//! is also HMAC-signed, so an attacker who cannot read the key cannot rewrite the
//! tail into a self-consistent chain.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// The all-zero hash that precedes the first entry.
pub const GENESIS: [u8; 32] = [0u8; 32];

/// A structured audit event. Free-form `detail` is redacted before it reaches
/// here (see [`crate::redact`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub request_id: String,
    pub tenant: String,
    pub principal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    pub method: String,
    /// e.g. `allow`, `deny:no_matching_rule`, `deny:rate_limited`.
    pub decision: String,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub detail: serde_json::Value,
}

/// One committed entry in the chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    /// Unix seconds.
    pub ts: u64,
    pub event: AuditEvent,
    /// Hex of the previous entry's hash (`GENESIS` for the first).
    pub prev: String,
    /// Hex of this entry's hash.
    pub hash: String,
    /// Hex HMAC of this entry's hash, empty if the chain is unsigned.
    #[serde(default)]
    pub sig: String,
}

/// Computes the content hash of an entry's fields (everything except `hash`/`sig`).
fn compute_hash(seq: u64, ts: u64, event: &AuditEvent, prev: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prev);
    hasher.update(&seq.to_le_bytes());
    hasher.update(&ts.to_le_bytes());
    // serde_json on our own type is deterministic in field order.
    let event_bytes = serde_json::to_vec(event).expect("event serialize");
    hasher.update(&event_bytes);
    *hasher.finalize().as_bytes()
}

fn sign(key: &[u8], hash: &[u8; 32]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(hash);
    mac.finalize().into_bytes().to_vec()
}

/// Append state for a chain: the next sequence number and the previous hash.
#[derive(Clone)]
pub struct AuditChain {
    seq: u64,
    prev: [u8; 32],
    key: Option<Vec<u8>>,
}

impl std::fmt::Debug for AuditChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditChain")
            .field("next_seq", &self.seq)
            .field("signed", &self.key.is_some())
            .finish_non_exhaustive()
    }
}

impl AuditChain {
    /// Start a fresh chain from genesis. Pass `Some(key)` to sign entries.
    #[must_use]
    pub fn genesis(key: Option<Vec<u8>>) -> Self {
        Self {
            seq: 0,
            prev: GENESIS,
            key,
        }
    }

    /// Resume an existing chain after entry `last_seq` with hash `last_hash`.
    #[must_use]
    pub fn resume(last_seq: u64, last_hash: [u8; 32], key: Option<Vec<u8>>) -> Self {
        Self {
            seq: last_seq + 1,
            prev: last_hash,
            key,
        }
    }

    /// The sequence number the next appended entry will carry.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.seq
    }

    /// Commit an event at time `ts`, returning the new entry and advancing state.
    pub fn append(&mut self, event: AuditEvent, ts: u64) -> Entry {
        let hash = compute_hash(self.seq, ts, &event, &self.prev);
        let sig = self
            .key
            .as_ref()
            .map(|k| hex::encode(sign(k, &hash)))
            .unwrap_or_default();
        let entry = Entry {
            seq: self.seq,
            ts,
            event,
            prev: hex::encode(self.prev),
            hash: hex::encode(hash),
            sig,
        };
        self.seq += 1;
        self.prev = hash;
        entry
    }
}

/// Why chain verification failed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("entry {0}: sequence number is out of order")]
    Sequence(u64),
    #[error("entry {0}: prev hash does not match the previous entry")]
    BrokenLink(u64),
    #[error("entry {0}: content hash does not match (tampered)")]
    BadHash(u64),
    #[error("entry {0}: signature invalid or missing")]
    BadSignature(u64),
    #[error("entry {0}: malformed hex")]
    Malformed(u64),
}

/// Verify a full chain from genesis. If `key` is provided, signatures are
/// required and checked; otherwise signatures are ignored.
pub fn verify_chain(entries: &[Entry], key: Option<&[u8]>) -> Result<(), VerifyError> {
    let mut expected_prev = GENESIS;
    for (i, entry) in entries.iter().enumerate() {
        let seq = i as u64;
        if entry.seq != seq {
            return Err(VerifyError::Sequence(entry.seq));
        }
        let prev = decode32(&entry.prev).ok_or(VerifyError::Malformed(seq))?;
        if prev != expected_prev {
            return Err(VerifyError::BrokenLink(seq));
        }
        let recomputed = compute_hash(entry.seq, entry.ts, &entry.event, &prev);
        let stored = decode32(&entry.hash).ok_or(VerifyError::Malformed(seq))?;
        if recomputed != stored {
            return Err(VerifyError::BadHash(seq));
        }
        if let Some(k) = key {
            let expected_sig = sign(k, &recomputed);
            let presented = hex::decode(&entry.sig).map_err(|_| VerifyError::Malformed(seq))?;
            if expected_sig.len() != presented.len() || !bool::from(expected_sig.ct_eq(&presented))
            {
                return Err(VerifyError::BadSignature(seq));
            }
        }
        expected_prev = stored;
    }
    Ok(())
}

fn decode32(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: &str) -> AuditEvent {
        AuditEvent {
            request_id: id.to_string(),
            tenant: "acme".into(),
            principal: "agent".into(),
            capability: Some("echo".into()),
            method: "tools/call".into(),
            decision: "allow".into(),
            detail: serde_json::Value::Null,
        }
    }

    fn build(n: usize, key: Option<Vec<u8>>) -> Vec<Entry> {
        let mut chain = AuditChain::genesis(key);
        (0..n)
            .map(|i| chain.append(event(&format!("r{i}")), 1000 + i as u64))
            .collect()
    }

    #[test]
    fn valid_chain_verifies() {
        let entries = build(5, None);
        assert!(verify_chain(&entries, None).is_ok());
    }

    #[test]
    fn signed_chain_verifies_with_key() {
        let key = b"chain-key".to_vec();
        let entries = build(5, Some(key.clone()));
        assert!(verify_chain(&entries, Some(&key)).is_ok());
    }

    #[test]
    fn tampering_with_an_event_is_detected() {
        let mut entries = build(4, None);
        entries[2].event.decision = "deny:tampered".into();
        assert_eq!(verify_chain(&entries, None), Err(VerifyError::BadHash(2)));
    }

    #[test]
    fn deleting_an_entry_breaks_the_chain() {
        let mut entries = build(4, None);
        entries.remove(1);
        // Sequence numbers now skip, caught immediately.
        assert!(matches!(
            verify_chain(&entries, None),
            Err(VerifyError::Sequence(_))
        ));
    }

    #[test]
    fn forged_tail_without_key_fails_signature_check() {
        let key = b"real-key".to_vec();
        let mut entries = build(3, Some(key.clone()));
        // Attacker rewrites the last event and re-hashes, but cannot sign.
        let forged = event("evil");
        let prev = decode32(&entries[2].prev).unwrap();
        let new_hash = compute_hash(2, entries[2].ts, &forged, &prev);
        entries[2].event = forged;
        entries[2].hash = hex::encode(new_hash);
        entries[2].sig = hex::encode(sign(b"wrong-key", &new_hash));
        assert_eq!(
            verify_chain(&entries, Some(&key)),
            Err(VerifyError::BadSignature(2))
        );
    }

    #[test]
    fn resume_continues_the_chain() {
        let mut entries = build(2, None);
        let last = &entries[1];
        let mut resumed = AuditChain::resume(last.seq, decode32(&last.hash).unwrap(), None);
        entries.push(resumed.append(event("r2"), 2000));
        assert!(verify_chain(&entries, None).is_ok());
    }
}
