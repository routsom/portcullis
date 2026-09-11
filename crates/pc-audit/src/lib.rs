//! portcullis audit: an append-only, hash-chained, optionally-signed audit log.
//!
//! The log is a public, versioned surface (CLAUDE.md §8). Every decision the
//! gateway makes can be recorded as an [`AuditEvent`]; entries are chained by
//! hash so tampering is detectable and, when signed, unforgeable without the
//! key. Redaction happens here at the boundary ([`redact`]), never at call
//! sites.

pub mod chain;
pub mod redact;

pub use chain::{AuditChain, AuditEvent, Entry, VerifyError, verify_chain};
pub use redact::{DEFAULT_SENSITIVE, redact};

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// A file-backed audit log writing one JSON entry per line (JSONL).
///
/// On open it loads and verifies any existing chain, then resumes appending. A
/// failed verification on open is surfaced so a tampered log cannot be silently
/// extended.
#[derive(Debug)]
pub struct FileAuditLog {
    chain: AuditChain,
    file: File,
    path: PathBuf,
}

impl FileAuditLog {
    /// Open (creating if absent) the log at `path`. Pass `Some(key)` to sign.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read/created, if an existing chain
    /// fails verification, or if the log is malformed.
    pub fn open(path: impl AsRef<Path>, key: Option<Vec<u8>>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let existing = if path.exists() {
            read_all(&path)?
        } else {
            Vec::new()
        };
        verify_chain(&existing, key.as_deref())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let chain = match existing.last() {
            Some(last) => {
                let last_hash = hex_to_32(&last.hash).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed hash")
                })?;
                AuditChain::resume(last.seq, last_hash, key)
            }
            None => AuditChain::genesis(key),
        };

        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { chain, file, path })
    }

    /// Append an event, stamping it with the current time. Flushes before
    /// returning so the entry is durable.
    ///
    /// # Errors
    /// Returns an error if the underlying write fails.
    pub fn append(&mut self, event: AuditEvent) -> std::io::Result<Entry> {
        let entry = self.chain.append(event, now_unix());
        let line = serde_json::to_string(&entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        Ok(entry)
    }

    /// The path this log writes to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Read and parse every entry from a JSONL audit file.
///
/// # Errors
/// Returns an error if the file cannot be read or a line is malformed.
pub fn read_all(path: impl AsRef<Path>) -> std::io::Result<Vec<Entry>> {
    let file = File::open(path)?;
    let mut entries = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: Entry = serde_json::from_str(&line)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Current Unix time in seconds.
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: &str) -> AuditEvent {
        AuditEvent {
            request_id: id.into(),
            tenant: "acme".into(),
            principal: "agent".into(),
            capability: Some("echo".into()),
            method: "tools/call".into(),
            decision: "allow".into(),
            detail: serde_json::Value::Null,
        }
    }

    #[test]
    fn append_persists_and_reopens_resuming_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let mut log = FileAuditLog::open(&path, None).unwrap();
            log.append(event("r0")).unwrap();
            log.append(event("r1")).unwrap();
        }
        // Reopen and continue.
        {
            let mut log = FileAuditLog::open(&path, None).unwrap();
            assert_eq!(log.chain.next_seq(), 2);
            log.append(event("r2")).unwrap();
        }
        let entries = read_all(&path).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(verify_chain(&entries, None).is_ok());
    }

    #[test]
    fn opening_a_tampered_log_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let mut log = FileAuditLog::open(&path, None).unwrap();
            log.append(event("r0")).unwrap();
            log.append(event("r1")).unwrap();
        }
        // Corrupt the first line's event without fixing the hash.
        let mut lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        lines[0] = lines[0].replace("\"allow\"", "\"deny:forged\"");
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        assert!(FileAuditLog::open(&path, None).is_err());
    }

    #[test]
    fn signed_log_roundtrips_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let key = b"audit-signing-key".to_vec();
        {
            let mut log = FileAuditLog::open(&path, Some(key.clone())).unwrap();
            log.append(event("r0")).unwrap();
        }
        let entries = read_all(&path).unwrap();
        assert!(verify_chain(&entries, Some(&key)).is_ok());
        // Wrong key fails.
        assert!(verify_chain(&entries, Some(b"wrong")).is_err());
    }
}
