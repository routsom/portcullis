//! Secret storage.
//!
//! The default store is an **encrypted-at-rest local file**: secrets are sealed
//! with XChaCha20-Poly1305 under a key derived from an operator passphrase via
//! Argon2id. This is the "no external vault required" default (CLAUDE.md §5 row
//! #8); `Vault`/`KMS`/keychain are optional integrations layered on the
//! [`SecretStore`] trait later. See `docs/adr/0004-broker-secret-store.md` for
//! why we use `RustCrypto` primitives directly rather than the `age` format.
//!
//! Secret values are wrapped in [`SecretValue`] (zeroized on drop) and are never
//! logged or placed in errors.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{BrokerError, Result};

/// A secret value, zeroized when dropped.
pub type SecretValue = Zeroizing<String>;

/// Somewhere secrets can be stored and retrieved. Implementations must be safe
/// for concurrent use.
pub trait SecretStore: Send + Sync {
    /// Fetch a secret by name.
    fn get(&self, name: &str) -> Result<SecretValue>;
    /// Store or replace a secret.
    fn put(&self, name: &str, value: SecretValue) -> Result<()>;
    /// Remove a secret. Removing a missing secret is not an error.
    fn delete(&self, name: &str) -> Result<()>;
    /// List secret names (never values).
    fn names(&self) -> Result<Vec<String>>;
}

/// An in-memory store. Useful for tests and ephemeral deployments; nothing is
/// persisted.
#[derive(Debug, Default)]
pub struct MemoryStore {
    inner: RwLock<BTreeMap<String, String>>,
}

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for MemoryStore {
    fn get(&self, name: &str) -> Result<SecretValue> {
        self.inner
            .read()
            .expect("secret lock poisoned")
            .get(name)
            .map(|v| Zeroizing::new(v.clone()))
            .ok_or_else(|| BrokerError::NotFound(name.to_string()))
    }

    fn put(&self, name: &str, value: SecretValue) -> Result<()> {
        self.inner
            .write()
            .expect("secret lock poisoned")
            .insert(name.to_string(), value.to_string());
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<()> {
        self.inner
            .write()
            .expect("secret lock poisoned")
            .remove(name);
        Ok(())
    }

    fn names(&self) -> Result<Vec<String>> {
        Ok(self
            .inner
            .read()
            .expect("secret lock poisoned")
            .keys()
            .cloned()
            .collect())
    }
}

const MAGIC: &[u8; 4] = b"PCB1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
// Header = magic(4) + m_cost(4) + t_cost(4) + p_cost(4) + salt(16). Used as AEAD
// associated data so the KDF parameters and salt cannot be swapped undetected.
const HEADER_LEN: usize = 4 + 4 + 4 + 4 + SALT_LEN;

/// Argon2id cost parameters, persisted in the file header so a store written
/// with stronger settings still opens.
// The `_cost` suffix is the established Argon2 vocabulary; renaming for the lint
// would obscure it.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug)]
struct KdfParams {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // ~19 MiB, 2 passes, 1 lane: OWASP-recommended interactive baseline.
        Self {
            m_cost: 19_456,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

/// An encrypted-at-rest local secret store.
///
/// The derived key is held in memory (zeroized on drop) so mutations can
/// re-seal the file without re-prompting for the passphrase. The decrypted map
/// is also held in memory for the process lifetime.
pub struct EncryptedFileStore {
    path: PathBuf,
    key: Zeroizing<[u8; KEY_LEN]>,
    salt: [u8; SALT_LEN],
    params: KdfParams,
    map: RwLock<BTreeMap<String, String>>,
}

impl std::fmt::Debug for EncryptedFileStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the key or secret values.
        f.debug_struct("EncryptedFileStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl EncryptedFileStore {
    /// Create a new, empty store at `path`, sealed with `passphrase`. Fails if
    /// the file already exists, to avoid clobbering secrets.
    pub fn create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(BrokerError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "secret store already exists",
            )));
        }
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt)?;
        let params = KdfParams::default();
        let key = derive_key(passphrase, &salt, params)?;
        let store = Self {
            path,
            key,
            salt,
            params,
            map: RwLock::new(BTreeMap::new()),
        };
        store.persist()?;
        Ok(store)
    }

    /// Open and decrypt an existing store with `passphrase`. A wrong passphrase
    /// or a tampered file yields [`BrokerError::Decrypt`].
    pub fn open(path: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let bytes = std::fs::read(&path)?;
        if bytes.len() < HEADER_LEN + NONCE_LEN {
            return Err(BrokerError::Format);
        }
        if &bytes[0..4] != MAGIC {
            return Err(BrokerError::Format);
        }
        let params = KdfParams {
            m_cost: u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes")),
            t_cost: u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes")),
            p_cost: u32::from_le_bytes(bytes[12..16].try_into().expect("4 bytes")),
        };
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[16..HEADER_LEN]);
        let header = &bytes[0..HEADER_LEN];
        let nonce = &bytes[HEADER_LEN..HEADER_LEN + NONCE_LEN];
        let ciphertext = &bytes[HEADER_LEN + NONCE_LEN..];

        let key = derive_key(passphrase, &salt, params)?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: header,
                    },
                )
                .map_err(|_| BrokerError::Decrypt)?,
        );
        let map: BTreeMap<String, String> =
            serde_json::from_slice(&plaintext).map_err(|_| BrokerError::Format)?;

        Ok(Self {
            path,
            key,
            salt,
            params,
            map: RwLock::new(map),
        })
    }

    /// Re-seal the current map to disk atomically (write temp, then rename).
    fn persist(&self) -> Result<()> {
        let header = self.header();
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce)?;

        let plaintext = {
            let map = self.map.read().expect("secret lock poisoned");
            Zeroizing::new(serde_json::to_vec(&*map).map_err(|_| BrokerError::Format)?)
        };
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| BrokerError::Decrypt)?;

        let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);

        // Atomic replace: write a temp file next to the target, then rename.
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &out)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    fn header(&self) -> [u8; HEADER_LEN] {
        let mut header = [0u8; HEADER_LEN];
        header[0..4].copy_from_slice(MAGIC);
        header[4..8].copy_from_slice(&self.params.m_cost.to_le_bytes());
        header[8..12].copy_from_slice(&self.params.t_cost.to_le_bytes());
        header[12..16].copy_from_slice(&self.params.p_cost.to_le_bytes());
        header[16..HEADER_LEN].copy_from_slice(&self.salt);
        header
    }
}

impl SecretStore for EncryptedFileStore {
    fn get(&self, name: &str) -> Result<SecretValue> {
        self.map
            .read()
            .expect("secret lock poisoned")
            .get(name)
            .map(|v| Zeroizing::new(v.clone()))
            .ok_or_else(|| BrokerError::NotFound(name.to_string()))
    }

    fn put(&self, name: &str, value: SecretValue) -> Result<()> {
        self.map
            .write()
            .expect("secret lock poisoned")
            .insert(name.to_string(), value.to_string());
        self.persist()
    }

    fn delete(&self, name: &str) -> Result<()> {
        let existed = self
            .map
            .write()
            .expect("secret lock poisoned")
            .remove(name)
            .is_some();
        if existed { self.persist() } else { Ok(()) }
    }

    fn names(&self) -> Result<Vec<String>> {
        Ok(self
            .map
            .read()
            .expect("secret lock poisoned")
            .keys()
            .cloned()
            .collect())
    }
}

fn derive_key(
    passphrase: &str,
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| BrokerError::KeyDerivation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|_| BrokerError::KeyDerivation)?;
    Ok(key)
}

fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| BrokerError::Random)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_roundtrips_and_lists() {
        let s = MemoryStore::new();
        s.put("api", Zeroizing::new("k-123".into())).unwrap();
        assert_eq!(*s.get("api").unwrap(), "k-123");
        assert_eq!(s.names().unwrap(), vec!["api".to_string()]);
        s.delete("api").unwrap();
        assert!(matches!(s.get("api"), Err(BrokerError::NotFound(_))));
    }

    #[test]
    fn encrypted_store_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.pcb");
        {
            let s = EncryptedFileStore::create(&path, "correct horse battery staple").unwrap();
            s.put("upstream_token", Zeroizing::new("sekret".into()))
                .unwrap();
        }
        let reopened = EncryptedFileStore::open(&path, "correct horse battery staple").unwrap();
        assert_eq!(*reopened.get("upstream_token").unwrap(), "sekret");
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.pcb");
        EncryptedFileStore::create(&path, "right").unwrap();
        assert!(matches!(
            EncryptedFileStore::open(&path, "wrong"),
            Err(BrokerError::Decrypt)
        ));
    }

    #[test]
    fn tampered_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.pcb");
        {
            let s = EncryptedFileStore::create(&path, "pw").unwrap();
            s.put("k", Zeroizing::new("v".into())).unwrap();
        }
        let mut bytes = std::fs::read(&path).unwrap();
        // Flip a byte in the ciphertext region.
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            EncryptedFileStore::open(&path, "pw"),
            Err(BrokerError::Decrypt)
        ));
    }

    #[test]
    fn create_refuses_to_clobber_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.pcb");
        EncryptedFileStore::create(&path, "pw").unwrap();
        assert!(EncryptedFileStore::create(&path, "pw").is_err());
    }
}
