//! Versioned, forward-migratable on-disk state.
//!
//! Every persisted structure carries a schema version and has a forward
//! migration with a test; no serde defaults silently reinterpret old data
//! (CLAUDE.md §7 "store nothing you cannot migrate"). The on-disk format is
//! `{ "version": N, "data": { … } }`. On load, data older than the current
//! version is migrated one step at a time up to current; data from a *newer*
//! version is refused (no silent downgrade). Writes are atomic.

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Errors from state persistence.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("state i/o error")]
    Io(#[from] std::io::Error),
    #[error("state file is malformed")]
    Malformed,
    #[error(
        "state file version {found} is newer than this binary supports ({supported}); \
         refusing to downgrade"
    )]
    TooNew { found: u32, supported: u32 },
    #[error("migration from version {0} failed: {1}")]
    Migration(u32, String),
    #[error("state data did not match its schema after migration")]
    Schema(#[source] serde_json::Error),
}

/// A type that can be persisted with versioning and migrated forward.
///
/// `migrate` transforms the raw `data` object from version `from` to `from + 1`.
/// The store calls it repeatedly until the data reaches [`CURRENT_VERSION`].
///
/// [`CURRENT_VERSION`]: Versioned::CURRENT_VERSION
pub trait Versioned: Serialize + DeserializeOwned {
    /// The schema version this binary writes and expects after migration.
    const CURRENT_VERSION: u32;

    /// Migrate `data` from `from` to `from + 1`. Only called for
    /// `from < CURRENT_VERSION`.
    fn migrate(from: u32, data: Value) -> Result<Value, String>;
}

/// A file-backed versioned store for one document of type `T`.
#[derive(Debug, Clone)]
pub struct Store {
    path: PathBuf,
}

#[derive(Serialize, serde::Deserialize)]
struct Envelope {
    version: u32,
    data: Value,
}

impl Store {
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Whether the state file exists.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Load and migrate the document. Returns `None` if the file does not exist.
    pub fn load<T: Versioned>(&self) -> Result<Option<T>, StateError> {
        if !self.path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&self.path)?;
        let envelope: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| StateError::Malformed)?;

        if envelope.version > T::CURRENT_VERSION {
            return Err(StateError::TooNew {
                found: envelope.version,
                supported: T::CURRENT_VERSION,
            });
        }

        let mut data = envelope.data;
        let mut version = envelope.version;
        while version < T::CURRENT_VERSION {
            data = T::migrate(version, data).map_err(|e| StateError::Migration(version, e))?;
            version += 1;
        }

        let value: T = serde_json::from_value(data).map_err(StateError::Schema)?;
        Ok(Some(value))
    }

    /// Persist the document at the current version, atomically.
    pub fn save<T: Versioned>(&self, value: &T) -> Result<(), StateError> {
        let envelope = Envelope {
            version: T::CURRENT_VERSION,
            data: serde_json::to_value(value).map_err(StateError::Schema)?,
        };
        let bytes = serde_json::to_vec_pretty(&envelope).map_err(StateError::Schema)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    // A settings document at schema version 2. v1 had no `theme`; the migration
    // introduces it with an explicit value (not a serde default).
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Settings {
        name: String,
        theme: String,
    }

    impl Versioned for Settings {
        const CURRENT_VERSION: u32 = 2;
        fn migrate(from: u32, mut data: Value) -> Result<Value, String> {
            match from {
                1 => {
                    // v1 -> v2: add `theme`, defaulting to "light".
                    if let Value::Object(map) = &mut data {
                        map.insert("theme".to_string(), Value::String("light".to_string()));
                    }
                    Ok(data)
                }
                other => Err(format!("no migration from version {other}")),
            }
        }
    }

    #[test]
    fn save_then_load_roundtrips_at_current_version() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("settings.json"));
        let s = Settings {
            name: "acme".into(),
            theme: "dark".into(),
        };
        store.save(&s).unwrap();
        assert_eq!(store.load::<Settings>().unwrap(), Some(s));
    }

    #[test]
    fn old_version_is_migrated_forward_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        // Hand-write a v1 file with no `theme`.
        std::fs::write(&path, r#"{"version":1,"data":{"name":"acme"}}"#).unwrap();

        let loaded: Settings = Store::new(&path).load().unwrap().unwrap();
        assert_eq!(loaded.name, "acme");
        assert_eq!(loaded.theme, "light", "migration supplied the new field");
    }

    #[test]
    fn newer_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"version":99,"data":{"name":"acme","theme":"dark"}}"#,
        )
        .unwrap();
        assert!(matches!(
            Store::new(&path).load::<Settings>(),
            Err(StateError::TooNew { .. })
        ));
    }

    #[test]
    fn missing_file_loads_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("absent.json"));
        assert_eq!(store.load::<Settings>().unwrap(), None);
    }
}
