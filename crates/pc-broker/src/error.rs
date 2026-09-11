//! Broker error types.
//!
//! Errors never contain secret material, passphrases, or plaintext. Crypto
//! failures are collapsed to opaque variants so nothing about a wrong key or a
//! tampered file leaks through the message (CLAUDE.md §11, §12).

/// Errors from broker operations.
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("secret {0:?} not found")]
    NotFound(String),

    #[error("secret store i/o error")]
    Io(#[source] std::io::Error),

    #[error("secret store is sealed: unlock with the correct passphrase first")]
    Sealed,

    /// Decryption or authentication failed: wrong passphrase, corrupt file, or
    /// tampering. Deliberately indistinguishable.
    #[error("could not decrypt secret store (wrong passphrase or corrupt data)")]
    Decrypt,

    #[error("secret store file is malformed or uses an unsupported version")]
    Format,

    #[error("key derivation failed")]
    KeyDerivation,

    #[error("randomness unavailable")]
    Random,

    #[error("invalid egress rule: {0}")]
    EgressRule(String),
}

impl From<std::io::Error> for BrokerError {
    fn from(e: std::io::Error) -> Self {
        BrokerError::Io(e)
    }
}

/// Result alias for broker operations.
pub type Result<T> = std::result::Result<T, BrokerError>;
