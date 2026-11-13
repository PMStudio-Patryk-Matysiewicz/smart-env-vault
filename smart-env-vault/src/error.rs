use thiserror::Error;

/// Errors of key management (device key, recovery key, DEK wrapping).
///
/// Never carries key material.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    /// The key is not a recipient of this envelope, or the envelope is corrupted.
    #[error("key does not match this envelope or the envelope is corrupted")]
    Unwrap,
    /// No recipients were given, or `age` encryption failed.
    #[error("could not wrap key")]
    Wrap,
    /// The recovery key text is malformed or has a typo.
    #[error("invalid recovery key")]
    InvalidRecoveryKey,
    /// The key loaded from a [`KeyStore`](crate::KeyStore) is not a valid key.
    #[error("invalid stored device key")]
    InvalidDeviceKey,
    /// The system keychain cannot be reached (e.g. no desktop session).
    #[error("system keychain is unavailable")]
    KeychainUnavailable,
    /// The passphrase does not open the key file.
    #[error("wrong passphrase")]
    WrongPassphrase,
    /// Reading or writing the key file failed.
    #[error("key storage error")]
    Storage,
    /// The system random generator is unavailable.
    #[error("system random generator is unavailable")]
    Random,
}
