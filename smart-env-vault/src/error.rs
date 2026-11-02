use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("key does not match this envelope or the envelope is corrupted")]
    Unwrap,
    #[error("could not wrap key")]
    Wrap,
    #[error("invalid recovery key")]
    InvalidRecoveryKey,
    #[error("invalid stored device key")]
    InvalidDeviceKey,
    #[error("system keychain is unavailable")]
    KeychainUnavailable,
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("key storage error")]
    Storage,
    #[error("system random generator is unavailable")]
    Random,
}