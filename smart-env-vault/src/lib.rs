//! Client-side encrypted secret store for `smart-env`.
//!
//! Key model (ADR-001):
//!
//! ```text
//! DeviceKey (X25519, keychain) ──┐
//!                                ├─ wrap ──> Dek per environment ── AES-256-GCM + Aad ──> secret values
//! RecoveryKey ───────────────────┘
//! ```
//!
//! Entry point: [`Vault`]. The database holds only ciphertext and wrapped keys.
#![forbid(unsafe_code)]

mod dek;
mod device;
mod error;
mod ids;
mod recovery;
mod secret;
mod store;
mod vault;

pub use dek::{Dek, Unwrapper, WrappedDek};
pub use device::{DeviceKey, PublicKey};
pub use error::KeyError;
pub use ids::{EnvironmentId, KeyId, ProjectId, RecipientId, VaultId};
pub use recovery::RecoveryKey;
pub use secret::{
    Aad, EncryptedValue, FORMAT_VERSION, MAX_NAME_LEN, MAX_VALUE_LEN, SecretError, SecretValue,
    VarName,
};
pub use store::{KeyStore, KeychainStore, MemoryStore, PassphraseFileStore};
pub use vault::{
    EnvKind, HISTORY_LIMIT, Recipient, RecipientKind, SecretMeta, SetOutcome, Vault, VaultError,
    VersionMeta,
};
