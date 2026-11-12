use crate::{EnvironmentId, KeyId, ProjectId, VaultId};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use zeroize::Zeroizing;

/// Version of the ciphertext format. Stored in every row and part of the [`Aad`],
/// so old rows stay readable after a format change.
pub const FORMAT_VERSION: u32 = 1;
/// Maximum secret value size in bytes (64 KiB), not in characters.
pub const MAX_VALUE_LEN: usize = 65_536;
/// Maximum variable name length in bytes (matches the schema `CHECK`).
pub const MAX_NAME_LEN: usize = 255;

/// Errors of secret validation and value encryption.
///
/// Never carries the secret value itself.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretError {
    /// Name is not `[A-Za-z_][A-Za-z0-9_]*` or is longer than [`MAX_NAME_LEN`].
    #[error("invalid variable name (expected [A-Za-z_][A-Za-z0-9_]*, at most 255 bytes)")]
    InvalidName,
    /// Value is longer than [`MAX_VALUE_LEN`] bytes.
    #[error("value exceeds 64 KiB")]
    ValueTooLarge,
    /// Value contains a NUL byte, which cannot be passed to a process environment.
    #[error("value contains a NUL byte")]
    InvalidValue,
    /// AES-GCM encryption failed.
    #[error("could not encrypt value")]
    Encrypt,
    /// Wrong DEK, tampered ciphertext/nonce, or a different [`Aad`] context.
    /// The causes are deliberately indistinguishable.
    #[error("value cannot be decrypted in this context or is corrupted")]
    Decrypt,
    /// The system random generator is unavailable (no nonce).
    #[error("system random generator is unavailable")]
    Random,
}

/// A validated environment variable name, e.g. `DATABASE_URL`.
///
/// Only a label: renaming does not re-encrypt, because the [`Aad`] uses the
/// stable [`KeyId`]. Case-sensitive (`DB_URL` ≠ `db_url`). Not secret, so it
/// implements `Debug` and `Display`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VarName(String);

impl VarName {
    /// Validates a POSIX environment variable name: `[A-Za-z_][A-Za-z0-9_]*`,
    /// 1..=255 bytes.
    ///
    /// # Errors
    /// [`SecretError::InvalidName`] for an empty name, a leading digit,
    /// characters outside ASCII letters/digits/`_`, or more than 255 bytes.
    pub fn parse(name: &str) -> Result<Self, SecretError> {
        let mut bytes = name.bytes();
        let valid_start = bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_');
        let valid_rest = bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        if valid_start && valid_rest && name.len() <= MAX_NAME_LEN {
            Ok(Self(name.to_owned()))
        } else {
            Err(SecretError::InvalidName)
        }
    }

    /// The name as text, e.g. for SQL parameters or `export NAME=...`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for VarName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A plaintext secret value held only in memory.
///
/// Wiped from memory on drop. Deliberately has no `Display` and no `Clone`,
/// and `Debug` prints `SecretValue(..)`, so the value cannot leak into logs,
/// panic messages or test output by accident.
pub struct SecretValue(SecretString);

impl SecretValue {
    /// Wraps a value after validation: at most [`MAX_VALUE_LEN`] bytes
    /// (counted in bytes, not characters) and no NUL byte.
    ///
    /// The input `String` is wiped from memory, also when it is rejected.
    ///
    /// # Errors
    /// [`SecretError::ValueTooLarge`] or [`SecretError::InvalidValue`] (NUL byte).
    pub fn new(value: String) -> Result<Self, SecretError> {
        let value = Zeroizing::new(value);
        if value.len() > MAX_VALUE_LEN {
            return Err(SecretError::ValueTooLarge);
        }
        if value.contains('\0') {
            return Err(SecretError::InvalidValue);
        }
        Ok(Self(SecretString::from(value.as_str())))
    }

    /// Reveals the plaintext. Use only where the value is really needed
    /// (encryption, injection into a process) and do not copy it further.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretValue(..)")
    }
}

/// Associated data binding a ciphertext to its place in the vault.
///
/// Authenticated by AES-GCM but neither encrypted nor stored in the
/// ciphertext. Decryption with any field changed fails, which detects a
/// ciphertext swapped between secrets, moved to another environment, or
/// rolled back to an old DEK version. Contains only stable identifiers,
/// never names, so renaming does not require re-encryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aad {
    /// Ciphertext format version, see [`FORMAT_VERSION`].
    pub format_version: u32,
    /// The vault the secret belongs to.
    pub vault: VaultId,
    /// The project the secret belongs to.
    pub project: ProjectId,
    /// The environment the secret belongs to.
    pub environment: EnvironmentId,
    /// Stable identity of the secret (survives renaming).
    pub key: KeyId,
    /// Version of the environment DEK used for encryption.
    pub dek_version: u32,
}

impl Aad {
    /// Canonical fixed-length encoding (72 bytes):
    /// `format_version` u32 BE | vault | project | environment | key (16 B each) | `dek_version` u32 BE.
    ///
    /// Fixed length makes the concatenation unambiguous.
    pub fn to_bytes(&self) -> [u8; 72] {
        let mut bytes = [0u8; 72];
        bytes[0..4].copy_from_slice(&self.format_version.to_be_bytes());
        bytes[4..20].copy_from_slice(self.vault.as_bytes());
        bytes[20..36].copy_from_slice(self.project.as_bytes());
        bytes[36..52].copy_from_slice(self.environment.as_bytes());
        bytes[52..68].copy_from_slice(self.key.as_bytes());
        bytes[68..72].copy_from_slice(&self.dek_version.to_be_bytes());
        bytes
    }
}

/// Result of [`Dek::encrypt`](crate::Dek::encrypt). Not secret: safe to store
/// and to print.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedValue {
    /// Random 96-bit nonce, unique for every write.
    pub nonce: [u8; 12],
    /// Encrypted value followed by the 16-byte GCM authentication tag.
    pub ciphertext: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn var_name_accepts_posix_names() {
        for ok in ["A", "_PRIVATE", "api_key_2", &"A".repeat(MAX_NAME_LEN)] {
            assert_eq!(VarName::parse(ok).unwrap().as_str(), ok);
        }
    }

    #[test]
    fn var_name_rejects_invalid_names() {
        for bad in [
            "",
            "1ABC",
            "MY-KEY",
            "WITH SPACE",
            "ZAŻÓŁĆ",
            &"A".repeat(MAX_NAME_LEN + 1),
        ] {
            assert_eq!(
                VarName::parse(bad).unwrap_err(),
                SecretError::InvalidName,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn value_limit_counts_bytes_not_chars() {
        let max = "ą".repeat(MAX_VALUE_LEN / 2);
        assert!(SecretValue::new(max.clone()).is_ok());
        assert_eq!(
            SecretValue::new(max + "a").unwrap_err(),
            SecretError::ValueTooLarge
        );
    }

    #[test]
    fn value_accepts_empty() {
        assert_eq!(SecretValue::new(String::new()).unwrap().expose(), "");
    }

    #[test]
    fn value_rejects_nul_byte() {
        assert_eq!(
            SecretValue::new("a\0b".into()).unwrap_err(),
            SecretError::InvalidValue
        );
    }

    #[test]
    fn value_debug_hides_content() {
        let value = SecretValue::new("hunter2".into()).unwrap();
        assert_eq!(format!("{value:?}"), "SecretValue(..)");
    }

    #[test]
    fn aad_has_fixed_layout() {
        let aad = Aad {
            format_version: 1,
            vault: VaultId::new(),
            project: ProjectId::new(),
            environment: EnvironmentId::new(),
            key: KeyId::new(),
            dek_version: 7,
        };
        let bytes = aad.to_bytes();
        assert_eq!(&bytes[0..4], &1u32.to_be_bytes());
        assert_eq!(&bytes[4..20], aad.vault.as_bytes());
        assert_eq!(&bytes[20..36], aad.project.as_bytes());
        assert_eq!(&bytes[36..52], aad.environment.as_bytes());
        assert_eq!(&bytes[52..68], aad.key.as_bytes());
        assert_eq!(&bytes[68..72], &7u32.to_be_bytes());
    }
}
