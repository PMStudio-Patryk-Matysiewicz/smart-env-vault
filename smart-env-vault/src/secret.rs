use crate::{EnvironmentId, KeyId, ProjectId, VaultId};
use secrecy::SecretString;
use thiserror::Error;

pub const FORMAT_VERSION: u32 = 1;
pub const MAX_VALUE_LEN: usize = 65_536;
pub const MAX_NAME_LEN: usize = 255;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretError {
    #[error("invalid variable name (expected [A-Za-z_][A-Za-z0-9_]*, at most 255 bytes)")]
    InvalidName,
    #[error("value exceeds 64 KiB")]
    ValueTooLarge,
    #[error("value contains a NUL byte")]
    InvalidValue,
    #[error("could not encrypt value")]
    Encrypt,
    #[error("value cannot be decrypted in this context or is corrupted")]
    Decrypt,
    #[error("system random generator is unavailable")]
    Random,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VarName(String);

impl VarName {
    pub fn parse(name: &str) -> Result<Self, SecretError> {
        todo!()
    }

    pub fn as_str(&self) -> &str {
        todo!()
    }
}

impl std::fmt::Display for VarName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub struct SecretValue(SecretString);

impl SecretValue {
    pub fn new(value: String) -> Result<Self, SecretError> {
        todo!()
    }

    pub fn expose(&self) -> &str {
        todo!()
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aad {
    pub format_version: u32,
    pub vault: VaultId,
    pub project: ProjectId,
    pub environment: EnvironmentId,
    pub key: KeyId,
    pub dek_version: u32,
}

impl Aad {
    pub fn to_bytes(&self) -> [u8; 72] {
        todo!()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedValue {
    pub nonce: [u8; 12],
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
