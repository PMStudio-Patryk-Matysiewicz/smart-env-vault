use crate::KeyError;
use age::x25519;
use secrecy::{ExposeSecret, SecretString};
use std::str::FromStr;

#[derive(Clone)]
pub struct DeviceKey(x25519::Identity);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(x25519::Recipient);

impl PublicKey {
    pub(crate) fn from_recipient(recipient: x25519::Recipient) -> Self {
        Self(recipient)
    }
}

impl DeviceKey {
    pub fn generate() -> Self {
        Self(x25519::Identity::generate())
    }

    pub fn from_secret(secret: &SecretString) -> Result<Self, KeyError> {
        x25519::Identity::from_str(secret.expose_secret())
            .map(Self)
            .map_err(|_| KeyError::InvalidDeviceKey)
    }

    pub fn to_secret(&self) -> SecretString {
        self.0.to_string()
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.to_public())
    }
}

impl PublicKey {
    pub(crate) fn recipient(&self) -> &x25519::Recipient {
        &self.0
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("DeviceKey")
            .field(&self.public())
            .finish()
    }
}

impl crate::Unwrapper for DeviceKey {
    fn identity(&self) -> &dyn age::Identity {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_unique() {
        assert_ne!(
            DeviceKey::generate().public(),
            DeviceKey::generate().public()
        );
    }

    #[test]
    fn public_key_uses_age_format() {
        assert!(
            DeviceKey::generate()
                .public()
                .to_string()
                .starts_with("age1")
        );
    }

    #[test]
    fn secret_round_trip_preserves_identity() {
        let key = DeviceKey::generate();
        let restored = DeviceKey::from_secret(&key.to_secret()).unwrap();
        assert_eq!(key.public(), restored.public());
    }

    #[test]
    fn rejects_malformed_secret() {
        let bad = SecretString::from("not-a-key".to_owned());
        assert_eq!(
            DeviceKey::from_secret(&bad).unwrap_err(),
            KeyError::InvalidDeviceKey
        );
    }

    #[test]
    fn debug_shows_only_public_part() {
        let key = DeviceKey::generate();
        let debug = format!("{key:?}");
        assert!(!debug.contains("AGE-SECRET-KEY"));
        assert!(debug.contains(&key.public().to_string()));
    }
}