use crate::KeyError;
use age::x25519;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use secrecy::{ExposeSecret, SecretString};
use std::str::FromStr;

/// Private X25519 key of this device (`age` identity).
///
/// Generated locally and kept in the system keychain (see [`KeyStore`](crate::KeyStore));
/// the private part never leaves the device. Opens [`WrappedDek`](crate::WrappedDek)s
/// via [`Unwrapper`](crate::Unwrapper). `Debug` shows only the public part.
#[derive(Clone)]
pub struct DeviceKey(x25519::Identity);

/// Public half of a [`DeviceKey`] or [`RecoveryKey`](crate::RecoveryKey) (`age1...`).
///
/// Not secret: used as a recipient in [`Dek::wrap`](crate::Dek::wrap).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(x25519::Recipient);

impl PublicKey {
    pub(crate) fn from_recipient(recipient: x25519::Recipient) -> Self {
        Self(recipient)
    }
}

impl DeviceKey {
    /// Generates a new random device key.
    pub fn generate() -> Self {
        Self(x25519::Identity::generate())
    }

    /// Restores a key from its text form (`AGE-SECRET-KEY-1...`), e.g. read from the keychain.
    ///
    /// # Errors
    /// [`KeyError::InvalidDeviceKey`] if the text is not a valid key.
    pub fn from_secret(secret: &SecretString) -> Result<Self, KeyError> {
        x25519::Identity::from_str(secret.expose_secret())
            .map(Self)
            .map_err(|_| KeyError::InvalidDeviceKey)
    }

    /// Text form of the private key, for saving in a [`KeyStore`](crate::KeyStore).
    /// Wrapped in [`SecretString`], so it is wiped on drop and hidden in `Debug`.
    pub fn to_secret(&self) -> SecretString {
        self.0.to_string()
    }

    /// The public key to wrap DEKs for this device.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.to_public())
    }
}

impl PublicKey {
    /// Parses the text form (`age1...`), e.g. read from the recipients table.
    ///
    /// # Errors
    /// [`KeyError::InvalidPublicKey`] if the text is not a valid public key
    /// (surrounding whitespace is not accepted).
    pub fn parse(text: &str) -> Result<Self, KeyError> {
        x25519::Recipient::from_str(text)
            .map(Self)
            .map_err(|_| KeyError::InvalidPublicKey)
    }

    pub(crate) fn recipient(&self) -> &x25519::Recipient {
        &self.0
    }
}

impl ToSql for PublicKey {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.to_string()))
    }
}

impl FromSql for PublicKey {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        Self::parse(value.as_str()?).map_err(|error| FromSqlError::Other(Box::new(error)))
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

    fn public(&self) -> PublicKey {
        DeviceKey::public(self)
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
    fn public_key_round_trips_through_text() {
        let key = DeviceKey::generate().public();
        assert_eq!(PublicKey::parse(&key.to_string()).unwrap(), key);
    }

    #[test]
    fn public_key_parse_rejects_garbage() {
        let key = DeviceKey::generate();
        let padded = format!(" {} ", key.public());
        let private = key.to_secret().expose_secret().to_owned();
        for bad in ["", "age1", "not-a-key", padded.as_str(), private.as_str()] {
            assert_eq!(
                PublicKey::parse(bad).unwrap_err(),
                KeyError::InvalidPublicKey,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn unwrapper_public_matches_key() {
        let key = DeviceKey::generate();
        assert_eq!(crate::Unwrapper::public(&key), key.public());
    }

    #[test]
    fn debug_shows_only_public_part() {
        let key = DeviceKey::generate();
        let debug = format!("{key:?}");
        assert!(!debug.contains("AGE-SECRET-KEY"));
        assert!(debug.contains(&key.public().to_string()));
    }
}
