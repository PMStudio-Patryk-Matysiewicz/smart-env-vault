use crate::KeyError;
use age::x25519;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use std::str::FromStr;
use zeroize::Zeroizing;

/// Prefix of the stored seed; the version changes with the derivation.
const SEED_PREFIX: &str = "se-device-seed-v1:";
const X25519_LABEL: &[u8] = b"smart-env/device/x25519";
const ED25519_LABEL: &[u8] = b"smart-env/device/ed25519";

/// Private keys of this device, derived from one 32-byte seed (ADR-002):
///
/// - X25519 (`age` identity): opens [`WrappedDek`](crate::WrappedDek)s via
///   [`Unwrapper`](crate::Unwrapper),
/// - Ed25519: signs requests and attestations (stage 2, ADR-009).
///
/// Each is HKDF-SHA256 of the seed with its own label
/// (`smart-env/device/x25519`, `smart-env/device/ed25519`). Generated locally
/// and kept in the system keychain (see [`KeyStore`](crate::KeyStore)); the
/// seed never leaves the device. `Debug` shows only the public part.
#[derive(Clone)]
pub struct DeviceKey {
    seed: Zeroizing<[u8; 32]>,
    x25519: x25519::Identity,
    signing: SigningKey,
}

/// Public Ed25519 key of a [`DeviceKey`]: verifies its signatures. Not secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigningPublicKey([u8; 32]);

impl SigningPublicKey {
    /// The 32 raw bytes (RFC 8032 encoding).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether `signature` is a valid Ed25519 signature of `message` by
    /// this key.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        VerifyingKey::from_bytes(&self.0).is_ok_and(|key| {
            key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
                .is_ok()
        })
    }
}

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
    ///
    /// # Panics
    /// If the system random generator is unavailable (like `age`'s own
    /// key generation).
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).expect("system random generator is unavailable");
        Self::from_seed(*seed)
    }

    /// Derives the device keys from a seed. Deterministic: the same seed
    /// always gives the same keys.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let seed = Zeroizing::new(seed);
        let x25519 = age_identity(&derive(&seed, X25519_LABEL));
        let signing = SigningKey::from_bytes(&derive(&seed, ED25519_LABEL));
        Self {
            seed,
            x25519,
            signing,
        }
    }

    /// Restores a key from its text form
    /// (`se-device-seed-v1:` + 64 lowercase hex digits), e.g. read from the keychain.
    ///
    /// # Errors
    /// [`KeyError::InvalidDeviceKey`] if the text is not a valid key.
    pub fn from_secret(secret: &SecretString) -> Result<Self, KeyError> {
        let hex = secret
            .expose_secret()
            .strip_prefix(SEED_PREFIX)
            .filter(|hex| hex.len() == 64)
            .ok_or(KeyError::InvalidDeviceKey)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        let (pairs, _) = hex.as_bytes().as_chunks::<2>();
        for (byte, &[high, low]) in seed.iter_mut().zip(pairs) {
            *byte = (nibble(high)? << 4) | nibble(low)?;
        }
        Ok(Self::from_seed(*seed))
    }

    /// Text form of the seed (`se-device-seed-v1:<hex>`), for saving in a
    /// [`KeyStore`](crate::KeyStore).
    /// Wrapped in [`SecretString`], so it is wiped on drop and hidden in `Debug`.
    pub fn to_secret(&self) -> SecretString {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        // Exact capacity: no reallocation leaves a copy of the seed behind.
        let mut text = String::with_capacity(SEED_PREFIX.len() + 64);
        text.push_str(SEED_PREFIX);
        for byte in self.seed.iter() {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        SecretString::from(text)
    }

    /// The public key to wrap DEKs for this device.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.x25519.to_public())
    }

    /// The public key that verifies this device's signatures.
    pub fn signing_public(&self) -> SigningPublicKey {
        SigningPublicKey(self.signing.verifying_key().to_bytes())
    }

    /// Ed25519 signature of `message` (RFC 8032, deterministic).
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

/// HKDF-SHA256 of the seed (no salt) with a label; 32 bytes.
fn derive(seed: &[u8; 32], label: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, seed)
        .expand(label, key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// `age` has no constructor from raw bytes, so the key goes through its text
/// form (`AGE-SECRET-KEY-1…`, Bech32), which is wiped afterwards.
fn age_identity(secret: &[u8; 32]) -> x25519::Identity {
    let hrp = bech32::Hrp::parse("age-secret-key-").expect("valid Bech32 prefix");
    let mut text = Zeroizing::new(
        bech32::encode::<bech32::Bech32>(hrp, secret).expect("32 bytes fit in a Bech32 string"),
    );
    text.make_ascii_uppercase(); // in place: no unwiped copy
    x25519::Identity::from_str(&text).expect("valid age identity encoding")
}

/// Lowercase hex digit.
fn nibble(digit: u8) -> Result<u8, KeyError> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        _ => Err(KeyError::InvalidDeviceKey),
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
        &self.x25519
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
