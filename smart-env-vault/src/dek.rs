use crate::{Aad, EncryptedValue, KeyError, PublicKey, SecretError, SecretValue};
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Nonce, Payload},
};
use age::{Decryptor, Encryptor};
use std::io::{Cursor, Read, Write};
use zeroize::Zeroizing;

/// Data Encryption Key: a random 256-bit key of one environment.
///
/// Encrypts secret values with AES-256-GCM. Never stored in plain form —
/// only as a [`WrappedDek`] encrypted for the device and recovery keys.
/// Bytes are wiped from memory on drop; `Debug` prints `Dek(..)`.
pub struct Dek(pub(crate) Zeroizing<[u8; 32]>);

/// A [`Dek`] encrypted (`age` X25519) for one or more [`PublicKey`]s.
///
/// Safe to store in the database or send to a server.
#[derive(Debug)]
pub struct WrappedDek(Vec<u8>);

/// A private key that can open a [`WrappedDek`]: [`DeviceKey`](crate::DeviceKey)
/// or [`RecoveryKey`](crate::RecoveryKey).
pub trait Unwrapper {
    /// The underlying `age` identity used to decrypt the envelope.
    fn identity(&self) -> &dyn age::Identity;
    /// The matching public key, used to find this key's envelope among the
    /// recipients of a DEK.
    fn public(&self) -> PublicKey;
}

impl Dek {
    /// Generates a new random DEK from the system CSPRNG.
    ///
    /// # Errors
    /// [`KeyError::Random`] if the system random generator is unavailable.
    pub fn generate() -> Result<Self, KeyError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| KeyError::Random)?;
        Ok(Self(bytes))
    }

    /// Encrypts this DEK so that any one of `recipients` can unwrap it.
    ///
    /// Typically: the device key plus the recovery key.
    ///
    /// # Errors
    /// [`KeyError::Wrap`] if `recipients` is empty or encryption fails.
    pub fn wrap(&self, recipients: &[&PublicKey]) -> Result<WrappedDek, KeyError> {
        if recipients.is_empty() {
            return Err(KeyError::Wrap);
        }
        let encryptor = Encryptor::with_recipients(
            recipients
                .iter()
                .map(|recipient| recipient.recipient() as &dyn age::Recipient),
        )
        .map_err(|_| KeyError::Wrap)?;
        let mut output = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut output)
            .map_err(|_| KeyError::Wrap)?;
        writer
            .write_all(self.0.as_ref())
            .map_err(|_| KeyError::Wrap)?;
        writer.finish().map_err(|_| KeyError::Wrap)?;
        Ok(WrappedDek(output))
    }

    /// Decrypts a [`WrappedDek`] with a private key.
    ///
    /// Authenticated: success proves the key is correct, so this doubles as
    /// the "is this the right key?" check before any write.
    ///
    /// # Errors
    /// [`KeyError::Unwrap`] if the key is not a recipient or the envelope is corrupted.
    pub fn unwrap<U: Unwrapper>(wrapped: &WrappedDek, key: &U) -> Result<Self, KeyError> {
        let decryptor = Decryptor::new(Cursor::new(&wrapped.0)).map_err(|_| KeyError::Unwrap)?;
        let mut reader = decryptor
            .decrypt(std::iter::once(key.identity()))
            .map_err(|_| KeyError::Unwrap)?;
        let mut bytes = [0u8; 32];
        reader
            .read_exact(&mut bytes)
            .map_err(|_| KeyError::Unwrap)?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Encrypts a secret value with AES-256-GCM.
    ///
    /// Uses a fresh random 96-bit nonce on every call, so the same value
    /// never produces the same ciphertext. `aad` binds the ciphertext to its
    /// place in the vault (see [`Aad`]); it is authenticated, not stored.
    ///
    /// # Errors
    /// [`SecretError::Random`] if no nonce can be generated,
    /// [`SecretError::Encrypt`] if encryption fails.
    pub fn encrypt(&self, value: &SecretValue, aad: &Aad) -> Result<EncryptedValue, SecretError> {
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| SecretError::Random)?;
        let ciphertext = self
            .cipher()?
            .encrypt(
                &Nonce::<Aes256Gcm>::from(nonce),
                Payload {
                    msg: value.expose().as_bytes(),
                    aad: &aad.to_bytes(),
                },
            )
            .map_err(|_| SecretError::Encrypt)?;
        Ok(EncryptedValue { nonce, ciphertext })
    }

    /// Decrypts a value produced by [`Dek::encrypt`].
    ///
    /// `aad` must be identical to the one used for encryption. The plaintext
    /// buffer is wiped from memory right after conversion.
    ///
    /// # Errors
    /// [`SecretError::Decrypt`] if the ciphertext, nonce or any [`Aad`] field
    /// differs, the DEK is wrong, or the plaintext is not valid UTF-8.
    pub fn decrypt(&self, value: &EncryptedValue, aad: &Aad) -> Result<SecretValue, SecretError> {
        let plaintext = Zeroizing::new(
            self.cipher()?
                .decrypt(
                    &Nonce::<Aes256Gcm>::from(value.nonce),
                    Payload {
                        msg: &value.ciphertext,
                        aad: &aad.to_bytes(),
                    },
                )
                .map_err(|_| SecretError::Decrypt)?,
        );
        let text = std::str::from_utf8(&plaintext).map_err(|_| SecretError::Decrypt)?;
        SecretValue::new(text.to_owned())
    }

    /// Built straight from the zeroizing buffer (no stack copy of the key);
    /// the `zeroize` feature of `aes-gcm` wipes the expanded key on drop.
    fn cipher(&self) -> Result<Aes256Gcm, SecretError> {
        Aes256Gcm::new_from_slice(self.0.as_ref()).map_err(|_| SecretError::Encrypt)
    }
}

impl WrappedDek {
    /// Raw envelope bytes, e.g. for the `environment_deks.wrapped` column.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Restores an envelope from stored bytes. Validity is checked only by
    /// [`Dek::unwrap`].
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for Dek {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Dek(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceKey, RecoveryKey};

    #[test]
    fn generated_deks_are_unique() {
        assert_ne!(*Dek::generate().unwrap().0, *Dek::generate().unwrap().0);
    }

    #[test]
    fn each_recipient_unwraps_the_same_dek() {
        let device = DeviceKey::generate();
        let (recovery, _) = RecoveryKey::generate();
        let dek = Dek::generate().unwrap();
        let wrapped = dek.wrap(&[&device.public(), &recovery.public()]).unwrap();

        assert_eq!(*Dek::unwrap(&wrapped, &device).unwrap().0, *dek.0);
        assert_eq!(*Dek::unwrap(&wrapped, &recovery).unwrap().0, *dek.0);
    }

    #[test]
    fn foreign_key_cannot_unwrap() {
        let wrapped = Dek::generate()
            .unwrap()
            .wrap(&[&DeviceKey::generate().public()])
            .unwrap();
        assert_eq!(
            Dek::unwrap(&wrapped, &DeviceKey::generate()).unwrap_err(),
            KeyError::Unwrap
        );
    }

    #[test]
    fn tampered_envelope_is_rejected() {
        let device = DeviceKey::generate();
        let wrapped = Dek::generate().unwrap().wrap(&[&device.public()]).unwrap();
        let mut bytes = wrapped.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert_eq!(
            Dek::unwrap(&WrappedDek::from_bytes(bytes), &device).unwrap_err(),
            KeyError::Unwrap
        );
    }

    #[test]
    fn wrapping_requires_a_recipient() {
        assert_eq!(
            Dek::generate().unwrap().wrap(&[]).unwrap_err(),
            KeyError::Wrap
        );
    }

    #[test]
    fn envelope_does_not_contain_plain_dek() {
        let dek = Dek::generate().unwrap();
        let wrapped = dek.wrap(&[&DeviceKey::generate().public()]).unwrap();
        assert!(
            !wrapped
                .as_bytes()
                .windows(32)
                .any(|w| w == dek.0.as_slice())
        );
    }

    #[test]
    fn debug_does_not_reveal_bytes() {
        assert_eq!(format!("{:?}", Dek::generate().unwrap()), "Dek(..)");
    }

    mod values {
        use super::*;
        use crate::{
            EnvironmentId, FORMAT_VERSION, KeyId, MAX_VALUE_LEN, ProjectId, SecretValue, VaultId,
        };

        fn aad() -> Aad {
            Aad {
                format_version: FORMAT_VERSION,
                vault: VaultId::new(),
                project: ProjectId::new(),
                environment: EnvironmentId::new(),
                key: KeyId::new(),
                dek_version: 1,
                version: 1,
            }
        }

        fn value(text: &str) -> SecretValue {
            SecretValue::new(text.to_owned()).unwrap()
        }

        #[test]
        fn round_trip_preserves_value() {
            let dek = Dek::generate().unwrap();
            let aad = aad();
            for text in [
                "postgres://u:p@h/db",
                "zażółć 🔑",
                "",
                &"x".repeat(MAX_VALUE_LEN),
            ] {
                let encrypted = dek.encrypt(&value(text), &aad).unwrap();
                assert_eq!(dek.decrypt(&encrypted, &aad).unwrap().expose(), text);
            }
        }

        #[test]
        fn same_value_encrypts_differently() {
            let dek = Dek::generate().unwrap();
            let aad = aad();
            let first = dek.encrypt(&value("v"), &aad).unwrap();
            let second = dek.encrypt(&value("v"), &aad).unwrap();
            assert_ne!(first.nonce, second.nonce);
            assert_ne!(first.ciphertext, second.ciphertext);
        }

        #[test]
        fn ciphertext_is_value_plus_tag() {
            let encrypted = Dek::generate()
                .unwrap()
                .encrypt(&value("abc"), &aad())
                .unwrap();
            assert_eq!(encrypted.ciphertext.len(), 3 + 16);
        }

        #[test]
        fn tampered_ciphertext_or_nonce_is_rejected() {
            let dek = Dek::generate().unwrap();
            let aad = aad();
            let good = dek.encrypt(&value("v"), &aad).unwrap();
            let mut ciphertext = good.clone();
            ciphertext.ciphertext[0] ^= 1;
            let mut nonce = good.clone();
            nonce.nonce[0] ^= 1;
            for bad in [ciphertext, nonce] {
                assert_eq!(dek.decrypt(&bad, &aad).unwrap_err(), SecretError::Decrypt);
            }
        }

        #[test]
        fn every_aad_field_is_authenticated() {
            let dek = Dek::generate().unwrap();
            let aad = aad();
            let encrypted = dek.encrypt(&value("v"), &aad).unwrap();
            let variants = [
                Aad {
                    format_version: 2,
                    ..aad
                },
                Aad {
                    vault: VaultId::new(),
                    ..aad
                },
                Aad {
                    project: ProjectId::new(),
                    ..aad
                },
                Aad {
                    environment: EnvironmentId::new(),
                    ..aad
                },
                Aad {
                    key: KeyId::new(),
                    ..aad
                },
                Aad {
                    dek_version: 2,
                    ..aad
                },
                Aad { version: 2, ..aad },
            ];
            for other in variants {
                assert_eq!(
                    dek.decrypt(&encrypted, &other).unwrap_err(),
                    SecretError::Decrypt,
                    "{other:?}"
                );
            }
        }

        #[test]
        fn other_dek_cannot_decrypt() {
            let aad = aad();
            let encrypted = Dek::generate().unwrap().encrypt(&value("v"), &aad).unwrap();
            assert_eq!(
                Dek::generate()
                    .unwrap()
                    .decrypt(&encrypted, &aad)
                    .unwrap_err(),
                SecretError::Decrypt
            );
        }

        #[test]
        fn ciphertext_does_not_contain_plaintext() {
            let encrypted = Dek::generate()
                .unwrap()
                .encrypt(&value("PLAINTEXT-MARKER"), &aad())
                .unwrap();
            assert!(
                !encrypted
                    .ciphertext
                    .windows(16)
                    .any(|window| window == b"PLAINTEXT-MARKER")
            );
        }
    }
}
