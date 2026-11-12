use crate::{Aad, EncryptedValue, KeyError, PublicKey, SecretError, SecretValue};
use age::{Decryptor, Encryptor};
use std::io::{Cursor, Read, Write};
use zeroize::Zeroizing;

pub struct Dek(pub(crate) Zeroizing<[u8; 32]>);

#[derive(Debug)]
pub struct WrappedDek(Vec<u8>);

pub trait Unwrapper {
    fn identity(&self) -> &dyn age::Identity;
}

impl Dek {
    pub fn generate() -> Result<Self, KeyError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| KeyError::Random)?;
        Ok(Self(bytes))
    }

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

    pub fn encrypt(&self, value: &SecretValue, aad: &Aad) -> Result<EncryptedValue, SecretError> {
        todo!()
    }

    pub fn decrypt(&self, value: &EncryptedValue, aad: &Aad) -> Result<SecretValue, SecretError> {
        todo!()
    }
}

impl WrappedDek {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

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
                Aad { format_version: 2, ..aad },
                Aad { vault: VaultId::new(), ..aad },
                Aad { project: ProjectId::new(), ..aad },
                Aad { environment: EnvironmentId::new(), ..aad },
                Aad { key: KeyId::new(), ..aad },
                Aad { dek_version: 2, ..aad },
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
            let encrypted = Dek::generate()
                .unwrap()
                .encrypt(&value("v"), &aad)
                .unwrap();
            assert_eq!(
                Dek::generate().unwrap().decrypt(&encrypted, &aad).unwrap_err(),
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