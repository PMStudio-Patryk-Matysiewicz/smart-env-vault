use crate::{KeyError, PublicKey};
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
}