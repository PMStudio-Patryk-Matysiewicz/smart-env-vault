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
        let wrapped = Dek::generate().unwrap().wrap(&[&DeviceKey::generate().public()]).unwrap();
        assert_eq!(Dek::unwrap(&wrapped, &DeviceKey::generate()).unwrap_err(), KeyError::Unwrap);
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
        assert_eq!(Dek::generate().unwrap().wrap(&[]).unwrap_err(), KeyError::Wrap);
    }

    #[test]
    fn envelope_does_not_contain_plain_dek() {
        let dek = Dek::generate().unwrap();
        let wrapped = dek.wrap(&[&DeviceKey::generate().public()]).unwrap();
        assert!(!wrapped.as_bytes().windows(32).any(|w| w == dek.0.as_slice()));
    }

    #[test]
    fn debug_does_not_reveal_bytes() {
        assert_eq!(format!("{:?}", Dek::generate().unwrap()), "Dek(..)");
    }
}