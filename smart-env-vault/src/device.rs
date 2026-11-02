#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_unique() {
        assert_ne!(DeviceKey::generate().public(), DeviceKey::generate().public());
    }

    #[test]
    fn public_key_uses_age_format() {
        assert!(DeviceKey::generate().public().to_string().starts_with("age1"));
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
        assert_eq!(DeviceKey::from_secret(&bad).unwrap_err(), KeyError::InvalidDeviceKey);
    }

    #[test]
    fn debug_shows_only_public_part() {
        let key = DeviceKey::generate();
        let debug = format!("{key:?}");
        assert!(!debug.contains("AGE-SECRET-KEY"));
        assert!(debug.contains(&key.public().to_string()));
    }
}