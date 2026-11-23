//! Device key derived from one seed (ADR-002, A9). The reference vector is a
//! format test: it was computed outside this code (pure Python after RFC
//! 5869, 7748, 8032 and BIP-173), so changing labels or the text form fails it.

use secrecy::{ExposeSecret, SecretString};
use smart_env_vault::{DeviceKey, KeyError, RecoveryKey};

const SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const SEED_TEXT: &str =
    "se-device-seed-v1:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const X25519_PUBLIC: &str = "age13n70x9cenfdavw3kgjqkcxzqgmwk4dctlfjpcwrlfpnjuze2w9nqa3k025";
const ED25519_PUBLIC: &str = "7d827b7d392cf3b0dfe1ffe6d643a741080e1c0ce24db451ea14d730575593c3";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn secret(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

#[test]
fn seed_derives_reference_keys() {
    let key = DeviceKey::from_seed(SEED);

    assert_eq!(key.public().to_string(), X25519_PUBLIC);
    assert_eq!(hex(key.signing_public().as_bytes()), ED25519_PUBLIC);
}

#[test]
fn text_form_is_versioned_hex_seed() {
    assert_eq!(
        DeviceKey::from_seed(SEED).to_secret().expose_secret(),
        SEED_TEXT
    );
}

#[test]
fn text_form_restores_both_keys() {
    let key = DeviceKey::from_secret(&secret(SEED_TEXT)).unwrap();

    assert_eq!(key.public().to_string(), X25519_PUBLIC);
    assert_eq!(hex(key.signing_public().as_bytes()), ED25519_PUBLIC);
}

#[test]
fn generated_key_round_trips_through_text() {
    let key = DeviceKey::generate();
    let restored = DeviceKey::from_secret(&key.to_secret()).unwrap();

    assert!(
        key.to_secret()
            .expose_secret()
            .starts_with("se-device-seed-v1:")
    );
    assert_eq!(restored.public(), key.public());
    assert_eq!(restored.signing_public(), key.signing_public());
}

#[test]
fn generated_keys_differ() {
    let (a, b) = (DeviceKey::generate(), DeviceKey::generate());

    assert_ne!(a.public(), b.public());
    assert_ne!(a.signing_public(), b.signing_public());
}

#[test]
fn rejects_other_text_forms() {
    // A valid `age` identity (the pre-A9 device key format) must be refused.
    let (_, age_identity) = RecoveryKey::generate();
    let cases = [
        age_identity.expose_secret().to_owned(),
        SEED_TEXT.replace("-v1:", "-v2:"),
        SEED_TEXT.to_uppercase(),
        SEED_TEXT[..SEED_TEXT.len() - 2].to_owned(),
        format!("{SEED_TEXT}00"),
        SEED_TEXT.replace("1f", "zz"),
        format!(" {SEED_TEXT}"),
        String::new(),
    ];
    for text in cases {
        assert_eq!(
            DeviceKey::from_secret(&secret(&text)).unwrap_err(),
            KeyError::InvalidDeviceKey,
            "{text:?}"
        );
    }
}

#[test]
fn signature_verifies_with_own_key_only() {
    let key = DeviceKey::from_seed(SEED);
    let other = DeviceKey::generate();
    let signature = key.sign(b"attest device");

    assert!(key.signing_public().verify(b"attest device", &signature));
    assert!(!key.signing_public().verify(b"attest device!", &signature));
    assert!(!other.signing_public().verify(b"attest device", &signature));
}

#[test]
fn debug_hides_seed() {
    let debug = format!("{:?}", DeviceKey::from_seed(SEED));

    assert!(!debug.contains("000102030405"));
    assert!(!debug.contains("se-device-seed"));
}
