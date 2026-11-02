use secrecy::SecretString;
use smart_env_vault::{Dek, DeviceKey, KeyError, KeyStore, MemoryStore, RecoveryKey, WrappedDek};

fn init(store: &impl KeyStore) -> (WrappedDek, SecretString) {
    let device = DeviceKey::generate();
    let (recovery, recovery_text) = RecoveryKey::generate();
    let envelope = Dek::generate()
        .unwrap()
        .wrap(&[&device.public(), &recovery.public()])
        .unwrap();
    store.save(&device).unwrap();
    (envelope, recovery_text)
}

#[test]
fn device_key_survives_restart_and_opens_envelope() {
    let store = MemoryStore::default();
    let (envelope, _) = init(&store);
    let device = store.load().unwrap().expect("key saved during init");
    assert!(Dek::unwrap(&envelope, &device).is_ok());
}

#[test]
fn recovery_key_restores_access_on_new_machine() {
    let (envelope, recovery_text) = init(&MemoryStore::default());

    let recovery = RecoveryKey::parse(&recovery_text).unwrap();
    let dek = Dek::unwrap(&envelope, &recovery).unwrap();
    let new_device = DeviceKey::generate();
    let new_envelope = dek.wrap(&[&new_device.public(), &recovery.public()]).unwrap();

    assert!(Dek::unwrap(&new_envelope, &new_device).is_ok());
}

#[test]
fn wrong_key_cannot_open_vault() {
    let (envelope, _) = init(&MemoryStore::default());
    assert_eq!(
        Dek::unwrap(&envelope, &DeviceKey::generate()).unwrap_err(),
        KeyError::Unwrap
    );
}