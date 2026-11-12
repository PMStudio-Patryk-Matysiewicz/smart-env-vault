use smart_env_vault::{DeviceKey, KeyStore, KeychainStore};

#[test]
#[ignore = "requires a system keychain (desktop session)"]
fn keychain_round_trip() {
    let store = KeychainStore::new(format!("test-{}", std::process::id()));
    let key = DeviceKey::generate();
    store.save(&key).unwrap();
    assert_eq!(store.load().unwrap().unwrap().public(), key.public());
    store.delete().unwrap();
}
