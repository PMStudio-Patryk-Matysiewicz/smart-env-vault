//! Real Linux kernel keyring; ignored by default like `keychain.rs`
//! (containers often block `add_key`/`keyctl`). Run with `--ignored`.

use smart_env_vault::{DeviceKey, KernelKeyringStore, KeyStore};
use std::time::Duration;

fn store(ttl: Duration) -> KernelKeyringStore {
    KernelKeyringStore::named(
        &format!("smart-env-test:{}:{:?}", std::process::id(), ttl),
        ttl,
    )
}

#[test]
#[ignore = "requires the Linux kernel keyring"]
fn kernel_keyring_round_trip() {
    let store = store(Duration::from_secs(60));
    let key = DeviceKey::generate();

    assert!(store.load().unwrap().is_none());
    store.save(&key).unwrap();
    assert_eq!(store.load().unwrap().unwrap().public(), key.public());
    store.delete().unwrap();
    assert!(store.load().unwrap().is_none());
    store.delete().unwrap(); // idempotent
}

#[test]
#[ignore = "requires the Linux kernel keyring"]
fn kernel_keyring_entry_expires() {
    let store = store(Duration::from_secs(1));
    store.save(&DeviceKey::generate()).unwrap();

    std::thread::sleep(Duration::from_millis(2_500));

    assert!(store.load().unwrap().is_none());
}

#[test]
#[ignore = "requires the Linux kernel keyring"]
fn saving_again_replaces_the_key() {
    let store = store(Duration::from_secs(60));
    let (first, second) = (DeviceKey::generate(), DeviceKey::generate());

    store.save(&first).unwrap();
    store.save(&second).unwrap();

    assert_eq!(store.load().unwrap().unwrap().public(), second.public());
    store.delete().unwrap();
}
