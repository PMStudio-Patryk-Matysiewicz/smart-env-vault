use smart_env_vault::DataPaths;
use tempfile::TempDir;

#[test]
fn initialize_should_create_directory_and_both_databases() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("data").join("smart-env");
    let paths = DataPaths::from_root(&root);

    let (_vault, _state) = paths.initialize().unwrap();

    assert!(paths.vault_db().exists());
    assert!(paths.state_db().exists());
}

#[test]
fn initialize_should_open_existing_databases_without_replacing_them() {
    let temp = TempDir::new().unwrap();
    let paths = DataPaths::from_root(temp.path().join("smart-env"));
    let (vault, _state) = paths.initialize().unwrap();
    let vault_id = vault.id();

    let (reopened, _state) = paths.initialize().unwrap();

    assert_eq!(reopened.id(), vault_id);
}

#[test]
fn from_root_should_return_vault_and_state_paths_below_directory() {
    let root = std::env::temp_dir().join("smart-env-test");
    let paths = DataPaths::from_root(&root);

    assert_eq!(paths.directory(), root);
    assert_eq!(paths.vault_db(), root.join("vault.db"));
    assert_eq!(paths.state_db(), root.join("state.db"));
}

#[test]
fn key_file_should_be_below_directory() {
    let root = std::env::temp_dir().join("smart-env-test");
    let paths = DataPaths::from_root(&root);

    assert_eq!(paths.key_file(), root.join("device.key"));
}

#[cfg(unix)]
#[test]
fn initialize_should_set_directory_permissions_to_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().unwrap();
    let root = temp.path().join("data").join("smart-env");
    let paths = DataPaths::from_root(&root);

    let _ = paths.initialize().unwrap();
    let mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;

    assert_eq!(mode, 0o700);
}
