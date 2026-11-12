use rusqlite::{Connection, params};
use smart_env_vault::{
    DeviceKey, EnvKind, EnvironmentId, KeyError, ProjectId, RecoveryKey, SecretError, SecretValue,
    VarName, Vault, VaultError,
};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

struct Fixture {
    dir: TempDir,
    path: PathBuf,
    vault: Vault,
    project: ProjectId,
    env: EnvironmentId,
    device: DeviceKey,
    recovery: RecoveryKey,
}

/// Vault with project "payments" and environment "dev" wrapped for a device and a recovery key.
fn setup() -> Fixture {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.db");
    let device = DeviceKey::generate();
    let (recovery, _) = RecoveryKey::generate();
    let mut vault = Vault::create(&path).unwrap();
    let project = vault.create_project("payments").unwrap();
    let env = vault
        .create_environment(
            project,
            "dev",
            EnvKind::Dev,
            &[&device.public(), &recovery.public()],
        )
        .unwrap();
    Fixture {
        dir,
        path,
        vault,
        project,
        env,
        device,
        recovery,
    }
}

fn name(text: &str) -> VarName {
    VarName::parse(text).unwrap()
}

fn value(text: &str) -> SecretValue {
    SecretValue::new(text.to_owned()).unwrap()
}

fn err<T>(result: Result<T, VaultError>) -> VaultError {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(error) => error,
    }
}

/// Direct access to the database file, bypassing `Vault` (simulates an attacker with disk access).
fn raw(path: &Path) -> Connection {
    Connection::open(path).unwrap()
}

/// (key_id, nonce, ciphertext) of every secret, ordered by key_id.
fn rows(path: &Path) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let db = raw(path);
    let mut statement = db
        .prepare("SELECT key_id, nonce, ciphertext FROM secrets ORDER BY key_id")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

/// (nonce, ciphertext) of a secret identified by environment and name.
fn sealed(path: &Path, env: EnvironmentId, var: &str) -> (Vec<u8>, Vec<u8>) {
    raw(path)
        .query_row(
            "SELECT nonce, ciphertext FROM secrets WHERE environment_id = ?1 AND name = ?2",
            params![&env, var],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn reseal(path: &Path, env: EnvironmentId, var: &str, (nonce, ciphertext): &(Vec<u8>, Vec<u8>)) {
    raw(path)
        .execute(
            "UPDATE secrets SET nonce = ?3, ciphertext = ?4 WHERE environment_id = ?1 AND name = ?2",
            params![&env, var, nonce, ciphertext],
        )
        .unwrap();
}

// --- Vault lifecycle -------------------------------------------------------

#[cfg(unix)]
#[test]
fn create_makes_file_readable_only_by_owner() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = setup();
    let mode = std::fs::metadata(&fixture.path)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn create_refuses_existing_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.db");
    std::fs::write(&path, "keep").unwrap();
    assert!(matches!(
        err(Vault::create(&path)),
        VaultError::AlreadyExists
    ));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep");
}

#[test]
fn open_returns_same_vault_id() {
    let fixture = setup();
    let id = fixture.vault.id();
    drop(fixture.vault);
    assert_eq!(Vault::open(&fixture.path).unwrap().id(), id);
}

#[test]
fn open_missing_path_fails_without_creating_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("missing.db");
    assert!(Vault::open(&path).is_err());
    assert!(!path.exists());
}

#[test]
fn open_rejects_non_vault_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.db");
    std::fs::write(&path, "hello").unwrap();
    assert!(matches!(
        err(Vault::open(&path)),
        VaultError::UnsupportedSchema
    ));
}

#[test]
fn environment_in_unknown_project_is_not_found() {
    let mut fixture = setup();
    let result = fixture.vault.create_environment(
        ProjectId::new(),
        "dev",
        EnvKind::Dev,
        &[&fixture.device.public()],
    );
    assert!(matches!(err(result), VaultError::NotFound));
}

#[test]
fn duplicate_environment_name_is_taken() {
    let mut fixture = setup();
    let result = fixture.vault.create_environment(
        fixture.project,
        "dev",
        EnvKind::Dev,
        &[&fixture.device.public()],
    );
    assert!(matches!(err(result), VaultError::NameTaken));
}

// --- Secrets ---------------------------------------------------------------

#[test]
fn set_then_get_round_trips() {
    let mut f = setup();
    let big = "x".repeat(65_536);
    for (var, text) in [
        ("URL", "postgres://u:p@h/db"),
        ("UNICODE", "zażółć 🔑"),
        ("EMPTY", ""),
        ("BIG", big.as_str()),
    ] {
        f.vault
            .set(f.env, &name(var), &value(text), &f.device)
            .unwrap();
        let back = f.vault.get(f.env, &name(var), &f.device).unwrap().unwrap();
        assert_eq!(back.expose(), text, "{var}");
    }
}

#[test]
fn get_missing_returns_none() {
    let f = setup();
    assert!(
        f.vault
            .get(f.env, &name("NOPE"), &f.device)
            .unwrap()
            .is_none()
    );
}

#[test]
fn overwrite_keeps_key_id_and_changes_nonce() {
    let mut f = setup();
    let first = f
        .vault
        .set(f.env, &name("A"), &value("v"), &f.device)
        .unwrap();
    let before = sealed(&f.path, f.env, "A");
    let second = f
        .vault
        .set(f.env, &name("A"), &value("v"), &f.device)
        .unwrap();
    let after = sealed(&f.path, f.env, "A");
    assert_eq!(first, second);
    assert_ne!(before.0, after.0);
    assert_ne!(before.1, after.1);
}

#[test]
fn recovery_key_reads_what_device_wrote() {
    let mut f = setup();
    f.vault
        .set(f.env, &name("A"), &value("v"), &f.device)
        .unwrap();
    let back = f
        .vault
        .get(f.env, &name("A"), &f.recovery)
        .unwrap()
        .unwrap();
    assert_eq!(back.expose(), "v");
}

#[test]
fn wrong_key_cannot_read() {
    let mut f = setup();
    f.vault
        .set(f.env, &name("A"), &value("v"), &f.device)
        .unwrap();
    let result = f.vault.get(f.env, &name("A"), &DeviceKey::generate());
    assert!(matches!(err(result), VaultError::Key(KeyError::Unwrap)));
}

#[test]
fn wrong_key_write_changes_nothing() {
    let mut f = setup();
    f.vault
        .set(f.env, &name("A"), &value("v"), &f.device)
        .unwrap();
    let before = rows(&f.path);
    let intruder = DeviceKey::generate();

    for var in ["A", "NEW"] {
        let result = f.vault.set(f.env, &name(var), &value("evil"), &intruder);
        assert!(
            matches!(err(result), VaultError::Key(KeyError::Unwrap)),
            "{var}"
        );
    }
    assert_eq!(rows(&f.path), before);
}

#[test]
fn ciphertext_swapped_between_keys_fails() {
    let mut f = setup();
    f.vault
        .set(f.env, &name("A"), &value("a"), &f.device)
        .unwrap();
    f.vault
        .set(f.env, &name("B"), &value("b"), &f.device)
        .unwrap();
    let (a, b) = (sealed(&f.path, f.env, "A"), sealed(&f.path, f.env, "B"));
    reseal(&f.path, f.env, "A", &b);
    reseal(&f.path, f.env, "B", &a);

    let result = f.vault.get(f.env, &name("A"), &f.device);
    assert!(matches!(
        err(result),
        VaultError::Secret(SecretError::Decrypt)
    ));
}

#[test]
fn ciphertext_moved_to_other_environment_fails() {
    let mut f = setup();
    let staging = f
        .vault
        .create_environment(
            f.project,
            "staging",
            EnvKind::Staging,
            &[&f.device.public(), &f.recovery.public()],
        )
        .unwrap();
    f.vault
        .set(f.env, &name("A"), &value("dev"), &f.device)
        .unwrap();
    f.vault
        .set(staging, &name("A"), &value("staging"), &f.device)
        .unwrap();
    reseal(&f.path, staging, "A", &sealed(&f.path, f.env, "A"));

    let result = f.vault.get(staging, &name("A"), &f.device);
    assert!(matches!(
        err(result),
        VaultError::Secret(SecretError::Decrypt)
    ));
}

#[test]
fn plaintext_never_reaches_disk() {
    let marker = "PLAINTEXT-MARKER-7f3a";
    let Fixture {
        dir,
        mut vault,
        env,
        device,
        ..
    } = setup();
    vault.set(env, &name("A"), &value(marker), &device).unwrap();
    drop(vault);

    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.windows(marker.len()).any(|w| w == marker.as_bytes()),
            "plaintext found in {}",
            path.display()
        );
    }
}

#[test]
fn list_returns_sorted_names_without_key() {
    let mut f = setup();
    for var in ["ZETA", "ALPHA", "MID"] {
        f.vault
            .set(f.env, &name(var), &value("v"), &f.device)
            .unwrap();
    }
    let names: Vec<String> = f
        .vault
        .list(f.env)
        .unwrap()
        .into_iter()
        .map(|meta| meta.name.to_string())
        .collect();
    assert_eq!(names, ["ALPHA", "MID", "ZETA"]);
}

#[test]
fn names_are_case_sensitive() {
    let mut f = setup();
    f.vault
        .set(f.env, &name("DB_URL"), &value("upper"), &f.device)
        .unwrap();
    f.vault
        .set(f.env, &name("db_url"), &value("lower"), &f.device)
        .unwrap();
    let get = |var| f.vault.get(f.env, &name(var), &f.device).unwrap().unwrap();
    assert_eq!(get("DB_URL").expose(), "upper");
    assert_eq!(get("db_url").expose(), "lower");
}

#[test]
fn remove_reports_whether_secret_existed() {
    let mut f = setup();
    f.vault
        .set(f.env, &name("A"), &value("v"), &f.device)
        .unwrap();
    assert!(f.vault.remove(f.env, &name("A")).unwrap());
    assert!(!f.vault.remove(f.env, &name("A")).unwrap());
    assert!(f.vault.get(f.env, &name("A"), &f.device).unwrap().is_none());
}

#[test]
fn rename_keeps_ciphertext_and_value() {
    let mut f = setup();
    let key_id = f
        .vault
        .set(f.env, &name("OLD"), &value("v"), &f.device)
        .unwrap();
    let before = sealed(&f.path, f.env, "OLD");

    f.vault.rename(f.env, &name("OLD"), &name("NEW")).unwrap();

    assert_eq!(sealed(&f.path, f.env, "NEW"), before);
    assert_eq!(f.vault.list(f.env).unwrap()[0].key_id, key_id);
    let back = f
        .vault
        .get(f.env, &name("NEW"), &f.device)
        .unwrap()
        .unwrap();
    assert_eq!(back.expose(), "v");
    assert!(
        f.vault
            .get(f.env, &name("OLD"), &f.device)
            .unwrap()
            .is_none()
    );
}

#[test]
fn rename_onto_existing_name_is_taken() {
    let mut f = setup();
    f.vault
        .set(f.env, &name("A"), &value("a"), &f.device)
        .unwrap();
    f.vault
        .set(f.env, &name("B"), &value("b"), &f.device)
        .unwrap();

    let result = f.vault.rename(f.env, &name("A"), &name("B"));
    assert!(matches!(err(result), VaultError::NameTaken));

    let get = |var| f.vault.get(f.env, &name(var), &f.device).unwrap().unwrap();
    assert_eq!(get("A").expose(), "a");
    assert_eq!(get("B").expose(), "b");
}

#[test]
fn rename_missing_secret_is_not_found() {
    let mut f = setup();
    let result = f.vault.rename(f.env, &name("NOPE"), &name("OTHER"));
    assert!(matches!(err(result), VaultError::NotFound));
}
