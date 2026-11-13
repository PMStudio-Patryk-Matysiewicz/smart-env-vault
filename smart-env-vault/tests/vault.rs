use rusqlite::{Connection, params};
use smart_env_vault::{
    Dek, DeviceKey, EnvKind, EnvironmentId, HISTORY_LIMIT, KeyError, ProjectId, Recipient,
    RecipientId, RecipientKind, RecoveryKey, SecretError, SecretValue, SetOutcome, VarName, Vault,
    VaultError, WrappedDek,
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
    device_id: RecipientId,
    recovery_id: RecipientId,
}

/// Vault with recipients "laptop" (device) and "recovery", project "payments" and environment "dev".
fn setup() -> Fixture {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.db");
    let device = DeviceKey::generate();
    let (recovery, _) = RecoveryKey::generate();
    let mut vault = Vault::create(&path).unwrap();
    let device_id = vault
        .add_recipient(RecipientKind::Device, "laptop", &device.public(), &device)
        .unwrap();
    let recovery_id = vault
        .add_recipient(
            RecipientKind::Recovery,
            "recovery",
            &recovery.public(),
            &device,
        )
        .unwrap();
    let project = vault.create_project("payments").unwrap();
    let env = vault
        .create_environment(project, "dev", EnvKind::Dev)
        .unwrap();
    Fixture {
        dir,
        path,
        vault,
        project,
        env,
        device,
        recovery,
        device_id,
        recovery_id,
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
    let result = fixture
        .vault
        .create_environment(ProjectId::new(), "dev", EnvKind::Dev);
    assert!(matches!(err(result), VaultError::NotFound));
}

#[test]
fn duplicate_environment_name_is_taken() {
    let mut fixture = setup();
    let result = fixture
        .vault
        .create_environment(fixture.project, "dev", EnvKind::Dev);
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
    assert_eq!(first.key_id, second.key_id);
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
        .create_environment(f.project, "staging", EnvKind::Staging)
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
        .unwrap()
        .key_id;
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

fn put(f: &mut Fixture, var: &str, text: &str) -> SetOutcome {
    f.vault
        .set(f.env, &name(var), &value(text), &f.device)
        .unwrap()
}

fn read(f: &Fixture, var: &str) -> Option<String> {
    f.vault
        .get(f.env, &name(var), &f.device)
        .unwrap()
        .map(|v| v.expose().to_owned())
}

fn revision(f: &Fixture) -> u64 {
    f.vault.revision(f.env).unwrap()
}

fn versions(f: &Fixture, var: &str) -> Vec<u32> {
    f.vault
        .history(f.env, &name(var))
        .unwrap()
        .into_iter()
        .map(|meta| meta.version)
        .collect()
}

/// Number of rows in `secret_versions`, read directly from the file.
fn history_rows(path: &Path) -> i64 {
    raw(path)
        .query_row("SELECT count(*) FROM secret_versions", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn versions_grow_with_each_set() {
    let mut f = setup();
    let first = put(&mut f, "A", "a");
    let second = put(&mut f, "A", "b");
    let third = put(&mut f, "A", "b"); // same value → still a new version
    assert_eq!([first.version, second.version, third.version], [1, 2, 3]);
    assert_eq!(first.key_id, third.key_id);
    assert_eq!(read(&f, "A").as_deref(), Some("b"));
}

#[test]
fn every_change_bumps_revision_exactly_once() {
    let mut f = setup();
    assert_eq!(revision(&f), 0);
    put(&mut f, "A", "a");
    assert_eq!(revision(&f), 1);
    put(&mut f, "A", "b");
    assert_eq!(revision(&f), 2);
    f.vault.rename(f.env, &name("A"), &name("B")).unwrap();
    assert_eq!(revision(&f), 3);
    assert!(f.vault.remove(f.env, &name("B")).unwrap());
    assert_eq!(revision(&f), 4);
    assert!(!f.vault.remove(f.env, &name("NOPE")).unwrap());
    assert_eq!(revision(&f), 4);
}

#[test]
fn revision_is_per_environment() {
    let mut f = setup();
    let staging = f
        .vault
        .create_environment(f.project, "staging", EnvKind::Staging)
        .unwrap();
    put(&mut f, "A", "a");
    assert_eq!(f.vault.revision(staging).unwrap(), 0);
}

#[test]
fn wrong_key_set_does_not_bump_revision() {
    let mut f = setup();
    put(&mut f, "A", "a");
    let result = f
        .vault
        .set(f.env, &name("A"), &value("evil"), &DeviceKey::generate());
    assert!(matches!(err(result), VaultError::Key(KeyError::Unwrap)));
    assert_eq!(revision(&f), 1);
}

#[test]
fn rename_keeps_version_and_value() {
    let mut f = setup();
    put(&mut f, "OLD", "a");
    put(&mut f, "OLD", "b");
    f.vault.rename(f.env, &name("OLD"), &name("NEW")).unwrap();
    assert_eq!(read(&f, "NEW").as_deref(), Some("b"));
    assert_eq!(f.vault.list(f.env).unwrap()[0].version, 2);
}

#[test]
fn revision_of_unknown_environment_is_not_found() {
    let f = setup();
    assert!(matches!(
        err(f.vault.revision(EnvironmentId::new())),
        VaultError::NotFound
    ));
}

#[test]
fn history_lists_current_and_previous_versions_newest_first() {
    let mut f = setup();
    for text in ["v1", "v2", "v3"] {
        put(&mut f, "A", text);
    }
    assert_eq!(versions(&f, "A"), [3, 2, 1]);
}

#[test]
fn history_is_capped_at_limit() {
    let mut f = setup();
    for i in 1..=12 {
        put(&mut f, "A", &format!("v{i}"));
    }
    let expected: Vec<u32> = (2..=12).rev().collect();
    assert_eq!(expected.len(), HISTORY_LIMIT + 1);
    assert_eq!(versions(&f, "A"), expected);
    assert_eq!(history_rows(&f.path), HISTORY_LIMIT as i64);
}

#[test]
fn history_never_stores_plaintext() {
    let mut f = setup();
    let markers: Vec<String> = (1..=12)
        .map(|i| format!("PLAINTEXT-MARKER-{i:02}"))
        .collect();
    for marker in &markers {
        put(&mut f, "A", marker);
    }
    assert_eq!(versions(&f, "A").len(), HISTORY_LIMIT + 1);
    let Fixture { dir, vault, .. } = f;
    drop(vault);

    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        let bytes = std::fs::read(&path).unwrap();
        for marker in &markers {
            assert!(
                !bytes.windows(marker.len()).any(|w| w == marker.as_bytes()),
                "{marker} found in {}",
                path.display()
            );
        }
    }
}

#[test]
fn old_version_swapped_in_as_current_is_rejected() {
    let mut f = setup();
    let outcome = put(&mut f, "A", "a");
    put(&mut f, "A", "b");
    // An attacker with disk access puts the version-1 ciphertext back as current.
    let old: (Vec<u8>, Vec<u8>) = raw(&f.path)
        .query_row(
            "SELECT nonce, ciphertext FROM secret_versions WHERE key_id = ?1 AND version = 1",
            [&outcome.key_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    reseal(&f.path, f.env, "A", &old);

    let result = f.vault.get(f.env, &name("A"), &f.device);
    assert!(matches!(
        err(result),
        VaultError::Secret(SecretError::Decrypt)
    ));
}

#[test]
fn history_of_missing_secret_is_not_found() {
    let f = setup();
    assert!(matches!(
        err(f.vault.history(f.env, &name("NOPE"))),
        VaultError::NotFound
    ));
}

#[test]
fn undo_restores_previous_value_as_new_version() {
    let mut f = setup();
    put(&mut f, "A", "a");
    put(&mut f, "A", "b");
    assert_eq!(f.vault.undo(f.env, &name("A"), &f.device).unwrap(), 3);
    assert_eq!(read(&f, "A").as_deref(), Some("a"));
    assert_eq!(versions(&f, "A"), [3, 2, 1]);
    assert_eq!(revision(&f), 3);
}

#[test]
fn second_undo_reverts_the_first() {
    let mut f = setup();
    put(&mut f, "A", "a");
    put(&mut f, "A", "b");
    f.vault.undo(f.env, &name("A"), &f.device).unwrap();
    assert_eq!(f.vault.undo(f.env, &name("A"), &f.device).unwrap(), 4);
    assert_eq!(read(&f, "A").as_deref(), Some("b"));
}

#[test]
fn removed_secret_is_hidden_but_kept() {
    let mut f = setup();
    put(&mut f, "A", "a");
    assert!(f.vault.remove(f.env, &name("A")).unwrap());
    assert_eq!(read(&f, "A"), None);
    assert!(f.vault.list(f.env).unwrap().is_empty());
    assert!(matches!(
        err(f.vault.history(f.env, &name("A"))),
        VaultError::NotFound
    ));
    assert_eq!(rows(&f.path).len(), 1, "soft delete keeps the row");
}

#[test]
fn undo_after_remove_restores_secret() {
    let mut f = setup();
    put(&mut f, "A", "a");
    f.vault.remove(f.env, &name("A")).unwrap();
    assert_eq!(f.vault.undo(f.env, &name("A"), &f.device).unwrap(), 1);
    assert_eq!(read(&f, "A").as_deref(), Some("a"));
    assert_eq!(revision(&f), 3);
}

#[test]
fn undo_without_history_fails() {
    let mut f = setup();
    put(&mut f, "A", "a");
    assert!(matches!(
        err(f.vault.undo(f.env, &name("A"), &f.device)),
        VaultError::NothingToUndo
    ));
    assert_eq!(revision(&f), 1);
}

#[test]
fn undo_of_missing_secret_is_not_found() {
    let mut f = setup();
    assert!(matches!(
        err(f.vault.undo(f.env, &name("NOPE"), &f.device)),
        VaultError::NotFound
    ));
}

#[test]
fn undo_after_purge_is_not_found() {
    let mut f = setup();
    put(&mut f, "A", "a");
    put(&mut f, "A", "b");
    assert!(f.vault.purge(f.env, &name("A")).unwrap());
    assert!(matches!(
        err(f.vault.undo(f.env, &name("A"), &f.device)),
        VaultError::NotFound
    ));
}

#[test]
fn wrong_key_undo_changes_nothing() {
    let mut f = setup();
    put(&mut f, "A", "a");
    put(&mut f, "A", "b");
    let before = (rows(&f.path), history_rows(&f.path), revision(&f));

    let result = f.vault.undo(f.env, &name("A"), &DeviceKey::generate());
    assert!(matches!(err(result), VaultError::Key(KeyError::Unwrap)));

    assert_eq!((rows(&f.path), history_rows(&f.path), revision(&f)), before);
    assert_eq!(read(&f, "A").as_deref(), Some("b"));
}

#[test]
fn set_on_removed_name_resurrects_with_history() {
    let mut f = setup();
    let first = put(&mut f, "A", "a");
    f.vault.remove(f.env, &name("A")).unwrap();
    let second = put(&mut f, "A", "b");
    assert_eq!(second.key_id, first.key_id);
    assert_eq!(second.version, 2);
    f.vault.undo(f.env, &name("A"), &f.device).unwrap();
    assert_eq!(read(&f, "A").as_deref(), Some("a"));
}

#[test]
fn rename_onto_removed_name_is_taken() {
    let mut f = setup();
    put(&mut f, "A", "a");
    put(&mut f, "B", "b");
    f.vault.remove(f.env, &name("B")).unwrap();

    let result = f.vault.rename(f.env, &name("A"), &name("B"));
    assert!(matches!(err(result), VaultError::NameTaken));

    f.vault.undo(f.env, &name("B"), &f.device).unwrap();
    assert_eq!(read(&f, "A").as_deref(), Some("a"));
    assert_eq!(read(&f, "B").as_deref(), Some("b"));
}

#[test]
fn rename_of_removed_secret_is_not_found() {
    let mut f = setup();
    put(&mut f, "A", "a");
    f.vault.remove(f.env, &name("A")).unwrap();
    let result = f.vault.rename(f.env, &name("A"), &name("B"));
    assert!(matches!(err(result), VaultError::NotFound));
}

#[test]
fn purge_removes_secret_and_history() {
    let mut f = setup();
    for text in ["a", "b", "c"] {
        put(&mut f, "A", text);
    }
    assert!(f.vault.purge(f.env, &name("A")).unwrap());
    assert!(matches!(
        err(f.vault.history(f.env, &name("A"))),
        VaultError::NotFound
    ));
    assert!(rows(&f.path).is_empty());
    assert_eq!(history_rows(&f.path), 0);
    assert_eq!(revision(&f), 4);
    assert!(!f.vault.purge(f.env, &name("A")).unwrap());
    assert_eq!(revision(&f), 4);
}

#[test]
fn purge_works_on_removed_secret() {
    let mut f = setup();
    put(&mut f, "A", "a");
    f.vault.remove(f.env, &name("A")).unwrap();
    assert!(f.vault.purge(f.env, &name("A")).unwrap());
    assert!(rows(&f.path).is_empty());
}

// --- A2: recipients and per-recipient wraps -----------------------------------

/// (kind, label, revoked) of every recipient, for compact assertions.
fn summary(recipients: Vec<Recipient>) -> Vec<(RecipientKind, String, bool)> {
    recipients
        .into_iter()
        .map(|r| (r.kind, r.label, r.revoked))
        .collect()
}

fn labels(recipients: Vec<Recipient>) -> Vec<String> {
    recipients.into_iter().map(|r| r.label).collect()
}

/// Number of rows in `dek_wraps`, read directly from the file.
fn wrap_rows(path: &Path) -> i64 {
    raw(path)
        .query_row("SELECT count(*) FROM dek_wraps", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn new_environment_is_wrapped_for_every_active_recipient() {
    let mut f = setup();
    put(&mut f, "A", "a");
    let by_recovery = f.vault.get(f.env, &name("A"), &f.recovery).unwrap();
    assert_eq!(by_recovery.unwrap().expose(), "a");
    assert_eq!(
        labels(f.vault.environment_recipients(f.env).unwrap()),
        ["laptop", "recovery"]
    );
}

#[test]
fn each_wrap_opens_only_with_its_recipient_key() {
    let f = setup();
    assert_eq!(wrap_rows(&f.path), 2);
    let device_wrap: Vec<u8> = raw(&f.path)
        .query_row(
            "SELECT w.wrapped FROM dek_wraps w JOIN recipients r ON r.id = w.recipient_id
              WHERE r.label = 'laptop'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let envelope = WrappedDek::from_bytes(device_wrap);
    assert!(Dek::unwrap(&envelope, &f.device).is_ok());
    assert_eq!(
        Dek::unwrap(&envelope, &f.recovery).unwrap_err(),
        KeyError::Unwrap
    );
}

#[test]
fn revoked_recipient_gets_no_wrap_for_new_environment() {
    let mut f = setup();
    f.vault.revoke_recipient(f.recovery_id).unwrap();
    let staging = f
        .vault
        .create_environment(f.project, "staging", EnvKind::Staging)
        .unwrap();
    f.vault
        .set(staging, &name("A"), &value("s"), &f.device)
        .unwrap();

    let result = f.vault.get(staging, &name("A"), &f.recovery);
    assert!(matches!(err(result), VaultError::Key(KeyError::Unwrap)));
    assert_eq!(
        labels(f.vault.environment_recipients(staging).unwrap()),
        ["laptop"]
    );
}

#[test]
fn revoked_recipient_keeps_existing_wraps_until_rotation() {
    let mut f = setup();
    put(&mut f, "A", "a");
    f.vault.revoke_recipient(f.recovery_id).unwrap();

    let back = f.vault.get(f.env, &name("A"), &f.recovery).unwrap();
    assert_eq!(back.unwrap().expose(), "a");
    let recovery = f
        .vault
        .environment_recipients(f.env)
        .unwrap()
        .into_iter()
        .find(|r| r.id == f.recovery_id)
        .unwrap();
    assert!(recovery.revoked);
}

#[test]
fn adding_recipient_wraps_existing_environments() {
    let mut f = setup();
    put(&mut f, "A", "a");
    let machine = DeviceKey::generate();
    f.vault
        .add_recipient(RecipientKind::Machine, "ci", &machine.public(), &f.device)
        .unwrap();

    let back = f.vault.get(f.env, &name("A"), &machine).unwrap();
    assert_eq!(back.unwrap().expose(), "a");
    assert_eq!(
        labels(f.vault.environment_recipients(f.env).unwrap()),
        ["laptop", "recovery", "ci"]
    );
}

#[test]
fn add_recipient_with_foreign_key_changes_nothing() {
    let mut f = setup();
    let before = summary(f.vault.recipients().unwrap());
    let intruder = DeviceKey::generate();

    let result = f.vault.add_recipient(
        RecipientKind::Device,
        "intruder",
        &intruder.public(),
        &intruder,
    );
    assert!(matches!(err(result), VaultError::Key(KeyError::Unwrap)));
    assert_eq!(summary(f.vault.recipients().unwrap()), before);
    assert_eq!(wrap_rows(&f.path), 2);
}

#[test]
fn environment_needs_an_active_recipient() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.db");
    let mut vault = Vault::create(&path).unwrap();
    let project = vault.create_project("payments").unwrap();
    let no_recipients = vault.create_environment(project, "dev", EnvKind::Dev);
    assert!(matches!(err(no_recipients), VaultError::NoRecipients));

    let device = DeviceKey::generate();
    let id = vault
        .add_recipient(RecipientKind::Device, "laptop", &device.public(), &device)
        .unwrap();
    vault.revoke_recipient(id).unwrap();
    let only_revoked = vault.create_environment(project, "dev", EnvKind::Dev);
    assert!(matches!(err(only_revoked), VaultError::NoRecipients));

    let environments: i64 = raw(&path)
        .query_row("SELECT count(*) FROM environments", [], |row| row.get(0))
        .unwrap();
    assert_eq!(environments, 0);
}

#[test]
fn duplicate_public_key_is_taken() {
    let mut f = setup();
    let result = f.vault.add_recipient(
        RecipientKind::Machine,
        "again",
        &f.device.public(),
        &f.device,
    );
    assert!(matches!(err(result), VaultError::NameTaken));
    assert_eq!(f.vault.recipients().unwrap().len(), 2);
}

#[test]
fn revoke_unknown_recipient_is_not_found() {
    let mut f = setup();
    assert!(matches!(
        err(f.vault.revoke_recipient(RecipientId::new())),
        VaultError::NotFound
    ));
}

#[test]
fn recipients_lists_kind_label_and_state() {
    let mut f = setup();
    assert_eq!(
        summary(f.vault.recipients().unwrap()),
        [
            (RecipientKind::Device, "laptop".to_owned(), false),
            (RecipientKind::Recovery, "recovery".to_owned(), false),
        ]
    );
    f.vault.revoke_recipient(f.recovery_id).unwrap();
    f.vault.revoke_recipient(f.recovery_id).unwrap(); // second revoke is a no-op
    let recipients = f.vault.recipients().unwrap();
    assert_eq!(recipients[0].id, f.device_id);
    assert_eq!(recipients[0].public_key, f.device.public());
    assert!(recipients[1].revoked);
}

#[test]
fn secret_without_wrap_for_key_is_unwrap_error_not_none() {
    let mut f = setup();
    put(&mut f, "A", "a");
    let result = f.vault.get(f.env, &name("A"), &DeviceKey::generate());
    assert!(matches!(err(result), VaultError::Key(KeyError::Unwrap)));
}
