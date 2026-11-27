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

// --- state: shell hook trust (allow / deny) ---

use smart_env_vault::{DataPathsError, ProjectId, TrustDecision};
use std::path::Path;

fn allowed(byte: u8) -> TrustDecision {
    TrustDecision::Allowed {
        file_hash: [byte; 32],
        project_id: "0b9e6d3c-5f1a-4c8e-9d2b-7a6e1f3c8b40"
            .parse::<ProjectId>()
            .unwrap(),
    }
}

/// A state database as `setup` wrote it before schema 2: version only.
fn state_v1(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.pragma_update(None, "user_version", 1).unwrap();
}

#[test]
fn state_creates_a_missing_state_database() {
    let temp = TempDir::new().unwrap();
    let paths = DataPaths::from_root(temp.path().join("smart-env"));

    let state = paths.state().unwrap();

    assert!(paths.state_db().exists());
    assert_eq!(state.trust(Path::new("/code/payments")).unwrap(), None);
}

#[test]
fn trust_decisions_are_stored_per_directory_and_replaced() {
    let temp = TempDir::new().unwrap();
    let paths = DataPaths::from_root(temp.path().join("smart-env"));
    let state = paths.state().unwrap();
    let payments = Path::new("/code/payments");
    let billing = Path::new("/code/billing");

    state.set_trust(payments, &allowed(1)).unwrap();
    state.set_trust(billing, &TrustDecision::Denied).unwrap();
    assert_eq!(state.trust(payments).unwrap(), Some(allowed(1)));
    assert_eq!(state.trust(billing).unwrap(), Some(TrustDecision::Denied));

    state.set_trust(payments, &allowed(2)).unwrap();
    state.set_trust(billing, &allowed(3)).unwrap();
    let reopened = paths.state().unwrap();
    assert_eq!(reopened.trust(payments).unwrap(), Some(allowed(2)));
    assert_eq!(reopened.trust(billing).unwrap(), Some(allowed(3)));

    state.set_trust(payments, &TrustDecision::Denied).unwrap();
    assert_eq!(state.trust(payments).unwrap(), Some(TrustDecision::Denied));
    assert_eq!(state.trust(Path::new("/code")).unwrap(), None);
}

#[test]
fn paths_are_compared_exactly() {
    let temp = TempDir::new().unwrap();
    let state = DataPaths::from_root(temp.path().join("smart-env"))
        .state()
        .unwrap();
    state
        .set_trust(Path::new("/code/payments"), &allowed(1))
        .unwrap();

    for other in ["/code/payments/", "/code/Payments", "/code/payments/src"] {
        assert_eq!(state.trust(Path::new(other)).unwrap(), None, "{other}");
    }
}

#[test]
fn state_schema_1_is_upgraded_in_place() {
    let temp = TempDir::new().unwrap();
    let paths = DataPaths::from_root(temp.path().join("smart-env"));
    state_v1(paths.state_db());

    let state = paths.state().unwrap();
    state
        .set_trust(Path::new("/code/payments"), &allowed(1))
        .unwrap();

    assert_eq!(
        state.trust(Path::new("/code/payments")).unwrap(),
        Some(allowed(1))
    );
    // initialize (setup) opens the upgraded file too.
    paths.initialize().unwrap();
}

#[test]
fn state_from_a_newer_version_is_refused() {
    let temp = TempDir::new().unwrap();
    let paths = DataPaths::from_root(temp.path().join("smart-env"));
    state_v1(paths.state_db());
    rusqlite::Connection::open(paths.state_db())
        .unwrap()
        .pragma_update(None, "user_version", 99)
        .unwrap();

    assert!(matches!(
        paths.state(),
        Err(DataPathsError::UnsupportedState)
    ));
}

// --- state: consent for reserved names (allow --var) ---

use smart_env_vault::{EnvironmentId, KeyId, VarConsent, VarName};

fn var(name: &str) -> VarName {
    VarName::parse(name).unwrap()
}

#[test]
fn var_consent_is_stored_per_environment_and_name() {
    let temp = TempDir::new().unwrap();
    let state = DataPaths::from_root(temp.path().join("smart-env"))
        .state()
        .unwrap();
    let (dev, prod) = (EnvironmentId::new(), EnvironmentId::new());
    let consent = VarConsent {
        key_id: KeyId::new(),
        version: 3,
    };

    assert_eq!(state.var_consent(dev, &var("NODE_OPTIONS")).unwrap(), None);
    state
        .set_var_consent(dev, &var("NODE_OPTIONS"), &consent)
        .unwrap();

    assert_eq!(
        state.var_consent(dev, &var("NODE_OPTIONS")).unwrap(),
        Some(consent)
    );
    assert_eq!(state.var_consent(prod, &var("NODE_OPTIONS")).unwrap(), None);
    assert_eq!(state.var_consent(dev, &var("PATH")).unwrap(), None);
}

#[test]
fn var_consent_is_replaced_and_removed() {
    let temp = TempDir::new().unwrap();
    let paths = DataPaths::from_root(temp.path().join("smart-env"));
    let state = paths.state().unwrap();
    let env = EnvironmentId::new();
    let name = var("NODE_OPTIONS");
    let key_id = KeyId::new();

    state
        .set_var_consent(env, &name, &VarConsent { key_id, version: 1 })
        .unwrap();
    state
        .set_var_consent(env, &name, &VarConsent { key_id, version: 2 })
        .unwrap();
    assert_eq!(
        paths.state().unwrap().var_consent(env, &name).unwrap(),
        Some(VarConsent { key_id, version: 2 })
    );

    assert!(state.remove_var_consent(env, &name).unwrap());
    assert_eq!(state.var_consent(env, &name).unwrap(), None);
    assert!(!state.remove_var_consent(env, &name).unwrap());
}

#[test]
fn state_schema_1_is_upgraded_to_hold_var_consent() {
    let temp = TempDir::new().unwrap();
    let paths = DataPaths::from_root(temp.path().join("smart-env"));
    state_v1(paths.state_db());

    let state = paths.state().unwrap();
    let env = EnvironmentId::new();
    let consent = VarConsent {
        key_id: KeyId::new(),
        version: 1,
    };
    state.set_var_consent(env, &var("PATH"), &consent).unwrap();
    assert_eq!(state.var_consent(env, &var("PATH")).unwrap(), Some(consent));
}

#[test]
fn state_schema_2_is_upgraded_keeping_directory_decisions() {
    let temp = TempDir::new().unwrap();
    let paths = DataPaths::from_root(temp.path().join("smart-env"));
    std::fs::create_dir_all(paths.directory()).unwrap();
    {
        // Schema 2 as the allow / deny item wrote it.
        let conn = rusqlite::Connection::open(paths.state_db()).unwrap();
        conn.execute_batch(
            "CREATE TABLE trust (
                path BLOB PRIMARY KEY,
                decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
                file_hash BLOB CHECK (file_hash IS NULL OR length(file_hash) = 32),
                project_id TEXT,
                decided_at INTEGER NOT NULL,
                CHECK ((decision = 'allow') = (file_hash IS NOT NULL AND project_id IS NOT NULL))
            ) STRICT;
            INSERT INTO trust (path, decision, decided_at) VALUES (CAST('/code/x' AS BLOB), 'deny', 0);
            PRAGMA user_version = 2;",
        )
        .unwrap();
    }

    let state = paths.state().unwrap();

    assert_eq!(
        state.trust(Path::new("/code/x")).unwrap(),
        Some(TrustDecision::Denied)
    );
    let env = EnvironmentId::new();
    assert_eq!(state.var_consent(env, &var("PATH")).unwrap(), None);
}

// --- state: settings ---

#[test]
fn auto_activate_is_on_by_default_and_can_be_turned_off() {
    let temp = TempDir::new().unwrap();
    let paths = DataPaths::from_root(temp.path().join("smart-env"));
    let state = paths.state().unwrap();

    assert!(state.auto_activate().unwrap());
    state.set_auto_activate(false).unwrap();
    assert!(!paths.state().unwrap().auto_activate().unwrap());
    state.set_auto_activate(true).unwrap();
    assert!(state.auto_activate().unwrap());
}

#[test]
fn state_schema_3_is_upgraded_keeping_var_consent() {
    let temp = TempDir::new().unwrap();
    let paths = DataPaths::from_root(temp.path().join("smart-env"));
    let env = EnvironmentId::new();
    let key_id = KeyId::new();
    {
        // Schema 3 as the allow --var item wrote it.
        state_v1(paths.state_db());
        let state = paths.state().unwrap();
        state
            .set_var_consent(env, &var("PATH"), &VarConsent { key_id, version: 2 })
            .unwrap();
        drop(state);
        let conn = rusqlite::Connection::open(paths.state_db()).unwrap();
        conn.execute_batch("DROP TABLE IF EXISTS settings; PRAGMA user_version = 3;")
            .unwrap();
    }

    let state = paths.state().unwrap();

    assert_eq!(
        state.var_consent(env, &var("PATH")).unwrap(),
        Some(VarConsent { key_id, version: 2 })
    );
    assert!(state.auto_activate().unwrap());
    state.set_auto_activate(false).unwrap();
}
