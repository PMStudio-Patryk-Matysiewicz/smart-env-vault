use rusqlite::{Connection, ErrorCode, params};

const SCHEMA: &str = include_str!("../migrations/20261102000000_init_schema.sql");

const VAULT: [u8; 16] = [1; 16];
const PROJECT: [u8; 16] = [2; 16];
const ENV: [u8; 16] = [3; 16];
const KEY: [u8; 16] = [4; 16];

fn id(n: u8) -> [u8; 16] {
    [n; 16]
}

fn open() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.pragma_update(None, "foreign_keys", true).unwrap();
    db.execute_batch(SCHEMA).unwrap();
    db
}

/// Vault -> project "payments" -> env "dev" with active DEK v1 -> secret DATABASE_URL.
fn seeded() -> Connection {
    let db = open();
    db.execute("INSERT INTO vaults (id) VALUES (?1)", [VAULT])
        .unwrap();
    db.execute(
        "INSERT INTO projects (id, vault_id, name) VALUES (?1, ?2, 'payments')",
        [PROJECT, VAULT],
    )
    .unwrap();
    db.execute(
        "INSERT INTO environments (id, project_id, name, kind) VALUES (?1, ?2, 'dev', 'dev')",
        [ENV, PROJECT],
    )
    .unwrap();
    db.execute(
        "INSERT INTO environment_deks (environment_id, version, wrapped) VALUES (?1, 1, x'00')",
        [ENV],
    )
    .unwrap();
    insert_secret(&db, KEY, "DATABASE_URL", 1, &[0; 12], &[0; 20]).unwrap();
    db
}

fn insert_secret(
    db: &Connection,
    key_id: [u8; 16],
    name: &str,
    dek_version: i64,
    nonce: &[u8],
    ciphertext: &[u8],
) -> rusqlite::Result<usize> {
    db.execute(
        "INSERT INTO secrets (key_id, environment_id, name, format_version, dek_version, version, nonce, ciphertext)
         VALUES (?1, ?2, ?3, 1, ?4, 1, ?5, ?6)",
        params![key_id, ENV, name, dek_version, nonce, ciphertext],
    )
}

fn assert_constraint(result: rusqlite::Result<usize>) {
    match result {
        Err(rusqlite::Error::SqliteFailure(error, _)) => {
            assert_eq!(error.code, ErrorCode::ConstraintViolation)
        }
        other => panic!("expected constraint violation, got {other:?}"),
    }
}

fn count(db: &Connection, table: &str) -> i64 {
    db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

#[test]
fn ids_must_be_16_byte_blobs() {
    let db = open();
    assert_constraint(db.execute("INSERT INTO vaults (id) VALUES (x'0102')", []));
}

#[test]
fn strict_tables_reject_text_in_blob_columns() {
    let db = open();
    assert_constraint(db.execute("INSERT INTO vaults (id) VALUES ('0123456789abcdef')", []));
}

#[test]
fn foreign_keys_are_enforced() {
    let db = open();
    assert_constraint(db.execute(
        "INSERT INTO projects (id, vault_id, name) VALUES (?1, ?2, 'orphan')",
        [PROJECT, VAULT],
    ));
}

#[test]
fn environment_names_are_unique_per_project_only() {
    let db = seeded();
    assert_constraint(db.execute(
        "INSERT INTO environments (id, project_id, name, kind) VALUES (?1, ?2, 'dev', 'dev')",
        [id(9), PROJECT],
    ));

    db.execute(
        "INSERT INTO projects (id, vault_id, name) VALUES (?1, ?2, 'billing')",
        [id(8), VAULT],
    )
    .unwrap();
    db.execute(
        "INSERT INTO environments (id, project_id, name, kind) VALUES (?1, ?2, 'dev', 'dev')",
        [id(9), id(8)],
    )
    .unwrap();
}

#[test]
fn environment_kind_and_access_are_closed_sets() {
    let db = seeded();
    assert_constraint(db.execute(
        "INSERT INTO environments (id, project_id, name, kind) VALUES (?1, ?2, 'qa', 'qa')",
        [id(9), PROJECT],
    ));
    assert_constraint(db.execute(
        "INSERT INTO environments (id, project_id, name, kind, access) VALUES (?1, ?2, 'ext', 'custom', 'open')",
        [id(9), PROJECT],
    ));
}

#[test]
fn only_one_active_dek_per_environment() {
    let db = seeded();
    assert_constraint(db.execute(
        "INSERT INTO environment_deks (environment_id, version, wrapped) VALUES (?1, 2, x'00')",
        [ENV],
    ));
}

#[test]
fn rotation_retires_old_dek_and_activates_new_one() {
    let db = seeded();
    db.execute(
        "UPDATE environment_deks SET retired_at = CURRENT_TIMESTAMP WHERE environment_id = ?1 AND version = 1",
        [ENV],
    )
    .unwrap();
    db.execute(
        "INSERT INTO environment_deks (environment_id, version, wrapped) VALUES (?1, 2, x'00')",
        [ENV],
    )
    .unwrap();
}

#[test]
fn dek_in_use_cannot_be_deleted() {
    let db = seeded();
    assert_constraint(db.execute(
        "DELETE FROM environment_deks WHERE environment_id = ?1 AND version = 1",
        [ENV],
    ));
}

#[test]
fn secret_must_reference_existing_dek_version() {
    let db = seeded();
    assert_constraint(insert_secret(&db, id(9), "OTHER", 7, &[0; 12], &[0; 20]));
}

#[test]
fn secret_names_follow_posix_rules() {
    let db = seeded();
    for bad in [
        "",
        "1ABC",
        "MY-KEY",
        "WITH SPACE",
        "ZAŻÓŁĆ",
        &"A".repeat(256),
    ] {
        assert_constraint(insert_secret(&db, id(9), bad, 1, &[0; 12], &[0; 20]));
    }
    for good in ["A", "_PRIVATE", "api_key_2", &"A".repeat(255)] {
        let key_id = id(10 + good.len() as u8 % 200);
        insert_secret(&db, key_id, good, 1, &[0; 12], &[0; 20]).unwrap();
        db.execute("DELETE FROM secrets WHERE key_id = ?1", [key_id])
            .unwrap();
    }
}

#[test]
fn secret_names_are_unique_per_environment() {
    let db = seeded();
    assert_constraint(insert_secret(
        &db,
        id(9),
        "DATABASE_URL",
        1,
        &[0; 12],
        &[0; 20],
    ));
}

#[test]
fn nonce_must_be_96_bits() {
    let db = seeded();
    assert_constraint(insert_secret(&db, id(9), "A", 1, &[0; 11], &[0; 20]));
    assert_constraint(insert_secret(&db, id(9), "A", 1, &[0; 13], &[0; 20]));
}

#[test]
fn ciphertext_holds_gcm_tag_and_at_most_64_kib() {
    let db = seeded();
    assert_constraint(insert_secret(&db, id(9), "A", 1, &[0; 12], &[0; 15]));
    assert_constraint(insert_secret(
        &db,
        id(9),
        "A",
        1,
        &[0; 12],
        &vec![0; 16 + 65_537],
    ));
    insert_secret(&db, id(9), "A", 1, &[0; 12], &vec![0; 16 + 65_536]).unwrap();
}

#[test]
fn rename_keeps_key_id() {
    let db = seeded();
    db.execute(
        "UPDATE secrets SET name = 'DB_URL' WHERE key_id = ?1",
        [KEY],
    )
    .unwrap();
    let key_id: [u8; 16] = db
        .query_row(
            "SELECT key_id FROM secrets WHERE name = 'DB_URL'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(key_id, KEY);
}

fn insert_version(db: &Connection, version: i64) -> rusqlite::Result<usize> {
    db.execute(
        "INSERT INTO secret_versions (key_id, version, format_version, dek_version, nonce, ciphertext, created_at)
         VALUES (?1, ?2, 1, 1, ?3, ?4, CURRENT_TIMESTAMP)",
        params![KEY, version, [0u8; 12], [0u8; 20]],
    )
}

#[test]
fn secret_version_must_be_positive() {
    let db = seeded();
    assert_constraint(db.execute("UPDATE secrets SET version = 0 WHERE key_id = ?1", [KEY]));
    assert_constraint(insert_version(&db, 0));
}

#[test]
fn environment_revision_starts_at_zero_and_cannot_go_negative() {
    let db = seeded();
    let revision: i64 = db
        .query_row(
            "SELECT revision FROM environments WHERE id = ?1",
            [ENV],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(revision, 0);
    assert_constraint(db.execute("UPDATE environments SET revision = -1 WHERE id = ?1", [ENV]));
}

#[test]
fn history_belongs_to_an_existing_secret_once_per_version() {
    let db = seeded();
    insert_version(&db, 1).unwrap();
    assert_constraint(insert_version(&db, 1));
    assert_constraint(db.execute(
        "INSERT INTO secret_versions (key_id, version, format_version, dek_version, nonce, ciphertext, created_at)
         VALUES (?1, 1, 1, 1, ?2, ?3, CURRENT_TIMESTAMP)",
        params![id(9), [0u8; 12], [0u8; 20]],
    ));
}

#[test]
fn deleting_secret_deletes_its_history() {
    let db = seeded();
    insert_version(&db, 1).unwrap();
    db.execute("DELETE FROM secrets WHERE key_id = ?1", [KEY])
        .unwrap();
    assert_eq!(count(&db, "secret_versions"), 0);
}

#[test]
fn deleting_vault_cascades_to_everything() {
    let db = seeded();
    insert_version(&db, 1).unwrap();
    db.execute("DELETE FROM vaults WHERE id = ?1", [VAULT])
        .unwrap();
    for table in [
        "projects",
        "environments",
        "environment_deks",
        "secrets",
        "secret_versions",
    ] {
        assert_eq!(count(&db, table), 0, "{table} not emptied");
    }
}
