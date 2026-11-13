use crate::{
    Aad, Dek, EncryptedValue, EnvironmentId, FORMAT_VERSION, KeyError, KeyId, ProjectId, PublicKey,
    SecretError, SecretValue, Unwrapper, VarName, VaultId, WrappedDek,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, ffi, params};
use std::{fs::OpenOptions, path::Path};
use thiserror::Error;

const SCHEMA: &str = include_str!("../migrations/20261102000000_init_schema.sql");
const SCHEMA_VERSION: i64 = 1;

/// Errors of [`Vault`] operations. Never carries a secret value.
#[derive(Debug, Error)]
pub enum VaultError {
    /// [`Vault::create`] found a file at the path and left it untouched.
    #[error("vault file already exists")]
    AlreadyExists,
    /// The file is not a SQLite database, or its schema version is unknown.
    #[error("not a smart-env vault or unsupported schema version")]
    UnsupportedSchema,
    /// Missing project, environment or secret (also a foreign key violation).
    #[error("project, environment or secret not found")]
    NotFound,
    /// The name is already used in this scope (`UNIQUE` violation).
    #[error("name already taken")]
    NameTaken,
    /// [`Vault::undo`] found no previous version of the secret.
    #[error("no previous version to restore")]
    NothingToUndo,
    /// Key error, e.g. [`KeyError::Unwrap`] when the key cannot open the environment DEK.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// Validation or encryption error, e.g. [`SecretError::Decrypt`] for tampered data.
    #[error(transparent)]
    Secret(#[from] SecretError),
    /// Any other SQLite error.
    #[error("storage error")]
    Storage(#[source] rusqlite::Error),
    /// File system error while creating the vault file.
    #[error("i/o error")]
    Io(#[source] std::io::Error),
}

impl From<rusqlite::Error> for VaultError {
    fn from(error: rusqlite::Error) -> Self {
        let code = match &error {
            rusqlite::Error::QueryReturnedNoRows => return Self::NotFound,
            rusqlite::Error::SqliteFailure(failure, _) => failure.extended_code,
            _ => return Self::Storage(error),
        };
        match code {
            ffi::SQLITE_CONSTRAINT_UNIQUE => Self::NameTaken,
            ffi::SQLITE_CONSTRAINT_FOREIGNKEY => Self::NotFound,
            ffi::SQLITE_NOTADB => Self::UnsupportedSchema,
            _ => Self::Storage(error),
        }
    }
}

/// Environment classification, stored as data (F03), so production rules
/// do not depend on the environment's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvKind {
    /// Local development.
    Dev,
    /// Pre-production.
    Staging,
    /// Production.
    Prod,
    /// Anything else.
    Custom,
}

impl EnvKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Staging => "staging",
            Self::Prod => "prod",
            Self::Custom => "custom",
        }
    }
}

/// Secret metadata returned by [`Vault::list`], without the value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretMeta {
    /// Current variable name.
    pub name: VarName,
    /// Stable identity of the secret.
    pub key_id: KeyId,
    /// Version of the current value.
    pub version: u32,
    /// Time of the last value change (UTC, `YYYY-MM-DD HH:MM:SS`).
    pub updated_at: String,
}

/// How many previous values [`Vault`] keeps per secret (the current value
/// does not count).
pub const HISTORY_LIMIT: usize = 10;

/// Result of [`Vault::set`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetOutcome {
    /// Stable identity of the secret (kept when overwriting).
    pub key_id: KeyId,
    /// Version of the value just written: 1 for a new secret, then +1.
    pub version: u32,
}

/// One entry of [`Vault::history`]: a version and when it was written, never
/// the value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionMeta {
    /// Version number of the value.
    pub version: u32,
    /// When this version was written (UTC, `YYYY-MM-DD HH:MM:SS`).
    pub created_at: String,
}

/// A secret row together with everything needed to rebuild its AAD.
struct StoredSecret {
    key_id: KeyId,
    project: ProjectId,
    format_version: u32,
    dek_version: u32,
    version: u32,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    wrapped_dek: Vec<u8>,
}

/// Local encrypted secret store: one SQLite file holding only ciphertext and
/// wrapped DEKs.
///
/// Every operation that touches values takes a key (`&impl Unwrapper`) and
/// unwraps the environment DEK first, so a wrong key cannot read or write
/// anything.
pub struct Vault {
    conn: Connection,
    id: VaultId,
}

impl Vault {
    /// Creates a new vault file with mode 0600. Refuses to touch an existing file.
    ///
    /// Applies the schema and generates a new [`VaultId`]. If initialization
    /// fails, the half-created file is removed.
    ///
    /// # Errors
    /// [`VaultError::AlreadyExists`] if the path exists, [`VaultError::Io`] or
    /// [`VaultError::Storage`] on file system or SQLite failure.
    pub fn create(path: &Path) -> Result<Vault, VaultError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options.open(path).map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => VaultError::AlreadyExists,
            _ => VaultError::Io(error),
        })?;

        Self::initialize(path).inspect_err(|_| {
            let _ = std::fs::remove_file(path);
        })
    }

    fn initialize(path: &Path) -> Result<Vault, VaultError> {
        let mut conn = connect(path)?;
        let id = VaultId::new();
        let tx = conn.transaction()?;
        tx.execute_batch(SCHEMA)?;
        tx.execute("INSERT INTO vaults (id) VALUES (?1)", [id])?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(Vault { conn, id })
    }

    /// Opens an existing vault. Never creates a file.
    ///
    /// # Errors
    /// [`VaultError::UnsupportedSchema`] for a non-database file or an unknown
    /// schema version, [`VaultError::Storage`] if the file cannot be opened.
    pub fn open(path: &Path) -> Result<Vault, VaultError> {
        let conn = connect(path)?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version != SCHEMA_VERSION {
            return Err(VaultError::UnsupportedSchema);
        }
        let id = conn.query_row("SELECT id FROM vaults", [], |row| row.get(0))?;
        Ok(Vault { conn, id })
    }

    /// Identifier of this vault (part of every [`Aad`]).
    pub fn id(&self) -> VaultId {
        self.id
    }

    /// Creates a project. Name validation rules come with F03.
    ///
    /// # Errors
    /// [`VaultError::NameTaken`] if a project with this name already exists.
    pub fn create_project(&mut self, name: &str) -> Result<ProjectId, VaultError> {
        let id = ProjectId::new();
        self.conn.execute(
            "INSERT INTO projects (id, vault_id, name) VALUES (?1, ?2, ?3)",
            params![id, self.id, name],
        )?;
        Ok(id)
    }

    /// Creates an environment with DEK version 1 wrapped for `recipients`.
    ///
    /// `recipients` should include the device key and the recovery key, or
    /// the environment cannot be recovered after losing the device.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] for an unknown project, [`VaultError::NameTaken`]
    /// for a duplicate name in the project, [`VaultError::Key`] if `recipients` is empty.
    pub fn create_environment(
        &mut self,
        project: ProjectId,
        name: &str,
        kind: EnvKind,
        recipients: &[&PublicKey],
    ) -> Result<EnvironmentId, VaultError> {
        let wrapped = Dek::generate()?.wrap(recipients)?;
        let id = EnvironmentId::new();
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO environments (id, project_id, name, kind) VALUES (?1, ?2, ?3, ?4)",
            params![id, project, name, kind.as_str()],
        )?;
        tx.execute(
            "INSERT INTO environment_deks (environment_id, version, wrapped) VALUES (?1, 1, ?2)",
            params![id, wrapped.as_bytes()],
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// Saves a secret: creates it or overwrites its value.
    ///
    /// Encrypts with the active DEK and a fresh nonce. Unwraps the DEK before
    /// writing anything. Overwriting keeps the existing [`KeyId`], moves the
    /// previous value to the history (at most [`HISTORY_LIMIT`] kept) and
    /// increments the version; setting a removed name brings the secret back
    /// with its history. Every successful call increments the environment
    /// [`revision`](Vault::revision).
    ///
    /// # Errors
    /// [`VaultError::Key`] (`Unwrap`) for a wrong key — nothing is written;
    /// [`VaultError::NotFound`] for an unknown environment.
    pub fn set(
        &mut self,
        env: EnvironmentId,
        name: &VarName,
        value: &SecretValue,
        key: &impl Unwrapper,
    ) -> Result<SetOutcome, VaultError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let (project, dek_version, wrapped): (ProjectId, u32, Vec<u8>) = tx.query_row(
            "SELECT e.project_id, d.version, d.wrapped
               FROM environments e
               JOIN environment_deks d ON d.environment_id = e.id AND d.retired_at IS NULL
              WHERE e.id = ?1",
            [env],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let dek = Dek::unwrap(&WrappedDek::from_bytes(wrapped), key)?;

        let key_id = tx
            .query_row(
                "SELECT key_id FROM secrets WHERE environment_id = ?1 AND name = ?2",
                params![env, name.as_str()],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_else(KeyId::new);

        let aad = Aad {
            format_version: FORMAT_VERSION,
            vault: self.id,
            project,
            environment: env,
            key: key_id,
            dek_version,
            version: 1,
        };
        let sealed = dek.encrypt(value, &aad)?;

        tx.execute(
            "INSERT INTO secrets
                 (key_id, environment_id, name, format_version, dek_version, version, nonce, ciphertext)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7)
             ON CONFLICT (environment_id, name) DO UPDATE SET
                 format_version = excluded.format_version,
                 dek_version    = excluded.dek_version,
                 nonce          = excluded.nonce,
                 ciphertext     = excluded.ciphertext,
                 updated_at     = CURRENT_TIMESTAMP",
            params![
                key_id,
                env,
                name.as_str(),
                FORMAT_VERSION,
                dek_version,
                &sealed.nonce[..],
                sealed.ciphertext
            ],
        )?;
        tx.commit()?;
        Ok(SetOutcome { key_id, version: 1 })
    }

    /// Reads and decrypts a secret; `Ok(None)` if no secret has this name.
    ///
    /// Uses the DEK version stored in the row (not the active one), so values
    /// stay readable during a DEK rotation.
    ///
    /// # Errors
    /// [`VaultError::Key`] (`Unwrap`) for a wrong key; [`VaultError::Secret`]
    /// (`Decrypt`) if the stored data was tampered with or moved.
    pub fn get(
        &self,
        env: EnvironmentId,
        name: &VarName,
        key: &impl Unwrapper,
    ) -> Result<Option<SecretValue>, VaultError> {
        let stored = self
            .conn
            .query_row(
                "SELECT s.key_id, e.project_id, s.format_version, s.dek_version, s.version,
                        s.nonce, s.ciphertext, d.wrapped
                   FROM secrets s
                   JOIN environments e ON e.id = s.environment_id
                   JOIN environment_deks d
                     ON d.environment_id = s.environment_id AND d.version = s.dek_version
                  WHERE s.environment_id = ?1 AND s.name = ?2",
                params![env, name.as_str()],
                |row| {
                    Ok(StoredSecret {
                        key_id: row.get(0)?,
                        project: row.get(1)?,
                        format_version: row.get(2)?,
                        dek_version: row.get(3)?,
                        version: row.get(4)?,
                        nonce: row.get(5)?,
                        ciphertext: row.get(6)?,
                        wrapped_dek: row.get(7)?,
                    })
                },
            )
            .optional()?;
        let Some(stored) = stored else {
            return Ok(None);
        };

        let dek = Dek::unwrap(&WrappedDek::from_bytes(stored.wrapped_dek), key)?;
        let sealed = EncryptedValue {
            nonce: stored.nonce.try_into().map_err(|_| SecretError::Decrypt)?,
            ciphertext: stored.ciphertext,
        };
        let aad = Aad {
            format_version: stored.format_version,
            vault: self.id,
            project: stored.project,
            environment: env,
            key: stored.key_id,
            dek_version: stored.dek_version,
            version: stored.version,
        };
        Ok(Some(dek.decrypt(&sealed, &aad)?))
    }

    /// Lists names without a key and without decrypting, sorted by name.
    pub fn list(&self, env: EnvironmentId) -> Result<Vec<SecretMeta>, VaultError> {
        let mut statement = self.conn.prepare(
            "SELECT name, key_id, version, updated_at
               FROM secrets WHERE environment_id = ?1 ORDER BY name",
        )?;
        let rows = statement
            .query_map([env], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(name, key_id, version, updated_at)| {
                Ok(SecretMeta {
                    name: VarName::parse(&name)?,
                    key_id,
                    version,
                    updated_at,
                })
            })
            .collect()
    }

    /// Soft-deletes a secret: it disappears from [`get`](Vault::get),
    /// [`list`](Vault::list) and [`history`](Vault::history), but the value and
    /// its history stay until [`purge`](Vault::purge), so [`undo`](Vault::undo)
    /// can bring it back. Returns `true` if a live secret was removed (and the
    /// [`revision`](Vault::revision) incremented), `false` otherwise.
    pub fn remove(&mut self, env: EnvironmentId, name: &VarName) -> Result<bool, VaultError> {
        let deleted = self.conn.execute(
            "DELETE FROM secrets WHERE environment_id = ?1 AND name = ?2",
            params![env, name.as_str()],
        )?;
        Ok(deleted > 0)
    }

    /// Renames a secret without re-encrypting it: only the label changes,
    /// while `key_id`, version, nonce and ciphertext stay unchanged.
    /// Increments the environment [`revision`](Vault::revision).
    ///
    /// # Errors
    /// [`VaultError::NotFound`] if `from` does not exist or was removed,
    /// [`VaultError::NameTaken`] if `to` is used, also by a removed secret
    /// (both secrets stay intact).
    pub fn rename(
        &mut self,
        env: EnvironmentId,
        from: &VarName,
        to: &VarName,
    ) -> Result<(), VaultError> {
        let renamed = self.conn.execute(
            "UPDATE secrets SET name = ?3 WHERE environment_id = ?1 AND name = ?2",
            params![env, from.as_str(), to.as_str()],
        )?;
        if renamed == 0 {
            return Err(VaultError::NotFound);
        }
        Ok(())
    }

    /// Change counter of an environment: starts at 0 and grows by exactly 1
    /// with every successful change of its secrets (`set`, `remove`, `rename`,
    /// `undo`, `purge`). Lets callers detect changes without decrypting.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] for an unknown environment.
    pub fn revision(&self, env: EnvironmentId) -> Result<u64, VaultError> {
        let _ = env;
        todo!()
    }

    /// Versions of a secret, newest first: the current one followed by up to
    /// [`HISTORY_LIMIT`] previous ones. No key needed; never returns values.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] if the secret does not exist or was removed.
    pub fn history(
        &self,
        env: EnvironmentId,
        name: &VarName,
    ) -> Result<Vec<VersionMeta>, VaultError> {
        let _ = (env, name);
        todo!()
    }

    /// Restores the previous state of a secret. History only grows:
    ///
    /// - a removed secret comes back with its value and version unchanged;
    /// - otherwise the newest previous value is written as a new version, and
    ///   the current one moves to the history (so a second `undo` reverts the
    ///   first).
    ///
    /// Unwraps the DEK before writing anything. Returns the version after the
    /// operation and increments the environment [`revision`](Vault::revision).
    ///
    /// # Errors
    /// [`VaultError::NotFound`] if the secret does not exist (or was purged),
    /// [`VaultError::NothingToUndo`] if there is no previous version,
    /// [`VaultError::Key`] (`Unwrap`) for a wrong key — nothing is written.
    pub fn undo(
        &mut self,
        env: EnvironmentId,
        name: &VarName,
        key: &impl Unwrapper,
    ) -> Result<u32, VaultError> {
        let _ = (env, name, key);
        todo!()
    }

    /// Deletes a secret permanently, together with its history; works on
    /// removed secrets too. Returns `true` if something was deleted (and the
    /// [`revision`](Vault::revision) incremented).
    pub fn purge(&mut self, env: EnvironmentId, name: &VarName) -> Result<bool, VaultError> {
        let _ = (env, name);
        todo!()
    }
}

/// Opens an existing file (never creates one) with foreign keys enforced.
fn connect(path: &Path) -> Result<Connection, VaultError> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.pragma_update(None, "foreign_keys", true)?;
    Ok(conn)
}
