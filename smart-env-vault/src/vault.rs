use crate::{
    Aad, Dek, EncryptedValue, EnvironmentId, FORMAT_VERSION, KeyError, KeyId, ProjectId, PublicKey,
    RecipientId, SecretError, SecretValue, Unwrapper, VarName, VaultId, WrappedDek,
};
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ValueRef};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, ffi, params};
use std::collections::{HashMap, HashSet, hash_map::Entry};
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
    /// No project with this id.
    #[error("project not found")]
    ProjectNotFound,
    /// No environment with this id.
    #[error("environment not found")]
    EnvironmentNotFound,
    /// No (live) secret with this name in the environment.
    #[error("secret not found")]
    SecretNotFound,
    /// No recipient with this id.
    #[error("recipient not found")]
    RecipientNotFound,
    /// A project with this name already exists in the vault.
    #[error("project name already taken")]
    ProjectNameTaken,
    /// An environment with this name already exists in the project.
    #[error("environment name already taken")]
    EnvironmentNameTaken,
    /// A secret with this name already exists in the environment (a removed
    /// one too, until purged).
    #[error("secret name already taken")]
    SecretNameTaken,
    /// This public key is already a recipient of the vault.
    #[error("public key is already a recipient")]
    RecipientKeyTaken,
    /// [`Vault::import`] got the same name twice; nothing was written.
    #[error("duplicate variable name in import: {0}")]
    DuplicateName(VarName),
    /// [`Vault::undo`] found no previous version of the secret.
    #[error("no previous version to restore")]
    NothingToUndo,
    /// [`Vault::create_environment`] found no active recipient to wrap the
    /// new DEK for; add one with [`Vault::add_recipient`] first.
    #[error("vault has no active recipients")]
    NoRecipients,
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

/// Does not guess what was missing or taken: operations check that
/// explicitly and return a specific variant. Anything left over is a
/// [`VaultError::Storage`] error.
impl From<rusqlite::Error> for VaultError {
    fn from(error: rusqlite::Error) -> Self {
        match sqlite_code(&error) {
            Some(ffi::SQLITE_NOTADB) => Self::UnsupportedSchema,
            _ => Self::Storage(error),
        }
    }
}

fn sqlite_code(error: &rusqlite::Error) -> Option<i32> {
    match error {
        rusqlite::Error::SqliteFailure(failure, _) => Some(failure.extended_code),
        _ => None,
    }
}

/// Maps a `UNIQUE` violation to `taken`; any other error as usual.
fn unique_as(error: rusqlite::Error, taken: VaultError) -> VaultError {
    if sqlite_code(&error) == Some(ffi::SQLITE_CONSTRAINT_UNIQUE) {
        taken
    } else {
        error.into()
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

/// Who a [`Recipient`] is. Stored as data (ADR-001).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecipientKind {
    /// A device of the user ([`DeviceKey`](crate::DeviceKey)).
    Device,
    /// The recovery key ([`RecoveryKey`](crate::RecoveryKey)).
    Recovery,
    /// A machine identity, e.g. CI or the zero-knowledge proxy.
    Machine,
}

impl RecipientKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Recovery => "recovery",
            Self::Machine => "machine",
        }
    }
}

impl FromSql for RecipientKind {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value.as_str()? {
            "device" => Ok(Self::Device),
            "recovery" => Ok(Self::Recovery),
            "machine" => Ok(Self::Machine),
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

/// A public key the vault wraps environment DEKs for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
    /// Stable identity of the recipient.
    pub id: RecipientId,
    /// Device, recovery key or machine.
    pub kind: RecipientKind,
    /// Human label, e.g. `laptop Oli`.
    pub label: String,
    /// The key DEKs are wrapped for.
    pub public_key: PublicKey,
    /// Revoked recipients get no envelope for new DEKs, but keep the ones
    /// they already have until the DEK is rotated.
    pub revoked: bool,
}

/// Where a secret is injected (ADR-005). An attribute of the secret, not of
/// a value version.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Inject {
    /// Exported by the shell hook and by `smart-env run` (default).
    #[default]
    Shell,
    /// Only for `smart-env run`; never exported into the shell, so
    /// editors, package scripts or agents started from it do not inherit it.
    Run,
}

impl Inject {
    fn as_str(self) -> &'static str {
        match self {
            Self::Shell => "shell",
            Self::Run => "run",
        }
    }
}

impl FromSql for Inject {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value.as_str()? {
            "shell" => Ok(Self::Shell),
            "run" => Ok(Self::Run),
            _ => Err(FromSqlError::InvalidType),
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
    /// Shell hook and `run`, or `run` only.
    pub inject: Inject,
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
    /// [`VaultError::ProjectNameTaken`] if a project with this name already exists.
    pub fn create_project(&mut self, name: &str) -> Result<ProjectId, VaultError> {
        let id = ProjectId::new();
        self.conn
            .execute(
                "INSERT INTO projects (id, vault_id, name) VALUES (?1, ?2, ?3)",
                params![id, self.id, name],
            )
            .map_err(|error| unique_as(error, VaultError::ProjectNameTaken))?;
        Ok(id)
    }

    /// Adds a recipient and wraps every existing DEK version of every
    /// environment for it, in one transaction (retired versions too, so
    /// values not yet re-encrypted by a rotation stay readable).
    ///
    /// `key` must open all those DEKs (on an empty vault it is not used).
    /// New environments are wrapped for every active recipient
    /// automatically.
    ///
    /// # Errors
    /// [`VaultError::Key`] (`Unwrap`) if `key` cannot open some DEK —
    /// nothing is written; [`VaultError::RecipientKeyTaken`] if this public
    /// key is already a recipient.
    pub fn add_recipient(
        &mut self,
        kind: RecipientKind,
        label: &str,
        public_key: &PublicKey,
        key: &impl Unwrapper,
    ) -> Result<RecipientId, VaultError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let id = RecipientId::new();
        tx.execute(
            "INSERT INTO recipients (id, vault_id, kind, label, public_key)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, self.id, kind.as_str(), label, public_key],
        )
        .map_err(|error| unique_as(error, VaultError::RecipientKeyTaken))?;

        let deks = {
            let mut statement = tx.prepare(
                "SELECT d.environment_id, d.version
                   FROM environment_deks d
                   JOIN environments e ON e.id = d.environment_id
                   JOIN projects p ON p.id = e.project_id
                  WHERE p.vault_id = ?1",
            )?;
            statement
                .query_map([self.id], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<Result<Vec<(EnvironmentId, u32)>, _>>()?
        };
        for (env, version) in deks {
            let dek = dek_at(&tx, env, version, key)?;
            store_wrap(&tx, env, version, &dek, id, public_key)?;
        }
        tx.commit()?;
        Ok(id)
    }

    /// Revokes a recipient: it gets no envelope for new DEKs. Envelopes it
    /// already has stay until the DEK is rotated (F08). Revoking twice is a
    /// no-op.
    ///
    /// # Errors
    /// [`VaultError::RecipientNotFound`] for an unknown recipient.
    pub fn revoke_recipient(&mut self, id: RecipientId) -> Result<(), VaultError> {
        let found = self.conn.execute(
            "UPDATE recipients SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP)
              WHERE id = ?1",
            [id],
        )?;
        if found == 0 {
            return Err(VaultError::RecipientNotFound);
        }
        Ok(())
    }

    /// All recipients of the vault, including revoked ones, in the order
    /// they were added.
    pub fn recipients(&self) -> Result<Vec<Recipient>, VaultError> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT {RECIPIENT_COLUMNS} FROM recipients r ORDER BY r.rowid"
        ))?;
        let recipients = statement
            .query_map([], recipient_from_row)?
            .collect::<Result<_, _>>()?;
        Ok(recipients)
    }

    /// Who can open the active DEK of an environment: every recipient with
    /// an envelope for it (a revoked one too, until rotation).
    ///
    /// # Errors
    /// [`VaultError::EnvironmentNotFound`] for an unknown environment.
    pub fn environment_recipients(&self, env: EnvironmentId) -> Result<Vec<Recipient>, VaultError> {
        ensure_environment(&self.conn, env)?;
        let mut statement = self.conn.prepare(&format!(
            "SELECT {RECIPIENT_COLUMNS}
               FROM dek_wraps w
               JOIN environment_deks d
                 ON d.environment_id = w.environment_id AND d.version = w.dek_version
                AND d.retired_at IS NULL
               JOIN recipients r ON r.id = w.recipient_id
              WHERE w.environment_id = ?1
              ORDER BY r.rowid"
        ))?;
        let recipients = statement
            .query_map([env], recipient_from_row)?
            .collect::<Result<_, _>>()?;
        Ok(recipients)
    }

    /// Creates an environment with a new DEK (version 1) wrapped separately
    /// for every active recipient of the vault.
    ///
    /// # Errors
    /// [`VaultError::NoRecipients`] if the vault has no active recipient,
    /// [`VaultError::ProjectNotFound`] for an unknown project,
    /// [`VaultError::EnvironmentNameTaken`] for a duplicate name in the
    /// project. Nothing is written on error.
    pub fn create_environment(
        &mut self,
        project: ProjectId,
        name: &str,
        kind: EnvKind,
    ) -> Result<EnvironmentId, VaultError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active = {
            let mut statement = tx.prepare(
                "SELECT id, public_key FROM recipients
                  WHERE vault_id = ?1 AND revoked_at IS NULL ORDER BY rowid",
            )?;
            statement
                .query_map([self.id], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<Result<Vec<(RecipientId, PublicKey)>, _>>()?
        };
        if active.is_empty() {
            return Err(VaultError::NoRecipients);
        }
        tx.query_row(
            "SELECT 1 FROM projects WHERE id = ?1 AND vault_id = ?2",
            params![project, self.id],
            |_| Ok(()),
        )
        .optional()?
        .ok_or(VaultError::ProjectNotFound)?;

        let id = EnvironmentId::new();
        tx.execute(
            "INSERT INTO environments (id, project_id, name, kind) VALUES (?1, ?2, ?3, ?4)",
            params![id, project, name, kind.as_str()],
        )
        .map_err(|error| unique_as(error, VaultError::EnvironmentNameTaken))?;
        tx.execute(
            "INSERT INTO environment_deks (environment_id, version) VALUES (?1, 1)",
            [id],
        )?;
        let dek = Dek::generate()?;
        for (recipient, public_key) in &active {
            store_wrap(&tx, id, 1, &dek, *recipient, public_key)?;
        }
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
    /// [`VaultError::EnvironmentNotFound`] for an unknown environment.
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
        let active = active_dek(&tx, env, key)?;
        let existing = current(&tx, env, name)?;
        let outcome = write_value(&tx, self.id, env, name, existing, value, &active)?;
        bump_revision(&tx, env)?;
        tx.commit()?;
        Ok(outcome)
    }

    /// Reads and decrypts a secret; `Ok(None)` if no secret has this name.
    ///
    /// Uses the DEK version stored in the row (not the active one), so values
    /// stay readable during a DEK rotation.
    ///
    /// # Errors
    /// [`VaultError::EnvironmentNotFound`] for an unknown environment (so a
    /// typo in its name does not look like a missing variable);
    /// [`VaultError::Key`] (`Unwrap`) for a wrong key; [`VaultError::Secret`]
    /// (`Decrypt`) if the stored data was tampered with or moved.
    pub fn get(
        &self,
        env: EnvironmentId,
        name: &VarName,
        key: &impl Unwrapper,
    ) -> Result<Option<SecretValue>, VaultError> {
        ensure_environment(&self.conn, env)?;
        let stored = self
            .conn
            .query_row(
                "SELECT s.key_id, e.project_id, s.format_version, s.dek_version, s.version,
                        s.nonce, s.ciphertext
                   FROM secrets s
                   JOIN environments e ON e.id = s.environment_id
                  WHERE s.environment_id = ?1 AND s.name = ?2 AND s.deleted_at IS NULL",
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
                    })
                },
            )
            .optional()?;
        let Some(stored) = stored else {
            return Ok(None);
        };

        let dek = dek_at(&self.conn, env, stored.dek_version, key)?;
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
    ///
    /// # Errors
    /// [`VaultError::EnvironmentNotFound`] for an unknown environment.
    pub fn list(&self, env: EnvironmentId) -> Result<Vec<SecretMeta>, VaultError> {
        ensure_environment(&self.conn, env)?;
        let mut statement = self.conn.prepare(&format!(
            "SELECT {META_COLUMNS} FROM secrets
              WHERE environment_id = ?1 AND deleted_at IS NULL ORDER BY name"
        ))?;
        let rows = statement
            .query_map([env], meta_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().collect()
    }

    /// Soft-deletes a secret: it disappears from [`get`](Vault::get),
    /// [`list`](Vault::list) and [`history`](Vault::history), but the value and
    /// its history stay until [`purge`](Vault::purge), so [`undo`](Vault::undo)
    /// can bring it back. Returns `true` if a live secret was removed (and the
    /// [`revision`](Vault::revision) incremented), `false` otherwise.
    ///
    /// # Errors
    /// [`VaultError::EnvironmentNotFound`] for an unknown environment.
    pub fn remove(&mut self, env: EnvironmentId, name: &VarName) -> Result<bool, VaultError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_environment(&tx, env)?;
        let removed = tx.execute(
            "UPDATE secrets SET deleted_at = CURRENT_TIMESTAMP
              WHERE environment_id = ?1 AND name = ?2 AND deleted_at IS NULL",
            params![env, name.as_str()],
        )?;
        if removed == 0 {
            return Ok(false);
        }
        bump_revision(&tx, env)?;
        tx.commit()?;
        Ok(true)
    }

    /// Renames a secret without re-encrypting it: only the label changes,
    /// while `key_id`, version, nonce and ciphertext stay unchanged.
    /// Increments the environment [`revision`](Vault::revision).
    ///
    /// # Errors
    /// [`VaultError::SecretNotFound`] if `from` does not exist or was removed,
    /// [`VaultError::SecretNameTaken`] if `to` is used, also by a removed
    /// secret (both secrets stay intact); [`VaultError::EnvironmentNotFound`].
    pub fn rename(
        &mut self,
        env: EnvironmentId,
        from: &VarName,
        to: &VarName,
    ) -> Result<(), VaultError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_environment(&tx, env)?;
        let renamed = tx
            .execute(
                "UPDATE secrets SET name = ?3
                  WHERE environment_id = ?1 AND name = ?2 AND deleted_at IS NULL",
                params![env, from.as_str(), to.as_str()],
            )
            .map_err(|error| unique_as(error, VaultError::SecretNameTaken))?;
        if renamed == 0 {
            return Err(VaultError::SecretNotFound);
        }
        bump_revision(&tx, env)?;
        tx.commit()?;
        Ok(())
    }

    /// Change counter of an environment: starts at 0 and grows by exactly 1
    /// with every successful change of its secrets (`set`, `remove`, `rename`,
    /// `undo`, `purge`). Lets callers detect changes without decrypting.
    ///
    /// # Errors
    /// [`VaultError::EnvironmentNotFound`] for an unknown environment.
    pub fn revision(&self, env: EnvironmentId) -> Result<u64, VaultError> {
        let revision: i64 = self
            .conn
            .query_row(
                "SELECT revision FROM environments WHERE id = ?1",
                [env],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(VaultError::EnvironmentNotFound)?;
        u64::try_from(revision)
            .map_err(|_| VaultError::Storage(rusqlite::Error::IntegralValueOutOfRange(0, revision)))
    }

    /// Versions of a secret, newest first: the current one followed by up to
    /// [`HISTORY_LIMIT`] previous ones. No key needed; never returns values.
    ///
    /// # Errors
    /// [`VaultError::SecretNotFound`] if the secret does not exist or was
    /// removed; [`VaultError::EnvironmentNotFound`].
    pub fn history(
        &self,
        env: EnvironmentId,
        name: &VarName,
    ) -> Result<Vec<VersionMeta>, VaultError> {
        ensure_environment(&self.conn, env)?;
        let (key_id, version, updated_at): (KeyId, u32, String) = self
            .conn
            .query_row(
                "SELECT key_id, version, updated_at FROM secrets
                  WHERE environment_id = ?1 AND name = ?2 AND deleted_at IS NULL",
                params![env, name.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or(VaultError::SecretNotFound)?;
        let mut statement = self.conn.prepare(
            "SELECT version, created_at FROM secret_versions
              WHERE key_id = ?1 ORDER BY version DESC",
        )?;
        let previous = statement.query_map([key_id], |row| {
            Ok(VersionMeta {
                version: row.get(0)?,
                created_at: row.get(1)?,
            })
        })?;
        std::iter::once(Ok(VersionMeta {
            version,
            created_at: updated_at,
        }))
        .chain(previous)
        .collect::<Result<_, _>>()
        .map_err(VaultError::from)
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
    /// [`VaultError::SecretNotFound`] if the secret does not exist (or was purged),
    /// [`VaultError::NothingToUndo`] if there is no previous version,
    /// [`VaultError::Key`] (`Unwrap`) for a wrong key — nothing is written.
    pub fn undo(
        &mut self,
        env: EnvironmentId,
        name: &VarName,
        key: &impl Unwrapper,
    ) -> Result<u32, VaultError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active = active_dek(&tx, env, key)?;
        let current = current(&tx, env, name)?.ok_or(VaultError::SecretNotFound)?;

        if current.deleted {
            tx.execute(
                "UPDATE secrets SET deleted_at = NULL WHERE key_id = ?1",
                [current.key_id],
            )?;
            bump_revision(&tx, env)?;
            tx.commit()?;
            return Ok(current.version);
        }

        let previous = tx
            .query_row(
                "SELECT version, format_version, dek_version, nonce, ciphertext
                   FROM secret_versions WHERE key_id = ?1
                  ORDER BY version DESC LIMIT 1",
                [current.key_id],
                |row| {
                    Ok((
                        row.get::<_, u32>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((version, format_version, dek_version, nonce, ciphertext)) = previous else {
            return Err(VaultError::NothingToUndo);
        };

        let old_dek;
        let dek = if dek_version == active.version {
            &active.dek
        } else {
            old_dek = dek_at(&tx, env, dek_version, key)?;
            &old_dek
        };
        let sealed = EncryptedValue {
            nonce: nonce.try_into().map_err(|_| SecretError::Decrypt)?,
            ciphertext,
        };
        let aad = Aad {
            format_version,
            vault: self.id,
            project: active.project,
            environment: env,
            key: current.key_id,
            dek_version,
            version,
        };
        let restored = dek.decrypt(&sealed, &aad)?;

        let outcome = write_value(&tx, self.id, env, name, Some(current), &restored, &active)?;
        bump_revision(&tx, env)?;
        tx.commit()?;
        Ok(outcome.version)
    }

    /// Deletes a secret permanently, together with its history; works on
    /// removed secrets too. Returns `true` if something was deleted (and the
    /// [`revision`](Vault::revision) incremented).
    ///
    /// # Errors
    /// [`VaultError::EnvironmentNotFound`] for an unknown environment.
    pub fn purge(&mut self, env: EnvironmentId, name: &VarName) -> Result<bool, VaultError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_environment(&tx, env)?;
        let purged = tx.execute(
            "DELETE FROM secrets WHERE environment_id = ?1 AND name = ?2",
            params![env, name.as_str()],
        )?;
        if purged == 0 {
            return Ok(false);
        }
        bump_revision(&tx, env)?;
        tx.commit()?;
        Ok(true)
    }

    /// Sets where a secret is injected ([`Inject`]). Metadata only: no key
    /// needed, value and version unchanged; increments the environment
    /// [`revision`](Vault::revision) so the shell hook notices.
    ///
    /// # Errors
    /// [`VaultError::SecretNotFound`] if the secret does not exist or was
    /// removed.
    pub fn set_inject(
        &mut self,
        env: EnvironmentId,
        name: &VarName,
        inject: Inject,
    ) -> Result<(), VaultError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_environment(&tx, env)?;
        let updated = tx.execute(
            "UPDATE secrets SET inject = ?3
              WHERE environment_id = ?1 AND name = ?2 AND deleted_at IS NULL",
            params![env, name.as_str(), inject.as_str()],
        )?;
        if updated == 0 {
            return Err(VaultError::SecretNotFound);
        }
        bump_revision(&tx, env)?;
        tx.commit()?;
        Ok(())
    }

    /// Reads and decrypts every live secret of an environment, sorted by
    /// name — what `run` and the shell hook need. Unwraps each DEK version
    /// once (normally once per environment) and always checks the key, even
    /// for an empty environment.
    ///
    /// # Errors
    /// [`VaultError::EnvironmentNotFound`], [`VaultError::Key`] (`Unwrap`)
    /// for a wrong key, [`VaultError::Secret`] (`Decrypt`) for tampered data.
    pub fn read_all(
        &self,
        env: EnvironmentId,
        key: &impl Unwrapper,
    ) -> Result<Vec<(SecretMeta, SecretValue)>, VaultError> {
        let active = active_dek(&self.conn, env, key)?;
        let project = active.project;
        let mut deks = HashMap::from([(active.version, active.dek)]);

        let mut statement = self.conn.prepare(&format!(
            "SELECT {META_COLUMNS}, format_version, dek_version, nonce, ciphertext
               FROM secrets
              WHERE environment_id = ?1 AND deleted_at IS NULL ORDER BY name"
        ))?;
        let rows = statement
            .query_map([env], |row| {
                Ok((
                    meta_from_row(row)?,
                    row.get::<_, u32>(5)?,
                    row.get::<_, u32>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut secrets = Vec::with_capacity(rows.len());
        for (meta, format_version, dek_version, nonce, ciphertext) in rows {
            let meta = meta?;
            let dek = match deks.entry(dek_version) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(dek_at(&self.conn, env, dek_version, key)?),
            };
            let sealed = EncryptedValue {
                nonce: nonce.try_into().map_err(|_| SecretError::Decrypt)?,
                ciphertext,
            };
            let aad = Aad {
                format_version,
                vault: self.id,
                project,
                environment: env,
                key: meta.key_id,
                dek_version,
                version: meta.version,
            };
            let value = dek.decrypt(&sealed, &aad)?;
            secrets.push((meta, value));
        }
        Ok(secrets)
    }

    /// Writes many secrets in one transaction: all or nothing. A name that
    /// already exists gets a new version (the old value goes to history).
    /// Increments the [`revision`](Vault::revision) once. Returns the
    /// outcomes in input order.
    ///
    /// # Errors
    /// [`VaultError::DuplicateName`] if a name appears twice in `entries`,
    /// [`VaultError::EnvironmentNotFound`], [`VaultError::Key`] (`Unwrap`) for
    /// a wrong key. Nothing is written on error.
    pub fn import(
        &mut self,
        env: EnvironmentId,
        entries: &[(VarName, SecretValue)],
        key: &impl Unwrapper,
    ) -> Result<Vec<SetOutcome>, VaultError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active = active_dek(&tx, env, key)?;
        let mut seen = HashSet::new();
        let mut outcomes = Vec::with_capacity(entries.len());
        for (name, value) in entries {
            if !seen.insert(name) {
                return Err(VaultError::DuplicateName(name.clone()));
            }
            let existing = current(&tx, env, name)?;
            outcomes.push(write_value(
                &tx, self.id, env, name, existing, value, &active,
            )?);
        }
        if !outcomes.is_empty() {
            bump_revision(&tx, env)?;
        }
        tx.commit()?;
        Ok(outcomes)
    }
}

/// The active DEK of an environment, unwrapped with the caller's key.
struct ActiveDek {
    project: ProjectId,
    version: u32,
    dek: Dek,
}

/// The row of a secret by name, including a soft-deleted one.
struct Current {
    key_id: KeyId,
    version: u32,
    deleted: bool,
}

/// Loads and unwraps the active DEK. Fails before any write for a wrong key
/// ([`KeyError::Unwrap`]) or an unknown environment
/// ([`VaultError::EnvironmentNotFound`]).
fn active_dek(
    conn: &Connection,
    env: EnvironmentId,
    key: &impl Unwrapper,
) -> Result<ActiveDek, VaultError> {
    let (project, version): (ProjectId, u32) = conn
        .query_row(
            "SELECT e.project_id, d.version
               FROM environments e
               JOIN environment_deks d ON d.environment_id = e.id AND d.retired_at IS NULL
              WHERE e.id = ?1",
            [env],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(VaultError::EnvironmentNotFound)?;
    let dek = dek_at(conn, env, version, key)?;
    Ok(ActiveDek {
        project,
        version,
        dek,
    })
}

/// Unwraps a specific (possibly retired) DEK version of an environment with
/// the caller's own envelope, found by its public key.
///
/// No envelope for this key is [`KeyError::Unwrap`] — the same as a key
/// that fails to open one — so a stranger cannot tell the two apart.
fn dek_at(
    conn: &Connection,
    env: EnvironmentId,
    version: u32,
    key: &impl Unwrapper,
) -> Result<Dek, VaultError> {
    let wrapped: Vec<u8> = conn
        .query_row(
            "SELECT w.wrapped
               FROM dek_wraps w
               JOIN recipients r ON r.id = w.recipient_id
              WHERE w.environment_id = ?1 AND w.dek_version = ?2 AND r.public_key = ?3",
            params![env, version, key.public()],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(KeyError::Unwrap)?;
    Ok(Dek::unwrap(&WrappedDek::from_bytes(wrapped), key)?)
}

/// Wraps `dek` for one recipient and stores the envelope.
fn store_wrap(
    conn: &Connection,
    env: EnvironmentId,
    dek_version: u32,
    dek: &Dek,
    recipient: RecipientId,
    public_key: &PublicKey,
) -> Result<(), VaultError> {
    let wrapped = dek.wrap(&[public_key])?;
    conn.execute(
        "INSERT INTO dek_wraps (environment_id, dek_version, recipient_id, wrapped)
         VALUES (?1, ?2, ?3, ?4)",
        params![env, dek_version, recipient, wrapped.as_bytes()],
    )?;
    Ok(())
}

fn recipient_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Recipient> {
    Ok(Recipient {
        id: row.get(0)?,
        kind: row.get(1)?,
        label: row.get(2)?,
        public_key: row.get(3)?,
        revoked: row.get(4)?,
    })
}

const RECIPIENT_COLUMNS: &str = "r.id, r.kind, r.label, r.public_key, r.revoked_at IS NOT NULL";

/// Columns read by [`meta_from_row`], always first in the `SELECT`.
const META_COLUMNS: &str = "name, key_id, version, inject, updated_at";

/// The outer `Result` is SQLite's, the inner one rejects a stored name that
/// is not a valid [`VarName`].
fn meta_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<SecretMeta, VaultError>> {
    let name: String = row.get(0)?;
    let (key_id, version, inject, updated_at) =
        (row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?);
    Ok(VarName::parse(&name)
        .map(|name| SecretMeta {
            name,
            key_id,
            version,
            inject,
            updated_at,
        })
        .map_err(VaultError::from))
}

/// [`VaultError::EnvironmentNotFound`] unless the environment exists.
fn ensure_environment(conn: &Connection, env: EnvironmentId) -> Result<(), VaultError> {
    conn.query_row(
        "SELECT 1 FROM environments WHERE id = ?1",
        [env],
        |_| Ok(()),
    )
    .optional()?
    .ok_or(VaultError::EnvironmentNotFound)
}

fn current(
    conn: &Connection,
    env: EnvironmentId,
    name: &VarName,
) -> Result<Option<Current>, VaultError> {
    Ok(conn
        .query_row(
            "SELECT key_id, version, deleted_at IS NOT NULL FROM secrets
              WHERE environment_id = ?1 AND name = ?2",
            params![env, name.as_str()],
            |row| {
                Ok(Current {
                    key_id: row.get(0)?,
                    version: row.get(1)?,
                    deleted: row.get(2)?,
                })
            },
        )
        .optional()?)
}

fn bump_revision(conn: &Connection, env: EnvironmentId) -> Result<(), VaultError> {
    conn.execute(
        "UPDATE environments SET revision = revision + 1 WHERE id = ?1",
        [env],
    )?;
    Ok(())
}

/// Writes `value` as the next version of a secret (or version 1 of a new one)
/// with the active DEK: archives the current value, trims the history to
/// [`HISTORY_LIMIT`] and clears a soft delete. Does not touch the revision:
/// each caller increments it once per operation.
fn write_value(
    conn: &Connection,
    vault: VaultId,
    env: EnvironmentId,
    name: &VarName,
    existing: Option<Current>,
    value: &SecretValue,
    active: &ActiveDek,
) -> Result<SetOutcome, VaultError> {
    let (key_id, version) = match &existing {
        Some(current) => (current.key_id, current.version + 1),
        None => (KeyId::new(), 1),
    };
    let aad = Aad {
        format_version: FORMAT_VERSION,
        vault,
        project: active.project,
        environment: env,
        key: key_id,
        dek_version: active.version,
        version,
    };
    let sealed = active.dek.encrypt(value, &aad)?;

    if existing.is_some() {
        conn.execute(
            "INSERT INTO secret_versions
                 (key_id, version, format_version, dek_version, nonce, ciphertext, created_at)
             SELECT key_id, version, format_version, dek_version, nonce, ciphertext, updated_at
               FROM secrets WHERE key_id = ?1",
            [key_id],
        )?;
        conn.execute(
            "DELETE FROM secret_versions
              WHERE key_id = ?1
                AND version NOT IN (SELECT version FROM secret_versions WHERE key_id = ?1
                                     ORDER BY version DESC LIMIT ?2)",
            params![key_id, HISTORY_LIMIT as i64],
        )?;
        conn.execute(
            "UPDATE secrets SET
                 format_version = ?2, dek_version = ?3, version = ?4,
                 nonce = ?5, ciphertext = ?6,
                 updated_at = CURRENT_TIMESTAMP, deleted_at = NULL
              WHERE key_id = ?1",
            params![
                key_id,
                FORMAT_VERSION,
                active.version,
                version,
                &sealed.nonce[..],
                sealed.ciphertext
            ],
        )?;
    } else {
        conn.execute(
            "INSERT INTO secrets
                 (key_id, environment_id, name, format_version, dek_version, version, nonce, ciphertext)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                key_id,
                env,
                name.as_str(),
                FORMAT_VERSION,
                active.version,
                version,
                &sealed.nonce[..],
                sealed.ciphertext
            ],
        )?;
    }
    Ok(SetOutcome { key_id, version })
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
