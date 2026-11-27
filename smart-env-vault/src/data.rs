use crate::{EnvironmentId, KeyId, ProjectId, VarName, Vault, VaultError};
use rusqlite::{Connection, OpenFlags, OptionalExtension, ffi};
use std::{
    fs::{OpenOptions, create_dir_all, remove_file},
    path::{Path, PathBuf},
};
use thiserror::Error;

const STATE_SCHEMA_VERSION: i64 = 3;

/// Schema 2: shell hook trust (`smart-env allow` / `deny`).
const STATE_SCHEMA_2: &str = "
    CREATE TABLE trust (
        path BLOB PRIMARY KEY,
        decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
        file_hash BLOB CHECK (file_hash IS NULL OR length(file_hash) = 32),
        project_id TEXT,
        decided_at INTEGER NOT NULL,
        CHECK ((decision = 'allow') = (file_hash IS NOT NULL AND project_id IS NOT NULL))
    ) STRICT;
";

/// Schema 3: consent to pass reserved names (`smart-env allow --var`).
const STATE_SCHEMA_3: &str = "
    CREATE TABLE var_consent (
        environment_id TEXT NOT NULL,
        name TEXT NOT NULL,
        key_id TEXT NOT NULL,
        version INTEGER NOT NULL CHECK (version >= 1),
        decided_at INTEGER NOT NULL,
        PRIMARY KEY (environment_id, name)
    ) STRICT;
";

/// Errors while locating or initializing smart-env application data.
#[derive(Debug, Error)]
pub enum DataPathsError {
    /// The operating system did not provide a user data directory.
    #[error("could not locate a user data directory")]
    NoDataDirectory,
    /// An application data file or directory could not be accessed.
    #[error("i/o error")]
    Io(#[source] std::io::Error),
    /// Opening or initializing an SQLite state file failed.
    #[error("state storage error")]
    Storage(#[source] rusqlite::Error),
    /// An existing state file is not a smart-env state database.
    #[error("not a smart-env state database or unsupported schema version")]
    UnsupportedState,
    /// Vault storage failed.
    #[error(transparent)]
    Vault(#[from] VaultError),
}

impl From<rusqlite::Error> for DataPathsError {
    fn from(error: rusqlite::Error) -> Self {
        match sqlite_code(&error) {
            Some(ffi::SQLITE_NOTADB) => Self::UnsupportedState,
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

/// Paths to the portable vault database and the local device state database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataPaths {
    directory: PathBuf,
    vault_db: PathBuf,
    state_db: PathBuf,
    key_file: PathBuf,
}

impl DataPaths {
    /// Resolves the platform-specific smart-env data directory.
    pub fn discover() -> Result<Self, DataPathsError> {
        let data_dir = dirs::data_dir().ok_or(DataPathsError::NoDataDirectory)?;
        Ok(Self::from_root(data_dir.join("smart-env")))
    }

    /// Builds paths below an explicit directory.
    pub fn from_root(directory: impl Into<PathBuf>) -> Self {
        let directory = directory.into();
        let vault_db = directory.join("vault.db");
        let state_db = directory.join("state.db");
        let key_file = directory.join("device.key");
        Self {
            directory,
            vault_db,
            state_db,
            key_file,
        }
    }

    /// Directory containing both database files.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Portable vault database path.
    pub fn vault_db(&self) -> &Path {
        &self.vault_db
    }

    /// Passphrase-encrypted device key file; it exists only in passphrase
    /// mode (no system keychain).
    pub fn key_file(&self) -> &Path {
        &self.key_file
    }

    /// Local, device-specific state database path.
    pub fn state_db(&self) -> &Path {
        &self.state_db
    }

    /// Creates or opens both databases.
    ///
    /// Existing files are opened and never replaced.
    pub fn initialize(&self) -> Result<(Vault, StateStore), DataPathsError> {
        create_dir_all(&self.directory).map_err(DataPathsError::Io)?;
        #[cfg(unix)]
        set_directory_mode(&self.directory)?;

        let vault_created = !self.vault_db.exists();
        let vault = if vault_created {
            Vault::create(&self.vault_db)?
        } else {
            Vault::open(&self.vault_db)?
        };

        let state = match if self.state_db.exists() {
            StateStore::open(&self.state_db)
        } else {
            StateStore::create(&self.state_db)
        } {
            Ok(state) => state,
            Err(error) => {
                if vault_created {
                    let _ = remove_file(&self.vault_db);
                }
                return Err(error);
            }
        };

        Ok((vault, state))
    }

    /// Opens the state database, creating it (and the directory) if it is
    /// missing; an older schema is upgraded in place.
    ///
    /// # Errors
    /// [`DataPathsError::UnsupportedState`] for a file that is not a
    /// smart-env state database or comes from a newer version; I/O and
    /// storage errors.
    pub fn state(&self) -> Result<StateStore, DataPathsError> {
        create_dir_all(&self.directory).map_err(DataPathsError::Io)?;
        #[cfg(unix)]
        set_directory_mode(&self.directory)?;
        if self.state_db.exists() {
            StateStore::open(&self.state_db)
        } else {
            StateStore::create(&self.state_db)
        }
    }
}

/// Consent to pass a variable with a reserved name (ADR-005): exactly this
/// secret at exactly this version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VarConsent {
    /// Stable identity of the secret.
    pub key_id: KeyId,
    /// Version of the value the user saw and allowed.
    pub version: u32,
}

/// What the user decided about loading a project directory in the shell
/// hook (`smart-env allow` / `deny`), on this device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustDecision {
    /// Allowed for this exact `smart-env.toml` content.
    Allowed {
        /// SHA-256 of `smart-env.toml` when it was allowed.
        file_hash: [u8; 32],
        /// `project_id` from that file.
        project_id: ProjectId,
    },
    /// Never load it (until allowed again).
    Denied,
}

#[cfg(unix)]
fn set_directory_mode(directory: &Path) -> Result<(), DataPathsError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
        .map_err(DataPathsError::Io)
}

/// The local state database, kept separate from portable vault data.
pub struct StateStore {
    conn: Connection,
}

impl StateStore {
    fn create(path: &Path) -> Result<Self, DataPathsError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options.open(path).map_err(DataPathsError::Io)?;

        match Self::initialize(path) {
            Ok(store) => Ok(store),
            Err(error) => {
                let _ = remove_file(path);
                Err(error)
            }
        }
    }

    fn initialize(path: &Path) -> Result<Self, DataPathsError> {
        let mut conn = connect_state(path)?;
        let tx = conn.transaction()?;
        tx.execute_batch(STATE_SCHEMA_2)?;
        tx.execute_batch(STATE_SCHEMA_3)?;
        tx.pragma_update(None, "user_version", STATE_SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(Self { conn })
    }

    fn open(path: &Path) -> Result<Self, DataPathsError> {
        let mut conn = connect_state(path)?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        // Before release the format may still change: older schemas are
        // upgraded in place (schema 1 had no tables).
        let upgrades: &[&str] = match version {
            STATE_SCHEMA_VERSION => &[],
            1 => &[STATE_SCHEMA_2, STATE_SCHEMA_3],
            2 => &[STATE_SCHEMA_3],
            _ => return Err(DataPathsError::UnsupportedState),
        };
        if !upgrades.is_empty() {
            let tx = conn.transaction()?;
            for schema in upgrades {
                tx.execute_batch(schema)?;
            }
            tx.pragma_update(None, "user_version", STATE_SCHEMA_VERSION)?;
            tx.commit()?;
        }
        Ok(Self { conn })
    }
}

impl StateStore {
    /// The decision stored for the project directory `dir` (canonical
    /// path), if any.
    ///
    /// # Errors
    /// Storage errors.
    pub fn trust(&self, dir: &Path) -> Result<Option<TrustDecision>, DataPathsError> {
        let row = self
            .conn
            .query_row(
                "SELECT decision, file_hash, project_id FROM trust WHERE path = ?1",
                [path_key(dir)],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((decision, file_hash, project_id)) = row else {
            return Ok(None);
        };
        match (decision.as_str(), file_hash, project_id) {
            ("deny", _, _) => Ok(Some(TrustDecision::Denied)),
            ("allow", Some(hash), Some(id)) => Ok(Some(TrustDecision::Allowed {
                file_hash: hash
                    .try_into()
                    .map_err(|_| DataPathsError::UnsupportedState)?,
                project_id: id.parse().map_err(|_| DataPathsError::UnsupportedState)?,
            })),
            _ => Err(DataPathsError::UnsupportedState),
        }
    }

    /// Stores `decision` for `dir`, replacing an earlier one.
    ///
    /// # Errors
    /// Storage errors.
    pub fn set_trust(&self, dir: &Path, decision: &TrustDecision) -> Result<(), DataPathsError> {
        let (kind, file_hash, project_id) = match decision {
            TrustDecision::Allowed {
                file_hash,
                project_id,
            } => (
                "allow",
                Some(file_hash.to_vec()),
                Some(project_id.to_string()),
            ),
            TrustDecision::Denied => ("deny", None, None),
        };
        let now = unix_now();
        self.conn.execute(
            "INSERT INTO trust (path, decision, file_hash, project_id, decided_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (path) DO UPDATE SET decision = excluded.decision,
                 file_hash = excluded.file_hash, project_id = excluded.project_id,
                 decided_at = excluded.decided_at",
            rusqlite::params![path_key(dir), kind, file_hash, project_id, now],
        )?;
        Ok(())
    }
}

impl StateStore {
    /// Consent for variable `name` in environment `env`, if any.
    ///
    /// # Errors
    /// Storage errors.
    pub fn var_consent(
        &self,
        env: EnvironmentId,
        name: &VarName,
    ) -> Result<Option<VarConsent>, DataPathsError> {
        let row = self
            .conn
            .query_row(
                "SELECT key_id, version FROM var_consent
                  WHERE environment_id = ?1 AND name = ?2",
                rusqlite::params![env.to_string(), name.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        row.map(|(key_id, version)| {
            Ok(VarConsent {
                key_id: key_id
                    .parse()
                    .map_err(|_| DataPathsError::UnsupportedState)?,
                version: u32::try_from(version).map_err(|_| DataPathsError::UnsupportedState)?,
            })
        })
        .transpose()
    }

    /// Stores `consent` for `name` in `env`, replacing an earlier one.
    ///
    /// # Errors
    /// Storage errors.
    pub fn set_var_consent(
        &self,
        env: EnvironmentId,
        name: &VarName,
        consent: &VarConsent,
    ) -> Result<(), DataPathsError> {
        self.conn.execute(
            "INSERT INTO var_consent (environment_id, name, key_id, version, decided_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (environment_id, name) DO UPDATE SET key_id = excluded.key_id,
                 version = excluded.version, decided_at = excluded.decided_at",
            rusqlite::params![
                env.to_string(),
                name.as_str(),
                consent.key_id.to_string(),
                consent.version,
                unix_now()
            ],
        )?;
        Ok(())
    }

    /// Removes the consent for `name` in `env`; returns whether there was one.
    ///
    /// # Errors
    /// Storage errors.
    pub fn remove_var_consent(
        &self,
        env: EnvironmentId,
        name: &VarName,
    ) -> Result<bool, DataPathsError> {
        let removed = self.conn.execute(
            "DELETE FROM var_consent WHERE environment_id = ?1 AND name = ?2",
            rusqlite::params![env.to_string(), name.as_str()],
        )?;
        Ok(removed > 0)
    }
}

/// Seconds since the Unix epoch (0 if the clock is before it).
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// The exact bytes of a path (not UTF-8 on every system).
fn path_key(dir: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        dir.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        dir.to_string_lossy().into_owned().into_bytes()
    }
}

fn connect_state(path: &Path) -> Result<Connection, DataPathsError> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.pragma_update(None, "secure_delete", true)?;
    conn.pragma_update(None, "trusted_schema", false)?;
    conn.pragma_update(None, "busy_timeout", 5_000)?;
    Ok(conn)
}
