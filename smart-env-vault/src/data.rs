use crate::{Vault, VaultError};
use rusqlite::{Connection, OpenFlags, ffi};
use std::{
    fs::{OpenOptions, create_dir_all, remove_file},
    path::{Path, PathBuf},
};
use thiserror::Error;

const STATE_SCHEMA_VERSION: i64 = 1;

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
        Self {
            directory,
            vault_db,
            state_db,
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
        todo!()
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
}

#[cfg(unix)]
fn set_directory_mode(directory: &Path) -> Result<(), DataPathsError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
        .map_err(DataPathsError::Io)
}

/// The local state database, kept separate from portable vault data.
pub struct StateStore {
    _conn: Connection,
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
        tx.pragma_update(None, "user_version", STATE_SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(Self { _conn: conn })
    }

    fn open(path: &Path) -> Result<Self, DataPathsError> {
        let conn = connect_state(path)?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version != STATE_SCHEMA_VERSION {
            return Err(DataPathsError::UnsupportedState);
        }
        Ok(Self { _conn: conn })
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
