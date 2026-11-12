use crate::{
    EnvironmentId, KeyError, KeyId, ProjectId, PublicKey, SecretError, SecretValue, Unwrapper,
    VarName, VaultId,
};
use rusqlite::Connection;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault file already exists")]
    AlreadyExists,
    #[error("not a smart-env vault or unsupported schema version")]
    UnsupportedSchema,
    #[error("project, environment or secret not found")]
    NotFound,
    #[error("name already taken")]
    NameTaken,
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Secret(#[from] SecretError),
    #[error("storage error")]
    Storage(#[source] rusqlite::Error),
    #[error("i/o error")]
    Io(#[source] std::io::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvKind {
    Dev,
    Staging,
    Prod,
    Custom,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretMeta {
    pub name: VarName,
    pub key_id: KeyId,
    pub updated_at: String,
}

pub struct Vault {
    conn: Connection,
    id: VaultId,
}

impl Vault {
    /// Creates a new vault file with mode 0600. Refuses to touch an existing file.
    pub fn create(path: &Path) -> Result<Vault, VaultError> {
        todo!()
    }

    /// Opens an existing vault. Never creates a file.
    pub fn open(path: &Path) -> Result<Vault, VaultError> {
        todo!()
    }

    pub fn id(&self) -> VaultId {
        todo!()
    }

    pub fn create_project(&mut self, name: &str) -> Result<ProjectId, VaultError> {
        todo!()
    }

    /// Creates an environment with DEK version 1 wrapped for `recipients`.
    pub fn create_environment(
        &mut self,
        project: ProjectId,
        name: &str,
        kind: EnvKind,
        recipients: &[&PublicKey],
    ) -> Result<EnvironmentId, VaultError> {
        todo!()
    }

    /// Encrypts with the active DEK. Unwraps the DEK before writing anything.
    pub fn set(
        &mut self,
        env: EnvironmentId,
        name: &VarName,
        value: &SecretValue,
        key: &impl Unwrapper,
    ) -> Result<KeyId, VaultError> {
        todo!()
    }

    /// Decrypts with the DEK version stored in the row.
    pub fn get(
        &self,
        env: EnvironmentId,
        name: &VarName,
        key: &impl Unwrapper,
    ) -> Result<Option<SecretValue>, VaultError> {
        todo!()
    }

    /// Lists names without a key and without decrypting, sorted by name.
    pub fn list(&self, env: EnvironmentId) -> Result<Vec<SecretMeta>, VaultError> {
        todo!()
    }

    pub fn remove(&mut self, env: EnvironmentId, name: &VarName) -> Result<bool, VaultError> {
        todo!()
    }

    /// Renames the label only; key_id, nonce and ciphertext stay unchanged.
    pub fn rename(
        &mut self,
        env: EnvironmentId,
        from: &VarName,
        to: &VarName,
    ) -> Result<(), VaultError> {
        todo!()
    }
}
