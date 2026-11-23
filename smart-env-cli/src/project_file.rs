//! `smart-env.toml`: the committed, secret-free project config (F06, F03).
//!
//! Errors never quote the file: someone may have pasted a secret into it, so
//! only key names, line numbers and paths appear in messages.

use std::path::{Path, PathBuf};

use crate::CliError;
use smart_env_vault::{ProjectId, Vault};

/// Name of the project config file.
pub const FILE_NAME: &str = "smart-env.toml";

/// Parsed `smart-env.toml`.
#[derive(Clone, Debug, PartialEq)]
pub struct ProjectFile {
    /// Project name (a label; [`Self::project_id`] decides).
    pub project: String,
    /// Stable project id.
    pub project_id: ProjectId,
    /// Default environment name.
    pub environment: String,
    /// Server URL (stage 2), stored as given.
    pub server: Option<String>,
    /// Names of the `[sync.*]` targets (F12 validates their content), in
    /// file order.
    pub sync: Vec<String>,
}

/// Why `smart-env.toml` could not be found or read. Never carries file content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProjectFileError {
    /// No `smart-env.toml` in the start directory or any parent.
    NotFound,
    /// The file exists but cannot be read.
    Unreadable(PathBuf),
    /// Not valid TOML; 1-based line of the error.
    Syntax {
        /// Line of the error, when known.
        line: Option<usize>,
    },
    /// A required key is missing.
    MissingKey(&'static str),
    /// A top-level key smart-env does not know (often a pasted variable).
    UnknownKey(String),
    /// A known key has the wrong type or an invalid value.
    InvalidValue(&'static str),
}

/// Project of `smart-env.toml` resolved against the vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedProject {
    /// Project id (from the file, confirmed by the vault).
    pub id: ProjectId,
    /// Current vault name when it differs from `project` in the file.
    pub renamed_to: Option<String>,
}

impl ResolvedProject {
    /// Warning to show when the project was renamed since the file was written.
    pub fn warning(&self) -> Option<String> {
        todo!()
    }
}

impl ProjectFile {
    /// Parses the file content.
    ///
    /// # Errors
    /// [`ProjectFileError::Syntax`], `MissingKey`, `UnknownKey` or `InvalidValue`.
    pub fn parse(_text: &str) -> Result<Self, ProjectFileError> {
        todo!()
    }

    /// Finds the nearest `smart-env.toml` in `start` or its parents and parses it.
    ///
    /// # Errors
    /// [`ProjectFileError::NotFound`] if there is none; `Unreadable` if the
    /// nearest one cannot be read (parents are not tried); parse errors.
    pub fn find(_start: &Path) -> Result<(PathBuf, Self), ProjectFileError> {
        todo!()
    }

    /// Translates the file's project into an id; the id decides, the name
    /// never does.
    ///
    /// # Errors
    /// `project_id_mismatch` (exit 5) if the id is unknown but a project with
    /// this name exists; `project_not_found` (exit 4) if neither is known.
    pub fn resolve(&self, _vault: &Vault) -> Result<ResolvedProject, CliError> {
        todo!()
    }
}

impl From<ProjectFileError> for CliError {
    fn from(_error: ProjectFileError) -> Self {
        todo!()
    }
}
