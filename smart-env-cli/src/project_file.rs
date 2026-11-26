//! `smart-env.toml`: the committed, secret-free project config (F06, F03).
//!
//! Errors never quote the file: someone may have pasted a secret into it, so
//! only key names, line numbers and paths appear in messages.

use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::env_ref::is_valid_part;
use crate::{CliError, Exit};
use smart_env_vault::{ProjectId, Vault, VaultError};
use toml_edit::{DocumentMut, Item};

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
        self.renamed_to.as_ref().map(|name| {
            format!("The project is now called {name}. Update project in smart-env.toml.")
        })
    }
}

impl ProjectFile {
    /// Parses the file content.
    ///
    /// # Errors
    /// [`ProjectFileError::Syntax`], `MissingKey`, `UnknownKey` or `InvalidValue`.
    pub fn parse(text: &str) -> Result<Self, ProjectFileError> {
        // `TomlError`'s message quotes the offending line, so only its span
        // is used.
        let doc: DocumentMut =
            text.parse()
                .map_err(|error: toml_edit::TomlError| ProjectFileError::Syntax {
                    line: error.span().map(|span| line_of(text, span.start)),
                })?;

        let (mut project, mut project_id, mut environment) = (None, None, None);
        let (mut server, mut sync) = (None, Vec::new());
        for (key, item) in doc.as_table() {
            match key {
                "project" => project = Some(name(item, "project")?),
                "project_id" => {
                    let id = item
                        .as_str()
                        .and_then(|text| text.parse::<ProjectId>().ok())
                        .ok_or(ProjectFileError::InvalidValue("project_id"))?;
                    project_id = Some(id);
                }
                "environment" => environment = Some(name(item, "environment")?),
                "server" => {
                    let url = item
                        .as_str()
                        .ok_or(ProjectFileError::InvalidValue("server"))?;
                    server = Some(url.to_owned());
                }
                "sync" => sync = sync_targets(item)?,
                other => return Err(ProjectFileError::UnknownKey(other.to_owned())),
            }
        }

        Ok(Self {
            project: project.ok_or(ProjectFileError::MissingKey("project"))?,
            project_id: project_id.ok_or(ProjectFileError::MissingKey("project_id"))?,
            environment: environment.ok_or(ProjectFileError::MissingKey("environment"))?,
            server,
            sync,
        })
    }

    /// Finds the nearest `smart-env.toml` in `start` or its parents and parses it.
    ///
    /// # Errors
    /// [`ProjectFileError::NotFound`] if there is none; `Unreadable` if the
    /// nearest one cannot be read (parents are not tried); parse errors.
    pub fn find(start: &Path) -> Result<(PathBuf, Self), ProjectFileError> {
        // Logical path (symlinks kept), so `..` above the start works like in
        // the shell the user typed it in.
        let start =
            std::path::absolute(start).map_err(|_| ProjectFileError::Unreadable(start.into()))?;
        for dir in start.ancestors() {
            let path = dir.join(FILE_NAME);
            match fs::metadata(&path) {
                Ok(meta) if meta.is_file() => {
                    let bytes =
                        fs::read(&path).map_err(|_| ProjectFileError::Unreadable(path.clone()))?;
                    let text = String::from_utf8(bytes).map_err(|error| {
                        let valid = error.utf8_error().valid_up_to();
                        ProjectFileError::Syntax {
                            line: Some(
                                1 + error.as_bytes()[..valid]
                                    .iter()
                                    .filter(|&&b| b == b'\n')
                                    .count(),
                            ),
                        }
                    })?;
                    return Ok((path, Self::parse(&text)?));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                // Never skip a file we cannot inspect: a parent's config
                // would be used silently instead.
                Err(_) => return Err(ProjectFileError::Unreadable(path)),
            }
        }
        Err(ProjectFileError::NotFound)
    }

    /// Translates the file's project into an id; the id decides, the name
    /// never does.
    ///
    /// # Errors
    /// `project_id_mismatch` (exit 5) if the id is unknown but a project with
    /// this name exists; `project_not_found` (exit 4) if neither is known.
    pub fn resolve(&self, vault: &Vault) -> Result<ResolvedProject, CliError> {
        match vault.project_name(self.project_id) {
            Ok(name) => Ok(ResolvedProject {
                id: self.project_id,
                renamed_to: (name != self.project).then_some(name),
            }),
            Err(VaultError::ProjectNotFound) => Err(match vault.find_project(&self.project)? {
                Some(_) => CliError::new(
                    "project_id_mismatch",
                    Exit::Conflict,
                    format!(
                        "Project {} has a different project_id in the vault than in smart-env.toml, so it was not activated.",
                        self.project
                    ),
                )
                .with_hint(
                    "smart-env.toml may have been changed in the repository; check: git log -p smart-env.toml",
                ),
                None => CliError::new(
                    "project_not_found",
                    Exit::NotFound,
                    format!("Project {} from smart-env.toml is not in this vault.", self.project),
                )
                .with_hint("Create the project from your .env files: smart-env init"),
            }),
            Err(error) => Err(error.into()),
        }
    }
}

impl From<ProjectFileError> for CliError {
    fn from(error: ProjectFileError) -> Self {
        let required = "Required keys: project, project_id, environment";
        let (code, exit, message, hint) = match error {
            ProjectFileError::NotFound => (
                "project_file_not_found",
                Exit::NotFound,
                "No smart-env.toml in this directory or any parent.".to_owned(),
                "Run: smart-env init".to_owned(),
            ),
            ProjectFileError::Unreadable(path) => (
                "project_file_unreadable",
                Exit::Failure,
                format!("Cannot read {}.", path.display()),
                "Check the file and directory permissions".to_owned(),
            ),
            ProjectFileError::Syntax { line } => (
                "project_file_syntax",
                Exit::Failure,
                match line {
                    Some(line) => format!("smart-env.toml: TOML syntax error on line {line}."),
                    None => "smart-env.toml: TOML syntax error.".to_owned(),
                },
                "Fix the file; syntax: https://toml.io".to_owned(),
            ),
            ProjectFileError::MissingKey(key) => (
                "project_file_missing_key",
                Exit::Failure,
                format!("smart-env.toml: missing key {key}."),
                required.to_owned(),
            ),
            ProjectFileError::UnknownKey(key) => {
                // A quoted TOML key may hold control characters.
                let key = key.escape_debug();
                (
                    "project_file_unknown_key",
                    Exit::Failure,
                    format!("smart-env.toml: unknown key {key}."),
                    format!(
                        "smart-env.toml does not hold secrets. Remove the key from the file and store the variable: smart-env set {key}"
                    ),
                )
            }
            ProjectFileError::InvalidValue(key) => (
                "project_file_invalid_value",
                Exit::Failure,
                format!("smart-env.toml: invalid value for {key}."),
                match key {
                    "project_id" => "project_id is the UUID assigned by smart-env init",
                    "project" | "environment" => {
                        "A quoted name without spaces, control characters or /"
                    }
                    "sync" => "Sync targets as tables, e.g. [sync.github]",
                    _ => "A quoted value, e.g. server = \"https://…\"",
                }
                .to_owned(),
            ),
        };
        Self::new(code, exit, message).with_hint(hint)
    }
}

/// 1-based line of a byte offset.
fn line_of(text: &str, offset: usize) -> usize {
    let end = offset.min(text.len());
    1 + text.as_bytes()[..end]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
}

/// `project` / `environment`: a string shaped like a part of `--env`.
fn name(item: &Item, key: &'static str) -> Result<String, ProjectFileError> {
    item.as_str()
        .filter(|name| is_valid_part(name))
        .map(str::to_owned)
        .ok_or(ProjectFileError::InvalidValue(key))
}

/// Names of `[sync.*]`; every target must be a table.
fn sync_targets(item: &Item) -> Result<Vec<String>, ProjectFileError> {
    let invalid = ProjectFileError::InvalidValue("sync");
    let table = item.as_table_like().ok_or(invalid.clone())?;
    table
        .iter()
        .map(|(target, item)| {
            if item.is_table_like() {
                Ok(target.to_owned())
            } else {
                Err(invalid.clone())
            }
        })
        .collect()
}
