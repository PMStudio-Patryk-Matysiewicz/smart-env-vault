//! `smart-env allow` / `deny`: whether the shell hook may load a project
//! directory on this device (ADR-005, direnv-like trust).
//!
//! A decision belongs to the directory holding `smart-env.toml` (canonical
//! path). `allow` is bound to the file's SHA-256 and `project_id`, so any
//! change to the file revokes it; `deny` holds whatever the file says.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::json;
use sha2::{Digest, Sha256};
use smart_env_vault::{DataPaths, DataPathsError, TrustDecision, Vault};

use crate::hook::display;
use crate::keys::{no_data_directory, not_set_up};
use crate::{CliError, Context, Exit, ProjectFile, ProjectFileError};

/// Whether the shell hook may load a project directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustStatus {
    /// Allowed, and `smart-env.toml` is unchanged since.
    Allowed,
    /// Allowed once, but `smart-env.toml` changed since.
    Changed,
    /// No decision for this directory (new, or moved).
    NotAllowed,
    /// Denied with `smart-env deny`.
    Denied,
}

/// The project a directory belongs to and the decision about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trust {
    /// Directory holding `smart-env.toml` (canonical).
    pub dir: PathBuf,
    /// Project name from `smart-env.toml`.
    pub project: String,
    /// The decision.
    pub status: TrustStatus,
}

/// Finds the project of `start` (nearest `smart-env.toml`) and checks the
/// decision about it. Needs no key.
///
/// # Errors
/// `not_set_up`, `project_file_*`, storage errors.
pub fn check_trust(ctx: &Context<'_>, start: &Path) -> Result<Trust, CliError> {
    let data = set_up(ctx)?;
    let project = ProjectDir::find(start)?;
    let status = match data
        .state()
        .map_err(state_error)?
        .trust(&project.dir)
        .map_err(state_error)?
    {
        None => TrustStatus::NotAllowed,
        Some(TrustDecision::Denied) => TrustStatus::Denied,
        Some(decision) if decision == project.decision() => TrustStatus::Allowed,
        Some(TrustDecision::Allowed { .. }) => TrustStatus::Changed,
    };
    Ok(Trust {
        dir: project.dir,
        project: project.file.project,
        status,
    })
}

/// `smart-env allow [DIR]`.
pub(crate) fn allow(
    ctx: &mut Context<'_>,
    json: bool,
    dir: Option<&Path>,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let start = start_dir(ctx, dir)?;
    let data = set_up(ctx)?;
    let project = ProjectDir::find(&start)?;
    // Only projects of this vault: allowing an unknown one has no effect,
    // and a mismatched id is exactly what a tampered file looks like.
    let resolved = project.file.resolve(&Vault::open(data.vault_db())?)?;
    let name = resolved
        .renamed_to
        .clone()
        .unwrap_or_else(|| project.file.project.clone());
    let label = format!("{name}/{}", project.file.environment);
    let shown = display(&project.dir, ctx.shell.home.as_deref());

    let state = data.state().map_err(state_error)?;
    let decision = project.decision();
    let previous = state.trust(&project.dir).map_err(state_error)?;
    let already = previous.as_ref() == Some(&decision);
    if !already {
        state
            .set_trust(&project.dir, &decision)
            .map_err(state_error)?;
    }

    let _ = if json {
        writeln!(
            out,
            "{}",
            json!({
                "status": if already { "already_allowed" } else { "allowed" },
                "path": project.dir.display().to_string(),
                "project": name,
                "environment": project.file.environment,
            })
        )
    } else if already {
        writeln!(out, "✓ {label} in {shown} is already allowed")
    } else {
        let changed = if matches!(previous, Some(TrustDecision::Allowed { .. })) {
            " (smart-env.toml changed since the last allow)"
        } else {
            ""
        };
        writeln!(out, "✓ Allowed {label} in {shown}{changed}")
            .and_then(|()| writeln!(out, "A change to smart-env.toml revokes it."))
    };
    if let Some(warning) = resolved.warning() {
        let _ = writeln!(out, "! {warning}");
    }
    Ok(Exit::Success)
}

/// `smart-env deny [DIR]`.
pub(crate) fn deny(
    ctx: &mut Context<'_>,
    json: bool,
    dir: Option<&Path>,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let start = start_dir(ctx, dir)?;
    let data = set_up(ctx)?;
    // Not resolved against the vault: denying a foreign project must work.
    let project = ProjectDir::find(&start)?;
    data.state()
        .map_err(state_error)?
        .set_trust(&project.dir, &TrustDecision::Denied)
        .map_err(state_error)?;

    let _ = if json {
        writeln!(
            out,
            "{}",
            json!({ "status": "denied", "path": project.dir.display().to_string() })
        )
    } else {
        writeln!(
            out,
            "✓ The shell hook will not load {}. Allow it again with: smart-env allow",
            display(&project.dir, ctx.shell.home.as_deref())
        )
    };
    Ok(Exit::Success)
}

/// Allows `dir` (holding a freshly written `smart-env.toml`) for `init`.
///
/// # Errors
/// `project_file_*`, storage errors.
pub(crate) fn allow_project_dir(ctx: &Context<'_>, dir: &Path) -> Result<(), CliError> {
    let data = set_up(ctx)?;
    let project = ProjectDir::find(dir)?;
    data.state()
        .map_err(state_error)?
        .set_trust(&project.dir, &project.decision())
        .map_err(state_error)
}

/// A project directory: where `smart-env.toml` is, what it says, its hash.
struct ProjectDir {
    /// Canonical directory holding `smart-env.toml`.
    dir: PathBuf,
    file: ProjectFile,
    hash: [u8; 32],
}

impl ProjectDir {
    fn find(start: &Path) -> Result<Self, CliError> {
        let (path, file) = ProjectFile::find(start)?;
        let unreadable = || CliError::from(ProjectFileError::Unreadable(path.clone()));
        let bytes = fs::read(&path).map_err(|_| unreadable())?;
        let dir = path
            .parent()
            .and_then(|dir| fs::canonicalize(dir).ok())
            .ok_or_else(unreadable)?;
        Ok(Self {
            dir,
            file,
            hash: Sha256::digest(&bytes).into(),
        })
    }

    /// `allow` for exactly this content.
    fn decision(&self) -> TrustDecision {
        TrustDecision::Allowed {
            file_hash: self.hash,
            project_id: self.file.project_id,
        }
    }
}

/// `DIR` (relative to the working directory) or the working directory; a
/// missing `DIR` is an error, so its parents' smart-env.toml is never used.
fn start_dir(ctx: &Context<'_>, dir: Option<&Path>) -> Result<PathBuf, CliError> {
    let current = ctx.current_dir.as_ref();
    let start = match (dir, current) {
        (Some(dir), _) if dir.is_absolute() => dir.to_path_buf(),
        (Some(dir), Some(current)) => current.join(dir),
        (None, Some(current)) => current.clone(),
        (_, None) => {
            return Err(CliError::new(
                "no_current_directory",
                Exit::Failure,
                "Cannot determine the current directory.",
            )
            .with_hint("Name the project directory: smart-env allow DIR"));
        }
    };
    if !start.is_dir() {
        return Err(CliError::new(
            "directory_not_found",
            Exit::NotFound,
            format!("Directory not found: {}.", start.display()),
        )
        .with_hint("Check the path"));
    }
    Ok(start)
}

fn set_up(ctx: &Context<'_>) -> Result<DataPaths, CliError> {
    let data = ctx.data.clone().ok_or_else(no_data_directory)?;
    if !data.vault_db().exists() {
        return Err(not_set_up());
    }
    Ok(data)
}

fn state_error(error: DataPathsError) -> CliError {
    match error {
        DataPathsError::Vault(error) => error.into(),
        DataPathsError::UnsupportedState => CliError::new(
            "unsupported_state",
            Exit::Failure,
            "state.db is not a smart-env state database or comes from a newer version.",
        )
        .with_hint("Update smart-env or check: smart-env doctor"),
        _ => CliError::new(
            "storage_error",
            Exit::Failure,
            "Could not read or write state.db.",
        )
        .with_hint("Diagnose: smart-env doctor"),
    }
}
