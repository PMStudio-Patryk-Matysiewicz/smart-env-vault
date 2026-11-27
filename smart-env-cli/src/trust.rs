//! `smart-env allow` / `deny`: whether the shell hook may load a project
//! directory on this device (ADR-005, direnv-like trust).
//!
//! A decision belongs to the directory holding `smart-env.toml` (canonical
//! path). `allow` is bound to the file's SHA-256 and `project_id`, so any
//! change to the file revokes it; `deny` holds whatever the file says.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{CliError, Context, Exit};

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
    let _ = (ctx, start);
    todo!("check_trust")
}

/// `smart-env allow [DIR]`.
pub(crate) fn allow(
    ctx: &mut Context<'_>,
    json: bool,
    dir: Option<&Path>,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let _ = (ctx, json, dir, out);
    todo!("allow")
}

/// `smart-env deny [DIR]`.
pub(crate) fn deny(
    ctx: &mut Context<'_>,
    json: bool,
    dir: Option<&Path>,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let _ = (ctx, json, dir, out);
    todo!("deny")
}

/// Allows `dir` (holding a freshly written `smart-env.toml`) for `init`.
///
/// # Errors
/// Storage errors.
#[allow(dead_code)] // used by `init` in the green phase
pub(crate) fn allow_project_dir(ctx: &Context<'_>, dir: &Path) -> Result<(), CliError> {
    let _ = (ctx, dir);
    todo!("allow_project_dir")
}
