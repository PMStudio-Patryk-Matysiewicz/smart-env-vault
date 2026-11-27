//! `smart-env hook <shell>` (the shell integration script), the hidden
//! `smart-env hook-env <shell>` it calls at every prompt, and installing the
//! hook in the shell's startup file during `setup` (ADR-005).
//!
//! What `hook-env` does inside a project (activation, restoring, changes from
//! another tab) comes with the "mechanics" item of step 3.

use std::io::Write;
use std::path::PathBuf;

use crate::{CliError, Context, Exit, Interaction, Shell};

/// Prints the hook script for `shell` to `out`.
pub(crate) fn hook(ctx: &Context<'_>, shell: Shell, out: &mut dyn Write) -> Result<Exit, CliError> {
    let _ = (ctx, shell, out);
    todo!("hook")
}

/// Called by the hook at every prompt. Never fails and never prints an
/// error: a broken hook must not break the prompt.
pub(crate) fn hook_env(
    ctx: &mut Context<'_>,
    shell: Shell,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Exit {
    let _ = (ctx, shell, out, err);
    todo!("hook_env")
}

/// What installing the hook did.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)] // used by `setup` in the green phase
pub(crate) enum Installed {
    /// The hook block was appended to `file`.
    Added { shell: Shell, file: PathBuf },
    /// `file` already loads the hook.
    Present { shell: Shell, file: PathBuf },
    /// The user answered "no".
    Declined { shell: Shell, file: PathBuf },
    /// No terminal and no `--yes`: nothing asked, nothing written.
    Skipped { shell: Shell, file: PathBuf },
    /// `$SHELL` is missing or not bash, zsh or fish.
    UnknownShell,
    /// Writing `file` failed.
    Failed { shell: Shell, file: PathBuf },
}

/// Adds the hook to the startup file of the user's shell, once, after a
/// confirmation (or `--yes`).
#[allow(dead_code)] // used by `setup` in the green phase
pub(crate) fn install(ctx: &mut Context<'_>, interaction: Interaction) -> Installed {
    let _ = (ctx, interaction);
    todo!("hook::install")
}
