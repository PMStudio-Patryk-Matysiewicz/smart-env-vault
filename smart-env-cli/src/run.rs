//! `smart-env run [--only A,B | --except C] -- <command>`: starts the command
//! with the environment's variables added to its environment, and exits with
//! its exit code ([[05 - Kontrakt DX]] Scenario 1 without the hook, F06 4).
//!
//! Variables reach only the command, never its arguments, and never the
//! shell. Reserved names (ADR-005) are skipped with a warning. stdout belongs
//! to the command: `run` writes nothing there; warnings go to stderr.

use std::io::Write;

use crate::{CliError, Context, EnvRef, Exit};

/// Runs `command` (program and arguments) with the variables of the
/// environment chosen by `env`.
///
/// Checks everything (environment, key, `--only` / `--except` names) before
/// starting anything.
pub(crate) fn run(
    _ctx: &mut Context<'_>,
    _env: Option<&EnvRef>,
    _only: &[String],
    _except: &[String],
    _command: &[String],
    _err: &mut dyn Write,
) -> Result<Exit, CliError> {
    todo!()
}
