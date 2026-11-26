//! `set`, `ls`, `rm` and `rename`: everyday work with variables of one
//! environment ([[05 - Kontrakt DX]] Scenarios 2 and 10).
//!
//! A value is never a command-line argument: `set` reads it from a prompt
//! without echo or from stdin (`--stdin`, one trailing newline cut), and no
//! command prints it. `ls`, `rm` and `rename` work without the device key.

use std::io::Write;

use crate::{CliError, Context, EnvRef, Exit, InjectArg};

/// `smart-env set NAME [--stdin] [--inject shell|run]`.
///
/// Checks the name, the environment and the device key before reading the
/// value, so nobody types a secret only to see an error.
pub(crate) fn set(
    _ctx: &mut Context<'_>,
    _json: bool,
    _env: Option<&EnvRef>,
    _name: &str,
    _stdin: bool,
    _inject: Option<InjectArg>,
    _out: &mut dyn Write,
) -> Result<Exit, CliError> {
    todo!()
}

/// `smart-env ls`: names with markers (`run only`, `reserved`), no values.
pub(crate) fn ls(
    _ctx: &mut Context<'_>,
    _json: bool,
    _env: Option<&EnvRef>,
    _out: &mut dyn Write,
) -> Result<Exit, CliError> {
    todo!()
}

/// `smart-env rm NAME`: soft delete without asking; `undo` brings it back.
pub(crate) fn rm(
    _ctx: &mut Context<'_>,
    _json: bool,
    _env: Option<&EnvRef>,
    _name: &str,
    _out: &mut dyn Write,
) -> Result<Exit, CliError> {
    todo!()
}

/// `smart-env rename FROM TO`: only the label changes, value and version
/// stay.
pub(crate) fn rename(
    _ctx: &mut Context<'_>,
    _json: bool,
    _env: Option<&EnvRef>,
    _from: &str,
    _to: &str,
    _out: &mut dyn Write,
) -> Result<Exit, CliError> {
    todo!()
}
