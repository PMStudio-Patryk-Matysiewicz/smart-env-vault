//! `smart-env status`: what is active in this shell, the project here and
//! its trust, reserved and run-only names, the key, auto-activation. Never
//! decrypts a value.

use std::io::Write;

use crate::{CliError, Context, Exit};

/// Prints the status (human lines or one JSON object) to `out`.
///
/// # Errors
/// `not_set_up`, storage errors.
pub(crate) fn status(
    ctx: &mut Context<'_>,
    json: bool,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let _ = (ctx, json, out);
    todo!("status")
}
