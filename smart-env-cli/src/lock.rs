//! `smart-env unlock` / `smart-env lock` (F01 8, ADR-002): the unlocked
//! device key lives in the kernel keyring for [`crate::UNLOCK_TTL`]; nothing
//! else ever asks for the passphrase.

use std::io::Write;

use crate::{CliError, Context, Exit};

/// Asks for the passphrase once (terminal only) and keeps the key unlocked.
pub(crate) fn unlock(
    _ctx: &mut Context<'_>,
    _json: bool,
    _out: &mut dyn Write,
) -> Result<Exit, CliError> {
    todo!()
}

/// Forgets the unlocked key now. Idempotent; never asks.
pub(crate) fn lock(
    _ctx: &mut Context<'_>,
    _json: bool,
    _out: &mut dyn Write,
) -> Result<Exit, CliError> {
    todo!()
}
