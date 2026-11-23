//! `smart-env setup`: device key, owner account, vault and recovery key,
//! once per machine ([[05 - Kontrakt DX]] Scenario 0, F01, ADR-012).
//!
//! The recovery key is shown and confirmed before anything is written, so an
//! interrupted or failed setup leaves nothing behind.

use std::io::Write;

use crate::{CliError, Context, Exit, Interaction};

/// Runs `setup`. Human output (`✓` lines) or one JSON object goes to `out`;
/// the recovery key and the prompt only through [`Context::terminal`].
pub(crate) fn run(
    _ctx: &mut Context<'_>,
    _interaction: Interaction,
    _json: bool,
    _out: &mut dyn Write,
) -> Result<Exit, CliError> {
    todo!()
}
