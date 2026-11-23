//! `smart-env init`: imports the project's `.env` files into the vault in one
//! transaction, verifies every value, writes `smart-env.toml` and
//! `.gitignore`, warns about git history and reserved names, and only then
//! offers to delete the plaintext ([[05 - Kontrakt DX]] Scenario 1, F06 3).
//!
//! File mapping: `.env` → `dev`, `.env.<x>` → `x` (`development` → `dev`,
//! `production` → `prod`); `*.local` files override their base file;
//! templates (`.env.example`, `.sample`, `.template`, `.dist`) are skipped.

use std::io::Write;

use crate::{CliError, Context, EnvRef, Exit, Interaction};

/// Runs `init` in [`Context::current_dir`]. `env` (`--env`) overrides the
/// project name (project part) and the default environment written to
/// `smart-env.toml` (environment part).
pub(crate) fn run(
    _ctx: &mut Context<'_>,
    _interaction: Interaction,
    _json: bool,
    _env: Option<&EnvRef>,
    _out: &mut dyn Write,
) -> Result<Exit, CliError> {
    todo!()
}
