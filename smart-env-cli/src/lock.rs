//! `smart-env unlock` / `smart-env lock` (F01 8, ADR-002): the unlocked
//! device key lives in the kernel keyring for [`UNLOCK_TTL`]; nothing else
//! ever asks for the passphrase.

use std::io::Write;

use smart_env_vault::{DataPaths, KeyStore, PassphraseFileStore};

use crate::keys::{key_error, no_data_directory, not_set_up};
use crate::{CliError, Context, Exit, UNLOCK_TTL};

/// How the device key is kept, from what is on disk.
enum Mode {
    NotSetUp,
    Keychain,
    Passphrase,
}

fn mode(data: &DataPaths) -> Mode {
    if data.key_file().exists() {
        Mode::Passphrase
    } else if data.vault_db().exists() {
        Mode::Keychain
    } else {
        Mode::NotSetUp
    }
}

/// `✓ Key unlocked for 8 h (…)`, shared with `setup`.
pub(crate) fn unlocked_line() -> String {
    format!(
        "✓ Key unlocked for {} h (lock it sooner: smart-env lock)",
        UNLOCK_TTL.as_secs() / 3600
    )
}

/// Asks for the passphrase once (terminal only) and keeps the key unlocked.
pub(crate) fn unlock(
    ctx: &mut Context<'_>,
    json: bool,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let data = ctx.data.clone().ok_or_else(no_data_directory)?;
    match mode(&data) {
        Mode::NotSetUp => Err(not_set_up()),
        Mode::Keychain => {
            not_needed(out, json, "unlock");
            Ok(Exit::Success)
        }
        Mode::Passphrase => {
            // A missing kernel keyring is reported before the prompt.
            ctx.session.load().map_err(key_error)?;
            let terminal = ctx.terminal.as_deref_mut().ok_or_else(|| {
                CliError::new(
                    "terminal_required",
                    Exit::Usage,
                    "smart-env unlock asks for the passphrase and needs a terminal (also with --yes).",
                )
                .with_hint("Run smart-env unlock in a terminal")
            })?;
            let passphrase = terminal.ask_secret("? Passphrase: ").map_err(|_| {
                CliError::new(
                    "unlock_cancelled",
                    Exit::Failure,
                    "No passphrase was entered; the key stays locked.",
                )
                .with_hint("Try again: smart-env unlock")
            })?;
            let key = PassphraseFileStore::new(data.key_file(), passphrase)
                .load()
                .map_err(key_error)?
                .ok_or_else(not_set_up)?;
            ctx.session.save(&key).map_err(key_error)?;
            let _ = if json {
                writeln!(
                    out,
                    "{}",
                    serde_json::json!({
                        "status": "unlocked",
                        "expires_in_seconds": UNLOCK_TTL.as_secs(),
                    })
                )
            } else {
                writeln!(out, "{}", unlocked_line())
            };
            Ok(Exit::Success)
        }
    }
}

/// Forgets the unlocked key now. Idempotent; never asks.
pub(crate) fn lock(
    ctx: &mut Context<'_>,
    json: bool,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let data = ctx.data.clone().ok_or_else(no_data_directory)?;
    match mode(&data) {
        Mode::NotSetUp => Err(not_set_up()),
        Mode::Keychain => {
            not_needed(out, json, "lock");
            Ok(Exit::Success)
        }
        Mode::Passphrase => {
            ctx.session.delete().map_err(key_error)?;
            let _ = if json {
                writeln!(out, "{}", serde_json::json!({ "status": "locked" }))
            } else {
                writeln!(out, "✓ Key locked")
            };
            Ok(Exit::Success)
        }
    }
}

fn not_needed(out: &mut dyn Write, json: bool, action: &str) {
    let _ = if json {
        writeln!(out, "{}", serde_json::json!({ "status": "not_needed" }))
    } else {
        writeln!(
            out,
            "✓ Nothing to {action}: the device key is in the system keychain"
        )
    };
}
