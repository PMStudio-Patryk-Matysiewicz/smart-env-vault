//! `smart-env setup`: device key, owner account, vault and recovery key,
//! once per machine ([[05 - Kontrakt DX]] Scenario 0, F01, ADR-012).
//!
//! The recovery key is shown and confirmed before anything is written, so an
//! interrupted or failed setup leaves nothing behind.

use std::fs;
use std::io::Write;

use secrecy::{ExposeSecret, SecretString};
use smart_env_vault::{
    DataPaths, DataPathsError, DeviceKey, KeyError, RecipientKind, RecoveryKey, Role, Vault,
    VaultError,
};
use zeroize::Zeroizing;

use crate::{CliError, Context, Exit, Interaction, Terminal};

/// Wrong answers allowed when confirming the recovery key.
const CONFIRM_ATTEMPTS: usize = 3;
/// Longest label the vault accepts (accounts, recipients).
const MAX_LABEL: usize = 128;

/// Runs `setup`. Human output (`✓` lines) or one JSON object goes to `out`;
/// the recovery key and the prompt only through [`Context::terminal`].
///
/// `--yes` changes nothing: the recovery key is always confirmed by typing.
pub(crate) fn run(
    ctx: &mut Context<'_>,
    _interaction: Interaction,
    json: bool,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let data = ctx.data.clone().ok_or_else(no_data_directory)?;
    // Before anything is generated or shown: an unreachable keychain must
    // not cost the user a recovery key they wrote down for nothing.
    let stored = ctx.keys.load().map_err(key_error)?;

    if data.vault_db().exists() {
        let device = stored.ok_or_else(device_key_missing)?;
        check_device(&Vault::open(data.vault_db())?, &device)?;
        report(out, json, "already_configured", &data, || {
            vec![format!(
                "✓ smart-env is already set up on this device ({})",
                data.directory().display()
            )]
        });
        return Ok(Exit::Success);
    }

    let terminal = ctx.terminal.as_deref_mut().ok_or_else(terminal_required)?;
    let key_is_new = stored.is_none();
    let device = stored.unwrap_or_else(DeviceKey::generate);
    let (recovery, recovery_text) = RecoveryKey::generate();

    confirm_recovery(terminal, &recovery_text)?;
    if !json {
        let _ = writeln!(out, "✓ Recovery key confirmed");
    }

    if key_is_new {
        ctx.keys.save(&device).map_err(key_error)?;
    }
    let state_existed = data.state_db().exists();
    let labels = (
        label(&ctx.account_label, "owner"),
        label(&ctx.device_label, "device"),
    );
    if let Err(error) = create_vault(&data, &device, &recovery, &labels) {
        // Only what this run created; files that existed stay untouched.
        let _ = fs::remove_file(data.vault_db());
        if !state_existed {
            let _ = fs::remove_file(data.state_db());
        }
        if key_is_new {
            let _ = ctx.keys.delete();
        }
        return Err(error);
    }

    report(out, json, "created", &data, || {
        vec![
            if key_is_new {
                "✓ Device key saved in the system keychain".to_owned()
            } else {
                "✓ Using the device key already saved in the keychain".to_owned()
            },
            format!("✓ Vault created ({})", data.directory().display()),
            "Next, in your project directory: smart-env init".to_owned(),
        ]
    });
    Ok(Exit::Success)
}

/// Shows the recovery key once and asks for its last 4 characters, up to
/// [`CONFIRM_ATTEMPTS`] times.
fn confirm_recovery(terminal: &mut dyn Terminal, key: &SecretString) -> Result<(), CliError> {
    let key = key.expose_secret();
    let shown = Zeroizing::new(format!(
        "! Recovery key (shown only once) — save it in your password manager.\n  \
         Without it, losing this device means losing your secrets.\n  {key}\n"
    ));
    terminal.show(&shown);

    let expected = &key[key.len() - 4..];
    for attempt in 1..=CONFIRM_ATTEMPTS {
        let answer = terminal
            .ask("? Type the last 4 characters of the key to confirm you saved it: ")
            .map_err(|_| recovery_not_confirmed())?;
        if answer.trim().eq_ignore_ascii_case(expected) {
            return Ok(());
        }
        if attempt < CONFIRM_ATTEMPTS {
            terminal.show("✗ That does not match — check the saved key and try again.\n");
        }
    }
    Err(recovery_not_confirmed())
}

/// Vault with the owner account, its device and the recovery recipient.
fn create_vault(
    data: &DataPaths,
    device: &DeviceKey,
    recovery: &RecoveryKey,
    (account_label, device_label): &(String, String),
) -> Result<(), CliError> {
    let (mut vault, _state) = data.initialize().map_err(data_error)?;
    let account = vault.create_account(account_label)?;
    vault.add_member(account, Role::Owner)?;
    vault.add_device(account, device_label, &device.public(), device)?;
    vault.add_recipient(
        RecipientKind::Recovery,
        "recovery",
        &recovery.public(),
        device,
    )?;
    Ok(())
}

/// The stored key must be an active device of this vault.
fn check_device(vault: &Vault, device: &DeviceKey) -> Result<(), CliError> {
    let public = device.public();
    let known = vault
        .recipients()?
        .into_iter()
        .any(|r| r.kind == RecipientKind::Device && !r.revoked && r.public_key == public);
    if known {
        Ok(())
    } else {
        Err(VaultError::Key(KeyError::Unwrap).into())
    }
}

/// Trims, falls back when empty, cuts to [`MAX_LABEL`] characters.
fn label(raw: &str, fallback: &str) -> String {
    match raw.trim() {
        "" => fallback.to_owned(),
        text => text.chars().take(MAX_LABEL).collect(),
    }
}

fn report(
    out: &mut dyn Write,
    json: bool,
    status: &str,
    data: &DataPaths,
    lines: impl FnOnce() -> Vec<String>,
) {
    let _ = if json {
        writeln!(
            out,
            "{}",
            serde_json::json!({
                "status": status,
                "data_dir": data.directory().display().to_string(),
            })
        )
    } else {
        lines().iter().try_for_each(|line| writeln!(out, "{line}"))
    };
}

fn key_error(error: KeyError) -> CliError {
    VaultError::Key(error).into()
}

fn data_error(error: DataPathsError) -> CliError {
    match error {
        DataPathsError::Vault(error) => error.into(),
        _ => CliError::new(
            "storage_error",
            Exit::Failure,
            "Could not create the smart-env data directory.",
        )
        .with_hint("Diagnose: smart-env doctor"),
    }
}

fn no_data_directory() -> CliError {
    CliError::new(
        "no_data_directory",
        Exit::Failure,
        "The system did not provide a user data directory.",
    )
    .with_hint("Set HOME (or XDG_DATA_HOME) and try again")
}

fn device_key_missing() -> CliError {
    CliError::new(
        "device_key_missing",
        Exit::Access,
        "A vault exists, but this device has no key that opens it.",
    )
    .with_hint("Restore access with your recovery key: smart-env recover")
}

fn terminal_required() -> CliError {
    CliError::new(
        "terminal_required",
        Exit::Usage,
        "smart-env setup shows the recovery key and needs a terminal (also with --yes).",
    )
    .with_hint("Run smart-env setup in a terminal")
}

fn recovery_not_confirmed() -> CliError {
    CliError::new(
        "recovery_not_confirmed",
        Exit::Failure,
        "The recovery key was not confirmed; nothing was saved.",
    )
    .with_hint("Run smart-env setup again — it will show a new key")
}
