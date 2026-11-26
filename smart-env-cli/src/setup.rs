//! `smart-env setup`: device key, owner account, vault and recovery key,
//! once per machine ([[05 - Kontrakt DX]] Scenario 0, F01, ADR-012).
//!
//! The recovery key is shown and confirmed before anything is written, so an
//! interrupted or failed setup leaves nothing behind.

use std::fs;
use std::io::Write;
use std::path::Path;

use secrecy::{ExposeSecret, SecretString};
use smart_env_vault::{
    DataPaths, DataPathsError, DeviceKey, KeyError, KeyStore, PassphraseFileStore, RecipientKind,
    RecoveryKey, Role, Vault,
};
use zeroize::Zeroizing;

use crate::keys::{device_key_missing, key_error, no_data_directory};
use crate::lock::unlocked_line;
use crate::{CliError, Context, Exit, Interaction, Terminal};

/// Wrong answers allowed when confirming the recovery key or choosing a
/// passphrase.
const CONFIRM_ATTEMPTS: usize = 3;
/// Longest label the vault accepts (accounts, recipients).
const MAX_LABEL: usize = 128;
/// Shortest passphrase for the device key file.
const MIN_PASSPHRASE: usize = 8;

/// Where the device key is, decided before anything is shown or written.
enum Source {
    /// System keychain, with the key if one is saved.
    Keychain(Option<DeviceKey>),
    /// No keychain: passphrase file `device.key` plus the kernel keyring.
    Passphrase {
        file_exists: bool,
        unlocked: Option<DeviceKey>,
    },
}

/// A key this run creates (and removes again if setup fails).
enum NewKey {
    Keychain,
    File(SecretString),
}

/// Runs `setup`. Human output (`✓` lines) or one JSON object goes to `out`;
/// the recovery key, the passphrase and the prompts only through
/// [`Context::terminal`].
///
/// `--yes` changes nothing: the recovery key is always confirmed by typing.
pub(crate) fn run(
    ctx: &mut Context<'_>,
    _interaction: Interaction,
    json: bool,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let data = ctx.data.clone().ok_or_else(no_data_directory)?;
    // Before anything is generated or shown: an unusable key store must not
    // cost the user a recovery key they wrote down for nothing.
    let source = key_source(ctx, &data)?;

    if data.vault_db().exists() {
        match &source {
            Source::Keychain(stored) => {
                let device = stored.clone().ok_or_else(device_key_missing)?;
                check_device(&Vault::open(data.vault_db())?, &device)?;
            }
            // Checking the key needs the passphrase; `unlock` does that.
            Source::Passphrase {
                file_exists: true, ..
            } => {}
            // A keychain vault whose keychain cannot be reached now.
            Source::Passphrase {
                file_exists: false, ..
            } => return Err(key_error(KeyError::KeychainUnavailable)),
        }
        report(out, json, "already_configured", &data, || {
            vec![format!(
                "✓ smart-env is already set up on this device ({})",
                data.directory().display()
            )]
        });
        return Ok(Exit::Success);
    }

    let terminal = ctx.terminal.as_deref_mut().ok_or_else(terminal_required)?;
    let (device, new_key) = match source {
        Source::Keychain(Some(stored)) => (stored, None),
        Source::Keychain(None) => (DeviceKey::generate(), Some(NewKey::Keychain)),
        // Left over from an interrupted setup: reuse it once unlocked.
        Source::Passphrase {
            file_exists: true,
            unlocked,
        } => (unlocked.ok_or_else(|| key_error(KeyError::Locked))?, None),
        Source::Passphrase {
            file_exists: false, ..
        } => {
            let passphrase = choose_passphrase(terminal)?;
            (DeviceKey::generate(), Some(NewKey::File(passphrase)))
        }
    };
    let (recovery, recovery_text) = RecoveryKey::generate();

    confirm_recovery(terminal, &recovery_text)?;
    if !json {
        let _ = writeln!(out, "✓ Recovery key confirmed");
    }

    let state_existed = data.state_db().exists();
    let account_label = label(&ctx.account_label, "owner");
    let device_label = device_label(&ctx.device_label, &account_label);
    let labels = (account_label, device_label);
    let written = store_key(ctx, &data, &device, new_key.as_ref())
        .and_then(|()| create_vault(&data, &device, &recovery, &labels));
    if let Err(error) = written {
        // Only what this run created; files that existed stay untouched.
        let _ = fs::remove_file(data.vault_db());
        if !state_existed {
            let _ = fs::remove_file(data.state_db());
        }
        match new_key {
            Some(NewKey::Keychain) => {
                let _ = ctx.keys.delete();
            }
            Some(NewKey::File(_)) => {
                let _ = fs::remove_file(data.key_file());
                let _ = ctx.session.delete();
            }
            None => {}
        }
        return Err(error);
    }

    report(out, json, "created", &data, || {
        let mut lines = match new_key {
            Some(NewKey::Keychain) => vec!["✓ Device key saved in the system keychain".to_owned()],
            Some(NewKey::File(_)) => vec![
                format!(
                    "✓ Device key saved in an encrypted file ({})",
                    data.key_file().display()
                ),
                unlocked_line(),
            ],
            None => vec!["✓ Using the device key saved earlier on this device".to_owned()],
        };
        lines.push(format!("✓ Vault created ({})", data.directory().display()));
        lines.push("Next, in your project directory: smart-env init".to_owned());
        lines
    });
    Ok(Exit::Success)
}

fn key_source(ctx: &Context<'_>, data: &DataPaths) -> Result<Source, CliError> {
    let file_exists = data.key_file().exists();
    if !file_exists {
        match ctx.keys.load() {
            Ok(stored) => return Ok(Source::Keychain(stored)),
            Err(KeyError::KeychainUnavailable) => {}
            Err(error) => return Err(key_error(error)),
        }
    }
    // Passphrase mode is useless without the kernel keyring: every command
    // would need the passphrase.
    let unlocked = ctx.session.load().map_err(key_error)?;
    Ok(Source::Passphrase {
        file_exists,
        unlocked,
    })
}

/// Asks for a new passphrase twice, up to [`CONFIRM_ATTEMPTS`] times.
fn choose_passphrase(terminal: &mut dyn Terminal) -> Result<SecretString, CliError> {
    terminal.show("! No system keychain. The device key will be encrypted with a passphrase.\n");
    for attempt in 1..=CONFIRM_ATTEMPTS {
        let first = terminal
            .ask_secret("? Passphrase for the device key: ")
            .map_err(|_| passphrase_not_set())?;
        let second = terminal
            .ask_secret("? Repeat the passphrase: ")
            .map_err(|_| passphrase_not_set())?;
        let problem = if first.expose_secret() != second.expose_secret() {
            "✗ The passphrases do not match.\n"
        } else if first.expose_secret().chars().count() < MIN_PASSPHRASE {
            "✗ The passphrase must have at least 8 characters.\n"
        } else {
            return Ok(first);
        };
        if attempt < CONFIRM_ATTEMPTS {
            terminal.show(problem);
        }
    }
    Err(passphrase_not_set())
}

/// Saves a key created by this run: keychain, or passphrase file plus
/// unlock in the kernel keyring.
fn store_key(
    ctx: &Context<'_>,
    data: &DataPaths,
    device: &DeviceKey,
    new_key: Option<&NewKey>,
) -> Result<(), CliError> {
    match new_key {
        None => Ok(()),
        Some(NewKey::Keychain) => ctx.keys.save(device).map_err(key_error),
        Some(NewKey::File(passphrase)) => {
            create_private_dir(data.directory())?;
            PassphraseFileStore::new(data.key_file(), passphrase.clone())
                .save(device)
                .map_err(key_error)?;
            ctx.session.save(device).map_err(key_error)
        }
    }
}

/// The data directory, owner-only from the start (the key file goes there
/// before the vault).
fn create_private_dir(directory: &Path) -> Result<(), CliError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(directory).map_err(|_| storage_error())
}

/// Shows the recovery key once and asks for its last 4 characters, up to
/// [`CONFIRM_ATTEMPTS`] times.
fn confirm_recovery(terminal: &mut dyn Terminal, key: &SecretString) -> Result<(), CliError> {
    let key = key.expose_secret();
    let shown = Zeroizing::new(format!(
        "! Recovery key (shown only once). Save it in your password manager.\n  \
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
            terminal.show("✗ That does not match. Check the saved key and try again.\n");
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
        Err(key_error(KeyError::Unwrap))
    }
}

/// Trims, falls back when empty, cuts to [`MAX_LABEL`] characters.
fn label(raw: &str, fallback: &str) -> String {
    match raw.trim() {
        "" => fallback.to_owned(),
        text => text.chars().take(MAX_LABEL).collect(),
    }
}

/// Host name as the device label; a placeholder host name (empty,
/// `localhost`, `localhost.localdomain`) becomes `<account>-<os>`, so lists
/// of devices stay readable.
fn device_label(host: &str, account_label: &str) -> String {
    let host = host.trim();
    let placeholder = host.is_empty()
        || host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("localhost.localdomain");
    if placeholder {
        label(
            &format!("{account_label}-{}", std::env::consts::OS),
            "device",
        )
    } else {
        label(host, "device")
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

fn data_error(error: DataPathsError) -> CliError {
    match error {
        DataPathsError::Vault(error) => error.into(),
        _ => storage_error(),
    }
}

fn storage_error() -> CliError {
    CliError::new(
        "storage_error",
        Exit::Failure,
        "Could not create the smart-env data directory.",
    )
    .with_hint("Diagnose: smart-env doctor")
}

fn passphrase_not_set() -> CliError {
    CliError::new(
        "passphrase_not_set",
        Exit::Failure,
        "No passphrase was set; nothing was saved.",
    )
    .with_hint("Run smart-env setup again")
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
    .with_hint("Run smart-env setup again to get a new key")
}
