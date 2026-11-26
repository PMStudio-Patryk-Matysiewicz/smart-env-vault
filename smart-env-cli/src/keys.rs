//! Loading the device key for commands, in keychain or passphrase mode
//! (ADR-002). Never asks for a passphrase: a locked key is an error that
//! points at `smart-env unlock`.

use smart_env_vault::{DeviceKey, KeyError, VaultError};

use crate::{CliError, Context, Exit};

/// The device key: from the system keychain, or (when the data directory
/// holds `device.key`, passphrase mode) from the kernel keyring after
/// `smart-env unlock`.
///
/// # Errors
/// `key_locked` (passphrase mode, not unlocked or expired),
/// `device_key_missing`, `keychain_unavailable`,
/// `session_keyring_unavailable`.
pub fn device_key(ctx: &Context<'_>) -> Result<DeviceKey, CliError> {
    let data = ctx.data.as_ref().ok_or_else(no_data_directory)?;
    if data.key_file().exists() {
        ctx.session
            .load()
            .map_err(key_error)?
            .ok_or_else(|| key_error(KeyError::Locked))
    } else {
        ctx.keys
            .load()
            .map_err(key_error)?
            .ok_or_else(device_key_missing)
    }
}

pub(crate) fn key_error(error: KeyError) -> CliError {
    VaultError::Key(error).into()
}

pub(crate) fn no_data_directory() -> CliError {
    CliError::new(
        "no_data_directory",
        Exit::Failure,
        "The system did not provide a user data directory.",
    )
    .with_hint("Set HOME (or XDG_DATA_HOME) and try again")
}

pub(crate) fn device_key_missing() -> CliError {
    CliError::new(
        "device_key_missing",
        Exit::Access,
        "A vault exists, but this device has no key that opens it.",
    )
    .with_hint("Restore access with your recovery key: smart-env recover")
}

pub(crate) fn not_set_up() -> CliError {
    CliError::new(
        "not_set_up",
        Exit::NotFound,
        "smart-env is not set up on this device yet.",
    )
    .with_hint("Run: smart-env setup")
}
