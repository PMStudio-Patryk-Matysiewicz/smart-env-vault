//! Loading the device key for commands, in keychain or passphrase mode
//! (ADR-002). Never asks for a passphrase: a locked key is an error that
//! points at `smart-env unlock`.

use smart_env_vault::DeviceKey;

use crate::{CliError, Context};

/// The device key: from the system keychain, or — when the data directory
/// holds `device.key` (passphrase mode) — from the kernel keyring after
/// `smart-env unlock`.
///
/// # Errors
/// `key_locked` (passphrase mode, not unlocked or expired),
/// `device_key_missing`, `keychain_unavailable`,
/// `session_keyring_unavailable`.
pub fn device_key(_ctx: &Context<'_>) -> Result<DeviceKey, CliError> {
    todo!()
}
