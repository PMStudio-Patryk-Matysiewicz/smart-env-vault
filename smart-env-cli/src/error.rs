use smart_env_vault::{KeyError, SecretError, VaultError};

use crate::Exit;

/// Error reported to the user: what happened, why, and the command that fixes
/// it. Never carries secret values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliError {
    code: &'static str,
    message: String,
    hint: Option<String>,
    exit: Exit,
}

impl CliError {
    /// New error with a stable machine-readable `code` (snake_case).
    pub fn new(code: &'static str, exit: Exit, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            hint: None,
            exit,
        }
    }

    /// Adds the "how to fix" line, usually a command.
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Wrong usage of the command line (code `usage`, exit 2).
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new("usage", Exit::Usage, message).with_hint("Help: smart-env --help")
    }

    /// The action needs a confirmation but there is no terminal to ask and no
    /// `--yes` (code `confirmation_required`, exit 2).
    pub fn confirmation_required(action: &str) -> Self {
        Self::new(
            "confirmation_required",
            Exit::Usage,
            format!("Confirmation needed ({action}), but there is no terminal to ask."),
        )
        .with_hint("Confirm up front with --yes")
    }

    /// Stable machine-readable code, e.g. `environment_not_found`.
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// What happened.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// How to fix it.
    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }

    /// Process exit code for this error.
    pub fn exit(&self) -> Exit {
        self.exit
    }

    /// Human form for stderr: `✗ <message>` and the hint indented below.
    pub fn render_human(&self) -> String {
        match &self.hint {
            Some(hint) => format!("✗ {}\n  {hint}\n", self.message),
            None => format!("✗ {}\n", self.message),
        }
    }

    /// `--json` form for stdout:
    /// `{"error": {"code": "...", "message": "...", "hint": "..." | null}}`.
    pub fn render_json(&self) -> String {
        serde_json::json!({
            "error": {
                "code": self.code,
                "message": self.message,
                "hint": self.hint,
            }
        })
        .to_string()
    }
}

/// Messages never use the library's `Display` of values; only a variable
/// name (not secret) may appear.
impl From<VaultError> for CliError {
    fn from(error: VaultError) -> Self {
        use Exit::{Access, Conflict, Failure, NotFound, Usage};
        let doctor = "Diagnose: smart-env doctor";
        let (code, exit, message, hint) = match error {
            VaultError::ProjectNotFound => (
                "project_not_found",
                NotFound,
                "Project not found.".to_owned(),
                "Check the project name in --env or smart-env.toml",
            ),
            VaultError::EnvironmentNotFound => (
                "environment_not_found",
                NotFound,
                "Environment not found.".to_owned(),
                "Check the environment name in --env or smart-env.toml",
            ),
            VaultError::SecretNotFound => (
                "secret_not_found",
                NotFound,
                "Variable not found.".to_owned(),
                "List variables: smart-env ls",
            ),
            VaultError::RecipientNotFound => (
                "recipient_not_found",
                NotFound,
                "Key recipient not found.".to_owned(),
                doctor,
            ),
            VaultError::AccountNotFound => (
                "account_not_found",
                NotFound,
                "Account not found.".to_owned(),
                doctor,
            ),
            VaultError::AlreadyMember => (
                "already_member",
                Conflict,
                "This account is already a member of the vault.".to_owned(),
                "Nothing to do",
            ),
            VaultError::NotAMember => (
                "not_a_member",
                Access,
                "The account is not a member of this vault, so its device gets no access."
                    .to_owned(),
                "Add the account to the vault as a member first",
            ),
            VaultError::DeviceNeedsAccount => (
                "device_needs_account",
                Failure,
                "A device must belong to an account.".to_owned(),
                doctor,
            ),
            VaultError::NothingToUndo => (
                "nothing_to_undo",
                NotFound,
                "No earlier version to restore.".to_owned(),
                "Variable history: smart-env history NAME",
            ),
            VaultError::VersionNotFound => (
                "version_not_found",
                NotFound,
                "This version is not in the variable's history.".to_owned(),
                "Versions: smart-env history NAME",
            ),
            VaultError::ProjectNameTaken => (
                "project_name_taken",
                Conflict,
                "A project with this name already exists.".to_owned(),
                "Choose another project name",
            ),
            VaultError::EnvironmentNameTaken => (
                "environment_name_taken",
                Conflict,
                "An environment with this name already exists in the project.".to_owned(),
                "Choose another environment name",
            ),
            VaultError::SecretNameTaken => (
                "secret_name_taken",
                Conflict,
                "A variable with this name already exists (possibly removed).".to_owned(),
                "Choose another name or restore the removed one: smart-env undo NAME",
            ),
            VaultError::RecipientKeyTaken => (
                "recipient_key_taken",
                Conflict,
                "This key is already a recipient of the vault.".to_owned(),
                "Nothing to do",
            ),
            VaultError::DuplicateName(name) => (
                "duplicate_name",
                Conflict,
                format!("Variable {name} appears more than once in the import; nothing was saved."),
                "Remove the duplicate and try again",
            ),
            VaultError::AlreadyExists => (
                "vault_exists",
                Conflict,
                "The vault already exists.".to_owned(),
                "Nothing to do — smart-env setup has already run",
            ),
            VaultError::UnsupportedSchema => (
                "unsupported_vault",
                Failure,
                "The file is not a smart-env vault or comes from a newer version.".to_owned(),
                "Update smart-env or check: smart-env doctor",
            ),
            VaultError::NoRecipients => (
                "no_recipients",
                Failure,
                "The vault has no active key recipient.".to_owned(),
                doctor,
            ),
            VaultError::Key(KeyError::Unwrap) => (
                "key_mismatch",
                Access,
                "This device's key does not open this environment.".to_owned(),
                doctor,
            ),
            VaultError::Key(KeyError::KeychainUnavailable) => (
                "keychain_unavailable",
                Access,
                "The system keychain is unavailable and the key is not unlocked.".to_owned(),
                "Unlock the key: smart-env unlock",
            ),
            VaultError::Key(KeyError::WrongPassphrase) => (
                "wrong_passphrase",
                Access,
                "Wrong passphrase for the key file.".to_owned(),
                "Try again: smart-env unlock",
            ),
            VaultError::Key(KeyError::Locked) => (
                "key_locked",
                Access,
                "The device key is locked.".to_owned(),
                "Unlock it: smart-env unlock",
            ),
            VaultError::Key(KeyError::SessionUnavailable) => (
                "session_keyring_unavailable",
                Failure,
                "The kernel keyring that keeps the unlocked key is unavailable.".to_owned(),
                "Passphrase mode needs the Linux kernel keyring (some containers block it); diagnose: smart-env doctor",
            ),
            VaultError::Key(_) => (
                "key_error",
                Failure,
                "Could not use the device key.".to_owned(),
                doctor,
            ),
            VaultError::Secret(SecretError::InvalidName) => (
                "invalid_name",
                Usage,
                "Invalid variable name.".to_owned(),
                "Name: letters, digits and _, not starting with a digit, up to 255 characters",
            ),
            VaultError::Secret(SecretError::ValueTooLarge) => (
                "value_too_large",
                Usage,
                "The value is larger than 64 KiB.".to_owned(),
                "Keep larger data in a file and store its path in the variable",
            ),
            VaultError::Secret(SecretError::InvalidValue) => (
                "invalid_value",
                Usage,
                "The value contains a NUL byte.".to_owned(),
                "Remove the NUL byte from the value",
            ),
            VaultError::Secret(SecretError::Decrypt) => (
                "decrypt_failed",
                Failure,
                "The value cannot be decrypted — the data is corrupted or was tampered with."
                    .to_owned(),
                doctor,
            ),
            VaultError::Secret(_) => (
                "crypto_error",
                Failure,
                "Encryption error.".to_owned(),
                doctor,
            ),
            VaultError::Storage(_) | VaultError::Io(_) => (
                "storage_error",
                Failure,
                "Could not read or write the vault.".to_owned(),
                doctor,
            ),
        };
        Self::new(code, exit, message).with_hint(hint)
    }
}
