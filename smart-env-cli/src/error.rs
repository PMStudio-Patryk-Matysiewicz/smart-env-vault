use smart_env_vault::VaultError;

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
    pub fn usage(_message: impl Into<String>) -> Self {
        todo!("F06 11: usage error")
    }

    /// The action needs a confirmation but there is no terminal to ask and no
    /// `--yes` (code `confirmation_required`, exit 2).
    pub fn confirmation_required(_action: &str) -> Self {
        todo!("F06 11: confirmation_required error")
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
        todo!("F06 11: human error rendering")
    }

    /// `--json` form for stdout:
    /// `{"error": {"code": "...", "message": "...", "hint": "..." | null}}`.
    pub fn render_json(&self) -> String {
        todo!("F06 11: JSON error rendering")
    }
}

impl From<VaultError> for CliError {
    fn from(_error: VaultError) -> Self {
        todo!("F06 11: VaultError → CliError")
    }
}
