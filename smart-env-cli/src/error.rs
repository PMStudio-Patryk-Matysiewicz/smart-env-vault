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
        Self::new("usage", Exit::Usage, message).with_hint("Pomoc: smart-env --help")
    }

    /// The action needs a confirmation but there is no terminal to ask and no
    /// `--yes` (code `confirmation_required`, exit 2).
    pub fn confirmation_required(action: &str) -> Self {
        Self::new(
            "confirmation_required",
            Exit::Usage,
            format!("Potrzebne potwierdzenie ({action}), a nie ma terminala, żeby o nie zapytać."),
        )
        .with_hint("Potwierdź z góry flagą --yes")
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
        let doctor = "Diagnoza: smart-env doctor";
        let (code, exit, message, hint) = match error {
            VaultError::ProjectNotFound => (
                "project_not_found",
                NotFound,
                "Nie znaleziono projektu.".to_owned(),
                "Sprawdź nazwę projektu w --env lub w smart-env.toml",
            ),
            VaultError::EnvironmentNotFound => (
                "environment_not_found",
                NotFound,
                "Nie znaleziono środowiska.".to_owned(),
                "Sprawdź nazwę środowiska w --env lub w smart-env.toml",
            ),
            VaultError::SecretNotFound => (
                "secret_not_found",
                NotFound,
                "Nie znaleziono zmiennej.".to_owned(),
                "Lista zmiennych: smart-env ls",
            ),
            VaultError::RecipientNotFound => (
                "recipient_not_found",
                NotFound,
                "Nie znaleziono odbiorcy klucza.".to_owned(),
                doctor,
            ),
            VaultError::AccountNotFound => (
                "account_not_found",
                NotFound,
                "Nie znaleziono konta.".to_owned(),
                doctor,
            ),
            VaultError::AlreadyMember => (
                "already_member",
                Conflict,
                "To konto już jest członkiem vaulta.".to_owned(),
                "Nic nie trzeba robić",
            ),
            VaultError::NotAMember => (
                "not_a_member",
                Access,
                "Konto nie jest członkiem tego vaulta, więc jego urządzenie nie dostanie dostępu."
                    .to_owned(),
                "Najpierw dodaj konto do vaulta jako członka",
            ),
            VaultError::DeviceNeedsAccount => (
                "device_needs_account",
                Failure,
                "Urządzenie musi należeć do konta.".to_owned(),
                doctor,
            ),
            VaultError::NothingToUndo => (
                "nothing_to_undo",
                NotFound,
                "Brak wcześniejszej wersji do przywrócenia.".to_owned(),
                "Historia zmiennej: smart-env history NAZWA",
            ),
            VaultError::ProjectNameTaken => (
                "project_name_taken",
                Conflict,
                "Projekt o tej nazwie już istnieje.".to_owned(),
                "Wybierz inną nazwę projektu",
            ),
            VaultError::EnvironmentNameTaken => (
                "environment_name_taken",
                Conflict,
                "Środowisko o tej nazwie już istnieje w projekcie.".to_owned(),
                "Wybierz inną nazwę środowiska",
            ),
            VaultError::SecretNameTaken => (
                "secret_name_taken",
                Conflict,
                "Zmienna o tej nazwie już istnieje (także usunięta).".to_owned(),
                "Wybierz inną nazwę albo przywróć usuniętą: smart-env undo NAZWA",
            ),
            VaultError::RecipientKeyTaken => (
                "recipient_key_taken",
                Conflict,
                "Ten klucz już jest odbiorcą vaulta.".to_owned(),
                "Nic nie trzeba robić",
            ),
            VaultError::DuplicateName(name) => (
                "duplicate_name",
                Conflict,
                format!("Zmienna {name} występuje w imporcie więcej niż raz; nic nie zapisano."),
                "Usuń powtórzenie i spróbuj ponownie",
            ),
            VaultError::AlreadyExists => (
                "vault_exists",
                Conflict,
                "Vault już istnieje.".to_owned(),
                "Nic nie trzeba robić — smart-env setup był już wykonany",
            ),
            VaultError::UnsupportedSchema => (
                "unsupported_vault",
                Failure,
                "Plik nie jest vaultem smart-env albo pochodzi z nowszej wersji.".to_owned(),
                "Zaktualizuj smart-env albo sprawdź: smart-env doctor",
            ),
            VaultError::NoRecipients => (
                "no_recipients",
                Failure,
                "Vault nie ma aktywnego odbiorcy klucza.".to_owned(),
                doctor,
            ),
            VaultError::Key(KeyError::Unwrap) => (
                "key_mismatch",
                Access,
                "Klucz tego urządzenia nie otwiera tego środowiska.".to_owned(),
                doctor,
            ),
            VaultError::Key(KeyError::KeychainUnavailable) => (
                "keychain_unavailable",
                Access,
                "Systemowy keychain jest niedostępny, a klucz nie jest odblokowany.".to_owned(),
                "Odblokuj klucz: smart-env unlock",
            ),
            VaultError::Key(KeyError::WrongPassphrase) => (
                "wrong_passphrase",
                Access,
                "Nieprawidłowe hasło do pliku klucza.".to_owned(),
                "Spróbuj ponownie: smart-env unlock",
            ),
            VaultError::Key(_) => (
                "key_error",
                Failure,
                "Nie udało się użyć klucza urządzenia.".to_owned(),
                doctor,
            ),
            VaultError::Secret(SecretError::InvalidName) => (
                "invalid_name",
                Usage,
                "Nieprawidłowa nazwa zmiennej.".to_owned(),
                "Nazwa: litery, cyfry i _, nie zaczyna się cyfrą, do 255 znaków",
            ),
            VaultError::Secret(SecretError::ValueTooLarge) => (
                "value_too_large",
                Usage,
                "Wartość jest większa niż 64 KiB.".to_owned(),
                "Zapisz większe dane w pliku, a w zmiennej ścieżkę do niego",
            ),
            VaultError::Secret(SecretError::InvalidValue) => (
                "invalid_value",
                Usage,
                "Wartość zawiera bajt NUL.".to_owned(),
                "Usuń bajt NUL z wartości",
            ),
            VaultError::Secret(SecretError::Decrypt) => (
                "decrypt_failed",
                Failure,
                "Wartości nie da się odszyfrować — dane są uszkodzone lub podmienione.".to_owned(),
                doctor,
            ),
            VaultError::Secret(_) => (
                "crypto_error",
                Failure,
                "Błąd szyfrowania.".to_owned(),
                doctor,
            ),
            VaultError::Storage(_) | VaultError::Io(_) => (
                "storage_error",
                Failure,
                "Błąd odczytu lub zapisu vaulta.".to_owned(),
                doctor,
            ),
        };
        Self::new(code, exit, message).with_hint(hint)
    }
}
