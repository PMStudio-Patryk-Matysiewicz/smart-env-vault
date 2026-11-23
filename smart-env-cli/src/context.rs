//! What a command may touch outside its arguments: the data directory, the
//! key store, names for the account and device, and the terminal. `main`
//! builds it from the system ([`System`]); tests build it from temporary
//! directories and fakes.

use std::io::{self, BufRead, IsTerminal, Write};

use smart_env_vault::{DataPaths, KeyStore, KeychainStore};

/// The user's terminal: shows text and asks questions.
///
/// Exists only when both stdin and stderr are terminals, so what goes
/// through it (e.g. the recovery key) never lands in a pipe, a log file or
/// CI output.
pub trait Terminal {
    /// Shows text to the user (no trailing newline added).
    fn show(&mut self, text: &str);
    /// Shows `question` and returns the answer without the line ending.
    ///
    /// # Errors
    /// Reading from the terminal failed or it was closed.
    fn ask(&mut self, question: &str) -> io::Result<String>;
}

/// Everything a command may use besides its arguments.
pub struct Context<'a> {
    /// Data directory (`vault.db`, `state.db`); `None` if the system did not
    /// provide one.
    pub data: Option<DataPaths>,
    /// Where the device key is kept.
    pub keys: &'a dyn KeyStore,
    /// Label of the owner account created by `setup` (system user name).
    pub account_label: String,
    /// Label of this device (host name).
    pub device_label: String,
    /// The user's terminal; `None` without one (pipe, CI, installer).
    pub terminal: Option<&'a mut dyn Terminal>,
}

/// Owns the real system resources a [`Context`] borrows.
pub struct System {
    data: Option<DataPaths>,
    keys: KeychainStore,
    account_label: String,
    device_label: String,
    terminal: Option<StdTerminal>,
}

impl System {
    /// Data directory, system keychain, user and host names, and the
    /// terminal when stdin and stderr are both terminals.
    pub fn detect() -> Self {
        let user = whoami::username().unwrap_or_default();
        Self {
            data: DataPaths::discover().ok(),
            keys: KeychainStore::new(if user.is_empty() {
                "default".to_owned()
            } else {
                user.clone()
            }),
            account_label: user,
            device_label: whoami::hostname().unwrap_or_default(),
            terminal: (io::stdin().is_terminal() && io::stderr().is_terminal())
                .then_some(StdTerminal),
        }
    }

    /// Borrows the resources for one [`crate::execute`] call.
    pub fn context(&mut self) -> Context<'_> {
        Context {
            data: self.data.clone(),
            keys: &self.keys,
            account_label: self.account_label.clone(),
            device_label: self.device_label.clone(),
            terminal: self
                .terminal
                .as_mut()
                .map(|terminal| terminal as &mut dyn Terminal),
        }
    }
}

/// stderr for showing, stdin for answers.
struct StdTerminal;

impl Terminal for StdTerminal {
    fn show(&mut self, text: &str) {
        let _ = io::stderr().lock().write_all(text.as_bytes());
    }

    fn ask(&mut self, question: &str) -> io::Result<String> {
        let mut stderr = io::stderr().lock();
        stderr.write_all(question.as_bytes())?;
        stderr.flush()?;
        let mut line = String::new();
        if io::stdin().lock().read_line(&mut line)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(line.trim_end_matches(['\n', '\r']).to_owned())
    }
}
