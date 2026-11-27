//! What a command may touch outside its arguments: the data directory, the
//! key store, names for the account and device, and the terminal. `main`
//! builds it from the system ([`System`]); tests build it from temporary
//! directories and fakes.

use std::ffi::OsString;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use smart_env_vault::{DataPaths, KernelKeyringStore, KeyStore, KeychainStore};

use crate::ShellEnv;

/// How long `unlock` keeps the device key in the kernel keyring (ADR-002).
pub const UNLOCK_TTL: Duration = Duration::from_secs(8 * 60 * 60);

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
    /// Like [`Terminal::ask`], but the answer is not echoed (passphrases).
    ///
    /// # Errors
    /// Reading from the terminal failed or it was closed.
    fn ask_secret(&mut self, question: &str) -> io::Result<SecretString>;
}

/// A command for `run` to start: program, arguments and the variables to add
/// to the inherited environment (they override inherited ones).
pub struct ChildCommand {
    /// Program, looked up in `PATH` like a shell does.
    pub program: OsString,
    /// Arguments, passed verbatim.
    pub args: Vec<OsString>,
    /// Variables from the vault; values never become arguments.
    pub env: Vec<(String, SecretString)>,
}

impl ChildCommand {
    /// The [`std::process::Command`] that starts it, inheriting stdio and the
    /// rest of the environment.
    pub fn to_command(&self) -> std::process::Command {
        let mut command = std::process::Command::new(&self.program);
        command.args(&self.args).envs(
            self.env
                .iter()
                .map(|(name, value)| (name, value.expose_secret())),
        );
        command
    }
}

/// Starts the command of `run`.
pub trait Runner {
    /// Runs `command` and returns its exit code. The real runner replaces
    /// the current process on Unix (`exec`), so it returns only on failure.
    ///
    /// # Errors
    /// The command could not be started (`NotFound`, `PermissionDenied`, …).
    fn run(&mut self, command: ChildCommand) -> io::Result<u8>;
}

/// Replaces the `smart-env` process with the command (Unix `exec`): its
/// exit code and signals are the command's own, and decrypted values do not
/// stay in a waiting `smart-env` process. Elsewhere: spawn and wait.
pub struct ProcessRunner;

impl Runner for ProcessRunner {
    #[cfg(unix)]
    fn run(&mut self, command: ChildCommand) -> io::Result<u8> {
        use std::os::unix::process::CommandExt;
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();
        // Returns only if the command could not be started.
        Err(command.to_command().exec())
    }

    #[cfg(not(unix))]
    fn run(&mut self, command: ChildCommand) -> io::Result<u8> {
        let status = command.to_command().status()?;
        Ok(status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .unwrap_or(1))
    }
}

/// Everything a command may use besides its arguments.
pub struct Context<'a> {
    /// Data directory (`vault.db`, `state.db`); `None` if the system did not
    /// provide one.
    pub data: Option<DataPaths>,
    /// Where the device key is kept in keychain mode.
    pub keys: &'a dyn KeyStore,
    /// Where the unlocked key is kept in passphrase mode (kernel keyring,
    /// expires after [`UNLOCK_TTL`]).
    pub session: &'a dyn KeyStore,
    /// Label of the owner account created by `setup` (system user name).
    pub account_label: String,
    /// Label of this device (host name).
    pub device_label: String,
    /// Working directory of the command (project commands start here);
    /// `None` if the system cannot tell.
    pub current_dir: Option<PathBuf>,
    /// The user's terminal; `None` without one (pipe, CI, installer).
    pub terminal: Option<&'a mut dyn Terminal>,
    /// Standard input, read only on request (`set --stdin`).
    pub stdin: Box<dyn Read + 'a>,
    /// Starts the command of `run`.
    pub runner: Box<dyn Runner + 'a>,
    /// The user's shell and where its startup files are (hook installation).
    pub shell: ShellEnv,
    /// This `smart-env` binary, called by the hook script by its absolute
    /// path; `None` if the system cannot tell.
    pub executable: Option<PathBuf>,
}

/// Owns the real system resources a [`Context`] borrows.
pub struct System {
    data: Option<DataPaths>,
    keys: KeychainStore,
    session: KernelKeyringStore,
    account_label: String,
    device_label: String,
    current_dir: Option<PathBuf>,
    terminal: Option<StdTerminal>,
    shell: ShellEnv,
    executable: Option<PathBuf>,
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
            session: KernelKeyringStore::new(UNLOCK_TTL),
            account_label: user,
            device_label: whoami::hostname().unwrap_or_default(),
            current_dir: std::env::current_dir().ok(),
            terminal: (io::stdin().is_terminal() && io::stderr().is_terminal())
                .then_some(StdTerminal),
            shell: ShellEnv::detect(),
            executable: std::env::current_exe().ok(),
        }
    }

    /// Borrows the resources for one [`crate::execute`] call.
    pub fn context(&mut self) -> Context<'_> {
        Context {
            data: self.data.clone(),
            keys: &self.keys,
            session: &self.session,
            account_label: self.account_label.clone(),
            device_label: self.device_label.clone(),
            current_dir: self.current_dir.clone(),
            terminal: self
                .terminal
                .as_mut()
                .map(|terminal| terminal as &mut dyn Terminal),
            stdin: Box::new(io::stdin()),
            runner: Box::new(ProcessRunner),
            shell: self.shell.clone(),
            executable: self.executable.clone(),
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

    fn ask_secret(&mut self, question: &str) -> io::Result<SecretString> {
        rpassword::prompt_password(question).map(SecretString::from)
    }
}
