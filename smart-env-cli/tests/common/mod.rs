//! Shared harness for in-process CLI tests: a temporary data directory,
//! in-memory key stores and a scripted terminal.
#![allow(dead_code)] // each test crate uses a different part

use secrecy::SecretString;
use smart_env_cli::{Context, Exit, Terminal, execute};
use smart_env_vault::{DataPaths, DeviceKey, KeyError, KeyStore, MemoryStore, Vault};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

// --- terminal ---

type Answer = Box<dyn FnMut(&str, &str) -> String>;

/// Records everything shown and every question; answers with a function of
/// (transcript so far, question). Secret answers are never added to the
/// transcript (no echo).
pub struct ScriptedTerminal {
    pub transcript: String,
    pub questions: usize,
    pub secret_questions: usize,
    answer: Answer,
}

impl ScriptedTerminal {
    pub fn new(answer: impl FnMut(&str, &str) -> String + 'static) -> Self {
        Self {
            transcript: String::new(),
            questions: 0,
            secret_questions: 0,
            answer: Box::new(answer),
        }
    }

    /// Confirms the recovery key; secret questions get an empty answer.
    pub fn confirming() -> Self {
        Self::with_passphrase("")
    }

    /// Confirms the recovery key and answers every passphrase question
    /// with `passphrase`.
    pub fn with_passphrase(passphrase: &str) -> Self {
        let passphrase = passphrase.to_owned();
        Self::new(move |transcript, question| {
            if is_passphrase_question(question) {
                passphrase.clone()
            } else {
                last4(&shown_key(transcript))
            }
        })
    }
}

pub fn is_passphrase_question(question: &str) -> bool {
    question.to_lowercase().contains("passphrase")
}

impl Terminal for ScriptedTerminal {
    fn show(&mut self, text: &str) {
        self.transcript.push_str(text);
    }

    fn ask(&mut self, question: &str) -> io::Result<String> {
        self.transcript.push_str(question);
        self.questions += 1;
        Ok((self.answer)(&self.transcript, question))
    }

    fn ask_secret(&mut self, question: &str) -> io::Result<SecretString> {
        self.transcript.push_str(question);
        self.transcript.push('\n');
        self.secret_questions += 1;
        Ok(SecretString::from((self.answer)(
            &self.transcript,
            question,
        )))
    }
}

/// The recovery key as shown on the terminal (pre-SE-RECOVERY format).
pub fn shown_key(transcript: &str) -> String {
    transcript
        .split_whitespace()
        .find(|word| word.starts_with("AGE-SECRET-KEY-1"))
        .expect("recovery key shown on the terminal")
        .to_owned()
}

pub fn last4(key: &str) -> String {
    key[key.len() - 4..].to_owned()
}

// --- key stores ---

/// Keychain (or kernel keyring) that cannot be reached.
pub struct UnavailableStore(pub KeyError);

impl KeyStore for UnavailableStore {
    fn load(&self) -> Result<Option<DeviceKey>, KeyError> {
        Err(self.0)
    }
    fn save(&self, _: &DeviceKey) -> Result<(), KeyError> {
        Err(self.0)
    }
    fn delete(&self) -> Result<(), KeyError> {
        Err(self.0)
    }
}

/// Empty store that fails to save.
pub struct FailingSaveStore;

impl KeyStore for FailingSaveStore {
    fn load(&self) -> Result<Option<DeviceKey>, KeyError> {
        Ok(None)
    }
    fn save(&self, _: &DeviceKey) -> Result<(), KeyError> {
        Err(KeyError::Storage)
    }
    fn delete(&self) -> Result<(), KeyError> {
        Ok(())
    }
}

// --- machine ---

/// One machine: data directory, keychain (`keys`) and kernel keyring
/// (`session`).
pub struct Machine {
    _dir: TempDir,
    pub data: PathBuf,
    /// Working directory of commands: an empty project directory `payments`.
    pub project: PathBuf,
    pub keys: Box<dyn KeyStore>,
    pub session: Box<dyn KeyStore>,
    pub account_label: String,
    pub device_label: String,
}

pub struct Run {
    pub exit: Exit,
    pub stdout: String,
    pub stderr: String,
}

impl Machine {
    /// Working keychain and kernel keyring, both empty.
    pub fn new() -> Self {
        Self::with_stores(MemoryStore::default(), MemoryStore::default())
    }

    /// Working kernel keyring, this keychain.
    pub fn with_keys(keys: impl KeyStore + 'static) -> Self {
        Self::with_stores(keys, MemoryStore::default())
    }

    /// No system keychain: passphrase mode with a working kernel keyring.
    pub fn without_keychain() -> Self {
        Self::with_keys(UnavailableStore(KeyError::KeychainUnavailable))
    }

    pub fn with_stores(keys: impl KeyStore + 'static, session: impl KeyStore + 'static) -> Self {
        let dir = TempDir::new().unwrap();
        let data = dir.path().join("smart-env");
        let project = dir.path().join("payments");
        std::fs::create_dir(&project).unwrap();
        Self {
            _dir: dir,
            data,
            project,
            keys: Box::new(keys),
            session: Box::new(session),
            account_label: "trawers".to_owned(),
            device_label: "laptop".to_owned(),
        }
    }

    pub fn context<'a>(&'a self, terminal: Option<&'a mut dyn Terminal>) -> Context<'a> {
        Context {
            data: Some(DataPaths::from_root(&self.data)),
            keys: self.keys.as_ref(),
            session: self.session.as_ref(),
            account_label: self.account_label.clone(),
            device_label: self.device_label.clone(),
            current_dir: Some(self.project.clone()),
            terminal,
            stdin: Box::new(io::empty()),
        }
    }

    pub fn run(&self, args: &[&str], terminal: Option<&mut ScriptedTerminal>) -> Run {
        self.run_with_stdin(args, terminal, b"")
    }

    /// Like [`Machine::run`], with `stdin` as standard input.
    pub fn run_with_stdin(
        &self,
        args: &[&str],
        terminal: Option<&mut ScriptedTerminal>,
        stdin: &[u8],
    ) -> Run {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut ctx = self.context(terminal.map(|t| t as &mut dyn Terminal));
        ctx.stdin = Box::new(stdin);
        let argv = std::iter::once("smart-env").chain(args.iter().copied());
        let exit = execute(argv, &mut ctx, &mut out, &mut err);
        Run {
            exit,
            stdout: String::from_utf8(out).unwrap(),
            stderr: String::from_utf8(err).unwrap(),
        }
    }

    /// `setup` on a terminal that confirms correctly; returns the run and
    /// the shown recovery key.
    pub fn setup(&self) -> (Run, String) {
        self.setup_with_passphrase("")
    }

    /// `setup` answering passphrase questions with `passphrase`.
    pub fn setup_with_passphrase(&self, passphrase: &str) -> (Run, String) {
        let mut terminal = ScriptedTerminal::with_passphrase(passphrase);
        let run = self.run(&["setup"], Some(&mut terminal));
        let key = shown_key(&terminal.transcript);
        (run, key)
    }

    /// Switches the working directory to a new empty directory `name`
    /// next to the data directory.
    pub fn use_project_dir(&mut self, name: &str) {
        self.project = self.data.parent().unwrap().join(name);
        std::fs::create_dir_all(&self.project).unwrap();
    }

    /// Writes a file in the project directory.
    pub fn write(&self, name: &str, content: &str) {
        std::fs::write(self.project.join(name), content).unwrap();
    }

    /// Reads a file of the project directory; `None` if it does not exist.
    pub fn read(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.project.join(name)).ok()
    }

    pub fn exists(&self, name: &str) -> bool {
        self.project.join(name).exists()
    }

    /// Runs git in the project directory with a fixed identity; panics on
    /// failure.
    pub fn git(&self, args: &[&str]) -> String {
        git(&self.project, args)
    }

    pub fn vault_db(&self) -> PathBuf {
        self.data.join("vault.db")
    }

    pub fn state_db(&self) -> PathBuf {
        self.data.join("state.db")
    }

    pub fn key_file(&self) -> PathBuf {
        self.data.join("device.key")
    }

    pub fn vault(&self) -> Vault {
        Vault::open(&self.vault_db()).unwrap()
    }

    pub fn stored_key(&self) -> Option<DeviceKey> {
        self.keys.load().unwrap()
    }

    pub fn unlocked_key(&self) -> Option<DeviceKey> {
        self.session.load().unwrap()
    }

    pub fn assert_nothing_written(&self) {
        assert!(!self.vault_db().exists(), "vault.db left behind");
        assert!(!self.state_db().exists(), "state.db left behind");
        assert!(!self.key_file().exists(), "device.key left behind");
        assert!(
            self.keys.load().map_or(true, |key| key.is_none()),
            "device key left in the keychain"
        );
        assert!(
            self.session.load().map_or(true, |key| key.is_none()),
            "device key left in the kernel keyring"
        );
    }
}

/// Everything a run printed, for "never printed" checks.
pub fn printed(run: &Run) -> String {
    format!("{}{}", run.stdout, run.stderr)
}

pub fn json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim()).unwrap()
}

/// Error code from `--json` output.
pub fn error_code(run: &Run) -> String {
    json(&run.stdout)["error"]["code"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Runs git in `dir` with a fixed identity and no user/system config;
/// panics on failure.
pub fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["-c", "user.name=Test", "-c", "user.email=test@example.com"])
        .args([
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .expect("git is installed");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
