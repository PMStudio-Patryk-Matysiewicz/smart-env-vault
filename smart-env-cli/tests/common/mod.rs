//! Shared harness for in-process CLI tests: a temporary data directory,
//! in-memory key stores and a scripted terminal.
#![allow(dead_code)] // each test crate uses a different part

use secrecy::{ExposeSecret, SecretString};
use smart_env_cli::{ChildCommand, Context, Exit, Runner, ShellEnv, Terminal, execute};
use smart_env_vault::{DataPaths, DeviceKey, KeyError, KeyStore, MemoryStore, Vault};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;
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

// --- runner ---

/// What `run` started: program, arguments and the added variables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Launched {
    pub program: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
}

/// How the fake command ends.
#[derive(Clone, Copy, Debug)]
pub enum ChildResult {
    Exit(u8),
    NotFound,
    PermissionDenied,
}

/// Records every command instead of starting it.
pub struct RecordingRunner {
    launched: Rc<RefCell<Vec<Launched>>>,
    result: ChildResult,
}

impl Runner for RecordingRunner {
    fn run(&mut self, command: ChildCommand) -> io::Result<u8> {
        let text = |s: &std::ffi::OsString| s.to_str().unwrap().to_owned();
        self.launched.borrow_mut().push(Launched {
            program: text(&command.program),
            args: command.args.iter().map(text).collect(),
            env: command
                .env
                .iter()
                .map(|(name, value)| (name.clone(), value.expose_secret().to_owned()))
                .collect(),
        });
        match self.result {
            ChildResult::Exit(code) => Ok(code),
            ChildResult::NotFound => Err(io::ErrorKind::NotFound.into()),
            ChildResult::PermissionDenied => Err(io::ErrorKind::PermissionDenied.into()),
        }
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
    /// Commands started by `run`, in order.
    pub launched: Rc<RefCell<Vec<Launched>>>,
    /// How the next commands started by `run` end (default: exit 0).
    pub child: Cell<ChildResult>,
    /// `$HOME`: an empty directory next to the data directory.
    pub home: PathBuf,
    /// `$SHELL`; `None` by default, so `setup` installs no hook unless a
    /// test asks for it.
    pub shell: Option<String>,
    /// `$ZDOTDIR`.
    pub zdotdir: Option<PathBuf>,
    /// `$XDG_CONFIG_HOME`.
    pub xdg_config_home: Option<PathBuf>,
    /// `$PATH`: by default only the directory of [`Machine::executable`].
    pub path: Option<OsString>,
    /// The `smart-env` binary the hook script calls: a fake in a directory
    /// with a space and a quote in its name. It appends its arguments to
    /// `calls` next to it and prints the file `output` next to it.
    pub executable: PathBuf,
}

/// Fake `smart-env` for hook scripts: logs its arguments, prints `output`.
const FAKE_SMART_ENV: &str = r#"#!/bin/sh
dir=$(dirname "$0")
printf '%s\n' "$*" >> "$dir/calls"
if [ -f "$dir/output" ]; then cat "$dir/output"; fi
"#;

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
        let home = dir.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let bin = dir.path().join("bin dir's");
        std::fs::create_dir(&bin).unwrap();
        let executable = bin.join("smart-env");
        std::fs::write(&executable, FAKE_SMART_ENV).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self {
            _dir: dir,
            data,
            project,
            keys: Box::new(keys),
            session: Box::new(session),
            account_label: "trawers".to_owned(),
            device_label: "laptop".to_owned(),
            launched: Rc::default(),
            child: Cell::new(ChildResult::Exit(0)),
            home,
            shell: None,
            zdotdir: None,
            xdg_config_home: None,
            path: Some(bin.into_os_string()),
            executable,
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
            runner: Box::new(RecordingRunner {
                launched: Rc::clone(&self.launched),
                result: self.child.get(),
            }),
            shell: ShellEnv {
                shell: self.shell.clone().map(OsString::from),
                home: Some(self.home.clone()),
                zdotdir: self.zdotdir.clone(),
                xdg_config_home: self.xdg_config_home.clone(),
                path: self.path.clone(),
            },
            executable: Some(self.executable.clone()),
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
