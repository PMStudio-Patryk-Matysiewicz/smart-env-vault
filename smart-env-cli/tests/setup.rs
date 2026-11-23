//! `smart-env setup` (plan: Plany/setup - Plan wdrożenia). In-process with a
//! temporary data directory, an in-memory key store and a scripted terminal.

use secrecy::SecretString;
use smart_env_cli::{Context, Exit, Terminal, execute};
use smart_env_vault::{
    DataPaths, DeviceKey, KeyError, KeyStore, MemoryStore, RecipientKind, RecoveryKey, Role, Vault,
};
use std::io;
use std::path::PathBuf;
use tempfile::TempDir;

// --- fakes ---

/// Records everything shown; answers with a function of the transcript.
struct ScriptedTerminal {
    transcript: String,
    questions: usize,
    answer: Box<dyn FnMut(&str) -> String>,
}

impl ScriptedTerminal {
    fn new(answer: impl FnMut(&str) -> String + 'static) -> Self {
        Self {
            transcript: String::new(),
            questions: 0,
            answer: Box::new(answer),
        }
    }

    /// Answers every question with the last 4 characters of the shown key.
    fn confirming() -> Self {
        Self::new(|transcript| last4(&shown_key(transcript)))
    }
}

impl Terminal for ScriptedTerminal {
    fn show(&mut self, text: &str) {
        self.transcript.push_str(text);
    }

    fn ask(&mut self, question: &str) -> io::Result<String> {
        self.transcript.push_str(question);
        self.questions += 1;
        Ok((self.answer)(&self.transcript))
    }
}

/// The recovery key as shown on the terminal (pre-SE-RECOVERY format).
fn shown_key(transcript: &str) -> String {
    transcript
        .split_whitespace()
        .find(|word| word.starts_with("AGE-SECRET-KEY-1"))
        .expect("recovery key shown on the terminal")
        .to_owned()
}

fn last4(key: &str) -> String {
    key[key.len() - 4..].to_owned()
}

/// Key store whose keychain cannot be reached.
struct UnavailableStore;

impl KeyStore for UnavailableStore {
    fn load(&self) -> Result<Option<DeviceKey>, KeyError> {
        Err(KeyError::KeychainUnavailable)
    }
    fn save(&self, _: &DeviceKey) -> Result<(), KeyError> {
        Err(KeyError::KeychainUnavailable)
    }
    fn delete(&self) -> Result<(), KeyError> {
        Err(KeyError::KeychainUnavailable)
    }
}

/// Key store that is empty and fails to save.
struct FailingSaveStore;

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

// --- harness ---

struct Machine {
    _dir: TempDir,
    data: PathBuf,
    keys: Box<dyn KeyStore>,
    account_label: String,
    device_label: String,
}

struct Run {
    exit: Exit,
    stdout: String,
    stderr: String,
}

impl Machine {
    fn new() -> Self {
        Self::with_keys(MemoryStore::default())
    }

    fn with_keys(keys: impl KeyStore + 'static) -> Self {
        let dir = TempDir::new().unwrap();
        let data = dir.path().join("smart-env");
        Self {
            _dir: dir,
            data,
            keys: Box::new(keys),
            account_label: "trawers".to_owned(),
            device_label: "laptop".to_owned(),
        }
    }

    fn run(&self, args: &[&str], terminal: Option<&mut ScriptedTerminal>) -> Run {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut ctx = Context {
            data: Some(DataPaths::from_root(&self.data)),
            keys: self.keys.as_ref(),
            account_label: self.account_label.clone(),
            device_label: self.device_label.clone(),
            terminal: terminal.map(|t| t as &mut dyn Terminal),
        };
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
    fn setup(&self) -> (Run, String) {
        let mut terminal = ScriptedTerminal::confirming();
        let run = self.run(&["setup"], Some(&mut terminal));
        let key = shown_key(&terminal.transcript);
        (run, key)
    }

    fn vault_db(&self) -> PathBuf {
        self.data.join("vault.db")
    }

    fn state_db(&self) -> PathBuf {
        self.data.join("state.db")
    }

    fn vault(&self) -> Vault {
        Vault::open(&self.vault_db()).unwrap()
    }

    fn stored_key(&self) -> Option<DeviceKey> {
        self.keys.load().unwrap()
    }

    fn assert_nothing_written(&self) {
        assert!(!self.vault_db().exists(), "vault.db left behind");
        assert!(!self.state_db().exists(), "state.db left behind");
        assert!(
            self.keys.load().map_or(true, |key| key.is_none()),
            "device key left behind"
        );
    }
}

fn json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim()).unwrap()
}

/// Error code from `--json` output.
fn error_code(run: &Run) -> String {
    json(&run.stdout)["error"]["code"]
        .as_str()
        .unwrap()
        .to_owned()
}

// --- fresh setup ---

#[test]
fn setup_creates_vault_key_owner_device_and_recovery() {
    let machine = Machine::new();

    let (run, _) = machine.setup();

    assert_eq!(run.exit, Exit::Success, "stderr: {}", run.stderr);
    assert!(machine.vault_db().is_file());
    assert!(machine.state_db().is_file());
    let device = machine.stored_key().expect("device key stored");

    let vault = machine.vault();
    let members = vault.members().unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].label, "trawers");
    assert_eq!(members[0].role, Role::Owner);

    let recipients = vault.recipients().unwrap();
    assert_eq!(recipients.len(), 2);
    let laptop = &recipients[0];
    assert_eq!(laptop.kind, RecipientKind::Device);
    assert_eq!(laptop.label, "laptop");
    assert_eq!(laptop.account, Some(members[0].account));
    assert_eq!(laptop.public_key, device.public());
    assert_eq!(recipients[1].kind, RecipientKind::Recovery);
    assert_eq!(recipients[1].label, "recovery");
    assert!(recipients.iter().all(|r| !r.revoked));
}

#[test]
fn shown_recovery_key_is_the_vault_recovery_recipient() {
    let machine = Machine::new();

    let (_, shown) = machine.setup();

    let recovery = RecoveryKey::parse(&SecretString::from(shown)).unwrap();
    let recipients = machine.vault().recipients().unwrap();
    assert_eq!(recipients[1].public_key, recovery.public());
}

#[test]
fn recovery_key_is_shown_once_and_only_on_the_terminal() {
    let machine = Machine::new();
    let mut terminal = ScriptedTerminal::confirming();

    let run = machine.run(&["setup"], Some(&mut terminal));

    let key = shown_key(&terminal.transcript);
    assert_eq!(terminal.transcript.matches(&key).count(), 1);
    assert!(!run.stdout.contains(&key));
    assert!(!run.stderr.contains(&key));
    assert!(
        !run.stdout.contains(&key[16..]),
        "no part of the key body on stdout"
    );
}

#[test]
fn setup_reports_progress_in_contract_order() {
    let machine = Machine::new();

    let (run, _) = machine.setup();

    let lines: Vec<&str> = run.stdout.lines().collect();
    let position = |needle: &str| {
        lines
            .iter()
            .position(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("missing line with {needle:?} in {lines:?}"))
    };
    let confirmed = position("✓ Recovery key confirmed");
    let key = position("✓ Device key saved");
    let vault = position("✓ Vault created");
    assert!(confirmed < key && key < vault);
    assert!(lines[vault].contains(&machine.data.display().to_string()));
    assert!(lines.last().unwrap().contains("smart-env init"));
}

#[test]
fn warning_about_losing_the_recovery_key_is_shown() {
    let machine = Machine::new();
    let mut terminal = ScriptedTerminal::confirming();

    machine.run(&["setup"], Some(&mut terminal));

    assert!(terminal.transcript.contains("shown only once"));
    assert!(terminal.transcript.contains("losing your secrets"));
}

// --- confirmation ---

#[test]
fn confirmation_ignores_case_and_surrounding_spaces() {
    let machine = Machine::new();
    let mut terminal =
        ScriptedTerminal::new(|t| format!("  {}  ", last4(&shown_key(t)).to_lowercase()));

    let run = machine.run(&["setup"], Some(&mut terminal));

    assert_eq!(run.exit, Exit::Success, "stderr: {}", run.stderr);
}

#[test]
fn one_wrong_answer_then_right_succeeds() {
    let machine = Machine::new();
    let mut wrong_first = true;
    let mut terminal = ScriptedTerminal::new(move |t| {
        if std::mem::take(&mut wrong_first) {
            "????".to_owned()
        } else {
            last4(&shown_key(t))
        }
    });

    let run = machine.run(&["setup"], Some(&mut terminal));

    assert_eq!(run.exit, Exit::Success, "stderr: {}", run.stderr);
    assert_eq!(terminal.questions, 2);
}

#[test]
fn three_wrong_answers_write_nothing() {
    let machine = Machine::new();
    let mut terminal = ScriptedTerminal::new(|_| "????".to_owned());

    let run = machine.run(&["setup", "--json"], Some(&mut terminal));

    assert_eq!(run.exit, Exit::Failure);
    assert_eq!(error_code(&run), "recovery_not_confirmed");
    assert_eq!(terminal.questions, 3);
    machine.assert_nothing_written();
}

#[test]
fn closed_terminal_during_confirmation_writes_nothing() {
    struct ClosingTerminal;
    impl Terminal for ClosingTerminal {
        fn show(&mut self, _: &str) {}
        fn ask(&mut self, _: &str) -> io::Result<String> {
            Err(io::ErrorKind::UnexpectedEof.into())
        }
    }
    let machine = Machine::new();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut terminal = ClosingTerminal;
    let mut ctx = Context {
        data: Some(DataPaths::from_root(&machine.data)),
        keys: machine.keys.as_ref(),
        account_label: "trawers".to_owned(),
        device_label: "laptop".to_owned(),
        terminal: Some(&mut terminal),
    };

    let exit = execute(["smart-env", "setup"], &mut ctx, &mut out, &mut err);

    assert_ne!(exit, Exit::Success);
    machine.assert_nothing_written();
}

// --- no terminal ---

#[test]
fn setup_without_terminal_is_refused() {
    let machine = Machine::new();

    let run = machine.run(&["setup", "--json"], None);

    assert_eq!(run.exit, Exit::Usage);
    assert_eq!(error_code(&run), "terminal_required");
    machine.assert_nothing_written();
}

#[test]
fn yes_does_not_skip_recovery_confirmation() {
    let machine = Machine::new();

    let run = machine.run(&["setup", "--yes", "--json"], None);

    assert_eq!(run.exit, Exit::Usage);
    assert_eq!(error_code(&run), "terminal_required");
    assert!(!run.stdout.contains("AGE-SECRET-KEY"));
    machine.assert_nothing_written();
}

// --- existing state ---

#[test]
fn second_setup_is_already_configured_and_changes_nothing() {
    let machine = Machine::new();
    machine.setup();
    let before = machine.vault().recipients().unwrap();
    let mut terminal = ScriptedTerminal::confirming();

    let run = machine.run(&["setup"], Some(&mut terminal));

    assert_eq!(run.exit, Exit::Success);
    assert_eq!(terminal.questions, 0);
    assert!(!terminal.transcript.contains("AGE-SECRET-KEY"));
    assert!(run.stdout.contains("already set up"));
    assert_eq!(machine.vault().recipients().unwrap(), before);
    assert_eq!(machine.vault().members().unwrap().len(), 1);
}

#[test]
fn vault_without_device_key_is_device_key_missing() {
    let machine = Machine::new();
    machine.setup();
    machine.keys.delete().unwrap();

    let run = machine.run(
        &["setup", "--json"],
        Some(&mut ScriptedTerminal::confirming()),
    );

    assert_eq!(run.exit, Exit::Access);
    assert_eq!(error_code(&run), "device_key_missing");
    assert!(
        json(&run.stdout)["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("smart-env recover")
    );
    assert_eq!(machine.vault().recipients().unwrap().len(), 2);
}

#[test]
fn vault_with_foreign_device_key_is_key_mismatch() {
    let machine = Machine::new();
    machine.setup();
    machine.keys.save(&DeviceKey::generate()).unwrap();

    let run = machine.run(
        &["setup", "--json"],
        Some(&mut ScriptedTerminal::confirming()),
    );

    assert_eq!(run.exit, Exit::Access);
    assert_eq!(error_code(&run), "key_mismatch");
    assert_eq!(machine.vault().recipients().unwrap().len(), 2);
}

#[test]
fn leftover_device_key_without_vault_is_reused() {
    let machine = Machine::new();
    let existing = DeviceKey::generate();
    machine.keys.save(&existing).unwrap();

    let (run, _) = machine.setup();

    assert_eq!(run.exit, Exit::Success, "stderr: {}", run.stderr);
    assert_eq!(machine.stored_key().unwrap().public(), existing.public());
    assert_eq!(
        machine.vault().recipients().unwrap()[0].public_key,
        existing.public()
    );
}

// --- key store failures ---

#[test]
fn unavailable_keychain_fails_before_showing_recovery_key() {
    let machine = Machine::with_keys(UnavailableStore);
    let mut terminal = ScriptedTerminal::confirming();

    let run = machine.run(&["setup", "--json"], Some(&mut terminal));

    assert_eq!(run.exit, Exit::Access);
    assert_eq!(error_code(&run), "keychain_unavailable");
    assert!(terminal.transcript.is_empty());
    assert!(!machine.vault_db().exists());
    assert!(!machine.state_db().exists());
}

#[test]
fn failed_key_save_after_confirmation_leaves_no_vault() {
    let machine = Machine::with_keys(FailingSaveStore);

    let run = machine.run(&["setup"], Some(&mut ScriptedTerminal::confirming()));

    assert_ne!(run.exit, Exit::Success);
    assert!(!machine.vault_db().exists());
    assert!(!machine.state_db().exists());
}

// --- json and labels ---

#[test]
fn json_reports_created_then_already_configured() {
    let machine = Machine::new();
    let mut terminal = ScriptedTerminal::confirming();

    let first = machine.run(&["setup", "--json"], Some(&mut terminal));
    let second = machine.run(
        &["setup", "--json"],
        Some(&mut ScriptedTerminal::confirming()),
    );

    let key = shown_key(&terminal.transcript);
    assert_eq!(first.exit, Exit::Success);
    let created = json(&first.stdout);
    assert_eq!(created["status"], "created");
    assert_eq!(created["data_dir"], machine.data.display().to_string());
    assert!(!first.stdout.contains(&key));
    assert_eq!(json(&second.stdout)["status"], "already_configured");
}

#[test]
fn empty_user_name_becomes_owner_and_long_host_name_is_cut() {
    let mut machine = Machine::new();
    machine.account_label = String::new();
    machine.device_label = "h".repeat(300);

    let (run, _) = machine.setup();

    assert_eq!(run.exit, Exit::Success, "stderr: {}", run.stderr);
    let vault = machine.vault();
    assert_eq!(vault.members().unwrap()[0].label, "owner");
    assert_eq!(vault.recipients().unwrap()[0].label, "h".repeat(128));
}

// --- device label without a real host name ---

/// Label of the device recipient after `setup` with these names.
fn device_label_for(account: &str, host: &str) -> String {
    let mut machine = Machine::new();
    machine.account_label = account.to_owned();
    machine.device_label = host.to_owned();
    let (run, _) = machine.setup();
    assert_eq!(run.exit, Exit::Success, "stderr: {}", run.stderr);
    machine.vault().recipients().unwrap()[0].label.clone()
}

#[test]
fn placeholder_host_names_become_user_and_os() {
    let expected = format!("trawers-{}", std::env::consts::OS);
    for host in [
        "localhost",
        "localhost.localdomain",
        "LOCALHOST.LocalDomain",
        " localhost ",
        "",
        "   ",
    ] {
        assert_eq!(device_label_for("trawers", host), expected, "{host:?}");
    }
}

#[test]
fn placeholder_host_without_user_name_uses_owner() {
    assert_eq!(
        device_label_for("", "localhost"),
        format!("owner-{}", std::env::consts::OS)
    );
}

#[test]
fn real_host_names_are_kept() {
    for host in ["laptop", "localhost-dev", "my.localdomain", "build-01"] {
        assert_eq!(device_label_for("trawers", host), host, "{host:?}");
    }
}
