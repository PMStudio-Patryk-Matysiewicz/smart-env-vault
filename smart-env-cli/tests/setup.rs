//! `smart-env setup` (plan: Plany/setup - Plan wdrożenia, unlock+lock - Plan
//! wdrożenia for passphrase mode). In-process with a temporary data
//! directory, in-memory key stores and a scripted terminal.

mod common;

use common::*;
use secrecy::SecretString;
use smart_env_cli::{Exit, Terminal, execute};
use smart_env_vault::{DeviceKey, KeyError, KeyStore, RecipientKind, RecoveryKey, Role};
use std::io;

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
        ScriptedTerminal::new(|t, _| format!("  {}  ", last4(&shown_key(t)).to_lowercase()));

    let run = machine.run(&["setup"], Some(&mut terminal));

    assert_eq!(run.exit, Exit::Success, "stderr: {}", run.stderr);
}

#[test]
fn one_wrong_answer_then_right_succeeds() {
    let machine = Machine::new();
    let mut wrong_first = true;
    let mut terminal = ScriptedTerminal::new(move |t, _| {
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
    let mut terminal = ScriptedTerminal::new(|_, _| "????".to_owned());

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
        fn ask_secret(&mut self, _: &str) -> io::Result<SecretString> {
            Err(io::ErrorKind::UnexpectedEof.into())
        }
    }
    let machine = Machine::new();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut terminal = ClosingTerminal;
    let mut ctx = machine.context(Some(&mut terminal));

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

// --- passphrase mode (no system keychain; unlock+lock plan) ---

const PASSPHRASE: &str = "correct horse battery";

#[test]
fn without_keychain_setup_uses_passphrase_file_and_unlocks() {
    let machine = Machine::without_keychain();

    let (run, _) = machine.setup_with_passphrase(PASSPHRASE);

    assert_eq!(run.exit, Exit::Success, "stdout: {}", run.stdout);
    assert!(machine.key_file().is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(machine.key_file())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let unlocked = machine.unlocked_key().expect("key unlocked after setup");
    let file_key = smart_env_vault::PassphraseFileStore::new(
        machine.key_file(),
        SecretString::from(PASSPHRASE),
    )
    .load()
    .unwrap()
    .unwrap();
    assert_eq!(unlocked.public(), file_key.public());
    assert_eq!(
        machine.vault().recipients().unwrap()[0].public_key,
        file_key.public()
    );
}

#[test]
fn passphrase_setup_reports_file_and_unlock_in_order() {
    let machine = Machine::without_keychain();

    let (run, _) = machine.setup_with_passphrase(PASSPHRASE);

    let lines: Vec<&str> = run.stdout.lines().collect();
    let position = |needle: &str| {
        lines
            .iter()
            .position(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("missing line with {needle:?} in {lines:?}"))
    };
    let confirmed = position("✓ Recovery key confirmed");
    let file = position("✓ Device key saved in an encrypted file");
    let unlocked = position("✓ Key unlocked for 8 h");
    let vault = position("✓ Vault created");
    assert!(confirmed < file && file < unlocked && unlocked < vault);
    assert!(lines[file].contains(&machine.key_file().display().to_string()));
    assert!(lines[unlocked].contains("smart-env lock"));
}

#[test]
fn passphrase_is_asked_twice_before_the_recovery_key_and_never_echoed() {
    let machine = Machine::without_keychain();
    let mut terminal = ScriptedTerminal::with_passphrase(PASSPHRASE);

    let run = machine.run(&["setup"], Some(&mut terminal));

    assert_eq!(run.exit, Exit::Success);
    assert_eq!(terminal.secret_questions, 2);
    let notice = terminal
        .transcript
        .find("No system keychain")
        .expect("notice shown");
    let key = terminal.transcript.find("AGE-SECRET-KEY-1").unwrap();
    assert!(notice < key);
    assert!(!terminal.transcript.contains(PASSPHRASE));
    assert!(!printed(&run).contains(PASSPHRASE));
}

#[test]
fn passphrase_not_set_after_three_bad_attempts_writes_nothing() {
    for (first, second) in [("long enough 1", "long enough 2"), ("short", "short")] {
        let machine = Machine::without_keychain();
        let mut repeat = false;
        let mut terminal = ScriptedTerminal::new(move |t, question| {
            if is_passphrase_question(question) {
                repeat = !repeat;
                if repeat { first } else { second }.to_owned()
            } else {
                last4(&shown_key(t))
            }
        });

        let run = machine.run(&["setup", "--json"], Some(&mut terminal));

        assert_eq!(run.exit, Exit::Failure, "{first:?}/{second:?}");
        assert_eq!(error_code(&run), "passphrase_not_set");
        assert_eq!(terminal.secret_questions, 6);
        assert!(!terminal.transcript.contains("AGE-SECRET-KEY"));
        machine.assert_nothing_written();
    }
}

#[test]
fn without_kernel_keyring_passphrase_setup_fails_before_asking() {
    let machine = Machine::with_stores(
        UnavailableStore(KeyError::KeychainUnavailable),
        UnavailableStore(KeyError::SessionUnavailable),
    );
    let mut terminal = ScriptedTerminal::with_passphrase(PASSPHRASE);

    let run = machine.run(&["setup", "--json"], Some(&mut terminal));

    assert_eq!(error_code(&run), "session_keyring_unavailable");
    assert!(terminal.transcript.is_empty());
    assert!(!machine.vault_db().exists());
    assert!(!machine.key_file().exists());
}

#[test]
fn second_passphrase_setup_is_already_configured_without_asking() {
    let machine = Machine::without_keychain();
    machine.setup_with_passphrase(PASSPHRASE);
    let mut terminal = ScriptedTerminal::with_passphrase(PASSPHRASE);

    let run = machine.run(&["setup", "--json"], Some(&mut terminal));

    assert_eq!(run.exit, Exit::Success);
    assert_eq!(json(&run.stdout)["status"], "already_configured");
    assert_eq!(terminal.secret_questions + terminal.questions, 0);
}

#[test]
fn failed_vault_after_passphrase_setup_removes_key_file_and_unlock() {
    // A state.db that is a directory makes creating the data files fail
    // after the key file and the unlock were written.
    let machine = Machine::without_keychain();
    std::fs::create_dir_all(machine.state_db()).unwrap();

    let (run, _) = machine.setup_with_passphrase(PASSPHRASE);

    assert_ne!(run.exit, Exit::Success);
    assert!(!machine.key_file().exists());
    assert!(machine.unlocked_key().is_none());
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
