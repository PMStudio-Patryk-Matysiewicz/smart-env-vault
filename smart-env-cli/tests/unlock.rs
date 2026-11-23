//! `smart-env unlock` / `lock` and loading the device key in both modes
//! (plan: Plany/unlock+lock - Plan wdrożenia).

mod common;

use common::*;
use secrecy::SecretString;
use smart_env_cli::{Exit, Terminal, UNLOCK_TTL, device_key};
use smart_env_vault::{KeyError, KeyStore, PassphraseFileStore};

const PASSPHRASE: &str = "correct horse battery";

/// Passphrase-mode machine after `setup`, with the key locked again.
fn locked_machine() -> Machine {
    let machine = Machine::without_keychain();
    let (run, _) = machine.setup_with_passphrase(PASSPHRASE);
    assert_eq!(run.exit, Exit::Success, "setup: {}", run.stdout);
    machine.session.delete().unwrap();
    machine
}

fn file_key_public(machine: &Machine) -> smart_env_vault::PublicKey {
    PassphraseFileStore::new(machine.key_file(), SecretString::from(PASSPHRASE))
        .load()
        .unwrap()
        .unwrap()
        .public()
}

fn unlock(machine: &Machine, passphrase: &str, args: &[&str]) -> (Run, ScriptedTerminal) {
    let mut terminal = ScriptedTerminal::with_passphrase(passphrase);
    let mut argv = vec!["unlock"];
    argv.extend_from_slice(args);
    let run = machine.run(&argv, Some(&mut terminal));
    (run, terminal)
}

// --- device_key ---

#[test]
fn locked_key_is_an_error_pointing_at_unlock() {
    let machine = locked_machine();

    let error = device_key(&machine.context(None)).unwrap_err();

    assert_eq!(error.code(), "key_locked");
    assert_eq!(error.exit(), Exit::Access);
    assert!(error.hint().unwrap().contains("smart-env unlock"));
}

#[test]
fn loading_a_locked_key_never_asks() {
    let machine = locked_machine();
    let mut terminal = ScriptedTerminal::with_passphrase(PASSPHRASE);

    let result = device_key(&machine.context(Some(&mut terminal as &mut dyn Terminal)));

    assert!(result.is_err());
    assert_eq!(terminal.questions + terminal.secret_questions, 0);
}

#[test]
fn unlocked_key_is_loaded_from_the_kernel_keyring() {
    let machine = Machine::without_keychain();
    machine.setup_with_passphrase(PASSPHRASE);

    let key = device_key(&machine.context(None)).unwrap();

    assert_eq!(key.public(), file_key_public(&machine));
}

#[test]
fn keychain_mode_loads_the_keychain_key() {
    let machine = Machine::new();
    machine.setup();

    let key = device_key(&machine.context(None)).unwrap();

    assert_eq!(key.public(), machine.stored_key().unwrap().public());
}

#[test]
fn keychain_mode_without_key_is_device_key_missing() {
    let machine = Machine::new();
    machine.setup();
    machine.keys.delete().unwrap();

    let error = device_key(&machine.context(None)).unwrap_err();

    assert_eq!(error.code(), "device_key_missing");
}

#[test]
fn passphrase_mode_without_kernel_keyring_is_reported() {
    let mut machine = locked_machine();
    machine.session = Box::new(UnavailableStore(KeyError::SessionUnavailable));

    let error = device_key(&machine.context(None)).unwrap_err();

    assert_eq!(error.code(), "session_keyring_unavailable");
}

// --- unlock ---

#[test]
fn unlock_with_the_right_passphrase_unlocks_for_8_hours() {
    let machine = locked_machine();

    let (run, terminal) = unlock(&machine, PASSPHRASE, &[]);

    assert_eq!(run.exit, Exit::Success, "stdout: {}", run.stdout);
    assert_eq!(terminal.secret_questions, 1);
    assert_eq!(terminal.questions, 0);
    assert!(run.stdout.contains("✓ Key unlocked for 8 h"));
    assert!(run.stdout.contains("smart-env lock"));
    let key = device_key(&machine.context(None)).unwrap();
    assert_eq!(key.public(), file_key_public(&machine));
}

#[test]
fn unlock_with_a_wrong_passphrase_stays_locked() {
    let machine = locked_machine();

    let (run, _) = unlock(&machine, "wrong passphrase", &["--json"]);

    assert_eq!(run.exit, Exit::Access);
    assert_eq!(error_code(&run), "wrong_passphrase");
    assert!(machine.unlocked_key().is_none());
}

#[test]
fn unlock_never_prints_the_passphrase() {
    let machine = locked_machine();

    let (ok, ok_terminal) = unlock(&machine, PASSPHRASE, &[]);
    let (bad, bad_terminal) = unlock(&machine, "wrong passphrase", &["--json"]);

    assert!(!printed(&ok).contains(PASSPHRASE));
    assert!(!ok_terminal.transcript.contains(PASSPHRASE));
    assert!(!printed(&bad).contains("wrong passphrase"));
    assert!(!bad_terminal.transcript.contains("wrong passphrase"));
}

#[test]
fn unlock_needs_a_terminal_even_with_yes() {
    let machine = locked_machine();

    for args in [
        &["unlock", "--json"][..],
        &["unlock", "--yes", "--json"][..],
    ] {
        let run = machine.run(args, None);

        assert_eq!(run.exit, Exit::Usage, "{args:?}");
        assert_eq!(error_code(&run), "terminal_required");
    }
    assert!(machine.unlocked_key().is_none());
}

#[test]
fn unlock_again_while_unlocked_succeeds() {
    let machine = Machine::without_keychain();
    machine.setup_with_passphrase(PASSPHRASE);

    let (run, _) = unlock(&machine, PASSPHRASE, &[]);

    assert_eq!(run.exit, Exit::Success);
    assert!(machine.unlocked_key().is_some());
}

#[test]
fn unlock_json_reports_expiry() {
    let machine = locked_machine();

    let (run, _) = unlock(&machine, PASSPHRASE, &["--json"]);

    let value = json(&run.stdout);
    assert_eq!(value["status"], "unlocked");
    assert_eq!(value["expires_in_seconds"], UNLOCK_TTL.as_secs());
}

// --- lock ---

#[test]
fn lock_forgets_the_key_and_is_idempotent() {
    let machine = Machine::without_keychain();
    machine.setup_with_passphrase(PASSPHRASE);

    let first = machine.run(&["lock"], None);
    let second = machine.run(&["lock"], None);

    assert_eq!(first.exit, Exit::Success);
    assert_eq!(second.exit, Exit::Success);
    assert!(first.stdout.contains("✓ Key locked"));
    assert!(machine.unlocked_key().is_none());
    assert_eq!(
        device_key(&machine.context(None)).unwrap_err().code(),
        "key_locked"
    );
}

#[test]
fn lock_json_reports_locked() {
    let machine = Machine::without_keychain();
    machine.setup_with_passphrase(PASSPHRASE);

    let run = machine.run(&["lock", "--json"], None);

    assert_eq!(json(&run.stdout)["status"], "locked");
}

// --- keychain mode and before setup ---

#[test]
fn keychain_mode_has_nothing_to_unlock_or_lock() {
    let machine = Machine::new();
    machine.setup();

    let (unlocked, terminal) = unlock(&machine, PASSPHRASE, &["--json"]);
    let locked = machine.run(&["lock", "--json"], None);

    assert_eq!(unlocked.exit, Exit::Success);
    assert_eq!(json(&unlocked.stdout)["status"], "not_needed");
    assert_eq!(terminal.questions + terminal.secret_questions, 0);
    assert_eq!(locked.exit, Exit::Success);
    assert_eq!(json(&locked.stdout)["status"], "not_needed");
    assert!(machine.stored_key().is_some());
}

#[test]
fn keychain_mode_human_message_says_why() {
    let machine = Machine::new();
    machine.setup();

    let (run, _) = unlock(&machine, PASSPHRASE, &[]);

    assert!(run.stdout.contains("Nothing to unlock"));
    assert!(run.stdout.contains("system keychain"));
}

#[test]
fn unlock_and_lock_before_setup_point_at_setup() {
    let machine = Machine::without_keychain();

    let (unlocked, _) = unlock(&machine, PASSPHRASE, &["--json"]);
    let locked = machine.run(&["lock", "--json"], None);

    for run in [&unlocked, &locked] {
        assert_eq!(run.exit, Exit::NotFound);
        assert_eq!(error_code(run), "not_set_up");
        assert!(
            json(&run.stdout)["error"]["hint"]
                .as_str()
                .unwrap()
                .contains("smart-env setup")
        );
    }
}
