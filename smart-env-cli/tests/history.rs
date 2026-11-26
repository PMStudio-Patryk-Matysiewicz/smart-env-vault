//! `history` and `undo` through `execute`, in a project created by `init`
//! ([[05 - Kontrakt DX]] Scenario 10, F06 9, F08 2).
mod common;

use common::{Machine, Run, ScriptedTerminal, error_code, json, printed};
use smart_env_cli::Exit;
use smart_env_vault::{EnvironmentId, HISTORY_LIMIT, Inject, SecretMeta, VarName};

const SECRET: &str = "hunter2";

// --- helpers ---

/// After `setup` and `init`: project `payments` with `dev` (`API_KEY`,
/// `DATABASE_URL`) and `prod` (`API_KEY`), each at version 1; every value
/// contains `hunter2`.
fn project() -> Machine {
    let m = Machine::new();
    let (setup, _) = m.setup();
    assert_eq!(setup.exit, Exit::Success, "{}", printed(&setup));
    m.write(
        ".env",
        "DATABASE_URL=postgres://u:hunter2@db\nAPI_KEY=dev-hunter2\n",
    );
    m.write(".env.production", "API_KEY=prod-hunter2\n");
    ok(m.run(&["init", "--yes"], None));
    m
}

/// `project()` in passphrase mode with the key locked again.
fn locked_project() -> Machine {
    let m = Machine::without_keychain();
    let (setup, _) = m.setup_with_passphrase("correct horse battery");
    assert_eq!(setup.exit, Exit::Success, "{}", printed(&setup));
    m.write(".env", "API_KEY=v1-hunter2\n");
    ok(m.run(&["init", "--yes"], None));
    ok(piped(&m, &["set", "API_KEY", "--stdin"], "v2-hunter2\n"));
    m.session.delete().unwrap();
    m
}

fn piped(m: &Machine, args: &[&str], input: &str) -> Run {
    m.run_with_stdin(args, None, input.as_bytes())
}

fn ok(run: Run) -> Run {
    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    run
}

/// `set NAME --stdin` with `value`.
fn set(m: &Machine, name: &str, value: &str) {
    ok(piped(m, &["set", name, "--stdin"], &format!("{value}\n")));
}

fn env_id(m: &Machine, environment: &str) -> EnvironmentId {
    let vault = m.vault();
    let project = vault.find_project("payments").unwrap().unwrap();
    vault
        .environments(project)
        .unwrap()
        .into_iter()
        .find(|info| info.name == environment)
        .unwrap_or_else(|| panic!("environment payments/{environment}"))
        .id
}

fn value(m: &Machine, environment: &str, name: &str) -> Option<String> {
    let key = m.stored_key().expect("device key in the keychain");
    m.vault()
        .get(env_id(m, environment), &VarName::parse(name).unwrap(), &key)
        .unwrap()
        .map(|value| value.expose().to_owned())
}

fn meta(m: &Machine, environment: &str, name: &str) -> Option<SecretMeta> {
    m.vault()
        .list(env_id(m, environment))
        .unwrap()
        .into_iter()
        .find(|meta| meta.name.as_str() == name)
}

fn revision(m: &Machine, environment: &str) -> u64 {
    m.vault().revision(env_id(m, environment)).unwrap()
}

/// Version numbers listed by human `history` output, in order.
fn listed_versions(stdout: &str) -> Vec<u32> {
    stdout
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next()?.parse().ok())
        .collect()
}

fn assert_no_secret(run: &Run) {
    assert!(
        !printed(run).contains(SECRET),
        "value printed: {}",
        printed(run)
    );
}

/// `YYYY-MM-DD HH:MM:SS`.
fn is_timestamp(text: &str) -> bool {
    let bytes = text.as_bytes();
    text.len() == 19
        && bytes.iter().enumerate().all(|(i, b)| match i {
            4 | 7 => *b == b'-',
            10 => *b == b' ',
            13 | 16 => *b == b':',
            _ => b.is_ascii_digit(),
        })
}

// --- history ---

#[test]
fn history_lists_versions_newest_first_without_values() {
    let m = project();
    set(&m, "API_KEY", "v2-hunter2");
    set(&m, "API_KEY", "v3-hunter2");
    let run = ok(m.run(&["history", "API_KEY"], None));

    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(
        lines[0],
        "API_KEY in payments/dev (current value: version 3)"
    );
    assert_eq!(listed_versions(&run.stdout), [3, 2, 1]);
    assert!(lines[1].starts_with("  3  "), "{}", run.stdout);
    assert!(lines[1].ends_with(" UTC  set"), "{}", run.stdout);
    assert!(lines[2].ends_with(" UTC  set"), "{}", run.stdout);
    assert!(lines[3].ends_with(" UTC  import"), "{}", run.stdout);
    assert!(
        is_timestamp(&lines[2]["  2  ".len()..][..19]),
        "{}",
        run.stdout
    );
    assert_eq!(
        *lines.last().unwrap(),
        "Undo the last change: smart-env undo API_KEY"
    );
    assert_no_secret(&run);
}

#[test]
fn history_of_a_single_version_has_no_undo_hint() {
    let m = project();
    let run = ok(m.run(&["history", "API_KEY"], None));

    assert_eq!(listed_versions(&run.stdout), [1]);
    assert!(!run.stdout.contains("smart-env undo"), "{}", run.stdout);
}

#[test]
fn history_with_env_flag_repeats_it_in_the_undo_hint() {
    let m = project();
    set_env(&m, "prod", "API_KEY", "p2");
    let run = ok(m.run(&["history", "API_KEY", "--env", "payments/prod"], None));

    assert!(
        run.stdout
            .starts_with("API_KEY in payments/prod (current value: version 2)\n"),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout
            .contains("Undo the last change: smart-env undo API_KEY --env payments/prod"),
        "{}",
        run.stdout
    );
}

fn set_env(m: &Machine, environment: &str, name: &str, value: &str) {
    ok(piped(
        m,
        &["set", name, "--env", environment, "--stdin"],
        &format!("{value}\n"),
    ));
}

#[test]
fn history_keeps_the_current_version_and_at_most_the_limit_of_previous_ones() {
    let m = project();
    for i in 0..HISTORY_LIMIT + 3 {
        set(&m, "API_KEY", &format!("v{i}"));
    }
    let run = ok(m.run(&["history", "API_KEY"], None));

    let versions = listed_versions(&run.stdout);
    assert_eq!(versions.len(), HISTORY_LIMIT + 1);
    let newest = (HISTORY_LIMIT + 4) as u32;
    assert_eq!(versions[0], newest);
    assert_eq!(*versions.last().unwrap(), newest - HISTORY_LIMIT as u32);
}

#[test]
fn history_of_a_missing_variable_is_not_found() {
    let m = project();
    let run = m.run(&["history", "NOPE", "--json"], None);

    assert_eq!(run.exit, Exit::NotFound);
    assert_eq!(error_code(&run), "secret_not_found");
}

#[test]
fn history_of_a_removed_variable_shows_it_and_points_at_undo() {
    let m = project();
    set(&m, "API_KEY", "v2");
    ok(m.run(&["rm", "API_KEY"], None));
    let run = ok(m.run(&["history", "API_KEY"], None));

    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(
        lines[0],
        "API_KEY in payments/dev (removed, last value: version 2)"
    );
    assert!(lines[1].ends_with(" UTC  removed"), "{}", run.stdout);
    assert!(!run.stdout.contains("(current)"), "{}", run.stdout);
    assert_eq!(listed_versions(&run.stdout), [2, 1]);
    assert_eq!(*lines.last().unwrap(), "Restore: smart-env undo API_KEY");

    let report = json(&ok(m.run(&["history", "API_KEY", "--json"], None)).stdout);
    assert_eq!(report["removed"], true);
    assert_eq!(report["versions"][0]["current"], false);
}

#[test]
fn history_with_an_invalid_name_is_a_usage_error() {
    let m = project();
    let run = m.run(&["history", "1BAD", "--json"], None);
    assert_eq!(run.exit, Exit::Usage);
    assert_eq!(error_code(&run), "invalid_name");
}

#[test]
fn history_works_with_a_locked_key() {
    let m = locked_project();
    let run = ok(m.run(&["history", "API_KEY"], None));
    assert_eq!(listed_versions(&run.stdout), [2, 1]);
}

#[test]
fn history_json_lists_versions_without_values() {
    let m = project();
    set(&m, "API_KEY", "v2-hunter2");
    let run = ok(m.run(&["history", "API_KEY", "--json"], None));

    let report = json(&run.stdout);
    assert_eq!(report["project"], "payments");
    assert_eq!(report["environment"], "dev");
    assert_eq!(report["name"], "API_KEY");
    let versions = report["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0]["version"], 2);
    assert_eq!(versions[0]["current"], true);
    assert_eq!(versions[1]["version"], 1);
    assert_eq!(versions[1]["current"], false);
    assert_eq!(versions[0]["operation"], "set");
    assert!(versions[0]["restored_version"].is_null());
    assert_eq!(versions[1]["operation"], "import");
    for version in versions {
        assert!(
            is_timestamp(version["created_at"].as_str().unwrap()),
            "{version}"
        );
        assert!(version.get("value").is_none(), "{version}");
    }
    assert_no_secret(&run);
}

#[test]
fn history_shows_what_wrote_each_version() {
    let m = project();
    set(&m, "API_KEY", "v2-hunter2");
    ok(m.run(&["undo", "API_KEY"], None));
    set(&m, "API_KEY", "v4-hunter2");
    let run = ok(m.run(&["history", "API_KEY"], None));

    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(listed_versions(&run.stdout), [4, 3, 2, 1]);
    assert!(lines[1].ends_with(" UTC  set"), "{}", run.stdout);
    assert!(lines[2].ends_with(" UTC  undo → 1"), "{}", run.stdout);
    assert!(lines[3].ends_with(" UTC  set"), "{}", run.stdout);
    assert!(lines[4].ends_with(" UTC  import"), "{}", run.stdout);
    assert_no_secret(&run);
}

#[test]
fn history_json_reports_the_restored_version_of_an_undo() {
    let m = project();
    set(&m, "API_KEY", "v2");
    ok(m.run(&["undo", "API_KEY"], None));
    let run = ok(m.run(&["history", "API_KEY", "--json"], None));

    let current = &json(&run.stdout)["versions"][0];
    assert_eq!(current["version"], 3);
    assert_eq!(current["operation"], "undo");
    assert_eq!(current["restored_version"], 1);
}

#[test]
fn rm_and_undo_add_events_but_no_versions() {
    let m = project();
    set(&m, "API_KEY", "v2");
    let before = ok(m.run(&["history", "API_KEY", "--json"], None));
    ok(m.run(&["rm", "API_KEY"], None));
    ok(m.run(&["undo", "API_KEY"], None));
    let after = json(&ok(m.run(&["history", "API_KEY", "--json"], None)).stdout);

    assert_eq!(after["versions"], json(&before.stdout)["versions"]);
    assert_eq!(after["removed"], false);
    let kinds: Vec<&str> = after["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["restore", "remove"]);
}

#[test]
fn history_shows_rm_and_restore_above_the_current_version() {
    let m = project();
    set(&m, "API_KEY", "v2");
    ok(m.run(&["rm", "API_KEY"], None));
    ok(m.run(&["undo", "API_KEY"], None));
    let run = ok(m.run(&["history", "API_KEY"], None));

    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(
        lines[0],
        "API_KEY in payments/dev (current value: version 2)"
    );
    assert!(lines[1].ends_with(" UTC  restored"), "{}", run.stdout);
    assert!(lines[2].ends_with(" UTC  removed"), "{}", run.stdout);
    assert!(lines[3].starts_with("  2  "), "{}", run.stdout);
    assert!(lines[3].ends_with(" UTC  set"), "{}", run.stdout);
    // Event lines leave the version column empty.
    assert!(lines[1].starts_with("     2"), "{}", run.stdout);
}

#[test]
fn history_follows_a_renamed_variable() {
    let m = project();
    ok(m.run(&["rename", "API_KEY", "STRIPE_KEY"], None));
    set(&m, "STRIPE_KEY", "v2-hunter2");
    let run = ok(m.run(&["history", "STRIPE_KEY"], None));

    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(
        lines[0],
        "STRIPE_KEY in payments/dev (current value: version 2)"
    );
    assert!(lines[1].starts_with("  2  "), "{}", run.stdout);
    assert!(
        lines[2].ends_with(" UTC  renamed API_KEY → STRIPE_KEY"),
        "{}",
        run.stdout
    );
    assert!(lines[3].ends_with(" UTC  import"), "{}", run.stdout);
    assert_no_secret(&run);

    let old = m.run(&["history", "API_KEY", "--json"], None);
    assert_eq!(error_code(&old), "secret_not_found");
}

#[test]
fn history_json_lists_events_without_values() {
    let m = project();
    ok(m.run(&["rename", "API_KEY", "STRIPE_KEY"], None));
    ok(m.run(&["rm", "STRIPE_KEY"], None));
    let run = ok(m.run(&["history", "STRIPE_KEY", "--json"], None));

    let report = json(&run.stdout);
    assert_eq!(report["removed"], true);
    let events = report["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["kind"], "remove");
    assert_eq!(events[0]["after_version"], 1);
    assert!(events[0]["from"].is_null() && events[0]["to"].is_null());
    assert_eq!(events[1]["kind"], "rename");
    assert_eq!(events[1]["from"], "API_KEY");
    assert_eq!(events[1]["to"], "STRIPE_KEY");
    for event in events {
        assert!(is_timestamp(event["at"].as_str().unwrap()), "{event}");
    }
    assert_no_secret(&run);
}

// --- undo ---

#[test]
fn undo_writes_the_previous_value_as_a_new_version() {
    let m = project();
    set(&m, "API_KEY", "wrong-hunter2");
    let before = revision(&m, "dev");
    let run = ok(m.run(&["undo", "API_KEY"], None));

    assert_eq!(value(&m, "dev", "API_KEY").as_deref(), Some("dev-hunter2"));
    assert_eq!(meta(&m, "dev", "API_KEY").unwrap().version, 3);
    assert_eq!(revision(&m, "dev"), before + 1);
    assert!(
        run.stdout
            .contains("✓ API_KEY restored to version 1 in payments/dev (saved as version 3)"),
        "{}",
        run.stdout
    );
    assert_no_secret(&run);
}

#[test]
fn second_undo_reverts_the_first() {
    let m = project();
    set(&m, "API_KEY", "v2-hunter2");
    ok(m.run(&["undo", "API_KEY"], None));
    let run = ok(m.run(&["undo", "API_KEY"], None));

    assert_eq!(value(&m, "dev", "API_KEY").as_deref(), Some("v2-hunter2"));
    assert!(
        run.stdout
            .contains("✓ API_KEY restored to version 2 in payments/dev (saved as version 4)"),
        "{}",
        run.stdout
    );
}

#[test]
fn undo_after_rm_brings_the_variable_back() {
    let m = project();
    set(&m, "API_KEY", "v2-hunter2");
    ok(m.run(&["rm", "API_KEY"], None));
    let run = ok(m.run(&["undo", "API_KEY"], None));

    assert_eq!(value(&m, "dev", "API_KEY").as_deref(), Some("v2-hunter2"));
    assert_eq!(meta(&m, "dev", "API_KEY").unwrap().version, 2);
    assert!(
        run.stdout
            .contains("✓ API_KEY restored in payments/dev (version 2)"),
        "{}",
        run.stdout
    );
    let history = ok(m.run(&["history", "API_KEY"], None));
    assert_eq!(listed_versions(&history.stdout), [2, 1]);
}

#[test]
fn undo_without_a_previous_version_is_nothing_to_undo() {
    let m = project();
    let before = revision(&m, "dev");
    let run = m.run(&["undo", "API_KEY", "--json"], None);

    assert_eq!(run.exit, Exit::NotFound);
    assert_eq!(error_code(&run), "nothing_to_undo");
    assert_eq!(revision(&m, "dev"), before);
}

#[test]
fn undo_of_a_missing_variable_is_not_found() {
    let m = project();
    let run = m.run(&["undo", "NOPE", "--json"], None);
    assert_eq!(run.exit, Exit::NotFound);
    assert_eq!(error_code(&run), "secret_not_found");
}

#[test]
fn undo_with_an_invalid_name_is_a_usage_error() {
    let m = project();
    let run = m.run(&["undo", "1BAD", "--json"], None);
    assert_eq!(run.exit, Exit::Usage);
    assert_eq!(error_code(&run), "invalid_name");
}

#[test]
fn undo_with_a_locked_key_changes_nothing_and_does_not_ask() {
    let m = locked_project();
    let before = m.vault().revision(env_id(&m, "dev")).unwrap();
    let mut terminal = ScriptedTerminal::new(|_, _| "correct horse battery".to_owned());
    let run = m.run(&["undo", "API_KEY", "--json"], Some(&mut terminal));

    assert_eq!(run.exit, Exit::Access);
    assert_eq!(error_code(&run), "key_locked");
    assert_eq!(terminal.questions + terminal.secret_questions, 0);
    assert_eq!(revision(&m, "dev"), before);
    assert_eq!(meta(&m, "dev", "API_KEY").unwrap().version, 2);
}

#[test]
fn undo_of_a_removed_variable_with_a_locked_key_changes_nothing() {
    let m = locked_project();
    ok(m.run(&["rm", "API_KEY"], None));
    let run = m.run(&["undo", "API_KEY", "--json"], None);

    assert_eq!(error_code(&run), "key_locked");
    assert!(meta(&m, "dev", "API_KEY").is_none());
}

#[test]
fn undo_never_asks() {
    let m = project();
    set(&m, "API_KEY", "v2");
    let mut terminal = ScriptedTerminal::new(|_, _| "n".to_owned());
    ok(m.run(&["undo", "API_KEY"], Some(&mut terminal)));
    assert_eq!(terminal.questions + terminal.secret_questions, 0);
}

#[test]
fn undo_keeps_inject() {
    let m = project();
    ok(piped(
        &m,
        &["set", "API_KEY", "--inject", "run", "--stdin"],
        "v2\n",
    ));
    ok(m.run(&["undo", "API_KEY"], None));
    assert_eq!(meta(&m, "dev", "API_KEY").unwrap().inject, Inject::Run);
}

#[test]
fn undo_with_env_flag_works_in_that_environment_only() {
    let m = project();
    set_env(&m, "prod", "API_KEY", "p2");
    set(&m, "API_KEY", "d2");
    let run = ok(m.run(&["undo", "API_KEY", "--env", "prod"], None));

    assert_eq!(
        value(&m, "prod", "API_KEY").as_deref(),
        Some("prod-hunter2")
    );
    assert_eq!(value(&m, "dev", "API_KEY").as_deref(), Some("d2"));
    assert!(run.stdout.contains("payments/prod"), "{}", run.stdout);
}

#[test]
fn undo_json_reports_the_restored_version() {
    let m = project();
    set(&m, "API_KEY", "v2");
    let run = ok(m.run(&["undo", "API_KEY", "--json"], None));

    let report = json(&run.stdout);
    assert_eq!(report["status"], "restored");
    assert_eq!(report["project"], "payments");
    assert_eq!(report["environment"], "dev");
    assert_eq!(report["name"], "API_KEY");
    assert_eq!(report["version"], 3);
    assert_eq!(report["restored_version"], 1);
    assert_eq!(report["was_removed"], false);
}

#[test]
fn undo_json_of_a_removed_variable() {
    let m = project();
    ok(m.run(&["rm", "API_KEY"], None));
    let run = ok(m.run(&["undo", "API_KEY", "--json"], None));

    let report = json(&run.stdout);
    assert_eq!(report["status"], "restored");
    assert_eq!(report["version"], 1);
    assert!(report["restored_version"].is_null());
    assert_eq!(report["was_removed"], true);
}

#[test]
fn history_and_undo_without_setup_are_not_set_up() {
    let m = Machine::new();
    for args in [
        &["history", "A", "--env", "payments/dev", "--json"][..],
        &["undo", "A", "--env", "payments/dev", "--json"][..],
    ] {
        let run = m.run(args, None);
        assert_eq!(run.exit, Exit::NotFound, "{args:?}");
        assert_eq!(error_code(&run), "not_set_up", "{args:?}");
    }
    m.assert_nothing_written();
}

// --- Scenario 10 and no echo ---

#[test]
fn scenario_10_wrong_value_history_undo_rm_undo() {
    let m = project();
    set(&m, "DATABASE_URL", "postgres://u:hunter2@db-v2");
    set(&m, "DATABASE_URL", "postgres://u:hunter2@db-v3");
    let wrong = ok(piped(
        &m,
        &["set", "DATABASE_URL", "--stdin"],
        "bad-hunter2\n",
    ));
    assert!(
        wrong
            .stdout
            .contains("✓ DATABASE_URL saved in payments/dev (version 4)")
    );

    let history = ok(m.run(&["history", "DATABASE_URL"], None));
    assert_eq!(listed_versions(&history.stdout), [4, 3, 2, 1]);

    let undo = ok(m.run(&["undo", "DATABASE_URL"], None));
    assert!(
        undo.stdout
            .contains("✓ DATABASE_URL restored to version 3 in payments/dev (saved as version 5)"),
        "{}",
        undo.stdout
    );
    assert_eq!(
        value(&m, "dev", "DATABASE_URL").as_deref(),
        Some("postgres://u:hunter2@db-v3")
    );

    let rm = ok(m.run(&["rm", "API_KEY"], None));
    assert!(rm.stdout.contains("smart-env undo API_KEY"));
    ok(m.run(&["undo", "API_KEY"], None));
    assert_eq!(value(&m, "dev", "API_KEY").as_deref(), Some("dev-hunter2"));

    for run in [&wrong, &history, &undo, &rm] {
        assert_no_secret(run);
    }
}

#[test]
fn values_never_reach_the_output_of_history_or_undo() {
    let m = project();
    set(&m, "API_KEY", "v2-hunter2");
    let mut runs = vec![
        m.run(&["history", "API_KEY"], None),
        m.run(&["history", "API_KEY", "--json"], None),
        m.run(&["undo", "API_KEY"], None),
        m.run(&["undo", "API_KEY", "--json"], None),
        m.run(&["undo", "DATABASE_URL", "--json"], None),
    ];
    ok(m.run(&["rm", "API_KEY"], None));
    runs.push(m.run(&["history", "API_KEY"], None));
    runs.push(m.run(&["undo", "API_KEY"], None));
    for run in &runs {
        assert_no_secret(run);
    }
}

// --- undo --to: a chosen version ---

/// `dev/API_KEY` at version 3: `dev-hunter2` (import), `v2-hunter2`,
/// `v3-hunter2`.
fn three_versions() -> Machine {
    let m = project();
    set(&m, "API_KEY", "v2-hunter2");
    set(&m, "API_KEY", "v3-hunter2");
    m
}

#[test]
fn undo_to_restores_the_chosen_version_as_a_new_one() {
    let m = three_versions();
    let before = revision(&m, "dev");
    let run = ok(m.run(&["undo", "API_KEY", "--to", "1"], None));

    assert_eq!(value(&m, "dev", "API_KEY").as_deref(), Some("dev-hunter2"));
    assert_eq!(meta(&m, "dev", "API_KEY").unwrap().version, 4);
    assert_eq!(revision(&m, "dev"), before + 1);
    assert!(
        run.stdout
            .contains("✓ API_KEY restored to version 1 in payments/dev (saved as version 4)"),
        "{}",
        run.stdout
    );
    assert_no_secret(&run);

    let history = ok(m.run(&["history", "API_KEY"], None));
    assert!(
        history.stdout.lines().nth(1).unwrap().contains("undo → 1"),
        "{}",
        history.stdout
    );
}

#[test]
fn undo_after_undo_to_goes_back_to_the_value_before_it() {
    let m = three_versions();
    ok(m.run(&["undo", "API_KEY", "--to", "1"], None));
    let run = ok(m.run(&["undo", "API_KEY"], None));

    assert_eq!(value(&m, "dev", "API_KEY").as_deref(), Some("v3-hunter2"));
    assert!(
        run.stdout
            .contains("✓ API_KEY restored to version 3 in payments/dev (saved as version 5)"),
        "{}",
        run.stdout
    );
}

#[test]
fn undo_to_the_current_version_is_nothing_to_undo() {
    let m = three_versions();
    let before = revision(&m, "dev");
    let run = m.run(&["undo", "API_KEY", "--to", "3", "--json"], None);

    assert_eq!(run.exit, Exit::NotFound);
    assert_eq!(error_code(&run), "nothing_to_undo");
    assert_eq!(revision(&m, "dev"), before);
}

#[test]
fn undo_to_a_version_not_in_the_history_points_at_history() {
    let m = three_versions();
    let run = m.run(&["undo", "API_KEY", "--to", "9", "--json"], None);

    assert_eq!(run.exit, Exit::NotFound);
    assert_eq!(error_code(&run), "version_not_found");
    let hint = json(&run.stdout)["error"]["hint"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(hint.contains("smart-env history API_KEY"), "{hint}");
}

#[test]
fn undo_to_needs_a_positive_number() {
    let m = three_versions();
    for to in ["0", "-1", "two", ""] {
        let run = m.run(&["undo", "API_KEY", "--to", to, "--json"], None);
        assert_eq!(run.exit, Exit::Usage, "{to:?}");
        assert_eq!(error_code(&run), "usage", "{to:?}");
    }
    assert_eq!(meta(&m, "dev", "API_KEY").unwrap().version, 3);
}

#[test]
fn undo_to_on_a_removed_variable_points_at_plain_undo() {
    let m = three_versions();
    ok(m.run(&["rm", "API_KEY"], None));
    let run = m.run(&["undo", "API_KEY", "--to", "1", "--json"], None);

    assert_eq!(run.exit, Exit::NotFound);
    assert_eq!(error_code(&run), "secret_not_found");
    let hint = json(&run.stdout)["error"]["hint"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(hint.contains("smart-env undo API_KEY"), "{hint}");
    assert!(!hint.contains("--to"), "{hint}");
    assert!(meta(&m, "dev", "API_KEY").is_none());
}

#[test]
fn undo_to_with_a_locked_key_changes_nothing() {
    let m = locked_project();
    let before = revision(&m, "dev");
    let run = m.run(&["undo", "API_KEY", "--to", "1", "--json"], None);

    assert_eq!(run.exit, Exit::Access);
    assert_eq!(error_code(&run), "key_locked");
    assert_eq!(revision(&m, "dev"), before);
}

#[test]
fn undo_to_with_env_flag_works_in_that_environment() {
    let m = three_versions();
    set_env(&m, "prod", "API_KEY", "p2");
    set_env(&m, "prod", "API_KEY", "p3");
    ok(m.run(
        &["undo", "API_KEY", "--to", "1", "--env", "payments/prod"],
        None,
    ));

    assert_eq!(
        value(&m, "prod", "API_KEY").as_deref(),
        Some("prod-hunter2")
    );
    assert_eq!(value(&m, "dev", "API_KEY").as_deref(), Some("v3-hunter2"));
}

#[test]
fn undo_to_json_reports_the_restored_version() {
    let m = three_versions();
    let run = ok(m.run(&["undo", "API_KEY", "--to", "2", "--json"], None));

    let report = json(&run.stdout);
    assert_eq!(report["status"], "restored");
    assert_eq!(report["name"], "API_KEY");
    assert_eq!(report["version"], 4);
    assert_eq!(report["restored_version"], 2);
    assert_eq!(report["was_removed"], false);
    assert_no_secret(&run);
}

// --- undo undoes the last change, whatever it was ---

#[test]
fn history_marks_no_line_as_current() {
    let m = project();
    set(&m, "API_KEY", "v2");
    let run = ok(m.run(&["history", "API_KEY"], None));
    assert!(!run.stdout.contains("(current)"), "{}", run.stdout);
}

#[test]
fn rename_points_at_undo() {
    let m = project();
    let run = ok(m.run(&["rename", "API_KEY", "STRIPE_KEY"], None));
    assert!(
        run.stdout.contains(
            "✓ Renamed API_KEY to STRIPE_KEY in payments/dev (undo: smart-env undo STRIPE_KEY)"
        ),
        "{}",
        run.stdout
    );
}

#[test]
fn history_after_a_rename_points_at_undo_even_with_one_version() {
    let m = project();
    ok(m.run(&["rename", "API_KEY", "STRIPE_KEY"], None));
    let run = ok(m.run(&["history", "STRIPE_KEY"], None));
    assert_eq!(
        run.stdout.lines().last().unwrap(),
        "Undo the last change: smart-env undo STRIPE_KEY"
    );
}

#[test]
fn undo_after_rename_renames_back_and_keeps_the_value() {
    let m = project();
    set(&m, "API_KEY", "v2-hunter2");
    ok(m.run(&["rename", "API_KEY", "STRIPE_KEY"], None));
    let run = ok(m.run(&["undo", "STRIPE_KEY"], None));

    assert!(
        run.stdout
            .contains("✓ Undid rename: STRIPE_KEY is API_KEY again in payments/dev"),
        "{}",
        run.stdout
    );
    assert!(meta(&m, "dev", "STRIPE_KEY").is_none());
    assert_eq!(meta(&m, "dev", "API_KEY").unwrap().version, 2);
    assert_eq!(value(&m, "dev", "API_KEY").as_deref(), Some("v2-hunter2"));
    assert_no_secret(&run);
}

#[test]
fn second_undo_after_rename_redoes_it() {
    let m = project();
    ok(m.run(&["rename", "API_KEY", "STRIPE_KEY"], None));
    ok(m.run(&["undo", "STRIPE_KEY"], None));
    let run = ok(m.run(&["undo", "API_KEY"], None));

    assert!(
        run.stdout
            .contains("✓ Undid rename: API_KEY is STRIPE_KEY again in payments/dev"),
        "{}",
        run.stdout
    );
    assert!(meta(&m, "dev", "STRIPE_KEY").is_some());
}

#[test]
fn undo_after_rename_and_set_undoes_the_value() {
    let m = project();
    ok(m.run(&["rename", "API_KEY", "STRIPE_KEY"], None));
    set(&m, "STRIPE_KEY", "v2");
    let run = ok(m.run(&["undo", "STRIPE_KEY"], None));

    assert!(
        run.stdout
            .contains("✓ STRIPE_KEY restored to version 1 in payments/dev (saved as version 3)"),
        "{}",
        run.stdout
    );
    assert_eq!(
        value(&m, "dev", "STRIPE_KEY").as_deref(),
        Some("dev-hunter2")
    );
}

#[test]
fn undo_of_a_rename_onto_a_name_taken_meanwhile_is_a_conflict() {
    let m = project();
    ok(m.run(&["rename", "API_KEY", "STRIPE_KEY"], None));
    set(&m, "API_KEY", "new");
    let before = revision(&m, "dev");
    let run = m.run(&["undo", "STRIPE_KEY", "--json"], None);

    assert_eq!(run.exit, Exit::Conflict);
    assert_eq!(error_code(&run), "secret_name_taken");
    assert_eq!(revision(&m, "dev"), before);
    assert!(meta(&m, "dev", "STRIPE_KEY").is_some());
}

#[test]
fn undo_after_restore_removes_again() {
    let m = project();
    ok(m.run(&["rm", "API_KEY"], None));
    ok(m.run(&["undo", "API_KEY"], None));
    let run = ok(m.run(&["undo", "API_KEY"], None));

    assert!(
        run.stdout.contains(
            "✓ Undid restore: API_KEY removed again from payments/dev (undo: smart-env undo API_KEY)"
        ),
        "{}",
        run.stdout
    );
    assert!(meta(&m, "dev", "API_KEY").is_none());
}

#[test]
fn undo_by_the_old_name_after_rename_points_at_the_new_name() {
    let m = project();
    ok(m.run(&["rename", "API_KEY", "STRIPE_KEY"], None));
    let run = m.run(&["undo", "API_KEY", "--json"], None);

    assert_eq!(run.exit, Exit::NotFound);
    assert_eq!(error_code(&run), "secret_not_found");
    let error = &json(&run.stdout)["error"];
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("API_KEY was renamed to STRIPE_KEY"),
        "{error}"
    );
    assert!(
        error["hint"]
            .as_str()
            .unwrap()
            .contains("smart-env undo STRIPE_KEY"),
        "{error}"
    );
    assert!(meta(&m, "dev", "STRIPE_KEY").is_some(), "nothing changed");
}

#[test]
fn history_by_the_old_name_after_rename_points_at_the_new_name() {
    let m = project();
    ok(m.run(&["rename", "API_KEY", "STRIPE_KEY"], None));
    let run = m.run(&["history", "API_KEY", "--json"], None);

    assert_eq!(error_code(&run), "secret_not_found");
    let hint = json(&run.stdout)["error"]["hint"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(hint.contains("smart-env history STRIPE_KEY"), "{hint}");
}

#[test]
fn undo_of_a_rename_with_a_locked_key_changes_nothing() {
    let m = locked_project();
    ok(m.run(&["rename", "API_KEY", "STRIPE_KEY"], None));
    let run = m.run(&["undo", "STRIPE_KEY", "--json"], None);

    assert_eq!(error_code(&run), "key_locked");
    assert!(meta(&m, "dev", "STRIPE_KEY").is_some());
}

#[test]
fn undo_json_says_what_was_undone() {
    let m = project();
    set(&m, "API_KEY", "v2");
    let value = json(&ok(m.run(&["undo", "API_KEY", "--json"], None)).stdout);
    assert_eq!(value["status"], "restored");
    assert_eq!(value["undone"], "value");
    assert_eq!(value["restored_version"], 1);

    ok(m.run(&["rename", "API_KEY", "STRIPE_KEY"], None));
    let rename = json(&ok(m.run(&["undo", "STRIPE_KEY", "--json"], None)).stdout);
    assert_eq!(rename["status"], "renamed");
    assert_eq!(rename["undone"], "rename");
    assert_eq!(rename["from"], "STRIPE_KEY");
    assert_eq!(rename["to"], "API_KEY");

    ok(m.run(&["rm", "API_KEY"], None));
    let removal = json(&ok(m.run(&["undo", "API_KEY", "--json"], None)).stdout);
    assert_eq!(removal["status"], "restored");
    assert_eq!(removal["undone"], "remove");
    assert_eq!(removal["was_removed"], true);

    let restore = json(&ok(m.run(&["undo", "API_KEY", "--json"], None)).stdout);
    assert_eq!(restore["status"], "removed");
    assert_eq!(restore["undone"], "restore");
}
