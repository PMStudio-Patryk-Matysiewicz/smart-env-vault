//! Reserved names (ADR-005): `smart-env allow --var` / `deny --var`, `run`
//! passing an allowed name at the allowed version only, `set` warning.
mod common;

use std::collections::BTreeMap;

use common::{Machine, Run, ScriptedTerminal, error_code, json, printed};
use smart_env_cli::Exit;

const NODE_OPTIONS: &str = "--require ./tracing.js";
const PASSPHRASE: &str = "correct horse battery staple";

// --- helpers ---

fn ok(run: Run) -> Run {
    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    run
}

/// `setup` and `init`: `payments/dev` with `API_KEY`, `NODE_OPTIONS`,
/// `PATH`, `PEM` (two lines, not reserved); `payments/prod` with
/// `NODE_OPTIONS`.
fn project() -> Machine {
    let m = Machine::new();
    ok(m.setup().0);
    write_env(&m);
    ok(m.run(&["init", "--yes"], None));
    m
}

fn write_env(m: &Machine) {
    m.write(
        ".env",
        &format!("API_KEY=dev-1\nNODE_OPTIONS={NODE_OPTIONS}\nPATH=/opt/bin\nGIT_SSH_COMMAND=\"ssh -i key\nsecond line\"\n"),
    );
    m.write(".env.production", "NODE_OPTIONS=--inspect\n");
}

/// A terminal answering every question with `answer`.
fn answering(answer: &str) -> ScriptedTerminal {
    let answer = answer.to_owned();
    ScriptedTerminal::new(move |_, _| answer.clone())
}

/// `allow --var NAME` (plus `args`) on a terminal answering `answer`.
fn allow_var(m: &Machine, name: &str, answer: &str, args: &[&str]) -> (Run, ScriptedTerminal) {
    let mut terminal = answering(answer);
    let mut argv = vec!["allow", "--var", name];
    argv.extend_from_slice(args);
    let run = m.run(&argv, Some(&mut terminal));
    (run, terminal)
}

/// Variables `run` passed (plus `args` before `--`).
fn passed(m: &Machine, args: &[&str]) -> (BTreeMap<String, String>, Run) {
    let mut argv = vec!["run"];
    argv.extend_from_slice(args);
    argv.extend_from_slice(&["--", "env"]);
    let run = ok(m.run(&argv, None));
    let env = m.launched.borrow().last().unwrap().env.clone();
    (env, run)
}

fn set(m: &Machine, name: &str, value: &str) -> Run {
    ok(m.run_with_stdin(
        &["set", name, "--stdin"],
        None,
        format!("{value}\n").as_bytes(),
    ))
}

// --- allow --var ---

#[test]
fn allow_var_shows_the_value_on_the_terminal_and_asks() {
    let m = project();

    let (run, terminal) = allow_var(&m, "NODE_OPTIONS", "y", &[]);

    let run = ok(run);
    assert!(
        terminal.transcript.contains(NODE_OPTIONS),
        "{}",
        terminal.transcript
    );
    assert!(
        terminal.transcript.contains("payments/dev (version 1)"),
        "{}",
        terminal.transcript
    );
    assert!(
        terminal
            .transcript
            .contains("? Pass NODE_OPTIONS to smart-env run and the shell hook? [y/N]"),
        "{}",
        terminal.transcript
    );
    assert!(!printed(&run).contains(NODE_OPTIONS), "{}", printed(&run));
    assert!(
        run.stdout.contains(
            "✓ Allowed NODE_OPTIONS (version 1) in payments/dev. A new value needs a new allow."
        ),
        "{}",
        run.stdout
    );
}

#[test]
fn an_allowed_reserved_name_is_passed_by_run_without_a_warning() {
    let m = project();
    ok(allow_var(&m, "NODE_OPTIONS", "y", &[]).0);

    let (env, run) = passed(&m, &[]);

    assert_eq!(
        env.get("NODE_OPTIONS").map(String::as_str),
        Some(NODE_OPTIONS)
    );
    assert!(!env.contains_key("PATH"), "only the allowed one: {env:?}");
    assert!(!run.stderr.contains("NODE_OPTIONS"), "{}", run.stderr);
    assert!(run.stderr.contains("PATH"), "{}", run.stderr);
}

#[test]
fn an_allowed_reserved_name_is_passed_with_only() {
    let m = project();
    ok(allow_var(&m, "NODE_OPTIONS", "y", &[]).0);

    let (env, _) = passed(&m, &["--only", "NODE_OPTIONS"]);

    assert_eq!(env.keys().collect::<Vec<_>>(), ["NODE_OPTIONS"]);
}

#[test]
fn a_multi_line_value_is_shown_indented() {
    let m = project();

    let (_, terminal) = allow_var(&m, "GIT_SSH_COMMAND", "n", &[]);

    assert!(
        terminal.transcript.contains("  ssh -i key\n  second line"),
        "{}",
        terminal.transcript
    );
}

#[test]
fn no_or_an_empty_answer_allows_nothing() {
    for answer in ["n", "", "maybe"] {
        let m = project();

        let (run, _) = allow_var(&m, "NODE_OPTIONS", answer, &[]);

        let run = ok(run);
        assert!(
            run.stdout.contains("NODE_OPTIONS not allowed."),
            "{answer:?}: {}",
            run.stdout
        );
        let (env, _) = passed(&m, &[]);
        assert!(!env.contains_key("NODE_OPTIONS"), "{answer:?}");
    }
}

#[test]
fn allow_var_again_is_already_allowed_without_asking() {
    let m = project();
    ok(allow_var(&m, "NODE_OPTIONS", "y", &[]).0);

    let (run, terminal) = allow_var(&m, "NODE_OPTIONS", "y", &[]);

    let run = ok(run);
    assert_eq!(terminal.questions, 0, "{}", terminal.transcript);
    assert!(!terminal.transcript.contains(NODE_OPTIONS));
    assert!(
        run.stdout
            .contains("✓ NODE_OPTIONS (version 1) is already allowed in payments/dev"),
        "{}",
        run.stdout
    );
}

#[test]
fn allow_var_needs_a_terminal_even_with_yes() {
    let m = project();
    for args in [
        &["allow", "--var", "NODE_OPTIONS"][..],
        &["allow", "--var", "NODE_OPTIONS", "--yes", "--json"][..],
    ] {
        let run = m.run(args, None);
        assert_eq!(run.exit, Exit::Usage, "{args:?}: {}", printed(&run));
        assert!(!printed(&run).contains(NODE_OPTIONS));
    }
    let run = m.run(&["allow", "--var", "NODE_OPTIONS", "--json"], None);
    assert_eq!(error_code(&run), "terminal_required");
    let (env, _) = passed(&m, &[]);
    assert!(!env.contains_key("NODE_OPTIONS"));
}

#[test]
fn allow_var_refuses_names_that_are_not_reserved() {
    let m = project();
    let (run, terminal) = allow_var(&m, "API_KEY", "y", &["--json"]);
    assert_eq!(run.exit, Exit::Usage, "{}", printed(&run));
    assert_eq!(error_code(&run), "not_reserved");
    assert_eq!(terminal.questions, 0);

    let (run, _) = allow_var(&m, "API_KEY", "y", &[]);
    assert!(
        run.stderr
            .contains("API_KEY is not a reserved name; smart-env run already passes it."),
        "{}",
        run.stderr
    );
}

#[test]
fn allow_var_refuses_unknown_and_invalid_names() {
    let m = project();

    let (run, _) = allow_var(&m, "LD_PRELOAD", "y", &["--json"]);
    assert_eq!(run.exit, Exit::NotFound, "{}", printed(&run));
    assert_eq!(error_code(&run), "secret_not_found");

    let (run, _) = allow_var(&m, "1BAD", "y", &["--json"]);
    assert_eq!(run.exit, Exit::Usage, "{}", printed(&run));
    assert_eq!(error_code(&run), "invalid_name");
}

#[test]
fn allow_var_with_a_locked_key_is_key_locked() {
    let m = Machine::without_keychain();
    ok(m.setup_with_passphrase(PASSPHRASE).0);
    write_env(&m);
    ok(m.run(&["init", "--yes"], None));
    ok(m.run(&["lock"], None));

    let (run, terminal) = allow_var(&m, "NODE_OPTIONS", "y", &["--json"]);

    assert_eq!(run.exit, Exit::Access, "{}", printed(&run));
    assert_eq!(error_code(&run), "key_locked");
    assert!(!terminal.transcript.contains(NODE_OPTIONS));
}

#[test]
fn allow_var_and_a_directory_cannot_be_combined() {
    let m = project();
    let dir = m.project.to_str().unwrap().to_owned();
    let (run, _) = allow_var(&m, "NODE_OPTIONS", "y", &[&dir]);
    assert_eq!(run.exit, Exit::Usage, "{}", printed(&run));
}

#[test]
fn reserved_names_are_matched_ignoring_case() {
    let m = project();
    set(&m, "node_options", "--trace-warnings");

    let (run, terminal) = allow_var(&m, "node_options", "y", &[]);

    ok(run);
    assert!(terminal.transcript.contains("--trace-warnings"));
    let (env, _) = passed(&m, &[]);
    assert_eq!(
        env.get("node_options").map(String::as_str),
        Some("--trace-warnings")
    );
}

#[test]
fn consent_belongs_to_one_environment() {
    let m = project();
    ok(allow_var(&m, "NODE_OPTIONS", "y", &[]).0);

    let (env, _) = passed(&m, &["--env", "prod"]);
    assert!(!env.contains_key("NODE_OPTIONS"));

    let (run, terminal) = allow_var(&m, "NODE_OPTIONS", "y", &["--env", "prod"]);
    ok(run);
    assert!(
        terminal.transcript.contains("--inspect"),
        "{}",
        terminal.transcript
    );
    let (env, _) = passed(&m, &["--env", "payments/prod"]);
    assert_eq!(
        env.get("NODE_OPTIONS").map(String::as_str),
        Some("--inspect")
    );
}

// --- a new value needs a new allow ---

#[test]
fn a_new_value_is_not_passed_until_allowed_again() {
    let m = project();
    ok(allow_var(&m, "NODE_OPTIONS", "y", &[]).0);
    set(&m, "NODE_OPTIONS", "--require ./evil.js");

    let (env, run) = passed(&m, &[]);

    assert!(!env.contains_key("NODE_OPTIONS"), "{env:?}");
    assert!(
        run.stderr.contains(
            "! NODE_OPTIONS changed since you allowed it and was not passed. Allow the new value with: smart-env allow --var NODE_OPTIONS"
        ),
        "{}",
        run.stderr
    );

    let (run, terminal) = allow_var(&m, "NODE_OPTIONS", "y", &[]);
    ok(run);
    assert!(terminal.transcript.contains("--require ./evil.js"));
    assert!(terminal.transcript.contains("(version 2)"));
    let (env, _) = passed(&m, &[]);
    assert_eq!(
        env.get("NODE_OPTIONS").map(String::as_str),
        Some("--require ./evil.js")
    );
}

#[test]
fn undo_is_a_new_value_too() {
    let m = project();
    set(&m, "NODE_OPTIONS", "--inspect");
    ok(allow_var(&m, "NODE_OPTIONS", "y", &[]).0);

    ok(m.run(&["undo", "NODE_OPTIONS"], None));

    let (env, run) = passed(&m, &[]);
    assert!(!env.contains_key("NODE_OPTIONS"), "{env:?}");
    assert!(
        run.stderr.contains("changed since you allowed it"),
        "{}",
        run.stderr
    );
}

#[test]
fn consent_does_not_follow_a_rename_to_another_reserved_name() {
    let m = project();
    ok(allow_var(&m, "NODE_OPTIONS", "y", &[]).0);

    ok(m.run(&["rename", "NODE_OPTIONS", "JAVA_TOOL_OPTIONS"], None));

    let (env, _) = passed(&m, &[]);
    assert!(!env.contains_key("JAVA_TOOL_OPTIONS"), "{env:?}");
}

// --- deny --var ---

#[test]
fn deny_var_stops_passing_the_name() {
    let m = project();
    ok(allow_var(&m, "NODE_OPTIONS", "y", &[]).0);

    let run = ok(m.run(&["deny", "--var", "NODE_OPTIONS"], None));

    assert!(
        run.stdout
            .contains("✓ NODE_OPTIONS is no longer passed in payments/dev."),
        "{}",
        run.stdout
    );
    let (env, _) = passed(&m, &[]);
    assert!(!env.contains_key("NODE_OPTIONS"));
}

#[test]
fn deny_var_without_consent_says_so_and_needs_no_key() {
    let m = Machine::without_keychain();
    ok(m.setup_with_passphrase(PASSPHRASE).0);
    write_env(&m);
    ok(m.run(&["init", "--yes"], None));
    ok(m.run(&["lock"], None));

    let run = ok(m.run(&["deny", "--var", "NODE_OPTIONS"], None));

    assert!(
        run.stdout
            .contains("✓ NODE_OPTIONS was not allowed in payments/dev."),
        "{}",
        run.stdout
    );
}

#[test]
fn deny_var_refuses_names_that_are_not_reserved() {
    let m = project();
    let run = m.run(&["deny", "--var", "API_KEY", "--json"], None);
    assert_eq!(run.exit, Exit::Usage);
    assert_eq!(error_code(&run), "not_reserved");
}

// --- --json ---

#[test]
fn json_reports_allow_and_deny_var() {
    let m = project();

    let (run, terminal) = allow_var(&m, "NODE_OPTIONS", "n", &["--json"]);
    let report = json(&ok(run).stdout);
    assert_eq!(report["status"], "declined");
    assert!(
        terminal.transcript.contains(NODE_OPTIONS),
        "value still shown"
    );

    let (run, _) = allow_var(&m, "NODE_OPTIONS", "y", &["--json"]);
    let run = ok(run);
    assert!(!run.stdout.contains(NODE_OPTIONS), "{}", run.stdout);
    let report = json(&run.stdout);
    assert_eq!(report["status"], "allowed");
    assert_eq!(report["name"], "NODE_OPTIONS");
    assert_eq!(report["environment"], "payments/dev");
    assert_eq!(report["version"], 1);

    let (run, _) = allow_var(&m, "NODE_OPTIONS", "y", &["--json"]);
    assert_eq!(json(&ok(run).stdout)["status"], "already_allowed");

    let run = ok(m.run(&["deny", "--var", "NODE_OPTIONS", "--json"], None));
    assert_eq!(json(&run.stdout)["status"], "denied");
    let run = ok(m.run(&["deny", "--var", "NODE_OPTIONS", "--json"], None));
    assert_eq!(json(&run.stdout)["status"], "not_allowed");
}

// --- set ---

#[test]
fn set_warns_about_a_reserved_name() {
    let m = project();

    let run = set(&m, "PYTHONPATH", "/srv/lib");

    assert!(
        run.stdout.contains(
            "! PYTHONPATH is a reserved name: smart-env run and the shell hook skip it until allowed: smart-env allow --var PYTHONPATH"
        ),
        "{}",
        run.stdout
    );
}
