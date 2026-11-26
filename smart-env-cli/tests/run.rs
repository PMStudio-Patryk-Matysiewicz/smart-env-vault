//! `run` through `execute` with a recording runner, `ChildCommand` with real
//! processes, and the binary once ([[05 - Kontrakt DX]] Scenario 1 without
//! the hook, F06 4).
mod common;

use std::collections::BTreeMap;
use std::process::Command;

use common::{ChildResult, Launched, Machine, Run, error_code, json, printed};
use secrecy::SecretString;
use smart_env_cli::{ChildCommand, Exit};

const SECRET: &str = "hunter2";

// --- helpers ---

/// After `setup` and `init`: project `payments` with `dev` (`API_KEY`,
/// `DATABASE_URL`) and `prod` (`API_KEY`); every value contains `hunter2`.
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
    m.launched.borrow_mut().clear();
    m
}

fn ok(run: Run) -> Run {
    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    run
}

fn set(m: &Machine, args: &[&str], value: &str) {
    let mut argv = vec!["set"];
    argv.extend_from_slice(args);
    argv.push("--stdin");
    ok(m.run_with_stdin(&argv, None, format!("{value}\n").as_bytes()));
    m.launched.borrow_mut().clear();
}

fn launched(m: &Machine) -> Vec<Launched> {
    m.launched.borrow().clone()
}

/// The only command started.
fn the_launch(m: &Machine) -> Launched {
    let launched = launched(m);
    assert_eq!(launched.len(), 1, "{launched:?}");
    launched.into_iter().next().unwrap()
}

fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

fn assert_no_secret(run: &Run) {
    assert!(
        !printed(run).contains(SECRET),
        "value printed: {}",
        printed(run)
    );
}

// --- the command and its variables ---

#[test]
fn run_starts_the_command_with_every_variable_of_the_environment() {
    let m = project();
    let run = ok(m.run(&["run", "--", "npm", "run", "dev"], None));

    let launch = the_launch(&m);
    assert_eq!(launch.program, "npm");
    assert_eq!(launch.args, ["run", "dev"]);
    assert_eq!(
        launch.env,
        env(&[
            ("API_KEY", "dev-hunter2"),
            ("DATABASE_URL", "postgres://u:hunter2@db"),
        ])
    );
    assert!(run.stdout.is_empty(), "stdout belongs to the command");
    assert_no_secret(&run);
}

#[test]
fn arguments_after_double_dash_are_passed_verbatim_and_never_carry_values() {
    let m = project();
    ok(m.run(
        &[
            "run",
            "--",
            "sh",
            "-c",
            "echo \"$API_KEY\"",
            "--json",
            "--env",
            "x y",
        ],
        None,
    ));

    let launch = the_launch(&m);
    assert_eq!(
        launch.args,
        ["-c", "echo \"$API_KEY\"", "--json", "--env", "x y"]
    );
    assert!(
        !launch.args.iter().any(|arg| arg.contains(SECRET)),
        "{launch:?}"
    );
}

#[test]
fn run_only_variables_are_passed_too() {
    let m = project();
    set(&m, &["TOKEN", "--inject", "run"], "t");
    ok(m.run(&["run", "--", "env"], None));
    assert_eq!(
        the_launch(&m).env.get("TOKEN").map(String::as_str),
        Some("t")
    );
}

#[test]
fn values_are_passed_exactly() {
    let m = project();
    let tricky = "a b\"c'$(touch x)`id`\\\nżółć;|&";
    set(&m, &["TRICKY"], tricky);
    ok(m.run(&["run", "--", "env"], None));
    assert_eq!(
        the_launch(&m).env.get("TRICKY").map(String::as_str),
        Some(tricky)
    );
}

#[test]
fn an_empty_environment_still_runs_the_command() {
    let m = Machine::new();
    let (setup, _) = m.setup();
    assert_eq!(setup.exit, Exit::Success, "{}", printed(&setup));
    ok(m.run(&["init", "--yes"], None));
    m.launched.borrow_mut().clear();

    ok(m.run(&["run", "--", "true"], None));
    assert!(the_launch(&m).env.is_empty());
}

#[test]
fn env_flag_selects_the_environment() {
    let mut m = project();
    ok(m.run(&["run", "--env", "prod", "--", "env"], None));
    assert_eq!(the_launch(&m).env, env(&[("API_KEY", "prod-hunter2")]));

    m.launched.borrow_mut().clear();
    m.use_project_dir("elsewhere");
    ok(m.run(&["run", "--env", "payments/prod", "--", "env"], None));
    assert_eq!(the_launch(&m).env, env(&[("API_KEY", "prod-hunter2")]));
}

// --- exit code ---

#[test]
fn run_exits_with_the_exit_code_of_the_command() {
    let m = project();
    for code in [0, 1, 7, 130, 255] {
        m.child.set(ChildResult::Exit(code));
        let run = m.run(&["run", "--", "false"], None);
        assert_eq!(run.exit.code(), code);
        assert_eq!(
            run.exit,
            if code == 0 {
                Exit::Success
            } else {
                Exit::Child(code)
            }
        );
    }
}

#[test]
fn child_exit_codes_map_to_themselves() {
    for code in [1, 2, 7, 126, 127, 255] {
        assert_eq!(Exit::Child(code).code(), code);
    }
}

#[test]
fn a_command_that_does_not_exist_exits_127() {
    let m = project();
    m.child.set(ChildResult::NotFound);
    let run = m.run(&["run", "--json", "--", "npmm", "run", "dev"], None);

    assert_eq!(run.exit.code(), 127);
    assert_eq!(error_code(&run), "command_not_found");
    let error = &json(&run.stdout)["error"];
    assert!(
        error["message"].as_str().unwrap().contains("npmm"),
        "{error}"
    );
    assert_no_secret(&run);
}

#[test]
fn a_command_that_cannot_be_executed_exits_126() {
    let m = project();
    m.child.set(ChildResult::PermissionDenied);
    let run = m.run(&["run", "--json", "--", "./script.sh"], None);

    assert_eq!(run.exit.code(), 126);
    assert_eq!(error_code(&run), "command_not_executable");
}

// --- --only / --except ---

#[test]
fn only_passes_just_the_named_variables() {
    let m = project();
    set(&m, &["THIRD"], "3");
    ok(m.run(&["run", "--only", "API_KEY,THIRD", "--", "env"], None));
    assert_eq!(
        the_launch(&m).env,
        env(&[("API_KEY", "dev-hunter2"), ("THIRD", "3")])
    );
}

#[test]
fn except_passes_everything_else() {
    let m = project();
    ok(m.run(&["run", "--except", "DATABASE_URL", "--", "env"], None));
    assert_eq!(the_launch(&m).env, env(&[("API_KEY", "dev-hunter2")]));
}

#[test]
fn only_and_except_accept_repeated_flags() {
    let m = project();
    set(&m, &["THIRD"], "3");
    ok(m.run(
        &[
            "run", "--except", "API_KEY", "--except", "THIRD", "--", "env",
        ],
        None,
    ));
    assert_eq!(
        the_launch(&m).env,
        env(&[("DATABASE_URL", "postgres://u:hunter2@db")])
    );
}

#[test]
fn an_unknown_name_in_only_or_except_is_an_error_and_starts_nothing() {
    let m = project();
    for args in [
        &["run", "--only", "API_KEY,NOPE", "--json", "--", "env"][..],
        &["run", "--except", "DATABSE_URL", "--json", "--", "env"][..],
    ] {
        let run = m.run(args, None);

        assert_eq!(run.exit, Exit::NotFound, "{args:?}");
        assert_eq!(error_code(&run), "secret_not_found", "{args:?}");
        let message = json(&run.stdout)["error"]["message"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            message.contains("NOPE") || message.contains("DATABSE_URL"),
            "{message}"
        );
    }
    assert!(launched(&m).is_empty());
}

#[test]
fn an_invalid_name_in_only_is_a_usage_error() {
    let m = project();
    let run = m.run(&["run", "--only", "1BAD", "--json", "--", "env"], None);
    assert_eq!(run.exit, Exit::Usage);
    assert_eq!(error_code(&run), "invalid_name");
    assert!(launched(&m).is_empty());
}

#[test]
fn only_and_except_together_are_a_usage_error() {
    let m = project();
    let run = m.run(
        &["run", "--only", "A", "--except", "B", "--json", "--", "env"],
        None,
    );
    assert_eq!(run.exit, Exit::Usage);
    assert!(launched(&m).is_empty());
}

// --- reserved names ---

#[test]
fn reserved_names_are_skipped_with_a_warning_on_stderr() {
    let m = project();
    set(&m, &["PATH"], "/evil/bin");
    set(&m, &["NODE_OPTIONS"], "--require ./evil.js");
    let run = ok(m.run(&["run", "--", "npm", "test"], None));

    let launch = the_launch(&m);
    assert!(!launch.env.contains_key("PATH"), "{launch:?}");
    assert!(!launch.env.contains_key("NODE_OPTIONS"), "{launch:?}");
    assert!(launch.env.contains_key("API_KEY"));
    assert!(run.stdout.is_empty(), "{}", run.stdout);
    assert!(
        run.stderr.contains(
            "! NODE_OPTIONS, PATH are reserved names and were not passed. Allow one with: smart-env allow --var NAME"
        ),
        "{}",
        run.stderr
    );
}

#[test]
fn a_reserved_name_is_skipped_even_when_named_in_only() {
    let m = project();
    set(&m, &["PATH"], "/evil/bin");
    let run = ok(m.run(&["run", "--only", "PATH,API_KEY", "--", "env"], None));

    assert_eq!(the_launch(&m).env, env(&[("API_KEY", "dev-hunter2")]));
    assert!(
        run.stderr
            .contains("! PATH is a reserved name and was not passed."),
        "{}",
        run.stderr
    );
}

// --- checks before anything starts ---

#[test]
fn a_locked_key_starts_nothing() {
    let m = Machine::without_keychain();
    let (setup, _) = m.setup_with_passphrase("correct horse battery");
    assert_eq!(setup.exit, Exit::Success, "{}", printed(&setup));
    m.write(".env", "A=1\n");
    ok(m.run(&["init", "--yes"], None));
    m.session.delete().unwrap();

    let run = m.run(&["run", "--json", "--", "env"], None);
    assert_eq!(run.exit, Exit::Access);
    assert_eq!(error_code(&run), "key_locked");
    assert!(launched(&m).is_empty());
}

#[test]
fn without_setup_or_project_nothing_starts() {
    let m = Machine::new();
    let run = m.run(&["run", "--json", "--", "env"], None);
    assert_eq!(error_code(&run), "not_set_up");

    let mut m = project();
    m.use_project_dir("elsewhere");
    let run = m.run(&["run", "--json", "--", "env"], None);
    assert_eq!(error_code(&run), "project_file_not_found");

    let run = m.run(
        &["run", "--env", "payments/stage", "--json", "--", "env"],
        None,
    );
    assert_eq!(error_code(&run), "environment_not_found");
    assert!(launched(&m).is_empty());
}

#[test]
fn a_missing_command_is_a_usage_error() {
    let m = project();
    for args in [&["run"][..], &["run", "--"][..]] {
        let run = m.run(args, None);
        assert_eq!(run.exit, Exit::Usage, "{args:?}");
    }
    assert!(launched(&m).is_empty());
}

#[test]
fn errors_with_json_go_to_stdout_and_warnings_never_do() {
    let m = project();
    set(&m, &["PATH"], "/bin");
    let run = ok(m.run(&["run", "--json", "--", "env"], None));
    assert!(run.stdout.is_empty(), "{}", run.stdout);
    assert!(run.stderr.contains("PATH"), "{}", run.stderr);
}

#[test]
fn a_renamed_project_warns_on_stderr_only() {
    let m = project();
    let toml = m.read("smart-env.toml").unwrap();
    m.write(
        "smart-env.toml",
        &toml.replace("project = \"payments\"", "project = \"old-name\""),
    );

    let run = ok(m.run(&["run", "--", "env"], None));
    assert!(run.stdout.is_empty(), "{}", run.stdout);
    assert!(run.stderr.contains("payments"), "{}", run.stderr);
}

// --- ChildCommand with real processes ---

fn child(program: &str, args: &[&str], vars: &[(&str, &str)]) -> ChildCommand {
    ChildCommand {
        program: program.into(),
        args: args.iter().map(Into::into).collect(),
        env: vars
            .iter()
            .map(|(name, value)| ((*name).to_owned(), SecretString::from(*value)))
            .collect(),
    }
}

#[test]
fn child_command_adds_variables_and_keeps_the_inherited_environment() {
    let output = child(
        "sh",
        &["-c", "printf '%s|%s' \"$A\" \"$HOME\""],
        &[("A", "x y $(id)")],
    )
    .to_command()
    .output()
    .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let home = std::env::var("HOME").unwrap_or_default();
    assert_eq!(stdout, format!("x y $(id)|{home}"));
}

#[test]
fn child_command_variables_override_inherited_ones() {
    let output = child(
        "sh",
        &["-c", "printf %s \"$HOME\""],
        &[("HOME", "/vault/home")],
    )
    .to_command()
    .output()
    .unwrap();
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "/vault/home");
}

#[test]
fn child_command_passes_arguments_verbatim() {
    let output = child("printf", &["%s|%s", "a b", "$HOME"], &[])
        .to_command()
        .output()
        .unwrap();
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "a b|$HOME");
}

#[test]
fn child_command_reports_the_exit_code() {
    let status = child("sh", &["-c", "exit 7"], &[])
        .to_command()
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(7));
}

// --- the binary ---

#[test]
fn binary_run_without_setup_reports_not_set_up_and_starts_nothing() {
    let home = tempfile::TempDir::new().unwrap();
    let marker = home.path().join("started");
    let output = Command::new(env!("CARGO_BIN_EXE_smart-env"))
        .current_dir(home.path())
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", home.path().join("data"))
        .args(["run", "--", "touch"])
        .arg(&marker)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(4));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("smart-env setup")
    );
    assert!(!marker.exists(), "the command must not start");
}
