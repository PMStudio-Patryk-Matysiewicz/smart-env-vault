//! The parser and error reporting, in-process through `execute` and once
//! through the real binary.
use std::process::Command;

use smart_env_cli::{Cli, Command as Cmd, Context, Exit, execute};
use smart_env_vault::{DataPaths, MemoryStore};

struct Output {
    exit: Exit,
    stdout: String,
    stderr: String,
}

fn smart_env(args: &[&str]) -> Output {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let argv = std::iter::once("smart-env").chain(args.iter().copied());
    let dir = tempfile::TempDir::new().unwrap();
    let keys = MemoryStore::default();
    let session = MemoryStore::default();
    let mut ctx = Context {
        data: Some(DataPaths::from_root(dir.path().join("smart-env"))),
        keys: &keys,
        session: &session,
        account_label: "trawers".to_owned(),
        device_label: "laptop".to_owned(),
        terminal: None,
    };
    let exit = execute(argv, &mut ctx, &mut out, &mut err);
    Output {
        exit,
        stdout: String::from_utf8(out).unwrap(),
        stderr: String::from_utf8(err).unwrap(),
    }
}

fn parse(args: &[&str]) -> Cli {
    use clap::Parser;
    Cli::try_parse_from(std::iter::once("smart-env").chain(args.iter().copied())).unwrap()
}

fn json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).unwrap()
}

#[test]
fn global_flags_should_be_accepted_after_the_command() {
    let cli = parse(&["ls", "--env", "payments/dev", "--json", "--yes"]);

    let env = cli.global.env.unwrap();
    assert_eq!(env.project.as_deref(), Some("payments"));
    assert_eq!(env.environment, "dev");
    assert!(cli.global.json);
    assert!(cli.global.yes);
    assert!(matches!(cli.command, Cmd::Ls));
}

#[test]
fn run_should_take_the_command_after_double_dash() {
    let cli = parse(&["run", "--only", "A,B", "--", "npm", "run", "dev", "--json"]);

    let Cmd::Run { only, command, .. } = cli.command else {
        panic!("expected run");
    };
    assert_eq!(only, ["A", "B"]);
    assert_eq!(command, ["npm", "run", "dev", "--json"]);
    assert!(!cli.global.json, "--json after -- belongs to the child");
}

#[test]
fn help_should_exit_0_on_stdout() {
    let output = smart_env(&["--help"]);

    assert_eq!(output.exit, Exit::Success);
    assert!(output.stdout.contains("smart-env"));
    assert!(output.stderr.is_empty());
}

#[test]
fn version_should_exit_0_on_stdout() {
    let output = smart_env(&["--version"]);

    assert_eq!(output.exit, Exit::Success);
    assert!(output.stdout.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn unknown_command_should_be_usage_error_with_help_hint() {
    let output = smart_env(&["frobnicate"]);

    assert_eq!(output.exit, Exit::Usage);
    assert!(output.stderr.starts_with("✗ "));
    assert!(output.stderr.contains("--help"));
    assert!(output.stdout.is_empty());
}

#[test]
fn malformed_env_should_be_usage_error() {
    let output = smart_env(&["ls", "--env", "a/b/c"]);

    assert_eq!(output.exit, Exit::Usage);
    assert!(output.stderr.starts_with("✗ "));
}

#[test]
fn usage_error_with_json_should_be_json_on_stdout() {
    let output = smart_env(&["frobnicate", "--json"]);

    assert_eq!(output.exit, Exit::Usage);
    assert!(output.stderr.is_empty());
    let json = json(&output.stdout);
    assert_eq!(json["error"]["code"], "usage");
    assert!(json["error"]["hint"].as_str().unwrap().contains("--help"));
}

#[test]
fn json_flag_before_the_command_should_also_apply_to_usage_errors() {
    let output = smart_env(&["--json", "rm"]);

    assert_eq!(output.exit, Exit::Usage);
    assert_eq!(json(&output.stdout)["error"]["code"], "usage");
}

#[test]
fn json_after_double_dash_should_not_switch_error_format() {
    let output = smart_env(&["run", "--bogus", "--", "--json"]);

    assert_eq!(output.exit, Exit::Usage);
    assert!(output.stdout.is_empty());
    assert!(output.stderr.starts_with("✗ "));
}

#[test]
fn usage_error_should_not_echo_a_value_given_as_argument() {
    // A value pasted where it does not belong must not land in the terminal or CI logs.
    for args in [
        &["set", "API_KEY", "hunter2-s3cr3t"][..],
        &["set", "API_KEY", "hunter2-s3cr3t", "--json"][..],
        &["--hunter2-s3cr3t"][..],
    ] {
        let output = smart_env(args);

        assert_eq!(output.exit, Exit::Usage, "{args:?}");
        assert!(
            !output.stdout.contains("hunter2"),
            "{args:?}: {}",
            output.stdout
        );
        assert!(
            !output.stderr.contains("hunter2"),
            "{args:?}: {}",
            output.stderr
        );
    }
}

#[test]
fn binary_should_exit_with_usage_code() {
    let output = Command::new(env!("CARGO_BIN_EXE_smart-env"))
        .arg("frobnicate")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stderr).unwrap().starts_with("✗ "));
}
