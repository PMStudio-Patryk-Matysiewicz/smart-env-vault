//! No leaks (F06 5): a value never reaches stdout, stderr, the terminal
//! (except the hidden prompt) or the arguments of any process.
//!
//! Every value contains [`CANARY`]; tests check for the fragment, not the
//! whole value, so a partial leak (one line of a multi-line value, a cut
//! value) is caught too.
mod common;

use std::process::Command;

use common::{Machine, Run, ScriptedTerminal, printed};
use secrecy::SecretString;
use smart_env_cli::{ChildCommand, Exit};

const CANARY: &str = "Zq7Kanarek";
const PASSPHRASE: &str = "correct horse battery staple";

/// `.env` with every value shape: URL with a password, several lines,
/// quotes and `$(...)`, Unicode, a `${VAR}` reference, a reserved name.
const DOTENV: &str = concat!(
    "DATABASE_URL=postgres://u:Zq7Kanarek-db@host/db\n",
    "API_KEY=sk_live_Zq7Kanarek\n",
    "PEM=\"-----BEGIN KEY-----\nZq7Kanarek-line2\n-----END KEY-----\"\n",
    "QUOTED=\"it's \\\"Zq7Kanarek\\\" $(id)\"\n",
    "UNICODE=zażółć-Zq7Kanarek-🔑\n",
    "INTERP=\"Zq7Kanarek-${HOME}\"\n",
    "PATH=/tmp/Zq7Kanarek/bin\n",
);

// --- helpers ---

fn assert_clean(what: &str, run: &Run) {
    let printed = printed(run);
    assert!(
        !printed.contains(CANARY),
        "{what}: value printed:\n{printed}"
    );
}

fn assert_terminal_clean(what: &str, terminal: &ScriptedTerminal) {
    assert!(
        !terminal.transcript.contains(CANARY),
        "{what}: value shown on the terminal:\n{}",
        terminal.transcript
    );
}

/// Runs `args` (with `--json` when asked) and checks the output.
fn go(m: &Machine, json: bool, args: &[&str]) -> Run {
    go_with_stdin(m, json, args, b"")
}

fn go_with_stdin(m: &Machine, json: bool, args: &[&str], stdin: &[u8]) -> Run {
    let mut argv: Vec<&str> = Vec::new();
    if json {
        argv.push("--json");
    }
    argv.extend_from_slice(args);
    let run = m.run_with_stdin(&argv, None, stdin);
    assert_clean(&argv.join(" "), &run);
    run
}

fn ok(what: &str, run: Run) -> Run {
    assert_eq!(run.exit, Exit::Success, "{what}: {}", printed(&run));
    run
}

fn failed(what: &str, run: &Run) {
    assert_ne!(run.exit, Exit::Success, "{what} should fail");
}

/// `setup` and `init` of [`DOTENV`] in project `payments`.
fn project() -> Machine {
    let m = Machine::new();
    let (setup, _) = m.setup();
    ok("setup", setup);
    m.write(".env", DOTENV);
    ok("init", m.run(&["init", "--yes"], None));
    m.launched.borrow_mut().clear();
    m
}

// --- every command, text and --json ---

fn sweep(json: bool) {
    let m = Machine::new();
    let mut terminal = ScriptedTerminal::confirming();
    let mut argv = vec!["setup"];
    if json {
        argv.insert(0, "--json");
    }
    let setup = m.run(&argv, Some(&mut terminal));
    ok("setup", setup);

    m.write(".env", DOTENV);
    ok("init", go(&m, json, &["init", "--yes"]));
    ok("ls", go(&m, json, &["ls"]));

    let value = |v: &str| format!("{v}-{CANARY}\n").into_bytes();
    ok(
        "set new",
        go_with_stdin(&m, json, &["set", "NEW", "--stdin"], &value("new")),
    );
    ok(
        "set change",
        go_with_stdin(&m, json, &["set", "API_KEY", "--stdin"], &value("v2")),
    );
    ok(
        "set same",
        go_with_stdin(&m, json, &["set", "API_KEY", "--stdin"], &value("v2")),
    );
    ok(
        "set --inject run",
        go_with_stdin(
            &m,
            json,
            &["set", "RUN_ONLY", "--stdin", "--inject", "run"],
            &value("run"),
        ),
    );
    ok("history", go(&m, json, &["history", "API_KEY"]));
    ok("undo", go(&m, json, &["undo", "API_KEY"]));
    ok("undo --to", go(&m, json, &["undo", "API_KEY", "--to", "2"]));
    ok("history after undo", go(&m, json, &["history", "API_KEY"]));
    ok("rename", go(&m, json, &["rename", "API_KEY", "STRIPE_KEY"]));
    go(&m, json, &["history", "API_KEY"]);
    ok("history renamed", go(&m, json, &["history", "STRIPE_KEY"]));
    ok("rm", go(&m, json, &["rm", "PEM"]));
    ok("history removed", go(&m, json, &["history", "PEM"]));
    ok("ls after rm", go(&m, json, &["ls"]));
    ok("undo rm", go(&m, json, &["undo", "PEM"]));
    ok("undo restore", go(&m, json, &["undo", "PEM"]));
    ok("undo removal again", go(&m, json, &["undo", "PEM"]));

    ok("run", go(&m, json, &["run", "--", "env"]));
    ok(
        "run --only",
        go(&m, json, &["run", "--only", "STRIPE_KEY,PATH", "--", "env"]),
    );
    ok(
        "run --except",
        go(&m, json, &["run", "--except", "UNICODE", "--", "env"]),
    );
}

#[test]
fn no_command_prints_a_value_as_text() {
    sweep(false);
}

#[test]
fn no_command_prints_a_value_as_json() {
    sweep(true);
}

// --- errors ---

#[test]
fn errors_of_variable_commands_never_print_the_value() {
    let m = project();
    for json in [false, true] {
        let cases: [(&str, Vec<&str>, Vec<u8>); 7] = [
            (
                "value as argument",
                vec!["set", "API_KEY", "sk_live_Zq7Kanarek"],
                Vec::new(),
            ),
            (
                "value as argument with --stdin",
                vec!["set", "API_KEY", "--stdin", "sk_live_Zq7Kanarek"],
                b"x\n".to_vec(),
            ),
            (
                "NAME=value",
                vec!["set", "API_KEY=sk_live_Zq7Kanarek", "--stdin"],
                b"x\n".to_vec(),
            ),
            (
                "NUL byte",
                vec!["set", "API_KEY", "--stdin"],
                format!("{CANARY}\0tail\n").into_bytes(),
            ),
            (
                "over 64 KiB",
                vec!["set", "API_KEY", "--stdin"],
                CANARY.repeat(70 * 1024 / CANARY.len()).into_bytes(),
            ),
            (
                "not UTF-8",
                vec!["set", "API_KEY", "--stdin"],
                [CANARY.as_bytes(), b"\xff\xfe\n"].concat(),
            ),
            (
                "no terminal, no --stdin",
                vec!["set", "API_KEY"],
                Vec::new(),
            ),
        ];
        for (what, args, stdin) in cases {
            let run = go_with_stdin(&m, json, &args, &stdin);
            failed(what, &run);
        }
        failed(
            "unknown name in --only",
            &go(&m, json, &["run", "--only", "NOPE", "--", "env"]),
        );
        failed(
            "invalid name in --except",
            &go(&m, json, &["run", "--except", "sk-Zq7Kanarek", "--", "env"]),
        );
        m.child.set(common::ChildResult::NotFound);
        failed(
            "command not found",
            &go(&m, json, &["run", "--", "no-such-command"]),
        );
        m.child.set(common::ChildResult::Exit(0));
    }
    // Nothing above changed the stored value.
    let run = ok(
        "run",
        m.run(&["run", "--only", "API_KEY", "--", "env"], None),
    );
    assert_clean("run", &run);
    let launch = m.launched.borrow().last().cloned().unwrap();
    assert_eq!(launch.env["API_KEY"], "sk_live_Zq7Kanarek");
}

#[test]
fn dotenv_errors_name_the_line_but_never_its_content() {
    let m = Machine::new();
    ok("setup", m.setup().0);
    let files: [(&str, &[u8]); 9] = [
        ("missing =", b"Zq7Kanarek\n"),
        ("invalid name", b"sk-live-Zq7Kanarek=1\n"),
        ("ambiguous comment", b"A=#Zq7Kanarek\n"),
        ("unterminated quote", b"A=\"Zq7Kanarek\n"),
        ("text after the quote", b"A=\"x\"Zq7Kanarek\n"),
        ("backticks", b"A=`Zq7Kanarek`\n"),
        ("duplicate", b"A=Zq7Kanarek-1\nA=Zq7Kanarek-2\n"),
        ("NUL byte", b"A=Zq7Kanarek\0x\n"),
        ("not UTF-8", b"A=Zq7Kanarek\xff\n"),
    ];
    for json in [false, true] {
        for (what, content) in files {
            std::fs::write(m.project.join(".env"), content).unwrap();
            let run = go(&m, json, &["init", "--yes"]);
            failed(what, &run);
        }
    }
}

// --- the terminal ---

#[test]
fn the_value_prompt_and_init_questions_never_show_a_value() {
    let m = Machine::new();
    ok("setup", m.setup().0);
    m.write(".env", DOTENV);

    let mut terminal = ScriptedTerminal::new(|_, _| "y".to_owned());
    let run = ok("init", m.run(&["init"], Some(&mut terminal)));
    assert_clean("init", &run);
    assert_terminal_clean("init", &terminal);

    let mut terminal = ScriptedTerminal::new(|_, _| format!("typed-{CANARY}"));
    let run = ok("set", m.run(&["set", "TYPED"], Some(&mut terminal)));
    assert_eq!(terminal.secret_questions, 1);
    assert_clean("set", &run);
    assert_terminal_clean("set", &terminal);
}

// --- passphrase mode ---

#[test]
fn lock_and_unlock_never_print_a_value() {
    let m = Machine::without_keychain();
    ok("setup", m.setup_with_passphrase(PASSPHRASE).0);
    m.write(".env", DOTENV);
    ok("init", m.run(&["init", "--yes"], None));

    for json in [false, true] {
        ok("lock", go(&m, json, &["lock"]));
        failed("run locked", &go(&m, json, &["run", "--", "env"]));

        let mut terminal = ScriptedTerminal::with_passphrase(PASSPHRASE);
        let mut argv = vec!["unlock"];
        if json {
            argv.insert(0, "--json");
        }
        let run = ok("unlock", m.run(&argv, Some(&mut terminal)));
        assert_clean("unlock", &run);
        assert_terminal_clean("unlock", &terminal);
        ok("run unlocked", go(&m, json, &["run", "--", "env"]));
    }
}

// --- process arguments ---

#[test]
fn run_puts_values_in_the_environment_never_in_the_arguments() {
    let m = project();
    ok(
        "run",
        go(&m, false, &["run", "--", "sh", "-c", "echo \"$API_KEY\""]),
    );
    let launch = m.launched.borrow().last().cloned().unwrap();
    assert!(!launch.program.contains(CANARY), "{launch:?}");
    assert!(
        !launch.args.iter().any(|arg| arg.contains(CANARY)),
        "{launch:?}"
    );
    assert!(
        launch.env.values().all(|value| value.contains(CANARY)),
        "every value reaches the environment: {launch:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_started_process_has_values_in_its_environment_not_its_command_line() {
    let read = |file: &str| {
        let command = ChildCommand {
            program: "cat".into(),
            args: vec![file.into()],
            env: vec![(
                "API_KEY".to_owned(),
                SecretString::from(format!("sk_live_{CANARY}")),
            )],
        };
        let output = command.to_command().output().unwrap();
        assert!(output.status.success());
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    let cmdline = read("/proc/self/cmdline");
    assert!(cmdline.contains("cat"), "{cmdline:?}");
    assert!(!cmdline.contains(CANARY), "value in argv: {cmdline:?}");
    assert!(read("/proc/self/environ").contains(CANARY));
}

// --- the binary ---

fn binary(args: &[&str]) -> std::process::Output {
    let home = tempfile::TempDir::new().unwrap();
    Command::new(env!("CARGO_BIN_EXE_smart-env"))
        .current_dir(home.path())
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", home.path().join("data"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn binary_never_repeats_a_value_typed_as_an_argument() {
    let cases: [&[&str]; 5] = [
        &["set", "API_KEY", "sk_live_Zq7Kanarek"],
        &["set", "API_KEY=sk_live_Zq7Kanarek"],
        &["sk_live_Zq7Kanarek"],
        &["run", "--only", "sk-Zq7Kanarek", "--", "true"],
        &["undo", "API_KEY", "--to", "Zq7Kanarek"],
    ];
    for args in cases {
        for json in [false, true] {
            let mut argv: Vec<&str> = args.to_vec();
            if json {
                argv.insert(0, "--json");
            }
            let output = binary(&argv);
            assert_eq!(output.status.code(), Some(2), "{argv:?}");
            let printed = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!printed.contains(CANARY), "{argv:?}: {printed}");
        }
    }
}
