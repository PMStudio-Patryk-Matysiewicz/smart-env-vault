//! `set`, `ls`, `rm` and `rename` through `execute`, in a project created by
//! `init` ([[05 - Kontrakt DX]] Scenarios 2 and 10).
mod common;

use common::{Machine, Run, ScriptedTerminal, error_code, json, printed};
use smart_env_cli::Exit;
use smart_env_vault::{EnvironmentId, Inject, MAX_VALUE_LEN, SecretMeta, VarName};

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
    let init = m.run(&["init", "--yes"], None);
    assert_eq!(init.exit, Exit::Success, "{}", printed(&init));
    m
}

/// Runs `args` with `input` on stdin and no terminal.
fn piped(m: &Machine, args: &[&str], input: &str) -> Run {
    m.run_with_stdin(args, None, input.as_bytes())
}

fn ok(run: Run) -> Run {
    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    run
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

/// Current value of `name` in `payments/<environment>`.
fn value(m: &Machine, environment: &str, name: &str) -> Option<String> {
    let key = m.stored_key().expect("device key in the keychain");
    m.vault()
        .get(env_id(m, environment), &VarName::parse(name).unwrap(), &key)
        .unwrap()
        .map(|value| value.expose().to_owned())
}

fn metas(m: &Machine, environment: &str) -> Vec<SecretMeta> {
    m.vault().list(env_id(m, environment)).unwrap()
}

fn names(m: &Machine, environment: &str) -> Vec<String> {
    metas(m, environment)
        .into_iter()
        .map(|meta| meta.name.to_string())
        .collect()
}

fn meta(m: &Machine, environment: &str, name: &str) -> SecretMeta {
    metas(m, environment)
        .into_iter()
        .find(|meta| meta.name.as_str() == name)
        .unwrap_or_else(|| panic!("{name} in payments/{environment}"))
}

fn revision(m: &Machine, environment: &str) -> u64 {
    m.vault().revision(env_id(m, environment)).unwrap()
}

/// Terminal that answers the hidden value question with `answer` and counts
/// questions; never confirms anything else.
fn typing(answer: &'static str) -> ScriptedTerminal {
    ScriptedTerminal::new(move |_, _| answer.to_owned())
}

fn assert_no_secret(run: &Run) {
    assert!(
        !printed(run).contains(SECRET),
        "value printed: {}",
        printed(run)
    );
}

// --- set: value from stdin ---

#[test]
fn set_from_stdin_stores_the_value_in_the_default_environment() {
    let m = project();
    let run = ok(piped(&m, &["set", "STRIPE_KEY", "--stdin"], "sk_hunter2\n"));

    assert_eq!(
        value(&m, "dev", "STRIPE_KEY").as_deref(),
        Some("sk_hunter2")
    );
    assert!(
        run.stdout
            .contains("✓ STRIPE_KEY saved in payments/dev (version 1)"),
        "{}",
        run.stdout
    );
    assert_no_secret(&run);
}

#[test]
fn set_from_stdin_cuts_exactly_one_trailing_newline() {
    let m = project();
    for (input, stored) in [
        ("abc\n", "abc"),
        ("abc\r\n", "abc"),
        ("abc", "abc"),
        ("abc\n\n", "abc\n"),
        ("line1\nline2\n", "line1\nline2"),
        ("  padded  \n", "  padded  "),
    ] {
        ok(piped(&m, &["set", "V", "--stdin"], input));
        assert_eq!(value(&m, "dev", "V").as_deref(), Some(stored), "{input:?}");
    }
}

#[test]
fn set_from_empty_stdin_stores_an_empty_value() {
    let m = project();
    ok(piped(&m, &["set", "EMPTY", "--stdin"], ""));
    assert_eq!(value(&m, "dev", "EMPTY").as_deref(), Some(""));
}

#[test]
fn set_from_stdin_refuses_a_value_over_64_kib() {
    let m = project();
    let input = "x".repeat(MAX_VALUE_LEN + 1);
    let run = piped(&m, &["set", "BIG", "--stdin", "--json"], &input);

    assert_eq!(run.exit, Exit::Usage);
    assert_eq!(error_code(&run), "value_too_large");
    assert!(!names(&m, "dev").contains(&"BIG".to_owned()));
}

#[test]
fn set_from_stdin_accepts_exactly_64_kib_plus_newline() {
    let m = project();
    let input = format!("{}\n", "x".repeat(MAX_VALUE_LEN));
    ok(piped(&m, &["set", "BIG", "--stdin"], &input));
    assert_eq!(
        value(&m, "dev", "BIG").map(|v| v.len()),
        Some(MAX_VALUE_LEN)
    );
}

#[test]
fn set_from_stdin_refuses_non_utf8() {
    let m = project();
    let run = m.run_with_stdin(
        &["set", "BIN", "--stdin", "--json"],
        None,
        b"\xff\xfehunter2",
    );

    assert_eq!(run.exit, Exit::Usage);
    assert_eq!(error_code(&run), "value_not_utf8");
    assert!(!names(&m, "dev").contains(&"BIN".to_owned()));
    assert_no_secret(&run);
}

#[test]
fn set_with_stdin_reads_stdin_even_on_a_terminal() {
    let m = project();
    let mut terminal = typing("from-terminal");
    ok(m.run_with_stdin(
        &["set", "V", "--stdin"],
        Some(&mut terminal),
        b"from-stdin\n",
    ));

    assert_eq!(value(&m, "dev", "V").as_deref(), Some("from-stdin"));
    assert_eq!(terminal.questions + terminal.secret_questions, 0);
}

// --- set: value from the prompt ---

#[test]
fn set_on_a_terminal_asks_once_without_echo() {
    let m = project();
    let mut terminal = typing("sk_hunter2");
    let run = ok(m.run(&["set", "STRIPE_KEY"], Some(&mut terminal)));

    assert_eq!(
        value(&m, "dev", "STRIPE_KEY").as_deref(),
        Some("sk_hunter2")
    );
    assert_eq!(terminal.secret_questions, 1);
    assert_eq!(terminal.questions, 0, "no visible question");
    assert!(
        terminal.transcript.contains("STRIPE_KEY"),
        "{}",
        terminal.transcript
    );
    assert!(
        !terminal.transcript.contains(SECRET),
        "{}",
        terminal.transcript
    );
    assert_no_secret(&run);
}

#[test]
fn set_on_a_terminal_refuses_an_empty_answer() {
    let m = project();
    let before = revision(&m, "dev");
    let mut terminal = typing("");
    let run = m.run(&["set", "STRIPE_KEY", "--json"], Some(&mut terminal));

    assert_eq!(run.exit, Exit::Usage);
    assert_eq!(error_code(&run), "empty_value");
    assert!(
        json(&run.stdout)["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("--stdin")
    );
    assert_eq!(revision(&m, "dev"), before, "nothing saved");
}

#[test]
fn set_without_terminal_and_without_stdin_flag_is_value_required() {
    let m = project();
    for args in [
        &["set", "V", "--json"][..],
        &["set", "V", "--yes", "--json"][..],
    ] {
        let run = piped(&m, args, "ignored\n");

        assert_eq!(run.exit, Exit::Usage, "{args:?}");
        assert_eq!(error_code(&run), "value_required", "{args:?}");
        assert!(
            json(&run.stdout)["error"]["hint"]
                .as_str()
                .unwrap()
                .contains("--stdin")
        );
    }
    assert!(!names(&m, "dev").contains(&"V".to_owned()));
}

// --- set: overwrite and inject ---

#[test]
fn set_overwrites_without_asking_and_reports_the_new_version() {
    let m = project();
    let mut terminal = typing("new-hunter2");
    let run = ok(m.run(&["set", "API_KEY"], Some(&mut terminal)));

    assert_eq!(value(&m, "dev", "API_KEY").as_deref(), Some("new-hunter2"));
    assert_eq!(terminal.questions, 0, "no confirmation");
    assert!(
        run.stdout
            .contains("✓ API_KEY saved in payments/dev (version 2)"),
        "{}",
        run.stdout
    );
}

#[test]
fn set_on_a_removed_name_brings_it_back_with_history() {
    let m = project();
    ok(m.run(&["rm", "API_KEY"], None));
    let run = ok(piped(&m, &["set", "API_KEY", "--stdin"], "again\n"));

    assert!(run.stdout.contains("(version 2)"), "{}", run.stdout);
    assert_eq!(value(&m, "dev", "API_KEY").as_deref(), Some("again"));
}

#[test]
fn set_inject_run_marks_the_variable_run_only() {
    let m = project();
    let run = ok(piped(
        &m,
        &["set", "ANALYTICS_TOKEN", "--inject", "run", "--stdin"],
        "t\n",
    ));

    assert_eq!(meta(&m, "dev", "ANALYTICS_TOKEN").inject, Inject::Run);
    assert!(
        run.stdout.contains(
            "✓ ANALYTICS_TOKEN saved in payments/dev (version 1, smart-env run only, not exported to the shell)"
        ),
        "{}",
        run.stdout
    );
}

#[test]
fn set_inject_run_on_an_existing_variable_is_one_change() {
    let m = project();
    let before = revision(&m, "dev");
    ok(piped(
        &m,
        &["set", "API_KEY", "--inject", "run", "--stdin"],
        "x\n",
    ));

    assert_eq!(meta(&m, "dev", "API_KEY").inject, Inject::Run);
    assert_eq!(revision(&m, "dev"), before + 1);
}

#[test]
fn set_without_inject_keeps_run_and_inject_shell_switches_back() {
    let m = project();
    ok(piped(
        &m,
        &["set", "T", "--inject", "run", "--stdin"],
        "1\n",
    ));
    let kept = ok(piped(&m, &["set", "T", "--stdin"], "2\n"));
    assert_eq!(meta(&m, "dev", "T").inject, Inject::Run);
    assert!(
        kept.stdout.contains("smart-env run only"),
        "{}",
        kept.stdout
    );

    let back = ok(piped(
        &m,
        &["set", "T", "--inject", "shell", "--stdin"],
        "3\n",
    ));
    assert_eq!(meta(&m, "dev", "T").inject, Inject::Shell);
    assert!(
        !back.stdout.contains("smart-env run only"),
        "{}",
        back.stdout
    );
}

#[test]
fn set_reserved_name_is_saved_with_a_warning() {
    let m = project();
    let run = ok(piped(
        &m,
        &["set", "NODE_OPTIONS", "--stdin"],
        "--inspect\n",
    ));

    assert_eq!(
        value(&m, "dev", "NODE_OPTIONS").as_deref(),
        Some("--inspect")
    );
    assert!(
        run.stdout.contains(
            "! NODE_OPTIONS is a reserved name: smart-env run and the shell hook skip it until allowed: smart-env allow --var NODE_OPTIONS"
        ),
        "{}",
        run.stdout
    );
}

#[test]
fn set_json_reports_the_variable_without_its_value() {
    let m = project();
    let run = ok(piped(
        &m,
        &["set", "PATH", "--inject", "run", "--stdin", "--json"],
        "/hunter2/bin\n",
    ));

    let report = json(&run.stdout);
    assert_eq!(report["status"], "saved");
    assert_eq!(report["project"], "payments");
    assert_eq!(report["environment"], "dev");
    assert_eq!(report["name"], "PATH");
    assert_eq!(report["version"], 1);
    assert_eq!(report["inject"], "run");
    assert_eq!(report["reserved"], true);
    assert!(report["warnings"].is_array());
    assert!(run.stderr.is_empty());
    assert_no_secret(&run);
}

// --- set: order of checks (nothing asked before it can be saved) ---

#[test]
fn set_with_an_invalid_name_fails_before_asking_for_the_value() {
    let m = project();
    for name in ["1ABC", "WITH-DASH", "A B", ""] {
        let mut terminal = typing("hunter2");
        let run = m.run(&["set", name, "--json"], Some(&mut terminal));

        assert_eq!(run.exit, Exit::Usage, "{name:?}");
        assert_eq!(error_code(&run), "invalid_name", "{name:?}");
        assert_eq!(terminal.secret_questions, 0, "{name:?}");
    }
}

#[test]
fn set_with_a_locked_key_fails_before_asking_for_the_value() {
    let m = Machine::without_keychain();
    let (setup, _) = m.setup_with_passphrase("correct horse battery");
    assert_eq!(setup.exit, Exit::Success, "{}", printed(&setup));
    m.write(".env", "A=1\n");
    ok(m.run(&["init", "--yes"], None));
    m.session.delete().unwrap();

    let mut terminal = typing("hunter2");
    let run = m.run(&["set", "B", "--json"], Some(&mut terminal));

    assert_eq!(run.exit, Exit::Access);
    assert_eq!(error_code(&run), "key_locked");
    assert_eq!(terminal.secret_questions, 0);
    assert_eq!(names(&m, "dev"), ["A"]);
}

// --- choosing the environment (shared by all four commands) ---

#[test]
fn env_flag_selects_another_environment_of_the_current_project() {
    let m = project();
    let run = ok(piped(&m, &["set", "X", "--env", "prod", "--stdin"], "p\n"));

    assert_eq!(value(&m, "prod", "X").as_deref(), Some("p"));
    assert!(!names(&m, "dev").contains(&"X".to_owned()));
    assert!(run.stdout.contains("payments/prod"), "{}", run.stdout);
}

#[test]
fn env_flag_with_project_works_outside_the_project_directory() {
    let mut m = project();
    m.use_project_dir("elsewhere");
    ok(piped(
        &m,
        &["set", "X", "--env", "payments/prod", "--stdin"],
        "p\n",
    ));
    assert_eq!(value(&m, "prod", "X").as_deref(), Some("p"));

    let ls = ok(m.run(&["ls", "--env", "payments/prod"], None));
    assert!(ls.stdout.contains("  X"), "{}", ls.stdout);
}

#[test]
fn project_comes_from_smart_env_toml_in_a_parent_directory() {
    let mut m = project();
    let root = m.project.clone();
    m.project = root.join("src").join("api");
    std::fs::create_dir_all(&m.project).unwrap();

    ok(piped(&m, &["set", "X", "--stdin"], "1\n"));
    assert_eq!(value(&m, "dev", "X").as_deref(), Some("1"));
}

#[test]
fn unknown_environment_is_not_found_and_lists_existing_ones() {
    let m = project();
    for args in [
        &["ls", "--env", "stage", "--json"][..],
        &["rm", "A", "--env", "stage", "--json"][..],
        &["rename", "A", "B", "--env", "stage", "--json"][..],
    ] {
        let run = m.run(args, None);

        assert_eq!(run.exit, Exit::NotFound, "{args:?}");
        assert_eq!(error_code(&run), "environment_not_found", "{args:?}");
        let error = &json(&run.stdout)["error"];
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("payments/stage"),
            "{error}"
        );
        assert!(
            error["hint"].as_str().unwrap().contains("dev, prod"),
            "{error}"
        );
    }
}

#[test]
fn set_in_an_unknown_environment_does_not_ask_for_the_value() {
    let m = project();
    let mut terminal = typing("hunter2");
    let run = m.run(
        &["set", "A", "--env", "stage", "--json"],
        Some(&mut terminal),
    );

    assert_eq!(error_code(&run), "environment_not_found");
    assert_eq!(terminal.secret_questions, 0);
}

#[test]
fn unknown_project_is_not_found() {
    let m = project();
    let run = m.run(&["ls", "--env", "shop/dev", "--json"], None);

    assert_eq!(run.exit, Exit::NotFound);
    assert_eq!(error_code(&run), "project_not_found");
}

#[test]
fn without_smart_env_toml_and_without_project_in_env_is_project_file_not_found() {
    let mut m = project();
    m.use_project_dir("elsewhere");
    for args in [&["ls", "--json"][..], &["ls", "--env", "dev", "--json"][..]] {
        let run = m.run(args, None);

        assert_eq!(run.exit, Exit::NotFound, "{args:?}");
        assert_eq!(error_code(&run), "project_file_not_found", "{args:?}");
    }
}

#[test]
fn without_setup_is_not_set_up_and_creates_nothing() {
    let m = Machine::new();
    for args in [
        &["ls", "--env", "payments/dev", "--json"][..],
        &["rm", "A", "--env", "payments/dev", "--json"][..],
        &["rename", "A", "B", "--env", "payments/dev", "--json"][..],
    ] {
        let run = m.run(args, None);

        assert_eq!(run.exit, Exit::NotFound, "{args:?}");
        assert_eq!(error_code(&run), "not_set_up", "{args:?}");
    }
    let run = piped(
        &m,
        &["set", "A", "--env", "payments/dev", "--stdin", "--json"],
        "1\n",
    );
    assert_eq!(error_code(&run), "not_set_up");
    m.assert_nothing_written();
}

// --- ls ---

#[test]
fn ls_lists_sorted_names_without_values() {
    let m = project();
    let run = ok(m.run(&["ls"], None));

    assert_eq!(
        run.stdout,
        "payments/dev (2 variables)\n  API_KEY\n  DATABASE_URL\n"
    );
    assert_no_secret(&run);
}

#[test]
fn ls_marks_run_only_and_reserved_names() {
    let m = project();
    ok(piped(
        &m,
        &["set", "TOKEN", "--inject", "run", "--stdin"],
        "t\n",
    ));
    ok(piped(&m, &["set", "PATH", "--stdin"], "/bin\n"));
    let run = ok(m.run(&["ls"], None));

    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(lines[0], "payments/dev (4 variables)");
    let line = |name: &str| {
        *lines
            .iter()
            .find(|line| line.trim_start().starts_with(name))
            .unwrap_or_else(|| panic!("{name} listed: {}", run.stdout))
    };
    assert!(line("TOKEN").ends_with("run only"), "{}", run.stdout);
    assert!(line("PATH").ends_with("reserved"), "{}", run.stdout);
    assert_eq!(line("API_KEY").trim(), "API_KEY");
    let order: Vec<&str> = lines[1..]
        .iter()
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(order, ["API_KEY", "DATABASE_URL", "PATH", "TOKEN"]);
}

#[test]
fn ls_of_an_empty_environment_points_at_set() {
    let m = Machine::new();
    let (setup, _) = m.setup();
    assert_eq!(setup.exit, Exit::Success, "{}", printed(&setup));
    ok(m.run(&["init", "--yes"], None));

    let run = ok(m.run(&["ls"], None));
    assert_eq!(
        run.stdout,
        "payments/dev (no variables)\nAdd one: smart-env set NAME\n"
    );
}

#[test]
fn ls_hides_removed_variables() {
    let m = project();
    ok(m.run(&["rm", "API_KEY"], None));
    let run = ok(m.run(&["ls"], None));

    assert!(!run.stdout.contains("API_KEY"), "{}", run.stdout);
    assert!(
        run.stdout.starts_with("payments/dev (1 variable)\n"),
        "{}",
        run.stdout
    );
}

#[test]
fn ls_rm_and_rename_work_with_a_locked_key() {
    let m = Machine::without_keychain();
    let (setup, _) = m.setup_with_passphrase("correct horse battery");
    assert_eq!(setup.exit, Exit::Success, "{}", printed(&setup));
    m.write(".env", "A=1\nB=2\n");
    ok(m.run(&["init", "--yes"], None));
    m.session.delete().unwrap();

    let ls = ok(m.run(&["ls"], None));
    assert!(ls.stdout.contains("A"), "{}", ls.stdout);
    ok(m.run(&["rename", "A", "C"], None));
    ok(m.run(&["rm", "B"], None));
    assert_eq!(names(&m, "dev"), ["C"]);
}

#[test]
fn ls_json_lists_metadata_without_values() {
    let m = project();
    ok(piped(
        &m,
        &["set", "PATH", "--inject", "run", "--stdin"],
        "/bin\n",
    ));
    let run = ok(m.run(&["ls", "--json"], None));

    let report = json(&run.stdout);
    assert_eq!(report["project"], "payments");
    assert_eq!(report["environment"], "dev");
    let variables = report["variables"].as_array().unwrap();
    let listed: Vec<&str> = variables
        .iter()
        .map(|v| v["name"].as_str().unwrap())
        .collect();
    assert_eq!(listed, ["API_KEY", "DATABASE_URL", "PATH"]);
    let path = &variables[2];
    assert_eq!(path["version"], 1);
    assert_eq!(path["inject"], "run");
    assert_eq!(path["reserved"], true);
    assert!(path["updated_at"].is_string());
    assert_eq!(variables[0]["inject"], "shell");
    assert_eq!(variables[0]["reserved"], false);
    for variable in variables {
        assert!(variable.get("value").is_none(), "{variable}");
    }
    assert_no_secret(&run);
}

// --- rm ---

#[test]
fn rm_soft_deletes_without_asking_and_points_at_undo() {
    let m = project();
    let mut terminal = typing("n");
    let run = ok(m.run(&["rm", "API_KEY"], Some(&mut terminal)));

    assert_eq!(names(&m, "dev"), ["DATABASE_URL"]);
    assert_eq!(terminal.questions + terminal.secret_questions, 0);
    assert!(
        run.stdout
            .contains("✓ Removed API_KEY from payments/dev (undo: smart-env undo API_KEY)"),
        "{}",
        run.stdout
    );

    // Soft delete: the library can still bring it back.
    let key = m.stored_key().unwrap();
    m.vault()
        .undo(env_id(&m, "dev"), &VarName::parse("API_KEY").unwrap(), &key)
        .unwrap();
    assert_eq!(value(&m, "dev", "API_KEY").as_deref(), Some("dev-hunter2"));
}

#[test]
fn rm_with_env_flag_repeats_it_in_the_undo_hint() {
    let m = project();
    let run = ok(m.run(&["rm", "API_KEY", "--env", "payments/prod"], None));

    assert!(
        run.stdout
            .contains("(undo: smart-env undo API_KEY --env payments/prod)"),
        "{}",
        run.stdout
    );
    assert_eq!(names(&m, "prod"), Vec::<String>::new());
    assert_eq!(names(&m, "dev"), ["API_KEY", "DATABASE_URL"]);
}

#[test]
fn rm_of_a_missing_variable_is_not_found() {
    let m = project();
    let before = revision(&m, "dev");
    for name in ["NOPE", "api_key"] {
        let run = m.run(&["rm", name, "--json"], None);

        assert_eq!(run.exit, Exit::NotFound, "{name}");
        assert_eq!(error_code(&run), "secret_not_found", "{name}");
    }
    assert_eq!(revision(&m, "dev"), before);
}

#[test]
fn rm_twice_is_not_found_the_second_time() {
    let m = project();
    ok(m.run(&["rm", "API_KEY"], None));
    let run = m.run(&["rm", "API_KEY", "--json"], None);
    assert_eq!(error_code(&run), "secret_not_found");
}

#[test]
fn rm_with_an_invalid_name_is_a_usage_error() {
    let m = project();
    let run = m.run(&["rm", "1BAD", "--json"], None);
    assert_eq!(run.exit, Exit::Usage);
    assert_eq!(error_code(&run), "invalid_name");
}

#[test]
fn rm_json_reports_the_removal() {
    let m = project();
    let run = ok(m.run(&["rm", "API_KEY", "--json"], None));

    let report = json(&run.stdout);
    assert_eq!(report["status"], "removed");
    assert_eq!(report["project"], "payments");
    assert_eq!(report["environment"], "dev");
    assert_eq!(report["name"], "API_KEY");
}

// --- rename ---

#[test]
fn rename_keeps_value_version_and_inject() {
    let m = project();
    ok(piped(
        &m,
        &["set", "API_KEY", "--inject", "run", "--stdin"],
        "v2-hunter2\n",
    ));
    let before = meta(&m, "dev", "API_KEY");
    let run = ok(m.run(&["rename", "API_KEY", "STRIPE_KEY"], None));

    assert_eq!(names(&m, "dev"), ["DATABASE_URL", "STRIPE_KEY"]);
    let after = meta(&m, "dev", "STRIPE_KEY");
    assert_eq!(after.key_id, before.key_id);
    assert_eq!(after.version, 2);
    assert_eq!(after.inject, Inject::Run);
    assert_eq!(
        value(&m, "dev", "STRIPE_KEY").as_deref(),
        Some("v2-hunter2")
    );
    assert!(
        run.stdout
            .contains("✓ Renamed API_KEY to STRIPE_KEY in payments/dev"),
        "{}",
        run.stdout
    );
    assert_no_secret(&run);
}

#[test]
fn rename_of_a_missing_variable_is_not_found() {
    let m = project();
    let run = m.run(&["rename", "NOPE", "OTHER", "--json"], None);
    assert_eq!(run.exit, Exit::NotFound);
    assert_eq!(error_code(&run), "secret_not_found");
}

#[test]
fn rename_onto_an_existing_name_is_a_conflict_and_changes_nothing() {
    let m = project();
    let before = revision(&m, "dev");
    let run = m.run(&["rename", "API_KEY", "DATABASE_URL", "--json"], None);

    assert_eq!(run.exit, Exit::Conflict);
    assert_eq!(error_code(&run), "secret_name_taken");
    assert_eq!(value(&m, "dev", "API_KEY").as_deref(), Some("dev-hunter2"));
    assert_eq!(
        value(&m, "dev", "DATABASE_URL").as_deref(),
        Some("postgres://u:hunter2@db")
    );
    assert_eq!(revision(&m, "dev"), before);
}

#[test]
fn rename_onto_a_removed_name_is_a_conflict_pointing_at_undo() {
    let m = project();
    ok(m.run(&["rm", "DATABASE_URL"], None));
    let run = m.run(&["rename", "API_KEY", "DATABASE_URL", "--json"], None);

    assert_eq!(run.exit, Exit::Conflict);
    assert_eq!(error_code(&run), "secret_name_taken");
    assert!(
        json(&run.stdout)["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("smart-env undo")
    );
}

#[test]
fn rename_with_an_invalid_name_is_a_usage_error() {
    let m = project();
    for args in [["rename", "API_KEY", "1BAD"], ["rename", "1BAD", "OTHER"]] {
        let mut argv = args.to_vec();
        argv.push("--json");
        let run = m.run(&argv, None);

        assert_eq!(run.exit, Exit::Usage, "{args:?}");
        assert_eq!(error_code(&run), "invalid_name", "{args:?}");
    }
    assert_eq!(names(&m, "dev"), ["API_KEY", "DATABASE_URL"]);
}

#[test]
fn rename_to_the_same_name_is_a_usage_error_and_changes_nothing() {
    let m = project();
    let before = revision(&m, "dev");
    let run = m.run(&["rename", "API_KEY", "API_KEY", "--json"], None);

    assert_eq!(run.exit, Exit::Usage);
    assert_eq!(error_code(&run), "same_name");
    assert_eq!(revision(&m, "dev"), before);
}

#[test]
fn rename_to_a_reserved_name_warns() {
    let m = project();
    let run = ok(m.run(&["rename", "API_KEY", "GIT_TOKEN"], None));

    assert!(
        run.stdout.contains(
            "! GIT_TOKEN is a reserved name: smart-env run and the shell hook skip it until allowed: smart-env allow --var GIT_TOKEN"
        ),
        "{}",
        run.stdout
    );
}

#[test]
fn rename_json_reports_both_names() {
    let m = project();
    let run = ok(m.run(&["rename", "API_KEY", "PATH", "--json"], None));

    let report = json(&run.stdout);
    assert_eq!(report["status"], "renamed");
    assert_eq!(report["project"], "payments");
    assert_eq!(report["environment"], "dev");
    assert_eq!(report["from"], "API_KEY");
    assert_eq!(report["to"], "PATH");
    assert_eq!(report["reserved"], true);
}

// --- no echo, anywhere ---

#[test]
fn values_never_reach_the_output_of_any_command() {
    let m = project();
    let mut runs = vec![
        piped(&m, &["set", "A", "--stdin"], "a-hunter2\n"),
        piped(&m, &["set", "A", "--stdin", "--json"], "b-hunter2\n"),
        piped(
            &m,
            &["set", "A", "--inject", "run", "--stdin"],
            "c-hunter2\n",
        ),
        m.run(&["ls"], None),
        m.run(&["ls", "--json"], None),
        m.run(&["rename", "A", "B"], None),
        m.run(&["rename", "B", "E", "--json"], None),
        m.run(&["rm", "E"], None),
        m.run(&["rm", "DATABASE_URL", "--json"], None),
    ];
    let mut terminal = typing("d-hunter2");
    runs.push(m.run(&["set", "C"], Some(&mut terminal)));
    assert!(
        !terminal.transcript.contains(SECRET),
        "{}",
        terminal.transcript
    );

    for run in &runs {
        assert_no_secret(run);
    }
}
