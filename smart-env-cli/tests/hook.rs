//! `smart-env hook <shell>`, the hidden `hook-env`, and installing the hook
//! in the shell's startup file during `setup` (ADR-005, step 3 item 1).
//!
//! Tests with a real shell are skipped (with a note on stderr) when that
//! shell is not installed; CI installs bash, zsh and fish.
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::{Machine, Run, ScriptedTerminal, json, last4, printed, shown_key};
use smart_env_cli::{Exit, Shell};

const ALL: [Shell; 3] = [Shell::Bash, Shell::Zsh, Shell::Fish];

// --- helpers ---

fn ok(run: Run) -> Run {
    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    run
}

/// The program for `shell`: `SMART_ENV_TEST_<SHELL>` if set (e.g.
/// `SMART_ENV_TEST_BASH=/bin/bash` for bash 3.2 on macOS), else from `PATH`.
fn program(shell: Shell) -> String {
    std::env::var(format!("SMART_ENV_TEST_{}", shell.name().to_uppercase()))
        .ok()
        .filter(|program| !program.is_empty())
        .unwrap_or_else(|| shell.name().to_owned())
}

/// Whether `shell` is installed; prints a note when it is not.
fn installed(shell: Shell) -> bool {
    let found = Command::new(program(shell))
        .args(["-c", "exit 0"])
        .output()
        .is_ok_and(|output| output.status.success());
    if !found {
        eprintln!("skipped: {} is not installed", shell.name());
    }
    found
}

/// Runs `script` in `shell` without any startup files.
fn run_shell(shell: Shell, script: &str) -> (String, String, Option<i32>) {
    let mut command = Command::new(program(shell));
    match shell {
        Shell::Bash => command.args(["--norc", "--noprofile", "-c", script]),
        Shell::Zsh => command.args(["-f", "-c", script]),
        Shell::Fish => command.args(["--no-config", "-c", script]),
    };
    let output = command.output().unwrap();
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

/// The hook script for `shell` from `smart-env hook`, saved next to the
/// project; returns its path.
fn hook_file(m: &Machine, shell: Shell) -> PathBuf {
    let run = ok(m.run(&["hook", shell.name()], None));
    let file = m.home.join(format!("hook.{}", shell.name()));
    std::fs::write(&file, run.stdout).unwrap();
    file
}

fn fake_dir(m: &Machine) -> &Path {
    m.executable.parent().unwrap()
}

/// What the fake `smart-env` printed to its `calls` log, one call per line.
fn calls(m: &Machine) -> Vec<String> {
    std::fs::read_to_string(fake_dir(m).join("calls"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Makes the fake `hook-env` print `output` (shell code to evaluate).
fn fake_output(m: &Machine, output: &str) {
    std::fs::write(fake_dir(m).join("output"), output).unwrap();
}

fn export_line(shell: Shell) -> &'static str {
    match shell {
        Shell::Bash | Shell::Zsh => "export SE_TEST='a b'\n",
        Shell::Fish => "set -gx SE_TEST 'a b'\n",
    }
}

fn source(shell: Shell, file: &Path) -> String {
    format!("source {}", shell.quote(file.to_str().unwrap()))
}

/// One prompt: what the shell does before showing it.
fn prompt(shell: Shell) -> &'static str {
    match shell {
        Shell::Bash => "eval \"$PROMPT_COMMAND\"",
        Shell::Zsh => "for f in $precmd_functions; do $f; done",
        Shell::Fish => "emit fish_prompt",
    }
}

/// A terminal for `setup`: confirms the recovery key and answers the hook
/// question with `hook_answer`.
fn terminal(hook_answer: &str) -> ScriptedTerminal {
    let hook_answer = hook_answer.to_owned();
    ScriptedTerminal::new(move |transcript, question| {
        if question.to_lowercase().contains("hook") {
            hook_answer.clone()
        } else {
            last4(&shown_key(transcript))
        }
    })
}

fn hook_questions(terminal: &ScriptedTerminal) -> usize {
    terminal.transcript.matches("? Add the shell hook").count()
}

fn with_shell(shell: &str) -> Machine {
    let mut m = Machine::new();
    m.shell = Some(shell.to_owned());
    m
}

fn bashrc(m: &Machine) -> PathBuf {
    m.home.join(".bashrc")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Lines that load the hook (comments excluded).
fn hook_lines(content: &str, shell: Shell) -> usize {
    content
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter(|line| line.contains(&format!("smart-env hook {}", shell.name())))
        .count()
}

/// First `setup` on a terminal answering the hook question with `answer`.
fn setup(m: &Machine, args: &[&str], answer: &str) -> (Run, ScriptedTerminal) {
    let mut terminal = terminal(answer);
    let mut argv = vec!["setup"];
    argv.extend_from_slice(args);
    let run = ok(m.run(&argv, Some(&mut terminal)));
    (run, terminal)
}

// --- smart-env hook ---

#[test]
fn hook_prints_a_script_calling_hook_env_by_absolute_path() {
    let m = Machine::new();
    for shell in ALL {
        let run = ok(m.run(&["hook", shell.name()], None));
        let exe = shell.quote(m.executable.to_str().unwrap());
        assert!(
            run.stdout.contains(&exe),
            "{}: {}",
            shell.name(),
            run.stdout
        );
        assert!(
            run.stdout.contains(&format!("hook-env {}", shell.name())),
            "{}",
            run.stdout
        );
        assert!(run.stdout.contains("_smart_env_hook"), "{}", run.stdout);
        assert!(run.stderr.is_empty(), "{}", run.stderr);
    }
}

#[test]
fn hook_without_a_known_executable_calls_smart_env_from_path() {
    let m = Machine::new();
    let mut ctx = m.context(None);
    ctx.executable = None;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let exit = smart_env_cli::execute(["smart-env", "hook", "bash"], &mut ctx, &mut out, &mut err);
    assert_eq!(exit, Exit::Success);
    let script = String::from_utf8(out).unwrap();
    assert!(script.contains("smart-env hook-env bash"), "{script}");
}

#[test]
fn hook_for_an_unsupported_shell_is_a_usage_error() {
    let m = Machine::new();
    for args in [&["hook", "tcsh"][..], &["hook"][..]] {
        let run = m.run(args, None);
        assert_eq!(run.exit, Exit::Usage, "{args:?}");
    }
}

// --- smart-env hook-env ---

#[test]
fn hook_env_is_silent_without_setup() {
    let m = Machine::new();
    for shell in ALL {
        let run = m.run(&["hook-env", shell.name()], None);
        assert_eq!(run.exit, Exit::Success);
        assert!(printed(&run).is_empty(), "{}", printed(&run));
    }
}

#[test]
fn hook_env_is_silent_outside_a_project() {
    let m = Machine::new();
    ok(m.setup().0);
    for shell in ALL {
        let run = m.run(&["hook-env", shell.name()], None);
        assert_eq!(run.exit, Exit::Success);
        assert!(printed(&run).is_empty(), "{}", printed(&run));
    }
}

#[test]
fn hook_env_is_hidden_from_help() {
    let m = Machine::new();
    let run = ok(m.run(&["--help"], None));
    assert!(run.stdout.contains("hook"), "{}", run.stdout);
    assert!(!run.stdout.contains("hook-env"), "{}", run.stdout);
}

// --- Shell ---

#[test]
fn shell_is_recognized_from_the_shell_variable() {
    for (path, shell) in [
        ("/bin/bash", Some(Shell::Bash)),
        ("/usr/local/bin/bash", Some(Shell::Bash)),
        ("bash", Some(Shell::Bash)),
        ("/usr/bin/zsh", Some(Shell::Zsh)),
        ("/opt/homebrew/bin/fish", Some(Shell::Fish)),
        ("/bin/sh", None),
        ("/bin/tcsh", None),
        ("/usr/bin/bashful", None),
        ("", None),
    ] {
        assert_eq!(Shell::from_path(path), shell, "{path:?}");
    }
}

const AWKWARD: [&str; 12] = [
    "plain",
    "a b",
    "it's",
    "\"double\"",
    "$(id)",
    "`id`",
    "$HOME",
    "back\\slash \\' \\\\",
    "new\nline",
    "zażółć 🔑",
    "*",
    "!x",
];

#[test]
fn quoted_text_is_taken_literally_by_the_shell() {
    for shell in ALL {
        if !installed(shell) {
            continue;
        }
        for text in AWKWARD {
            let (stdout, stderr, _) =
                run_shell(shell, &format!("printf '%s' {}", shell.quote(text)));
            assert_eq!(stdout, text, "{}: {stderr}", shell.name());
        }
    }
}

#[test]
fn quoting_is_a_single_word() {
    for shell in ALL {
        for text in AWKWARD {
            let quoted = shell.quote(text);
            assert!(quoted.starts_with('\''), "{}: {quoted}", shell.name());
            assert!(quoted.ends_with('\''), "{}: {quoted}", shell.name());
        }
    }
}

// --- the script in real shells ---

#[test]
fn hook_script_has_valid_syntax() {
    let m = Machine::new();
    for shell in ALL {
        if !installed(shell) {
            continue;
        }
        let file = hook_file(&m, shell);
        let status = Command::new(program(shell))
            .arg("-n")
            .arg(&file)
            .status()
            .unwrap();
        assert!(status.success(), "{}", shell.name());
    }
}

#[test]
fn every_prompt_runs_hook_env_once_and_evaluates_its_output() {
    for shell in ALL {
        if !installed(shell) {
            continue;
        }
        let m = Machine::new();
        let file = hook_file(&m, shell);
        fake_output(&m, export_line(shell));
        let script = format!(
            "{source}\n{source}\n{prompt}\necho \"SE_TEST=$SE_TEST\"",
            source = source(shell, &file),
            prompt = prompt(shell),
        );

        let (stdout, stderr, code) = run_shell(shell, &script);

        assert_eq!(code, Some(0), "{}: {stderr}", shell.name());
        assert!(
            stdout.contains("SE_TEST=a b"),
            "{}: {stdout}{stderr}",
            shell.name()
        );
        assert_eq!(
            calls(&m),
            [format!("hook-env {}", shell.name())],
            "{}",
            shell.name()
        );
    }
}

#[test]
fn loading_the_script_does_not_run_or_export_anything() {
    for shell in ALL {
        if !installed(shell) {
            continue;
        }
        let m = Machine::new();
        let file = hook_file(&m, shell);
        let script = format!("{}\nenv", source(shell, &file));
        let (stdout, stderr, code) = run_shell(shell, &script);
        assert_eq!(code, Some(0), "{}: {stderr}", shell.name());
        assert!(calls(&m).is_empty(), "{}: {:?}", shell.name(), calls(&m));
        assert!(!stdout.contains("smart_env"), "{}: {stdout}", shell.name());
    }
}

#[test]
fn the_hook_passes_its_state_to_hook_env_without_exporting_it() {
    for shell in ALL {
        if !installed(shell) {
            continue;
        }
        let m = Machine::new();
        let file = hook_file(&m, shell);
        fake_output(
            &m,
            match shell {
                Shell::Fish => "set -g _smart_env_state 'state one'\n",
                _ => "_smart_env_state='state one'\n",
            },
        );
        let script = format!(
            "{source}\n{prompt}\n{prompt}\nprintenv _smart_env_state; echo \"exported={status}\"",
            source = source(shell, &file),
            prompt = prompt(shell),
            status = if shell == Shell::Fish {
                "$status"
            } else {
                "$?"
            },
        );

        let (stdout, stderr, _) = run_shell(shell, &script);

        let states = std::fs::read_to_string(fake_dir(&m).join("states")).unwrap_or_default();
        assert_eq!(states, "\nstate one\n", "{}: {stderr}", shell.name());
        assert!(stdout.contains("exported=1"), "{}: {stdout}", shell.name());
    }
}

#[test]
fn the_smart_env_function_runs_activate_in_this_shell_and_keeps_the_exit_code() {
    for shell in ALL {
        if !installed(shell) {
            continue;
        }
        let m = Machine::new();
        let file = hook_file(&m, shell);
        fake_output(&m, export_line(shell));
        std::fs::write(fake_dir(&m).join("exit"), "3").unwrap();
        let status = if shell == Shell::Fish {
            "$status"
        } else {
            "$?"
        };
        let script = format!(
            "{source}\nsmart-env activate --env 'pay ments/dev'\necho \"rc=${status_var}\"\necho \"SE_TEST=$SE_TEST\"",
            source = source(shell, &file),
            status_var = &status[1..],
        );

        let (stdout, stderr, _) = run_shell(shell, &script);

        assert_eq!(
            calls(&m),
            [format!(
                "hook-env {} --activate --env pay ments/dev",
                shell.name()
            )],
            "{}: {stderr}",
            shell.name()
        );
        assert!(
            stdout.contains("rc=3"),
            "{}: {stdout}{stderr}",
            shell.name()
        );
        assert!(stdout.contains("SE_TEST=a b"), "{}: {stdout}", shell.name());
    }
}

#[test]
fn the_smart_env_function_runs_deactivate_in_this_shell() {
    for shell in ALL {
        if !installed(shell) {
            continue;
        }
        let m = Machine::new();
        let file = hook_file(&m, shell);
        fake_output(&m, export_line(shell));
        let script = format!(
            "{}\nsmart-env deactivate\necho \"SE_TEST=$SE_TEST\"",
            source(shell, &file)
        );

        let (stdout, stderr, _) = run_shell(shell, &script);

        assert_eq!(
            calls(&m),
            [format!("hook-env {} --deactivate", shell.name())],
            "{}: {stderr}",
            shell.name()
        );
        assert!(stdout.contains("SE_TEST=a b"), "{}: {stdout}", shell.name());
    }
}

#[test]
fn other_commands_go_to_the_binary_with_the_hook_state() {
    for shell in ALL {
        if !installed(shell) {
            continue;
        }
        let m = Machine::new();
        let file = hook_file(&m, shell);
        fake_output(&m, "plain output\n");
        std::fs::write(fake_dir(&m).join("exit"), "4").unwrap();
        let set_state = match shell {
            Shell::Fish => "set -g _smart_env_state 'state two'",
            _ => "_smart_env_state='state two'",
        };
        let status = if shell == Shell::Fish { "status" } else { "?" };
        let script = format!(
            "{}\n{set_state}\nsmart-env status --json 'a b'\necho \"rc=${status}\"",
            source(shell, &file)
        );

        let (stdout, stderr, _) = run_shell(shell, &script);

        assert_eq!(
            calls(&m),
            ["status --json a b"],
            "{}: {stderr}",
            shell.name()
        );
        let states = std::fs::read_to_string(fake_dir(&m).join("states")).unwrap();
        assert_eq!(states, "state two\n", "{}", shell.name());
        assert!(
            stdout.contains("plain output"),
            "{}: {stdout}",
            shell.name()
        );
        assert!(stdout.contains("rc=4"), "{}: {stdout}", shell.name());
    }
}

#[test]
fn bash_hook_keeps_the_existing_prompt_command_and_exit_status() {
    let shell = Shell::Bash;
    if !installed(shell) {
        return;
    }
    let m = Machine::new();
    let file = hook_file(&m, shell);
    let script = format!(
        "PROMPT_COMMAND='echo user-prompt'\n{source}\n{source}\n\
         echo \"pc=$PROMPT_COMMAND\"\neval \"$PROMPT_COMMAND\"\n\
         false; _smart_env_hook; echo \"status=$?\"",
        source = source(shell, &file),
    );

    let (stdout, stderr, _) = run_shell(shell, &script);

    assert!(stdout.contains("user-prompt"), "{stdout}{stderr}");
    let pc = stdout.lines().find(|l| l.starts_with("pc=")).unwrap();
    assert_eq!(pc.matches("_smart_env_hook").count(), 1, "{pc}");
    assert!(pc.contains("echo user-prompt"), "{pc}");
    assert!(stdout.contains("status=1"), "{stdout}");
}

#[test]
fn zsh_hook_registers_once_in_precmd_and_chpwd_and_keeps_exit_status() {
    let shell = Shell::Zsh;
    if !installed(shell) {
        return;
    }
    let m = Machine::new();
    let file = hook_file(&m, shell);
    let script = format!(
        "user_precmd() {{ echo user-prompt }}\nprecmd_functions=(user_precmd)\n\
         {source}\n{source}\n\
         print -r -- \"precmd=${{(j:,:)precmd_functions}}\"\n\
         print -r -- \"chpwd=${{(j:,:)chpwd_functions}}\"\n\
         {prompt}\nfalse; _smart_env_hook; echo \"status=$?\"",
        source = source(shell, &file),
        prompt = prompt(shell),
    );

    let (stdout, stderr, _) = run_shell(shell, &script);

    let line = |prefix: &str| {
        stdout
            .lines()
            .find(|l| l.starts_with(prefix))
            .unwrap_or_else(|| panic!("{prefix}: {stdout}{stderr}"))
            .to_owned()
    };
    assert_eq!(line("precmd=").matches("_smart_env_hook").count(), 1);
    assert!(line("precmd=").contains("user_precmd"));
    assert_eq!(line("chpwd=").matches("_smart_env_hook").count(), 1);
    assert!(stdout.contains("user-prompt"), "{stdout}");
    assert!(stdout.contains("status=1"), "{stdout}");
}

#[test]
fn fish_hook_runs_on_prompt_and_on_directory_change() {
    let shell = Shell::Fish;
    if !installed(shell) {
        return;
    }
    let m = Machine::new();
    let file = hook_file(&m, shell);
    let script = format!(
        "{source}\n{source}\nemit fish_prompt\ncd /\n",
        source = source(shell, &file)
    );

    let (_, stderr, code) = run_shell(shell, &script);

    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(calls(&m), ["hook-env fish", "hook-env fish"]);
}

#[test]
fn binary_hook_script_works_in_bash_and_is_silent_without_setup() {
    if !installed(Shell::Bash) {
        return;
    }
    let home = tempfile::TempDir::new().unwrap();
    let exe = env!("CARGO_BIN_EXE_smart-env");
    let script = format!(
        "eval \"$({} hook bash)\"\ntype _smart_env_hook >/dev/null && echo defined\n\
         false; _smart_env_hook; echo \"status=$?\"",
        Shell::Bash.quote(exe)
    );
    let output = Command::new(program(Shell::Bash))
        .args(["--norc", "--noprofile", "-c", &script])
        .current_dir(home.path())
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", home.path().join("data"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stdout, "defined\nstatus=1\n", "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
}

// --- setup: confirmation ---

#[test]
fn setup_adds_the_hook_to_bashrc_after_yes() {
    let m = with_shell("/bin/bash");

    let (run, terminal) = setup(&m, &[], "y");

    assert_eq!(hook_questions(&terminal), 1, "{}", terminal.transcript);
    assert!(
        terminal.transcript.contains("~/.bashrc"),
        "{}",
        terminal.transcript
    );
    let content = read(&bashrc(&m));
    assert_eq!(hook_lines(&content, Shell::Bash), 1, "{content}");
    assert!(
        content.contains(
            "if [ -n \"$BASH_VERSION\" ] && command -v smart-env >/dev/null 2>&1; then eval \"$(smart-env hook bash)\"; fi"
        ),
        "{content}"
    );
    assert!(content.contains("# smart-env"), "{content}");
    assert!(
        run.stdout.contains("✓ Shell hook added to ~/.bashrc"),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("source ~/.bashrc"), "{}", run.stdout);
}

#[test]
fn empty_answer_means_yes() {
    let m = with_shell("/bin/bash");
    setup(&m, &[], "");
    assert_eq!(hook_lines(&read(&bashrc(&m)), Shell::Bash), 1);
}

#[test]
fn no_leaves_the_startup_file_alone_and_shows_the_line() {
    let m = with_shell("/bin/bash");

    let (run, _) = setup(&m, &[], "n");

    assert!(!bashrc(&m).exists());
    assert!(
        run.stdout.contains("Shell hook not added"),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("eval \"$(smart-env hook bash)\""),
        "{}",
        run.stdout
    );
    assert!(m.vault_db().exists(), "the vault stays");
}

#[test]
fn yes_flag_adds_the_hook_without_asking() {
    let m = with_shell("/bin/bash");

    let (_, terminal) = setup(&m, &["--yes"], "n");

    assert_eq!(hook_questions(&terminal), 0, "{}", terminal.transcript);
    assert_eq!(hook_lines(&read(&bashrc(&m)), Shell::Bash), 1);
}

#[test]
fn hook_lines_come_before_the_next_step() {
    let m = with_shell("/bin/bash");
    let (run, _) = setup(&m, &[], "y");
    let lines: Vec<&str> = run.stdout.lines().collect();
    let hook = lines
        .iter()
        .position(|l| l.contains("Shell hook added"))
        .unwrap();
    let vault = lines
        .iter()
        .position(|l| l.contains("Vault created"))
        .unwrap();
    assert!(vault < hook, "{lines:?}");
    assert!(
        lines.last().unwrap().contains("smart-env init"),
        "{lines:?}"
    );
}

// --- setup again: existing machines ---

#[test]
fn second_setup_without_terminal_and_yes_skips_the_hook_with_a_hint() {
    let mut m = Machine::new();
    ok(m.setup().0);
    m.shell = Some("/bin/bash".to_owned());

    let run = ok(m.run(&["setup"], None));

    assert!(!bashrc(&m).exists());
    assert!(run.stdout.contains("already set up"), "{}", run.stdout);
    assert!(
        run.stdout.contains("smart-env setup --yes"),
        "{}",
        run.stdout
    );
}

#[test]
fn second_setup_with_yes_adds_the_hook_to_an_existing_machine() {
    let mut m = Machine::new();
    ok(m.setup().0);
    m.shell = Some("/bin/bash".to_owned());

    let run = ok(m.run(&["setup", "--yes"], None));

    assert_eq!(hook_lines(&read(&bashrc(&m)), Shell::Bash), 1);
    assert!(run.stdout.contains("Shell hook added"), "{}", run.stdout);
}

#[test]
fn second_setup_asks_about_the_hook_on_a_terminal() {
    let mut m = Machine::new();
    ok(m.setup().0);
    m.shell = Some("/usr/bin/zsh".to_owned());
    let mut terminal = terminal("y");

    ok(m.run(&["setup"], Some(&mut terminal)));

    assert_eq!(hook_questions(&terminal), 1, "{}", terminal.transcript);
    assert_eq!(hook_lines(&read(&m.home.join(".zshrc")), Shell::Zsh), 1);
}

// --- setup: idempotence ---

#[test]
fn hook_is_added_once() {
    let m = with_shell("/bin/bash");
    setup(&m, &[], "y");
    let mut terminal = terminal("y");

    let run = ok(m.run(&["setup"], Some(&mut terminal)));

    assert_eq!(hook_questions(&terminal), 0, "{}", terminal.transcript);
    assert_eq!(hook_lines(&read(&bashrc(&m)), Shell::Bash), 1);
    assert!(
        run.stdout.contains("✓ Shell hook already in ~/.bashrc"),
        "{}",
        run.stdout
    );
}

#[test]
fn a_line_added_by_hand_counts_as_installed() {
    let m = with_shell("/bin/bash");
    let manual = "export EDITOR=vim\neval \"$(smart-env hook bash)\"\n";
    std::fs::write(bashrc(&m), manual).unwrap();

    let (run, terminal) = setup(&m, &[], "y");

    assert_eq!(hook_questions(&terminal), 0);
    assert_eq!(read(&bashrc(&m)), manual);
    assert!(run.stdout.contains("already in"), "{}", run.stdout);
}

#[test]
fn a_commented_out_line_does_not_count() {
    let m = with_shell("/bin/bash");
    std::fs::write(bashrc(&m), "# eval \"$(smart-env hook bash)\"\n").unwrap();

    setup(&m, &[], "y");

    let content = read(&bashrc(&m));
    assert!(
        content.starts_with("# eval \"$(smart-env hook bash)\"\n"),
        "{content}"
    );
    assert_eq!(hook_lines(&content, Shell::Bash), 1, "{content}");
}

#[test]
fn existing_content_is_kept_and_the_block_starts_on_a_new_line() {
    let m = with_shell("/bin/bash");
    std::fs::write(bashrc(&m), "alias ll='ls -l'").unwrap();

    setup(&m, &[], "y");

    let content = read(&bashrc(&m));
    assert!(content.starts_with("alias ll='ls -l'\n"), "{content:?}");
    assert!(
        content
            .lines()
            .any(|l| l.starts_with("if [ -n \"$BASH_VERSION\" ] && command -v smart-env")),
        "{content:?}"
    );
    assert!(content.ends_with('\n'), "{content:?}");
}

#[test]
fn a_symlinked_startup_file_stays_a_symlink() {
    let m = with_shell("/bin/bash");
    let dotfiles = m.home.join("dotfiles");
    std::fs::create_dir(&dotfiles).unwrap();
    std::fs::write(dotfiles.join("bashrc"), "export A=1\n").unwrap();
    std::os::unix::fs::symlink(dotfiles.join("bashrc"), bashrc(&m)).unwrap();

    setup(&m, &[], "y");

    assert!(
        std::fs::symlink_metadata(bashrc(&m))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let content = read(&dotfiles.join("bashrc"));
    assert!(content.starts_with("export A=1\n"), "{content}");
    assert_eq!(hook_lines(&content, Shell::Bash), 1, "{content}");
}

// --- setup: zsh and fish ---

#[test]
fn zsh_hook_goes_to_zdotdir_when_set() {
    let mut m = with_shell("/usr/bin/zsh");
    let zdotdir = m.home.join(".config/zsh");
    std::fs::create_dir_all(&zdotdir).unwrap();
    m.zdotdir = Some(zdotdir.clone());

    setup(&m, &["--yes"], "y");

    let content = read(&zdotdir.join(".zshrc"));
    assert!(
        content.contains(
            "if command -v smart-env >/dev/null 2>&1; then eval \"$(smart-env hook zsh)\"; fi"
        ),
        "{content}"
    );
    assert!(!m.home.join(".zshrc").exists());
}

#[test]
fn zsh_hook_goes_to_zshrc_in_home_without_zdotdir() {
    let m = with_shell("/usr/bin/zsh");
    setup(&m, &["--yes"], "y");
    assert_eq!(hook_lines(&read(&m.home.join(".zshrc")), Shell::Zsh), 1);
    assert!(!bashrc(&m).exists());
}

#[test]
fn fish_hook_gets_its_own_file_in_conf_d() {
    let m = with_shell("/usr/bin/fish");

    let (run, _) = setup(&m, &["--yes"], "y");

    let file = m.home.join(".config/fish/conf.d/smart-env.fish");
    let content = read(&file);
    assert!(
        content.contains("smart-env hook fish | source"),
        "{content}"
    );
    assert!(content.contains("status is-interactive"), "{content}");
    assert!(content.contains("command -q smart-env"), "{content}");
    assert!(
        run.stdout.contains("~/.config/fish/conf.d/smart-env.fish"),
        "{}",
        run.stdout
    );
}

#[test]
fn fish_hook_follows_xdg_config_home() {
    let mut m = with_shell("/usr/bin/fish");
    let config = m.home.join("cfg");
    m.xdg_config_home = Some(config.clone());

    setup(&m, &["--yes"], "y");

    assert_eq!(
        hook_lines(
            &read(&config.join("fish/conf.d/smart-env.fish")),
            Shell::Fish
        ),
        1
    );
}

#[test]
fn fish_hook_already_in_config_fish_is_not_added_again() {
    let m = with_shell("/usr/bin/fish");
    let config = m.home.join(".config/fish");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("config.fish"), "smart-env hook fish | source\n").unwrap();

    let (run, _) = setup(&m, &["--yes"], "y");

    assert!(!config.join("conf.d/smart-env.fish").exists());
    assert!(run.stdout.contains("already in"), "{}", run.stdout);
}

#[test]
fn fish_hook_file_is_valid_fish() {
    if !installed(Shell::Fish) {
        return;
    }
    let m = with_shell("/usr/bin/fish");
    setup(&m, &["--yes"], "y");
    let status = Command::new("fish")
        .arg("-n")
        .arg(m.home.join(".config/fish/conf.d/smart-env.fish"))
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn bash_and_zsh_hook_lines_are_valid_and_quiet_without_smart_env_in_path() {
    for (shell, path) in [(Shell::Bash, "/bin/bash"), (Shell::Zsh, "/usr/bin/zsh")] {
        if !installed(shell) {
            continue;
        }
        let m = with_shell(path);
        setup(&m, &["--yes"], "y");
        let file = match shell {
            Shell::Bash => bashrc(&m),
            _ => m.home.join(".zshrc"),
        };
        let script = format!(
            "PATH=/nonexistent\n{}\necho \"done $?\"",
            source(shell, &file)
        );
        let (stdout, stderr, _) = run_shell(shell, &script);
        assert_eq!(stdout, "done 0\n", "{}: {stderr}", shell.name());
        assert!(stderr.is_empty(), "{}: {stderr}", shell.name());
    }
}

// --- setup: bash on macOS ---

/// bash on macOS: Terminal.app and iTerm start login shells, which read
/// the first of ~/.bash_profile, ~/.bash_login, ~/.profile, never ~/.bashrc.
fn mac_bash() -> Machine {
    let mut m = with_shell("/bin/bash");
    m.macos = true;
    m
}

#[test]
fn macos_bash_hook_goes_to_a_new_bash_profile() {
    let m = mac_bash();

    let (run, terminal) = setup(&m, &[], "y");

    assert!(
        terminal.transcript.contains("~/.bash_profile"),
        "{}",
        terminal.transcript
    );
    assert_eq!(
        hook_lines(&read(&m.home.join(".bash_profile")), Shell::Bash),
        1
    );
    assert!(!bashrc(&m).exists());
    assert!(
        run.stdout.contains("✓ Shell hook added to ~/.bash_profile"),
        "{}",
        run.stdout
    );
}

#[test]
fn macos_bash_hook_goes_to_the_login_file_bash_reads() {
    // Creating ~/.bash_profile would hide ~/.bash_login and ~/.profile.
    for (existing, expected) in [
        (&[".bash_profile", ".profile"][..], ".bash_profile"),
        (&[".bash_login", ".profile"][..], ".bash_login"),
        (&[".profile"][..], ".profile"),
    ] {
        let m = mac_bash();
        for file in existing {
            std::fs::write(m.home.join(file), "export A=1\n").unwrap();
        }

        setup(&m, &["--yes"], "y");

        for file in existing {
            let content = read(&m.home.join(file));
            let want = usize::from(*file == expected);
            assert_eq!(
                hook_lines(&content, Shell::Bash),
                want,
                "{existing:?} {file}"
            );
            assert!(content.starts_with("export A=1\n"), "{content}");
        }
        assert_eq!(
            m.home.join(".bash_profile").exists(),
            existing.contains(&".bash_profile"),
            "{existing:?}"
        );
    }
}

#[test]
fn bash_hook_line_runs_only_in_bash() {
    // ~/.profile is also read by sh.
    let m = mac_bash();
    std::fs::write(m.home.join(".profile"), "").unwrap();
    setup(&m, &["--yes"], "y");
    let content = read(&m.home.join(".profile"));
    assert!(
        content.contains("if [ -n \"$BASH_VERSION\" ] && command -v smart-env"),
        "{content}"
    );
}

#[test]
fn sh_reading_the_profile_skips_the_hook_quietly() {
    // dash is a plain sh; on many systems /bin/sh is bash in disguise.
    let available = Command::new("dash")
        .args(["-c", "exit 0"])
        .status()
        .is_ok_and(|status| status.success());
    if !available {
        eprintln!("skipped: dash is not installed");
        return;
    }
    let m = mac_bash();
    std::fs::write(m.home.join(".profile"), "export A=1\n").unwrap();
    setup(&m, &["--yes"], "y");
    let script = format!(
        "PATH={}:$PATH\n. {}\necho \"done $?\"",
        Shell::Bash.quote(fake_dir(&m).to_str().unwrap()),
        Shell::Bash.quote(m.home.join(".profile").to_str().unwrap()),
    );

    let output = Command::new("dash").args(["-c", &script]).output().unwrap();

    assert_eq!(String::from_utf8_lossy(&output.stdout), "done 0\n");
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(calls(&m).is_empty(), "{:?}", calls(&m));
}

#[test]
fn macos_bash_hook_already_in_the_login_file_is_present() {
    let m = mac_bash();
    std::fs::write(
        m.home.join(".bash_profile"),
        "eval \"$(smart-env hook bash)\"\n",
    )
    .unwrap();

    let (run, terminal) = setup(&m, &[], "y");

    assert_eq!(hook_questions(&terminal), 0);
    assert!(
        run.stdout.contains("already in ~/.bash_profile"),
        "{}",
        run.stdout
    );
}

#[test]
fn linux_bash_ignores_login_files() {
    let m = with_shell("/bin/bash");
    std::fs::write(m.home.join(".bash_profile"), "").unwrap();
    setup(&m, &["--yes"], "y");
    assert_eq!(hook_lines(&read(&bashrc(&m)), Shell::Bash), 1);
    assert_eq!(read(&m.home.join(".bash_profile")), "");
}

#[test]
fn macos_zsh_and_fish_use_the_same_files_as_linux() {
    let mut m = with_shell("/bin/zsh");
    m.macos = true;
    setup(&m, &["--yes"], "y");
    assert_eq!(hook_lines(&read(&m.home.join(".zshrc")), Shell::Zsh), 1);

    let mut m = with_shell("/opt/homebrew/bin/fish");
    m.macos = true;
    setup(&m, &["--yes"], "y");
    assert!(m.home.join(".config/fish/conf.d/smart-env.fish").exists());
}

// --- setup: no hook possible ---

#[test]
fn unknown_or_missing_shell_installs_nothing_and_points_at_run() {
    for shell in [Some("/bin/tcsh"), Some("/bin/sh"), None] {
        let mut m = Machine::new();
        m.shell = shell.map(str::to_owned);

        let (run, terminal) = setup(&m, &[], "y");

        assert_eq!(hook_questions(&terminal), 0, "{shell:?}");
        assert!(
            run.stdout.contains("! Shell not recognized"),
            "{shell:?}: {}",
            run.stdout
        );
        assert!(run.stdout.contains("smart-env run --"), "{}", run.stdout);
        assert_eq!(
            std::fs::read_dir(&m.home).unwrap().count(),
            0,
            "{shell:?}: nothing written in the home directory"
        );
    }
}

#[test]
fn smart_env_missing_from_path_is_a_warning() {
    let mut m = with_shell("/bin/bash");
    m.path = Some("/nonexistent:/also-missing".into());

    let (run, _) = setup(&m, &["--yes"], "y");

    assert_eq!(hook_lines(&read(&bashrc(&m)), Shell::Bash), 1);
    assert!(
        run.stdout
            .contains("! smart-env is not in PATH, so the hook line does nothing until it is."),
        "{}",
        run.stdout
    );
}

#[test]
fn smart_env_in_path_gives_no_warning() {
    let m = with_shell("/bin/bash");
    let (run, _) = setup(&m, &["--yes"], "y");
    assert!(!run.stdout.contains("not in PATH"), "{}", run.stdout);
}

#[test]
fn unwritable_startup_file_is_a_warning_not_a_failed_setup() {
    use std::os::unix::fs::PermissionsExt;
    let m = with_shell("/bin/bash");
    std::fs::set_permissions(&m.home, std::fs::Permissions::from_mode(0o500)).unwrap();

    let mut terminal = terminal("y");
    let run = m.run(&["setup"], Some(&mut terminal));
    std::fs::set_permissions(&m.home, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    assert!(m.vault_db().exists());
    assert!(
        run.stdout.contains("! Could not write ~/.bashrc"),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("eval \"$(smart-env hook bash)\""),
        "{}",
        run.stdout
    );
}

// --- setup: --json ---

#[test]
fn json_reports_the_hook() {
    let m = with_shell("/bin/bash");
    let (run, _) = setup(&m, &["--json"], "y");
    let report = json(&run.stdout);
    assert_eq!(report["status"], "created");
    assert_eq!(report["hook"]["shell"], "bash");
    assert_eq!(report["hook"]["status"], "added");
    assert_eq!(report["hook"]["file"], bashrc(&m).display().to_string());

    let again = ok(m.run(&["setup", "--json"], None));
    let report = json(&again.stdout);
    assert_eq!(report["status"], "already_configured");
    assert_eq!(report["hook"]["status"], "present");
}

#[test]
fn json_reports_declined_skipped_and_unknown_shell() {
    let m = with_shell("/bin/bash");
    let (run, _) = setup(&m, &["--json"], "n");
    assert_eq!(json(&run.stdout)["hook"]["status"], "declined");

    let run = ok(m.run(&["setup", "--json"], None));
    assert_eq!(json(&run.stdout)["hook"]["status"], "skipped");

    let m = Machine::new();
    let (run, _) = setup(&m, &["--json"], "y");
    let hook = &json(&run.stdout)["hook"];
    assert_eq!(hook["status"], "unknown_shell");
    assert!(hook["shell"].is_null());
    assert!(hook["file"].is_null());
}
