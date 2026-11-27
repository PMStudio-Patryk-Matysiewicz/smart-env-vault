//! `smart-env status`: what is active in this shell and why something is
//! not (step 3 item 8). The shell state comes from a real bash session.
mod common;

use std::path::Path;

use common::session::{PASSPHRASE, Projects, Session, checkout, ok, projects, projects_on, set};
use common::{Machine, ScriptedTerminal, error_code, json, printed};
use smart_env_cli::{Exit, Shell, execute};

struct Status {
    exit: Exit,
    stdout: String,
    stderr: String,
}

/// `smart-env status ARGS` in `dir`, run by the shell function with the
/// shell's `state` (`None`: no hook in this shell).
fn status(m: &Machine, dir: &Path, state: Option<String>, args: &[&str]) -> Status {
    let mut ctx = m.context(None);
    ctx.current_dir = Some(dir.to_path_buf());
    ctx.hook_state = state;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let argv = ["smart-env", "status"]
        .into_iter()
        .chain(args.iter().copied());
    let exit = execute(argv, &mut ctx, &mut out, &mut err);
    Status {
        exit,
        stdout: String::from_utf8(out).unwrap(),
        stderr: String::from_utf8(err).unwrap(),
    }
}

/// `status` in `dir` after the bash session `s` (empty state = hook
/// loaded, nothing active).
fn status_in(s: &Session<'_>, dir: &Path) -> String {
    let run = status(s.m, dir, Some(s.state().unwrap_or_default()), &[]);
    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    run.stdout
}

fn line<'a>(out: &'a str, label: &str) -> Option<&'a str> {
    out.lines().find(|line| line.starts_with(label))
}

fn bash_session(p: &Projects) -> Option<Session<'_>> {
    let found = std::process::Command::new("bash")
        .args(["-c", "exit 0"])
        .status()
        .is_ok_and(|status| status.success());
    found.then(|| Session::new(&p.m, Shell::Bash, &[]))
}

// --- Shell ---

#[test]
fn without_the_hook_status_says_how_to_load_it() {
    let p = projects();
    let run = status(&p.m, &p.payments, None, &[]);
    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    assert_eq!(
        line(&run.stdout, "Shell:"),
        Some("Shell:     hook not loaded in this shell (smart-env setup)")
    );
}

#[test]
fn shell_shows_an_automatic_activation() {
    let p = projects();
    let Some(mut s) = bash_session(&p) else {
        return;
    };
    s.prompt(&p.payments);

    let out = status_in(&s, &p.payments);

    assert_eq!(
        line(&out, "Shell:"),
        Some("Shell:     active payments/dev (2 variables, auto)"),
        "{out}"
    );
}

#[test]
fn shell_shows_a_manual_activation() {
    let p = projects();
    let Some(mut s) = bash_session(&p) else {
        return;
    };
    s.activate(&p.home, &["--env", "payments/staging"]);

    let out = status_in(&s, &p.home);

    assert_eq!(
        line(&out, "Shell:"),
        Some("Shell:     active payments/staging (1 variable, manual)"),
        "{out}"
    );
}

#[test]
fn shell_shows_nothing_active() {
    let p = projects();
    let Some(s) = bash_session(&p) else { return };
    let out = status_in(&s, &p.home);
    assert_eq!(line(&out, "Shell:"), Some("Shell:     not active"), "{out}");
}

#[test]
fn shell_shows_why_nothing_was_loaded() {
    let p = projects_on(Machine::without_keychain(), Some(PASSPHRASE));
    let Some(mut s) = bash_session(&p) else {
        return;
    };
    ok(&p.m, &["lock"]);
    s.prompt(&p.payments);

    let out = status_in(&s, &p.payments);

    assert_eq!(
        line(&out, "Shell:"),
        Some(
            "Shell:     not active: payments/dev not loaded, the key is locked (smart-env unlock)"
        ),
        "{out}"
    );
}

// --- Here ---

#[test]
fn here_shows_the_project_and_its_trust() {
    let p = projects();
    let clone = checkout(&p, &p.payments, "clone");
    let denied = checkout(&p, &p.payments, "denied");
    ok(&p.m, &["deny", denied.to_str().unwrap()]);
    let changed = checkout(&p, &p.payments, "changed");
    ok(&p.m, &["allow", changed.to_str().unwrap()]);
    let toml = changed.join("smart-env.toml");
    let content = std::fs::read_to_string(&toml).unwrap();
    std::fs::write(&toml, format!("{content}# edited\n")).unwrap();
    let canonical = |dir: &Path| std::fs::canonicalize(dir).unwrap().display().to_string();

    for (dir, expected) in [
        (&p.payments, "allowed"),
        (&clone, "not allowed (smart-env allow)"),
        (&denied, "denied (smart-env allow)"),
        (
            &changed,
            "smart-env.toml changed since allowed (smart-env allow)",
        ),
    ] {
        let run = status(&p.m, dir, Some(String::new()), &[]);
        assert_eq!(
            line(&run.stdout, "Here:"),
            Some(format!("Here:      payments/dev in {}, {expected}", canonical(dir)).as_str()),
            "{}",
            run.stdout
        );
    }
    let run = status(&p.m, &p.home, Some(String::new()), &[]);
    assert_eq!(
        line(&run.stdout, "Here:"),
        Some("Here:      no smart-env.toml")
    );
}

// --- names ---

#[test]
fn reserved_changed_and_run_only_names_are_listed() {
    let p = projects();
    set(&p.m, &["PATH", "--env", "payments/dev"], "/evil");
    set(
        &p.m,
        &["NODE_OPTIONS", "--env", "payments/dev"],
        "--inspect",
    );
    set(
        &p.m,
        &["GIT_SSH_COMMAND", "--env", "payments/dev"],
        "ssh -i key",
    );
    set(
        &p.m,
        &[
            "ANALYTICS_TOKEN",
            "--env",
            "payments/dev",
            "--inject",
            "run",
        ],
        "t",
    );
    let mut terminal = ScriptedTerminal::new(|_, _| "y".to_owned());
    let allowed = p.m.run(
        &["allow", "--var", "GIT_SSH_COMMAND", "--env", "payments/dev"],
        Some(&mut terminal),
    );
    assert_eq!(allowed.exit, Exit::Success, "{}", printed(&allowed));
    set(
        &p.m,
        &["GIT_SSH_COMMAND", "--env", "payments/dev"],
        "ssh -i other",
    );

    let run = status(&p.m, &p.payments, Some(String::new()), &[]);

    assert_eq!(
        line(&run.stdout, "Reserved:"),
        Some("Reserved:  NODE_OPTIONS, PATH not loaded (smart-env allow --var NAME)"),
        "{}",
        run.stdout
    );
    assert_eq!(
        line(&run.stdout, "Changed:"),
        Some(
            "Changed:   GIT_SSH_COMMAND changed since allowed (smart-env allow --var GIT_SSH_COMMAND)"
        )
    );
    assert_eq!(
        line(&run.stdout, "Run only:"),
        Some("Run only:  ANALYTICS_TOKEN")
    );
    for value in ["/evil", "--inspect", "ssh -i", "\"t\""] {
        assert!(
            !run.stdout.contains(value),
            "value {value:?}: {}",
            run.stdout
        );
    }
}

#[test]
fn one_reserved_name_points_at_its_allow() {
    let p = projects();
    set(&p.m, &["PATH", "--env", "payments/dev"], "/evil");
    let run = status(&p.m, &p.payments, Some(String::new()), &[]);
    assert_eq!(
        line(&run.stdout, "Reserved:"),
        Some("Reserved:  PATH not loaded (smart-env allow --var PATH)")
    );
}

#[test]
fn empty_lines_are_left_out() {
    let p = projects();
    let run = status(&p.m, &p.payments, Some(String::new()), &[]);
    for label in ["Reserved:", "Changed:", "Run only:"] {
        assert_eq!(line(&run.stdout, label), None, "{label}: {}", run.stdout);
    }
}

#[test]
fn names_come_from_the_active_environment_first() {
    let p = projects();
    set(
        &p.m,
        &["STG_ONLY", "--env", "payments/staging", "--inject", "run"],
        "x",
    );
    let Some(mut s) = bash_session(&p) else {
        return;
    };
    s.activate(&p.home, &["--env", "payments/staging"]);

    let out = status_in(&s, &p.payments);

    assert_eq!(
        line(&out, "Run only:"),
        Some("Run only:  STG_ONLY"),
        "{out}"
    );
}

// --- Key and Auto ---

#[test]
fn key_shows_unlocked_and_locked() {
    let p = projects_on(Machine::without_keychain(), Some(PASSPHRASE));
    let run = status(&p.m, &p.home, Some(String::new()), &[]);
    assert_eq!(line(&run.stdout, "Key:"), Some("Key:       unlocked"));

    ok(&p.m, &["lock"]);
    let run = status(&p.m, &p.home, Some(String::new()), &[]);
    assert_eq!(
        line(&run.stdout, "Key:"),
        Some("Key:       locked (smart-env unlock)")
    );
}

#[test]
fn auto_shows_the_setting() {
    let p = projects();
    let run = status(&p.m, &p.home, Some(String::new()), &[]);
    assert_eq!(line(&run.stdout, "Auto:"), Some("Auto:      on"));

    ok(&p.m, &["auto-activate", "off"]);
    let run = status(&p.m, &p.home, Some(String::new()), &[]);
    assert_eq!(
        line(&run.stdout, "Auto:"),
        Some("Auto:      off (smart-env auto-activate on)")
    );
}

// --- --json and errors ---

#[test]
fn json_status() {
    let p = projects();
    set(&p.m, &["PATH", "--env", "payments/dev"], "/evil");
    set(
        &p.m,
        &[
            "ANALYTICS_TOKEN",
            "--env",
            "payments/dev",
            "--inject",
            "run",
        ],
        "t",
    );
    let Some(mut s) = bash_session(&p) else {
        return;
    };
    s.prompt(&p.payments);

    let run = status(&p.m, &p.payments, s.state(), &["--json"]);

    assert_eq!(run.exit, Exit::Success, "{}", run.stderr);
    let report = json(&run.stdout);
    assert_eq!(report["shell"]["hook"], true);
    assert_eq!(report["shell"]["status"], "active");
    assert_eq!(report["shell"]["label"], "payments/dev");
    assert_eq!(report["shell"]["mode"], "auto");
    assert_eq!(report["shell"]["variables"], 2);
    assert_eq!(report["here"]["label"], "payments/dev");
    assert_eq!(report["here"]["trust"], "allowed");
    assert_eq!(report["reserved_skipped"], serde_json::json!(["PATH"]));
    assert_eq!(report["reserved_changed"], serde_json::json!([]));
    assert_eq!(report["run_only"], serde_json::json!(["ANALYTICS_TOKEN"]));
    assert_eq!(report["key"], "unlocked");
    assert_eq!(report["auto_activate"], true);

    let run = status(&p.m, &p.home, None, &["--json"]);
    let report = json(&run.stdout);
    assert_eq!(report["shell"]["hook"], false);
    assert!(report["here"].is_null());
}

#[test]
fn status_without_setup_is_not_set_up() {
    let m = Machine::new();
    let run = status(&m, &m.project, Some(String::new()), &["--json"]);
    assert_eq!(run.exit, Exit::NotFound);
    let run = common::Run {
        exit: run.exit,
        stdout: run.stdout,
        stderr: run.stderr,
    };
    assert_eq!(error_code(&run), "not_set_up");
}
