//! `smart-env activate` / `deactivate` through the shell function, and
//! `smart-env auto-activate on|off` (ADR-005, step 3 item 6).
mod common;

use common::session::{PASSPHRASE, Session, checkout, each_shell, ok, projects, projects_on, set};
use common::{Machine, error_code, json, printed};
use smart_env_cli::Exit;

// --- activate ---

#[test]
fn activate_loads_a_project_that_is_not_allowed() {
    each_shell(|shell| {
        let p = projects();
        let clone = checkout(&p, &p.payments, "clone");
        let mut s = Session::new(&p.m, shell, &[]);
        s.prompt(&clone);
        assert_eq!(s.var("API_KEY"), None);

        let prompt = s.activate(&clone, &[]);

        assert_eq!(prompt.exit, Exit::Success, "{}", prompt.stderr);
        assert_eq!(
            prompt.stderr,
            "smart-env: active payments/dev (2 variables)\n",
            "{}",
            shell.name()
        );
        assert_eq!(
            s.var("API_KEY").as_deref(),
            Some("pay-1"),
            "{}",
            shell.name()
        );
        s.quiet(&clone);
    });
}

#[test]
fn activate_works_after_deny_in_this_shell_only() {
    each_shell(|shell| {
        let p = projects();
        let clone = checkout(&p, &p.payments, "denied");
        ok(&p.m, &["deny", clone.to_str().unwrap()]);
        let mut s = Session::new(&p.m, shell, &[]);

        let prompt = s.activate(&clone, &[]);

        assert_eq!(prompt.exit, Exit::Success, "{}", prompt.stderr);
        assert_eq!(
            s.var("API_KEY").as_deref(),
            Some("pay-1"),
            "{}",
            shell.name()
        );
        let mut other = Session::new(&p.m, shell, &[]);
        other.quiet(&clone);
        assert_eq!(other.var("API_KEY"), None, "the deny stays");
    });
}

#[test]
fn activate_another_environment_or_project_by_name() {
    each_shell(|shell| {
        let p = projects();
        let mut s = Session::new(&p.m, shell, &[]);
        s.prompt(&p.payments);

        let prompt = s.activate(&p.payments, &["--env", "staging"]);
        assert_eq!(
            prompt.stderr,
            "smart-env: active payments/staging (1 variable)\n",
            "{}",
            shell.name()
        );
        assert_eq!(s.var("API_KEY").as_deref(), Some("pay-stg"));
        assert_eq!(s.var("DATABASE_URL"), None, "dev is gone");

        let prompt = s.activate(&p.home, &["--env", "billing/dev"]);
        assert_eq!(
            prompt.stderr,
            "smart-env: active billing/dev (2 variables)\n"
        );
        assert_eq!(s.var("BILLING_TOKEN").as_deref(), Some("tok-1"));
    });
}

#[test]
fn a_manual_activation_stays_until_deactivate() {
    each_shell(|shell| {
        let p = projects();
        let mut s = Session::new(&p.m, shell, &[]);
        s.activate(&p.payments, &["--env", "staging"]);

        s.quiet(&p.home);
        s.quiet(&p.billing);
        s.quiet(&p.payments);

        assert_eq!(
            s.var("API_KEY").as_deref(),
            Some("pay-stg"),
            "{}",
            shell.name()
        );
        assert_eq!(
            s.var("BILLING_TOKEN"),
            None,
            "billing was not auto-activated"
        );
    });
}

#[test]
fn a_manual_activation_follows_changes_from_another_tab() {
    each_shell(|shell| {
        let p = projects();
        let mut s = Session::new(&p.m, shell, &[]);
        s.activate(&p.home, &["--env", "payments/staging"]);
        set(&p.m, &["API_KEY", "--env", "payments/staging"], "pay-stg-2");

        let prompt = s.prompt(&p.home);

        assert_eq!(
            prompt.stderr,
            "smart-env: updated payments/staging (~API_KEY)\n",
            "{}",
            shell.name()
        );
        assert_eq!(s.var("API_KEY").as_deref(), Some("pay-stg-2"));
    });
}

// --- deactivate ---

#[test]
fn deactivate_restores_the_values_from_before() {
    each_shell(|shell| {
        let p = projects();
        let mut s = Session::new(&p.m, shell, &[("API_KEY", "mine")]);
        s.activate(&p.home, &["--env", "payments/dev"]);

        let prompt = s.deactivate(&p.home);

        assert_eq!(prompt.exit, Exit::Success);
        assert_eq!(
            prompt.stderr,
            "smart-env: restored environment from before payments/dev\n",
            "{}",
            shell.name()
        );
        assert_eq!(s.var("API_KEY").as_deref(), Some("mine"));
        assert_eq!(s.var("DATABASE_URL"), None);
        s.quiet(&p.home);
    });
}

#[test]
fn after_deactivate_the_hook_leaves_the_project_alone_until_you_leave_it() {
    each_shell(|shell| {
        let p = projects();
        let mut s = Session::new(&p.m, shell, &[]);
        s.prompt(&p.payments);
        s.deactivate(&p.payments);

        s.quiet(&p.payments);
        s.quiet(&p.payments.join("."));
        assert_eq!(s.var("API_KEY"), None, "{}", shell.name());

        s.quiet(&p.home);
        let prompt = s.prompt(&p.payments);
        assert_eq!(
            prompt.stderr,
            "smart-env: active payments/dev (2 variables)\n"
        );
    });
}

#[test]
fn deactivate_with_nothing_active_says_so() {
    each_shell(|shell| {
        let p = projects();
        let mut s = Session::new(&p.m, shell, &[]);

        let prompt = s.deactivate(&p.home);

        assert_eq!(prompt.exit, Exit::Success);
        assert_eq!(
            prompt.stderr,
            "smart-env: nothing is active\n",
            "{}",
            shell.name()
        );
        assert_eq!(prompt.code, "");
    });
}

// --- activate: refused ---

#[test]
fn a_failed_activate_leaves_the_shell_as_it_was() {
    each_shell(|shell| {
        let p = projects();
        let mut s = Session::new(&p.m, shell, &[]);
        s.prompt(&p.payments);

        for (dir, args, exit) in [
            (&p.home, &[][..], Exit::NotFound),
            (&p.payments, &["--env", "nope"][..], Exit::NotFound),
            (&p.payments, &["--env", "nope/dev"][..], Exit::NotFound),
        ] {
            let prompt = s.activate(dir, args);
            assert_eq!(
                prompt.exit,
                exit,
                "{}: {args:?}: {}",
                shell.name(),
                prompt.stderr
            );
            assert_eq!(prompt.code, "", "{args:?}");
            assert!(prompt.stderr.starts_with("✗ "), "{}", prompt.stderr);
            assert_eq!(s.var("API_KEY").as_deref(), Some("pay-1"), "{args:?}");
        }
    });
}

#[test]
fn activate_with_a_locked_key_asks_nothing_and_fails() {
    each_shell(|shell| {
        let p = projects_on(Machine::without_keychain(), Some(PASSPHRASE));
        ok(&p.m, &["lock"]);
        let mut s = Session::new(&p.m, shell, &[]);

        let prompt = s.activate(&p.home, &["--env", "payments/dev"]);

        assert_eq!(prompt.exit, Exit::Access, "{}", prompt.stderr);
        assert!(
            prompt.stderr.contains("smart-env unlock"),
            "{}",
            prompt.stderr
        );
        assert_eq!(s.var("API_KEY"), None, "{}", shell.name());
    });
}

#[test]
fn activate_without_setup_is_not_set_up() {
    each_shell(|shell| {
        let m = Machine::new();
        let mut s = Session::new(&m, shell, &[]);
        let prompt = s.activate(&m.project, &["--json"]);
        assert_eq!(prompt.exit, Exit::NotFound);
        assert!(prompt.code.contains("not_set_up") || prompt.stderr.contains("smart-env setup"));
    });
}

// --- auto-activate ---

#[test]
fn auto_activate_off_stops_loading_on_cd() {
    each_shell(|shell| {
        let p = projects();
        let run = p.m.run(&["auto-activate", "off"], None);
        assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
        assert_eq!(
            run.stdout,
            "✓ Auto-activation off. Load variables with: smart-env activate\n"
        );
        let mut s = Session::new(&p.m, shell, &[]);

        s.quiet(&p.payments);
        assert_eq!(s.var("API_KEY"), None, "{}", shell.name());

        let prompt = s.activate(&p.payments, &[]);
        assert_eq!(prompt.exit, Exit::Success, "{}", prompt.stderr);
        assert_eq!(s.var("API_KEY").as_deref(), Some("pay-1"));
        s.quiet(&p.home);
        assert_eq!(s.var("API_KEY").as_deref(), Some("pay-1"), "manual stays");
    });
}

#[test]
fn turning_auto_activate_off_unloads_an_automatic_activation() {
    each_shell(|shell| {
        let p = projects();
        let mut s = Session::new(&p.m, shell, &[("API_KEY", "mine")]);
        s.prompt(&p.payments);
        ok(&p.m, &["auto-activate", "off"]);

        let prompt = s.prompt(&p.payments);

        assert_eq!(
            prompt.stderr,
            "smart-env: restored environment from before payments/dev\n",
            "{}",
            shell.name()
        );
        assert_eq!(s.var("API_KEY").as_deref(), Some("mine"));
        s.quiet(&p.payments);
    });
}

#[test]
fn auto_activate_on_turns_it_back_on() {
    each_shell(|shell| {
        let p = projects();
        ok(&p.m, &["auto-activate", "off"]);
        let run = p.m.run(&["auto-activate", "on"], None);
        assert_eq!(run.stdout, "✓ Auto-activation on\n");
        let mut s = Session::new(&p.m, shell, &[]);

        let prompt = s.prompt(&p.payments);

        assert_eq!(
            prompt.stderr,
            "smart-env: active payments/dev (2 variables)\n",
            "{}",
            shell.name()
        );
    });
}

#[test]
fn auto_activate_json() {
    let p = projects();
    let run = p.m.run(&["auto-activate", "off", "--json"], None);
    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    assert_eq!(json(&run.stdout)["auto_activate"], false);
    let run = p.m.run(&["auto-activate", "on", "--json"], None);
    assert_eq!(json(&run.stdout)["auto_activate"], true);
}

#[test]
fn auto_activate_needs_setup() {
    let m = Machine::new();
    let run = m.run(&["auto-activate", "off", "--json"], None);
    assert_eq!(run.exit, Exit::NotFound);
    assert_eq!(error_code(&run), "not_set_up");
}

// --- the binary without the shell function ---

#[test]
fn activate_and_deactivate_without_the_shell_function_explain_how_to_load_it() {
    let p = projects();
    for command in ["activate", "deactivate"] {
        let run = p.m.run(&[command], None);
        assert_eq!(run.exit, Exit::Usage, "{command}");
        assert!(
            run.stderr.contains(&format!(
                "✗ smart-env {command} changes your shell, so it needs the shell function."
            )),
            "{}",
            run.stderr
        );
        assert!(
            run.stderr.contains("eval \"$(smart-env hook bash)\""),
            "{}",
            run.stderr
        );
        let run = p.m.run(&[command, "--json"], None);
        assert_eq!(error_code(&run), "shell_function_required");
    }
}
