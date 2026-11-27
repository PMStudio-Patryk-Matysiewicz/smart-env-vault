//! The shell hook at work (`smart-env hook-env`): variables appear on `cd`
//! into an allowed project and the earlier values come back on the way out
//! (ADR-005, step 3 items 4, 5 and 7).
//!
//! A [`Session`] replays a shell session in a real shell: the hook script,
//! then every `hook-env` output so far, in order. `hook-env` runs in-process
//! (fake key stores), with the state the shell holds after the previous
//! prompt. Shells that are not installed are skipped with a note.
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::{Machine, ScriptedTerminal, printed};
use smart_env_cli::{Exit, Shell, Terminal, execute};

const ALL: [Shell; 3] = [Shell::Bash, Shell::Zsh, Shell::Fish];
const PASSPHRASE: &str = "correct horse battery staple";

// --- a shell session ---

fn installed(shell: Shell) -> bool {
    let found = Command::new(shell.name())
        .args(["-c", "exit 0"])
        .output()
        .is_ok_and(|output| output.status.success());
    if !found {
        eprintln!("skipped: {} is not installed", shell.name());
    }
    found
}

/// Runs `test` once for every installed shell.
fn each_shell(test: impl Fn(Shell)) {
    for shell in ALL {
        if installed(shell) {
            test(shell);
        }
    }
}

fn run_shell(shell: Shell, script: &str) -> String {
    let mut command = Command::new(shell.name());
    match shell {
        Shell::Bash => command.args(["--norc", "--noprofile", "-c", script]),
        Shell::Zsh => command.args(["-f", "-c", script]),
        Shell::Fish => command.args(["--no-config", "-c", script]),
    };
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}: {}\n--- script ---\n{script}",
        shell.name(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// What one prompt did.
struct Prompt {
    exit: Exit,
    /// Shell code the hook evaluates.
    code: String,
    /// What the user sees.
    stderr: String,
}

struct Session<'a> {
    m: &'a Machine,
    shell: Shell,
    /// Everything the shell has run so far.
    code: String,
}

impl<'a> Session<'a> {
    /// A shell with `preset` variables exported, then the hook loaded.
    fn new(m: &'a Machine, shell: Shell, preset: &[(&str, &str)]) -> Self {
        let mut code = String::new();
        for (name, value) in preset {
            let value = shell.quote(value);
            code.push_str(&match shell {
                Shell::Fish => format!("set -gx {name} {value}\n"),
                _ => format!("export {name}={value}\n"),
            });
        }
        let hook = m.run(&["hook", shell.name()], None);
        assert_eq!(hook.exit, Exit::Success);
        code.push_str(&hook.stdout);
        Self { m, shell, code }
    }

    fn eval(&self, tail: &str) -> String {
        run_shell(self.shell, &format!("{}\n{tail}", self.code))
    }

    /// The hook state the shell holds now.
    fn state(&self) -> Option<String> {
        let state = self.eval(match self.shell {
            Shell::Fish => "printf '%s' \"$_smart_env_state\"",
            _ => "printf '%s' \"${_smart_env_state-}\"",
        });
        (!state.is_empty()).then_some(state)
    }

    /// The exported value of `name`, `None` if it is not in the environment
    /// of processes the shell starts.
    fn var(&self, name: &str) -> Option<String> {
        let or = if self.shell == Shell::Fish {
            "; or"
        } else {
            " ||"
        };
        let out = self.eval(&format!("printenv {name}{or} printf '<unset>'"));
        (out != "<unset>").then(|| out.strip_suffix('\n').unwrap_or(&out).to_owned())
    }

    /// One prompt in `dir` with no terminal.
    fn prompt(&mut self, dir: &Path) -> Prompt {
        self.prompt_with(dir, None)
    }

    fn prompt_with(&mut self, dir: &Path, terminal: Option<&mut ScriptedTerminal>) -> Prompt {
        let state = self.state();
        let mut ctx = self.m.context(terminal.map(|t| t as &mut dyn Terminal));
        ctx.current_dir = Some(dir.to_path_buf());
        ctx.hook_state = state;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let exit = execute(
            ["smart-env", "hook-env", self.shell.name()],
            &mut ctx,
            &mut out,
            &mut err,
        );
        let prompt = Prompt {
            exit,
            code: String::from_utf8(out).unwrap(),
            stderr: String::from_utf8(err).unwrap(),
        };
        assert_eq!(prompt.exit, Exit::Success, "hook-env never fails");
        self.code.push('\n');
        self.code.push_str(&prompt.code);
        prompt
    }

    /// A prompt that must print nothing at all.
    fn quiet(&mut self, dir: &Path) {
        let prompt = self.prompt(dir);
        assert_eq!(prompt.code, "", "{}: no shell code", self.shell.name());
        assert_eq!(prompt.stderr, "", "{}: no message", self.shell.name());
    }
}

// --- projects ---

fn ok(m: &Machine, args: &[&str]) {
    let run = m.run(args, None);
    assert_eq!(run.exit, Exit::Success, "{args:?}: {}", printed(&run));
}

fn set(m: &Machine, args: &[&str], value: &str) {
    let mut argv = vec!["set"];
    argv.extend_from_slice(args);
    argv.push("--stdin");
    let run = m.run_with_stdin(&argv, None, format!("{value}\n").as_bytes());
    assert_eq!(run.exit, Exit::Success, "{argv:?}: {}", printed(&run));
}

struct Projects {
    m: Machine,
    payments: PathBuf,
    billing: PathBuf,
    /// A directory outside every project.
    home: PathBuf,
}

/// `payments/dev` (`API_KEY`, `DATABASE_URL`) and `billing/dev` (`API_KEY`,
/// `BILLING_TOKEN`), both initialized (so allowed) on this device.
fn projects() -> Projects {
    projects_on(Machine::new(), None)
}

fn projects_on(mut m: Machine, passphrase: Option<&str>) -> Projects {
    let setup = match passphrase {
        Some(passphrase) => m.setup_with_passphrase(passphrase).0,
        None => m.setup().0,
    };
    assert_eq!(setup.exit, Exit::Success, "{}", printed(&setup));
    let payments = m.project.clone();
    m.write(".env", "API_KEY=pay-1\nDATABASE_URL=postgres://pay\n");
    ok(&m, &["init", "--yes"]);
    m.use_project_dir("billing");
    let billing = m.project.clone();
    m.write(".env", "API_KEY=bill-1\nBILLING_TOKEN=tok-1\n");
    ok(&m, &["init", "--yes"]);
    m.use_project_dir("elsewhere");
    let home = m.project.clone();
    Projects {
        m,
        payments,
        billing,
        home,
    }
}

/// `smart-env.toml` of `from` copied to a new directory `name`: the same
/// project, never allowed there.
fn checkout(p: &Projects, from: &Path, name: &str) -> PathBuf {
    let dir = p.home.parent().unwrap().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(from.join("smart-env.toml"), dir.join("smart-env.toml")).unwrap();
    dir
}

// --- entering and leaving ---

#[test]
fn outside_a_project_the_hook_is_quiet() {
    each_shell(|shell| {
        let p = projects();
        let mut s = Session::new(&p.m, shell, &[]);
        s.quiet(&p.home);
        s.quiet(&p.home);
        assert_eq!(s.state(), None);
    });
}

#[test]
fn entering_an_allowed_project_exports_its_variables() {
    each_shell(|shell| {
        let p = projects();
        let mut s = Session::new(&p.m, shell, &[]);

        let prompt = s.prompt(&p.payments);

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
        assert_eq!(s.var("DATABASE_URL").as_deref(), Some("postgres://pay"));
        assert!(s.state().is_some());
    });
}

#[test]
fn the_next_prompt_and_subdirectories_are_quiet() {
    each_shell(|shell| {
        let p = projects();
        let sub = p.payments.join("src/api");
        std::fs::create_dir_all(&sub).unwrap();
        let mut s = Session::new(&p.m, shell, &[]);
        s.prompt(&p.payments);

        s.quiet(&p.payments);
        s.quiet(&sub);
        assert_eq!(s.var("API_KEY").as_deref(), Some("pay-1"));
    });
}

#[test]
fn leaving_restores_the_values_from_before() {
    each_shell(|shell| {
        let p = projects();
        let mut s = Session::new(&p.m, shell, &[("API_KEY", "mine")]);
        s.prompt(&p.payments);
        assert_eq!(s.var("API_KEY").as_deref(), Some("pay-1"));

        let prompt = s.prompt(&p.home);

        assert_eq!(
            prompt.stderr,
            "smart-env: restored environment from before payments/dev\n",
            "{}",
            shell.name()
        );
        assert_eq!(
            s.var("API_KEY").as_deref(),
            Some("mine"),
            "{}",
            shell.name()
        );
        assert_eq!(s.var("DATABASE_URL"), None, "{}", shell.name());
        assert_eq!(s.state(), None);
        s.quiet(&p.home);
    });
}

#[test]
fn moving_between_projects_swaps_their_variables() {
    each_shell(|shell| {
        let p = projects();
        let mut s = Session::new(&p.m, shell, &[("API_KEY", "mine")]);
        s.prompt(&p.payments);

        let prompt = s.prompt(&p.billing);

        assert_eq!(
            prompt.stderr,
            "smart-env: active billing/dev (2 variables)\n",
            "{}",
            shell.name()
        );
        assert_eq!(s.var("API_KEY").as_deref(), Some("bill-1"));
        assert_eq!(s.var("BILLING_TOKEN").as_deref(), Some("tok-1"));
        assert_eq!(s.var("DATABASE_URL"), None, "payments is gone");

        s.prompt(&p.home);
        assert_eq!(
            s.var("API_KEY").as_deref(),
            Some("mine"),
            "{}",
            shell.name()
        );
        assert_eq!(s.var("BILLING_TOKEN"), None);
    });
}

// --- changes from another tab ---

#[test]
fn a_change_from_another_tab_shows_up_at_the_next_prompt() {
    each_shell(|shell| {
        let p = projects();
        let mut s = Session::new(&p.m, shell, &[("OLD_ONLY", "before")]);
        set(&p.m, &["OLD_ONLY", "--env", "payments/dev"], "from-vault");
        s.prompt(&p.payments);
        assert_eq!(s.var("OLD_ONLY").as_deref(), Some("from-vault"));

        set(&p.m, &["API_KEY", "--env", "payments/dev"], "pay-2");
        set(&p.m, &["STRIPE_KEY", "--env", "payments/dev"], "sk-1");
        ok(&p.m, &["rm", "OLD_ONLY", "--env", "payments/dev"]);
        let prompt = s.prompt(&p.payments);

        assert_eq!(
            prompt.stderr,
            "smart-env: updated payments/dev (+STRIPE_KEY ~API_KEY -OLD_ONLY)\n",
            "{}",
            shell.name()
        );
        assert_eq!(s.var("API_KEY").as_deref(), Some("pay-2"));
        assert_eq!(s.var("STRIPE_KEY").as_deref(), Some("sk-1"));
        assert_eq!(
            s.var("OLD_ONLY").as_deref(),
            Some("before"),
            "a removed variable gets its value from before back"
        );
        s.quiet(&p.payments);

        s.prompt(&p.home);
        assert_eq!(s.var("STRIPE_KEY"), None);
        assert_eq!(s.var("OLD_ONLY").as_deref(), Some("before"));
    });
}

// --- quoting ---

/// Values a careless `eval` would mangle or run; `marker` is created if
/// any code runs.
fn awkward(marker: &Path) -> Vec<String> {
    let marker = marker.display();
    vec![
        "it's".to_owned(),
        "\"double\"".to_owned(),
        format!("$(touch {marker})"),
        format!("`touch {marker}`"),
        format!("; touch {marker} #"),
        "$HOME".to_owned(),
        "back\\slash \\' \\\\".to_owned(),
        "new\nline".to_owned(),
        "zażółć 🔑".to_owned(),
        "*".to_owned(),
        "!x".to_owned(),
    ]
}

#[test]
fn values_reach_the_shell_literally_and_run_no_code() {
    each_shell(|shell| {
        let p = projects();
        let marker = p.home.join("PWNED");
        let values = awkward(&marker);
        for (index, value) in values.iter().enumerate() {
            set(
                &p.m,
                &[&format!("V{index}"), "--env", "payments/dev"],
                value,
            );
        }
        let mut s = Session::new(&p.m, shell, &[]);
        s.prompt(&p.payments);

        for (index, value) in values.iter().enumerate() {
            assert_eq!(
                s.var(&format!("V{index}")).as_deref(),
                Some(value.as_str()),
                "{}: {value:?}",
                shell.name()
            );
        }
        assert!(!marker.exists(), "{}: a value ran as code", shell.name());
    });
}

// --- what is exported ---

#[test]
fn run_only_variables_never_reach_the_shell() {
    each_shell(|shell| {
        let p = projects();
        set(
            &p.m,
            &[
                "ANALYTICS_TOKEN",
                "--env",
                "payments/dev",
                "--inject",
                "run",
            ],
            "secret",
        );
        let mut s = Session::new(&p.m, shell, &[]);

        let prompt = s.prompt(&p.payments);

        assert_eq!(s.var("ANALYTICS_TOKEN"), None, "{}", shell.name());
        assert_eq!(
            prompt.stderr,
            "smart-env: active payments/dev (2 variables)\n"
        );
    });
}

#[test]
fn reserved_names_need_consent_for_the_current_value() {
    each_shell(|shell| {
        let p = projects();
        set(
            &p.m,
            &["NODE_OPTIONS", "--env", "payments/dev"],
            "--inspect",
        );
        set(&p.m, &["PATH", "--env", "payments/dev"], "/evil");
        let mut s = Session::new(&p.m, shell, &[]);
        let path = s.var("PATH");

        let prompt = s.prompt(&p.payments);
        assert_eq!(
            prompt.stderr,
            "smart-env: NODE_OPTIONS, PATH are reserved names and were not loaded. Allow one with: smart-env allow --var NAME\n\
             smart-env: active payments/dev (2 variables)\n",
            "{}",
            shell.name()
        );
        assert_eq!(s.var("NODE_OPTIONS"), None);
        assert_eq!(s.var("PATH"), path);

        let mut terminal = ScriptedTerminal::new(|_, _| "y".to_owned());
        let allowed = p.m.run(
            &["allow", "--var", "NODE_OPTIONS", "--env", "payments/dev"],
            Some(&mut terminal),
        );
        assert_eq!(allowed.exit, Exit::Success, "{}", printed(&allowed));
        s.prompt(&p.home);
        s.prompt(&p.payments);
        assert_eq!(s.var("NODE_OPTIONS").as_deref(), Some("--inspect"));

        set(
            &p.m,
            &["NODE_OPTIONS", "--env", "payments/dev"],
            "--require evil",
        );
        let prompt = s.prompt(&p.payments);
        assert!(
            prompt.stderr.contains(
                "smart-env: NODE_OPTIONS changed since you allowed it and was not loaded. Allow the new value with: smart-env allow --var NODE_OPTIONS"
            ),
            "{}",
            prompt.stderr
        );
        assert_eq!(s.var("NODE_OPTIONS"), None, "{}", shell.name());
    });
}

// --- trust ---

#[test]
fn a_directory_that_is_not_allowed_loads_nothing_and_says_so_once() {
    each_shell(|shell| {
        let p = projects();
        let clone = checkout(&p, &p.payments, "clone");
        let mut s = Session::new(&p.m, shell, &[]);

        let prompt = s.prompt(&clone);

        assert_eq!(
            prompt.stderr,
            "smart-env: payments/dev is not allowed here. Run: smart-env allow\n",
            "{}",
            shell.name()
        );
        assert_eq!(s.var("API_KEY"), None);
        s.quiet(&clone);

        let allowed = p.m.run(&["allow", clone.to_str().unwrap()], None);
        assert_eq!(allowed.exit, Exit::Success, "{}", printed(&allowed));
        let prompt = s.prompt(&clone);
        assert_eq!(
            prompt.stderr,
            "smart-env: active payments/dev (2 variables)\n"
        );
        assert_eq!(s.var("API_KEY").as_deref(), Some("pay-1"));
    });
}

#[test]
fn a_denied_directory_is_silent() {
    each_shell(|shell| {
        let p = projects();
        let clone = checkout(&p, &p.payments, "denied");
        let denied = p.m.run(&["deny", clone.to_str().unwrap()], None);
        assert_eq!(denied.exit, Exit::Success);
        let mut s = Session::new(&p.m, shell, &[]);

        s.quiet(&clone);
        assert_eq!(s.var("API_KEY"), None, "{}", shell.name());
    });
}

#[test]
fn changing_smart_env_toml_unloads_the_project_until_allowed_again() {
    each_shell(|shell| {
        let p = projects();
        let mut s = Session::new(&p.m, shell, &[("API_KEY", "mine")]);
        s.prompt(&p.payments);
        let toml = p.payments.join("smart-env.toml");
        let content = std::fs::read_to_string(&toml).unwrap();
        std::fs::write(&toml, format!("{content}# edited\n")).unwrap();

        let prompt = s.prompt(&p.payments);

        assert_eq!(
            prompt.stderr,
            "smart-env: smart-env.toml changed since it was allowed. Review it, then run: smart-env allow\n",
            "{}",
            shell.name()
        );
        assert_eq!(s.var("API_KEY").as_deref(), Some("mine"));
        s.quiet(&p.payments);
    });
}

// --- the key ---

#[test]
fn a_locked_key_loads_nothing_asks_nothing_and_says_so_once() {
    each_shell(|shell| {
        let p = projects_on(Machine::without_keychain(), Some(PASSPHRASE));
        ok(&p.m, &["lock"]);
        let mut s = Session::new(&p.m, shell, &[]);
        let mut terminal = ScriptedTerminal::with_passphrase(PASSPHRASE);

        let prompt = s.prompt_with(&p.payments, Some(&mut terminal));

        assert_eq!(
            terminal.questions + terminal.secret_questions,
            0,
            "never asks"
        );
        assert_eq!(
            prompt.stderr,
            "smart-env: payments/dev not loaded: the key is locked. Run: smart-env unlock\n",
            "{}",
            shell.name()
        );
        assert_eq!(s.var("API_KEY"), None);
        s.quiet(&p.payments);

        let unlocked = p.m.run(&["unlock"], Some(&mut terminal));
        assert_eq!(unlocked.exit, Exit::Success, "{}", printed(&unlocked));
        let prompt = s.prompt(&p.payments);
        assert_eq!(
            prompt.stderr,
            "smart-env: active payments/dev (2 variables)\n"
        );
        assert_eq!(s.var("API_KEY").as_deref(), Some("pay-1"));
    });
}

#[test]
fn an_unchanged_prompt_needs_no_key() {
    each_shell(|shell| {
        let p = projects_on(Machine::without_keychain(), Some(PASSPHRASE));
        let mut s = Session::new(&p.m, shell, &[]);
        s.prompt(&p.payments);
        ok(&p.m, &["lock"]);

        s.quiet(&p.payments);
        assert_eq!(
            s.var("API_KEY").as_deref(),
            Some("pay-1"),
            "{}",
            shell.name()
        );
    });
}

// --- broken input ---

#[test]
fn a_broken_smart_env_toml_is_reported_once() {
    each_shell(|shell| {
        let p = projects();
        let broken = p.home.parent().unwrap().join("broken");
        std::fs::create_dir_all(&broken).unwrap();
        std::fs::write(broken.join("smart-env.toml"), "project = \n").unwrap();
        let mut s = Session::new(&p.m, shell, &[]);

        let prompt = s.prompt(&broken);

        assert!(
            prompt.stderr.starts_with("smart-env: smart-env.toml"),
            "{}: {}",
            shell.name(),
            prompt.stderr
        );
        assert_eq!(prompt.stderr.lines().count(), 1, "{}", prompt.stderr);
        s.quiet(&broken);
    });
}

#[test]
fn a_damaged_state_counts_as_no_state() {
    let p = projects();
    for state in ["", "not json", "{\"v\":99}", "{}"] {
        let mut ctx = p.m.context(None);
        ctx.current_dir = Some(p.payments.clone());
        ctx.hook_state = Some(state.to_owned());
        let mut out = Vec::new();
        let mut err = Vec::new();
        let exit = execute(
            ["smart-env", "hook-env", "bash"],
            &mut ctx,
            &mut out,
            &mut err,
        );
        assert_eq!(exit, Exit::Success, "{state:?}");
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "smart-env: active payments/dev (2 variables)\n",
            "{state:?}"
        );
    }
}

#[test]
fn messages_never_show_values() {
    each_shell(|shell| {
        let p = projects();
        set(
            &p.m,
            &["NODE_OPTIONS", "--env", "payments/dev"],
            "Zq7Kanarek",
        );
        set(&p.m, &["API_KEY", "--env", "payments/dev"], "Zq7Kanarek-2");
        let mut s = Session::new(&p.m, shell, &[]);
        let mut seen = String::new();
        seen.push_str(&s.prompt(&p.payments).stderr);
        set(&p.m, &["API_KEY", "--env", "payments/dev"], "Zq7Kanarek-3");
        seen.push_str(&s.prompt(&p.payments).stderr);
        seen.push_str(&s.prompt(&p.home).stderr);
        assert!(!seen.contains("Zq7Kanarek"), "{}: {seen}", shell.name());
    });
}
