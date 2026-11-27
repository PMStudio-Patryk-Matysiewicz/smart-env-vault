//! A shell session replayed in a real shell: the hook script, then every
//! `hook-env` output so far, in order. `hook-env` runs in-process (fake key
//! stores) with the state the shell holds after the previous prompt.

use std::path::{Path, PathBuf};
use std::process::Command;

use smart_env_cli::{Exit, Shell, Terminal, execute};

use super::{Machine, ScriptedTerminal, printed};

pub const ALL: [Shell; 3] = [Shell::Bash, Shell::Zsh, Shell::Fish];
pub const PASSPHRASE: &str = "correct horse battery staple";

pub fn installed(shell: Shell) -> bool {
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
pub fn each_shell(test: impl Fn(Shell)) {
    for shell in ALL {
        if installed(shell) {
            test(shell);
        }
    }
}

pub fn run_shell(shell: Shell, script: &str) -> String {
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
pub struct Prompt {
    pub exit: Exit,
    /// Shell code the hook evaluates.
    pub code: String,
    /// What the user sees.
    pub stderr: String,
}

pub struct Session<'a> {
    pub m: &'a Machine,
    pub shell: Shell,
    /// Everything the shell has run so far.
    pub code: String,
}

impl<'a> Session<'a> {
    /// A shell with `preset` variables exported, then the hook loaded.
    pub fn new(m: &'a Machine, shell: Shell, preset: &[(&str, &str)]) -> Self {
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

    pub fn eval(&self, tail: &str) -> String {
        run_shell(self.shell, &format!("{}\n{tail}", self.code))
    }

    /// The hook state the shell holds now.
    pub fn state(&self) -> Option<String> {
        let state = self.eval(match self.shell {
            Shell::Fish => "printf '%s' \"$_smart_env_state\"",
            _ => "printf '%s' \"${_smart_env_state-}\"",
        });
        (!state.is_empty()).then_some(state)
    }

    /// The exported value of `name`, `None` if it is not in the environment
    /// of processes the shell starts.
    pub fn var(&self, name: &str) -> Option<String> {
        let or = if self.shell == Shell::Fish {
            "; or"
        } else {
            " ||"
        };
        let out = self.eval(&format!("printenv {name}{or} printf '<unset>'"));
        (out != "<unset>").then(|| out.strip_suffix('\n').unwrap_or(&out).to_owned())
    }

    /// One prompt in `dir` with no terminal.
    pub fn prompt(&mut self, dir: &Path) -> Prompt {
        self.prompt_with(dir, None)
    }

    pub fn prompt_with(&mut self, dir: &Path, terminal: Option<&mut ScriptedTerminal>) -> Prompt {
        let prompt = self.hook_env(dir, &[], terminal);
        assert_eq!(prompt.exit, Exit::Success, "hook-env never fails");
        prompt
    }

    /// `hook-env <shell> ARGS` in `dir` with the shell's state, as the hook
    /// or the `smart-env` shell function runs it; its output is evaluated.
    pub fn hook_env(
        &mut self,
        dir: &Path,
        args: &[&str],
        terminal: Option<&mut ScriptedTerminal>,
    ) -> Prompt {
        let state = self.state().unwrap_or_default();
        let mut ctx = self.m.context(terminal.map(|t| t as &mut dyn Terminal));
        ctx.current_dir = Some(dir.to_path_buf());
        ctx.hook_state = Some(state);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let argv = ["smart-env", "hook-env", self.shell.name()]
            .into_iter()
            .chain(args.iter().copied());
        let exit = execute(argv, &mut ctx, &mut out, &mut err);
        let prompt = Prompt {
            exit,
            code: String::from_utf8(out).unwrap(),
            stderr: String::from_utf8(err).unwrap(),
        };
        self.code.push('\n');
        self.code.push_str(&prompt.code);
        prompt
    }

    /// `smart-env activate ARGS` through the shell function.
    pub fn activate(&mut self, dir: &Path, args: &[&str]) -> Prompt {
        let mut argv = vec!["--activate"];
        argv.extend_from_slice(args);
        self.hook_env(dir, &argv, None)
    }

    /// `smart-env deactivate` through the shell function.
    pub fn deactivate(&mut self, dir: &Path) -> Prompt {
        self.hook_env(dir, &["--deactivate"], None)
    }

    /// A prompt that must print nothing at all.
    pub fn quiet(&mut self, dir: &Path) {
        let prompt = self.prompt(dir);
        assert_eq!(prompt.code, "", "{}: no shell code", self.shell.name());
        assert_eq!(prompt.stderr, "", "{}: no message", self.shell.name());
    }
}

// --- projects ---

pub fn ok(m: &Machine, args: &[&str]) {
    let run = m.run(args, None);
    assert_eq!(run.exit, Exit::Success, "{args:?}: {}", printed(&run));
}

pub fn set(m: &Machine, args: &[&str], value: &str) {
    let mut argv = vec!["set"];
    argv.extend_from_slice(args);
    argv.push("--stdin");
    let run = m.run_with_stdin(&argv, None, format!("{value}\n").as_bytes());
    assert_eq!(run.exit, Exit::Success, "{argv:?}: {}", printed(&run));
}

pub struct Projects {
    pub m: Machine,
    pub payments: PathBuf,
    pub billing: PathBuf,
    /// A directory outside every project.
    pub home: PathBuf,
}

/// `payments/dev` (`API_KEY`, `DATABASE_URL`), `payments/staging`
/// (`API_KEY`) and `billing/dev` (`API_KEY`,
/// `BILLING_TOKEN`), both initialized (so allowed) on this device.
pub fn projects() -> Projects {
    projects_on(Machine::new(), None)
}

pub fn projects_on(mut m: Machine, passphrase: Option<&str>) -> Projects {
    let setup = match passphrase {
        Some(passphrase) => m.setup_with_passphrase(passphrase).0,
        None => m.setup().0,
    };
    assert_eq!(setup.exit, Exit::Success, "{}", printed(&setup));
    let payments = m.project.clone();
    m.write(".env", "API_KEY=pay-1\nDATABASE_URL=postgres://pay\n");
    m.write(".env.staging", "API_KEY=pay-stg\n");
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
pub fn checkout(p: &Projects, from: &Path, name: &str) -> PathBuf {
    let dir = p.home.parent().unwrap().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(from.join("smart-env.toml"), dir.join("smart-env.toml")).unwrap();
    dir
}
