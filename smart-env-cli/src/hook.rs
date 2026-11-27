//! `smart-env hook <shell>` (the shell integration script), the hidden
//! `smart-env hook-env <shell>` it calls at every prompt, and installing the
//! hook in the shell's startup file during `setup` (ADR-005).
//!
//! What `hook-env` does inside a project (activation, restoring, changes from
//! another tab) comes with the "mechanics" item of step 3.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::init::ask_yes;
use crate::{CliError, Context, Exit, Interaction, Shell, ShellEnv};

/// Prints the hook script for `shell` to `out`.
pub(crate) fn hook(ctx: &Context<'_>, shell: Shell, out: &mut dyn Write) -> Result<Exit, CliError> {
    let executable = ctx
        .executable
        .as_deref()
        .and_then(Path::to_str)
        .map_or_else(|| "smart-env".to_owned(), |path| shell.quote(path));
    // A closed pipe cannot be reported anywhere better.
    let _ = out.write_all(shell.hook_script(&executable).as_bytes());
    Ok(Exit::Success)
}

/// Called by the hook at every prompt. Never fails and never prints an
/// error: a broken hook must not break the prompt.
pub(crate) fn hook_env(
    ctx: &mut Context<'_>,
    shell: Shell,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Exit {
    // Activation comes with the "mechanics" item; until then the hook is a
    // no-op everywhere.
    let _ = (ctx, shell, out, err);
    Exit::Success
}

/// What installing the hook did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Installed {
    /// The hook block was appended to `file`.
    Added { shell: Shell, file: PathBuf },
    /// `file` already loads the hook.
    Present { shell: Shell, file: PathBuf },
    /// The user answered "no".
    Declined { shell: Shell, file: PathBuf },
    /// No terminal and no `--yes`: nothing asked, nothing written.
    Skipped { shell: Shell, file: PathBuf },
    /// `$SHELL` is missing or not bash, zsh or fish.
    UnknownShell,
    /// Writing `file` failed.
    Failed { shell: Shell, file: PathBuf },
}

impl Installed {
    /// Lines for `setup`'s human output; `home` shortens paths to `~/…`,
    /// `in_path` says whether the hook line will find `smart-env`.
    pub(crate) fn lines(&self, home: Option<&Path>, in_path: bool) -> Vec<String> {
        let shown = |file: &Path| display(file, home);
        match self {
            Self::Added { file, .. } => {
                let file = shown(file);
                let mut lines = vec![format!(
                    "✓ Shell hook added to {file}. Open a new terminal or run: source {file}"
                )];
                if !in_path {
                    lines.push(
                        "! smart-env is not in PATH, so the hook line does nothing until it is."
                            .to_owned(),
                    );
                }
                lines
            }
            Self::Present { file, .. } => vec![format!("✓ Shell hook already in {}", shown(file))],
            Self::Declined { shell, file } => vec![format!(
                "Shell hook not added. To add it yourself, put this line in {}: {}",
                shown(file),
                shell.startup_line()
            )],
            Self::Skipped { shell, file } => vec![format!(
                "Shell hook not added. Add it with: smart-env setup --yes, or put this line in {}: {}",
                shown(file),
                shell.startup_line()
            )],
            Self::UnknownShell => vec![
                "! Shell not recognized (bash, zsh and fish are supported). Without the hook, use: smart-env run -- <command>"
                    .to_owned(),
            ],
            Self::Failed { shell, file } => vec![format!(
                "! Could not write {}. Add this line yourself: {}",
                shown(file),
                shell.startup_line()
            )],
        }
    }

    /// `hook` field of `setup --json`.
    pub(crate) fn to_json(&self) -> Value {
        let (status, target) = match self {
            Self::Added { shell, file } => ("added", Some((shell, file))),
            Self::Present { shell, file } => ("present", Some((shell, file))),
            Self::Declined { shell, file } => ("declined", Some((shell, file))),
            Self::Skipped { shell, file } => ("skipped", Some((shell, file))),
            Self::Failed { shell, file } => ("failed", Some((shell, file))),
            Self::UnknownShell => ("unknown_shell", None),
        };
        json!({
            "shell": target.map(|(shell, _)| shell.name()),
            "file": target.map(|(_, file)| file.display().to_string()),
            "status": status,
        })
    }
}

/// Adds the hook to the startup file of the user's shell, once, after a
/// confirmation (or `--yes`).
pub(crate) fn install(ctx: &mut Context<'_>, interaction: Interaction) -> Installed {
    let Some(shell) = ctx
        .shell
        .shell
        .as_deref()
        .and_then(|path| path.to_str())
        .and_then(Shell::from_path)
    else {
        return Installed::UnknownShell;
    };
    let Some(file) = startup_file(shell, &ctx.shell) else {
        // No home directory to put a startup file in.
        let name = match shell {
            Shell::Bash => ".bashrc",
            Shell::Zsh => ".zshrc",
            Shell::Fish => "config.fish",
        };
        return Installed::Failed {
            shell,
            file: PathBuf::from(name),
        };
    };

    let mut loaded_from = vec![file.clone()];
    if shell == Shell::Fish
        && let Some(config) = fish_config_dir(&ctx.shell)
    {
        loaded_from.push(config.join("config.fish"));
    }
    if let Some(found) = loaded_from.into_iter().find(|path| loads_hook(path, shell)) {
        return Installed::Present { shell, file: found };
    }

    let yes = match interaction {
        Interaction::AssumeYes => true,
        Interaction::NonInteractive => return Installed::Skipped { shell, file },
        Interaction::Interactive => {
            let question = format!(
                "? Add the shell hook to {} (variables load when you cd into a project)? [Y/n] ",
                display(&file, ctx.shell.home.as_deref())
            );
            ask_yes(ctx, &question)
        }
    };
    if !yes {
        return Installed::Declined { shell, file };
    }

    match append_block(&file, &shell.startup_block()) {
        Ok(()) => Installed::Added { shell, file },
        Err(_) => Installed::Failed { shell, file },
    }
}

/// Whether a `smart-env` executable is in `$PATH`, so the hook line finds it.
pub(crate) fn in_path(env: &ShellEnv) -> bool {
    use std::os::unix::fs::PermissionsExt;
    env.path.as_ref().is_some_and(|path| {
        std::env::split_paths(path).any(|dir| {
            fs::metadata(dir.join("smart-env"))
                .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        })
    })
}

/// bash: `~/.bashrc` (macOS: the login file); zsh: `$ZDOTDIR/.zshrc` or `~/.zshrc`; fish: its own
/// file in `conf.d`.
fn startup_file(shell: Shell, env: &ShellEnv) -> Option<PathBuf> {
    match shell {
        Shell::Bash if env.macos => Some(bash_login_file(env.home.as_ref()?)),
        Shell::Bash => Some(env.home.as_ref()?.join(".bashrc")),
        Shell::Zsh => Some(env.zdotdir.as_ref().or(env.home.as_ref())?.join(".zshrc")),
        Shell::Fish => Some(fish_config_dir(env)?.join("conf.d").join("smart-env.fish")),
    }
}

/// The file a bash login shell reads: the first of `~/.bash_profile`,
/// `~/.bash_login`, `~/.profile` that exists (creating `~/.bash_profile`
/// next to one of the others would hide it), else `~/.bash_profile`.
fn bash_login_file(home: &Path) -> PathBuf {
    [".bash_profile", ".bash_login", ".profile"]
        .iter()
        .map(|name| home.join(name))
        .find(|path| path.exists())
        .unwrap_or_else(|| home.join(".bash_profile"))
}

/// `$XDG_CONFIG_HOME/fish` or `~/.config/fish`.
fn fish_config_dir(env: &ShellEnv) -> Option<PathBuf> {
    let config = match &env.xdg_config_home {
        Some(dir) => dir.clone(),
        None => env.home.as_ref()?.join(".config"),
    };
    Some(config.join("fish"))
}

/// The file has a line (not a comment) that loads the hook for `shell`,
/// ours or one added by hand.
fn loads_hook(path: &Path, shell: Shell) -> bool {
    let needle = format!("smart-env hook {}", shell.name());
    fs::read_to_string(path).is_ok_and(|content| {
        content
            .lines()
            .any(|line| !line.trim_start().starts_with('#') && line.contains(&needle))
    })
}

/// Appends `block` (not write-and-rename: a symlinked dotfile stays a
/// symlink), after a blank line when the file has content.
fn append_block(file: &Path, block: &str) -> std::io::Result<()> {
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent)?;
    }
    let existing = fs::read(file).unwrap_or_default();
    let separator = match existing.last() {
        None => "",
        Some(b'\n') => "\n",
        Some(_) => "\n\n",
    };
    let mut handle = OpenOptions::new().create(true).append(true).open(file)?;
    handle.write_all(format!("{separator}{block}").as_bytes())?;
    handle.flush()
}

/// `~/…` under the home directory, the full path elsewhere.
pub(crate) fn display(file: &Path, home: Option<&Path>) -> String {
    match home.and_then(|home| file.strip_prefix(home).ok()) {
        Some(rest) => format!("~/{}", rest.display()),
        None => file.display().to_string(),
    }
}
