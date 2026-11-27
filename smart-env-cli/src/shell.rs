//! Supported shells: detection from `$SHELL`, quoting for `eval`, the hook
//! script and the startup file it is installed in (ADR-005).

use std::ffi::OsString;
use std::path::PathBuf;

use clap::ValueEnum;

/// A shell the hook supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Shell {
    /// GNU bash.
    Bash,
    /// Z shell.
    Zsh,
    /// fish.
    Fish,
}

/// What the system says about the user's shell setup: the variables that
/// decide which shell gets the hook and where its startup file is.
#[derive(Clone, Debug, Default)]
pub struct ShellEnv {
    /// `$SHELL`: the user's login shell.
    pub shell: Option<OsString>,
    /// `$HOME`.
    pub home: Option<PathBuf>,
    /// `$ZDOTDIR`: where zsh keeps `.zshrc`.
    pub zdotdir: Option<PathBuf>,
    /// `$XDG_CONFIG_HOME`: where fish keeps its configuration.
    pub xdg_config_home: Option<PathBuf>,
    /// `$PATH`, to warn when the hook line cannot find `smart-env`.
    pub path: Option<OsString>,
}

impl ShellEnv {
    /// Reads `SHELL`, `HOME`, `ZDOTDIR`, `XDG_CONFIG_HOME` and `PATH`.
    pub fn detect() -> Self {
        let var = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());
        Self {
            shell: var("SHELL"),
            home: var("HOME").map(PathBuf::from),
            zdotdir: var("ZDOTDIR").map(PathBuf::from),
            xdg_config_home: var("XDG_CONFIG_HOME").map(PathBuf::from),
            path: var("PATH"),
        }
    }
}

impl Shell {
    /// The shell named by a `$SHELL` value (`/usr/bin/zsh` → zsh); `None`
    /// for unsupported shells.
    pub fn from_path(path: &str) -> Option<Self> {
        let _ = path;
        todo!("Shell::from_path")
    }

    /// Name as typed in `smart-env hook <shell>`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
        }
    }

    /// `text` as one word for this shell, taken literally (no expansion,
    /// no command substitution).
    pub fn quote(self, text: &str) -> String {
        let _ = text;
        todo!("Shell::quote")
    }

    /// The script `smart-env hook <shell>` prints: defines `_smart_env_hook`,
    /// which runs `<executable> hook-env <shell>` at every prompt and
    /// evaluates its output. Loading it twice registers it once.
    pub fn hook_script(self, executable: &str) -> String {
        let _ = executable;
        todo!("Shell::hook_script")
    }
}
