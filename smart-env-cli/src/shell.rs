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
    /// macOS: terminals start login shells, so bash reads its login file
    /// (`~/.bash_profile`, …) instead of `~/.bashrc`.
    pub macos: bool,
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
            macos: cfg!(target_os = "macos"),
        }
    }
}

impl Shell {
    /// The shell named by a `$SHELL` value (`/usr/bin/zsh` → zsh); `None`
    /// for unsupported shells.
    pub fn from_path(path: &str) -> Option<Self> {
        match std::path::Path::new(path).file_name()?.to_str()? {
            "bash" => Some(Self::Bash),
            "zsh" => Some(Self::Zsh),
            "fish" => Some(Self::Fish),
            _ => None,
        }
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
        match self {
            // Nothing is special inside '…' except ' itself: close, escape, reopen.
            Self::Bash | Self::Zsh => format!("'{}'", text.replace('\'', r"'\''")),
            // fish: inside '…' only \\ and \' are escapes.
            Self::Fish => format!("'{}'", text.replace('\\', r"\\").replace('\'', r"\'")),
        }
    }

    /// The script `smart-env hook <shell>` prints: defines `_smart_env_hook`,
    /// which runs `<executable> hook-env <shell>` at every prompt and
    /// evaluates its output. Loading it twice registers it once.
    pub fn hook_script(self, executable: &str) -> String {
        let template = match self {
            Self::Bash => BASH_HOOK,
            Self::Zsh => ZSH_HOOK,
            Self::Fish => FISH_HOOK,
        };
        template.replace("@SMART_ENV@", executable)
    }
}

/// Runs first in `PROMPT_COMMAND`; keeps `$?` for the user's prompt. The
/// `smart-env` function runs `activate` / `deactivate` in this shell and
/// passes the state to every other command (for `status`). The
/// state goes to `hook-env` for that one call only, never exported. Saved
/// values stay in the shell. Locals have long names: `eval` must not hit a
/// project variable with the same name.
const BASH_HOOK: &str = r#"_smart_env_hook() {
  local _smart_env_status=$?
  eval "$(SMART_ENV_HOOK_STATE="${_smart_env_state-}" @SMART_ENV@ hook-env bash)"
  return $_smart_env_status
}
_smart_env_save() {
  if [[ -n "${!1+x}" ]]; then
    printf -v "_smart_env_saved_$1" '%s' "${!1}"
  else
    printf -v "_smart_env_unset_$1" '%s' 1
  fi
}
_smart_env_restore() {
  local _smart_env_s="_smart_env_saved_$1" _smart_env_u="_smart_env_unset_$1"
  if [[ -n "${!_smart_env_s+x}" ]]; then
    export "$1=${!_smart_env_s}"
    unset "$_smart_env_s"
  elif [[ -n "${!_smart_env_u+x}" ]]; then
    unset "$1" "$_smart_env_u"
  fi
}
smart-env() {
  case "${1-}" in
    activate|deactivate)
      local _smart_env_out _smart_env_rc
      _smart_env_out="$(SMART_ENV_HOOK_STATE="${_smart_env_state-}" @SMART_ENV@ hook-env bash --"$1" "${@:2}")"
      _smart_env_rc=$?
      eval "$_smart_env_out"
      return $_smart_env_rc
      ;;
    *)
      SMART_ENV_HOOK_STATE="${_smart_env_state-}" @SMART_ENV@ "$@"
      ;;
  esac
}
if [[ ";${PROMPT_COMMAND:-};" != *";_smart_env_hook;"* ]]; then
  PROMPT_COMMAND="_smart_env_hook${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
fi
"#;

/// Runs before every prompt and after every `cd`; keeps `$?`.
const ZSH_HOOK: &str = r#"_smart_env_hook() {
  local _smart_env_status=$?
  eval "$(SMART_ENV_HOOK_STATE="${_smart_env_state-}" @SMART_ENV@ hook-env zsh)"
  return $_smart_env_status
}
_smart_env_save() {
  if (( ${+parameters[$1]} )); then
    typeset -g "_smart_env_saved_$1=${(P)1}"
  else
    typeset -g "_smart_env_unset_$1=1"
  fi
}
_smart_env_restore() {
  local _smart_env_s="_smart_env_saved_$1" _smart_env_u="_smart_env_unset_$1"
  if (( ${+parameters[$_smart_env_s]} )); then
    export "$1=${(P)_smart_env_s}"
    unset "$_smart_env_s"
  elif (( ${+parameters[$_smart_env_u]} )); then
    unset "$1" "$_smart_env_u"
  fi
}
smart-env() {
  case "${1-}" in
    activate|deactivate)
      local _smart_env_out _smart_env_rc
      _smart_env_out="$(SMART_ENV_HOOK_STATE="${_smart_env_state-}" @SMART_ENV@ hook-env zsh --"$1" "${@:2}")"
      _smart_env_rc=$?
      eval "$_smart_env_out"
      return $_smart_env_rc
      ;;
    *)
      SMART_ENV_HOOK_STATE="${_smart_env_state-}" @SMART_ENV@ "$@"
      ;;
  esac
}
typeset -ag precmd_functions chpwd_functions
if (( ! ${precmd_functions[(I)_smart_env_hook]} )); then
  precmd_functions=(_smart_env_hook $precmd_functions)
fi
if (( ! ${chpwd_functions[(I)_smart_env_hook]} )); then
  chpwd_functions=(_smart_env_hook $chpwd_functions)
fi
"#;

/// Event handlers belong to the function: loading again replaces them.
const FISH_HOOK: &str = r#"function _smart_env_hook --on-event fish_prompt
    SMART_ENV_HOOK_STATE="$_smart_env_state" @SMART_ENV@ hook-env fish | source
end
function _smart_env_hook_cd --on-variable PWD
    _smart_env_hook
end
function _smart_env_save
    set -l _smart_env_n $argv[1]
    if set -q $_smart_env_n
        set -g _smart_env_saved_$_smart_env_n $$_smart_env_n
    else
        set -g _smart_env_unset_$_smart_env_n 1
    end
end
function _smart_env_restore
    set -l _smart_env_s _smart_env_saved_$argv[1]
    set -l _smart_env_u _smart_env_unset_$argv[1]
    if set -q $_smart_env_s
        set -gx $argv[1] $$_smart_env_s
        set -e $_smart_env_s
    else if set -q $_smart_env_u
        set -e $argv[1]
        set -e $_smart_env_u
    end
end
function smart-env
    switch "$argv[1]"
        case activate deactivate
            set -l _smart_env_args $argv
            set -e _smart_env_args[1]
            set -l _smart_env_out (SMART_ENV_HOOK_STATE="$_smart_env_state" @SMART_ENV@ hook-env fish --$argv[1] $_smart_env_args)
            set -l _smart_env_rc $status
            string join \n -- $_smart_env_out | source
            return $_smart_env_rc
        case '*'
            SMART_ENV_HOOK_STATE="$_smart_env_state" @SMART_ENV@ $argv
    end
end
"#;

/// Shell code `hook-env` prints for the hook to evaluate. Names are valid
/// variable names (`[A-Za-z_][A-Za-z0-9_]*`), so they need no quoting.
impl Shell {
    /// Remembers the current value of `name` (or that it is unset) in the
    /// shell, then exports `value` literally.
    pub(crate) fn save_and_export(self, name: &str, value: &str) -> String {
        let value = self.quote(value);
        match self {
            Self::Bash | Self::Zsh => format!("_smart_env_save {name}\nexport {name}={value}\n"),
            Self::Fish => format!("_smart_env_save {name}\nset -gx {name} {value}\n"),
        }
    }

    /// Puts back what `name` was before [`Shell::save_and_export`].
    pub(crate) fn restore(self, name: &str) -> String {
        format!("_smart_env_restore {name}\n")
    }

    /// Stores the hook state for the next prompt (not exported).
    pub(crate) fn set_state(self, state: &str) -> String {
        let state = self.quote(state);
        match self {
            Self::Bash | Self::Zsh => format!("_smart_env_state={state}\n"),
            Self::Fish => format!("set -g _smart_env_state {state}\n"),
        }
    }

    /// Forgets the hook state.
    pub(crate) fn clear_state(self) -> String {
        match self {
            Self::Bash | Self::Zsh => "unset _smart_env_state\n".to_owned(),
            Self::Fish => "set -e _smart_env_state\n".to_owned(),
        }
    }
}

impl Shell {
    /// The block `setup` appends to the startup file.
    pub(crate) fn startup_block(self) -> String {
        let load = match self {
            Self::Bash | Self::Zsh => format!("{}\n", self.startup_line()),
            Self::Fish => format!(
                "if status is-interactive; and command -q smart-env\n    {}\nend\n",
                self.startup_line()
            ),
        };
        format!("# smart-env: load project variables on cd (smart-env hook --help)\n{load}")
    }

    /// The line that loads the hook, for messages.
    pub(crate) fn startup_line(self) -> String {
        match self {
            // ~/.profile (bash on macOS) is also read by sh. `if` keeps the
            // file's exit status 0 when the hook is not loaded.
            Self::Bash => "if [ -n \"$BASH_VERSION\" ] && command -v smart-env >/dev/null 2>&1; then eval \"$(smart-env hook bash)\"; fi".to_owned(),
            Self::Zsh => "if command -v smart-env >/dev/null 2>&1; then eval \"$(smart-env hook zsh)\"; fi".to_owned(),
            Self::Fish => "smart-env hook fish | source".to_owned(),
        }
    }
}
