use std::ffi::OsString;
use std::io::Write;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::{EnvRef, Exit};

/// `smart-env` command line.
#[derive(Debug, Parser)]
#[command(
    name = "smart-env",
    version,
    about = "Sekrety projektu bez plików .env"
)]
pub struct Cli {
    /// Flags accepted by every command.
    #[command(flatten)]
    pub global: GlobalArgs,
    /// Command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Flags accepted before or after any command.
#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// `<environment>` or `<project>/<environment>`.
    #[arg(long, global = true, value_name = "[PROJEKT/]ŚRODOWISKO")]
    pub env: Option<EnvRef>,
    /// Machine-readable output, errors included.
    #[arg(long, global = true)]
    pub json: bool,
    /// Answer "yes" to every confirmation (non-interactive mode).
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,
}

/// `--inject` value of `set`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum InjectArg {
    /// Shell hook and `run`.
    Shell,
    /// Only `smart-env run`.
    Run,
}

/// Commands of step 2 (Stage 1). Behaviour comes with each checklist item.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Once per machine: device key, vault, recovery key.
    Setup,
    /// Import `.env` files of the current project.
    Init,
    /// Store a variable; the value comes from a prompt or `--stdin`, never an argument.
    Set {
        /// Variable name.
        name: String,
        /// Read the value from stdin.
        #[arg(long)]
        stdin: bool,
        /// Where the variable is injected.
        #[arg(long, value_enum)]
        inject: Option<InjectArg>,
    },
    /// List variables (names only).
    Ls,
    /// Remove a variable (undoable).
    Rm {
        /// Variable name.
        name: String,
    },
    /// Rename a variable.
    Rename {
        /// Current name.
        from: String,
        /// New name.
        to: String,
    },
    /// Versions of a variable, without values.
    History {
        /// Variable name.
        name: String,
    },
    /// Restore the previous version or a removed variable.
    Undo {
        /// Variable name.
        name: String,
    },
    /// Run a command with the environment's variables.
    Run {
        /// Only these variables.
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        /// All variables except these.
        #[arg(long, value_delimiter = ',')]
        except: Vec<String>,
        /// Command and its arguments, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Unlock the key file until the session expires (machines without a keychain).
    Unlock,
    /// Forget the unlocked key.
    Lock,
}

/// Runs the CLI with `args` (program name first) and returns the exit code.
///
/// Normal output goes to `out`. Errors go to `err` as `✗ …`, or to `out` as
/// JSON with `--json` — also when the arguments themselves are wrong.
/// `stdin_is_tty` decides interactive mode together with `--yes`.
pub fn execute<I, T>(
    _args: I,
    _stdin_is_tty: bool,
    _out: &mut dyn Write,
    _err: &mut dyn Write,
) -> Exit
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    todo!("F06 11: dispatch and error reporting")
}
