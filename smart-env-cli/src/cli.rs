use std::ffi::OsString;
use std::io::Write;

use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::{
    CliError, Context, EnvRef, Exit, Interaction, Shell, hook, init, lock, reserved, run, setup,
    status, trust, variables,
};

/// `smart-env` command line.
#[derive(Debug, Parser)]
#[command(
    name = "smart-env",
    version,
    about = "Project secrets without .env files"
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
    #[arg(long, global = true, value_name = "[PROJECT/]ENVIRONMENT")]
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

/// `on` / `off` switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OnOff {
    /// Enabled.
    On,
    /// Disabled.
    Off,
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
    /// Undo the last change of a variable (value, rename, removal or restore).
    Undo {
        /// Variable name.
        name: String,
        /// Restore this version from `smart-env history` instead of the
        /// previous one.
        #[arg(long, value_name = "VERSION", value_parser = clap::value_parser!(u32).range(1..))]
        to: Option<u32>,
    },
    /// Run a command with the environment's variables.
    Run {
        /// Only these variables.
        #[arg(long, value_delimiter = ',', conflicts_with = "except")]
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
    /// Let the shell hook load this project here (until smart-env.toml changes),
    /// or pass a variable with a reserved name (--var).
    Allow {
        /// Project directory (default: the current one).
        dir: Option<std::path::PathBuf>,
        /// Reserved name to pass (shows its value and asks).
        #[arg(long, value_name = "NAME", conflicts_with = "dir")]
        var: Option<String>,
    },
    /// Never let the shell hook load this project here, or stop passing a
    /// reserved name (--var).
    Deny {
        /// Project directory (default: the current one).
        dir: Option<std::path::PathBuf>,
        /// Reserved name to stop passing.
        #[arg(long, value_name = "NAME", conflicts_with = "dir")]
        var: Option<String>,
    },
    /// Shell integration script; `setup` adds it to the shell's startup file.
    Hook {
        /// Shell to print the script for.
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Called by the shell hook at every prompt, and by the shell function
    /// for `activate` / `deactivate`.
    #[command(name = "hook-env", hide = true)]
    HookEnv {
        /// Shell the output is for.
        #[arg(value_enum)]
        shell: Shell,
        /// Activate the environment explicitly (`smart-env activate`).
        #[arg(long, conflicts_with = "deactivate")]
        activate: bool,
        /// Deactivate (`smart-env deactivate`).
        #[arg(long)]
        deactivate: bool,
    },
    /// Load the environment's variables into this shell until deactivate.
    Activate,
    /// Put back the variables from before the activation.
    Deactivate,
    /// Turn loading on cd on or off on this device.
    #[command(name = "auto-activate")]
    AutoActivate {
        /// on or off.
        #[arg(value_enum)]
        mode: OnOff,
    },
    /// What is active in this shell and why something is not.
    Status,
}

impl Command {
    /// Name as typed on the command line.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Init => "init",
            Self::Set { .. } => "set",
            Self::Ls => "ls",
            Self::Rm { .. } => "rm",
            Self::Rename { .. } => "rename",
            Self::History { .. } => "history",
            Self::Undo { .. } => "undo",
            Self::Run { .. } => "run",
            Self::Unlock => "unlock",
            Self::Lock => "lock",
            Self::Allow { .. } => "allow",
            Self::Deny { .. } => "deny",
            Self::Hook { .. } => "hook",
            Self::HookEnv { .. } => "hook-env",
            Self::Activate => "activate",
            Self::Deactivate => "deactivate",
            Self::AutoActivate { .. } => "auto-activate",
            Self::Status => "status",
        }
    }
}

/// Runs the CLI with `args` (program name first) and returns the exit code.
///
/// Normal output goes to `out`. Errors go to `err` as `✗ …`, or to `out` as
/// JSON with `--json`, also when the arguments themselves are wrong.
/// Whether there is a terminal in `ctx` decides interactive mode together
/// with `--yes`.
pub fn execute<I, T>(
    args: I,
    ctx: &mut Context<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Exit
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let json = json_requested(&args);
    let result = match Cli::try_parse_from(&args) {
        Ok(cli) => {
            let interaction = Interaction::detect(cli.global.yes, ctx.terminal.is_some());
            dispatch(&cli, ctx, interaction, json, out, err)
        }
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            // Output errors (closed pipe) cannot be reported anywhere better.
            let _ = write!(out, "{}", error.render());
            Ok(Exit::Success)
        }
        Err(error) => Err(usage_error(&error)),
    };
    match result {
        Ok(exit) => exit,
        Err(error) => {
            let _ = if json {
                writeln!(out, "{}", error.render_json())
            } else {
                write!(err, "{}", error.render_human())
            };
            error.exit()
        }
    }
}

/// `--json` anywhere before `--`, so it also applies when parsing fails.
fn json_requested(args: &[OsString]) -> bool {
    args.iter()
        .skip(1)
        .take_while(|arg| *arg != "--")
        .any(|arg| arg == "--json")
}

/// Runs the parsed command.
fn dispatch(
    cli: &Cli,
    ctx: &mut Context<'_>,
    interaction: Interaction,
    json: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<Exit, CliError> {
    let env = cli.global.env.as_ref();
    match &cli.command {
        Command::Setup => setup::run(ctx, interaction, json, out),
        Command::Init => init::run(ctx, interaction, json, env, out),
        Command::Set {
            name,
            stdin,
            inject,
        } => variables::set(ctx, json, env, name, *stdin, *inject, out),
        Command::Ls => variables::ls(ctx, json, env, out),
        Command::Rm { name } => variables::rm(ctx, json, env, name, out),
        Command::Rename { from, to } => variables::rename(ctx, json, env, from, to, out),
        Command::History { name } => variables::history(ctx, json, env, name, out),
        Command::Undo { name, to } => variables::undo(ctx, json, env, name, *to, out),
        Command::Run {
            only,
            except,
            command,
        } => run::run(ctx, env, only, except, command, err),
        Command::Unlock => lock::unlock(ctx, json, out),
        Command::Lock => lock::lock(ctx, json, out),
        Command::Allow {
            var: Some(name), ..
        } => reserved::allow_var(ctx, json, env, name, out),
        Command::Allow { dir, var: None } => trust::allow(ctx, json, dir.as_deref(), out),
        Command::Deny {
            var: Some(name), ..
        } => reserved::deny_var(ctx, json, env, name, out),
        Command::Deny { dir, var: None } => trust::deny(ctx, json, dir.as_deref(), out),
        Command::Hook { shell } => hook::hook(ctx, *shell, out),
        Command::HookEnv {
            shell,
            activate: true,
            ..
        } => hook::activate(ctx, *shell, env, out, err),
        Command::HookEnv {
            shell,
            deactivate: true,
            ..
        } => hook::deactivate(ctx, *shell, out, err),
        Command::HookEnv { shell, .. } => Ok(hook::hook_env(ctx, *shell, out, err)),
        Command::Activate | Command::Deactivate => {
            Err(hook::shell_function_required(cli.command.name()))
        }
        Command::AutoActivate { mode } => hook::auto_activate(ctx, json, *mode == OnOff::On, out),
        Command::Status => status::status(ctx, json, out),
    }
}

/// Describes a parse error without repeating what the user typed: an
/// unexpected argument may be a pasted secret. Only names of our own
/// arguments are quoted.
fn usage_error(error: &clap::Error) -> CliError {
    let own_arg = || match error.get(ContextKind::InvalidArg) {
        Some(ContextValue::String(arg)) => format!(": {arg}"),
        Some(ContextValue::Strings(args)) => format!(": {}", args.join(", ")),
        _ => String::new(),
    };
    let message = match error.kind() {
        ErrorKind::InvalidSubcommand => "Unknown command.".to_owned(),
        ErrorKind::UnknownArgument => "Unexpected argument.".to_owned(),
        ErrorKind::MissingSubcommand | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            "Missing command.".to_owned()
        }
        ErrorKind::MissingRequiredArgument => format!("Missing required argument{}", own_arg()),
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => {
            format!("Invalid value{}", own_arg())
        }
        ErrorKind::ArgumentConflict => format!("Conflicting arguments{}", own_arg()),
        ErrorKind::TooManyValues | ErrorKind::WrongNumberOfValues => {
            format!("Wrong number of values{}", own_arg())
        }
        _ => "Invalid usage.".to_owned(),
    };
    CliError::usage(message)
}
