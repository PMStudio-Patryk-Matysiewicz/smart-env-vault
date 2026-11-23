//! `smart-env` command line: parser, global flags, exit codes and error
//! reporting shared by every command ([[05 - Kontrakt DX]], F06 11).
//!
//! Entry point: [`execute`]. `main` only wires real stdio to it, so the whole
//! CLI is testable in-process.
#![forbid(unsafe_code)]

mod cli;
mod context;
mod env_ref;
mod error;
mod exit;
mod interaction;
mod keys;
mod lock;
mod project_file;
mod setup;

pub use cli::{Cli, Command, GlobalArgs, InjectArg, execute};
pub use context::{Context, System, Terminal, UNLOCK_TTL};
pub use env_ref::{EnvRef, EnvRefError};
pub use error::CliError;
pub use exit::Exit;
pub use interaction::Interaction;
pub use keys::device_key;
pub use project_file::{FILE_NAME, ProjectFile, ProjectFileError, ResolvedProject};
