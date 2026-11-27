//! `smart-env run [--only A,B | --except C] -- <command>`: starts the command
//! with the environment's variables added to its environment, and exits with
//! its exit code ([[05 - Kontrakt DX]] Scenario 1 without the hook, F06 4).
//!
//! Variables reach only the command, never its arguments, and never the
//! shell. Reserved names (ADR-005) are skipped with a warning unless
//! allowed at their current version (`smart-env allow --var`). stdout belongs
//! to the command: `run` writes nothing there; warnings go to stderr.

use std::collections::BTreeSet;
use std::io::{self, Write};

use secrecy::SecretString;
use smart_env_vault::{SecretError, VarName, VaultError};

use crate::keys::device_key;
use crate::reserved::{Consent, consent, is_reserved};
use crate::variables::env_flag;
use crate::{ChildCommand, CliError, Context, EnvRef, Exit, target};

/// Runs `command` (program and arguments) with the variables of the
/// environment chosen by `env`.
///
/// Checks everything (environment, key, `--only` / `--except` names) before
/// starting anything.
pub(crate) fn run(
    ctx: &mut Context<'_>,
    env: Option<&EnvRef>,
    only: &[String],
    except: &[String],
    command: &[String],
    err: &mut dyn Write,
) -> Result<Exit, CliError> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| CliError::usage("Missing command after --."))?;
    let only = parse_names(only)?;
    let except = parse_names(except)?;

    let (vault, target) = target::resolve(ctx, env)?;
    let key = device_key(ctx)?;
    let variables = vault.read_all(target.environment.id, &key)?;

    // A name in --only / --except that is not there is most likely a typo;
    // with --except it would pass a variable the user meant to hold back.
    let present: BTreeSet<&str> = variables
        .iter()
        .map(|(meta, _)| meta.name.as_str())
        .collect();
    let unknown: Vec<&str> = only
        .iter()
        .chain(&except)
        .map(VarName::as_str)
        .filter(|name| !present.contains(name))
        .collect();
    if !unknown.is_empty() {
        return Err(CliError::new(
            "secret_not_found",
            Exit::NotFound,
            format!("Not in {}: {}.", target.label(), unknown.join(", ")),
        )
        .with_hint(format!("List variables: smart-env ls{}", env_flag(env))));
    }

    // Consent for reserved names lives in state.db (smart-env allow --var).
    let state = ctx.data.as_ref().and_then(|data| data.state().ok());
    let mut skipped = Vec::new();
    let mut changed = Vec::new();
    let mut child_env = Vec::new();
    for (meta, value) in variables {
        let name = meta.name.as_str();
        if (!only.is_empty() && !only.contains(&meta.name)) || except.contains(&meta.name) {
            continue;
        }
        if is_reserved(name) {
            match consent(state.as_ref(), target.environment.id, &meta) {
                Consent::Current => {}
                Consent::Stale => {
                    changed.push(name.to_owned());
                    continue;
                }
                Consent::Missing => {
                    skipped.push(name.to_owned());
                    continue;
                }
            }
        }
        child_env.push((
            name.to_owned(),
            SecretString::from(value.expose().to_owned()),
        ));
    }

    for warning in &target.warnings {
        let _ = writeln!(err, "! {warning}");
    }
    match skipped.as_slice() {
        [] => {}
        [name] => {
            let _ = writeln!(
                err,
                "! {name} is a reserved name and was not passed. Allow it with: smart-env allow --var {name}"
            );
        }
        names => {
            let _ = writeln!(
                err,
                "! {} are reserved names and were not passed. Allow one with: smart-env allow --var NAME",
                names.join(", ")
            );
        }
    }
    for name in &changed {
        let _ = writeln!(
            err,
            "! {name} changed since you allowed it and was not passed. Allow the new value with: smart-env allow --var {name}"
        );
    }
    let _ = err.flush();

    let child = ChildCommand {
        program: program.into(),
        args: args.iter().map(Into::into).collect(),
        env: child_env,
    };
    match ctx.runner.run(child) {
        Ok(0) => Ok(Exit::Success),
        Ok(code) => Ok(Exit::Child(code)),
        Err(error) => Err(start_failed(program, &error)),
    }
}

fn parse_names(names: &[String]) -> Result<Vec<VarName>, CliError> {
    names
        .iter()
        .map(|name| {
            VarName::parse(name).map_err(|_| VaultError::Secret(SecretError::InvalidName).into())
        })
        .collect()
}

/// 127 / 126 like a shell, so `smart-env run -- cmd || …` behaves the same.
fn start_failed(program: &str, error: &io::Error) -> CliError {
    match error.kind() {
        io::ErrorKind::NotFound => CliError::new(
            "command_not_found",
            Exit::Child(127),
            format!("Command not found: {program}."),
        )
        .with_hint("Check the name, or that it is installed and in PATH"),
        io::ErrorKind::PermissionDenied => CliError::new(
            "command_not_executable",
            Exit::Child(126),
            format!("Command cannot be executed: {program}."),
        )
        .with_hint(format!("Check that it is executable: chmod +x {program}")),
        _ => CliError::new(
            "command_failed",
            Exit::Failure,
            format!("Could not start {program}."),
        )
        .with_hint("Check the command and try again"),
    }
}
