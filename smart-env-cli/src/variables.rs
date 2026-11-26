//! `set`, `ls`, `rm` and `rename`: everyday work with variables of one
//! environment ([[05 - Kontrakt DX]] Scenarios 2 and 10).
//!
//! A value is never a command-line argument: `set` reads it from a prompt
//! without echo or from stdin (`--stdin`, one trailing newline cut), and no
//! command prints it. `ls`, `rm` and `rename` work without the device key.

use std::io::{Read, Write};

use secrecy::ExposeSecret;
use serde_json::json;
use smart_env_vault::{
    EnvironmentId, Event, EventMeta, HistoryEntry, Inject, MAX_VALUE_LEN, Operation, SecretError,
    SecretValue, Undone, VarName, Vault, VaultError, VersionMeta,
};
use zeroize::Zeroizing;

use crate::keys::device_key;
use crate::reserved::is_reserved;
use crate::target::{self, Target};
use crate::{CliError, Context, EnvRef, Exit, InjectArg};

/// `smart-env set NAME [--stdin] [--inject shell|run]`.
///
/// Checks the name, the environment and the device key before reading the
/// value, so nobody types a secret only to see an error.
pub(crate) fn set(
    ctx: &mut Context<'_>,
    json: bool,
    env: Option<&EnvRef>,
    name: &str,
    stdin: bool,
    inject: Option<InjectArg>,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let name = parse_name(name)?;
    let (mut vault, target) = target::resolve(ctx, env)?;
    let key = device_key(ctx)?;
    let value = if stdin {
        read_stdin(ctx)?
    } else {
        prompt(ctx, &name)?
    };

    let inject = inject.map(|inject| match inject {
        InjectArg::Shell => Inject::Shell,
        InjectArg::Run => Inject::Run,
    });
    let env_id = target.environment.id;
    let outcome = vault.set_with(env_id, &name, &value, inject, &key)?;
    let inject = vault
        .list(env_id)?
        .into_iter()
        .find(|meta| meta.key_id == outcome.key_id)
        .map_or(Inject::Shell, |meta| meta.inject);

    let reserved = is_reserved(name.as_str());
    let warnings = warnings(&target, reserved.then_some(&name));
    let label = target.label();
    if json {
        print_json(
            out,
            json!({
                "status": "saved",
                "project": target.project,
                "environment": target.environment.name,
                "name": name.as_str(),
                "version": outcome.version,
                "inject": inject_str(inject),
                "reserved": reserved,
                "warnings": warnings,
            }),
        );
    } else {
        let run_only = if inject == Inject::Run {
            ", smart-env run only, not exported to the shell"
        } else {
            ""
        };
        print_warnings(out, &warnings);
        let _ = writeln!(
            out,
            "✓ {name} saved in {label} (version {}{run_only})",
            outcome.version
        );
    }
    Ok(Exit::Success)
}

/// `smart-env ls`: names with markers (`run only`, `reserved`), no values.
pub(crate) fn ls(
    ctx: &mut Context<'_>,
    json: bool,
    env: Option<&EnvRef>,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let (vault, target) = target::resolve(ctx, env)?;
    let metas = vault.list(target.environment.id)?;
    let warnings = warnings(&target, None);

    if json {
        let variables: Vec<_> = metas
            .iter()
            .map(|meta| {
                json!({
                    "name": meta.name.as_str(),
                    "version": meta.version,
                    "inject": inject_str(meta.inject),
                    "reserved": is_reserved(meta.name.as_str()),
                    "updated_at": meta.updated_at,
                })
            })
            .collect();
        print_json(
            out,
            json!({
                "project": target.project,
                "environment": target.environment.name,
                "variables": variables,
                "warnings": warnings,
            }),
        );
        return Ok(Exit::Success);
    }

    print_warnings(out, &warnings);
    let label = target.label();
    if metas.is_empty() {
        let _ = writeln!(out, "{label} (no variables)\nAdd one: smart-env set NAME");
        return Ok(Exit::Success);
    }
    let _ = writeln!(out, "{label} ({})", count(metas.len(), "variable"));
    let width = metas
        .iter()
        .map(|meta| meta.name.as_str().len())
        .max()
        .unwrap_or(0);
    for meta in &metas {
        let name = meta.name.as_str();
        let mut markers = Vec::new();
        if meta.inject == Inject::Run {
            markers.push("run only");
        }
        if is_reserved(name) {
            markers.push("reserved");
        }
        let _ = if markers.is_empty() {
            writeln!(out, "  {name}")
        } else {
            writeln!(out, "  {name:<width$}  {}", markers.join(", "))
        };
    }
    Ok(Exit::Success)
}

/// `smart-env rm NAME`: soft delete without asking; `undo` brings it back.
pub(crate) fn rm(
    ctx: &mut Context<'_>,
    json: bool,
    env: Option<&EnvRef>,
    name: &str,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let name = parse_name(name)?;
    let (mut vault, target) = target::resolve(ctx, env)?;
    if !vault.remove(target.environment.id, &name)? {
        return Err(VaultError::SecretNotFound.into());
    }

    let warnings = warnings(&target, None);
    if json {
        print_json(
            out,
            json!({
                "status": "removed",
                "project": target.project,
                "environment": target.environment.name,
                "name": name.as_str(),
                "warnings": warnings,
            }),
        );
    } else {
        print_warnings(out, &warnings);
        let _ = writeln!(
            out,
            "✓ Removed {name} from {} (undo: smart-env undo {name}{})",
            target.label(),
            env_flag(env)
        );
    }
    Ok(Exit::Success)
}

/// `smart-env rename FROM TO`: only the label changes, value and version
/// stay.
pub(crate) fn rename(
    ctx: &mut Context<'_>,
    json: bool,
    env: Option<&EnvRef>,
    from: &str,
    to: &str,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let from = parse_name(from)?;
    let to = parse_name(to)?;
    if from == to {
        return Err(CliError::new(
            "same_name",
            Exit::Usage,
            format!("{from} already has this name; nothing to rename."),
        )
        .with_hint("Give a different new name: smart-env rename FROM TO"));
    }
    let (mut vault, target) = target::resolve(ctx, env)?;
    vault.rename(target.environment.id, &from, &to)?;

    let reserved = is_reserved(to.as_str());
    let warnings = warnings(&target, reserved.then_some(&to));
    if json {
        print_json(
            out,
            json!({
                "status": "renamed",
                "project": target.project,
                "environment": target.environment.name,
                "from": from.as_str(),
                "to": to.as_str(),
                "reserved": reserved,
                "warnings": warnings,
            }),
        );
    } else {
        print_warnings(out, &warnings);
        let _ = writeln!(
            out,
            "✓ Renamed {from} to {to} in {} (undo: smart-env undo {to}{})",
            target.label(),
            env_flag(env)
        );
    }
    Ok(Exit::Success)
}

/// `smart-env history NAME`: versions newest first with UTC times, never
/// values; works without the device key.
pub(crate) fn history(
    ctx: &mut Context<'_>,
    json: bool,
    env: Option<&EnvRef>,
    name: &str,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let name = parse_name(name)?;
    let (vault, target) = target::resolve(ctx, env)?;
    let timeline = vault
        .timeline(target.environment.id, &name)
        .map_err(|error| match error {
            VaultError::SecretNotFound => {
                renamed_hint(&vault, target.environment.id, &name, "history", env)
                    .unwrap_or_else(|| error.into())
            }
            error => error.into(),
        })?;
    let versions: Vec<&VersionMeta> = timeline
        .entries
        .iter()
        .filter_map(|entry| match entry {
            HistoryEntry::Version(meta) => Some(meta),
            HistoryEntry::Event(_) => None,
        })
        .collect();
    let events: Vec<&EventMeta> = timeline
        .entries
        .iter()
        .filter_map(|entry| match entry {
            HistoryEntry::Event(meta) => Some(meta),
            HistoryEntry::Version(_) => None,
        })
        .collect();
    // The newest version is current unless the variable is removed.
    let newest = versions.first().map_or(0, |meta| meta.version);
    let current = (!timeline.removed).then_some(newest);

    let warnings = warnings(&target, None);
    if json {
        let versions: Vec<_> = versions
            .iter()
            .map(|meta| {
                let (operation, restored_version) = match meta.operation {
                    Operation::Import => ("import", None),
                    Operation::Set => ("set", None),
                    Operation::Undo { restored } => ("undo", Some(restored)),
                    Operation::Unknown => ("unknown", None),
                };
                json!({
                    "version": meta.version,
                    "created_at": meta.created_at,
                    "operation": operation,
                    "restored_version": restored_version,
                    "current": current == Some(meta.version),
                })
            })
            .collect();
        let events: Vec<_> = events
            .iter()
            .map(|meta| {
                let (kind, from, to) = match &meta.event {
                    Event::Rename { from, to } => {
                        ("rename", Some(from.as_str()), Some(to.as_str()))
                    }
                    Event::Remove => ("remove", None, None),
                    Event::Restore => ("restore", None, None),
                };
                json!({
                    "at": meta.at,
                    "after_version": meta.after_version,
                    "kind": kind,
                    "from": from,
                    "to": to,
                })
            })
            .collect();
        print_json(
            out,
            json!({
                "project": target.project,
                "environment": target.environment.name,
                "name": name.as_str(),
                "removed": timeline.removed,
                "versions": versions,
                "events": events,
                "warnings": warnings,
            }),
        );
        return Ok(Exit::Success);
    }

    print_warnings(out, &warnings);
    let state = if timeline.removed {
        format!("removed, last value: version {newest}")
    } else {
        format!("current value: version {newest}")
    };
    let _ = writeln!(out, "{name} in {} ({state})", target.label());
    let width = versions
        .iter()
        .map(|meta| meta.version.to_string().len())
        .max()
        .unwrap_or(1);
    for entry in &timeline.entries {
        let _ = match entry {
            HistoryEntry::Version(meta) => {
                let operation = operation_text(meta.operation);
                writeln!(
                    out,
                    "  {:>width$}  {} UTC  {operation}",
                    meta.version, meta.created_at
                )
            }
            HistoryEntry::Event(meta) => {
                let text = match &meta.event {
                    Event::Rename { from, to } => format!("renamed {from} → {to}"),
                    Event::Remove => "removed".to_owned(),
                    Event::Restore => "restored".to_owned(),
                };
                writeln!(out, "  {:>width$}  {} UTC  {text}", "", meta.at)
            }
        };
    }
    if timeline.removed {
        let _ = writeln!(out, "Restore: smart-env undo {name}{}", env_flag(env));
    } else if timeline.entries.len() > 1 {
        let _ = writeln!(
            out,
            "Undo the last change: smart-env undo {name}{}",
            env_flag(env)
        );
    }
    Ok(Exit::Success)
}

/// `import`, `set`, `undo → N`, `unknown`.
fn operation_text(operation: Operation) -> String {
    match operation {
        Operation::Import => "import".to_owned(),
        Operation::Set => "set".to_owned(),
        Operation::Undo { restored } => format!("undo → {restored}"),
        Operation::Unknown => "unknown".to_owned(),
    }
}

/// `smart-env undo NAME [--to VERSION]`: brings back a removed variable, or
/// writes the previous value (or that of `--to`) as a new version. Needs the
/// device key; never asks.
pub(crate) fn undo(
    ctx: &mut Context<'_>,
    json: bool,
    env: Option<&EnvRef>,
    name: &str,
    to: Option<u32>,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let name = parse_name(name)?;
    let (mut vault, target) = target::resolve(ctx, env)?;
    let key = device_key(ctx)?;
    let env_id = target.environment.id;

    let undone = match to {
        Some(to) => {
            let version = vault
                .restore(env_id, &name, to, &key)
                .map_err(|error| match error {
                    VaultError::VersionNotFound => CliError::from(error).with_hint(format!(
                        "Versions: smart-env history {name}{}",
                        env_flag(env)
                    )),
                    VaultError::SecretNotFound => renamed_hint(&vault, env_id, &name, "undo", env)
                        .unwrap_or_else(|| {
                            CliError::from(error).with_hint(format!(
                                "A removed variable comes back first with: smart-env undo {name}{}",
                                env_flag(env)
                            ))
                        }),
                    error => error.into(),
                })?;
            Undone::Value {
                version,
                restored: to,
            }
        }
        None => vault
            .undo_last(env_id, &name, &key)
            .map_err(|error| match error {
                VaultError::SecretNotFound => {
                    renamed_hint(&vault, env_id, &name, "undo", env).unwrap_or_else(|| error.into())
                }
                error => error.into(),
            })?,
    };

    let warnings = warnings(&target, None);
    let label = target.label();
    let base = json!({
        "project": target.project,
        "environment": target.environment.name,
        "warnings": warnings,
    });
    let (report, line) = match &undone {
        Undone::Value { version, restored } => (
            json!({
                "status": "restored",
                "undone": "value",
                "name": name.as_str(),
                "version": version,
                "restored_version": restored,
                "was_removed": false,
            }),
            format!(
                "✓ {name} restored to version {restored} in {label} (saved as version {version})"
            ),
        ),
        Undone::Removal { version } => (
            json!({
                "status": "restored",
                "undone": "remove",
                "name": name.as_str(),
                "version": version,
                "restored_version": null,
                "was_removed": true,
            }),
            format!("✓ {name} restored in {label} (version {version})"),
        ),
        Undone::Restore => (
            json!({
                "status": "removed",
                "undone": "restore",
                "name": name.as_str(),
            }),
            format!(
                "✓ Undid restore: {name} removed again from {label} (undo: smart-env undo {name}{})",
                env_flag(env)
            ),
        ),
        Undone::Rename { from, to } => (
            json!({
                "status": "renamed",
                "undone": "rename",
                "from": from.as_str(),
                "to": to.as_str(),
            }),
            format!("✓ Undid rename: {from} is {to} again in {label}"),
        ),
    };
    if json {
        let mut report = report;
        if let (Some(report), Some(base)) = (report.as_object_mut(), base.as_object()) {
            report.extend(base.clone());
        }
        print_json(out, report);
    } else {
        print_warnings(out, &warnings);
        let _ = writeln!(out, "{line}");
    }
    Ok(Exit::Success)
}

// --- value input ---

/// Whole stdin with exactly one trailing `\n` (or `\r\n`) cut. Reads at most
/// a few bytes past the limit, so a huge pipe is not buffered.
fn read_stdin(ctx: &mut Context<'_>) -> Result<SecretValue, CliError> {
    let mut bytes = Zeroizing::new(Vec::new());
    ctx.stdin
        .as_mut()
        .take(MAX_VALUE_LEN as u64 + 3)
        .read_to_end(&mut bytes)
        .map_err(|_| stdin_unreadable())?;
    let len = bytes.len();
    if bytes.ends_with(b"\r\n") {
        bytes.truncate(len - 2);
    } else if bytes.ends_with(b"\n") {
        bytes.truncate(len - 1);
    }
    if bytes.len() > MAX_VALUE_LEN {
        return Err(VaultError::Secret(SecretError::ValueTooLarge).into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| value_not_utf8())?;
    SecretValue::new(text.to_owned()).map_err(|error| VaultError::Secret(error).into())
}

/// One hidden question on the terminal; an empty answer is refused.
fn prompt(ctx: &mut Context<'_>, name: &VarName) -> Result<SecretValue, CliError> {
    let terminal = ctx
        .terminal
        .as_deref_mut()
        .ok_or_else(|| value_required(name))?;
    let answer = terminal
        .ask_secret(&format!("? Value for {name} (input hidden): "))
        .map_err(|_| value_required(name))?;
    if answer.expose_secret().is_empty() {
        return Err(empty_value(name));
    }
    SecretValue::new(answer.expose_secret().to_owned())
        .map_err(|error| VaultError::Secret(error).into())
}

// --- helpers ---

fn parse_name(name: &str) -> Result<VarName, CliError> {
    VarName::parse(name).map_err(|error| VaultError::Secret(error).into())
}

/// `secret_not_found` saying what `name` was renamed to and how to run
/// `smart-env <command>` with the new name; `None` if it was not renamed.
fn renamed_hint(
    vault: &Vault,
    env_id: EnvironmentId,
    name: &VarName,
    command: &str,
    env: Option<&EnvRef>,
) -> Option<CliError> {
    let renamed = vault.renamed_to(env_id, name).ok()??;
    Some(
        CliError::new(
            "secret_not_found",
            Exit::NotFound,
            format!("{name} was renamed to {renamed}."),
        )
        .with_hint(format!(
            "Use the new name: smart-env {command} {renamed}{}",
            env_flag(env)
        )),
    )
}

/// ` --env <as typed>` when `--env` was given, for hints that repeat a
/// command.
fn env_flag(env: Option<&EnvRef>) -> String {
    env.map_or_else(String::new, |env| match &env.project {
        Some(project) => format!(" --env {project}/{}", env.environment),
        None => format!(" --env {}", env.environment),
    })
}

fn inject_str(inject: Inject) -> &'static str {
    match inject {
        Inject::Shell => "shell",
        Inject::Run => "run",
    }
}

/// The target's warnings plus the reserved-name warning for `reserved`.
fn warnings(target: &Target, reserved: Option<&VarName>) -> Vec<String> {
    let mut warnings = target.warnings.clone();
    if let Some(name) = reserved {
        warnings.push(format!(
            "{name} is a reserved name. The shell hook skips it until allowed: smart-env allow --var {name}"
        ));
    }
    warnings
}

fn print_warnings(out: &mut dyn Write, warnings: &[String]) {
    for warning in warnings {
        let _ = writeln!(out, "! {warning}");
    }
}

fn print_json(out: &mut dyn Write, value: serde_json::Value) {
    let _ = writeln!(out, "{value}");
}

/// `1 variable`, `2 variables`.
fn count(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

// --- errors ---

fn value_required(name: &VarName) -> CliError {
    CliError::new(
        "value_required",
        Exit::Usage,
        "No value: there is no terminal to ask and --stdin was not given.",
    )
    .with_hint(format!("Pipe the value: … | smart-env set {name} --stdin"))
}

fn empty_value(name: &VarName) -> CliError {
    CliError::new(
        "empty_value",
        Exit::Usage,
        "No value entered; nothing was saved.",
    )
    .with_hint(format!(
        "To store an empty value: printf '' | smart-env set {name} --stdin"
    ))
}

fn value_not_utf8() -> CliError {
    CliError::new(
        "value_not_utf8",
        Exit::Usage,
        "The value is not valid UTF-8; nothing was saved.",
    )
    .with_hint("smart-env stores text; encode binary data first, e.g. base64")
}

fn stdin_unreadable() -> CliError {
    CliError::new(
        "stdin_unreadable",
        Exit::Failure,
        "Could not read the value from stdin; nothing was saved.",
    )
    .with_hint("Pipe the value: … | smart-env set NAME --stdin")
}
