//! Reserved variable names (ADR-005): variables that change how tools behave
//! rather than the application. The shell hook and `run` skip them until
//! allowed on this device (`smart-env allow --var`); `init` and `set` warn
//! about them.

use std::io::Write;

use serde_json::json;
use smart_env_vault::{
    EnvironmentId, SecretError, SecretMeta, StateStore, VarConsent, VarName, VaultError,
};

use crate::keys::device_key;
use crate::trust::state_error;
use crate::{CliError, Context, EnvRef, Exit, target};

/// Whether `name` is reserved: an exact name from the ADR-005 list or a
/// reserved prefix (`DYLD_`, `GIT_`, `SMART_ENV_`), ignoring case.
pub(crate) fn is_reserved(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    EXACT.contains(&name.as_str()) || PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

/// Exact names from ADR-005, upper case.
const EXACT: &[&str] = &[
    // loading code
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    // shell and paths
    "PATH",
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
    "PROMPT_COMMAND",
    "SHELLOPTS",
    "IFS",
    "HOME",
    // interpreter options
    "NODE_OPTIONS",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PERL5OPT",
    "RUBYOPT",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    // tools
    "EDITOR",
    "VISUAL",
    "PAGER",
    "SSH_AUTH_SOCK",
    // network and certificates
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
];

/// Reserved prefixes from ADR-005, upper case.
const PREFIXES: &[&str] = &["DYLD_", "GIT_", "SMART_ENV_"];

/// Whether a reserved name may be passed, from the consent stored on this
/// device and the secret's current version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Consent {
    /// Allowed at the current version.
    Current,
    /// Allowed at an older value; the current one was never seen.
    Stale,
    /// Never allowed.
    Missing,
}

/// The consent for `meta` in `env`. A state database that cannot be read
/// counts as no consent: nothing reserved is passed by mistake.
pub(crate) fn consent(
    state: Option<&StateStore>,
    env: EnvironmentId,
    meta: &SecretMeta,
) -> Consent {
    match state.and_then(|state| state.var_consent(env, &meta.name).ok().flatten()) {
        Some(consent) if consent == current(meta) => Consent::Current,
        Some(_) => Consent::Stale,
        None => Consent::Missing,
    }
}

fn current(meta: &SecretMeta) -> VarConsent {
    VarConsent {
        key_id: meta.key_id,
        version: meta.version,
    }
}

/// `smart-env allow --var NAME`: shows the value on the terminal and, after
/// a "yes", lets `run` (and later the hook) pass this reserved name at its
/// current version.
pub(crate) fn allow_var(
    ctx: &mut Context<'_>,
    json: bool,
    env: Option<&EnvRef>,
    name: &str,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let name = reserved_name(name)?;
    let (vault, target) = target::resolve(ctx, env)?;
    let label = target.label();
    let env_id = target.environment.id;
    let meta = vault
        .list(env_id)?
        .into_iter()
        .find(|meta| meta.name == name)
        .ok_or_else(|| CliError::from(VaultError::SecretNotFound))?;
    let data = ctx
        .data
        .clone()
        .ok_or_else(crate::keys::no_data_directory)?;
    let state = data.state().map_err(state_error)?;
    let version = meta.version;

    let report = |out: &mut dyn Write, status: &str, line: String| {
        let _ = if json {
            writeln!(
                out,
                "{}",
                json!({ "status": status, "name": name.as_str(), "environment": label, "version": version })
            )
        } else {
            writeln!(out, "{line}")
        };
    };

    if state.var_consent(env_id, &name).map_err(state_error)? == Some(current(&meta)) {
        report(
            out,
            "already_allowed",
            format!("✓ {name} (version {version}) is already allowed in {label}"),
        );
        return Ok(Exit::Success);
    }

    // The user consents to a value they have seen: no terminal, no consent.
    if ctx.terminal.is_none() {
        return Err(CliError::new(
            "terminal_required",
            Exit::Usage,
            format!("smart-env allow --var shows the value of {name} and needs a terminal (also with --yes)."),
        )
        .with_hint(format!("Run it in a terminal: smart-env allow --var {name}")));
    }
    let key = device_key(ctx)?;
    let value = vault
        .get(env_id, &name, &key)?
        .ok_or_else(|| CliError::from(VaultError::SecretNotFound))?;

    let terminal = ctx.terminal.as_deref_mut().expect("checked above");
    let mut shown = format!(
        "! {name} changes how tools behave, not just your app. Its value in {label} (version {version}):\n"
    );
    for line in value.expose().split('\n') {
        shown.push_str(&format!("  {line}\n"));
    }
    terminal.show(&shown);
    let yes = terminal
        .ask(&format!(
            "? Pass {name} to smart-env run and the shell hook? [y/N] "
        ))
        .is_ok_and(|answer| matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"));

    if !yes {
        report(out, "declined", format!("{name} not allowed."));
        return Ok(Exit::Success);
    }
    state
        .set_var_consent(env_id, &name, &current(&meta))
        .map_err(state_error)?;
    report(
        out,
        "allowed",
        format!("✓ Allowed {name} (version {version}) in {label}. A new value needs a new allow."),
    );
    Ok(Exit::Success)
}

/// `smart-env deny --var NAME`: stops passing a reserved name. Needs no key.
pub(crate) fn deny_var(
    ctx: &mut Context<'_>,
    json: bool,
    env: Option<&EnvRef>,
    name: &str,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let name = reserved_name(name)?;
    let (_, target) = target::resolve(ctx, env)?;
    let label = target.label();
    let data = ctx
        .data
        .clone()
        .ok_or_else(crate::keys::no_data_directory)?;
    let removed = data
        .state()
        .map_err(state_error)?
        .remove_var_consent(target.environment.id, &name)
        .map_err(state_error)?;
    let _ = match (json, removed) {
        (true, _) => writeln!(
            out,
            "{}",
            json!({
                "status": if removed { "denied" } else { "not_allowed" },
                "name": name.as_str(),
                "environment": label,
            })
        ),
        (false, true) => writeln!(out, "✓ {name} is no longer passed in {label}."),
        (false, false) => writeln!(out, "✓ {name} was not allowed in {label}."),
    };
    Ok(Exit::Success)
}

/// A valid variable name on the reserved list.
fn reserved_name(name: &str) -> Result<VarName, CliError> {
    let name = VarName::parse(name)
        .map_err(|_| CliError::from(VaultError::Secret(SecretError::InvalidName)))?;
    if !is_reserved(name.as_str()) {
        return Err(CliError::new(
            "not_reserved",
            Exit::Usage,
            format!("{name} is not a reserved name; smart-env run already passes it."),
        )
        .with_hint("Only reserved names need: smart-env allow --var NAME"));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::is_reserved;

    #[test]
    fn exact_names_from_adr_005() {
        for name in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "PATH",
            "BASH_ENV",
            "ENV",
            "ZDOTDIR",
            "PROMPT_COMMAND",
            "SHELLOPTS",
            "IFS",
            "HOME",
            "NODE_OPTIONS",
            "PYTHONSTARTUP",
            "PYTHONPATH",
            "PERL5OPT",
            "RUBYOPT",
            "JAVA_TOOL_OPTIONS",
            "_JAVA_OPTIONS",
            "EDITOR",
            "VISUAL",
            "PAGER",
            "SSH_AUTH_SOCK",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "NODE_EXTRA_CA_CERTS",
            "REQUESTS_CA_BUNDLE",
        ] {
            assert!(is_reserved(name), "{name}");
        }
    }

    #[test]
    fn reserved_prefixes() {
        for name in [
            "DYLD_INSERT_LIBRARIES",
            "GIT_SSH_COMMAND",
            "GIT_EXEC_PATH",
            "SMART_ENV_DEBUG",
        ] {
            assert!(is_reserved(name), "{name}");
        }
    }

    #[test]
    fn case_is_ignored() {
        for name in [
            "path",
            "Node_Options",
            "http_proxy",
            "git_dir",
            "smart_env_x",
        ] {
            assert!(is_reserved(name), "{name}");
        }
    }

    #[test]
    fn ordinary_names_are_not_reserved() {
        for name in [
            "DATABASE_URL",
            "API_KEY",
            "PATHS",
            "MY_PATH",
            "HOMEPAGE_URL",
            "GITHUB_TOKEN",
            "DYLD",
            "SMART_ENVIRONMENT",
            "NODE_ENV",
            "ENVIRONMENT",
        ] {
            assert!(!is_reserved(name), "{name}");
        }
    }
}
