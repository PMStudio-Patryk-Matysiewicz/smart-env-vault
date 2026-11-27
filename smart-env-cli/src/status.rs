//! `smart-env status`: what is active in this shell, the project here and
//! its trust, reserved and run-only names, the key, auto-activation. Never
//! decrypts a value.

use std::io::Write;

use serde_json::{Value, json};
use smart_env_vault::{EnvironmentId, Inject, StateStore, TrustDecision, Vault};

use crate::hook::{Found, State, StateKind, display};
use crate::keys::{device_key, no_data_directory, not_set_up};
use crate::reserved::{Consent, consent, is_reserved};
use crate::trust::state_error;
use crate::{CliError, Context, Exit};

/// Prints the status (human lines or one JSON object) to `out`.
///
/// # Errors
/// `not_set_up`, storage errors.
pub(crate) fn status(
    ctx: &mut Context<'_>,
    json: bool,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let data = ctx.data.clone().ok_or_else(no_data_directory)?;
    if !data.vault_db().exists() {
        return Err(not_set_up());
    }
    let state = data.state().map_err(state_error)?;
    let vault = Vault::open(data.vault_db())?;
    let home = ctx.shell.home.clone();

    let shell = Shell::read(ctx.hook_state.as_deref());
    let here = ctx
        .current_dir
        .as_deref()
        .and_then(Found::nearest)
        .map(|found| Here::read(&found, &vault, &state));
    // Names of the active environment, else of the project here.
    let env = shell
        .active_env()
        .or_else(|| here.as_ref().and_then(|here| here.env));
    let names = env
        .map(|env| Names::read(&vault, &state, env))
        .unwrap_or_default();
    let key = match device_key(ctx) {
        Ok(_) => Key::Unlocked,
        Err(error) if error.code() == "key_locked" => Key::Locked,
        Err(error) => Key::Error(error.message().to_owned()),
    };
    let auto = state.auto_activate().map_err(state_error)?;

    if json {
        let _ = writeln!(
            out,
            "{}",
            json!({
                "shell": shell.to_json(),
                "here": here.as_ref().map_or(Value::Null, Here::to_json),
                "reserved_skipped": names.skipped,
                "reserved_changed": names.changed,
                "run_only": names.run_only,
                "key": key.code(),
                "auto_activate": auto,
            })
        );
        return Ok(Exit::Success);
    }

    let mut lines = vec![("Shell:", shell.text())];
    lines.push((
        "Here:",
        here.as_ref().map_or_else(
            || "no smart-env.toml".to_owned(),
            |here| here.text(home.as_deref()),
        ),
    ));
    if let Some(text) = names_line(&names.skipped, "not loaded", "smart-env allow --var") {
        lines.push(("Reserved:", text));
    }
    if let Some(text) = names_line(
        &names.changed,
        "changed since allowed",
        "smart-env allow --var",
    ) {
        lines.push(("Changed:", text));
    }
    if !names.run_only.is_empty() {
        lines.push(("Run only:", names.run_only.join(", ")));
    }
    lines.push(("Key:", key.text()));
    lines.push((
        "Auto:",
        if auto {
            "on".to_owned()
        } else {
            "off (smart-env auto-activate on)".to_owned()
        },
    ));
    for (label, text) in lines {
        let _ = writeln!(out, "{label:<11}{text}");
    }
    Ok(Exit::Success)
}

/// `A, B not loaded (smart-env allow --var NAME)`; with one name the hint
/// names it.
fn names_line(names: &[String], what: &str, command: &str) -> Option<String> {
    match names {
        [] => None,
        [name] => Some(format!("{name} {what} ({command} {name})")),
        names => Some(format!("{} {what} ({command} NAME)", names.join(", "))),
    }
}

/// What the shell holds.
enum Shell {
    /// No hook and no shell function in this shell.
    NotLoaded,
    Inactive,
    Active {
        label: String,
        env: EnvironmentId,
        manual: bool,
        variables: usize,
    },
    Blocked {
        label: String,
        reason: String,
    },
}

impl Shell {
    fn read(hook_state: Option<&str>) -> Self {
        let Some(text) = hook_state else {
            return Self::NotLoaded;
        };
        match State::parse(text) {
            None => Self::Inactive,
            Some(State {
                label,
                kind:
                    StateKind::Active {
                        env, manual, vars, ..
                    },
                ..
            }) => Self::Active {
                label,
                env,
                manual,
                variables: vars.len(),
            },
            Some(State {
                label,
                kind: StateKind::Blocked { reason },
                ..
            }) => Self::Blocked { label, reason },
        }
    }

    fn active_env(&self) -> Option<EnvironmentId> {
        match self {
            Self::Active { env, .. } => Some(*env),
            _ => None,
        }
    }

    fn text(&self) -> String {
        match self {
            Self::NotLoaded => "hook not loaded in this shell (smart-env setup)".to_owned(),
            Self::Inactive => "not active".to_owned(),
            Self::Active {
                label,
                manual,
                variables,
                ..
            } => {
                let count = if *variables == 1 {
                    "1 variable".to_owned()
                } else {
                    format!("{variables} variables")
                };
                let mode = if *manual { "manual" } else { "auto" };
                format!("active {label} ({count}, {mode})")
            }
            Self::Blocked { label, reason } => {
                let why = match reason.as_str() {
                    "locked" => format!("{label} not loaded, the key is locked (smart-env unlock)"),
                    "not_allowed" => format!("{label} is not allowed here (smart-env allow)"),
                    "changed" => {
                        "smart-env.toml changed since allowed (smart-env allow)".to_owned()
                    }
                    "deactivated" => format!("deactivated in {label} (smart-env activate)"),
                    other => format!("{label} not loaded ({other})"),
                };
                format!("not active: {why}")
            }
        }
    }

    fn to_json(&self) -> Value {
        match self {
            Self::NotLoaded => json!({ "hook": false }),
            Self::Inactive => json!({ "hook": true, "status": "inactive" }),
            Self::Active {
                label,
                manual,
                variables,
                ..
            } => json!({
                "hook": true,
                "status": "active",
                "label": label,
                "mode": if *manual { "manual" } else { "auto" },
                "variables": variables,
            }),
            Self::Blocked { label, reason } => json!({
                "hook": true,
                "status": "blocked",
                "label": label,
                "reason": reason,
            }),
        }
    }
}

/// The project in the current directory and the decision about it.
struct Here {
    /// `project/environment`, or the file's error.
    label: String,
    path: std::path::PathBuf,
    /// `allowed`, `not_allowed`, `changed`, `denied`, `invalid`.
    trust: &'static str,
    /// Its environment in the vault, if it is there.
    env: Option<EnvironmentId>,
}

impl Here {
    fn read(found: &Found, vault: &Vault, state: &StateStore) -> Self {
        let file = match found.file() {
            Ok(file) => file,
            Err(error) => {
                return Self {
                    label: error.message().to_owned(),
                    path: found.dir.clone(),
                    trust: "invalid",
                    env: None,
                };
            }
        };
        let allowed = TrustDecision::Allowed {
            file_hash: found.hash,
            project_id: file.project_id,
        };
        let trust = match state.trust(&found.dir).ok().flatten() {
            Some(decision) if decision == allowed => "allowed",
            Some(TrustDecision::Denied) => "denied",
            Some(TrustDecision::Allowed { .. }) => "changed",
            None => "not_allowed",
        };
        let env = file.resolve(vault).ok().and_then(|resolved| {
            vault
                .environments(resolved.id)
                .ok()?
                .into_iter()
                .find(|info| info.name == file.environment)
                .map(|info| info.id)
        });
        Self {
            label: format!("{}/{}", file.project, file.environment),
            path: found.dir.clone(),
            trust,
            env,
        }
    }

    fn text(&self, home: Option<&std::path::Path>) -> String {
        let decision = match self.trust {
            "allowed" => "allowed",
            "denied" => "denied (smart-env allow)",
            "changed" => "smart-env.toml changed since allowed (smart-env allow)",
            "invalid" => return format!("{} ({})", self.label, display(&self.path, home)),
            _ => "not allowed (smart-env allow)",
        };
        format!(
            "{} in {}, {decision}",
            self.label,
            display(&self.path, home)
        )
    }

    fn to_json(&self) -> Value {
        json!({
            "label": self.label,
            "path": self.path.display().to_string(),
            "trust": self.trust,
        })
    }
}

/// Names the hook leaves out of the shell, and why.
#[derive(Default)]
struct Names {
    skipped: Vec<String>,
    changed: Vec<String>,
    run_only: Vec<String>,
}

impl Names {
    fn read(vault: &Vault, state: &StateStore, env: EnvironmentId) -> Self {
        let mut names = Self::default();
        for meta in vault.list(env).unwrap_or_default() {
            let name = meta.name.as_str().to_owned();
            if meta.inject == Inject::Run {
                names.run_only.push(name);
            } else if is_reserved(&name) {
                match consent(Some(state), env, &meta) {
                    Consent::Current => {}
                    Consent::Stale => names.changed.push(name),
                    Consent::Missing => names.skipped.push(name),
                }
            }
        }
        names
    }
}

enum Key {
    Unlocked,
    Locked,
    Error(String),
}

impl Key {
    fn text(&self) -> String {
        match self {
            Self::Unlocked => "unlocked".to_owned(),
            Self::Locked => "locked (smart-env unlock)".to_owned(),
            Self::Error(message) => message.clone(),
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::Unlocked => "unlocked",
            Self::Locked => "locked",
            Self::Error(_) => "error",
        }
    }
}
