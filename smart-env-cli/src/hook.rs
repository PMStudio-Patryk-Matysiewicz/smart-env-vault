//! `smart-env hook <shell>` (the shell integration script), the hidden
//! `smart-env hook-env <shell>` it calls at every prompt, and installing the
//! hook in the shell's startup file during `setup` (ADR-005).
//!
//! `hook-env --activate` / `--deactivate` serve the `smart-env activate` /
//! `deactivate` shell function; `smart-env auto-activate on|off` turns
//! loading on `cd` on or off.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use smart_env_vault::{
    DataPaths, DeviceKey, EnvironmentId, Inject, KeyId, SecretValue, StateStore, TrustDecision,
    Vault, VaultError,
};

use crate::init::ask_yes;
use crate::keys::{device_key, no_data_directory, not_set_up};
use crate::project_file::ProjectFileError;
use crate::reserved::{Consent, consent, is_reserved};
use crate::target;
use crate::trust::state_error;
use crate::{
    CliError, Context, EnvRef, Exit, FILE_NAME, Interaction, ProjectFile, Shell, ShellEnv,
};

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
///
/// stdout is shell code for the hook to evaluate (restore, export, the new
/// state); stderr gets at most a few `smart-env: …` lines, never values.
pub(crate) fn hook_env(
    ctx: &mut Context<'_>,
    shell: Shell,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Exit {
    let previous = ctx.hook_state.as_deref().and_then(State::parse);
    let mut step = Step::new(shell);
    step.run(ctx, previous.as_ref());
    step.write(out, err);
    Exit::Success
}

/// `hook-env <shell> --activate`, run by the shell function for
/// `smart-env activate`: loads the environment (explicit consent, no
/// `allow`) and keeps it until `deactivate`.
///
/// # Errors
/// `not_set_up`, `project_file_*`, `environment_not_found`, `key_locked`…;
/// nothing is printed to stdout, so the shell is left as it was.
pub(crate) fn activate(
    ctx: &mut Context<'_>,
    shell: Shell,
    env: Option<&EnvRef>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<Exit, CliError> {
    let previous = ctx.hook_state.as_deref().and_then(State::parse);
    let (vault, target) = target::resolve(ctx, env)?;
    let key = device_key(ctx)?;
    let data = ctx.data.clone().ok_or_else(no_data_directory)?;
    let consents = data.state().ok();
    let mut step = Step::new(shell);
    let (revision, loaded) =
        step.decrypt(&vault, target.environment.id, &key, consents.as_ref())?;
    step.activate(
        previous.as_ref(),
        State {
            dir: String::new(),
            hash: String::new(),
            label: target.label(),
            kind: StateKind::Active {
                env: target.environment.id,
                revision,
                manual: true,
                vars: Vec::new(),
            },
        },
        loaded,
    );
    step.write(out, err);
    Ok(Exit::Success)
}

/// `hook-env <shell> --deactivate`, run by the shell function for
/// `smart-env deactivate`. The project in the current directory stays
/// unloaded until the shell leaves it.
///
/// # Errors
/// None in practice; kept for symmetry with `activate`.
pub(crate) fn deactivate(
    ctx: &mut Context<'_>,
    shell: Shell,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<Exit, CliError> {
    let previous = ctx.hook_state.as_deref().and_then(State::parse);
    let mut step = Step::new(shell);
    match previous.as_ref() {
        Some(
            state @ State {
                kind: StateKind::Active { .. },
                ..
            },
        ) => {
            step.messages
                .push(format!("restored environment from before {}", state.label));
            step.restore(previous.as_ref());
            match ctx.current_dir.as_deref().and_then(Found::nearest) {
                Some(found) => {
                    let (dir, hash) = found.key();
                    let marker = State {
                        dir,
                        hash,
                        label: state.label.clone(),
                        kind: StateKind::Blocked {
                            reason: DEACTIVATED.to_owned(),
                        },
                    };
                    step.code.push_str(&shell.set_state(&marker.to_json()));
                }
                None => step.code.push_str(&shell.clear_state()),
            }
        }
        _ => step.messages.push("nothing is active".to_owned()),
    }
    step.write(out, err);
    Ok(Exit::Success)
}

/// `smart-env activate` / `deactivate` run as a plain binary: only the
/// shell function can change the shell.
pub(crate) fn shell_function_required(command: &str) -> CliError {
    CliError::new(
        "shell_function_required",
        Exit::Usage,
        format!("smart-env {command} changes your shell, so it needs the shell function."),
    )
    .with_hint("Load it: eval \"$(smart-env hook bash)\", or add it for good: smart-env setup")
}

/// `smart-env auto-activate on|off`.
pub(crate) fn auto_activate(
    ctx: &mut Context<'_>,
    json: bool,
    on: bool,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let data = ctx.data.clone().ok_or_else(no_data_directory)?;
    if !data.vault_db().exists() {
        return Err(not_set_up());
    }
    data.state()
        .map_err(state_error)?
        .set_auto_activate(on)
        .map_err(state_error)?;
    let _ = if json {
        writeln!(out, "{}", json!({ "auto_activate": on }))
    } else if on {
        writeln!(out, "✓ Auto-activation on")
    } else {
        writeln!(
            out,
            "✓ Auto-activation off. Load variables with: smart-env activate"
        )
    };
    Ok(Exit::Success)
}

/// Version of the hook state format.
const STATE_VERSION: u64 = 1;

/// Blocked reason after `deactivate`: the project here stays unloaded until
/// the shell leaves it.
const DEACTIVATED: &str = "deactivated";

/// What the hook remembers between prompts, in a shell variable. Never
/// holds values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct State {
    /// Canonical project directory (empty for `activate`).
    pub dir: String,
    /// SHA-256 of `smart-env.toml` (hex; empty for `activate`).
    pub hash: String,
    /// `project/environment`, for messages.
    pub label: String,
    pub kind: StateKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StateKind {
    /// Variables exported.
    Active {
        env: EnvironmentId,
        revision: u64,
        /// `smart-env activate`: stays until `deactivate`, whatever the
        /// directory.
        manual: bool,
        /// Exported names with the secret and version behind each.
        vars: Vec<(String, KeyId, u32)>,
    },
    /// Nothing exported; `reason` was reported once.
    Blocked { reason: String },
}

impl State {
    /// The state the shell holds; `None` for none, empty or damaged.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let value: Value = serde_json::from_str(text).ok()?;
        if value["v"].as_u64()? != STATE_VERSION {
            return None;
        }
        let text = |key: &str| value[key].as_str().map(str::to_owned);
        let kind = match value["status"].as_str()? {
            "active" => StateKind::Active {
                env: value["env"].as_str()?.parse().ok()?,
                revision: value["revision"].as_u64()?,
                manual: value["manual"].as_bool().unwrap_or(false),
                vars: value["vars"]
                    .as_array()?
                    .iter()
                    .map(|var| {
                        Some((
                            var[0].as_str()?.to_owned(),
                            var[1].as_str()?.parse().ok()?,
                            u32::try_from(var[2].as_u64()?).ok()?,
                        ))
                    })
                    .collect::<Option<_>>()?,
            },
            "blocked" => StateKind::Blocked {
                reason: text("reason")?,
            },
            _ => return None,
        };
        Some(Self {
            dir: text("dir")?,
            hash: text("hash")?,
            label: text("label")?,
            kind,
        })
    }

    fn to_json(&self) -> String {
        let mut value = json!({
            "v": STATE_VERSION,
            "dir": self.dir,
            "hash": self.hash,
            "label": self.label,
        });
        match &self.kind {
            StateKind::Active {
                env,
                revision,
                manual,
                vars,
            } => {
                value["status"] = json!("active");
                value["env"] = json!(env.to_string());
                value["revision"] = json!(revision);
                value["manual"] = json!(manual);
                value["vars"] = vars
                    .iter()
                    .map(|(name, key, version)| json!([name, key.to_string(), version]))
                    .collect();
            }
            StateKind::Blocked { reason } => {
                value["status"] = json!("blocked");
                value["reason"] = json!(reason);
            }
        }
        value.to_string()
    }

    fn exported(&self) -> &[(String, KeyId, u32)] {
        match &self.kind {
            StateKind::Active { vars, .. } => vars,
            StateKind::Blocked { .. } => &[],
        }
    }

    fn is_manual(&self) -> bool {
        matches!(self.kind, StateKind::Active { manual: true, .. })
    }
}

/// The nearest `smart-env.toml`: its directory, bytes and hash.
pub(crate) struct Found {
    pub dir: PathBuf,
    pub bytes: Vec<u8>,
    pub hash: [u8; 32],
}

impl Found {
    /// Like `ProjectFile::find`, but also for a file that does not parse
    /// (reported once, keyed by its hash).
    pub(crate) fn nearest(start: &Path) -> Option<Self> {
        let start = std::path::absolute(start).ok()?;
        let path = start
            .ancestors()
            .map(|dir| dir.join(FILE_NAME))
            .find(|path| fs::metadata(path).is_ok_and(|meta| meta.is_file()))?;
        let bytes = fs::read(&path).ok()?;
        let dir = fs::canonicalize(path.parent()?).ok()?;
        let hash = Sha256::digest(&bytes).into();
        Some(Self { dir, bytes, hash })
    }

    fn key(&self) -> (String, String) {
        (
            self.dir.to_string_lossy().into_owned(),
            self.hash.iter().map(|byte| format!("{byte:02x}")).collect(),
        )
    }

    /// The parsed `smart-env.toml`.
    pub(crate) fn file(&self) -> Result<ProjectFile, CliError> {
        std::str::from_utf8(&self.bytes)
            .map_err(|_| ProjectFileError::Syntax { line: None })
            .and_then(ProjectFile::parse)
            .map_err(CliError::from)
    }
}

/// One prompt's output.
struct Step {
    shell: Shell,
    code: String,
    messages: Vec<String>,
}

impl Step {
    fn new(shell: Shell) -> Self {
        Self {
            shell,
            code: String::new(),
            messages: Vec::new(),
        }
    }

    fn write(&self, out: &mut dyn Write, err: &mut dyn Write) {
        let _ = out.write_all(self.code.as_bytes());
        for message in &self.messages {
            let _ = writeln!(err, "smart-env: {message}");
        }
    }

    fn run(&mut self, ctx: &Context<'_>, previous: Option<&State>) {
        let Some(data) = ctx.data.clone().filter(|data| data.vault_db().exists()) else {
            self.leave(previous);
            return;
        };
        // `activate` sticks until `deactivate`, whatever the directory.
        if let Some(state) = previous.filter(|state| state.is_manual()) {
            self.refresh_manual(ctx, &data, state);
            return;
        }
        let auto = data
            .state()
            .ok()
            .and_then(|state| state.auto_activate().ok())
            .unwrap_or(true);
        let found = ctx.current_dir.as_deref().and_then(Found::nearest);
        let Some(found) = found.filter(|_| auto) else {
            self.leave(previous);
            return;
        };
        let (dir, hash) = found.key();
        let here = |state: &&State| state.dir == dir && state.hash == hash;

        // After `deactivate`: this project stays unloaded until the shell
        // leaves it.
        if previous.filter(here).is_some_and(
            |state| matches!(&state.kind, StateKind::Blocked { reason } if reason == DEACTIVATED),
        ) {
            return;
        }

        // Fast path: same file, same environment revision. No key, no
        // decryption.
        if let Some(State {
            kind: StateKind::Active { env, revision, .. },
            ..
        }) = previous.filter(here)
            && Vault::open(data.vault_db())
                .and_then(|vault| vault.revision(*env))
                .is_ok_and(|current| current == *revision)
        {
            return;
        }

        match self.load(ctx, &data, &found) {
            Ok((label, env, revision, loaded)) => {
                self.activate(
                    previous,
                    State {
                        dir,
                        hash,
                        label,
                        kind: StateKind::Active {
                            env,
                            revision,
                            manual: false,
                            vars: Vec::new(),
                        },
                    },
                    loaded,
                );
            }
            // Denied: nothing to report, so nothing to remember either.
            Err(Blocked { message: None, .. }) => {
                if previous.is_some() {
                    self.restore(previous);
                    self.code.push_str(&self.shell.clear_state());
                }
            }
            Err(Blocked {
                label,
                reason,
                message,
            }) => {
                let state = State {
                    dir,
                    hash,
                    label,
                    kind: StateKind::Blocked { reason },
                };
                // Reported once: the same outcome for the same file is quiet.
                let repeated = previous == Some(&state);
                self.restore(previous);
                if !repeated {
                    self.messages.extend(message);
                    self.code.push_str(&self.shell.set_state(&state.to_json()));
                }
            }
        }
    }

    /// A manual activation follows changes from another tab; anything that
    /// fails (locked key, removed environment) keeps what is loaded.
    fn refresh_manual(&mut self, ctx: &Context<'_>, data: &DataPaths, state: &State) {
        let StateKind::Active { env, revision, .. } = state.kind else {
            return;
        };
        let Ok(vault) = Vault::open(data.vault_db()) else {
            return;
        };
        if vault.revision(env).is_ok_and(|current| current == revision) {
            return;
        }
        let Ok(key) = device_key(ctx) else { return };
        let consents = data.state().ok();
        let mut step = Self::new(self.shell);
        if let Ok((revision, loaded)) = step.decrypt(&vault, env, &key, consents.as_ref()) {
            step.activate(
                Some(state),
                State {
                    kind: StateKind::Active {
                        env,
                        revision,
                        manual: true,
                        vars: Vec::new(),
                    },
                    ..state.clone()
                },
                loaded,
            );
            self.code.push_str(&step.code);
            self.messages.extend(step.messages);
        }
    }

    /// Leaves whatever was loaded (no project here, auto-activation off, or
    /// not set up).
    fn leave(&mut self, previous: Option<&State>) {
        let Some(previous) = previous else { return };
        if matches!(previous.kind, StateKind::Active { .. }) {
            self.messages.push(format!(
                "restored environment from before {}",
                previous.label
            ));
        }
        self.restore(Some(previous));
        self.code.push_str(&self.shell.clear_state());
    }

    /// Puts back the values from before the previous activation.
    fn restore(&mut self, previous: Option<&State>) {
        for (name, ..) in previous.map(State::exported).unwrap_or_default() {
            self.code.push_str(&self.shell.restore(name));
        }
    }

    /// Checks trust, the environment and the key, then decrypts.
    fn load(
        &mut self,
        ctx: &Context<'_>,
        data: &DataPaths,
        found: &Found,
    ) -> Result<(String, EnvironmentId, u64, Vec<Loaded>), Blocked> {
        let error = |label: &str, reason: &str, message: String| Blocked {
            label: label.to_owned(),
            reason: reason.to_owned(),
            message: Some(message),
        };
        let file = found
            .file()
            .map_err(|e| error("", "invalid", e.message().to_owned()))?;
        let label = format!("{}/{}", file.project, file.environment);

        let state = data.state().ok();
        let decision = state
            .as_ref()
            .and_then(|state| state.trust(&found.dir).ok().flatten());
        let allowed = TrustDecision::Allowed {
            file_hash: found.hash,
            project_id: file.project_id,
        };
        match decision {
            Some(decision) if decision == allowed => {}
            Some(TrustDecision::Denied) => {
                return Err(Blocked {
                    label,
                    reason: "denied".to_owned(),
                    message: None,
                });
            }
            Some(TrustDecision::Allowed { .. }) => {
                return Err(error(
                    &label,
                    "changed",
                    "smart-env.toml changed since it was allowed. Review it, then run: smart-env allow"
                        .to_owned(),
                ));
            }
            None => {
                let message = format!("{label} is not allowed here. Run: smart-env allow");
                return Err(error(&label, "not_allowed", message));
            }
        }

        let failed =
            |label: &str, e: CliError| error(label, "error", format!("{label}: {}", e.message()));
        let vault = Vault::open(data.vault_db()).map_err(|e| failed(&label, e.into()))?;
        let resolved = file.resolve(&vault).map_err(|e| failed(&label, e))?;
        let project = resolved.renamed_to.unwrap_or(file.project);
        let label = format!("{project}/{}", file.environment);
        let env = vault
            .environments(resolved.id)
            .map_err(|e| failed(&label, e.into()))?
            .into_iter()
            .find(|info| info.name == file.environment)
            .ok_or_else(|| failed(&label, VaultError::EnvironmentNotFound.into()))?
            .id;

        let key = device_key(ctx).map_err(|e| {
            if e.code() == "key_locked" {
                error(
                    &label,
                    "locked",
                    format!("{label} not loaded: the key is locked. Run: smart-env unlock"),
                )
            } else {
                error(
                    &label,
                    "key",
                    format!("{label} not loaded: {}", e.message()),
                )
            }
        })?;
        let (revision, loaded) = self
            .decrypt(&vault, env, &key, state.as_ref())
            .map_err(|e| failed(&label, e))?;
        Ok((label, env, revision, loaded))
    }

    /// Decrypts the environment and picks what reaches the shell: never
    /// `inject = run`, reserved names only with consent for their current
    /// value (reported here).
    fn decrypt(
        &mut self,
        vault: &Vault,
        env: EnvironmentId,
        key: &DeviceKey,
        consents: Option<&StateStore>,
    ) -> Result<(u64, Vec<Loaded>), CliError> {
        let revision = vault.revision(env)?;
        let variables = vault.read_all(env, key)?;

        let mut loaded = Vec::new();
        let mut skipped = Vec::new();
        let mut changed = Vec::new();
        for (meta, value) in variables {
            if meta.inject == Inject::Run {
                continue;
            }
            let name = meta.name.as_str().to_owned();
            if is_reserved(&name) {
                match consent(consents, env, &meta) {
                    Consent::Current => {}
                    Consent::Stale => {
                        changed.push(name);
                        continue;
                    }
                    Consent::Missing => {
                        skipped.push(name);
                        continue;
                    }
                }
            }
            loaded.push(Loaded {
                name,
                key: meta.key_id,
                version: meta.version,
                value,
            });
        }
        match skipped.as_slice() {
            [] => {}
            [name] => self.messages.push(format!(
                "{name} is a reserved name and was not loaded. Allow it with: smart-env allow --var {name}"
            )),
            names => self.messages.push(format!(
                "{} are reserved names and were not loaded. Allow one with: smart-env allow --var NAME",
                names.join(", ")
            )),
        }
        for name in changed {
            self.messages.push(format!(
                "{name} changed since you allowed it and was not loaded. Allow the new value with: smart-env allow --var {name}"
            ));
        }
        Ok((revision, loaded))
    }

    /// Restores the previous variables, exports the new ones, reports.
    fn activate(&mut self, previous: Option<&State>, mut state: State, loaded: Vec<Loaded>) {
        self.restore(previous);
        for var in &loaded {
            self.code
                .push_str(&self.shell.save_and_export(&var.name, var.value.expose()));
        }
        let vars: Vec<(String, KeyId, u32)> = loaded
            .iter()
            .map(|var| (var.name.clone(), var.key, var.version))
            .collect();

        let same_environment = match (previous.map(|p| (&p.dir, &p.kind)), &state.kind) {
            (Some((dir, StateKind::Active { env: old, .. })), StateKind::Active { env, .. }) => {
                *dir == state.dir && old == env
            }
            _ => false,
        };
        if same_environment {
            let old = previous.map(State::exported).unwrap_or_default();
            let find = |list: &[(String, KeyId, u32)], name: &str| {
                list.iter()
                    .find(|(n, ..)| n == name)
                    .map(|(_, k, v)| (*k, *v))
            };
            let added: Vec<String> = vars
                .iter()
                .filter(|(name, ..)| find(old, name).is_none())
                .map(|(name, ..)| format!("+{name}"))
                .collect();
            let changed: Vec<String> = vars
                .iter()
                .filter(|(name, key, version)| {
                    find(old, name).is_some_and(|before| before != (*key, *version))
                })
                .map(|(name, ..)| format!("~{name}"))
                .collect();
            let removed: Vec<String> = old
                .iter()
                .filter(|(name, ..)| find(&vars, name).is_none())
                .map(|(name, ..)| format!("-{name}"))
                .collect();
            let diff: Vec<String> = added.into_iter().chain(changed).chain(removed).collect();
            if !diff.is_empty() {
                self.messages
                    .push(format!("updated {} ({})", state.label, diff.join(" ")));
            }
        } else {
            let count = if vars.len() == 1 {
                "1 variable".to_owned()
            } else {
                format!("{} variables", vars.len())
            };
            self.messages
                .push(format!("active {} ({count})", state.label));
        }

        if let StateKind::Active { vars: slot, .. } = &mut state.kind {
            *slot = vars;
        }
        self.code.push_str(&self.shell.set_state(&state.to_json()));
    }
}

/// A variable to export.
struct Loaded {
    name: String,
    key: KeyId,
    version: u32,
    value: SecretValue,
}

/// Why nothing is loaded; `message` is shown once (none for `deny`).
struct Blocked {
    label: String,
    reason: String,
    message: Option<String>,
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
