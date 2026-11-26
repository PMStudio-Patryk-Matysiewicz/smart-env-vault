//! Which environment a variable command works on: `--env <project>/<env>`
//! (by project name in the vault, no `smart-env.toml` needed), `--env <env>`
//! (project from the nearest `smart-env.toml`, its `project_id` decides) or
//! both from `smart-env.toml`.

use smart_env_vault::{EnvironmentInfo, Vault};

use crate::keys::{no_data_directory, not_set_up};
use crate::{CliError, Context, EnvRef, Exit, ProjectFile};

/// The environment a command works on.
#[derive(Debug)]
pub(crate) struct Target {
    /// Current project name in the vault.
    pub project: String,
    /// The environment.
    pub environment: EnvironmentInfo,
    /// Warnings to show (e.g. the project was renamed since `smart-env.toml`
    /// was written).
    pub warnings: Vec<String>,
}

impl Target {
    /// `<project>/<environment>` for messages.
    pub fn label(&self) -> String {
        format!("{}/{}", self.project, self.environment.name)
    }
}

/// Opens the vault and resolves `env` (`--env`) against it and
/// `smart-env.toml`.
///
/// # Errors
/// `not_set_up`, `no_data_directory`, `no_current_directory`,
/// `project_file_*`, `project_id_mismatch`, `project_not_found`,
/// `environment_not_found` (hint lists the project's environments).
pub(crate) fn resolve(
    ctx: &Context<'_>,
    env: Option<&EnvRef>,
) -> Result<(Vault, Target), CliError> {
    let data = ctx.data.as_ref().ok_or_else(no_data_directory)?;
    if !data.vault_db().exists() {
        return Err(not_set_up());
    }
    let vault = Vault::open(data.vault_db())?;

    let mut warnings = Vec::new();
    let (project_id, project, environment) = match env {
        Some(EnvRef {
            project: Some(project),
            environment,
        }) => {
            let id = vault
                .find_project(project)?
                .ok_or_else(|| project_not_found(project))?;
            (id, project.clone(), environment.clone())
        }
        _ => {
            let dir = ctx.current_dir.as_ref().ok_or_else(no_current_directory)?;
            let (_, file) = ProjectFile::find(dir)?;
            let resolved = file.resolve(&vault)?;
            warnings.extend(resolved.warning());
            let name = resolved
                .renamed_to
                .clone()
                .unwrap_or_else(|| file.project.clone());
            let environment = env.map_or(file.environment, |env| env.environment.clone());
            (resolved.id, name, environment)
        }
    };

    let environments = vault.environments(project_id)?;
    let Some(info) = environments
        .iter()
        .find(|info| info.name == environment)
        .cloned()
    else {
        return Err(environment_not_found(&project, &environment, &environments));
    };
    Ok((
        vault,
        Target {
            project,
            environment: info,
            warnings,
        },
    ))
}

fn no_current_directory() -> CliError {
    CliError::new(
        "no_current_directory",
        Exit::Failure,
        "Cannot determine the current directory.",
    )
    .with_hint("Name the environment explicitly: --env <project>/<environment>")
}

fn project_not_found(project: &str) -> CliError {
    CliError::new(
        "project_not_found",
        Exit::NotFound,
        format!("Project {project} is not in this vault."),
    )
    .with_hint("Create it from the project's .env files: smart-env init")
}

fn environment_not_found(
    project: &str,
    environment: &str,
    existing: &[EnvironmentInfo],
) -> CliError {
    let names: Vec<&str> = existing.iter().map(|info| info.name.as_str()).collect();
    CliError::new(
        "environment_not_found",
        Exit::NotFound,
        format!("Environment {project}/{environment} not found."),
    )
    .with_hint(format!("Environments of {project}: {}", names.join(", ")))
}
