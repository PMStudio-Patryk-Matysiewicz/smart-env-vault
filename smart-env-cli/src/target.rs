//! Which environment a variable command works on: `--env <project>/<env>`
//! (by project name in the vault, no `smart-env.toml` needed), `--env <env>`
//! (project from the nearest `smart-env.toml`, its `project_id` decides) or
//! both from `smart-env.toml`.

use smart_env_vault::{EnvironmentInfo, ProjectId, Vault};

use crate::{CliError, Context, EnvRef};

/// The environment a command works on.
#[derive(Debug)]
pub(crate) struct Target {
    /// Project id.
    pub project_id: ProjectId,
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
    _ctx: &Context<'_>,
    _env: Option<&EnvRef>,
) -> Result<(Vault, Target), CliError> {
    todo!()
}
