use std::fmt;
use std::str::FromStr;

/// Value of `--env`: `<environment>` (in the current project) or
/// `<project>/<environment>`.
///
/// Only the shape is checked here; name rules belong to F03.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvRef {
    /// Project name, `None` = the project from `smart-env.toml`.
    pub project: Option<String>,
    /// Environment name.
    pub environment: String,
}

/// `--env` value is empty or not of the form `[project/]environment`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvRefError;

impl fmt::Display for EnvRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected <environment> or <project>/<environment>")
    }
}

impl std::error::Error for EnvRefError {}

impl FromStr for EnvRef {
    type Err = EnvRefError;

    fn from_str(_input: &str) -> Result<Self, Self::Err> {
        todo!("F06 11: --env parsing")
    }
}
