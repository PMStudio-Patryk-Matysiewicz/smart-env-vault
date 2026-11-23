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

/// Shape of one part of `[project/]environment`: not empty, no whitespace,
/// no `/`. Shared with `smart-env.toml`.
pub(crate) fn is_valid_part(part: &str) -> bool {
    !part.is_empty() && !part.contains(char::is_whitespace) && !part.contains('/')
}

impl FromStr for EnvRef {
    type Err = EnvRefError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input.split_once('/') {
            None if is_valid_part(input) => Ok(Self {
                project: None,
                environment: input.to_owned(),
            }),
            Some((project, environment))
                if is_valid_part(project) && is_valid_part(environment) =>
            {
                Ok(Self {
                    project: Some(project.to_owned()),
                    environment: environment.to_owned(),
                })
            }
            _ => Err(EnvRefError),
        }
    }
}
