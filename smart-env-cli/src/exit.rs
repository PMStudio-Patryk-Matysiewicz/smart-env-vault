/// Process exit codes from the DX contract.
///
/// `run` returning the child's exit code is handled by the `run` command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// `0`: success.
    Success,
    /// `1`: general error.
    Failure,
    /// `2`: wrong usage (unknown flag, missing argument, confirmation needed
    /// in non-interactive mode).
    Usage,
    /// `3`: no access or locked key.
    Access,
    /// `4`: project, environment or variable not found.
    NotFound,
    /// `5`: conflict (name taken, changed in the meantime).
    Conflict,
}

impl Exit {
    /// Numeric process exit code.
    pub fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Failure => 1,
            Self::Usage => 2,
            Self::Access => 3,
            Self::NotFound => 4,
            Self::Conflict => 5,
        }
    }
}
