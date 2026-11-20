use crate::CliError;

/// Whether the CLI may ask questions.
///
/// `--yes` answers every confirmation with "yes"; without a terminal on stdin
/// and without `--yes` nothing is asked and a confirmation is an error that
/// points at `--yes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interaction {
    /// Terminal on stdin, no `--yes`: ask.
    Interactive,
    /// `--yes`: never ask, confirm everything.
    AssumeYes,
    /// No terminal, no `--yes`: never ask, refuse confirmations.
    NonInteractive,
}

impl Interaction {
    /// Picks the mode from `--yes` and whether stdin is a terminal.
    pub fn detect(_yes: bool, _stdin_is_tty: bool) -> Self {
        todo!("F06 11: interaction mode")
    }

    /// Confirms `action`. `ask` shows the question and is called only in
    /// [`Interaction::Interactive`] mode.
    pub fn confirm(self, _action: &str, _ask: impl FnOnce() -> bool) -> Result<bool, CliError> {
        todo!("F06 11: confirmation")
    }
}
