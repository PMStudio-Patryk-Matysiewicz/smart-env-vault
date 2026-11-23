//! Parser of `.env` files for `init` (F06 2, ADR-007).
//!
//! Strict on purpose: whatever popular loaders read differently (a value
//! starting with `#`, backticks, a name defined twice) is an error with a line
//! number instead of a guess, because `init` deletes the plaintext after the
//! import. No error or warning ever contains a value or the raw line.

use smart_env_vault::{SecretError, SecretValue, VarName};
use std::fmt;

/// A parsed `.env` file: entries in file order plus warnings.
#[derive(Debug)]
pub struct Dotenv {
    /// Variables in the order they appear in the file.
    pub entries: Vec<DotenvEntry>,
    /// Non-fatal findings (`${VAR}` kept literally), at most one per entry.
    pub warnings: Vec<DotenvWarning>,
}

/// One variable from a `.env` file.
#[derive(Debug)]
pub struct DotenvEntry {
    /// Validated name.
    pub name: VarName,
    /// Value after unquoting and escapes; `Debug` does not reveal it.
    pub value: SecretValue,
    /// 1-based line where the entry starts.
    pub line: usize,
}

/// A non-fatal finding while parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DotenvWarning {
    /// `${VAR}` or `$VAR` kept literally — smart-env never substitutes.
    Interpolation {
        /// Variable whose value contains the reference.
        name: VarName,
        /// 1-based line where the entry starts.
        line: usize,
    },
}

/// Why a `.env` file was rejected. Carries line numbers and validated names
/// only, never a value or the raw line.
#[derive(Debug, PartialEq, Eq)]
pub enum DotenvError {
    /// The line is not valid UTF-8.
    Encoding {
        /// 1-based line.
        line: usize,
    },
    /// A non-comment line without `=`.
    MissingEquals {
        /// 1-based line.
        line: usize,
    },
    /// The name is not `[A-Za-z_][A-Za-z0-9_]*` (not quoted: it may be a
    /// pasted secret).
    InvalidName {
        /// 1-based line.
        line: usize,
    },
    /// An unquoted value starting with `#`: loaders read it either as an
    /// empty value or as `#…`.
    AmbiguousComment {
        /// 1-based line.
        line: usize,
    },
    /// A quote that is never closed.
    UnterminatedQuote {
        /// 1-based line where the entry starts.
        line: usize,
    },
    /// Something other than whitespace or a comment after the closing quote.
    TrailingContent {
        /// 1-based line of the closing quote.
        line: usize,
    },
    /// A value in backticks.
    UnsupportedQuote {
        /// 1-based line.
        line: usize,
    },
    /// The same name defined twice.
    Duplicate {
        /// The repeated name.
        name: VarName,
        /// Line of the first definition.
        first: usize,
        /// Line of the second definition.
        second: usize,
    },
    /// The value is rejected by [`SecretValue::new`] (NUL byte, over 64 KiB).
    InvalidValue {
        /// Variable with the rejected value.
        name: VarName,
        /// 1-based line where the entry starts.
        line: usize,
        /// [`SecretError::InvalidValue`] or [`SecretError::ValueTooLarge`].
        reason: SecretError,
    },
}

impl fmt::Display for DotenvError {
    fn fmt(&self, _formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl std::error::Error for DotenvError {}

impl Dotenv {
    /// Parses the bytes of a `.env` file.
    ///
    /// # Errors
    /// The first [`DotenvError`] in the file (duplicates are reported at the
    /// second definition).
    pub fn parse(_input: &[u8]) -> Result<Self, DotenvError> {
        todo!()
    }
}
