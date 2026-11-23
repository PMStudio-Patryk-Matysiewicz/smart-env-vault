//! Parser of `.env` files for `init` (F06 2, ADR-007).
//!
//! Strict on purpose: whatever popular loaders read differently (a value
//! starting with `#`, backticks, a name defined twice) is an error with a line
//! number instead of a guess, because `init` deletes the plaintext after the
//! import. No error or warning ever contains a value or the raw line.

use smart_env_vault::{SecretError, SecretValue, VarName};
use std::collections::HashMap;
use std::fmt;
use zeroize::Zeroizing;

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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding { line } => write!(formatter, "line {line}: not valid UTF-8"),
            Self::MissingEquals { line } => write!(formatter, "line {line}: expected NAME=value"),
            Self::InvalidName { line } => write!(
                formatter,
                "line {line}: invalid variable name (letters, digits and _, not starting with a digit)"
            ),
            Self::AmbiguousComment { line } => write!(
                formatter,
                "line {line}: value starts with # — put it in quotes if # is part of the value"
            ),
            Self::UnterminatedQuote { line } => {
                write!(formatter, "line {line}: quote is never closed")
            }
            Self::TrailingContent { line } => {
                write!(
                    formatter,
                    "line {line}: unexpected text after the closing quote"
                )
            }
            Self::UnsupportedQuote { line } => write!(
                formatter,
                "line {line}: backtick quotes are not supported — use single or double quotes"
            ),
            Self::Duplicate {
                name,
                first,
                second,
            } => write!(
                formatter,
                "{name} is defined twice, in lines {first} and {second} — keep one"
            ),
            Self::InvalidValue { name, line, reason } => {
                write!(formatter, "line {line}: {name}: {reason}")
            }
        }
    }
}

impl std::error::Error for DotenvError {}

impl Dotenv {
    /// Parses the bytes of a `.env` file.
    ///
    /// # Errors
    /// The first [`DotenvError`] in the file (duplicates are reported at the
    /// second definition).
    pub fn parse(input: &[u8]) -> Result<Self, DotenvError> {
        let input = input.strip_prefix(b"\xef\xbb\xbf").unwrap_or(input);
        let lines = Lines(
            input
                .split(|&byte| byte == b'\n')
                .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
                .collect(),
        );
        let mut file = Self {
            entries: Vec::new(),
            warnings: Vec::new(),
        };
        let mut seen: HashMap<VarName, usize> = HashMap::new();
        let mut index = 0;
        while index < lines.0.len() {
            let line = index + 1;
            let text = lines.text(index)?.trim_start();
            if text.is_empty() || text.starts_with('#') {
                index += 1;
                continue;
            }
            let (name, rest) = strip_export(text)
                .split_once('=')
                .ok_or(DotenvError::MissingEquals { line })?;
            let name =
                VarName::parse(name.trim()).map_err(|_| DotenvError::InvalidName { line })?;
            if let Some(&first) = seen.get(&name) {
                return Err(DotenvError::Duplicate {
                    name,
                    first,
                    second: line,
                });
            }

            let rest = rest.trim_start();
            let (mut value, reference, last) = match rest.chars().next() {
                Some(quote @ ('"' | '\'')) => quoted(&lines, index, &rest[1..], quote)?,
                Some('`') => return Err(DotenvError::UnsupportedQuote { line }),
                Some('#') => return Err(DotenvError::AmbiguousComment { line }),
                _ => {
                    let value = unquoted(rest);
                    (
                        Zeroizing::new(value.to_owned()),
                        has_reference(value),
                        index,
                    )
                }
            };

            // `SecretValue::new` wipes the moved buffer, also when it rejects it.
            let value = SecretValue::new(std::mem::take(&mut *value)).map_err(|reason| {
                DotenvError::InvalidValue {
                    name: name.clone(),
                    line,
                    reason,
                }
            })?;
            if reference {
                file.warnings.push(DotenvWarning::Interpolation {
                    name: name.clone(),
                    line,
                });
            }
            seen.insert(name.clone(), line);
            file.entries.push(DotenvEntry { name, value, line });
            index = last + 1;
        }
        Ok(file)
    }
}

/// Raw lines without `\n` / `\r\n`, decoded only when reached, so the first
/// error in the file is the one reported.
struct Lines<'a>(Vec<&'a [u8]>);

impl<'a> Lines<'a> {
    fn text(&self, index: usize) -> Result<&'a str, DotenvError> {
        std::str::from_utf8(self.0[index]).map_err(|_| DotenvError::Encoding { line: index + 1 })
    }
}

/// `export NAME=…` → `NAME=…`; `export=…` and `exported=…` stay names.
fn strip_export(text: &str) -> &str {
    match text.strip_prefix("export") {
        Some(rest) if rest.starts_with([' ', '\t']) => {
            let rest = rest.trim_start();
            if rest.starts_with('=') { text } else { rest }
        }
        _ => text,
    }
}

/// Unquoted value: up to a `#` preceded by whitespace, trimmed.
fn unquoted(rest: &str) -> &str {
    let mut previous_blank = false;
    for (position, character) in rest.char_indices() {
        if character == '#' && previous_blank {
            return rest[..position].trim_end();
        }
        previous_blank = character.is_whitespace();
    }
    rest.trim_end()
}

/// `$` followed by `{`, a letter or `_`.
fn has_reference(value: &str) -> bool {
    value
        .match_indices('$')
        .any(|(position, _)| starts_reference(&value[position + 1..]))
}

fn starts_reference(after_dollar: &str) -> bool {
    after_dollar
        .chars()
        .next()
        .is_some_and(|next| next == '{' || next == '_' || next.is_ascii_alphabetic())
}

/// A quoted value starting at line `start` (`body` = text after the opening
/// quote), possibly spanning lines. Returns the value, whether a double-quoted
/// value has a `${…}` / `$NAME` reference, and the index of the closing line.
fn quoted(
    lines: &Lines<'_>,
    start: usize,
    body: &str,
    quote: char,
) -> Result<(Zeroizing<String>, bool, usize), DotenvError> {
    let double = quote == '"';
    let mut value = Zeroizing::new(String::new());
    let mut reference = false;
    let mut index = start;
    let mut text = body;
    loop {
        let mut characters = text.char_indices().peekable();
        while let Some((position, character)) = characters.next() {
            if character == quote {
                let after = text[position + 1..].trim_start();
                if !(after.is_empty() || after.starts_with('#')) {
                    return Err(DotenvError::TrailingContent { line: index + 1 });
                }
                return Ok((value, reference, index));
            }
            if double && character == '\\' {
                let escaped = match characters.peek() {
                    Some((_, 'n')) => Some('\n'),
                    Some((_, 'r')) => Some('\r'),
                    Some((_, 't')) => Some('\t'),
                    Some((_, '"')) => Some('"'),
                    Some((_, '\\')) => Some('\\'),
                    _ => None,
                };
                if let Some(escaped) = escaped {
                    characters.next();
                    value.push(escaped);
                    continue;
                }
            }
            if double && character == '$' && starts_reference(&text[position + 1..]) {
                reference = true;
            }
            value.push(character);
        }
        index += 1;
        if index >= lines.0.len() {
            return Err(DotenvError::UnterminatedQuote { line: start + 1 });
        }
        value.push('\n');
        text = lines.text(index)?;
    }
}
