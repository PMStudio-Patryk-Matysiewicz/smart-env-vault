use crate::KeyError;
use age::x25519;
use secrecy::{ExposeSecret, SecretString};
use std::str::FromStr;

pub struct RecoveryKey(x25519::Identity);

impl RecoveryKey {
    pub fn generate() -> (Self, SecretString) {
        let key = Self(x25519::Identity::generate());
        let text = key.0.to_string();
        (key, text)
    }

    pub fn parse(text: &SecretString) -> Result<Self, KeyError> {
        x25519::Identity::from_str(text.expose_secret().trim())
            .map(Self)
            .map_err(|_| KeyError::InvalidRecoveryKey)
    }

    pub fn public(&self) -> crate::PublicKey {
        crate::PublicKey::from_recipient(self.0.to_public())
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RecoveryKey(..)")
    }
}

impl crate::Unwrapper for RecoveryKey {
    fn identity(&self) -> &dyn age::Identity {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shown_text_parses_back_to_same_key() {
        let (key, text) = RecoveryKey::generate();
        assert_eq!(RecoveryKey::parse(&text).unwrap().public(), key.public());
    }

    #[test]
    fn rejects_typo_thanks_to_checksum() {
        let (_, text) = RecoveryKey::generate();
        let mut typo = text.expose_secret().to_owned();
        let last = typo.pop().unwrap();
        typo.push(if last == 'Q' { 'P' } else { 'Q' });
        assert_eq!(
            RecoveryKey::parse(&SecretString::from(typo)).unwrap_err(),
            KeyError::InvalidRecoveryKey
        );
    }

    #[test]
    fn tolerates_whitespace_from_copy_paste() {
        let (key, text) = RecoveryKey::generate();
        let pasted = SecretString::from(format!("  {}\n", text.expose_secret()));
        assert_eq!(RecoveryKey::parse(&pasted).unwrap().public(), key.public());
    }

    #[test]
    fn debug_does_not_reveal_secret() {
        let (key, _) = RecoveryKey::generate();
        assert!(!format!("{key:?}").contains("AGE-SECRET-KEY"));
    }
}