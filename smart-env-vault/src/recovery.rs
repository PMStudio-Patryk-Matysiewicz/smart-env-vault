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