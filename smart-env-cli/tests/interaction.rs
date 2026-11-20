use std::cell::Cell;

use smart_env_cli::{Exit, Interaction};

#[test]
fn terminal_without_yes_should_be_interactive() {
    assert_eq!(Interaction::detect(false, true), Interaction::Interactive);
}

#[test]
fn yes_should_assume_yes_with_or_without_terminal() {
    assert_eq!(Interaction::detect(true, true), Interaction::AssumeYes);
    assert_eq!(Interaction::detect(true, false), Interaction::AssumeYes);
}

#[test]
fn no_terminal_without_yes_should_be_non_interactive() {
    assert_eq!(
        Interaction::detect(false, false),
        Interaction::NonInteractive
    );
}

#[test]
fn interactive_confirm_should_return_the_answer() {
    assert!(Interaction::Interactive.confirm("import", || true).unwrap());
    assert!(
        !Interaction::Interactive
            .confirm("import", || false)
            .unwrap()
    );
}

#[test]
fn assume_yes_should_confirm_without_asking() {
    let asked = Cell::new(false);

    let confirmed = Interaction::AssumeYes
        .confirm("import", || {
            asked.set(true);
            false
        })
        .unwrap();

    assert!(confirmed);
    assert!(!asked.get());
}

#[test]
fn non_interactive_confirm_should_fail_without_asking() {
    let asked = Cell::new(false);

    let error = Interaction::NonInteractive
        .confirm("import", || {
            asked.set(true);
            true
        })
        .unwrap_err();

    assert_eq!(error.code(), "confirmation_required");
    assert_eq!(error.exit(), Exit::Usage);
    assert!(error.hint().unwrap().contains("--yes"));
    assert!(!asked.get());
}
