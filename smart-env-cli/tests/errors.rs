use smart_env_cli::{CliError, Exit};
use smart_env_vault::{KeyError, VarName, VaultError};

#[test]
fn exit_codes_should_match_dx_contract() {
    assert_eq!(Exit::Success.code(), 0);
    assert_eq!(Exit::Failure.code(), 1);
    assert_eq!(Exit::Usage.code(), 2);
    assert_eq!(Exit::Access.code(), 3);
    assert_eq!(Exit::NotFound.code(), 4);
    assert_eq!(Exit::Conflict.code(), 5);
}

#[test]
fn human_error_should_show_message_and_indented_hint() {
    let error = CliError::new(
        "no_config",
        Exit::NotFound,
        "Brak smart-env.toml w tym katalogu ani wyżej.",
    )
    .with_hint("Uruchom: smart-env init");

    assert_eq!(
        error.render_human(),
        "✗ Brak smart-env.toml w tym katalogu ani wyżej.\n  Uruchom: smart-env init\n"
    );
}

#[test]
fn human_error_without_hint_should_be_one_line() {
    let error = CliError::new("failure", Exit::Failure, "Coś poszło nie tak.");

    assert_eq!(error.render_human(), "✗ Coś poszło nie tak.\n");
}

#[test]
fn json_error_should_have_code_message_and_hint() {
    let error = CliError::new("no_config", Exit::NotFound, "Brak smart-env.toml.")
        .with_hint("Uruchom: smart-env init");

    let json: serde_json::Value = serde_json::from_str(&error.render_json()).unwrap();

    assert_eq!(
        json,
        serde_json::json!({"error": {
            "code": "no_config",
            "message": "Brak smart-env.toml.",
            "hint": "Uruchom: smart-env init"
        }})
    );
}

#[test]
fn json_error_without_hint_should_have_null_hint() {
    let error = CliError::new("failure", Exit::Failure, "Coś poszło nie tak.");

    let json: serde_json::Value = serde_json::from_str(&error.render_json()).unwrap();

    assert_eq!(json["error"]["hint"], serde_json::Value::Null);
}

#[test]
fn json_error_should_escape_quotes_and_newlines() {
    let error = CliError::new("failure", Exit::Failure, "zła \"nazwa\"\nw linii");

    let json: serde_json::Value = serde_json::from_str(&error.render_json()).unwrap();

    assert_eq!(json["error"]["message"], "zła \"nazwa\"\nw linii");
}

#[test]
fn usage_error_should_exit_with_2() {
    let error = CliError::usage("Nieznana flaga.");

    assert_eq!(error.code(), "usage");
    assert_eq!(error.exit(), Exit::Usage);
    assert_eq!(error.message(), "Nieznana flaga.");
}

#[test]
fn confirmation_required_should_point_at_yes_flag() {
    let error = CliError::confirmation_required("usunięcie plików .env");

    assert_eq!(error.code(), "confirmation_required");
    assert_eq!(error.exit(), Exit::Usage);
    assert!(error.message().contains("usunięcie plików .env"));
    assert!(error.hint().unwrap().contains("--yes"));
}

#[test]
fn vault_errors_should_map_to_contract_exit_codes() {
    let name = VarName::parse("API_KEY").unwrap();
    let cases = [
        (
            VaultError::ProjectNotFound,
            "project_not_found",
            Exit::NotFound,
        ),
        (
            VaultError::EnvironmentNotFound,
            "environment_not_found",
            Exit::NotFound,
        ),
        (
            VaultError::SecretNotFound,
            "secret_not_found",
            Exit::NotFound,
        ),
        (
            VaultError::ProjectNameTaken,
            "project_name_taken",
            Exit::Conflict,
        ),
        (
            VaultError::EnvironmentNameTaken,
            "environment_name_taken",
            Exit::Conflict,
        ),
        (
            VaultError::SecretNameTaken,
            "secret_name_taken",
            Exit::Conflict,
        ),
        (
            VaultError::DuplicateName(name),
            "duplicate_name",
            Exit::Conflict,
        ),
        (
            VaultError::Key(KeyError::Unwrap),
            "key_mismatch",
            Exit::Access,
        ),
        (
            VaultError::Key(KeyError::KeychainUnavailable),
            "keychain_unavailable",
            Exit::Access,
        ),
        (
            VaultError::Key(KeyError::WrongPassphrase),
            "wrong_passphrase",
            Exit::Access,
        ),
        (
            VaultError::UnsupportedSchema,
            "unsupported_vault",
            Exit::Failure,
        ),
    ];

    for (vault_error, code, exit) in cases {
        let error = CliError::from(vault_error);
        assert_eq!((error.code(), error.exit()), (code, exit));
        assert!(error.hint().is_some(), "{code} should say how to fix it");
    }
}

#[test]
fn locked_key_should_hint_unlock() {
    let error = CliError::from(VaultError::Key(KeyError::KeychainUnavailable));

    assert!(error.hint().unwrap().contains("smart-env unlock"));
}

#[test]
fn duplicate_name_should_be_named_in_message() {
    let name = VarName::parse("API_KEY").unwrap();

    let error = CliError::from(VaultError::DuplicateName(name));

    assert!(error.message().contains("API_KEY"));
}

#[test]
fn account_errors_should_map_to_contract_exit_codes() {
    let cases = [
        (
            VaultError::AccountNotFound,
            "account_not_found",
            Exit::NotFound,
        ),
        (VaultError::AlreadyMember, "already_member", Exit::Conflict),
        (VaultError::NotAMember, "not_a_member", Exit::Access),
        (
            VaultError::DeviceNeedsAccount,
            "device_needs_account",
            Exit::Failure,
        ),
    ];

    for (vault_error, code, exit) in cases {
        let error = CliError::from(vault_error);
        assert_eq!((error.code(), error.exit()), (code, exit));
        assert!(error.hint().is_some(), "{code} should say how to fix it");
    }
}
