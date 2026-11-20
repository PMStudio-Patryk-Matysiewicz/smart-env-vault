use smart_env_cli::EnvRef;

fn parse(input: &str) -> Result<EnvRef, smart_env_cli::EnvRefError> {
    input.parse()
}

#[test]
fn environment_alone_should_refer_to_current_project() {
    let env = parse("dev").unwrap();

    assert_eq!(env.project, None);
    assert_eq!(env.environment, "dev");
}

#[test]
fn project_and_environment_should_be_split_on_slash() {
    let env = parse("payments/prod").unwrap();

    assert_eq!(env.project.as_deref(), Some("payments"));
    assert_eq!(env.environment, "prod");
}

#[test]
fn malformed_env_should_be_rejected() {
    for input in [
        "",
        "/",
        "/dev",
        "payments/",
        "a/b/c",
        " dev",
        "pay ments/dev",
    ] {
        assert!(parse(input).is_err(), "{input:?} should be rejected");
    }
}
