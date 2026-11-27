//! `smart-env allow` / `deny` and `check_trust`: whether the shell hook may
//! load a project directory (ADR-005, step 3 item 2).
mod common;

use std::path::{Path, PathBuf};

use common::{Machine, Run, error_code, json, printed};
use smart_env_cli::{Exit, TrustStatus, check_trust};

const PASSPHRASE: &str = "correct horse battery staple";

// --- helpers ---

fn ok(run: Run) -> Run {
    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    run
}

/// `setup` and `init` of project `payments` (environments `dev`, `prod`).
fn project() -> Machine {
    let m = Machine::new();
    ok(m.setup().0);
    init(&m);
    m
}

fn init(m: &Machine) -> Run {
    m.write(".env", "API_KEY=dev-1\n");
    m.write(".env.production", "API_KEY=prod-1\n");
    ok(m.run(&["init", "--yes"], None))
}

/// The same project checked out in another directory `name` (a fresh
/// clone: never allowed or denied); becomes the working directory.
fn clone(m: &mut Machine, name: &str) -> PathBuf {
    let toml = std::fs::read(m.project.join("smart-env.toml")).unwrap();
    m.use_project_dir(name);
    std::fs::write(m.project.join("smart-env.toml"), toml).unwrap();
    m.project.clone()
}

fn status(m: &Machine, dir: &Path) -> TrustStatus {
    check_trust(&m.context(None), dir).unwrap().status
}

fn toml(m: &Machine) -> String {
    m.read("smart-env.toml").unwrap()
}

fn canonical(dir: &Path) -> PathBuf {
    std::fs::canonicalize(dir).unwrap()
}

// --- allow ---

#[test]
fn a_fresh_checkout_is_not_allowed() {
    let mut m = project();
    let dir = clone(&mut m, "clone");
    assert_eq!(status(&m, &dir), TrustStatus::NotAllowed);
}

#[test]
fn allow_lets_the_hook_load_the_directory() {
    let mut m = project();
    let dir = clone(&mut m, "clone");

    let run = ok(m.run(&["allow"], None));

    assert_eq!(status(&m, &dir), TrustStatus::Allowed);
    assert!(
        run.stdout.contains("✓ Allowed payments/dev in"),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout.contains(&canonical(&dir).display().to_string()),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout
            .contains("A change to smart-env.toml revokes it."),
        "{}",
        run.stdout
    );
}

#[test]
fn check_trust_reports_the_project_directory_and_name() {
    let mut m = project();
    let dir = clone(&mut m, "clone");
    std::fs::create_dir_all(dir.join("src/api")).unwrap();

    let trust = check_trust(&m.context(None), &dir.join("src/api")).unwrap();

    assert_eq!(trust.dir, canonical(&dir));
    assert_eq!(trust.project, "payments");
    assert_eq!(trust.status, TrustStatus::NotAllowed);
}

#[test]
fn allow_from_a_subdirectory_allows_the_whole_project() {
    let mut m = project();
    let dir = clone(&mut m, "clone");
    std::fs::create_dir_all(dir.join("src/api")).unwrap();
    m.project = dir.join("src/api");

    ok(m.run(&["allow"], None));

    assert_eq!(status(&m, &dir), TrustStatus::Allowed);
    assert_eq!(status(&m, &dir.join("src")), TrustStatus::Allowed);
}

#[test]
fn allow_takes_a_directory_argument() {
    let mut m = project();
    let dir = clone(&mut m, "clone");
    m.use_project_dir("elsewhere");

    ok(m.run(&["allow", dir.to_str().unwrap()], None));

    assert_eq!(status(&m, &dir), TrustStatus::Allowed);
}

#[test]
fn allow_again_is_already_allowed() {
    let mut m = project();
    clone(&mut m, "clone");
    ok(m.run(&["allow"], None));

    let run = ok(m.run(&["allow"], None));

    assert!(run.stdout.contains("✓ payments/dev in"), "{}", run.stdout);
    assert!(run.stdout.contains("is already allowed"), "{}", run.stdout);
}

// --- changes to smart-env.toml ---

#[test]
fn changing_smart_env_toml_revokes_the_allow() {
    let mut m = project();
    let dir = clone(&mut m, "clone");
    ok(m.run(&["allow"], None));

    m.write("smart-env.toml", &format!("{}# comment\n", toml(&m)));
    assert_eq!(status(&m, &dir), TrustStatus::Changed);

    let run = ok(m.run(&["allow"], None));
    assert_eq!(status(&m, &dir), TrustStatus::Allowed);
    assert!(
        run.stdout
            .contains("(smart-env.toml changed since the last allow)"),
        "{}",
        run.stdout
    );
}

#[test]
fn switching_the_environment_in_smart_env_toml_revokes_the_allow() {
    let mut m = project();
    let dir = clone(&mut m, "clone");
    ok(m.run(&["allow"], None));

    m.write(
        "smart-env.toml",
        &toml(&m).replace("environment = \"dev\"", "environment = \"prod\""),
    );

    assert_eq!(status(&m, &dir), TrustStatus::Changed);
}

#[test]
fn writing_the_same_content_keeps_the_allow() {
    let mut m = project();
    let dir = clone(&mut m, "clone");
    ok(m.run(&["allow"], None));

    let content = toml(&m);
    std::fs::remove_file(dir.join("smart-env.toml")).unwrap();
    m.write("smart-env.toml", &content);

    assert_eq!(status(&m, &dir), TrustStatus::Allowed);
}

// --- paths ---

#[test]
fn a_symlink_to_an_allowed_directory_is_allowed() {
    let mut m = project();
    let dir = clone(&mut m, "clone");
    ok(m.run(&["allow"], None));
    let link = dir.parent().unwrap().join("link");
    std::os::unix::fs::symlink(&dir, &link).unwrap();

    let trust = check_trust(&m.context(None), &link).unwrap();

    assert_eq!(trust.status, TrustStatus::Allowed);
    assert_eq!(trust.dir, canonical(&dir));
}

#[test]
fn a_moved_directory_is_not_allowed() {
    let mut m = project();
    let dir = clone(&mut m, "clone");
    ok(m.run(&["allow"], None));
    let moved = dir.parent().unwrap().join("moved");
    std::fs::rename(&dir, &moved).unwrap();

    assert_eq!(status(&m, &moved), TrustStatus::NotAllowed);
}

#[test]
fn a_nested_project_needs_its_own_allow() {
    let mut m = project();
    let dir = clone(&mut m, "clone");
    ok(m.run(&["allow"], None));
    let nested = dir.join("services/other");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::copy(dir.join("smart-env.toml"), nested.join("smart-env.toml")).unwrap();

    assert_eq!(status(&m, &nested), TrustStatus::NotAllowed);
    assert_eq!(status(&m, &dir.join("services")), TrustStatus::Allowed);
}

// --- allow: refused ---

#[test]
fn allow_refuses_a_project_that_is_not_in_the_vault() {
    let mut m = project();
    let dir = clone(&mut m, "clone");
    m.write(
        "smart-env.toml",
        "project = \"other\"\nproject_id = \"0b9e6d3c-5f1a-4c8e-9d2b-7a6e1f3c8b40\"\nenvironment = \"dev\"\n",
    );

    let run = m.run(&["allow", "--json"], None);

    assert_eq!(run.exit, Exit::NotFound, "{}", printed(&run));
    assert_eq!(error_code(&run), "project_not_found");
    assert_eq!(status(&m, &dir), TrustStatus::NotAllowed);
}

#[test]
fn allow_refuses_a_project_id_that_does_not_match_the_name() {
    let mut m = project();
    let dir = clone(&mut m, "clone");
    m.write(
        "smart-env.toml",
        "project = \"payments\"\nproject_id = \"0b9e6d3c-5f1a-4c8e-9d2b-7a6e1f3c8b40\"\nenvironment = \"dev\"\n",
    );

    let run = m.run(&["allow", "--json"], None);

    assert_eq!(run.exit, Exit::Conflict, "{}", printed(&run));
    assert_eq!(error_code(&run), "project_id_mismatch");
    assert_eq!(status(&m, &dir), TrustStatus::NotAllowed);
}

#[test]
fn allow_without_smart_env_toml_points_at_init() {
    let mut m = project();
    m.use_project_dir("empty");

    let run = m.run(&["allow", "--json"], None);

    assert_eq!(run.exit, Exit::NotFound, "{}", printed(&run));
    assert_eq!(error_code(&run), "project_file_not_found");
}

#[test]
fn allow_and_deny_refuse_a_directory_that_does_not_exist() {
    let m = project();
    let missing = m.project.join("no-such-dir");
    for command in ["allow", "deny"] {
        let run = m.run(&[command, "--json", missing.to_str().unwrap()], None);
        assert_eq!(run.exit, Exit::NotFound, "{command}: {}", printed(&run));
        assert_eq!(error_code(&run), "directory_not_found", "{command}");
    }
    // The parent's smart-env.toml was not allowed or denied by accident.
    assert_eq!(status(&m, &m.project), TrustStatus::Allowed);
}

#[test]
fn allow_and_deny_need_setup() {
    let m = Machine::new();
    m.write(
        "smart-env.toml",
        "project = \"payments\"\nproject_id = \"0b9e6d3c-5f1a-4c8e-9d2b-7a6e1f3c8b40\"\nenvironment = \"dev\"\n",
    );
    for command in ["allow", "deny"] {
        let run = m.run(&[command, "--json"], None);
        assert_eq!(run.exit, Exit::NotFound, "{command}");
        assert_eq!(error_code(&run), "not_set_up", "{command}");
    }
}

#[test]
fn allow_works_with_a_locked_key() {
    let mut m = Machine::without_keychain();
    ok(m.setup_with_passphrase(PASSPHRASE).0);
    init(&m);
    ok(m.run(&["lock"], None));
    let dir = clone(&mut m, "clone");

    ok(m.run(&["allow"], None));

    assert_eq!(status(&m, &dir), TrustStatus::Allowed);
}

#[test]
fn allow_creates_a_missing_state_database() {
    let mut m = project();
    let dir = clone(&mut m, "clone");
    std::fs::remove_file(m.state_db()).unwrap();

    ok(m.run(&["allow"], None));

    assert!(m.state_db().exists());
    assert_eq!(status(&m, &dir), TrustStatus::Allowed);
}

// --- deny ---

#[test]
fn deny_stops_the_hook_whatever_the_file_says() {
    let mut m = project();
    let dir = clone(&mut m, "clone");

    let run = ok(m.run(&["deny"], None));

    assert_eq!(status(&m, &dir), TrustStatus::Denied);
    assert!(
        run.stdout.contains("✓ The shell hook will not load"),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("smart-env allow"), "{}", run.stdout);

    m.write("smart-env.toml", &format!("{}# changed\n", toml(&m)));
    assert_eq!(status(&m, &dir), TrustStatus::Denied);
}

#[test]
fn deny_works_for_a_project_that_is_not_in_the_vault() {
    let mut m = project();
    let dir = clone(&mut m, "foreign");
    m.write(
        "smart-env.toml",
        "project = \"other\"\nproject_id = \"0b9e6d3c-5f1a-4c8e-9d2b-7a6e1f3c8b40\"\nenvironment = \"dev\"\n",
    );

    ok(m.run(&["deny"], None));

    assert_eq!(status(&m, &dir), TrustStatus::Denied);
}

#[test]
fn the_last_decision_wins() {
    let mut m = project();
    let dir = clone(&mut m, "clone");

    ok(m.run(&["deny"], None));
    ok(m.run(&["allow"], None));
    assert_eq!(status(&m, &dir), TrustStatus::Allowed);

    ok(m.run(&["deny"], None));
    assert_eq!(status(&m, &dir), TrustStatus::Denied);
}

// --- --json ---

#[test]
fn json_reports_allow_and_deny() {
    let mut m = project();
    let dir = clone(&mut m, "clone");
    let path = canonical(&dir).display().to_string();

    let first = json(&ok(m.run(&["allow", "--json"], None)).stdout);
    assert_eq!(first["status"], "allowed");
    assert_eq!(first["path"], path);
    assert_eq!(first["project"], "payments");
    assert_eq!(first["environment"], "dev");

    let again = json(&ok(m.run(&["allow", "--json"], None)).stdout);
    assert_eq!(again["status"], "already_allowed");

    let denied = json(&ok(m.run(&["deny", "--json"], None)).stdout);
    assert_eq!(denied["status"], "denied");
    assert_eq!(denied["path"], path);
}

// --- check_trust ---

#[test]
fn check_trust_outside_a_project_is_project_file_not_found() {
    let mut m = project();
    m.use_project_dir("empty");
    let error = check_trust(&m.context(None), &m.project).unwrap_err();
    assert_eq!(error.code(), "project_file_not_found");
}

// --- init ---

#[test]
fn init_allows_its_directory() {
    let m = Machine::new();
    ok(m.setup().0);

    let run = init(&m);

    assert_eq!(status(&m, &m.project), TrustStatus::Allowed);
    assert!(
        run.stdout
            .contains("✓ Allowed this directory for the shell hook"),
        "{}",
        run.stdout
    );
}
