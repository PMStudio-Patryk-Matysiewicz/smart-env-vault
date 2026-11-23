mod common;

use common::{
    Machine, Run, ScriptedTerminal, error_code, is_passphrase_question, json, last4, printed,
    shown_key,
};
use smart_env_cli::{Exit, FILE_NAME, ProjectFile};
use smart_env_vault::{EnvKind, EnvironmentInfo, Vault};

const SECRET: &str = "hunter2";

// --- helpers ---

/// Terminal that confirms a recovery key if `setup` runs, answers the
/// passphrase question with `passphrase`, and answers the import and delete
/// questions.
fn answering(import: &'static str, delete: &'static str) -> ScriptedTerminal {
    ScriptedTerminal::new(move |transcript, question| {
        if question.contains("Import?") {
            import.to_owned()
        } else if question.contains("Delete plaintext") {
            delete.to_owned()
        } else if is_passphrase_question(question) {
            "correct horse battery".to_owned()
        } else {
            last4(&shown_key(transcript))
        }
    })
}

/// A machine after `setup`, with an empty project directory `payments`.
fn ready() -> Machine {
    let m = Machine::new();
    let (run, _) = m.setup();
    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    m
}

fn init(m: &Machine, args: &[&str]) -> Run {
    let mut argv = vec!["init"];
    argv.extend_from_slice(args);
    m.run(&argv, None)
}

fn init_yes(m: &Machine) -> Run {
    let run = init(m, &["--yes"]);
    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    run
}

fn init_on_terminal(m: &Machine, terminal: &mut ScriptedTerminal) -> Run {
    m.run(&["init"], Some(terminal))
}

fn project_id(vault: &Vault, name: &str) -> smart_env_vault::ProjectId {
    vault
        .find_project(name)
        .unwrap()
        .unwrap_or_else(|| panic!("project {name} in the vault"))
}

fn environments(m: &Machine, project: &str) -> Vec<EnvironmentInfo> {
    let vault = m.vault();
    vault.environments(project_id(&vault, project)).unwrap()
}

/// Decrypted variables of `project/environment`, sorted by name.
fn values(m: &Machine, project: &str, environment: &str) -> Vec<(String, String)> {
    let vault = m.vault();
    let env = vault
        .environments(project_id(&vault, project))
        .unwrap()
        .into_iter()
        .find(|info| info.name == environment)
        .unwrap_or_else(|| panic!("environment {project}/{environment}"))
        .id;
    let key = m.stored_key().expect("device key in the keychain");
    vault
        .read_all(env, &key)
        .unwrap()
        .into_iter()
        .map(|(meta, value)| (meta.name.to_string(), value.expose().to_owned()))
        .collect()
}

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect()
}

fn project_file(m: &Machine) -> ProjectFile {
    ProjectFile::parse(&m.read(FILE_NAME).expect("smart-env.toml written")).unwrap()
}

fn no_project(m: &Machine, name: &str) -> bool {
    !m.vault_db().exists() || m.vault().find_project(name).unwrap().is_none()
}

/// The line of `text` that contains every part.
fn line_with<'a>(text: &'a str, parts: &[&str]) -> &'a str {
    text.lines()
        .find(|line| parts.iter().all(|part| line.contains(part)))
        .unwrap_or_else(|| panic!("no line with {parts:?} in:\n{text}"))
}

fn has_line_with(text: &str, parts: &[&str]) -> bool {
    text.lines()
        .any(|line| parts.iter().all(|part| line.contains(part)))
}

fn position(text: &str, parts: &[&str]) -> usize {
    let line = line_with(text, parts);
    text.find(line).unwrap()
}

/// Nothing written by a refused `init`: no project, no `smart-env.toml`, no
/// `.gitignore`, files untouched.
fn assert_untouched(m: &Machine, files: &[(&str, &str)]) {
    assert!(no_project(m, "payments"), "project created");
    assert!(!m.exists(FILE_NAME), "smart-env.toml written");
    assert!(!m.exists(".gitignore"), ".gitignore written");
    for (name, content) in files {
        assert_eq!(m.read(name).as_deref(), Some(*content), "{name} changed");
    }
}

// --- happy path ---

#[test]
fn interactive_import_verifies_writes_config_and_deletes_plaintext() {
    let m = ready();
    m.write(
        ".env",
        "DATABASE_URL=postgres://localhost/app\nAPI_KEY=abc\n",
    );
    m.write(".env.production", "DATABASE_URL=postgres://prod/app\n");
    m.write(".env.example", "DATABASE_URL=\nAPI_KEY=\n");
    let mut terminal = answering("y", "y");

    let run = init_on_terminal(&m, &mut terminal);

    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    assert_eq!(
        values(&m, "payments", "dev"),
        pairs(&[
            ("API_KEY", "abc"),
            ("DATABASE_URL", "postgres://localhost/app")
        ])
    );
    assert_eq!(
        values(&m, "payments", "prod"),
        pairs(&[("DATABASE_URL", "postgres://prod/app")])
    );
    let file = project_file(&m);
    assert_eq!(file.project, "payments");
    assert_eq!(file.environment, "dev");
    assert_eq!(file.project_id, project_id(&m.vault(), "payments"));
    assert!(!m.exists(".env"));
    assert!(!m.exists(".env.production"));
    assert!(m.exists(".env.example"), "templates are never deleted");
}

#[test]
fn output_follows_the_contract() {
    let m = ready();
    m.write(".env", "A=1\nB=2\n");
    m.write(".env.production", "A=3\n");
    m.write(".env.example", "A=\n");
    let mut terminal = answering("y", "y");

    let out = init_on_terminal(&m, &mut terminal).stdout;

    line_with(&out, &["Found files:"]);
    line_with(&out, &[".env ", "→ payments/dev", "(2 variables)"]);
    line_with(
        &out,
        &[".env.production", "→ payments/prod", "(1 variable)"],
    );
    line_with(&out, &[".env.example", "skipped (template)"]);
    line_with(&out, &["✓ Imported and verified 3 variables"]);
    line_with(&out, &["✓ Created smart-env.toml", "safe to commit"]);
    line_with(&out, &["✓ Added .env, .env.production to .gitignore"]);
    line_with(&out, &["✓ Deleted 2 files"]);
    assert_eq!(
        out.lines().last(),
        Some("Next: smart-env run -- <your command>")
    );
    assert!(
        position(&out, &["Found files:"]) < position(&out, &["✓ Imported"])
            && position(&out, &["✓ Imported"]) < position(&out, &["✓ Created smart-env.toml"])
            && position(&out, &["✓ Created smart-env.toml"]) < position(&out, &["✓ Deleted"])
    );
    assert!(terminal.transcript.contains("? Import? [Y/n]"));
    assert!(
        terminal
            .transcript
            .contains("? Delete plaintext files .env, .env.production? [Y/n]")
    );
    assert_eq!(terminal.questions, 2);
}

#[test]
fn empty_answers_mean_yes() {
    let m = ready();
    m.write(".env", "A=1\n");
    let mut terminal = answering("", "");
    let run = init_on_terminal(&m, &mut terminal);
    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    assert_eq!(values(&m, "payments", "dev"), pairs(&[("A", "1")]));
    assert!(!m.exists(".env"));
}

#[test]
fn yes_flag_imports_and_deletes_without_a_terminal() {
    let m = ready();
    m.write(".env", "A=1\n");
    init_yes(&m);
    assert_eq!(values(&m, "payments", "dev"), pairs(&[("A", "1")]));
    assert!(m.exists(FILE_NAME));
    assert!(!m.exists(".env"));
}

// --- declining ---

#[test]
fn declining_the_import_writes_nothing() {
    let m = ready();
    m.write(".env", "A=1\n");
    let mut terminal = answering("n", "y");
    let run = init_on_terminal(&m, &mut terminal);
    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    line_with(&run.stdout, &["Nothing imported"]);
    assert_untouched(&m, &[(".env", "A=1\n")]);
    assert_eq!(terminal.questions, 1);
}

#[test]
fn declining_the_deletion_keeps_the_plaintext() {
    let m = ready();
    m.write(".env", "A=1\n");
    let mut terminal = answering("y", "n");
    let run = init_on_terminal(&m, &mut terminal);
    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    assert_eq!(values(&m, "payments", "dev"), pairs(&[("A", "1")]));
    assert!(m.exists(FILE_NAME));
    assert_eq!(m.read(".env").as_deref(), Some("A=1\n"));
    line_with(&run.stdout, &["! Plaintext files kept: .env"]);
    assert!(!has_line_with(&run.stdout, &["✓ Deleted"]));
}

#[test]
fn without_terminal_and_without_yes_confirmation_is_required() {
    let m = ready();
    m.write(".env", "A=1\n");
    let run = init(&m, &["--json"]);
    assert_eq!(run.exit, Exit::Usage);
    assert_eq!(error_code(&run), "confirmation_required");
    assert_untouched(&m, &[(".env", "A=1\n")]);
}

// --- file discovery and mapping ---

#[test]
fn files_map_to_environments_and_kinds() {
    let m = ready();
    m.write(".env", "A=dev\n");
    m.write(".env.staging", "A=staging\n");
    m.write(".env.production", "A=prod\n");
    m.write(".env.test", "A=test\n");
    init_yes(&m);
    assert_eq!(
        environments(&m, "payments")
            .into_iter()
            .map(|info| (info.name, info.kind))
            .collect::<Vec<_>>(),
        vec![
            ("dev".to_owned(), EnvKind::Dev),
            ("prod".to_owned(), EnvKind::Prod),
            ("staging".to_owned(), EnvKind::Staging),
            ("test".to_owned(), EnvKind::Custom),
        ]
    );
    assert_eq!(values(&m, "payments", "test"), pairs(&[("A", "test")]));
}

#[test]
fn development_is_an_alias_of_dev() {
    let m = ready();
    m.write(".env.development", "A=1\n");
    init_yes(&m);
    assert_eq!(values(&m, "payments", "dev"), pairs(&[("A", "1")]));
}

#[test]
fn listing_order_is_dev_staging_prod_then_alphabetical() {
    let m = ready();
    for name in [
        ".env.zeta",
        ".env.production",
        ".env.alpha",
        ".env.staging",
        ".env",
    ] {
        m.write(name, "A=1\n");
    }
    let out = init_yes(&m).stdout;
    let order: Vec<usize> = ["/dev ", "/staging ", "/prod ", "/alpha ", "/zeta "]
        .iter()
        .map(|env| position(&out, &["→ payments", env]))
        .collect();
    assert!(order.windows(2).all(|pair| pair[0] < pair[1]), "{out}");
}

#[test]
fn local_files_override_their_base_in_framework_order() {
    let m = ready();
    m.write(".env", "A=env\nB=env\nC=env\nD=env\n");
    m.write(
        ".env.development",
        "B=development\nC=development\nD=development\n",
    );
    m.write(".env.local", "C=local\nD=local\n");
    m.write(".env.development.local", "D=development.local\n");
    m.write(".env.production", "A=production\nB=production\n");
    m.write(".env.production.local", "B=production.local\n");

    let out = init_yes(&m).stdout;

    assert_eq!(
        values(&m, "payments", "dev"),
        pairs(&[
            ("A", "env"),
            ("B", "development"),
            ("C", "local"),
            ("D", "development.local"),
        ])
    );
    assert_eq!(
        values(&m, "payments", "prod"),
        pairs(&[("A", "production"), ("B", "production.local")])
    );
    line_with(
        &out,
        &[
            ".env + .env.development + .env.local + .env.development.local",
            "→ payments/dev",
            "(4 variables)",
        ],
    );
    line_with(
        &out,
        &[
            ".env.production + .env.production.local",
            "→ payments/prod",
            "(2 variables)",
        ],
    );
    line_with(&out, &["✓ Imported and verified 6 variables"]);
    line_with(&out, &["✓ Deleted 6 files"]);
    for name in [
        ".env",
        ".env.development",
        ".env.local",
        ".env.development.local",
        ".env.production",
        ".env.production.local",
    ] {
        assert!(!m.exists(name), "{name} deleted");
    }
}

#[test]
fn local_file_alone_is_dev() {
    let m = ready();
    m.write(".env.local", "A=1\n");
    init_yes(&m);
    assert_eq!(values(&m, "payments", "dev"), pairs(&[("A", "1")]));
}

#[test]
fn templates_are_skipped_and_kept() {
    let m = ready();
    m.write(".env", "A=1\n");
    for name in [".env.example", ".env.sample", ".env.template", ".env.dist"] {
        m.write(name, "A=\n");
    }
    let out = init_yes(&m).stdout;
    for name in [".env.example", ".env.sample", ".env.template", ".env.dist"] {
        line_with(&out, &[name, "skipped (template)"]);
        assert!(m.exists(name), "{name} kept");
    }
    assert_eq!(
        environments(&m, "payments")
            .into_iter()
            .map(|info| info.name)
            .collect::<Vec<_>>(),
        vec!["dev".to_owned()]
    );
}

#[test]
fn other_names_and_directories_are_ignored() {
    let m = ready();
    m.write(".env", "A=1\n");
    m.write("prod.env", "A=2\n");
    m.write(".envrc", "export A=3\n");
    std::fs::create_dir(m.project.join(".env.d")).unwrap();
    let out = init_yes(&m).stdout;
    assert!(m.exists("prod.env") && m.exists(".envrc"));
    assert!(!out.contains("prod.env") && !out.contains(".envrc") && !out.contains(".env.d"));
    assert_eq!(environments(&m, "payments").len(), 1);
}

#[test]
fn invalid_environment_name_is_skipped_and_kept() {
    let m = ready();
    m.write(".env", "A=1\n");
    m.write(".env.my env", "A=2\n");
    let out = init_yes(&m).stdout;
    line_with(&out, &[".env.my env", "skipped (invalid environment name)"]);
    assert!(m.exists(".env.my env"));
    assert_eq!(environments(&m, "payments").len(), 1);
}

#[test]
fn no_env_files_creates_an_empty_dev_environment() {
    let m = ready();
    let run = init_yes(&m);
    assert!(values(&m, "payments", "dev").is_empty());
    assert_eq!(project_file(&m).environment, "dev");
    line_with(&run.stdout, &["no .env files"]);
    assert!(!run.stdout.contains("Delete"));
}

// --- --env and project name ---

#[test]
fn env_flag_sets_project_name_and_default_environment() {
    let m = ready();
    m.write(".env", "A=1\n");
    init(&m, &["--yes", "--env", "shop/main"]);
    let file = project_file(&m);
    assert_eq!(file.project, "shop");
    assert_eq!(file.environment, "main");
    assert_eq!(values(&m, "shop", "dev"), pairs(&[("A", "1")]));
    assert!(
        values(&m, "shop", "main").is_empty(),
        "missing default is created empty"
    );
    assert!(no_project(&m, "payments"));
}

#[test]
fn env_flag_without_project_keeps_the_directory_name() {
    let m = ready();
    m.write(".env.staging", "A=1\n");
    init(&m, &["--yes", "--env", "staging"]);
    let file = project_file(&m);
    assert_eq!(file.project, "payments");
    assert_eq!(file.environment, "staging");
    assert_eq!(environments(&m, "payments").len(), 1);
}

#[test]
fn invalid_directory_name_needs_a_project_name() {
    let mut m = ready();
    m.use_project_dir("my app");
    m.write(".env", "A=1\n");
    let run = init(&m, &["--yes", "--json"]);
    assert_eq!(run.exit, Exit::Failure);
    assert_eq!(error_code(&run), "invalid_project_name");
    assert!(
        json(&run.stdout)["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("smart-env init --env")
    );
    assert_eq!(m.read(".env").as_deref(), Some("A=1\n"));
    assert!(!m.exists(FILE_NAME));
}

// --- refusals ---

#[test]
fn already_initialized_directory_is_left_alone() {
    let m = ready();
    let config = "project = \"payments\"\n";
    m.write(FILE_NAME, config);
    m.write(".env", "A=1\n");
    let run = init(&m, &["--yes", "--json"]);
    assert_eq!(run.exit, Exit::Conflict);
    assert_eq!(error_code(&run), "already_initialized");
    assert_eq!(m.read(FILE_NAME).as_deref(), Some(config));
    assert_eq!(m.read(".env").as_deref(), Some("A=1\n"));
    assert!(no_project(&m, "payments"));
}

#[test]
fn taken_project_name_is_a_conflict() {
    let m = ready();
    m.vault().create_project("payments").unwrap();
    m.write(".env", "A=1\n");
    let run = init(&m, &["--yes", "--json"]);
    assert_eq!(run.exit, Exit::Conflict);
    assert_eq!(error_code(&run), "project_name_taken");
    assert_eq!(m.read(".env").as_deref(), Some("A=1\n"));
    assert!(!m.exists(FILE_NAME));
}

#[test]
fn parse_error_in_any_file_writes_nothing() {
    let m = ready();
    m.write(".env", "A=1\n");
    m.write(".env.production", "OK=1\nbad-name=hunter2\n");
    let run = init(&m, &["--yes", "--json"]);
    assert_eq!(run.exit, Exit::Failure);
    assert_eq!(error_code(&run), "env_file_invalid");
    let message = json(&run.stdout)["error"]["message"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        message.contains(".env.production") && message.contains("line 2"),
        "{message}"
    );
    assert!(!printed(&run).contains(SECRET));
    assert_untouched(
        &m,
        &[
            (".env", "A=1\n"),
            (".env.production", "OK=1\nbad-name=hunter2\n"),
        ],
    );
}

// --- keys and setup ---

#[test]
fn init_runs_setup_first_on_a_new_machine() {
    let m = Machine::new();
    m.write(".env", "A=1\n");
    let mut terminal = answering("y", "y");
    let run = init_on_terminal(&m, &mut terminal);
    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    assert!(
        position(&run.stdout, &["✓ Recovery key confirmed"])
            < position(&run.stdout, &["✓ Imported and verified 1 variable"])
    );
    assert_eq!(values(&m, "payments", "dev"), pairs(&[("A", "1")]));
}

#[test]
fn locked_key_is_reported_before_anything_is_written() {
    let m = Machine::without_keychain();
    let (setup, _) = m.setup_with_passphrase("correct horse battery");
    assert_eq!(setup.exit, Exit::Success, "{}", printed(&setup));
    m.session.delete().unwrap();
    m.write(".env", "A=1\n");
    let run = init(&m, &["--yes", "--json"]);
    assert_eq!(run.exit, Exit::Access);
    assert_eq!(error_code(&run), "key_locked");
    assert_untouched(&m, &[(".env", "A=1\n")]);
}

// --- .gitignore ---

#[test]
fn gitignore_is_created_with_imported_files_only() {
    let m = ready();
    m.write(".env", "A=1\n");
    m.write(".env.local", "B=1\n");
    m.write(".env.example", "A=\n");
    init_yes(&m);
    let ignore = m.read(".gitignore").unwrap();
    let lines: Vec<&str> = ignore.lines().collect();
    assert!(
        lines.contains(&"/.env") && lines.contains(&"/.env.local"),
        "{ignore}"
    );
    assert!(!ignore.contains(".env.example"), "{ignore}");
}

#[test]
fn gitignore_is_appended_on_a_new_line() {
    let m = ready();
    m.write(".gitignore", "node_modules");
    m.write(".env", "A=1\n");
    init_yes(&m);
    let ignore = m.read(".gitignore").unwrap();
    let lines: Vec<&str> = ignore.lines().collect();
    assert_eq!(lines.first(), Some(&"node_modules"), "{ignore}");
    assert!(lines.contains(&"/.env"), "{ignore}");
}

#[test]
fn gitignore_line_already_present_is_not_repeated() {
    let m = ready();
    m.write(".gitignore", ".env\n");
    m.write(".env", "A=1\n");
    let out = init_yes(&m).stdout;
    assert_eq!(m.read(".gitignore").as_deref(), Some(".env\n"));
    assert!(!has_line_with(&out, &["to .gitignore"]), "{out}");
}

#[test]
fn files_git_already_ignores_are_not_added() {
    let m = ready();
    m.git(&["init", "-q"]);
    m.write(".gitignore", ".env*\n!.env.example\n");
    m.write(".env", "A=1\n");
    m.write(".env.production", "A=2\n");
    let out = init_yes(&m).stdout;
    assert_eq!(
        m.read(".gitignore").as_deref(),
        Some(".env*\n!.env.example\n")
    );
    assert!(!has_line_with(&out, &["to .gitignore"]), "{out}");
}

// --- git history ---

#[test]
fn committed_env_file_is_reported_with_its_commit_count() {
    let m = ready();
    m.git(&["init", "-q"]);
    m.write(".env", "A=1\n");
    m.git(&["add", ".env"]);
    m.git(&["commit", "-q", "-m", "first"]);
    m.write(".env", "A=2\n");
    m.git(&["commit", "-q", "-am", "second"]);

    let run = init(&m, &["--yes"]);

    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    line_with(
        &run.stdout,
        &[
            "! .env was in git history (2 commits)",
            "smart-env scan --history",
        ],
    );
    line_with(&run.stdout, &["git rm --cached .env"]);
}

#[test]
fn untracked_env_file_in_a_repository_has_no_history_warning() {
    let m = ready();
    m.git(&["init", "-q"]);
    m.write("README", "x\n");
    m.git(&["add", "README"]);
    m.git(&["commit", "-q", "-m", "readme"]);
    m.write(".env", "A=1\n");
    let out = init_yes(&m).stdout;
    assert!(!out.contains("git history"), "{out}");
    assert!(!out.contains("git rm"), "{out}");
}

#[test]
fn outside_a_repository_there_is_no_history_check() {
    let m = ready();
    m.write(".env", "A=1\n");
    let out = init_yes(&m).stdout;
    assert!(!out.contains("git history"), "{out}");
}

// --- warnings ---

#[test]
fn reserved_names_are_imported_with_one_warning() {
    let m = ready();
    m.write(
        ".env",
        "PATH=/opt/bin\nnode_options=--inspect\nGIT_DIR=/tmp/x\nAPI=1\n",
    );
    let out = init_yes(&m).stdout;
    assert_eq!(values(&m, "payments", "dev").len(), 4);
    line_with(
        &out,
        &[
            "! GIT_DIR, PATH, node_options are reserved names",
            "smart-env allow --var NAME",
        ],
    );
    assert!(!out.contains("API,") && !out.contains(", API"), "{out}");
}

#[test]
fn interpolation_warning_names_file_line_and_variable() {
    let m = ready();
    m.write(".env", "A=1\nURL=${HOST}/x\n");
    let out = init_yes(&m).stdout;
    line_with(&out, &["! .env line 2: URL", "kept literally"]);
    assert_eq!(values(&m, "payments", "dev")[1].1, "${HOST}/x");
}

// --- JSON ---

#[test]
fn json_output_describes_the_import_without_values() {
    let m = ready();
    m.write(".env", "A=hunter2\nB=2\n");
    m.write(".env.production", "A=hunter2\n");
    m.write(".env.example", "A=\n");

    let run = init(&m, &["--yes", "--json"]);

    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    assert!(!printed(&run).contains(SECRET));
    let report = json(&run.stdout);
    assert_eq!(report["status"], "initialized");
    assert_eq!(report["project"], "payments");
    assert_eq!(
        report["project_id"].as_str().unwrap(),
        project_id(&m.vault(), "payments").to_string()
    );
    assert_eq!(
        report["environments"],
        serde_json::json!([
            {"name": "dev", "files": [".env"], "variables": 2},
            {"name": "prod", "files": [".env.production"], "variables": 1},
        ])
    );
    assert_eq!(
        report["skipped"],
        serde_json::json!([{"file": ".env.example", "reason": "template"}])
    );
    assert_eq!(
        report["gitignore"],
        serde_json::json!([".env", ".env.production"])
    );
    assert_eq!(
        report["deleted"],
        serde_json::json!([".env", ".env.production"])
    );
    assert_eq!(report["git_history"], serde_json::json!([]));
}

#[test]
fn json_reports_a_declined_import() {
    let m = ready();
    m.write(".env", "A=1\n");
    let mut terminal = answering("n", "y");
    let run = m.run(&["init", "--json"], Some(&mut terminal));
    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    assert_eq!(json(&run.stdout)["status"], "declined");
    assert_untouched(&m, &[(".env", "A=1\n")]);
}

// --- no echo ---

#[test]
fn values_never_leave_the_vault() {
    let m = ready();
    m.write(
        ".env",
        "PASSWORD=hunter2\nURL=\"postgres://u:hunter2@db/${NAME}\"\nPATH=/hunter2\n",
    );
    m.write(".env.production", "PASSWORD='hunter2'\n");
    let mut terminal = answering("y", "n");

    let run = init_on_terminal(&m, &mut terminal);

    assert_eq!(run.exit, Exit::Success, "{}", printed(&run));
    assert!(!printed(&run).contains(SECRET), "{}", printed(&run));
    assert!(
        !terminal.transcript.contains(SECRET),
        "{}",
        terminal.transcript
    );
    assert!(!m.read(FILE_NAME).unwrap().contains(SECRET));
    assert!(!m.read(".gitignore").unwrap().contains(SECRET));
}
