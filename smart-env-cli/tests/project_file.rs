use smart_env_cli::{CliError, Exit, FILE_NAME, ProjectFile, ProjectFileError, ResolvedProject};
use smart_env_vault::{ProjectId, Vault};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const ID: &str = "0b9e6d3c-5f1a-4c8e-9d2b-7a6e1f3c8b40";

fn minimal() -> String {
    format!("project = \"payments\"\nproject_id = \"{ID}\"\nenvironment = \"dev\"\n")
}

fn parse_err(text: &str) -> ProjectFileError {
    match ProjectFile::parse(text) {
        Ok(file) => panic!("expected an error, got {file:?}"),
        Err(error) => error,
    }
}

fn write(dir: &Path, text: &str) {
    fs::write(dir.join(FILE_NAME), text).unwrap();
}

/// The secret must not appear anywhere the user or a script could see it.
fn assert_no_echo(error: &CliError, secret: &str) {
    assert!(
        !error.message().contains(secret),
        "message: {}",
        error.message()
    );
    assert!(
        !error.hint().unwrap_or("").contains(secret),
        "hint: {:?}",
        error.hint()
    );
    assert!(!error.render_human().contains(secret));
    assert!(!error.render_json().contains(secret));
}

// --- parse ---

#[test]
fn parse_minimal_file() {
    let file = ProjectFile::parse(&minimal()).unwrap();

    assert_eq!(file.project, "payments");
    assert_eq!(file.project_id, ID.parse::<ProjectId>().unwrap());
    assert_eq!(file.environment, "dev");
    assert_eq!(file.server, None);
    assert!(file.sync.is_empty());
}

#[test]
fn parse_keeps_comments_server_and_sync_targets() {
    let text = format!(
        "# projekt\n{}server = \"https://vault.example.com\"\n\n\
         [sync.github]\nrepository = \"firma/payments\"\n\
         environments = {{ staging = \"staging\", prod = \"production\" }}\n\n\
         [sync.vercel]\nproject = \"payments-web\"\n",
        minimal()
    );

    let file = ProjectFile::parse(&text).unwrap();

    assert_eq!(file.server.as_deref(), Some("https://vault.example.com"));
    assert_eq!(file.sync, ["github", "vercel"]);
}

#[test]
fn parse_rejects_missing_required_keys() {
    for key in ["project", "project_id", "environment"] {
        let text: String = minimal()
            .lines()
            .filter(|line| !line.starts_with(&format!("{key} ")))
            .map(|line| format!("{line}\n"))
            .collect();

        assert_eq!(parse_err(&text), ProjectFileError::MissingKey(key), "{key}");
    }
}

#[test]
fn parse_rejects_unknown_top_level_key_by_name() {
    let text = format!("{}API_KEY = \"hunter2\"\n", minimal());

    assert_eq!(
        parse_err(&text),
        ProjectFileError::UnknownKey("API_KEY".to_owned())
    );
}

#[test]
fn parse_rejects_unknown_table() {
    let text = format!("{}[secrets]\nAPI_KEY = \"hunter2\"\n", minimal());

    assert_eq!(
        parse_err(&text),
        ProjectFileError::UnknownKey("secrets".to_owned())
    );
}

#[test]
fn parse_rejects_wrong_types() {
    let cases = [
        (
            "project",
            "project = 42\nproject_id = \"ID\"\nenvironment = \"dev\"\n",
        ),
        (
            "project_id",
            "project = \"payments\"\nproject_id = 42\nenvironment = \"dev\"\n",
        ),
        (
            "environment",
            "project = \"payments\"\nproject_id = \"ID\"\nenvironment = [\"dev\"]\n",
        ),
        (
            "server",
            "project = \"payments\"\nproject_id = \"ID\"\nenvironment = \"dev\"\nserver = true\n",
        ),
        (
            "sync",
            "project = \"payments\"\nproject_id = \"ID\"\nenvironment = \"dev\"\nsync = \"github\"\n",
        ),
        (
            "sync",
            "project = \"payments\"\nproject_id = \"ID\"\nenvironment = \"dev\"\n[sync]\ngithub = \"x\"\n",
        ),
    ];
    for (key, text) in cases {
        let text = text.replace("ID", ID);

        assert_eq!(
            parse_err(&text),
            ProjectFileError::InvalidValue(key),
            "{text}"
        );
    }
}

#[test]
fn parse_rejects_project_id_that_is_not_a_uuid() {
    let text = minimal().replace(ID, "payments-prod");

    assert_eq!(
        parse_err(&text),
        ProjectFileError::InvalidValue("project_id")
    );
}

#[test]
fn parse_rejects_names_that_are_not_env_ref_parts() {
    for bad in ["", "pay ments", "pay/ments", " dev"] {
        let project = minimal().replace("\"payments\"", &format!("{bad:?}"));
        let environment = minimal().replace("\"dev\"", &format!("{bad:?}"));

        assert_eq!(
            parse_err(&project),
            ProjectFileError::InvalidValue("project"),
            "{bad:?}"
        );
        assert_eq!(
            parse_err(&environment),
            ProjectFileError::InvalidValue("environment"),
            "{bad:?}"
        );
    }
}

#[test]
fn parse_reports_syntax_error_line() {
    let text = "project = \"payments\"\nproject_id = \"0b9e6d3c\nenvironment = \"dev\"\n";

    assert_eq!(parse_err(text), ProjectFileError::Syntax { line: Some(2) });
}

// --- no echo of file content ---

#[test]
fn errors_never_quote_file_content() {
    let secret = "hunter2";
    let cases = [
        format!("{}API_KEY = \"{secret}\"\n", minimal()),
        minimal().replace(ID, secret),
        format!("project = \"payments\"\nproject_id = \"{ID}\"\nenvironment = [\"{secret}\"]\n"),
        format!("project = \"payments\"\nproject_id = \"{ID}\"\nenvironment = \"{secret} x\"\n"),
        format!("project = \"payments\"\nproject_id = \"{secret}\nenvironment = \"dev\"\n"),
        format!("{}server = [\"{secret}\"]\n", minimal()),
        format!("{secret}\n"),
    ];
    for text in cases {
        let error = CliError::from(parse_err(&text));

        assert_no_echo(&error, secret);
    }
}

// --- errors for the user ---

#[test]
fn not_found_error_points_to_init() {
    let error = CliError::from(ProjectFileError::NotFound);

    assert_eq!(error.code(), "project_file_not_found");
    assert_eq!(error.exit(), Exit::NotFound);
    assert_eq!(
        error.message(),
        "Brak smart-env.toml w tym katalogu ani wyżej."
    );
    assert_eq!(error.hint(), Some("Uruchom: smart-env init"));
}

#[test]
fn unknown_key_error_names_the_key_and_points_to_set() {
    let error = CliError::from(ProjectFileError::UnknownKey("API_KEY".to_owned()));

    assert_eq!(error.code(), "project_file_unknown_key");
    assert_eq!(error.exit(), Exit::Failure);
    assert!(error.message().contains("API_KEY"));
    assert!(error.hint().unwrap().contains("smart-env set API_KEY"));
}

#[test]
fn parse_errors_have_stable_codes() {
    let cases = [
        (
            ProjectFileError::Unreadable("/x/smart-env.toml".into()),
            "project_file_unreadable",
        ),
        (
            ProjectFileError::Syntax { line: Some(3) },
            "project_file_syntax",
        ),
        (
            ProjectFileError::Syntax { line: None },
            "project_file_syntax",
        ),
        (
            ProjectFileError::MissingKey("project_id"),
            "project_file_missing_key",
        ),
        (
            ProjectFileError::InvalidValue("project_id"),
            "project_file_invalid_value",
        ),
    ];
    for (error, code) in cases {
        let error = CliError::from(error);

        assert_eq!(error.code(), code);
        assert_eq!(error.exit(), Exit::Failure);
        assert!(error.hint().is_some(), "{code}");
    }
}

#[test]
fn errors_name_line_key_and_path() {
    let syntax = CliError::from(ProjectFileError::Syntax { line: Some(3) });
    let missing = CliError::from(ProjectFileError::MissingKey("project_id"));
    let invalid = CliError::from(ProjectFileError::InvalidValue("environment"));
    let unreadable = CliError::from(ProjectFileError::Unreadable("/x/smart-env.toml".into()));

    assert!(syntax.message().contains('3'));
    assert!(missing.message().contains("project_id"));
    assert!(invalid.message().contains("environment"));
    assert!(unreadable.message().contains("/x/smart-env.toml"));
}

// --- find ---

#[test]
fn find_in_start_directory() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), &minimal());

    let (path, file) = ProjectFile::find(dir.path()).unwrap();

    assert_eq!(path, dir.path().join(FILE_NAME));
    assert_eq!(file.project, "payments");
}

#[test]
fn find_walks_up_to_parent() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), &minimal());
    let nested = dir.path().join("src/api");
    fs::create_dir_all(&nested).unwrap();

    let (path, _) = ProjectFile::find(&nested).unwrap();

    assert_eq!(path, dir.path().join(FILE_NAME));
}

#[test]
fn find_prefers_nearest_file() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), &minimal());
    let nested = dir.path().join("services/billing");
    fs::create_dir_all(&nested).unwrap();
    write(&nested, &minimal().replace("payments", "billing"));

    let (path, file) = ProjectFile::find(&nested.join("..").join("billing")).unwrap();

    assert_eq!(file.project, "billing");
    assert!(path.ends_with(Path::new("billing").join(FILE_NAME)));
}

#[test]
fn find_skips_directory_named_like_the_file() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), &minimal());
    let nested = dir.path().join("app");
    fs::create_dir_all(nested.join(FILE_NAME)).unwrap();

    let (path, _) = ProjectFile::find(&nested).unwrap();

    assert_eq!(path, dir.path().join(FILE_NAME));
}

#[test]
fn find_without_file_is_not_found() {
    let dir = TempDir::new().unwrap();
    let nested = dir.path().join("a/b");
    fs::create_dir_all(&nested).unwrap();

    // A smart-env.toml above the temp dir (e.g. in /tmp) would make this
    // test meaningless.
    if dir.path().ancestors().any(|d| d.join(FILE_NAME).is_file()) {
        return;
    }
    assert_eq!(ProjectFile::find(&nested), Err(ProjectFileError::NotFound));
}

#[cfg(unix)]
#[test]
fn find_does_not_fall_back_to_parent_when_nearest_is_unreadable() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    write(dir.path(), &minimal());
    let nested = dir.path().join("app");
    fs::create_dir_all(&nested).unwrap();
    write(&nested, &minimal());
    let blocked = nested.join(FILE_NAME);
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(&blocked).is_ok() {
        return; // root ignores permissions
    }

    assert_eq!(
        ProjectFile::find(&nested),
        Err(ProjectFileError::Unreadable(blocked))
    );
}

#[test]
fn find_returns_parse_error_of_nearest_file() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), &minimal());
    let nested = dir.path().join("app");
    fs::create_dir_all(&nested).unwrap();
    write(&nested, "project = \"payments\"\n");

    assert_eq!(
        ProjectFile::find(&nested),
        Err(ProjectFileError::MissingKey("project_id"))
    );
}

// --- resolve ---

struct VaultFixture {
    _dir: TempDir,
    vault: Vault,
    payments: ProjectId,
}

fn vault() -> VaultFixture {
    let dir = TempDir::new().unwrap();
    let mut vault = Vault::create(&dir.path().join("vault.db")).unwrap();
    let payments = vault.create_project("payments").unwrap();
    VaultFixture {
        _dir: dir,
        vault,
        payments,
    }
}

fn file(project: &str, id: ProjectId) -> ProjectFile {
    ProjectFile::parse(
        &minimal()
            .replace("payments", project)
            .replace(ID, &id.to_string()),
    )
    .unwrap()
}

#[test]
fn resolve_matching_id_and_name() {
    let f = vault();

    let resolved = file("payments", f.payments).resolve(&f.vault).unwrap();

    assert_eq!(
        resolved,
        ResolvedProject {
            id: f.payments,
            renamed_to: None
        }
    );
    assert_eq!(resolved.warning(), None);
}

#[test]
fn resolve_renamed_project_by_id_with_warning() {
    let f = vault();

    let resolved = file("payments-old", f.payments).resolve(&f.vault).unwrap();

    assert_eq!(resolved.id, f.payments);
    assert_eq!(resolved.renamed_to.as_deref(), Some("payments"));
    let warning = resolved.warning().unwrap();
    assert!(warning.contains("payments"));
    assert!(warning.contains("smart-env.toml"));
}

#[test]
fn resolve_never_falls_back_to_project_with_same_name() {
    let f = vault();

    let error = file("payments", ProjectId::new())
        .resolve(&f.vault)
        .unwrap_err();

    assert_eq!(error.code(), "project_id_mismatch");
    assert_eq!(error.exit(), Exit::Conflict);
    assert!(error.hint().is_some());
}

#[test]
fn resolve_unknown_id_and_name_is_not_found() {
    let f = vault();

    let error = file("billing", ProjectId::new())
        .resolve(&f.vault)
        .unwrap_err();

    assert_eq!(error.code(), "project_not_found");
    assert_eq!(error.exit(), Exit::NotFound);
    assert!(error.hint().unwrap().contains("smart-env init"));
}
