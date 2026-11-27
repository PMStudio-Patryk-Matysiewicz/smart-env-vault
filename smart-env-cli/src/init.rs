//! `smart-env init`: imports the project's `.env` files into the vault in one
//! transaction, verifies every value, writes `smart-env.toml` and
//! `.gitignore`, warns about git history and reserved names, and only then
//! offers to delete the plaintext ([[05 - Kontrakt DX]] Scenario 1, F06 3).
//!
//! File mapping: `.env` → `dev`, `.env.<x>` → `x` (`development` → `dev`,
//! `production` → `prod`); `*.local` files override their base file;
//! templates (`.env.example`, `.sample`, `.template`, `.dist`) are skipped.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::json;
use smart_env_vault::{EnvKind, NewEnvironment, SecretValue, VarName, Vault};
use zeroize::Zeroizing;

use crate::env_ref::is_valid_part;
use crate::keys::{device_key, no_data_directory};
use crate::reserved::is_reserved;
use crate::{
    CliError, Context, Dotenv, DotenvWarning, EnvRef, Exit, FILE_NAME, Interaction, setup,
};

/// Template files: names only, never imported or deleted.
const TEMPLATES: &[&str] = &["example", "sample", "template", "dist"];
/// Environment of `.env` and `.env.local`.
const DEV: &str = "dev";

/// Runs `init` in [`Context::current_dir`]. `env` (`--env`) overrides the
/// project name (project part) and the default environment written to
/// `smart-env.toml` (environment part).
pub(crate) fn run(
    ctx: &mut Context<'_>,
    interaction: Interaction,
    json: bool,
    env: Option<&EnvRef>,
    out: &mut dyn Write,
) -> Result<Exit, CliError> {
    let dir = ctx.current_dir.clone().ok_or_else(no_current_directory)?;
    if dir.join(FILE_NAME).exists() {
        return Err(already_initialized());
    }
    let project = match env.and_then(|env| env.project.clone()) {
        Some(project) => project,
        None => dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned(),
    };
    if !is_valid_part(&project) {
        return Err(invalid_project_name());
    }
    let default_env = env.map_or_else(|| DEV.to_owned(), |env| env.environment.clone());

    let data = ctx.data.clone().ok_or_else(no_data_directory)?;
    if !data.vault_db().exists() {
        // Same path and output as `smart-env setup`; with --json only the
        // init report is printed.
        if json {
            setup::run(ctx, interaction, true, &mut io::sink())?;
        } else {
            setup::run(ctx, interaction, false, out)?;
        }
    }
    let key = device_key(ctx)?;

    let (sources, skipped) = discover(&dir)?;
    let imports = sources
        .iter()
        .map(|source| parse_source(&dir, source))
        .collect::<Result<Vec<_>, _>>()?;
    let mut vault = Vault::open(data.vault_db())?;
    if vault.find_project(&project)?.is_some() {
        return Err(project_name_taken());
    }

    let mut report = Report::new(json, out);
    if !sources.is_empty() {
        report.listing(&project, &sources, &imports, &skipped);
        let import =
            interaction.confirm("import .env files", || ask_yes(ctx, "? Import? [Y/n] "))?;
        if !import {
            report.line("✓ Nothing imported");
            report.finish_json(json!({ "status": "declined" }));
            return Ok(Exit::Success);
        }
    }

    // One transaction: the project, every environment and every value.
    let mut environments: Vec<NewEnvironment<'_>> = sources
        .iter()
        .zip(&imports)
        .map(|(source, import)| NewEnvironment {
            name: &source.environment,
            kind: source.kind,
            entries: &import.entries,
        })
        .collect();
    if !sources
        .iter()
        .any(|source| source.environment == default_env)
    {
        environments.push(NewEnvironment {
            name: &default_env,
            kind: kind_of(&default_env),
            entries: &[],
        });
    }
    let (project_id, ids) = vault.import_project(&project, &environments)?;
    for (id, import) in ids.iter().zip(&imports) {
        verify(&vault.read_all(*id, &key)?, &import.entries)?;
    }

    let total: usize = imports.iter().map(|import| import.entries.len()).sum();
    if sources.is_empty() {
        report.line(&format!(
            "✓ Created {project}/{default_env} (no .env files found)"
        ));
    } else {
        report.line(&format!(
            "✓ Imported and verified {}",
            count(total, "variable")
        ));
    }

    write_project_file(&dir, &project, &project_id.to_string(), &default_env)?;
    report.line("✓ Created smart-env.toml (no secrets, safe to commit)");

    let files: Vec<String> = sources
        .iter()
        .flat_map(|source| source.files.iter().cloned())
        .collect();
    let repository = is_repository(&dir);
    let added = add_to_gitignore(&dir, &files, repository)?;
    if !added.is_empty() {
        report.line(&format!("✓ Added {} to .gitignore", added.join(", ")));
    }

    let history = if repository {
        git_history(&dir, &files)
    } else {
        Vec::new()
    };
    for entry in &history {
        if entry.commits > 0 {
            report.line(&format!(
                "! {} was in git history ({}), so values may be known. Consider rotating: smart-env scan --history",
                entry.file,
                count(entry.commits, "commit")
            ));
        }
        if entry.tracked {
            report.line(&format!(
                "! {} is tracked by git. Stop tracking it: git rm --cached {}",
                entry.file, entry.file
            ));
        }
    }

    let reserved: BTreeSet<String> = imports
        .iter()
        .flat_map(|import| import.entries.iter())
        .map(|(name, _)| name.to_string())
        .filter(|name| is_reserved(name))
        .collect();
    let reserved: Vec<String> = reserved.into_iter().collect();
    if !reserved.is_empty() {
        let verb = if reserved.len() == 1 {
            "is a reserved name"
        } else {
            "are reserved names"
        };
        report.line(&format!(
            "! {} {verb}. The shell hook skips them until allowed: smart-env allow --var NAME",
            reserved.join(", ")
        ));
    }
    let warnings: Vec<String> = imports
        .iter()
        .flat_map(|import| import.warnings.iter().cloned())
        .collect();
    for warning in &warnings {
        report.line(&format!("! {warning}"));
    }

    let mut deleted = Vec::new();
    if !files.is_empty() {
        let question = format!("? Delete plaintext files {}? [Y/n] ", files.join(", "));
        let delete =
            interaction.confirm("delete plaintext .env files", || ask_yes(ctx, &question))?;
        if delete {
            let mut failed = Vec::new();
            for file in &files {
                match fs::remove_file(dir.join(file)) {
                    Ok(()) => deleted.push(file.clone()),
                    Err(_) => failed.push(file.clone()),
                }
            }
            report.line(&format!("✓ Deleted {}", count(deleted.len(), "file")));
            if !failed.is_empty() {
                report.line(&format!(
                    "! Could not delete {}. Delete them yourself",
                    failed.join(", ")
                ));
            }
        } else {
            report.line(&format!(
                "! Plaintext files kept: {}. Delete them when ready",
                files.join(", ")
            ));
        }
    }
    report.line("Next: smart-env run -- <your command>");

    let mut listed: Vec<serde_json::Value> = sources
        .iter()
        .zip(&imports)
        .map(|(source, import)| {
            json!({
                "name": source.environment,
                "files": source.files,
                "variables": import.entries.len(),
            })
        })
        .collect();
    if !sources
        .iter()
        .any(|source| source.environment == default_env)
    {
        listed.push(json!({ "name": default_env, "files": [], "variables": 0 }));
    }
    report.finish_json(json!({
        "status": "initialized",
        "project": project,
        "project_id": project_id.to_string(),
        "environments": listed,
        "skipped": skipped
            .iter()
            .map(|skip| json!({ "file": skip.file, "reason": skip.reason.code() }))
            .collect::<Vec<_>>(),
        "gitignore": added,
        "git_history": history
            .iter()
            .map(|entry| json!({
                "file": entry.file,
                "commits": entry.commits,
                "tracked": entry.tracked,
            }))
            .collect::<Vec<_>>(),
        "reserved": reserved,
        "warnings": warnings,
        "deleted": deleted,
    }));
    Ok(Exit::Success)
}

// --- discovery ---

/// One environment and its files, base first (later files override).
struct Source {
    environment: String,
    kind: EnvKind,
    files: Vec<String>,
}

struct Skipped {
    file: String,
    reason: SkipReason,
}

enum SkipReason {
    Template,
    InvalidEnvironmentName,
}

impl SkipReason {
    fn code(&self) -> &'static str {
        match self {
            Self::Template => "template",
            Self::InvalidEnvironmentName => "invalid_environment_name",
        }
    }

    fn text(&self) -> &'static str {
        match self {
            Self::Template => "skipped (template)",
            Self::InvalidEnvironmentName => "skipped (invalid environment name)",
        }
    }
}

/// `.env` files of `dir`, grouped by environment in display order.
fn discover(dir: &Path) -> Result<(Vec<Source>, Vec<Skipped>), CliError> {
    let entries = fs::read_dir(dir).map_err(|_| directory_unreadable())?;
    // environment → (rank, file)
    let mut groups: BTreeMap<String, Vec<(u8, String)>> = BTreeMap::new();
    let mut skipped = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| directory_unreadable())?;
        let Ok(file) = entry.file_name().into_string() else {
            continue;
        };
        if !entry.path().is_file() {
            continue;
        }
        match classify(&file) {
            Class::Ignored => {}
            Class::Skipped(reason) => skipped.push(Skipped { file, reason }),
            Class::Layer { environment, rank } => {
                groups.entry(environment).or_default().push((rank, file));
            }
        }
    }

    let mut sources: Vec<Source> = groups
        .into_iter()
        .map(|(environment, mut layers)| {
            layers.sort();
            Source {
                kind: kind_of(&environment),
                files: layers.into_iter().map(|(_, file)| file).collect(),
                environment,
            }
        })
        .collect();
    sources.sort_by(|a, b| {
        (display_rank(&a.environment), &a.environment)
            .cmp(&(display_rank(&b.environment), &b.environment))
    });
    skipped.sort_by(|a, b| a.file.cmp(&b.file));
    Ok((sources, skipped))
}

enum Class {
    Ignored,
    Skipped(SkipReason),
    /// Part of `environment`; higher `rank` overrides lower.
    Layer {
        environment: String,
        rank: u8,
    },
}

/// Framework order: `.env` < `.env.<x>` < `.env.local` < `.env.<x>.local`
/// for `dev`; `.env.<x>` < `.env.<x>.local` elsewhere.
fn classify(file: &str) -> Class {
    if file == ".env" {
        return Class::Layer {
            environment: DEV.to_owned(),
            rank: 0,
        };
    }
    let Some(rest) = file.strip_prefix(".env.") else {
        return Class::Ignored;
    };
    if rest == "local" {
        return Class::Layer {
            environment: DEV.to_owned(),
            rank: 2,
        };
    }
    let (part, local) = match rest.strip_suffix(".local") {
        Some(part) => (part, true),
        None => (rest, false),
    };
    if TEMPLATES.contains(&part) {
        return Class::Skipped(SkipReason::Template);
    }
    let environment = match part {
        "development" => DEV,
        "production" => "prod",
        other => other,
    };
    if !is_valid_part(environment) {
        return Class::Skipped(SkipReason::InvalidEnvironmentName);
    }
    let rank = match (environment == DEV, local) {
        (true, false) => 1,
        (true, true) => 3,
        (false, false) => 0,
        (false, true) => 1,
    };
    Class::Layer {
        environment: environment.to_owned(),
        rank,
    }
}

fn kind_of(environment: &str) -> EnvKind {
    match environment {
        "dev" => EnvKind::Dev,
        "staging" => EnvKind::Staging,
        "prod" => EnvKind::Prod,
        _ => EnvKind::Custom,
    }
}

fn display_rank(environment: &str) -> u8 {
    match environment {
        "dev" => 0,
        "staging" => 1,
        "prod" => 2,
        _ => 3,
    }
}

// --- parsing ---

/// Variables of one environment after applying its layers, in first-seen
/// order, plus parser warnings with file names.
struct Import {
    entries: Vec<(VarName, SecretValue)>,
    warnings: Vec<String>,
}

fn parse_source(dir: &Path, source: &Source) -> Result<Import, CliError> {
    let mut entries: Vec<(VarName, SecretValue)> = Vec::new();
    let mut positions: HashMap<VarName, usize> = HashMap::new();
    let mut warnings = Vec::new();
    for file in &source.files {
        let bytes =
            Zeroizing::new(fs::read(dir.join(file)).map_err(|_| env_file_unreadable(file))?);
        let parsed = Dotenv::parse(&bytes).map_err(|error| env_file_invalid(file, &error))?;
        warnings.extend(parsed.warnings.iter().map(|warning| match warning {
            DotenvWarning::Interpolation { name, line } => format!(
                "{file} line {line}: {name} contains ${{…}} or $NAME, kept literally (smart-env does not substitute)"
            ),
        }));
        for entry in parsed.entries {
            match positions.get(&entry.name) {
                Some(&index) => entries[index].1 = entry.value,
                None => {
                    positions.insert(entry.name.clone(), entries.len());
                    entries.push((entry.name, entry.value));
                }
            }
        }
    }
    Ok(Import { entries, warnings })
}

/// Every imported name with exactly its value, nothing more.
fn verify(
    stored: &[(smart_env_vault::SecretMeta, SecretValue)],
    expected: &[(VarName, SecretValue)],
) -> Result<(), CliError> {
    let stored: HashMap<&VarName, &str> = stored
        .iter()
        .map(|(meta, value)| (&meta.name, value.expose()))
        .collect();
    let matches = stored.len() == expected.len()
        && expected
            .iter()
            .all(|(name, value)| stored.get(name) == Some(&value.expose()));
    if matches {
        Ok(())
    } else {
        Err(import_verification_failed())
    }
}

// --- files ---

/// `smart-env.toml` via a temporary file and `rename`, so a crash never
/// leaves half a file.
fn write_project_file(
    dir: &Path,
    project: &str,
    project_id: &str,
    environment: &str,
) -> Result<(), CliError> {
    let mut document = toml_edit::DocumentMut::new();
    document["project"] = toml_edit::value(project);
    document["project_id"] = toml_edit::value(project_id);
    document["environment"] = toml_edit::value(environment);

    let path = dir.join(FILE_NAME);
    let temporary = dir.join(format!(".{FILE_NAME}.{}.tmp", std::process::id()));
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(document.to_string().as_bytes())?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&temporary, &path));
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(file_not_written(FILE_NAME));
    }
    Ok(())
}

/// Appends `/<file>` for every file not ignored yet; returns the added names.
fn add_to_gitignore(
    dir: &Path,
    files: &[String],
    repository: bool,
) -> Result<Vec<String>, CliError> {
    let path = dir.join(".gitignore");
    let existing = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(_) => return Err(file_not_written(".gitignore")),
    };
    let listed: BTreeSet<&str> = existing
        .lines()
        .map(str::trim)
        .map(|line| line.strip_prefix('/').unwrap_or(line))
        .collect();
    let added: Vec<String> = files
        .iter()
        .filter(|file| !listed.contains(file.as_str()))
        .filter(|file| !(repository && git_ignores(dir, file)))
        .cloned()
        .collect();
    if added.is_empty() {
        return Ok(added);
    }

    let mut text = existing;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    for file in &added {
        text.push('/');
        text.push_str(file);
        text.push('\n');
    }
    fs::write(&path, text).map_err(|_| file_not_written(".gitignore"))?;
    Ok(added)
}

// --- git ---

struct History {
    file: String,
    commits: usize,
    tracked: bool,
}

fn git(dir: &Path, args: &[&str]) -> Option<std::process::Output> {
    Command::new("git")
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
}

/// Inside a git work tree and git is installed.
fn is_repository(dir: &Path) -> bool {
    git(dir, &["rev-parse", "--is-inside-work-tree"])
        .is_some_and(|output| output.status.success() && output.stdout.starts_with(b"true"))
}

fn git_ignores(dir: &Path, file: &str) -> bool {
    git(dir, &["check-ignore", "-q", "--", file]).is_some_and(|output| output.status.success())
}

/// Files that are or were in git (commit counts over all refs).
fn git_history(dir: &Path, files: &[String]) -> Vec<History> {
    files
        .iter()
        .filter_map(|file| {
            let commits = git(dir, &["log", "--all", "--format=%H", "--", file])
                .filter(|output| output.status.success())
                .map_or(0, |output| {
                    output
                        .stdout
                        .split(|&byte| byte == b'\n')
                        .filter(|line| !line.is_empty())
                        .count()
                });
            let tracked = git(dir, &["ls-files", "--error-unmatch", "--", file])
                .is_some_and(|output| output.status.success());
            (commits > 0 || tracked).then(|| History {
                file: file.clone(),
                commits,
                tracked,
            })
        })
        .collect()
}

// --- interaction and output ---

/// `[Y/n]`: an empty answer, `y` or `yes` is yes; a closed terminal is no.
pub(crate) fn ask_yes(ctx: &mut Context<'_>, question: &str) -> bool {
    let Some(terminal) = ctx.terminal.as_deref_mut() else {
        return false;
    };
    terminal.ask(question).is_ok_and(|answer| {
        matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "" | "y" | "yes"
        )
    })
}

/// Human lines as they happen, or one JSON object at the end.
struct Report<'a> {
    json: bool,
    out: &'a mut dyn Write,
}

impl<'a> Report<'a> {
    fn new(json: bool, out: &'a mut dyn Write) -> Self {
        Self { json, out }
    }

    fn line(&mut self, line: &str) {
        if !self.json {
            let _ = writeln!(self.out, "{line}");
        }
    }

    fn finish_json(&mut self, value: serde_json::Value) {
        if self.json {
            let _ = writeln!(self.out, "{value}");
        }
    }

    fn listing(
        &mut self,
        project: &str,
        sources: &[Source],
        imports: &[Import],
        skipped: &[Skipped],
    ) {
        let labels: Vec<String> = sources
            .iter()
            .map(|source| source.files.join(" + "))
            .collect();
        let width = labels
            .iter()
            .map(String::len)
            .chain(skipped.iter().map(|skip| skip.file.len()))
            .max()
            .unwrap_or(0);
        self.line("Found files:");
        for ((label, source), import) in labels.iter().zip(sources).zip(imports) {
            self.line(&format!(
                "  {label:<width$} → {project}/{} ({})",
                source.environment,
                count(import.entries.len(), "variable")
            ));
        }
        for skip in skipped {
            self.line(&format!("  {:<width$} → {}", skip.file, skip.reason.text()));
        }
    }
}

/// `1 variable`, `2 variables`.
fn count(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

// --- errors ---

fn no_current_directory() -> CliError {
    CliError::new(
        "no_current_directory",
        Exit::Failure,
        "The current directory is not available.",
    )
    .with_hint("Run smart-env init from the project directory")
}

fn directory_unreadable() -> CliError {
    CliError::new(
        "directory_unreadable",
        Exit::Failure,
        "The current directory cannot be read.",
    )
    .with_hint("Check the directory permissions and run: smart-env init")
}

fn already_initialized() -> CliError {
    CliError::new(
        "already_initialized",
        Exit::Conflict,
        "This directory already has smart-env.toml.",
    )
    .with_hint("Add variables with: smart-env set NAME --env <environment>")
}

fn invalid_project_name() -> CliError {
    CliError::new(
        "invalid_project_name",
        Exit::Failure,
        "The directory name cannot be used as a project name (whitespace, control characters or /).",
    )
    .with_hint("Choose a name: smart-env init --env <name>/dev")
}

fn project_name_taken() -> CliError {
    CliError::new(
        "project_name_taken",
        Exit::Conflict,
        "A project with this name already exists in the vault.",
    )
    .with_hint("Choose another name: smart-env init --env <other-name>/dev")
}

fn env_file_unreadable(file: &str) -> CliError {
    CliError::new(
        "env_file_unreadable",
        Exit::Failure,
        format!("{file} cannot be read."),
    )
    .with_hint(format!(
        "Check the permissions of {file} and run: smart-env init"
    ))
}

fn env_file_invalid(file: &str, error: &crate::DotenvError) -> CliError {
    CliError::new(
        "env_file_invalid",
        Exit::Failure,
        format!("{file}: {error}"),
    )
    .with_hint(format!("Fix {file} and run: smart-env init"))
}

fn import_verification_failed() -> CliError {
    CliError::new(
        "import_verification_failed",
        Exit::Failure,
        "Values read back from the vault differ from the files; the files were not touched.",
    )
    .with_hint("Diagnose: smart-env doctor")
}

fn file_not_written(file: &str) -> CliError {
    CliError::new(
        "file_not_written",
        Exit::Failure,
        format!("{file} could not be written; the variables are already in the vault."),
    )
    .with_hint("Check the directory permissions; the .env files were not touched")
}
