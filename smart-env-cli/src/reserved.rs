//! Reserved variable names (ADR-005): variables that change how tools behave
//! rather than the application. The shell hook and `run` skip them until
//! allowed on this device; `init` warns about them.

/// Whether `name` is reserved: an exact name from the ADR-005 list or a
/// reserved prefix (`DYLD_`, `GIT_`, `SMART_ENV_`), ignoring case.
pub(crate) fn is_reserved(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    EXACT.contains(&name.as_str()) || PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

/// Exact names from ADR-005, upper case.
const EXACT: &[&str] = &[
    // loading code
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    // shell and paths
    "PATH",
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
    "PROMPT_COMMAND",
    "SHELLOPTS",
    "IFS",
    "HOME",
    // interpreter options
    "NODE_OPTIONS",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PERL5OPT",
    "RUBYOPT",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    // tools
    "EDITOR",
    "VISUAL",
    "PAGER",
    "SSH_AUTH_SOCK",
    // network and certificates
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
];

/// Reserved prefixes from ADR-005, upper case.
const PREFIXES: &[&str] = &["DYLD_", "GIT_", "SMART_ENV_"];

#[cfg(test)]
mod tests {
    use super::is_reserved;

    #[test]
    fn exact_names_from_adr_005() {
        for name in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "PATH",
            "BASH_ENV",
            "ENV",
            "ZDOTDIR",
            "PROMPT_COMMAND",
            "SHELLOPTS",
            "IFS",
            "HOME",
            "NODE_OPTIONS",
            "PYTHONSTARTUP",
            "PYTHONPATH",
            "PERL5OPT",
            "RUBYOPT",
            "JAVA_TOOL_OPTIONS",
            "_JAVA_OPTIONS",
            "EDITOR",
            "VISUAL",
            "PAGER",
            "SSH_AUTH_SOCK",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "NODE_EXTRA_CA_CERTS",
            "REQUESTS_CA_BUNDLE",
        ] {
            assert!(is_reserved(name), "{name}");
        }
    }

    #[test]
    fn reserved_prefixes() {
        for name in [
            "DYLD_INSERT_LIBRARIES",
            "GIT_SSH_COMMAND",
            "GIT_EXEC_PATH",
            "SMART_ENV_DEBUG",
        ] {
            assert!(is_reserved(name), "{name}");
        }
    }

    #[test]
    fn case_is_ignored() {
        for name in [
            "path",
            "Node_Options",
            "http_proxy",
            "git_dir",
            "smart_env_x",
        ] {
            assert!(is_reserved(name), "{name}");
        }
    }

    #[test]
    fn ordinary_names_are_not_reserved() {
        for name in [
            "DATABASE_URL",
            "API_KEY",
            "PATHS",
            "MY_PATH",
            "HOMEPAGE_URL",
            "GITHUB_TOKEN",
            "DYLD",
            "SMART_ENVIRONMENT",
            "NODE_ENV",
            "ENVIRONMENT",
        ] {
            assert!(!is_reserved(name), "{name}");
        }
    }
}
