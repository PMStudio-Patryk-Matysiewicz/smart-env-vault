use smart_env_cli::{Dotenv, DotenvError, DotenvWarning};
use smart_env_vault::{MAX_VALUE_LEN, SecretError, VarName};

fn parse(input: &str) -> Dotenv {
    match Dotenv::parse(input.as_bytes()) {
        Ok(file) => file,
        Err(error) => panic!("expected a parsed file, got {error:?}"),
    }
}

fn err_bytes(input: &[u8]) -> DotenvError {
    match Dotenv::parse(input) {
        Ok(file) => panic!("expected an error, got {file:?}"),
        Err(error) => error,
    }
}

fn err(input: &str) -> DotenvError {
    err_bytes(input.as_bytes())
}

fn name(text: &str) -> VarName {
    VarName::parse(text).unwrap()
}

fn pairs(file: &Dotenv) -> Vec<(String, String)> {
    file.entries
        .iter()
        .map(|entry| (entry.name.to_string(), entry.value.expose().to_owned()))
        .collect()
}

fn lines(file: &Dotenv) -> Vec<usize> {
    file.entries.iter().map(|entry| entry.line).collect()
}

fn pair(name: &str, value: &str) -> (String, String) {
    (name.to_owned(), value.to_owned())
}

/// Value of the only entry.
fn value(input: &str) -> String {
    let file = parse(input);
    assert_eq!(file.entries.len(), 1, "{input:?}");
    file.entries[0].value.expose().to_owned()
}

fn interpolation(var: &str, line: usize) -> DotenvWarning {
    DotenvWarning::Interpolation {
        name: name(var),
        line,
    }
}

/// The secret must not appear in anything a user, a log or a panic could show.
fn assert_no_echo(error: &DotenvError, secret: &str) {
    let display = error.to_string();
    let debug = format!("{error:?}");
    assert!(!display.contains(secret), "display: {display}");
    assert!(!debug.contains(secret), "debug: {debug}");
}

// --- grammar ---

#[test]
fn empty_file_and_comments_only_have_no_entries() {
    assert!(parse("").entries.is_empty());
    let file = parse("# comment\n\n   \n\t# indented comment\n");
    assert!(file.entries.is_empty());
    assert!(file.warnings.is_empty());
}

#[test]
fn simple_entries_keep_file_order_and_lines() {
    let file = parse("# header\n\nB=2\n  # indented\nA=1\n");
    assert_eq!(pairs(&file), vec![pair("B", "2"), pair("A", "1")]);
    assert_eq!(lines(&file), vec![3, 5]);
}

#[test]
fn export_prefix_is_ignored() {
    assert_eq!(
        pairs(&parse("export A=1\nexport\tB=2\nexport  C = 3\n")),
        vec![pair("A", "1"), pair("B", "2"), pair("C", "3")]
    );
}

#[test]
fn names_starting_with_export_are_names() {
    assert_eq!(
        pairs(&parse("export=1\nexported=2\n")),
        vec![pair("export", "1"), pair("exported", "2")]
    );
}

#[test]
fn whitespace_around_equals_and_value_is_trimmed() {
    assert_eq!(value("KEY = value"), "value");
    assert_eq!(value("  KEY=  value  "), "value");
    assert_eq!(value("KEY=\tvalue\t"), "value");
}

#[test]
fn empty_values() {
    assert_eq!(value("KEY="), "");
    assert_eq!(value("KEY=   "), "");
    assert_eq!(value("KEY=\"\""), "");
    assert_eq!(value("KEY=''"), "");
}

#[test]
fn equals_sign_inside_value_is_kept() {
    assert_eq!(value("KEY=a=b=c"), "a=b=c");
    assert_eq!(value("KEY=dGVzdA=="), "dGVzdA==");
}

#[test]
fn hash_without_preceding_whitespace_is_part_of_unquoted_value() {
    assert_eq!(value("URL=http://x/#frag"), "http://x/#frag");
    assert_eq!(value("KEY=a#b"), "a#b");
}

#[test]
fn hash_after_whitespace_starts_a_comment_in_unquoted_value() {
    assert_eq!(value("KEY=value # comment"), "value");
    assert_eq!(value("KEY=value\t# comment"), "value");
    assert_eq!(value("KEY=a b # comment"), "a b");
}

#[test]
fn quote_inside_unquoted_value_is_literal() {
    assert_eq!(value("KEY=say\"hi\""), "say\"hi\"");
    assert_eq!(value("KEY=it's"), "it's");
}

#[test]
fn unicode_values_are_kept() {
    assert_eq!(value("KEY=zażółć gęślą jaźń 🚀"), "zażółć gęślą jaźń 🚀");
    assert_eq!(value("KEY=\"日本語\""), "日本語");
}

// --- single quotes ---

#[test]
fn single_quotes_are_literal() {
    assert_eq!(value(r"KEY='a\nb'"), r"a\nb");
    assert_eq!(value(r#"KEY='a\"b'"#), r#"a\"b"#);
    assert_eq!(value("KEY='a # b'"), "a # b");
    assert_eq!(value("KEY='  padded  '"), "  padded  ");
    assert_eq!(value("KEY='say \"hi\"'"), "say \"hi\"");
}

#[test]
fn comment_after_single_quotes() {
    assert_eq!(value("KEY='x' # comment"), "x");
    assert_eq!(value("KEY='x'#comment"), "x");
    assert_eq!(value("KEY='x'   "), "x");
}

#[test]
fn single_quotes_span_lines() {
    let file = parse("A='line one\nline two'\nB=1\n");
    assert_eq!(
        pairs(&file),
        vec![pair("A", "line one\nline two"), pair("B", "1")]
    );
    assert_eq!(lines(&file), vec![1, 3]);
}

// --- double quotes ---

#[test]
fn double_quotes_support_the_five_escapes() {
    assert_eq!(value(r#"KEY="a\nb\tc\rd\"e\\f""#), "a\nb\tc\rd\"e\\f");
}

#[test]
fn unknown_escapes_stay_literal() {
    assert_eq!(value(r#"KEY="\x\$\0\a""#), r"\x\$\0\a");
    assert_eq!(value(r#"KEY="C:\Users\me""#), r"C:\Users\me");
}

#[test]
fn escaped_backslash_before_n_is_not_a_newline() {
    assert_eq!(value(r#"KEY="a\\nb""#), r"a\nb");
}

#[test]
fn double_quotes_keep_hash_and_padding() {
    assert_eq!(value("KEY=\"a # b\""), "a # b");
    assert_eq!(value("KEY=\"  padded  \""), "  padded  ");
    assert_eq!(value("KEY=\"it's\""), "it's");
}

#[test]
fn comment_after_double_quotes() {
    assert_eq!(value("KEY=\"x\" # comment"), "x");
    assert_eq!(value("KEY=\"x\"#comment"), "x");
    assert_eq!(value("KEY= \"x\"  "), "x");
}

#[test]
fn double_quotes_span_lines() {
    let file = parse("A=\"line one\nline two\"\nB=1\n");
    assert_eq!(
        pairs(&file),
        vec![pair("A", "line one\nline two"), pair("B", "1")]
    );
    assert_eq!(lines(&file), vec![1, 3]);
}

#[test]
fn hash_lines_inside_multiline_value_are_not_comments() {
    assert_eq!(
        value("KEY=\"a\n# not a comment\nb\""),
        "a\n# not a comment\nb"
    );
}

// --- encoding ---

#[test]
fn bom_is_skipped() {
    assert_eq!(pairs(&parse("\u{feff}A=1\n")), vec![pair("A", "1")]);
}

#[test]
fn crlf_line_endings_are_stripped() {
    let file = parse("A=1\r\nB=\"two\"\r\nC='three'\r\n");
    assert_eq!(
        pairs(&file),
        vec![pair("A", "1"), pair("B", "two"), pair("C", "three")]
    );
}

#[test]
fn crlf_inside_multiline_value_becomes_lf() {
    assert_eq!(value("KEY=\"x\r\ny\"\r\n"), "x\ny");
    assert_eq!(value("KEY='x\r\ny'\r\n"), "x\ny");
}

#[test]
fn last_line_without_newline() {
    assert_eq!(
        pairs(&parse("A=1\nB=2")),
        vec![pair("A", "1"), pair("B", "2")]
    );
}

#[test]
fn invalid_utf8_is_an_error_with_its_line() {
    assert_eq!(
        err_bytes(b"A=1\nB=\xff\xfe\n"),
        DotenvError::Encoding { line: 2 }
    );
}

// --- ${VAR} / $VAR ---

#[test]
fn braced_reference_is_kept_literally_with_a_warning() {
    let file = parse("A=1\nURL=${HOST}/x\n");
    assert_eq!(file.entries[1].value.expose(), "${HOST}/x");
    assert_eq!(file.warnings, vec![interpolation("URL", 2)]);
}

#[test]
fn bare_reference_is_kept_literally_with_a_warning() {
    let file = parse("HOME_DIR=$HOME\nPRIV=$_private\n");
    assert_eq!(
        pairs(&file),
        vec![pair("HOME_DIR", "$HOME"), pair("PRIV", "$_private")]
    );
    assert_eq!(
        file.warnings,
        vec![interpolation("HOME_DIR", 1), interpolation("PRIV", 2)]
    );
}

#[test]
fn reference_in_double_quotes_warns() {
    let file = parse("A=\"${X}\"\n");
    assert_eq!(file.entries[0].value.expose(), "${X}");
    assert_eq!(file.warnings, vec![interpolation("A", 1)]);
}

#[test]
fn reference_in_multiline_value_warns_with_the_start_line() {
    let file = parse("A=1\nB=\"first\nsecond ${X}\"\n");
    assert_eq!(file.warnings, vec![interpolation("B", 2)]);
}

#[test]
fn one_warning_per_entry() {
    let file = parse("A=${X}${Y}$Z\n");
    assert_eq!(file.warnings, vec![interpolation("A", 1)]);
}

#[test]
fn single_quotes_do_not_warn() {
    let file = parse("A='${X} $Y'\n");
    assert_eq!(file.entries[0].value.expose(), "${X} $Y");
    assert!(file.warnings.is_empty());
}

#[test]
fn dollar_not_followed_by_a_name_does_not_warn() {
    let file = parse("A=cost$\nB=$1\nC=$ 5\nD=\"price: 5$\"\nE=a$-b\n");
    assert_eq!(
        pairs(&file),
        vec![
            pair("A", "cost$"),
            pair("B", "$1"),
            pair("C", "$ 5"),
            pair("D", "price: 5$"),
            pair("E", "a$-b"),
        ]
    );
    assert!(file.warnings.is_empty(), "{:?}", file.warnings);
}

// --- errors ---

#[test]
fn line_without_equals_is_an_error() {
    assert_eq!(
        err("A=1\nJUSTTEXT\n"),
        DotenvError::MissingEquals { line: 2 }
    );
    assert_eq!(err("export FOO\n"), DotenvError::MissingEquals { line: 1 });
}

#[test]
fn invalid_names_are_errors() {
    for (input, line) in [
        ("1A=x", 1),
        ("A=1\nmy-key=x", 2),
        ("=x", 1),
        ("MY KEY=x", 1),
        ("KEY.NAME=x", 1),
        ("ZAŻÓŁĆ=x", 1),
    ] {
        assert_eq!(err(input), DotenvError::InvalidName { line }, "{input:?}");
    }
}

#[test]
fn unquoted_value_starting_with_hash_is_ambiguous() {
    assert_eq!(err("KEY=#x\n"), DotenvError::AmbiguousComment { line: 1 });
    assert_eq!(
        err("A=1\nKEY= # comment\n"),
        DotenvError::AmbiguousComment { line: 2 }
    );
}

#[test]
fn unterminated_quote_reports_the_start_line() {
    assert_eq!(
        err("A=1\nB=\"open\nC=3\nD=4\n"),
        DotenvError::UnterminatedQuote { line: 2 }
    );
    assert_eq!(err("A='open\n"), DotenvError::UnterminatedQuote { line: 1 });
    assert_eq!(
        err(r#"A="ends with escaped quote\""#),
        DotenvError::UnterminatedQuote { line: 1 }
    );
}

#[test]
fn content_after_closing_quote_is_an_error() {
    assert_eq!(err("A=\"a\"b\n"), DotenvError::TrailingContent { line: 1 });
    assert_eq!(err("A='a' b\n"), DotenvError::TrailingContent { line: 1 });
    assert_eq!(
        err("A=1\nB=\"x\ny\"z\n"),
        DotenvError::TrailingContent { line: 3 }
    );
}

#[test]
fn backticks_are_unsupported() {
    assert_eq!(err("A=`x`\n"), DotenvError::UnsupportedQuote { line: 1 });
}

#[test]
fn duplicate_names_are_errors_with_both_lines() {
    assert_eq!(
        err("A=1\nB=2\nexport A=3\n"),
        DotenvError::Duplicate {
            name: name("A"),
            first: 1,
            second: 3,
        }
    );
}

#[test]
fn names_are_case_sensitive_for_duplicates() {
    assert_eq!(
        pairs(&parse("key=1\nKEY=2\n")),
        vec![pair("key", "1"), pair("KEY", "2")]
    );
}

#[test]
fn nul_byte_is_an_invalid_value() {
    assert_eq!(
        err("A=1\nB=a\0b\n"),
        DotenvError::InvalidValue {
            name: name("B"),
            line: 2,
            reason: SecretError::InvalidValue,
        }
    );
}

#[test]
fn oversized_value_is_an_invalid_value() {
    let input = format!("BIG={}\n", "x".repeat(MAX_VALUE_LEN + 1));
    assert_eq!(
        err(&input),
        DotenvError::InvalidValue {
            name: name("BIG"),
            line: 1,
            reason: SecretError::ValueTooLarge,
        }
    );
    let max = format!("MAX={}\n", "x".repeat(MAX_VALUE_LEN));
    assert_eq!(value(&max).len(), MAX_VALUE_LEN);
}

#[test]
fn messages_name_the_line_and_the_fix() {
    let missing = err("A=1\nJUSTTEXT\n").to_string();
    assert!(missing.contains("line 2"), "{missing}");

    let duplicate = err("A=1\nB=2\nA=3\n").to_string();
    assert!(duplicate.contains('A'), "{duplicate}");
    assert!(duplicate.contains("lines 1 and 3"), "{duplicate}");

    let ambiguous = err("KEY=#x\n").to_string();
    assert!(ambiguous.contains("quote"), "{ambiguous}");
}

// --- no echo ---

#[test]
fn errors_never_echo_values_or_rejected_lines() {
    let cases: [&[u8]; 9] = [
        b"hunter2-key=x\n",
        b"sk_live_hunter2\n",
        b"A=\"hunter2\nB=1\n",
        b"A=\"hunter2\"x\n",
        b"A=`hunter2`\n",
        b"A=#hunter2\n",
        b"A=hunter2\xff\n",
        b"A=hunter2\0\n",
        b"A=hunter2\nA=hunter2\n",
    ];
    for input in cases {
        assert_no_echo(&err_bytes(input), "hunter2");
    }
}

#[test]
fn debug_of_parsed_file_does_not_reveal_values() {
    let file = parse("A=hunter2\nB=${hunter2}\n");
    let debug = format!("{file:?}");
    assert!(!debug.contains("hunter2"), "{debug}");
}

// --- fixtures: import 1:1 ---

#[test]
fn fixture_node_style() {
    let file = Dotenv::parse(include_bytes!("fixtures/dotenv/node.env")).unwrap();
    assert_eq!(
        pairs(&file),
        vec![
            pair("NODE_ENV", "development"),
            pair("PORT", "3000"),
            pair("DATABASE_URL", "postgres://user:p@ss#1@localhost:5432/app"),
            pair("API_KEY", "sk_test_51Habc"),
            pair("EMPTY", ""),
            pair("GREETING", "Hello, World!"),
            pair("MULTI", "line one\nline two"),
            pair("ESCAPED", "first\nsecond"),
            pair("SECRET_TOKEN", "abc123"),
            pair("URL_WITH_HASH", "https://example.com/page#section"),
        ]
    );
    assert_eq!(lines(&file), vec![2, 3, 4, 5, 6, 7, 8, 10, 11, 12]);
    assert!(file.warnings.is_empty());
}

#[test]
fn fixture_compose_style() {
    let file = Dotenv::parse(include_bytes!("fixtures/dotenv/compose.env")).unwrap();
    assert_eq!(
        pairs(&file),
        vec![
            pair("POSTGRES_USER", "app"),
            pair("POSTGRES_PASSWORD", "s3cr3t$tuff"),
            pair("POSTGRES_DB", "app_db"),
            pair("TZ", "Europe/Warsaw"),
            pair("JAVA_OPTS", "-Xmx512m -Dfile.encoding=UTF-8"),
            pair("QUOTE_INSIDE", "say\"hi\""),
            pair("REDIS_URL", "redis://${REDIS_HOST}:6379"),
        ]
    );
    assert_eq!(file.warnings, vec![interpolation("REDIS_URL", 8)]);
}

#[test]
fn fixture_pem_in_both_forms_is_identical() {
    let file = Dotenv::parse(include_bytes!("fixtures/dotenv/pem.env")).unwrap();
    let expected =
        "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBg\nkqhkiG9w0BAQEF\n-----END PRIVATE KEY-----\n";
    assert_eq!(
        pairs(&file),
        vec![
            pair("KEY_ESCAPED", expected),
            pair("KEY_MULTILINE", expected),
        ]
    );
    assert_eq!(lines(&file), vec![1, 2]);
}

#[test]
fn fixture_crlf_with_bom() {
    let file = Dotenv::parse(include_bytes!("fixtures/dotenv/crlf-bom.env")).unwrap();
    assert_eq!(
        pairs(&file),
        vec![pair("A", "1"), pair("B", "x\ny"), pair("C", "three")]
    );
    assert_eq!(lines(&file), vec![1, 2, 5]);
}
