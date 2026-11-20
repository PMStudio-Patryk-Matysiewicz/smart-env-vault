#![forbid(unsafe_code)]
use std::io::IsTerminal;
use std::process::ExitCode;

fn main() -> ExitCode {
    let exit = smart_env_cli::execute(
        std::env::args_os(),
        std::io::stdin().is_terminal(),
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    ExitCode::from(exit.code())
}
