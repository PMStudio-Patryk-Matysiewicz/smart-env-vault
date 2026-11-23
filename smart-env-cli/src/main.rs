#![forbid(unsafe_code)]
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut system = smart_env_cli::System::detect();
    let exit = smart_env_cli::execute(
        std::env::args_os(),
        &mut system.context(),
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    ExitCode::from(exit.code())
}
