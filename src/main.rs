#![cfg_attr(all(windows, feature = "gui"), windows_subsystem = "windows")]

mod cli;
#[cfg(feature = "gui")]
mod gui;

fn main() -> std::process::ExitCode {
    zalivka::logging::init(zalivka::logging::Level::Trace);
    #[cfg(windows)]
    if let Some(code) = zalivka::drivers::run_elevated_helper() {
        std::process::exit(code as i32);
    }
    let _logs = match zalivka::logging::background() {
        Ok(logs) => logs,
        Err(error) => {
            zalivka::log!(Error, "journal", "Starting journal thread: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match cli::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            zalivka::log!(Error, "app", "{e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
