mod cli;
#[cfg(feature = "gui")]
mod gui;

fn main() -> std::process::ExitCode {
    zalivka::logging::init(false);
    match cli::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            zalivka::log!(Error, "app", "{e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
