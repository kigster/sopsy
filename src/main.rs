//! Thin binary wrapper around [`sopsy::run`].
//!
//! Installs `color_eyre` for pretty panic/error reports, runs the CLI, and maps
//! any error to a non-zero process exit code while printing it via the UI's
//! conventions.

use std::process::ExitCode;

use owo_colors::OwoColorize;

fn main() -> ExitCode {
    // Pretty backtraces; ignore failure to install (e.g. if already installed).
    let _ = color_eyre::install();

    match sopsy::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{} {err}", "✗".red().bold());
            ExitCode::FAILURE
        }
    }
}
