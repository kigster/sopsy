//! `sopsy` — the missing developer experience for SOPS.
//!
//! This crate wraps [SOPS](https://github.com/getsops/sops),
//! [age](https://github.com/FiloSottile/age), and `age-plugin-se` to make
//! managing Git-stored encrypted secrets delightful on macOS. The binary is a
//! thin shell over [`run`].
//!
//! ## Module map
//!
//! - [`cli`] — clap definition for every command and flag.
//! - [`ui`] — colorful output + interactive/non-interactive prompting.
//! - [`config`] — serde model for `.sopsy.yml`.
//! - [`error`] — the library [`Error`](error::Error) enum and [`Result`].
//! - [`commands`] — one module per subcommand.
//! - [`sops`], [`enclave`], [`git`] — helpers wrapping external tools.

pub mod cli;
pub mod commands;
pub mod config;
pub mod enclave;
pub mod error;
pub mod git;
pub mod sops;
pub mod ui;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::error::Result;
use crate::ui::Ui;

/// Parse arguments, build the UI layer, and dispatch to the requested command.
///
/// This is the single entry point used by the binary. It returns a
/// [`Result`]; the binary maps the error to a process exit code.
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let ui = Ui::new(
        cli.global.resolve_color(),
        cli.global.verbose,
        cli.global.resolve_interactive(),
    );
    dispatch(&ui, cli.command)
}

/// Dispatch a parsed [`Command`] using the given [`Ui`].
///
/// Separated from [`run`] so it can be unit-tested without touching argv.
fn dispatch(ui: &Ui, command: Command) -> Result<()> {
    match command {
        Command::Init(args) => commands::init::run(ui, &args),
        Command::Doctor => commands::doctor::run(ui),
        Command::Edit(args) => commands::edit::run(ui, &args),
        Command::Recipient(cmd) => commands::recipient::run(ui, &cmd),
        Command::Check => commands::check::run(ui),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{EditArgs, InitArgs};
    use std::path::PathBuf;

    fn test_ui() -> Ui {
        Ui::new(false, false, false)
    }

    #[test]
    fn dispatch_doctor_is_ok() {
        assert!(dispatch(&test_ui(), Command::Doctor).is_ok());
    }

    #[test]
    fn dispatch_stub_commands_are_ok() {
        let ui = test_ui();
        assert!(dispatch(&ui, Command::Check).is_ok());
        // `init` is a real command now: with no key and `--no-generate` it
        // errors *before* touching the filesystem, which is what we assert
        // here (a full happy-path init lives in `tests/init.rs`).
        assert!(
            dispatch(
                &ui,
                Command::Init(InitArgs {
                    recipient_name: None,
                    public_key: None,
                    no_generate: true,
                    force: false,
                })
            )
            .is_err()
        );
        assert!(
            dispatch(
                &ui,
                Command::Edit(EditArgs {
                    file: PathBuf::from("secrets.env"),
                    editor: None,
                    sops_args: vec![],
                })
            )
            .is_ok()
        );
    }
}
