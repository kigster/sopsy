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
//! - [`sops`], [`enclave`], [`age`], [`git`] — helpers wrapping external tools.

pub mod age;
pub mod cli;
pub mod commands;
pub mod config;
pub mod enclave;
pub mod error;
pub mod git;
pub mod keystore;
pub mod sops;
pub mod ui;

use clap::Parser;

use crate::cli::{Cli, Command, SecretsCommand};
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
    )
    .with_git(cli.global.git);
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
        Command::Join(args) => commands::join::run(ui, &args),
        Command::Approve(args) => commands::approve::run(ui, &args),
        Command::Recipient(cmd) => commands::recipient::run(ui, &cmd),
        Command::Secrets(cmd) => commands::secrets::run(ui, &cmd),
        // `sopsy encrypt`/`sopsy decrypt` are shorthands for the `secrets`
        // subcommands, routed through the same handler.
        Command::Encrypt(args) => commands::secrets::run(ui, &SecretsCommand::Encrypt(args)),
        Command::Decrypt(args) => commands::secrets::run(ui, &SecretsCommand::Decrypt(args)),
        Command::ListSupportedTypes => {
            commands::secrets::list_supported_types(ui);
            Ok(())
        }
        Command::Check => commands::check::run(ui),
        Command::Deps(args) => commands::deps::run(ui, &args),
        Command::Completion(args) => commands::completion::run(&args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{CompletionArgs, DepsArgs, InitArgs, SecretsDecryptArgs, SecretsEncryptArgs};

    fn test_ui() -> Ui {
        Ui::new(false, false, false)
    }

    #[test]
    fn dispatch_doctor_is_ok() {
        assert!(dispatch(&test_ui(), Command::Doctor).is_ok());
    }

    #[test]
    fn dispatch_deps_and_completion_are_ok() {
        let ui = test_ui();
        // `--dry-run` only prints the would-be `brew install` line.
        assert!(
            dispatch(
                &ui,
                Command::Deps(DepsArgs {
                    check: false,
                    dry_run: true,
                })
            )
            .is_ok()
        );
        assert!(
            dispatch(
                &ui,
                Command::Completion(CompletionArgs {
                    shell: clap_complete::Shell::Bash,
                })
            )
            .is_ok()
        );
    }

    #[test]
    fn dispatch_encrypt_decrypt_shorthands_route_to_secrets() {
        // Both arms route through `commands::secrets::run`; a nonexistent
        // input file proves the arm is taken and the shared validation
        // rejects it before any external tool is invoked.
        let ui = test_ui();
        assert!(
            dispatch(
                &ui,
                Command::Encrypt(SecretsEncryptArgs {
                    file: "no-such-file.env".into(),
                    output: None,
                    file_type: None,
                })
            )
            .is_err()
        );
        assert!(
            dispatch(
                &ui,
                Command::Decrypt(SecretsDecryptArgs {
                    file: "no-such-file.env.encrypted".into(),
                    output: None,
                    file_type: None,
                })
            )
            .is_err()
        );
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
                    username: None,
                    public_key: None,
                    no_generate: true,
                    break_glass: false,
                    no_break_glass: true,
                    force: false,
                })
            )
            .is_err()
        );
        // `Command::Edit` is no longer a stub; its behavior (file existence,
        // sops invocation) is covered by `tests/edit.rs` against real `sops`.
    }
}
