//! Command-line interface definition (clap derive).
//!
//! Every interactive prompt in sopsy has an equivalent flag here so the tool is
//! fully scriptable. Global flags ([`GlobalArgs`]) control color, verbosity and
//! interactivity and are flattened into the top-level [`Cli`].
//!
//! Non-interactivity is auto-enabled when stdout is not a TTY; see
//! [`GlobalArgs::resolve_interactive`].

use std::io::IsTerminal;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Top-level CLI parser.
#[derive(Debug, Parser)]
#[command(name = "sopsy")]
#[command(version)]
#[command(about = "The missing developer experience for SOPS")]
#[command(propagate_version = true)]
pub struct Cli {
    /// Global flags shared by every subcommand.
    #[command(flatten)]
    pub global: GlobalArgs,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Flags available on every subcommand.
#[derive(Debug, Args, Clone)]
pub struct GlobalArgs {
    /// Disable all interactive prompts; fail instead of asking. Also enabled
    /// automatically when stdout is not a TTY. Aliased as `--yes`/`-y`.
    #[arg(long, short = 'y', visible_alias = "yes", global = true)]
    pub non_interactive: bool,

    /// Disable colored output (also honors the `NO_COLOR` environment variable).
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Increase output verbosity (show debug detail).
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,
}

impl GlobalArgs {
    /// Resolve whether interactive prompting is allowed, accounting for the
    /// explicit flag and TTY detection.
    pub fn resolve_interactive(&self) -> bool {
        !self.non_interactive && std::io::stdout().is_terminal()
    }

    /// Resolve whether color should be used (subject to further `NO_COLOR`/TTY
    /// checks performed inside [`crate::ui::Ui::new`]).
    pub fn resolve_color(&self) -> bool {
        !self.no_color
    }
}

/// All sopsy subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Bootstrap an encrypted repository (tools, identity, `.sops.yaml`, …).
    Init(InitArgs),

    /// Run health checks on the local setup and repository.
    Doctor,

    /// Edit an encrypted file with your editor via `sops`.
    Edit(EditArgs),

    /// Manage repository recipients (add/remove/list).
    #[command(subcommand)]
    Recipient(RecipientCommand),

    /// CI gate: verify the repo's encrypted-secrets hygiene (exit 0/1).
    Check,
}

/// Arguments for `sopsy init`.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Name to record for the recipient created/registered during init.
    #[arg(long)]
    pub recipient_name: Option<String>,

    /// Use an existing age public key instead of generating a new identity.
    #[arg(long)]
    pub public_key: Option<String>,

    /// Skip Secure Enclave identity generation (e.g. when supplying a key).
    #[arg(long)]
    pub no_generate: bool,

    /// Proceed even if some doctor checks fail.
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `sopsy edit`.
#[derive(Debug, Args)]
pub struct EditArgs {
    /// The encrypted file to edit.
    pub file: PathBuf,

    /// Editor to use (overrides `$EDITOR`); falls back to a sensible default.
    #[arg(long)]
    pub editor: Option<String>,

    /// Extra arguments forwarded verbatim to `sops` after `--`.
    #[arg(last = true)]
    pub sops_args: Vec<String>,
}

/// `sopsy recipient` subcommands.
#[derive(Debug, Subcommand)]
pub enum RecipientCommand {
    /// Add a recipient and re-encrypt secrets (`sops updatekeys -r .`).
    Add(RecipientAddArgs),

    /// Remove a recipient and re-encrypt secrets.
    Remove(RecipientRemoveArgs),

    /// List configured recipients.
    List,
}

/// Arguments for `sopsy recipient add`.
#[derive(Debug, Args)]
pub struct RecipientAddArgs {
    /// Positional recipient name (equivalent to `--name`).
    pub name_pos: Option<String>,

    /// Recipient name.
    #[arg(long = "name")]
    pub name: Option<String>,

    /// The recipient's age public key (`age1...`).
    #[arg(long)]
    pub public_key: Option<String>,

    /// Mark this recipient as the break-glass emergency key.
    #[arg(long)]
    pub break_glass: bool,

    /// Skip running `sops updatekeys` after editing `.sops.yaml`.
    #[arg(long)]
    pub no_updatekeys: bool,
}

impl RecipientAddArgs {
    /// The effective recipient name from either the positional or `--name`.
    pub fn resolved_name(&self) -> Option<&str> {
        self.name.as_deref().or(self.name_pos.as_deref())
    }
}

/// Arguments for `sopsy recipient remove`.
#[derive(Debug, Args)]
pub struct RecipientRemoveArgs {
    /// Positional recipient name (equivalent to `--name`).
    pub name_pos: Option<String>,

    /// Recipient name to remove.
    #[arg(long = "name")]
    pub name: Option<String>,

    /// Skip running `sops updatekeys` after editing `.sops.yaml`.
    #[arg(long)]
    pub no_updatekeys: bool,
}

impl RecipientRemoveArgs {
    /// The effective recipient name from either the positional or `--name`.
    pub fn resolved_name(&self) -> Option<&str> {
        self.name.as_deref().or(self.name_pos.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        // clap's debug assertions catch malformed derive definitions.
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_recipient_add_with_flags() {
        let cli = Cli::try_parse_from([
            "sopsy",
            "--non-interactive",
            "recipient",
            "add",
            "--name",
            "alice",
            "--public-key",
            "age1alice",
        ])
        .unwrap();
        assert!(cli.global.non_interactive);
        match cli.command {
            Command::Recipient(RecipientCommand::Add(args)) => {
                assert_eq!(args.resolved_name(), Some("alice"));
                assert_eq!(args.public_key.as_deref(), Some("age1alice"));
            }
            _ => panic!("expected recipient add"),
        }
    }

    #[test]
    fn yes_alias_enables_non_interactive() {
        let cli = Cli::try_parse_from(["sopsy", "-y", "doctor"]).unwrap();
        assert!(cli.global.non_interactive);
    }
}
