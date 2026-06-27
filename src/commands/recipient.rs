//! `sopsy recipient` — manage repository recipients.
//!
//! TODO (full contract, per AGENT.md):
//! - `add [name]`: resolve the name/public key (from flags or prompts), add the
//!   recipient to `.sops.yaml` `creation_rules` and `.sopsy.yml`, mark
//!   break-glass when requested, then run `sops updatekeys -r .` (unless
//!   `--no-updatekeys`).
//! - `remove [name]`: remove the recipient from both files and re-encrypt.
//! - `list`: print all configured recipients, flagging the break-glass key.

use crate::cli::{RecipientAddArgs, RecipientCommand, RecipientRemoveArgs};
use crate::error::Result;
use crate::ui::Ui;

/// Dispatch a `recipient` subcommand.
pub fn run(ui: &Ui, command: &RecipientCommand) -> Result<()> {
    match command {
        RecipientCommand::Add(args) => add(ui, args),
        RecipientCommand::Remove(args) => remove(ui, args),
        RecipientCommand::List => list(ui),
    }
}

/// Add a recipient.
fn add(ui: &Ui, args: &RecipientAddArgs) -> Result<()> {
    ui.header("sopsy recipient add");
    if let Some(name) = args.resolved_name() {
        ui.info(format!("would add recipient `{name}`"));
    }
    ui.warn("`sopsy recipient add` is not yet implemented");
    Ok(())
}

/// Remove a recipient.
fn remove(ui: &Ui, args: &RecipientRemoveArgs) -> Result<()> {
    ui.header("sopsy recipient remove");
    if let Some(name) = args.resolved_name() {
        ui.info(format!("would remove recipient `{name}`"));
    }
    ui.warn("`sopsy recipient remove` is not yet implemented");
    Ok(())
}

/// List recipients.
fn list(ui: &Ui) -> Result<()> {
    ui.header("sopsy recipient list");
    ui.warn("`sopsy recipient list` is not yet implemented");
    Ok(())
}
