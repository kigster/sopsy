//! `sopsy edit <file>` — edit an encrypted file via `sops`.
//!
//! TODO (full contract, per AGENT.md): resolve the editor (`--editor`, then
//! `$EDITOR`, then a sensible default), verify the file exists and is covered by
//! a `.sops.yaml` creation rule, then run `EDITOR=<editor> sops <file>` with any
//! trailing `-- <sops args>` forwarded verbatim, surfacing nicer errors than
//! raw sops on failure.

use crate::cli::EditArgs;
use crate::error::Result;
use crate::ui::Ui;

/// Run the edit command.
pub fn run(ui: &Ui, args: &EditArgs) -> Result<()> {
    ui.header("sopsy edit");
    ui.info(format!("would edit {}", args.file.display()));
    ui.warn("`sopsy edit` is not yet implemented");
    Ok(())
}
