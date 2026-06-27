//! `sopsy check` — CI gate verifying encrypted-secrets hygiene.
//!
//! TODO (full contract, per AGENT.md): exit 0 on success, 1 on failure after
//! verifying that `.env` is not committed and is git-ignored, `.sops.yaml` is
//! valid, every encrypted file matches a creation rule, no plaintext secrets
//! exist in tracked files, all encrypted files parse, and a break-glass
//! recipient exists. Intended for pre-commit hooks and CI.

use crate::error::Result;
use crate::ui::Ui;

/// Run the CI check command.
pub fn run(ui: &Ui) -> Result<()> {
    ui.header("sopsy check");
    ui.warn("`sopsy check` is not yet implemented");
    Ok(())
}
