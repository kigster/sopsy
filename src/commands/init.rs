//! `sopsy init` — bootstrap an encrypted repository.
//!
//! TODO (full contract, per AGENT.md): verify Homebrew/`sops`/`age-plugin-se`;
//! generate a Secure Enclave identity if needed (honoring `--public-key` /
//! `--no-generate`); print the public recipient; create `.sops.yaml`,
//! `.env.example`, and an encrypted `.env.encrypted`; update `.gitignore`;
//! write `.sopsy.yml` (recording the recipient named via `--recipient-name` or
//! prompted interactively); then run the doctor checks. Must be idempotent.

use crate::cli::InitArgs;
use crate::error::Result;
use crate::ui::Ui;

/// Run repository initialization.
pub fn run(ui: &Ui, _args: &InitArgs) -> Result<()> {
    ui.header("sopsy init");
    ui.warn("`sopsy init` is not yet implemented");
    Ok(())
}
