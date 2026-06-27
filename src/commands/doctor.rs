//! `sopsy doctor` — health checks for the local setup and repository.
//!
//! TODO (full contract, per AGENT.md): verify macOS version, Apple Silicon,
//! Secure Enclave availability and Touch ID; check `sops`, `age-plugin-se`,
//! `git`; validate `.sops.yaml` exists and parses; confirm the repository is
//! healthy; and warn when no break-glass emergency recipient is configured.
//!
//! For now this performs the real tool-presence probing ported from the
//! original `main.rs` so the command is already useful.

use crate::error::Result;
use crate::ui::Ui;

/// External tools sopsy depends on.
const REQUIRED_TOOLS: &[&str] = &["git", "sops", "age-plugin-se"];

/// Run the doctor checks.
pub fn run(ui: &Ui) -> Result<()> {
    ui.header("sopsy doctor");

    for tool in REQUIRED_TOOLS {
        match which::which(tool) {
            Ok(path) => ui.success(format!("{tool} found at {}", path.display())),
            Err(_) => ui.failure(format!("{tool} not found on PATH")),
        }
    }

    // TODO: macOS/Secure Enclave/Touch ID checks, `.sops.yaml` validation,
    // repository health, and break-glass recipient warning.
    ui.warn("Full diagnostics (Secure Enclave, .sops.yaml, repo health) not yet implemented");

    Ok(())
}
