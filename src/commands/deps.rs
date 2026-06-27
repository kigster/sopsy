//! `sopsy deps` — install sopsy's external tool dependencies via Homebrew.
//!
//! sopsy orchestrates three external tools: `sops`, `age`, and `age-plugin-se`.
//! This command probes for each, then `brew install`s the ones that are missing
//! — the remedy that pairs with [`crate::commands::doctor`]'s diagnosis.
//!
//! `git` is intentionally **not** installed here: it ships with macOS / the
//! Xcode Command Line Tools and is not a Homebrew formula sopsy should manage.
//!
//! The `brew` binary can be overridden via the `SOPSY_BREW_BIN` environment
//! variable (defaulting to `brew`), which is primarily useful for injecting a
//! fake binary in tests.

use std::ffi::OsString;
use std::process::Command;

use crate::cli::DepsArgs;
use crate::error::{Error, Result};
use crate::ui::Ui;

/// External tools sopsy installs via Homebrew, in probe order.
const DEPENDENCIES: &[&str] = &["sops", "age", "age-plugin-se"];

/// The default Homebrew binary name.
pub const BREW_BIN: &str = "brew";

/// Environment variable that overrides the `brew` binary path (for testing).
pub const BREW_BIN_ENV: &str = "SOPSY_BREW_BIN";

/// Resolve the `brew` binary to invoke, honoring [`BREW_BIN_ENV`].
fn brew_bin() -> OsString {
    std::env::var_os(BREW_BIN_ENV).unwrap_or_else(|| OsString::from(BREW_BIN))
}

/// Run `sopsy deps`.
///
/// Probes each dependency and, depending on the flags, reports status
/// (`--check`), prints what it would do (`--dry-run`), or installs the missing
/// tools with Homebrew.
pub fn run(ui: &Ui, args: &DepsArgs) -> Result<()> {
    ui.header("sopsy deps");

    let missing = report_and_collect_missing(ui);

    // `--check`: report only; exit non-zero if anything is missing.
    if args.check {
        return if missing.is_empty() {
            ui.success("all dependencies are installed");
            Ok(())
        } else {
            Err(Error::Validation(format!(
                "{} missing dependency(ies): {}",
                missing.len(),
                missing.join(", ")
            )))
        };
    }

    if missing.is_empty() {
        ui.success("all dependencies are already installed — nothing to do");
        return Ok(());
    }

    let command = format!("{BREW_BIN} install {}", missing.join(" "));

    // `--dry-run`: show the command without touching the system.
    if args.dry_run {
        ui.info(format!("dry run — would run: {command}"));
        return Ok(());
    }

    ensure_brew_available()?;

    // `deps` is an explicit install command, and `--dry-run` / `--check` already
    // cover previewing, so we install directly rather than prompting again.
    ui.info(format!("running: {command}"));
    install(&missing)?;
    ui.success(format!("installed: {}", missing.join(", ")));
    Ok(())
}

/// Probe each dependency, print a ✔/⚠ line, and return the ones not on `PATH`.
fn report_and_collect_missing(ui: &Ui) -> Vec<&'static str> {
    let mut missing = Vec::new();
    for tool in DEPENDENCIES {
        match which::which(tool) {
            Ok(path) => ui.success(format!("{tool} found at {}", path.display())),
            Err(_) => {
                ui.warn(format!("{tool} is not installed"));
                missing.push(*tool);
            }
        }
    }
    missing
}

/// Verify Homebrew is available, with an actionable error otherwise.
fn ensure_brew_available() -> Result<()> {
    if which::which(brew_bin()).is_err() {
        return Err(Error::Validation(
            "Homebrew (`brew`) is required to install dependencies but was not found on PATH. \
             Install it from https://brew.sh and re-run `sopsy deps`."
                .to_string(),
        ));
    }
    Ok(())
}

/// Run `brew install <tools…>`, streaming Homebrew's output to the terminal.
fn install(tools: &[&str]) -> Result<()> {
    let status = Command::new(brew_bin())
        .arg("install")
        .args(tools)
        .status()?;
    if status.success() {
        return Ok(());
    }
    Err(Error::ProcessFailed {
        tool: BREW_BIN.to_string(),
        code: status.code().unwrap_or(-1),
        message: format!("`brew install {}` failed", tools.join(" ")),
    })
}
