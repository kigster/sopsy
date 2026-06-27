//! `sopsy doctor` — health checks for the local setup and repository.
//!
//! The doctor is purely **informational**: it prints a colorful, grouped report
//! of the environment and the current repository and always returns `Ok(())`,
//! even when optional pieces are missing. This keeps its output safe to paste
//! into a bug report or GitHub issue. Hard failures are shown as `✗` lines
//! rather than propagated as errors.
//!
//! Report groups:
//!
//! - **System** — macOS version, Apple Silicon, Secure Enclave and Touch ID.
//!   These are macOS-only and are `cfg`-gated; on other platforms (e.g. the
//!   Linux CI runner) a neutral "n/a (macOS only)" line is printed instead.
//! - **Tools** — `sops`, `age-plugin-se`, `git` resolved on `PATH`.
//! - **Repository** — whether the current directory is inside a git repo and
//!   whether `.sops.yaml` / `.sopsy.yml` are present and parse.
//! - **Recipients** — a break-glass emergency key reminder when `.sopsy.yml`
//!   is present but no break-glass recipient is configured.

use std::path::Path;

use crate::config::{CONFIG_FILE_NAME, Config};
use crate::error::Result;
use crate::git;
use crate::ui::Ui;

/// External tools sopsy depends on, in the order they are probed.
const REQUIRED_TOOLS: &[&str] = &["sops", "age-plugin-se", "git"];

/// Run the doctor checks.
///
/// Always returns `Ok(())`; problems are reported as `✗`/`⚠` lines so the
/// output is always pasteable and the command is never fatal.
pub fn run(ui: &Ui) -> Result<()> {
    ui.header("sopsy doctor");

    system_checks(ui);
    tool_checks(ui);
    repo_checks(ui);

    Ok(())
}

// ----- System -------------------------------------------------------------

/// macOS-only system probes (version, Apple Silicon, Secure Enclave, Touch ID).
///
/// On non-macOS platforms this degrades to a neutral informational line so the
/// command stays cross-platform for CI without ever failing.
fn system_checks(ui: &Ui) {
    ui.header("System");

    #[cfg(target_os = "macos")]
    macos_system_checks(ui);

    #[cfg(not(target_os = "macos"))]
    ui.info("System checks: n/a (macOS only)");
}

/// Probe macOS-specific properties, tolerating missing/again-changed tools.
#[cfg(target_os = "macos")]
fn macos_system_checks(ui: &Ui) {
    match capture_stdout("sw_vers", &["-productVersion"]) {
        Some(version) => ui.success(format!("macOS {version}")),
        None => ui.warn("could not determine macOS version (sw_vers unavailable)"),
    }

    let arch = capture_stdout("uname", &["-m"]);
    let apple_silicon = arch.as_deref() == Some("arm64");
    if apple_silicon {
        ui.success("Apple Silicon (arm64)");
        // On Apple Silicon a Secure Enclave is always present, which is what
        // `age-plugin-se` relies on.
        ui.success("Secure Enclave available");
    } else {
        ui.warn(format!(
            "not Apple Silicon (arch: {})",
            arch.as_deref().unwrap_or("unknown")
        ));
        ui.warn("Secure Enclave unavailable (requires Apple Silicon)");
    }

    // Touch ID detection is best-effort: `bioutil -r` is undocumented and its
    // output format varies, so we never fail on it.
    match capture_combined("bioutil", &["-r"]) {
        Some(out) if out.contains('1') => ui.success("Touch ID appears configured"),
        Some(_) => ui.warn("Touch ID present but may not be enrolled"),
        None => ui.warn("Touch ID status unknown (bioutil unavailable)"),
    }
}

/// Run `bin args...` and return trimmed stdout, or `None` if the tool is
/// missing, fails, or prints nothing.
#[cfg(target_os = "macos")]
fn capture_stdout(bin: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(bin).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

/// Run `bin args...` and return trimmed stdout+stderr combined, ignoring the
/// exit status (some diagnostic tools report via stderr / non-zero status).
/// Returns `None` only when the binary cannot be launched.
#[cfg(target_os = "macos")]
fn capture_combined(bin: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(bin).args(args).output().ok()?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Some(text)
}

// ----- Tools --------------------------------------------------------------

/// Probe the external binaries sopsy orchestrates, reporting their resolved
/// `PATH` location or a not-found `✗` line.
fn tool_checks(ui: &Ui) {
    ui.header("Tools");
    for tool in REQUIRED_TOOLS {
        match which::which(tool) {
            Ok(path) => ui.success(format!("{tool} found at {}", path.display())),
            Err(_) => ui.failure(format!("{tool} not found on PATH")),
        }
    }
}

// ----- Repository ---------------------------------------------------------

/// Inspect the repository containing the current directory: git presence,
/// `.sops.yaml`, `.sopsy.yml`, and (transitively) the break-glass recipient.
fn repo_checks(ui: &Ui) {
    ui.header("Repository");

    let cwd = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            ui.failure(format!("could not determine current directory: {err}"));
            return;
        }
    };

    let root = match git::repo_root(&cwd) {
        Ok(root) => {
            ui.success(format!("inside a git repository ({})", root.display()));
            root
        }
        Err(_) => {
            ui.failure("not inside a git repository");
            return;
        }
    };

    // `.sops.yaml` — consumed by sops itself; we only verify it parses as YAML.
    let sops_yaml = root.join(".sops.yaml");
    if sops_yaml.exists() {
        match parse_yaml(&sops_yaml) {
            Ok(()) => ui.success(".sops.yaml present and parses"),
            Err(err) => ui.failure(format!(".sops.yaml present but failed to parse: {err}")),
        }
    } else {
        ui.failure(".sops.yaml missing (run `sopsy init`)");
    }

    // `.sopsy.yml` — sopsy's own metadata; parse it into the typed `Config`.
    let sopsy_yml = root.join(CONFIG_FILE_NAME);
    if sopsy_yml.exists() {
        match Config::load(&sopsy_yml) {
            Ok(config) => {
                ui.success(format!("{CONFIG_FILE_NAME} present and parses"));
                recipient_checks(ui, &config);
            }
            Err(err) => {
                ui.failure(format!(
                    "{CONFIG_FILE_NAME} present but failed to parse: {err}"
                ));
            }
        }
    } else {
        ui.warn(format!("{CONFIG_FILE_NAME} missing (run `sopsy init`)"));
    }
}

/// Verify that the file at `path` is syntactically valid YAML.
fn parse_yaml(path: &Path) -> Result<()> {
    let raw = std::fs::read_to_string(path)?;
    let _: serde_yaml_ng::Value = serde_yaml_ng::from_str(&raw)?;
    Ok(())
}

// ----- Recipients ---------------------------------------------------------

/// Report on the configured recipients, warning loudly when no break-glass
/// emergency key exists.
fn recipient_checks(ui: &Ui, config: &Config) {
    ui.header("Recipients");

    if config.recipients.is_empty() {
        ui.warn("no recipients configured");
    } else {
        ui.success(format!(
            "{} recipient(s) configured",
            config.recipients.len()
        ));
    }

    match config.break_glass_recipient() {
        Some(recipient) => {
            ui.success(format!(
                "break-glass recipient configured: {}",
                recipient.name
            ));
        }
        None => {
            ui.warn("no break-glass emergency recipient configured");
            ui.warn(
                "> [!CAUTION] Create a break-glass key pair and store it offline in a \
                 vault (e.g. 1Password) that only a few admins can access.",
            );
        }
    }
}
