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

/// Severity of a single rendered diagnostic line, decoupling the *decision*
/// (which is pure and unit-testable) from the *rendering* (which writes to the
/// terminal via [`Ui`]).
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    /// Rendered as a green success line.
    Success,
    /// Rendered as a yellow warning line.
    Warn,
}

/// Probe macOS-specific properties, tolerating missing/changed tools.
///
/// The actual probes ([`capture_stdout`] / [`capture_combined`]) are the only
/// impure part; the interpretation of their results lives in the pure
/// `*_line` helpers so every branch is exercisable without Apple hardware.
#[cfg(target_os = "macos")]
fn macos_system_checks(ui: &Ui) {
    emit(
        ui,
        macos_version_line(capture_stdout("sw_vers", &["-productVersion"])),
    );
    for line in arch_lines(capture_stdout("uname", &["-m"]).as_deref()) {
        emit(ui, line);
    }
    // Touch ID detection is best-effort: `bioutil -r` is undocumented and its
    // output format varies, so we never fail on it.
    emit(
        ui,
        touch_id_line(capture_combined("bioutil", &["-r"]).as_deref()),
    );
}

/// Render a `(Severity, message)` decision to the terminal.
#[cfg(target_os = "macos")]
fn emit(ui: &Ui, (severity, message): (Severity, String)) {
    match severity {
        Severity::Success => ui.success(message),
        Severity::Warn => ui.warn(message),
    }
}

/// Interpret the `sw_vers -productVersion` result.
#[cfg(target_os = "macos")]
fn macos_version_line(version: Option<String>) -> (Severity, String) {
    match version {
        Some(version) => (Severity::Success, format!("macOS {version}")),
        None => (
            Severity::Warn,
            "could not determine macOS version (sw_vers unavailable)".to_string(),
        ),
    }
}

/// Interpret the `uname -m` architecture result. On Apple Silicon a Secure
/// Enclave is always present, which is what `age-plugin-se` relies on.
#[cfg(target_os = "macos")]
fn arch_lines(arch: Option<&str>) -> Vec<(Severity, String)> {
    if arch == Some("arm64") {
        vec![
            (Severity::Success, "Apple Silicon (arm64)".to_string()),
            (Severity::Success, "Secure Enclave available".to_string()),
        ]
    } else {
        vec![
            (
                Severity::Warn,
                format!("not Apple Silicon (arch: {})", arch.unwrap_or("unknown")),
            ),
            (
                Severity::Warn,
                "Secure Enclave unavailable (requires Apple Silicon)".to_string(),
            ),
        ]
    }
}

/// Interpret the combined `bioutil -r` output for Touch ID status.
#[cfg(target_os = "macos")]
fn touch_id_line(report: Option<&str>) -> (Severity, String) {
    match report {
        Some(out) if out.contains('1') => {
            (Severity::Success, "Touch ID appears configured".to_string())
        }
        Some(_) => (
            Severity::Warn,
            "Touch ID present but may not be enrolled".to_string(),
        ),
        None => (
            Severity::Warn,
            "Touch ID status unknown (bioutil unavailable)".to_string(),
        ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Recipient;
    use crate::ui::Ui;

    /// A quiet, non-interactive `Ui` suitable for exercising the print paths.
    fn ui() -> Ui {
        Ui::new(false, false, false)
    }

    #[test]
    fn run_is_always_ok() {
        // The doctor is informational and must never fail, regardless of the
        // surrounding environment.
        run(&ui()).unwrap();
    }

    #[test]
    fn parse_yaml_accepts_valid_and_rejects_invalid() {
        let dir = assert_fs::TempDir::new().unwrap();
        let good = dir.path().join("good.yaml");
        std::fs::write(&good, "a: 1\nb: [1, 2, 3]\n").unwrap();
        assert!(parse_yaml(&good).is_ok());

        let bad = dir.path().join("bad.yaml");
        // Unbalanced flow mapping is a YAML syntax error.
        std::fs::write(&bad, "a: [1, 2\n").unwrap();
        assert!(parse_yaml(&bad).is_err());

        // A missing file surfaces an I/O error rather than panicking.
        assert!(parse_yaml(&dir.path().join("missing.yaml")).is_err());
    }

    #[test]
    fn recipient_checks_cover_all_branches() {
        // Empty recipients + no break-glass.
        recipient_checks(&ui(), &Config::default());

        // Recipients present, but still no break-glass key.
        let mut cfg = Config::default();
        cfg.recipients.push(Recipient::new("alice", "age1alice"));
        recipient_checks(&ui(), &cfg);

        // A break-glass recipient is configured.
        cfg.recipients.push(Recipient {
            break_glass: true,
            ..Recipient::new("break-glass", "age1emergency")
        });
        recipient_checks(&ui(), &cfg);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_version_line_branches() {
        assert_eq!(
            macos_version_line(Some("15.0".to_string())),
            (Severity::Success, "macOS 15.0".to_string())
        );
        assert_eq!(macos_version_line(None).0, Severity::Warn);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn arch_lines_branches() {
        let arm = arch_lines(Some("arm64"));
        assert!(arm.iter().all(|(s, _)| *s == Severity::Success));
        assert!(arm.iter().any(|(_, m)| m.contains("Apple Silicon")));

        let intel = arch_lines(Some("x86_64"));
        assert!(intel.iter().all(|(s, _)| *s == Severity::Warn));
        assert!(intel.iter().any(|(_, m)| m.contains("x86_64")));

        // Unknown architecture falls back to "unknown".
        let unknown = arch_lines(None);
        assert!(unknown.iter().any(|(_, m)| m.contains("unknown")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn touch_id_line_branches() {
        assert_eq!(touch_id_line(Some("Biometrics: 1")).0, Severity::Success);
        assert_eq!(touch_id_line(Some("no digits here")).0, Severity::Warn);
        assert_eq!(touch_id_line(None).0, Severity::Warn);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn emit_renders_both_severities() {
        emit(&ui(), (Severity::Success, "ok".to_string()));
        emit(&ui(), (Severity::Warn, "careful".to_string()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn capture_helpers_handle_success_failure_and_missing() {
        // Success with output.
        assert_eq!(capture_stdout("echo", &["hi"]).as_deref(), Some("hi"));
        // Success but empty output → None.
        assert!(capture_stdout("true", &[]).is_none());
        // Non-zero exit → None.
        assert!(capture_stdout("false", &[]).is_none());
        // Missing binary → None.
        assert!(capture_stdout("sopsy-no-such-bin-xyz", &[]).is_none());

        // capture_combined returns Some even on failure, None only when the
        // binary cannot be launched.
        assert!(capture_combined("false", &[]).is_some());
        assert!(capture_combined("sopsy-no-such-bin-xyz", &[]).is_none());
    }
}
