//! Helpers for invoking the external `sops` binary.
//!
//! sopsy never reimplements encryption; it orchestrates `sops`. This module
//! owns all process invocation so command code stays declarative.
//!
//! ```text
//! edit  -> EDITOR=<editor> sops <extra args> <file>
//! encrypt -> sops --encrypt --input-type T --output-type T --in-place <file>
//! decrypt -> sops --decrypt --input-type T --output-type T <file>
//! updatekeys -> sops updatekeys [-y] -r <path>   (after recipients change)
//! ```
//!
//! The `sops` binary can be overridden via the `SOPSY_SOPS_BIN` environment
//! variable (defaulting to `sops`), which is primarily useful for injecting a
//! fake binary in tests.

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use crate::error::{Error, Result};

/// The default name of the external binary this module drives.
pub const SOPS_BIN: &str = "sops";

/// Environment variable that overrides the `sops` binary path (for testing).
pub const SOPS_BIN_ENV: &str = "SOPSY_SOPS_BIN";

/// Resolve the `sops` binary to invoke, honoring [`SOPS_BIN_ENV`].
fn sops_bin() -> OsString {
    std::env::var_os(SOPS_BIN_ENV).unwrap_or_else(|| OsString::from(SOPS_BIN))
}

/// Supported sops input/output formats. `dotenv` is the primary use case for
/// sopsy (`.env` files), alongside YAML and JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// `.env`-style `KEY=value` files.
    Dotenv,
    /// YAML documents.
    Yaml,
    /// JSON documents.
    Json,
    /// Opaque binary blobs.
    Binary,
}

impl FileType {
    /// The string sops expects for `--input-type` / `--output-type`.
    pub fn as_sops_type(self) -> &'static str {
        match self {
            FileType::Dotenv => "dotenv",
            FileType::Yaml => "yaml",
            FileType::Json => "json",
            FileType::Binary => "binary",
        }
    }

    /// Infer a [`FileType`] from a file name / extension.
    ///
    /// Detection rules:
    /// - `.env`, `.env.*` (e.g. `.env.production`), or `*.env` → [`FileType::Dotenv`]
    /// - `.yaml` / `.yml` → [`FileType::Yaml`]
    /// - `.json` → [`FileType::Json`]
    /// - anything else → [`FileType::Binary`]
    pub fn from_path(path: &Path) -> Self {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let lower = name.to_ascii_lowercase();

        // dotenv: the file is exactly `.env`, begins with `.env.`, or ends in `.env`.
        if lower == ".env" || lower.starts_with(".env.") || lower.ends_with(".env") {
            return FileType::Dotenv;
        }

        match path
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .as_deref()
        {
            Some("yaml") | Some("yml") => FileType::Yaml,
            Some("json") => FileType::Json,
            Some("env") => FileType::Dotenv,
            _ => FileType::Binary,
        }
    }
}

/// Convert a finished [`std::process::Output`] into a [`Result`], mapping a
/// non-zero exit status to [`Error::ProcessFailed`] with sops's stderr.
fn check_status(output: &std::process::Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    Err(Error::ProcessFailed {
        tool: SOPS_BIN.to_string(),
        code: output.status.code().unwrap_or(-1),
        message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

/// Verify that the `sops` binary is available on `PATH` (or via
/// [`SOPS_BIN_ENV`]), returning a friendly error otherwise.
pub fn ensure_available() -> Result<()> {
    let bin = sops_bin();
    if which::which(&bin).is_ok() {
        return Ok(());
    }
    Err(Error::ToolNotFound(format!(
        "{} (install it with `brew install sops`)",
        bin.to_string_lossy()
    )))
}

/// Launch `sops` to interactively edit `file` using `editor`, forwarding
/// `sops_args` verbatim before the file path.
///
/// stdio is inherited so the editor takes over the terminal. When `editor` is
/// `Some`, the `EDITOR` environment variable is set for the child process.
pub fn edit(file: &Path, editor: Option<&str>, sops_args: &[String]) -> Result<()> {
    let mut command = Command::new(sops_bin());
    if let Some(editor) = editor {
        command.env("EDITOR", editor);
    }
    command.args(sops_args);
    command.arg(file);

    let status = command.status()?;
    if status.success() {
        return Ok(());
    }
    Err(Error::ProcessFailed {
        tool: SOPS_BIN.to_string(),
        code: status.code().unwrap_or(-1),
        message: format!(
            "sops exited unsuccessfully while editing {}",
            file.display()
        ),
    })
}

/// Encrypt `file` in place with the given `file_type`.
///
/// Runs `sops --encrypt --input-type T --output-type T --in-place <file>`,
/// relying on `.sops.yaml` creation rules to supply the recipients.
pub fn encrypt_in_place(file: &Path, file_type: FileType) -> Result<()> {
    let ty = file_type.as_sops_type();
    let output = Command::new(sops_bin())
        .args(["--encrypt", "--input-type", ty, "--output-type", ty])
        .arg("--in-place")
        .arg(file)
        .output()?;
    check_status(&output)
}

/// Decrypt `file` and return its plaintext contents.
///
/// Runs `sops --decrypt --input-type T --output-type T <file>` and captures
/// stdout as a UTF-8 string.
pub fn decrypt(file: &Path, file_type: FileType) -> Result<String> {
    let ty = file_type.as_sops_type();
    let output = Command::new(sops_bin())
        .args(["--decrypt", "--input-type", ty, "--output-type", ty])
        .arg(file)
        .output()?;
    check_status(&output)?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Re-encrypt every managed file for the current recipient set, equivalent to
/// `sops updatekeys -r <dir_or_path>` (with `-y` when `assume_yes` is set so it
/// runs non-interactively).
pub fn updatekeys(dir_or_path: &Path, assume_yes: bool) -> Result<()> {
    let mut command = Command::new(sops_bin());
    command.arg("updatekeys");
    if assume_yes {
        command.arg("-y");
    }
    command.arg("-r").arg(dir_or_path);

    let output = command.output()?;
    check_status(&output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn from_path_detects_dotenv() {
        for name in [".env", ".env.production", ".env.local", "service.env"] {
            assert_eq!(
                FileType::from_path(&PathBuf::from(name)),
                FileType::Dotenv,
                "{name} should be dotenv"
            );
        }
    }

    #[test]
    fn from_path_detects_structured_formats() {
        assert_eq!(
            FileType::from_path(&PathBuf::from("config.yaml")),
            FileType::Yaml
        );
        assert_eq!(
            FileType::from_path(&PathBuf::from("config.yml")),
            FileType::Yaml
        );
        assert_eq!(
            FileType::from_path(&PathBuf::from("config.json")),
            FileType::Json
        );
    }

    #[test]
    fn from_path_falls_back_to_binary() {
        assert_eq!(
            FileType::from_path(&PathBuf::from("secret.pem")),
            FileType::Binary
        );
        assert_eq!(
            FileType::from_path(&PathBuf::from("README")),
            FileType::Binary
        );
    }

    #[test]
    fn sops_type_strings_are_stable() {
        assert_eq!(FileType::Dotenv.as_sops_type(), "dotenv");
        assert_eq!(FileType::Yaml.as_sops_type(), "yaml");
        assert_eq!(FileType::Json.as_sops_type(), "json");
        assert_eq!(FileType::Binary.as_sops_type(), "binary");
    }
}
