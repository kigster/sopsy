//! Helpers for invoking the external `sops` binary.
//!
//! sopsy never reimplements encryption; it orchestrates `sops`. This module
//! owns all process invocation so command code stays declarative.
//!
//! ```text
//! edit  -> EDITOR=<editor> sops <extra args> <file>
//! encrypt -> sops --encrypt --input-type T --output-type T --in-place <file>
//! decrypt -> sops --decrypt --input-type T --output-type T <file>
//! updatekeys -> sops updatekeys [-y] --input-type T <file>  (per file)
//! ```
//!
//! Note that real `sops updatekeys` operates on a **single file** and refuses
//! directories, so [`updatekeys`] walks a directory itself when handed one.
//!
//! The `sops` binary can be overridden via the `SOPSY_SOPS_BIN` environment
//! variable (defaulting to `sops`), which is primarily useful for injecting a
//! fake binary in tests.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
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

        // Any `*.env` file was already classified as dotenv above, so only the
        // structured extensions remain to distinguish here.
        match path
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .as_deref()
        {
            Some("yaml") | Some("yml") => FileType::Yaml,
            Some("json") => FileType::Json,
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

/// Re-encrypt managed file(s) for the current recipient set after the
/// `.sops.yaml` creation rules change.
///
/// Real `sops updatekeys` (3.13.x) operates on a **single file**, requires an
/// explicit `--input-type`, refuses directories ("can't operate on a
/// directory"), and does not accept `-r`. To preserve the convenient "update
/// the whole repo" ergonomics, this helper does the walking itself:
///
/// - When `dir_or_path` is a directory, it is walked recursively (skipping
///   `.git/`); every sops-encrypted file found (detected by its `ENC[` marker)
///   is updated with `sops updatekeys [-y] --input-type <inferred> <file>`.
/// - When `dir_or_path` is a single file, just that file is updated.
///
/// `-y` is passed when `assume_yes` is set so it runs non-interactively.
pub fn updatekeys(dir_or_path: &Path, assume_yes: bool) -> Result<()> {
    if dir_or_path.is_dir() {
        let mut files = Vec::new();
        collect_encrypted_files(dir_or_path, &mut files)?;
        files.sort();
        for file in &files {
            updatekeys_file(file, assume_yes)?;
        }
        Ok(())
    } else {
        updatekeys_file(dir_or_path, assume_yes)
    }
}

/// Run `sops updatekeys [-y] --input-type <inferred> <file>` for a single file.
fn updatekeys_file(file: &Path, assume_yes: bool) -> Result<()> {
    let ty = FileType::from_path(file).as_sops_type();
    let mut command = Command::new(sops_bin());
    command.arg("updatekeys");
    if assume_yes {
        command.arg("-y");
    }
    command.args(["--input-type", ty]).arg(file);

    let output = command.output()?;
    check_status(&output)
}

/// Recursively collect sops-encrypted files under `dir`, skipping the `.git/`
/// directory. Detection is by the `ENC[` marker sops writes into every
/// encrypted value, which is also present in encrypted binary blobs.
fn collect_encrypted_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") {
                continue;
            }
            collect_encrypted_files(&path, out)?;
        } else if file_type.is_file() && is_sops_encrypted(&path) {
            out.push(path);
        }
    }
    Ok(())
}

/// Heuristically detect whether `file` is a sops-encrypted artifact by scanning
/// its contents for the `ENC[` marker. Unreadable files are treated as not
/// encrypted rather than aborting the whole walk.
fn is_sops_encrypted(file: &Path) -> bool {
    match std::fs::read(file) {
        Ok(bytes) => bytes.windows(4).any(|window| window == b"ENC["),
        Err(_) => false,
    }
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

    #[test]
    fn from_path_is_case_insensitive() {
        for (name, expected) in [
            (".ENV", FileType::Dotenv),
            (".Env.Production", FileType::Dotenv),
            ("Service.ENV", FileType::Dotenv),
            ("CONFIG.YAML", FileType::Yaml),
            ("Config.YML", FileType::Yaml),
            ("Data.JSON", FileType::Json),
        ] {
            assert_eq!(
                FileType::from_path(&PathBuf::from(name)),
                expected,
                "{name} misclassified"
            );
        }
    }

    #[test]
    fn from_path_handles_pathless_names() {
        // An empty path has no file name; it must fall back to binary.
        assert_eq!(FileType::from_path(&PathBuf::from("")), FileType::Binary);
    }

    #[test]
    fn is_sops_encrypted_detects_marker() {
        let dir = assert_fs::TempDir::new().unwrap();
        let enc = dir.path().join("secret.enc");
        std::fs::write(&enc, "data=ENC[AES256_GCM,data:xx]\n").unwrap();
        assert!(is_sops_encrypted(&enc));

        let plain = dir.path().join("plain.txt");
        std::fs::write(&plain, "nothing secret here\n").unwrap();
        assert!(!is_sops_encrypted(&plain));

        // A path that cannot be read is treated as not encrypted.
        assert!(!is_sops_encrypted(dir.path().join("missing").as_path()));
    }

    #[test]
    fn collect_encrypted_files_walks_and_skips_git() {
        let dir = assert_fs::TempDir::new().unwrap();
        let root = dir.path();
        std::fs::write(root.join("top.enc"), "x=ENC[AES256_GCM,data:1]\n").unwrap();
        std::fs::write(root.join("plain.txt"), "plain\n").unwrap();
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("nested/inner.enc"), "ENC[AES256_GCM,data:2]\n").unwrap();
        // A `.git` directory must be skipped even if it contains an ENC[ marker.
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".git/index.enc"), "ENC[AES256_GCM,data:3]\n").unwrap();

        let mut found = Vec::new();
        collect_encrypted_files(root, &mut found).unwrap();
        found.sort();

        assert!(found.iter().any(|p| p.ends_with("top.enc")));
        assert!(found.iter().any(|p| p.ends_with("nested/inner.enc")));
        assert!(!found.iter().any(|p| p.to_string_lossy().contains(".git")));
        assert!(!found.iter().any(|p| p.ends_with("plain.txt")));
        assert_eq!(found.len(), 2);
    }
}
