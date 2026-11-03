//! Helpers for invoking the external `sops` binary.
//!
//! sopsy never reimplements encryption; it orchestrates `sops`. This module
//! owns all process invocation so command code stays declarative.
//!
//! ```text
//! edit  -> EDITOR=<editor> sops <extra args> <file>
//! encrypt -> sops --encrypt --input-type T --output-type T --in-place <file>
//! decrypt -> sops --decrypt --input-type T --output-type T <file>
//! ```
//!
//! Re-keying after a `.sops.yaml` change (`sops updatekeys`) lives with the
//! recipient commands in [`crate::commands::recipient`], which scans the repo
//! for managed files and runs `sops updatekeys` per file.
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
/// sopsy (`.env` files), alongside YAML, JSON and INI. Anything else is treated
/// as opaque `binary` (the whole file is encrypted, not value-by-value).
///
/// Derives [`clap::ValueEnum`] so it can back the `--type` flag directly; the
/// generated value names (`dotenv`/`yaml`/`json`/`ini`/`binary`) match
/// [`FileType::as_sops_type`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum FileType {
    /// `.env`-style `KEY=value` files.
    Dotenv,
    /// YAML documents.
    Yaml,
    /// JSON documents.
    Json,
    /// INI files.
    Ini,
    /// Opaque binary blobs (whole-file encryption).
    Binary,
}

impl FileType {
    /// The string sops expects for `--input-type` / `--output-type`.
    pub fn as_sops_type(self) -> &'static str {
        match self {
            FileType::Dotenv => "dotenv",
            FileType::Yaml => "yaml",
            FileType::Json => "json",
            FileType::Ini => "ini",
            FileType::Binary => "binary",
        }
    }

    /// A human hint of which file names auto-detect to this type, for
    /// `sopsy list-supported-types`.
    pub fn extension_hint(self) -> &'static str {
        match self {
            FileType::Dotenv => ".env, .env.*, *.env",
            FileType::Yaml => ".yaml, .yml",
            FileType::Json => ".json",
            FileType::Ini => ".ini",
            FileType::Binary => "anything else (whole-file)",
        }
    }

    /// All supported types, in display order.
    pub fn all() -> [FileType; 5] {
        [
            FileType::Dotenv,
            FileType::Yaml,
            FileType::Json,
            FileType::Ini,
            FileType::Binary,
        ]
    }

    /// Infer a [`FileType`] from a file name / extension.
    ///
    /// A trailing `.encrypted` is stripped first, so encrypted artifacts are
    /// detected by their *inner* type (e.g. `config.json.encrypted` → JSON,
    /// `.env.encrypted` → dotenv). Detection rules on the remaining name:
    /// - `.env`, `.env.*` (e.g. `.env.production`), or `*.env` → [`FileType::Dotenv`]
    /// - `.yaml` / `.yml` → [`FileType::Yaml`]
    /// - `.json` → [`FileType::Json`]
    /// - `.ini` → [`FileType::Ini`]
    /// - anything else → [`FileType::Binary`]
    pub fn from_path(path: &Path) -> Self {
        let original = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // Strip a trailing `.encrypted` (case-insensitive) so the encrypted
        // artifact detects by its inner format.
        let name = if original.to_ascii_lowercase().ends_with(".encrypted") {
            original[..original.len() - ".encrypted".len()].to_string()
        } else {
            original
        };
        let lower = name.to_ascii_lowercase();

        // dotenv: the file is exactly `.env`, begins with `.env.`, or ends in `.env`.
        if lower == ".env" || lower.starts_with(".env.") || lower.ends_with(".env") {
            return FileType::Dotenv;
        }

        // Any `*.env` file was already classified as dotenv above, so only the
        // structured extensions remain to distinguish here.
        match Path::new(&name)
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .as_deref()
        {
            Some("yaml") | Some("yml") => FileType::Yaml,
            Some("json") => FileType::Json,
            Some("ini") => FileType::Ini,
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
    crate::keystore::configure_sops_env(&mut command);
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
    let mut command = Command::new(sops_bin());
    crate::keystore::configure_sops_env(&mut command);
    let output = command
        .args(["--encrypt", "--input-type", ty, "--output-type", ty])
        .arg("--in-place")
        .arg(file)
        .output()?;
    check_status(&output)
}

/// Encrypt `file` and return the ciphertext, leaving `file` untouched.
///
/// `filename_override` is the name sops uses to match `.sops.yaml`
/// `creation_rules` (i.e. the intended `.encrypted` artifact name) — the
/// plaintext file's own name usually does not match a rule, so without this sops
/// would not know which recipients to use. The explicit `--input-type` /
/// `--output-type` still force the format regardless of that override.
pub fn encrypt_to_string(
    file: &Path,
    file_type: FileType,
    filename_override: &Path,
) -> Result<String> {
    let ty = file_type.as_sops_type();
    let mut command = Command::new(sops_bin());
    crate::keystore::configure_sops_env(&mut command);
    let output = command
        .args(["--encrypt", "--input-type", ty, "--output-type", ty])
        .arg("--filename-override")
        .arg(filename_override)
        .arg(file)
        .output()?;
    check_status(&output)?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Decrypt `file` and return its plaintext contents.
///
/// Runs `sops --decrypt --input-type T --output-type T <file>` and captures
/// stdout as a UTF-8 string.
pub fn decrypt(file: &Path, file_type: FileType) -> Result<String> {
    let ty = file_type.as_sops_type();
    let mut command = Command::new(sops_bin());
    crate::keystore::configure_sops_env(&mut command);
    let output = command
        .args(["--decrypt", "--input-type", ty, "--output-type", ty])
        .arg(file)
        .output()?;
    check_status(&output)?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// The first sops release with `sops set --value-stdin`.
pub const SET_VALUE_STDIN_SINCE: (u32, u32, u32) = (3, 11, 0);

/// The installed sops version, from `sops --version`.
pub fn version() -> Result<(u32, u32, u32)> {
    let output = Command::new(sops_bin()).arg("--version").output()?;
    check_status(&output)?;
    let text = String::from_utf8_lossy(&output.stdout);
    parse_version(&text).ok_or_else(|| {
        Error::Validation(format!(
            "could not read the sops version from `{}`",
            text.lines().next().unwrap_or("").trim()
        ))
    })
}

/// Fail with an upgrade hint unless sops is at least `min`.
pub fn require_version(min: (u32, u32, u32), feature: &str) -> Result<()> {
    let found = version()?;
    if found >= min {
        return Ok(());
    }
    let show = |(a, b, c): (u32, u32, u32)| format!("{a}.{b}.{c}");
    Err(Error::Validation(format!(
        "{feature} needs sops {} or newer, and sops {} is installed; upgrade it \
         (`brew upgrade sops`, or a release from https://github.com/getsops/sops/releases)",
        show(min),
        show(found)
    )))
}

/// `sops 3.13.2 (latest)` → `(3, 13, 2)`.
fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    let word = text
        .split_whitespace()
        .map(|w| w.trim_start_matches('v'))
        .find(|w| w.chars().next().is_some_and(|c| c.is_ascii_digit()))?;
    let mut parts = word.split('.').map(|p| {
        p.chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse::<u32>()
            .ok()
    });
    Some((
        parts.next()??,
        parts.next()??,
        parts.next().flatten().unwrap_or(0),
    ))
}

/// Decrypt `file` and return it as JSON, whatever its own format: what
/// `sopsy run` reads its variables from. (sops's dotenv output writes a newline
/// and a literal backslash-n the same way, so it cannot be decoded losslessly.)
pub fn decrypt_as_json(file: &Path, file_type: FileType) -> Result<String> {
    let mut command = Command::new(sops_bin());
    crate::keystore::configure_sops_env(&mut command);
    let output = command
        .args(["--decrypt", "--input-type", file_type.as_sops_type()])
        .args(["--output-type", "json"])
        .arg(file)
        .output()?;
    check_status(&output)?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Set `path` (a sops tree path such as `["API_KEY"]`) to `json_value` in
/// `file`, in place. The value goes through stdin (`--value-stdin`), so it
/// never appears in a process listing.
pub fn set_value(file: &Path, file_type: FileType, path: &str, json_value: &str) -> Result<()> {
    use std::io::Write;
    use std::process::Stdio;
    // An older sops would need the value on the command line, visible to
    // every process on the machine; refuse instead.
    require_version(
        SET_VALUE_STDIN_SINCE,
        "`sopsy set` (it passes the value on stdin)",
    )?;
    let ty = file_type.as_sops_type();
    let mut command = Command::new(sops_bin());
    crate::keystore::configure_sops_env(&mut command);
    let mut child = command
        .args([
            "set",
            "--input-type",
            ty,
            "--output-type",
            ty,
            "--value-stdin",
        ])
        .arg(file)
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(json_value.as_bytes())?;
    }
    check_status(&child.wait_with_output()?)
}

/// Remove `path` from `file`, in place.
pub fn unset_value(file: &Path, file_type: FileType, path: &str) -> Result<()> {
    let ty = file_type.as_sops_type();
    let mut command = Command::new(sops_bin());
    crate::keystore::configure_sops_env(&mut command);
    let output = command
        .args(["unset", "--input-type", ty, "--output-type", ty])
        .arg(file)
        .arg(path)
        .output()?;
    check_status(&output)
}

/// Re-encrypt `file` in place under a brand-new data key, for the same
/// recipients (`sops rotate -i`).
pub fn rotate_in_place(file: &Path, file_type: FileType) -> Result<()> {
    let ty = file_type.as_sops_type();
    let mut command = Command::new(sops_bin());
    crate::keystore::configure_sops_env(&mut command);
    let output = command
        .args([
            "rotate",
            "--in-place",
            "--input-type",
            ty,
            "--output-type",
            ty,
        ])
        .arg(file)
        .output()?;
    check_status(&output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sops_versions_are_parsed() {
        assert_eq!(parse_version("sops 3.13.2 (latest)\n"), Some((3, 13, 2)));
        assert_eq!(parse_version("sops 3.9.4"), Some((3, 9, 4)));
        assert_eq!(parse_version("sops v3.11.0-rc1"), Some((3, 11, 0)));
        assert_eq!(parse_version("sops 3.12"), Some((3, 12, 0)));
        assert_eq!(parse_version("no version here"), None);
        assert!((3, 9, 4) < SET_VALUE_STDIN_SINCE && (3, 11, 0) >= SET_VALUE_STDIN_SINCE);
    }
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
        assert_eq!(
            FileType::from_path(&PathBuf::from("app.ini")),
            FileType::Ini
        );
    }

    #[test]
    fn from_path_strips_encrypted_suffix_for_inner_type() {
        // Encrypted artifacts detect by their inner format.
        assert_eq!(
            FileType::from_path(&PathBuf::from(".env.encrypted")),
            FileType::Dotenv
        );
        assert_eq!(
            FileType::from_path(&PathBuf::from("config.json.encrypted")),
            FileType::Json
        );
        assert_eq!(
            FileType::from_path(&PathBuf::from("helm.yml.ENCRYPTED")),
            FileType::Yaml
        );
        assert_eq!(
            FileType::from_path(&PathBuf::from("app.ini.encrypted")),
            FileType::Ini
        );
        // No inner extension → binary (caller can pass --type).
        assert_eq!(
            FileType::from_path(&PathBuf::from("secret.encrypted")),
            FileType::Binary
        );
    }

    #[test]
    fn sops_type_includes_ini() {
        assert_eq!(FileType::Ini.as_sops_type(), "ini");
        assert_eq!(FileType::all().len(), 5);
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
}
