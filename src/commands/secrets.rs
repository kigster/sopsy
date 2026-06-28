//! `sopsy secrets` — encrypt/decrypt a file to stdout (or `-o <file>`).
//!
//! These are thin, scriptable wrappers over `sops` for one-shot use:
//!
//! - `secrets encrypt <file>` turns a plaintext `.env`/YAML/JSON/INI file into
//!   ciphertext. The intended encrypted artifact always ends in `.encrypted`, so
//!   it is covered by the default `.sops.yaml` rule; sops is told that name via
//!   `--filename-override` to resolve the recipients.
//! - `secrets decrypt <file>` prints the plaintext — designed for piping, e.g.
//!   `eval "$(sopsy secrets decrypt .env.encrypted | sed 's/^/export /')"` in a
//!   direnv `.envrc`.
//!
//! The secret payload goes to **stdout** so it stays pipe-clean; status messages
//! are only printed when writing to a file (`-o`), where they cannot corrupt the
//! output.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::cli::{SecretsCommand, SecretsDecryptArgs, SecretsEncryptArgs};
use crate::error::{Error, Result};
use crate::sops::{self, FileType};
use crate::ui::Ui;

/// Dispatch a `secrets` subcommand.
pub fn run(ui: &Ui, command: &SecretsCommand) -> Result<()> {
    match command {
        SecretsCommand::Encrypt(args) => encrypt(ui, args),
        SecretsCommand::Decrypt(args) => decrypt(ui, args),
    }
}

/// Encrypt a plaintext file to stdout (or `-o <file>`).
fn encrypt(ui: &Ui, args: &SecretsEncryptArgs) -> Result<()> {
    if !args.file.exists() {
        return Err(Error::FileNotFound(args.file.clone()));
    }
    let file_type = args
        .file_type
        .unwrap_or_else(|| FileType::from_path(&args.file));

    // The name sops matches against `.sops.yaml` to pick recipients. With `-o`
    // it must be the (validated `.encrypted`) output name; to stdout we synthesize
    // `<file>.encrypted` so a default rule still matches.
    let override_name = match output_target(&args.output) {
        OutputTarget::File(path) => {
            if !ends_with_encrypted(path) {
                return Err(Error::Validation(format!(
                    "output must end in `.encrypted` (got `{}`)",
                    path.display()
                )));
            }
            path.to_path_buf()
        }
        OutputTarget::Stdout => with_encrypted_suffix(&args.file),
    };

    let ciphertext = sops::encrypt_to_string(&args.file, file_type, &override_name)?;
    write_output(ui, &args.output, ciphertext.as_bytes(), "ciphertext")
}

/// Decrypt an encrypted file to stdout (or `-o <file>`).
fn decrypt(ui: &Ui, args: &SecretsDecryptArgs) -> Result<()> {
    if !args.file.exists() {
        return Err(Error::FileNotFound(args.file.clone()));
    }
    let file_type = args
        .file_type
        .unwrap_or_else(|| FileType::from_path(&args.file));
    let plaintext = sops::decrypt(&args.file, file_type)?;
    write_output(ui, &args.output, plaintext.as_bytes(), "plaintext")
}

/// Print the supported file types (for `sopsy list-supported-types`).
pub fn list_supported_types(ui: &Ui) {
    ui.header("Supported file types");
    ui.info("Structured formats encrypt values only (keys/structure stay diffable);");
    ui.info("`binary` encrypts the whole file. Pass --type to override detection.");
    for file_type in FileType::all() {
        ui.info(format!(
            "  {:<8} {}",
            file_type.as_sops_type(),
            file_type.extension_hint()
        ));
    }
}

/// Where output should go.
enum OutputTarget<'a> {
    Stdout,
    File(&'a Path),
}

/// Resolve `-o`: absent or `-` means stdout, anything else is a file.
fn output_target(output: &Option<PathBuf>) -> OutputTarget<'_> {
    match output {
        Some(path) if path.as_os_str() != "-" => OutputTarget::File(path),
        _ => OutputTarget::Stdout,
    }
}

/// Write `data` to the chosen target. The payload goes to stdout untouched;
/// status (printed only for file output) cannot then corrupt a pipe.
fn write_output(ui: &Ui, output: &Option<PathBuf>, data: &[u8], label: &str) -> Result<()> {
    match output_target(output) {
        OutputTarget::File(path) => {
            std::fs::write(path, data)?;
            ui.success(format!("wrote {label} to {}", path.display()));
        }
        OutputTarget::Stdout => {
            std::io::stdout().write_all(data)?;
        }
    }
    Ok(())
}

/// Whether `path` ends in `.encrypted` (case-insensitive).
fn ends_with_encrypted(path: &Path) -> bool {
    path.to_string_lossy()
        .to_ascii_lowercase()
        .ends_with(".encrypted")
}

/// Append `.encrypted` to `path` (`config.json` → `config.json.encrypted`).
fn with_encrypted_suffix(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".encrypted");
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ends_with_encrypted_is_case_insensitive() {
        assert!(ends_with_encrypted(Path::new(".env.encrypted")));
        assert!(ends_with_encrypted(Path::new("config.json.ENCRYPTED")));
        assert!(!ends_with_encrypted(Path::new("config.json")));
        assert!(!ends_with_encrypted(Path::new("notes.encrypted.txt")));
    }

    #[test]
    fn with_encrypted_suffix_appends() {
        assert_eq!(
            with_encrypted_suffix(Path::new("config.json")),
            PathBuf::from("config.json.encrypted")
        );
        assert_eq!(
            with_encrypted_suffix(Path::new(".env")),
            PathBuf::from(".env.encrypted")
        );
    }

    #[test]
    fn output_target_treats_dash_and_none_as_stdout() {
        assert!(matches!(output_target(&None), OutputTarget::Stdout));
        assert!(matches!(
            output_target(&Some(PathBuf::from("-"))),
            OutputTarget::Stdout
        ));
        assert!(matches!(
            output_target(&Some(PathBuf::from("x.encrypted"))),
            OutputTarget::File(_)
        ));
    }
}
