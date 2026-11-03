//! `sopsy secrets` — encrypt/decrypt a file to stdout, `-o <file>` or `-w`.
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
//! `-w` writes by naming convention (`FILE` ↔ `FILE.encrypted`). Whenever a
//! file target already exists, [`existing`] decides whether to replace it, back
//! it up first, or ask.
//!
//! The secret payload goes to **stdout** so it stays pipe-clean; status messages
//! are only printed when writing to a file (`-o`/`-w`), where they cannot corrupt the
//! output.

mod existing;
mod target;

use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

use self::existing::Disposition;
use self::target::Direction;
use crate::cli::{SecretsCommand, SecretsDecryptArgs, SecretsEncryptArgs, WriteArgs};
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

/// Encrypt a plaintext file to stdout, `-o <file>` or `FILE.encrypted` (`-w`).
fn encrypt(ui: &Ui, args: &SecretsEncryptArgs) -> Result<()> {
    if !args.file.exists() {
        return Err(Error::FileNotFound(args.file.clone()));
    }
    let file_type = args
        .file_type
        .unwrap_or_else(|| FileType::from_path(&args.file));
    let destination = target::destination(
        Direction::Encrypt,
        &args.file,
        args.output.as_deref(),
        args.write.write,
    )?;

    // The name sops matches against `.sops.yaml` to pick recipients. With a
    // file target it must be that (validated `.encrypted`) name; to stdout we
    // synthesize `<file>.encrypted` so a default rule still matches.
    let override_name = match &destination {
        Some(path) if !target::ends_with_encrypted(path) => {
            return Err(Error::Validation(format!(
                "output must end in `.encrypted` (got `{}`)",
                path.display()
            )));
        }
        Some(path) => path.clone(),
        None => target::with_encrypted_suffix(&args.file),
    };

    let ciphertext = sops::encrypt_to_string(&args.file, file_type, &override_name)?;
    let sink = Sink {
        direction: Direction::Encrypt,
        write: args.write,
        label: "ciphertext",
    };
    sink.deliver(ui, destination.as_deref(), ciphertext.as_bytes())
}

/// Decrypt an encrypted file to stdout, `-o <file>` or `FILE` (`-w`).
///
/// The whole plaintext is decrypted into memory before the target is touched,
/// so a failed decrypt never truncates an existing file.
fn decrypt(ui: &Ui, args: &SecretsDecryptArgs) -> Result<()> {
    if !args.file.exists() {
        return Err(Error::FileNotFound(args.file.clone()));
    }
    let file_type = args
        .file_type
        .unwrap_or_else(|| FileType::from_path(&args.file));
    let destination = target::destination(
        Direction::Decrypt,
        &args.file,
        args.output.as_deref(),
        args.write.write,
    )?;
    crate::commands::keys::prompt_for_yubikey_if_needed(ui)?;
    let plaintext = sops::decrypt(&args.file, file_type)?;
    let sink = Sink {
        direction: Direction::Decrypt,
        write: args.write,
        label: "plaintext",
    };
    sink.deliver(ui, destination.as_deref(), plaintext.as_bytes())
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

/// Writes a finished payload to stdout or a file, honoring the
/// existing-target rules for files.
struct Sink {
    direction: Direction,
    write: WriteArgs,
    label: &'static str,
}

impl Sink {
    /// Write `data` to `destination` (`None` is stdout). The payload goes to
    /// stdout untouched; status, printed only for file output, cannot then
    /// corrupt a pipe.
    fn deliver(&self, ui: &Ui, destination: Option<&Path>, data: &[u8]) -> Result<()> {
        let Some(path) = destination else {
            std::io::stdout().write_all(data)?;
            return Ok(());
        };
        match existing::decide(ui, self.direction, path, self.write.overwrite)? {
            Disposition::Skip => {
                ui.warn(format!(
                    "left {} unchanged; nothing written",
                    path.display()
                ));
                return Ok(());
            }
            Disposition::BackupThenWrite => {
                let backup = existing::back_up(path, SystemTime::now())?;
                ui.info(format!(
                    "backed up {} to {}",
                    path.display(),
                    backup.display()
                ));
            }
            Disposition::Write => {}
        }
        std::fs::write(path, data)?;
        ui.success(format!("wrote {} to {}", self.label, path.display()));
        Ok(())
    }
}
