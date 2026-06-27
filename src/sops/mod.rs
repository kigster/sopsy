//! Helpers for invoking the external `sops` binary.
//!
//! sopsy never reimplements encryption; it orchestrates `sops`. This module
//! will own all process invocation so command code stays declarative. Functions
//! here are **stubs** for now — signatures and contracts are fixed so the next
//! phase can fill in the bodies.
//!
//! ```text
//! edit  -> EDITOR=<editor> sops <file> [extra args]
//! encrypt/decrypt -> sops --encrypt/--decrypt [--input-type dotenv ...] <file>
//! updatekeys -> sops updatekeys -r .   (after recipients change)
//! ```

use std::path::Path;

use crate::error::Result;

/// The name of the external binary this module drives.
pub const SOPS_BIN: &str = "sops";

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
}

/// Verify that the `sops` binary is available on `PATH`.
///
/// TODO: return its version string for diagnostics.
pub fn ensure_available() -> Result<()> {
    let _ = which::which(SOPS_BIN);
    todo!("verify sops is installed and return version")
}

/// Launch `sops` to interactively edit `file` using `editor`, forwarding
/// `extra_args` verbatim.
///
/// TODO: set `EDITOR`, inherit stdio, map non-zero exit to `ProcessFailed`.
pub fn edit(_file: &Path, _editor: Option<&str>, _extra_args: &[String]) -> Result<()> {
    todo!("invoke `EDITOR=<editor> sops <file> <extra_args>`")
}

/// Encrypt `file` in place with the given `file_type`.
///
/// TODO: run `sops --encrypt --in-place --input-type <ty> <file>`.
pub fn encrypt(_file: &Path, _file_type: FileType) -> Result<()> {
    todo!("encrypt file with sops")
}

/// Decrypt `file` and return its plaintext contents.
///
/// TODO: run `sops --decrypt --input-type <ty> <file>` and capture stdout.
pub fn decrypt(_file: &Path, _file_type: FileType) -> Result<String> {
    todo!("decrypt file with sops")
}

/// Re-encrypt every managed file for the current recipient set, equivalent to
/// `sops updatekeys -r .` (with `-y` in non-interactive mode).
///
/// TODO: run in `dir`, surface errors via `ProcessFailed`.
pub fn updatekeys(_dir: &Path, _assume_yes: bool) -> Result<()> {
    todo!("run `sops updatekeys -r .`")
}
