//! The everyday `sops` operations, with sopsy's file-type detection, YubiKey
//! prompts and no plaintext on disk:
//!
//! - `sopsy run`: secrets into one command's environment ([`run`]).
//! - `sopsy set` / `sopsy unset`: change one value ([`values`]).
//! - `sopsy rotate-data-key`: re-encrypt under a new data key ([`rotate`]).

use std::path::Path;

use crate::error::{Error, Result};
use crate::sops::FileType;

mod blocked;
mod program;
mod rotate;
mod run;
mod values;

pub use blocked::{BLOCKED_VARIABLES, is_blocked};
pub use rotate::rotate_data_key;
pub use run::run;
pub use values::{set, unset};

/// The type of an existing encrypted `file`: `explicit`, else detected from
/// its name.
fn encrypted_file_type(file: &Path, explicit: Option<FileType>) -> Result<FileType> {
    if !file.exists() {
        return Err(Error::FileNotFound(file.to_path_buf()));
    }
    Ok(explicit.unwrap_or_else(|| FileType::from_path(file)))
}
