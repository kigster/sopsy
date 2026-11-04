//! Delivering a finished `encrypt`/`decrypt` payload to stdout or a file.

use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

use super::existing::{self, Disposition};
use super::plaintext;
use super::target::Direction;
use crate::cli::WriteArgs;
use crate::error::Result;
use crate::ui::Ui;

/// Writes a finished payload to stdout or a file, honoring the
/// existing-target rules for files.
pub(super) struct Sink {
    pub(super) direction: Direction,
    pub(super) write: WriteArgs,
    pub(super) label: &'static str,
}

impl Sink {
    /// Write `data` to `destination` (`None` is stdout). The payload goes to
    /// stdout untouched; status, printed only for file output, cannot then
    /// corrupt a pipe.
    pub(super) fn deliver(&self, ui: &Ui, destination: Option<&Path>, data: &[u8]) -> Result<()> {
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
        match self.direction {
            Direction::Decrypt => plaintext::write(path, data)?,
            Direction::Encrypt => std::fs::write(path, data)?,
        }
        ui.success(format!("wrote {} to {}", self.label, path.display()));
        Ok(())
    }
}
