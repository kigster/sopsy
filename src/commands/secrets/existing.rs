//! What to do when the file `encrypt`/`decrypt` is about to write exists.
//!
//! | Situation | Encrypt | Decrypt |
//! | --- | --- | --- |
//! | target absent | write | write |
//! | `--overwrite` or `--yes` / `SOPSY_ASSUME_YES` | replace | back up, replace |
//! | interactive, answered Yes | replace | replace |
//! | interactive, answered No | leave it, write nothing | back up, replace |
//! | not interactive, no flag | error | error |
//!
//! Only plaintext is backed up: a ciphertext backup is clutter (decision D2).

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::target::Direction;
use crate::error::{Error, Result};
use crate::ui::Ui;

/// How to treat the target before writing to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Disposition {
    /// Write it; nothing is there, or it may be replaced as is.
    Write,
    /// Copy the current file to a timestamped backup, then write.
    BackupThenWrite,
    /// Leave the target alone and write nothing.
    Skip,
}

/// Decide what to do with `target`, asking the user when the rules say so.
pub(super) fn decide(
    ui: &Ui,
    direction: Direction,
    target: &Path,
    overwrite: bool,
) -> Result<Disposition> {
    if !target.exists() {
        return Ok(Disposition::Write);
    }
    let backs_up = direction == Direction::Decrypt;
    if overwrite || ui.assumes_yes() {
        return Ok(if backs_up {
            Disposition::BackupThenWrite
        } else {
            Disposition::Write
        });
    }
    if !ui.is_interactive() {
        return Err(Error::Validation(format!(
            "`{}` exists; pass `--overwrite` to replace it",
            target.display()
        )));
    }
    let prompt = format!("{} exists. Overwrite?", target.display());
    Ok(
        match (ui.confirm(&prompt, "--overwrite", false)?, backs_up) {
            (true, _) => Disposition::Write,
            (false, true) => Disposition::BackupThenWrite,
            (false, false) => Disposition::Skip,
        },
    )
}

/// Copy `target` to its timestamped backup and return the backup's path.
///
/// Refuses to replace an existing backup, so no earlier copy is ever lost.
pub(super) fn back_up(target: &Path, now: SystemTime) -> Result<PathBuf> {
    let backup = backup_path(target, now);
    if backup.exists() {
        return Err(Error::Validation(format!(
            "backup `{}` already exists; try again in a second",
            backup.display()
        )));
    }
    std::fs::copy(target, &backup)?;
    Ok(backup)
}

/// `FILE.YYYY-MM-DD.HHMMSS.bak`, stamped in UTC (decision D1).
pub(super) fn backup_path(target: &Path, now: SystemTime) -> PathBuf {
    // `2026-11-03T23:50:07Z` → `2026-11-03` and `235007`.
    let stamp = humantime::format_rfc3339_seconds(now).to_string();
    let date = &stamp[..10];
    let time: String = stamp[11..19].chars().filter(|c| *c != ':').collect();
    let mut name = target.as_os_str().to_os_string();
    name.push(format!(".{date}.{time}.bak"));
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use crate::ui::Answer;

    /// 2026-11-03T23:50:07Z.
    fn instant() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_793_749_807)
    }

    fn existing(dir: &tempfile::TempDir) -> PathBuf {
        let path = dir.path().join(".env");
        std::fs::write(&path, "OLD=1\n").unwrap();
        path
    }

    fn plain_ui() -> Ui {
        Ui::new(false, false, false)
    }

    #[test]
    fn backup_path_keeps_the_extension_last() {
        assert_eq!(
            backup_path(Path::new("dir/.env"), instant()),
            PathBuf::from("dir/.env.2026-11-03.235007.bak")
        );
    }

    #[test]
    fn back_up_copies_and_never_replaces_a_backup() {
        let dir = tempfile::tempdir().unwrap();
        let target = existing(&dir);
        let backup = back_up(&target, instant()).unwrap();
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "OLD=1\n");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "OLD=1\n");
        assert!(back_up(&target, instant()).is_err());
    }

    #[test]
    fn absent_target_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("missing");
        for direction in [Direction::Encrypt, Direction::Decrypt] {
            assert_eq!(
                decide(&plain_ui(), direction, &target, false).unwrap(),
                Disposition::Write
            );
        }
    }

    #[test]
    fn overwrite_backs_up_plaintext_only() {
        let dir = tempfile::tempdir().unwrap();
        let target = existing(&dir);
        assert_eq!(
            decide(&plain_ui(), Direction::Decrypt, &target, true).unwrap(),
            Disposition::BackupThenWrite
        );
        assert_eq!(
            decide(&plain_ui(), Direction::Encrypt, &target, true).unwrap(),
            Disposition::Write
        );
    }

    #[test]
    fn assume_yes_acts_like_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let target = existing(&dir);
        let ui = plain_ui().with_assume_yes(true);
        assert_eq!(
            decide(&ui, Direction::Decrypt, &target, false).unwrap(),
            Disposition::BackupThenWrite
        );
        assert_eq!(
            decide(&ui, Direction::Encrypt, &target, false).unwrap(),
            Disposition::Write
        );
    }

    #[test]
    fn non_interactive_without_a_flag_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let target = existing(&dir);
        let err = decide(&plain_ui(), Direction::Decrypt, &target, false).unwrap_err();
        assert!(err.to_string().contains("pass `--overwrite`"), "{err}");
    }

    #[test]
    fn interactive_answers() {
        let dir = tempfile::tempdir().unwrap();
        let target = existing(&dir);
        let cases = [
            (Direction::Decrypt, true, Disposition::Write),
            (Direction::Decrypt, false, Disposition::BackupThenWrite),
            (Direction::Encrypt, true, Disposition::Write),
            (Direction::Encrypt, false, Disposition::Skip),
        ];
        for (direction, answer, expected) in cases {
            let ui = Ui::scripted(vec![Answer::Yes(answer)]);
            assert_eq!(decide(&ui, direction, &target, false).unwrap(), expected);
        }
    }
}
