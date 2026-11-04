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

use super::plaintext;
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
    if overwrite || ui.consents_to_overwrite() {
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
/// The backup holds plaintext, so it is created mode 0600 whatever the old
/// file's mode. It never replaces anything: when a name is taken (two runs in
/// one second, or a planted symlink), the next free `-1`, `-2`, … name is used.
pub(super) fn back_up(target: &Path, now: SystemTime) -> Result<PathBuf> {
    let mut source = std::fs::File::open(target)?;
    for n in 0..MAX_SAME_SECOND_BACKUPS {
        let candidate = backup_path(target, now, n);
        match plaintext::create_new(&candidate) {
            Ok(mut backup) => {
                std::io::copy(&mut source, &mut backup)?;
                return Ok(candidate);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Err(Error::Validation(format!(
        "{MAX_SAME_SECOND_BACKUPS} backups of `{}` already exist for this second",
        target.display()
    )))
}

/// How many backups of one file a single second may hold.
const MAX_SAME_SECOND_BACKUPS: u32 = 100;

/// The `n`th backup name for one second, stamped in UTC (decision D1):
/// `FILE.YYYY-MM-DD.HHMMSS.bak` for `n == 0`, then
/// `FILE.YYYY-MM-DD.HHMMSS-1.bak`, `-2`, ….
fn backup_path(target: &Path, now: SystemTime, n: u32) -> PathBuf {
    // `2026-11-03T23:50:07Z` → `2026-11-03` and `235007`.
    let stamp = humantime::format_rfc3339_seconds(now).to_string();
    let date = &stamp[..10];
    let time: String = stamp[11..19].chars().filter(|c| *c != ':').collect();
    let counter = if n == 0 {
        String::new()
    } else {
        format!("-{n}")
    };
    let mut name = target.as_os_str().to_os_string();
    name.push(format!(".{date}.{time}{counter}.bak"));
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
            backup_path(Path::new("dir/.env"), instant(), 0),
            PathBuf::from("dir/.env.2026-11-03.235007.bak")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_backup_is_private_even_when_the_original_is_not() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = existing(&dir);
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let backup = back_up(&target, instant()).unwrap();
        let mode = std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_backup_name_is_skipped_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = existing(&dir);
        let planted = backup_path(&target, instant(), 0);
        std::os::unix::fs::symlink(dir.path().join("stolen"), &planted).unwrap();
        let backup = back_up(&target, instant()).unwrap();
        assert_eq!(backup, backup_path(&target, instant(), 1));
        assert!(!dir.path().join("stolen").exists());
    }

    #[test]
    fn back_up_copies_and_never_replaces_a_backup() {
        let dir = tempfile::tempdir().unwrap();
        let target = existing(&dir);
        let backup = back_up(&target, instant()).unwrap();
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "OLD=1\n");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "OLD=1\n");

        std::fs::write(&target, "NEWER=2\n").unwrap();
        let second = back_up(&target, instant()).unwrap();
        assert_eq!(second, dir.path().join(".env.2026-11-03.235007-1.bak"));
        assert_eq!(std::fs::read_to_string(&second).unwrap(), "NEWER=2\n");
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "OLD=1\n");
    }

    #[test]
    fn back_up_gives_up_when_every_name_is_taken() {
        let dir = tempfile::tempdir().unwrap();
        let target = existing(&dir);
        for n in 0..MAX_SAME_SECOND_BACKUPS {
            std::fs::write(backup_path(&target, instant(), n), "").unwrap();
        }
        let err = back_up(&target, instant()).unwrap_err();
        assert!(err.to_string().contains("already exist"), "{err}");
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
    fn yes_flag_acts_like_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let target = existing(&dir);
        let ui = plain_ui().with_yes_flag(true);
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
