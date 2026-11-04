//! Writing decrypted plaintext so only its owner can read it.
//!
//! Every plaintext file sopsy writes, the decrypted output and each backup of
//! it, is mode 0600 on Unix, whatever the umask or the old file's mode.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::error::Result;

/// Owner read and write only.
#[cfg(unix)]
const PRIVATE_MODE: u32 = 0o600;

/// Write `data` to `path`, replacing its contents, and leave it mode 0600.
///
/// An existing file is narrowed to 0600 before anything is written to it, so
/// the new plaintext is never readable by others, even for a moment.
pub(super) fn write(path: &Path, data: &[u8]) -> Result<()> {
    if path.exists() {
        restrict(path)?;
    }
    let mut file = options().create(true).truncate(true).open(path)?;
    file.write_all(data)?;
    Ok(())
}

/// Create `path` as a new 0600 file. Fails with `AlreadyExists` when anything,
/// a dangling symlink included, is already there, so a planted link can never
/// receive the plaintext.
pub(super) fn create_new(path: &Path) -> std::io::Result<File> {
    options().create_new(true).open(path)
}

fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(PRIVATE_MODE);
    }
    options
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_MODE))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_new_file_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        write(&path, b"A=1\n").unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"A=1\n");
    }

    #[test]
    fn an_existing_readable_file_is_narrowed_and_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, "OLD=1\nLONGER=2\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write(&path, b"A=1\n").unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"A=1\n");
    }

    #[test]
    fn create_new_refuses_a_planted_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("x.bak");
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), &link).unwrap();
        let err = create_new(&link).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(!dir.path().join("elsewhere").exists());
    }
}
