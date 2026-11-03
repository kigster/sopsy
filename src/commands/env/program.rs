//! Find the program `sopsy run` starts, before anything from an encrypted file
//! reaches its environment.
//!
//! `Command` searches the child's `PATH` once one is set on it, so the lookup
//! happens here, against sopsy's own `PATH`, and the command is started by its
//! full path.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// The program `name` names: as given when it contains a `/`, else the first
/// executable file called `name` in an absolute directory of `path`. Empty and
/// relative entries (`""`, `.`, `bin`) are skipped: they mean the current
/// directory, which in a checkout belongs to whoever wrote the repository.
pub fn resolve(name: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    if name.is_empty() {
        return None;
    }
    if name.contains('/') {
        return Some(PathBuf::from(name));
    }
    std::env::split_paths(path?)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    fn program(dir: &Path, name: &str, mode: u32) -> PathBuf {
        let file = dir.join(name);
        std::fs::write(&file, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        file
    }

    fn path_of(dirs: &[&Path]) -> OsString {
        std::env::join_paths(dirs).unwrap()
    }

    #[test]
    fn finds_the_first_executable_in_path_order() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        program(a.path(), "tool", 0o644); // not executable: skipped
        let wanted = program(b.path(), "tool", 0o755);
        let path = path_of(&[a.path(), b.path()]);
        assert_eq!(resolve("tool", Some(&path)), Some(wanted));
        assert_eq!(resolve("missing", Some(&path)), None);
        assert_eq!(resolve("tool", None), None);
        assert_eq!(resolve("", Some(&path)), None);
    }

    #[test]
    fn a_name_with_a_slash_is_used_as_given() {
        assert_eq!(resolve("bin/rails", None), Some(PathBuf::from("bin/rails")));
        assert_eq!(
            resolve("/usr/bin/env", None),
            Some(PathBuf::from("/usr/bin/env"))
        );
    }

    #[test]
    fn empty_and_relative_entries_are_never_searched() {
        let cwd = std::env::current_dir().unwrap();
        let name = "sopsy-resolve-test-planted";
        let planted = program(&cwd, name, 0o755);
        for path in ["", ".", ":", "./", "target"] {
            assert_eq!(resolve(name, Some(OsStr::new(path))), None, "PATH={path:?}");
        }
        std::fs::remove_file(planted).unwrap();
    }
}
