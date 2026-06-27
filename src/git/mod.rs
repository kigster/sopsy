//! Git helpers used by `init`, `doctor`, and `check`.
//!
//! sopsy needs to know whether it is inside a repository, which files are
//! tracked (so `check` can ensure no plaintext secrets are committed), and
//! whether sensitive paths are ignored. These helpers shell out to `git`.
//!
//! Functions here are **stubs** for now; signatures and contracts are fixed for
//! the implementation phase.

use std::path::{Path, PathBuf};

use crate::error::Result;

/// The name of the external binary this module drives.
pub const GIT_BIN: &str = "git";

/// Locate the root of the git repository containing `start`.
///
/// TODO: run `git -C <start> rev-parse --show-toplevel`; return
/// [`crate::error::Error::NotAGitRepo`] when outside a repo.
pub fn repo_root(_start: &Path) -> Result<PathBuf> {
    todo!("resolve git repository root")
}

/// List files tracked by git under `dir`.
///
/// TODO: run `git -C <dir> ls-files`.
pub fn tracked_files(_dir: &Path) -> Result<Vec<PathBuf>> {
    todo!("list git-tracked files")
}

/// Report whether `path` is ignored by git (matched in `.gitignore`).
///
/// TODO: run `git -C <dir> check-ignore <path>` and interpret the exit code.
pub fn is_ignored(_dir: &Path, _path: &Path) -> Result<bool> {
    todo!("check whether a path is git-ignored")
}

/// Report whether `path` is tracked by git.
///
/// TODO: run `git -C <dir> ls-files --error-unmatch <path>`.
pub fn is_tracked(_dir: &Path, _path: &Path) -> Result<bool> {
    todo!("check whether a path is git-tracked")
}

/// Ensure `pattern` is present in the repository's `.gitignore`, appending it if
/// missing. Returns `true` if the file was modified.
///
/// TODO: idempotently add the pattern.
pub fn ensure_gitignored(_dir: &Path, _pattern: &str) -> Result<bool> {
    todo!("ensure a pattern is present in .gitignore")
}
