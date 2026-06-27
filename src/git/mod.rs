//! Git helpers used by `init`, `doctor`, and `check`.
//!
//! sopsy needs to know whether it is inside a repository, which files are
//! tracked (so `check` can ensure no plaintext secrets are committed), and
//! whether sensitive paths are ignored. These helpers shell out to `git`.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Error, Result};

/// The name of the external binary this module drives.
pub const GIT_BIN: &str = "git";

/// Run `git -C <dir> <args...>` and return the captured [`std::process::Output`].
///
/// I/O failures (e.g. `git` missing) are mapped to [`Error::Io`]; the exit
/// status is left for the caller to interpret since several git subcommands
/// communicate meaning through non-zero exit codes.
fn git(dir: &Path, args: &[&str]) -> Result<std::process::Output> {
    let output = Command::new(GIT_BIN)
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()?;
    Ok(output)
}

/// Locate the root of the git repository containing `start`.
///
/// Runs `git -C <start> rev-parse --show-toplevel`, returning
/// [`Error::NotAGitRepo`] when `start` is not inside a repository.
pub fn repo_root(start: &Path) -> Result<PathBuf> {
    let output = git(start, &["rev-parse", "--show-toplevel"])?;
    if !output.status.success() {
        return Err(Error::NotAGitRepo);
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        return Err(Error::NotAGitRepo);
    }
    Ok(PathBuf::from(path))
}

/// List files tracked by git under `repo`.
///
/// Runs `git -C <repo> ls-files`, returning one [`PathBuf`] per tracked path
/// (relative to `repo`).
pub fn tracked_files(repo: &Path) -> Result<Vec<PathBuf>> {
    let output = git(repo, &["ls-files"])?;
    if !output.status.success() {
        return Err(Error::ProcessFailed {
            tool: GIT_BIN.to_string(),
            code: output.status.code().unwrap_or(-1),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect())
}

/// Report whether `path` is tracked by git.
///
/// Runs `git -C <repo> ls-files --error-unmatch <path>`: exit 0 means tracked,
/// a non-zero exit means untracked. `path` is interpreted relative to `repo`
/// (absolute paths inside the repo also work).
pub fn is_tracked(repo: &Path, path: &Path) -> Result<bool> {
    let path_str = path.to_string_lossy();
    let output = git(repo, &["ls-files", "--error-unmatch", &path_str])?;
    Ok(output.status.success())
}

/// Report whether `path` is ignored by git (matched by a `.gitignore` rule).
///
/// Runs `git -C <repo> check-ignore <path>`: exit 0 means ignored, exit 1 means
/// not ignored, and any other exit code is surfaced as [`Error::ProcessFailed`].
pub fn is_ignored(repo: &Path, path: &Path) -> Result<bool> {
    let path_str = path.to_string_lossy();
    let output = git(repo, &["check-ignore", "--quiet", &path_str])?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        other => Err(Error::ProcessFailed {
            tool: GIT_BIN.to_string(),
            code: other.unwrap_or(-1),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        }),
    }
}

/// Ensure `pattern` is present in the repository's `.gitignore`, appending it if
/// missing. Returns `true` if the file was modified, `false` if `pattern` was
/// already present. Idempotent.
pub fn ensure_gitignored(repo: &Path, pattern: &str) -> Result<bool> {
    let gitignore = repo.join(".gitignore");
    let existing = match std::fs::read_to_string(&gitignore) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(Error::Io(err)),
    };

    let already_present = existing
        .lines()
        .map(str::trim)
        .any(|line| line == pattern.trim());
    if already_present {
        return Ok(false);
    }

    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(pattern.trim_end());
    updated.push('\n');
    std::fs::write(&gitignore, updated)?;
    Ok(true)
}
