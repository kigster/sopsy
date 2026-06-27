//! Integration tests for [`sopsy::git`] against a **real** git repository.
//!
//! Each test creates a throwaway repo with `git init`, tracks files, and
//! exercises the helpers end-to-end. No mocking — these prove the actual `git`
//! invocations and exit-code handling are correct.

use std::path::Path;
use std::process::Command;

use assert_fs::TempDir;
use sopsy::git;

/// Run `git <args>` inside `dir`, asserting success.
fn run_git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .expect("git should be available");
    assert!(status.success(), "git {args:?} failed in {}", dir.display());
}

/// Initialize a real git repo with a stable identity and default branch.
fn init_repo() -> TempDir {
    let dir = TempDir::new().unwrap();
    run_git(dir.path(), &["init", "-q", "-b", "main"]);
    run_git(dir.path(), &["config", "user.email", "test@example.com"]);
    run_git(dir.path(), &["config", "user.name", "Sopsy Test"]);
    dir
}

#[test]
fn repo_root_resolves_toplevel() {
    let dir = init_repo();
    // git on macOS canonicalizes /var -> /private/var, so compare canonicalized.
    let expected = std::fs::canonicalize(dir.path()).unwrap();

    let root = git::repo_root(dir.path()).unwrap();
    assert_eq!(std::fs::canonicalize(&root).unwrap(), expected);

    // Also resolvable from a nested subdirectory.
    let nested = dir.path().join("a/b");
    std::fs::create_dir_all(&nested).unwrap();
    let from_nested = git::repo_root(&nested).unwrap();
    assert_eq!(std::fs::canonicalize(&from_nested).unwrap(), expected);
}

#[test]
fn repo_root_errors_outside_repo() {
    // A fresh temp dir that is NOT a git repo.
    let dir = TempDir::new().unwrap();
    let err = git::repo_root(dir.path()).unwrap_err();
    assert!(matches!(err, sopsy::error::Error::NotAGitRepo));
}

#[test]
fn tracked_files_lists_added_files() {
    let dir = init_repo();
    std::fs::write(dir.path().join("a.txt"), "alpha").unwrap();
    std::fs::write(dir.path().join("b.txt"), "bravo").unwrap();
    run_git(dir.path(), &["add", "a.txt", "b.txt"]);
    run_git(dir.path(), &["commit", "-q", "-m", "add files"]);

    let tracked = git::tracked_files(dir.path()).unwrap();
    assert!(tracked.iter().any(|p| p.ends_with("a.txt")));
    assert!(tracked.iter().any(|p| p.ends_with("b.txt")));
    assert_eq!(tracked.len(), 2);
}

#[test]
fn is_tracked_distinguishes_tracked_and_untracked() {
    let dir = init_repo();
    std::fs::write(dir.path().join("tracked.txt"), "x").unwrap();
    run_git(dir.path(), &["add", "tracked.txt"]);
    run_git(dir.path(), &["commit", "-q", "-m", "init"]);
    std::fs::write(dir.path().join("loose.txt"), "y").unwrap();

    assert!(git::is_tracked(dir.path(), Path::new("tracked.txt")).unwrap());
    assert!(!git::is_tracked(dir.path(), Path::new("loose.txt")).unwrap());
}

#[test]
fn is_ignored_respects_gitignore() {
    let dir = init_repo();
    std::fs::write(dir.path().join(".gitignore"), ".env\n*.key\n").unwrap();

    assert!(git::is_ignored(dir.path(), Path::new(".env")).unwrap());
    assert!(git::is_ignored(dir.path(), Path::new("secret.key")).unwrap());
    assert!(!git::is_ignored(dir.path(), Path::new("README.md")).unwrap());
}

#[test]
fn ensure_gitignored_is_idempotent() {
    let dir = init_repo();

    // First call creates/appends and reports a modification.
    assert!(git::ensure_gitignored(dir.path(), ".env").unwrap());
    // Second call is a no-op.
    assert!(!git::ensure_gitignored(dir.path(), ".env").unwrap());

    // Adding a different pattern modifies again.
    assert!(git::ensure_gitignored(dir.path(), "*.key").unwrap());

    let contents = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert_eq!(contents.matches(".env").count(), 1);
    assert!(contents.contains("*.key"));
    // And git now actually ignores it.
    assert!(git::is_ignored(dir.path(), Path::new(".env")).unwrap());
}

#[test]
fn ensure_gitignored_preserves_existing_content() {
    let dir = init_repo();
    std::fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();

    assert!(git::ensure_gitignored(dir.path(), ".env").unwrap());
    let contents = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert!(contents.contains("node_modules/"));
    assert!(contents.contains(".env"));
}
