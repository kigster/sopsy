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

#[test]
fn ensure_gitignored_adds_newline_before_appending() {
    let dir = init_repo();
    // Existing content WITHOUT a trailing newline: the helper must insert one
    // before appending the new pattern.
    std::fs::write(dir.path().join(".gitignore"), "node_modules/").unwrap();

    assert!(git::ensure_gitignored(dir.path(), ".env").unwrap());
    let contents = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert_eq!(contents, "node_modules/\n.env\n");
}

#[test]
fn ensure_gitignored_creates_file_when_absent() {
    let dir = init_repo();
    // No `.gitignore` yet: the helper must create it and report a modification.
    assert!(!dir.path().join(".gitignore").exists());
    assert!(git::ensure_gitignored(dir.path(), "*.key").unwrap());
    let contents = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert_eq!(contents, "*.key\n");
}

#[test]
fn ensure_gitignored_surfaces_read_errors() {
    let dir = init_repo();
    // Make `.gitignore` a directory so `read_to_string` fails with a non
    // NotFound error, exercising the `Error::Io` mapping branch.
    std::fs::create_dir(dir.path().join(".gitignore")).unwrap();
    let err = git::ensure_gitignored(dir.path(), ".env").unwrap_err();
    assert!(matches!(err, sopsy::error::Error::Io(_)));
}

#[test]
fn tracked_files_errors_outside_repo() {
    // `git ls-files` exits non-zero outside a repository → ProcessFailed.
    let dir = TempDir::new().unwrap();
    let err = git::tracked_files(dir.path()).unwrap_err();
    match err {
        sopsy::error::Error::ProcessFailed { tool, .. } => assert_eq!(tool, "git"),
        other => panic!("expected ProcessFailed, got {other:?}"),
    }
}

#[test]
fn is_ignored_errors_outside_repo() {
    // `git check-ignore` exits 128 (not 0/1) outside a repo → the catch-all
    // ProcessFailed arm.
    let dir = TempDir::new().unwrap();
    let err = git::is_ignored(dir.path(), Path::new(".env")).unwrap_err();
    match err {
        sopsy::error::Error::ProcessFailed { tool, .. } => assert_eq!(tool, "git"),
        other => panic!("expected ProcessFailed, got {other:?}"),
    }
}

#[test]
fn is_tracked_works_with_absolute_paths() {
    let dir = init_repo();
    std::fs::write(dir.path().join("tracked.txt"), "x").unwrap();
    run_git(dir.path(), &["add", "tracked.txt"]);
    run_git(dir.path(), &["commit", "-q", "-m", "init"]);

    // Absolute path inside the repo resolves as tracked.
    let abs = dir.path().join("tracked.txt");
    assert!(git::is_tracked(dir.path(), &abs).unwrap());
}

// ----- The `--git` staging helpers ----------------------------------------

#[test]
fn stage_adds_only_existing_files_and_reports_them() {
    let dir = init_repo();
    let present = dir.path().join("a.txt");
    std::fs::write(&present, "alpha").unwrap();
    let missing = dir.path().join("nope.txt");

    // The absent path is silently skipped; only the present one is returned.
    let staged = git::stage(dir.path(), &[present.clone(), missing]).unwrap();
    assert_eq!(staged, vec![present]);
    // git now has it in the index.
    assert!(git::is_tracked(dir.path(), Path::new("a.txt")).unwrap());
}

#[test]
fn stage_is_a_noop_when_empty_or_all_missing() {
    let dir = init_repo();
    assert!(git::stage(dir.path(), &[]).unwrap().is_empty());
    assert!(
        git::stage(dir.path(), &[dir.path().join("ghost")])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn current_branch_reports_the_checked_out_branch() {
    let dir = init_repo();
    // `init_repo` forces `-b main`; it resolves even before the first commit
    // (unborn branch), which is the post-`sopsy init` state.
    assert_eq!(git::current_branch(dir.path()).as_deref(), Some("main"));

    run_git(dir.path(), &["checkout", "-q", "-b", "feature/x"]);
    assert_eq!(
        git::current_branch(dir.path()).as_deref(),
        Some("feature/x")
    );
}

#[test]
fn current_branch_is_none_when_detached() {
    let dir = init_repo();
    std::fs::write(dir.path().join("f"), "x").unwrap();
    run_git(dir.path(), &["add", "f"]);
    run_git(dir.path(), &["commit", "-q", "-m", "one"]);
    // Detach HEAD onto the commit; there is no current branch.
    run_git(dir.path(), &["checkout", "-q", "--detach", "HEAD"]);
    assert!(git::current_branch(dir.path()).is_none());
}

#[test]
fn stage_errors_when_git_add_fails() {
    // An existing file in a directory that is NOT a git repo: the file passes
    // the existence filter, so `git add` actually runs — and exits non-zero,
    // which must surface as ProcessFailed rather than a silent skip.
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("a.txt");
    std::fs::write(&file, "alpha").unwrap();

    let err = git::stage(dir.path(), &[file]).unwrap_err();
    match err {
        sopsy::error::Error::ProcessFailed { tool, .. } => assert_eq!(tool, "git"),
        other => panic!("expected ProcessFailed, got {other:?}"),
    }
}

#[test]
fn stage_and_advise_stages_the_given_files() {
    let dir = init_repo();
    for name in [".sops.yaml", ".sopsy.yml"] {
        std::fs::write(dir.path().join(name), "x").unwrap();
    }
    let ui = sopsy::ui::Ui::new(false, false, false);
    let files = [dir.path().join(".sops.yaml"), dir.path().join(".sopsy.yml")];

    git::stage_and_advise(&ui, dir.path(), &files, "Add sopsy secrets").unwrap();

    assert!(git::is_tracked(dir.path(), Path::new(".sops.yaml")).unwrap());
    assert!(git::is_tracked(dir.path(), Path::new(".sopsy.yml")).unwrap());
}

#[test]
fn stage_and_advise_succeeds_when_nothing_exists_to_stage() {
    // Only nonexistent paths: nothing is staged, the helper warns and returns
    // early with Ok — it must NOT print commit/push advice or fail.
    let dir = init_repo();
    let ui = sopsy::ui::Ui::new(false, false, false);
    let files = [dir.path().join("ghost-a"), dir.path().join("ghost-b")];

    git::stage_and_advise(&ui, dir.path(), &files, "Nothing to stage").unwrap();

    // Nothing ended up in the index.
    assert!(git::tracked_files(dir.path()).unwrap().is_empty());
}

#[test]
fn stage_and_advise_handles_detached_head() {
    // On a detached HEAD there is no current branch, so the advice falls back
    // to `git push -u origin HEAD`; staging itself must still succeed.
    let dir = init_repo();
    std::fs::write(dir.path().join("f"), "x").unwrap();
    run_git(dir.path(), &["add", "f"]);
    run_git(dir.path(), &["commit", "-q", "-m", "one"]);
    run_git(dir.path(), &["checkout", "-q", "--detach", "HEAD"]);
    assert!(git::current_branch(dir.path()).is_none());

    std::fs::write(dir.path().join(".sops.yaml"), "y").unwrap();
    let ui = sopsy::ui::Ui::new(false, false, false);
    let files = [dir.path().join(".sops.yaml")];

    git::stage_and_advise(&ui, dir.path(), &files, "Add sopsy secrets").unwrap();

    assert!(git::is_tracked(dir.path(), Path::new(".sops.yaml")).unwrap());
}
