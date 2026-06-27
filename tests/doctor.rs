//! Integration tests for `sopsy doctor`.
//!
//! These drive the compiled binary with `assert_cmd` against throwaway
//! directories and real temp git repositories. They are deliberately
//! **cross-platform**: no assertions touch the macOS-only System group (macOS
//! version, Apple Silicon, Secure Enclave, Touch ID), so they pass on the Linux
//! CI runner as well as on macOS. The doctor is informational and must always
//! exit 0, which every test asserts.

use std::path::Path;
use std::process::Command as StdCommand;

use assert_cmd::Command;
use assert_fs::TempDir;
use predicates::prelude::*;

/// Build a `Command` for the compiled `sopsy` binary, running non-interactively
/// in `dir`.
fn sopsy_in(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("sopsy").expect("binary `sopsy` should build");
    cmd.current_dir(dir).args(["--non-interactive", "doctor"]);
    cmd
}

/// Run `git <args>` inside `dir`, asserting success.
fn run_git(dir: &Path, args: &[&str]) {
    let status = StdCommand::new("git")
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
fn doctor_in_plain_dir_reports_tools_and_exits_zero() {
    // A bare temp dir that is not a git repository.
    let dir = TempDir::new().unwrap();

    sopsy_in(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Tools"))
        // Each tool prints either "<tool> found at ..." or "<tool> not found",
        // so the tool name always appears regardless of install state.
        .stdout(predicate::str::contains("sops"))
        .stdout(predicate::str::contains("git"));
}

#[test]
fn doctor_without_sops_yaml_warns_break_glass() {
    let dir = init_repo();
    // A `.sopsy.yml` without a break-glass recipient triggers the warning.
    std::fs::write(
        dir.path().join(".sopsy.yml"),
        "recipients:\n  - name: alice\n    public_key: age1alice\n",
    )
    .unwrap();

    sopsy_in(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains(".sops.yaml missing"))
        .stdout(predicate::str::contains(
            "no break-glass emergency recipient configured",
        ))
        .stdout(predicate::str::contains("[!CAUTION]"));
}

#[test]
fn doctor_with_valid_config_has_no_break_glass_warning() {
    let dir = init_repo();
    std::fs::write(
        dir.path().join(".sops.yaml"),
        "creation_rules:\n  - path_regex: \\.env\\.encrypted$\n    age: age1alice\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join(".sopsy.yml"),
        "recipients:\n  - name: alice\n    public_key: age1alice\n  \
         - name: break-glass\n    public_key: age1emergency\n    break_glass: true\n",
    )
    .unwrap();

    sopsy_in(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains(".sops.yaml present and parses"))
        .stdout(predicate::str::contains(".sopsy.yml present and parses"))
        .stdout(predicate::str::contains("break-glass recipient configured"))
        // The CAUTION reminder must NOT appear when a break-glass key exists.
        .stdout(predicate::str::contains("[!CAUTION]").not());
}

#[test]
fn doctor_reports_unparseable_sops_yaml() {
    let dir = init_repo();
    // Invalid YAML (unbalanced flow sequence) must be reported, not fatal.
    std::fs::write(dir.path().join(".sops.yaml"), "creation_rules: [1, 2\n").unwrap();

    sopsy_in(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains(
            ".sops.yaml present but failed to parse",
        ));
}

#[test]
fn doctor_reports_unparseable_sopsy_yml() {
    let dir = init_repo();
    std::fs::write(
        dir.path().join(".sops.yaml"),
        "creation_rules:\n  - path_regex: x\n    age: age1alice\n",
    )
    .unwrap();
    // `recipients` must be a sequence; a scalar makes Config::load fail.
    std::fs::write(dir.path().join(".sopsy.yml"), "recipients: not-a-list\n").unwrap();

    sopsy_in(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains(
            ".sopsy.yml present but failed to parse",
        ));
}

#[test]
fn doctor_warns_when_no_recipients_configured() {
    let dir = init_repo();
    // A valid but empty `.sopsy.yml` reaches the recipient checks with zero
    // recipients, exercising the "no recipients configured" warning.
    std::fs::write(dir.path().join(".sopsy.yml"), "recipients: []\n").unwrap();

    sopsy_in(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("no recipients configured"));
}
