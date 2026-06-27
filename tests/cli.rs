//! End-to-end smoke tests for the `sopsy` binary.
//!
//! These verify the CLI wiring (help/version/subcommands) using `assert_cmd`.
//! They intentionally avoid touching real `sops`/Secure Enclave state; deeper
//! integration tests against real `sops` arrive with the command implementations.

use assert_cmd::Command;
use predicates::prelude::*;

/// Build a `Command` for the compiled `sopsy` binary.
fn sopsy() -> Command {
    Command::cargo_bin("sopsy").expect("binary `sopsy` should build")
}

#[test]
fn help_lists_all_commands() {
    sopsy()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("edit"))
        .stdout(predicate::str::contains("recipient"))
        .stdout(predicate::str::contains("check"));
}

#[test]
fn version_prints_crate_version() {
    sopsy()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn doctor_runs_and_reports_tools() {
    // Non-interactive so it never blocks; doctor only probes PATH.
    sopsy()
        .args(["--non-interactive", "doctor"])
        .assert()
        .success()
        .stdout(predicate::str::contains("git"));
}

#[test]
fn recipient_help_lists_subcommands() {
    sopsy()
        .args(["recipient", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("add"))
        .stdout(predicate::str::contains("remove"))
        .stdout(predicate::str::contains("list"));
}

#[test]
fn unknown_command_fails() {
    sopsy().arg("definitely-not-a-command").assert().failure();
}
