//! End-to-end smoke tests for the `sopsy` binary.
//!
//! These verify the CLI wiring (help/version/subcommands) using `assert_cmd`.
//! They intentionally avoid touching real `sops`/Secure Enclave state; deeper
//! integration tests against real `sops` arrive with the command implementations.

use assert_cmd::Command;
use predicates::prelude::*;

/// Build a `Command` for the compiled `sopsy` binary.
fn sopsy() -> Command {
    let mut cmd = Command::cargo_bin("sopsy").expect("binary `sopsy` should build");
    cmd.env("SOPSY_BREW_BIN", "/nonexistent/sopsy-test-brew"); // never run a real `brew` from tests
    cmd
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
fn init_help_documents_allow_stores_any() {
    sopsy()
        .args(["init", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--allow-stores"))
        .stdout(predicate::str::contains("any"))
        .stdout(predicate::str::contains("hardware only"));
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

/// `sopsy yubikey` / `sopsy enclave` hand every argument, flags included, to
/// the plugin unchanged, and pass its failure back.
#[cfg(unix)]
#[test]
fn plugin_commands_pass_arguments_through() {
    use std::os::unix::fs::PermissionsExt;
    let dir = assert_fs::TempDir::new().unwrap();
    let fake = dir.path().join("plugin");
    std::fs::write(
        &fake,
        "#!/bin/sh\necho \"args: $*\"\n[ \"$1\" = fail ] && exit 3\nexit 0\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

    for (cmd, env) in [
        ("yubikey", "SOPSY_AGE_PLUGIN_YUBIKEY_BIN"),
        ("enclave", "SOPSY_AGE_PLUGIN_SE_BIN"),
    ] {
        sopsy()
            .env(env, &fake)
            .args([cmd, "--list", "--help", "-x", "value"])
            .assert()
            .success()
            .stdout(predicate::str::contains("args: --list --help -x value"));
        sopsy()
            .env(env, &fake)
            .args([cmd, "fail"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("see the plugin's output above"));
    }
}
