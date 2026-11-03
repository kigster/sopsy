//! Integration tests for `sopsy completion`.

use assert_cmd::Command;
use predicates::prelude::*;

fn sopsy() -> Command {
    let mut cmd = Command::cargo_bin("sopsy").unwrap();
    cmd.env("SOPSY_BREW_BIN", "/nonexistent/sopsy-test-brew"); // never run a real `brew` from tests
    cmd
}

#[test]
fn bash_completion_is_emitted() {
    sopsy()
        .args(["completion", "bash"])
        .assert()
        .success()
        // The bash generator defines a `_sopsy` completion function.
        .stdout(predicate::str::contains("_sopsy"));
}

#[test]
fn zsh_completion_is_emitted() {
    sopsy()
        .args(["completion", "zsh"])
        .assert()
        .success()
        // zsh completion scripts begin with a `#compdef` directive.
        .stdout(predicate::str::contains("#compdef sopsy"));
}

#[test]
fn fish_completion_is_emitted() {
    sopsy()
        .args(["completion", "fish"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sopsy"));
}

#[test]
fn powershell_completion_is_emitted() {
    sopsy()
        .args(["completion", "powershell"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sopsy"));
}

#[test]
fn unknown_shell_is_rejected() {
    sopsy().args(["completion", "tcsh"]).assert().failure();
}

#[test]
fn requires_a_shell_argument() {
    // `completion` with no shell is a usage error.
    sopsy().arg("completion").assert().failure();
}
