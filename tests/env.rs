//! Integration tests for `sopsy run`, `set`, `unset` and `rotate-data-key`
//! against real `sops` and `age`, driving the compiled binary.

use std::path::Path;
use std::process::Command as StdCommand;

use assert_cmd::Command;
use assert_fs::TempDir;
use predicates::prelude::*;

/// A temp dir with an age key, a `.sops.yaml` and `.env.encrypted` holding
/// `FOO=bar`.
fn fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("key.txt");
    let out = StdCommand::new("age-keygen")
        .arg("-o")
        .arg(&key)
        .output()
        .expect("age-keygen should be installed");
    let public = String::from_utf8_lossy(&out.stderr)
        .lines()
        .find_map(|l| l.split("Public key:").nth(1).map(|s| s.trim().to_string()))
        .unwrap();
    std::fs::write(
        dir.path().join(".sops.yaml"),
        format!("creation_rules:\n  - path_regex: \\.encrypted$\n    age: {public}\n"),
    )
    .unwrap();
    std::fs::write(dir.path().join(".env"), "FOO=bar\n").unwrap();
    let enc = StdCommand::new("sops")
        .current_dir(dir.path())
        .args([
            "--encrypt",
            "--input-type",
            "dotenv",
            "--output-type",
            "dotenv",
        ])
        .args(["--filename-override", ".env.encrypted", ".env"])
        .output()
        .expect("sops should be installed");
    assert!(
        enc.status.success(),
        "{}",
        String::from_utf8_lossy(&enc.stderr)
    );
    std::fs::write(dir.path().join(".env.encrypted"), enc.stdout).unwrap();
    std::fs::remove_file(dir.path().join(".env")).unwrap();
    dir
}

fn sopsy(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("sopsy").unwrap();
    cmd.current_dir(dir)
        .env("SOPSY_KEYS_FILE", dir.join("key.txt"))
        .env("SOPSY_BREW_BIN", "/nonexistent/sopsy-test-brew")
        .env_remove("SOPS_AGE_KEY")
        .env_remove("SOPS_AGE_KEY_FILE")
        .arg("--non-interactive");
    cmd
}

fn run_echo(dir: &Path, expr: &str) -> String {
    let out = sopsy(dir)
        .args(["run", "sh", "-c", &format!("printf '%s' \"{expr}\"")])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn run_puts_secrets_in_the_environment_and_passes_the_exit_code() {
    let dir = fixture();
    assert_eq!(run_echo(dir.path(), "$FOO"), "bar");
    // The command's own flags are not sopsy's, and its exit code comes back.
    sopsy(dir.path())
        .args(["run", "sh", "-c", "exit 7"])
        .assert()
        .code(7);
}

#[test]
fn run_pristine_passes_only_the_secrets() {
    let dir = fixture();
    sopsy(dir.path())
        .env("SOPSY_TEST_MARKER", "leak")
        .args(["run", "--pristine", "/usr/bin/env"])
        .assert()
        .success()
        .stdout(predicate::str::contains("FOO=bar"))
        .stdout(predicate::str::contains("SOPSY_TEST_MARKER").not());
}

#[test]
fn set_and_unset_change_one_value() {
    let dir = fixture();
    sopsy(dir.path())
        .args(["set", "API_KEY", "sEcReT \"quoted\" value"])
        .assert()
        .success();
    // Without a value and without a terminal, the value comes from stdin.
    sopsy(dir.path())
        .args(["set", "TOKEN"])
        .write_stdin("from-stdin\n")
        .assert()
        .success();
    assert_eq!(
        run_echo(dir.path(), "$FOO|$API_KEY|$TOKEN"),
        "bar|sEcReT \"quoted\" value|from-stdin"
    );

    sopsy(dir.path()).args(["unset", "FOO"]).assert().success();
    assert_eq!(run_echo(dir.path(), "[${FOO-unset}]"), "[unset]");
    let raw = std::fs::read_to_string(dir.path().join(".env.encrypted")).unwrap();
    assert!(!raw.contains("sEcReT"), "values stay encrypted:\n{raw}");
}

#[test]
fn rotate_data_key_reencrypts_and_still_decrypts() {
    let dir = fixture();
    let before = std::fs::read_to_string(dir.path().join(".env.encrypted")).unwrap();
    sopsy(dir.path())
        .args(["rotate-data-key", ".env.encrypted"])
        .assert()
        .success()
        .stdout(predicate::str::contains("new data key for .env.encrypted"));
    let after = std::fs::read_to_string(dir.path().join(".env.encrypted")).unwrap();
    assert_ne!(before, after);
    assert_eq!(run_echo(dir.path(), "$FOO"), "bar");
}

#[test]
fn set_refuses_binary_files() {
    let dir = fixture();
    sopsy(dir.path())
        .args(["set", "K", "v", "--type", "binary"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("binary file"));
}

#[test]
fn set_refuses_a_sops_without_value_stdin() {
    // Older sops would need the secret on the command line; sopsy refuses.
    let dir = TempDir::new().unwrap();
    let fake = dir.path().join("sops");
    std::fs::write(&fake, "#!/bin/sh\necho 'sops 3.9.4'\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::write(dir.path().join(".env.encrypted"), "").unwrap();
    sopsy(dir.path())
        .env("SOPSY_SOPS_BIN", &fake)
        .args(["set", "K", "v"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("needs sops 3.11.0 or newer"))
        .stderr(predicate::str::contains("3.9.4 is installed"));
}
