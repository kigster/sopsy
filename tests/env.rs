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
    fixture_with("FOO=bar\n")
}

/// Like [`fixture`], with `.env.encrypted` holding `dotenv`.
fn fixture_with(dotenv: &str) -> TempDir {
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
    std::fs::write(dir.path().join(".env"), dotenv).unwrap();
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
fn run_pristine_says_what_it_dropped() {
    let dir = fixture();
    sopsy(dir.path())
        .env("HOME", "/home/test")
        .args(["run", "--pristine", "--", "env"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "--pristine: starting env with only the 1 decrypted value; dropped PATH, HOME",
        ));
}

/// Every refused variable, set in a real encrypted file: `run` must refuse it
/// by name and never start the command. Reads the same table `run` enforces,
/// so an entry cannot be dropped from the rule without failing here.
#[test]
fn run_refuses_every_blocked_variable_from_the_file() {
    for entry in sopsy::commands::env::BLOCKED_VARIABLES {
        let name = entry.replace('*', "PRELOAD");
        let dir = fixture_with(&format!("FOO=bar\n{name}=/tmp/sopsy-test-planted\n"));
        sopsy(dir.path())
            .args(["run", "--", "sh", "-c", "touch ran"])
            .assert()
            .failure()
            .stderr(predicate::str::contains(format!(
                "the encrypted file sets `{name}`, which changes the code a program loads"
            )));
        assert!(!dir.path().join("ran").exists(), "{name}: the command ran");
    }
}

/// A program planted in the repository is not found through an empty or `.`
/// PATH entry: `run` searches absolute directories only.
#[cfg(unix)]
#[test]
fn run_never_starts_a_program_from_the_current_directory() {
    use std::os::unix::fs::PermissionsExt;
    let dir = fixture();
    let planted = dir.path().join("planted-tool");
    std::fs::write(&planted, "#!/bin/sh\ntouch ran\n").unwrap();
    std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(".::{}", std::env::var("PATH").unwrap());
    sopsy(dir.path())
        .env("PATH", path)
        .args(["run", "--", "planted-tool"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("planted-tool"));
    assert!(!dir.path().join("ran").exists(), "the planted program ran");
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

/// A fake `sops` that reports a recent version and fails everything else, to
/// drive sopsy's handling of sops errors.
fn failing_sops(dir: &Path) -> std::path::PathBuf {
    let fake = dir.join("fake-sops");
    std::fs::write(
        &fake,
        "#!/bin/sh\n[ \"$1\" = --version ] && { echo 'sops 3.13.2'; exit 0; }\n\
         echo 'sops: simulated failure' >&2\nexit 3\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    fake
}

fn git_init(dir: &Path) {
    let ok = StdCommand::new("git")
        .args(["init", "-q"])
        .current_dir(dir)
        .status()
        .unwrap()
        .success();
    assert!(ok);
}

#[test]
fn sops_failures_are_reported_for_every_command() {
    let dir = fixture();
    let fake = failing_sops(dir.path());
    for args in [
        vec!["run", "true"],
        vec!["set", "K", "v"],
        vec!["unset", "FOO"],
        vec!["rotate-data-key", ".env.encrypted"],
    ] {
        sopsy(dir.path())
            .env("SOPSY_SOPS_BIN", &fake)
            .args(&args)
            .assert()
            .failure()
            .stderr(
                predicate::str::contains("simulated failure")
                    .or(predicate::str::contains("not rotated")),
            );
    }
}

#[test]
fn set_reports_the_sops_error_when_sops_never_reads_the_value() {
    // A value larger than a pipe buffer makes the write fail every time
    // against a sops that exits without reading stdin.
    let dir = fixture();
    let fake = failing_sops(dir.path());
    sopsy(dir.path())
        .env("SOPSY_SOPS_BIN", &fake)
        .args(["set", "K"])
        .write_stdin("v".repeat(1 << 20))
        .assert()
        .failure()
        .stderr(predicate::str::contains("simulated failure"))
        .stderr(predicate::str::contains("Broken pipe").not());
}

#[test]
fn run_reports_a_missing_file_and_a_missing_program() {
    let dir = fixture();
    sopsy(dir.path())
        .args(["run", "-f", "nope.encrypted", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("nope.encrypted"));
    sopsy(dir.path())
        .args(["run", "sopsy-test-no-such-program"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("sopsy-test-no-such-program"));
}

#[test]
fn run_keeps_a_literal_backslash_n() {
    let dir = fixture();
    sopsy(dir.path())
        .args(["set", "WIN", r"C:\new\dir"])
        .assert()
        .success();
    assert_eq!(run_echo(dir.path(), "$WIN"), r"C:\new\dir");
}

#[test]
fn set_from_stdin_drops_a_crlf_line_ending() {
    let dir = fixture();
    sopsy(dir.path())
        .args(["set", "TOKEN"])
        .write_stdin("windows\r\n")
        .assert()
        .success();
    assert_eq!(run_echo(dir.path(), "[$TOKEN]"), "[windows]");
}

#[test]
fn rotate_data_key_without_files_uses_the_repository() {
    let dir = fixture();
    git_init(dir.path());
    std::fs::write(dir.path().join(".sopsy.yml"), "recipients: []\n").unwrap();
    let before = std::fs::read_to_string(dir.path().join(".env.encrypted")).unwrap();
    sopsy(dir.path())
        .arg("rotate-data-key")
        .assert()
        .success()
        .stdout(predicate::str::contains("new data key for"));
    let after = std::fs::read_to_string(dir.path().join(".env.encrypted")).unwrap();
    assert_ne!(before, after);
}

#[test]
fn rotate_data_key_with_nothing_to_rotate_says_so() {
    let dir = TempDir::new().unwrap();
    git_init(dir.path());
    std::fs::write(dir.path().join(".sopsy.yml"), "recipients: []\n").unwrap();
    sopsy(dir.path())
        .arg("rotate-data-key")
        .assert()
        .success()
        .stdout(predicate::str::contains("nothing to rotate"));
}

#[test]
fn rotate_data_key_keeps_going_and_names_the_failures() {
    let dir = fixture();
    std::fs::write(dir.path().join("broken.env.encrypted"), "NOT=sops\n").unwrap();
    let before = std::fs::read_to_string(dir.path().join(".env.encrypted")).unwrap();
    sopsy(dir.path())
        .args(["rotate-data-key", "broken.env.encrypted", ".env.encrypted"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("1 of 2 files were not rotated"))
        .stderr(predicate::str::contains("broken.env.encrypted"));
    let after = std::fs::read_to_string(dir.path().join(".env.encrypted")).unwrap();
    assert_ne!(before, after, "the good file is still rotated");
}

#[test]
fn set_reports_an_unreadable_sops_version() {
    let dir = TempDir::new().unwrap();
    let fake = dir.path().join("sops");
    std::fs::write(&fake, "#!/bin/sh\necho 'sops nightly'\n").unwrap();
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
        .stderr(predicate::str::contains("could not read the sops version"));
}
