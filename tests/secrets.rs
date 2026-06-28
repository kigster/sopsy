//! Integration tests for `sopsy secrets {encrypt,decrypt}` and
//! `sopsy list-supported-types`, against **real** `sops` + `age`.
//!
//! Each test builds a temp dir with a real age key and a `.sops.yaml` whose rule
//! covers `\.encrypted$`, then drives the compiled binary. The child process
//! gets its own cwd and `SOPS_AGE_KEY_FILE`, so nothing mutates global state and
//! the tests run in parallel (no `#[serial]`).

use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use assert_fs::TempDir;
use predicates::prelude::*;

/// Generate a real age keypair in `dir`, returning `(public_key, key_file)`.
fn age_key(dir: &Path) -> (String, PathBuf) {
    let key_file = dir.join("age.key");
    let out = StdCommand::new("age-keygen")
        .arg("-o")
        .arg(&key_file)
        .output()
        .expect("age-keygen should be installed");
    assert!(out.status.success(), "age-keygen failed");
    let public_key = String::from_utf8_lossy(&out.stderr)
        .lines()
        .find_map(|l| l.split("Public key:").nth(1))
        .map(|s| s.trim().to_string())
        .expect("age-keygen should print the public key");
    (public_key, key_file)
}

/// Write a `.sops.yaml` whose single rule encrypts any `*.encrypted` to `key`.
fn write_sops_yaml(dir: &Path, key: &str) {
    std::fs::write(
        dir.join(".sops.yaml"),
        format!("creation_rules:\n  - path_regex: \\.encrypted$\n    age: {key}\n"),
    )
    .unwrap();
}

/// A `sopsy` command rooted in `dir` (child cwd, so it finds `.sops.yaml`).
fn sopsy(dir: &Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::cargo_bin("sopsy").expect("binary builds");
    cmd.current_dir(dir);
    cmd
}

#[test]
fn encrypt_to_file_then_decrypt_dotenv_roundtrip() {
    let dir = TempDir::new().unwrap();
    let (public_key, key_file) = age_key(dir.path());
    write_sops_yaml(dir.path(), &public_key);
    let plain = "PASSWORD=hunter2\nAPI_KEY=abc123\n"; // pragma: allowlist secret
    std::fs::write(dir.path().join(".env"), plain).unwrap();

    sopsy(dir.path())
        .args(["secrets", "encrypt", ".env", "-o", ".env.encrypted"])
        .assert()
        .success();

    let enc = std::fs::read_to_string(dir.path().join(".env.encrypted")).unwrap();
    assert!(enc.contains("ENC["), "values should be encrypted");
    assert!(enc.contains("PASSWORD"), "dotenv keys stay visible");
    assert!(!enc.contains("hunter2"), "the value must not be plaintext");

    let out = sopsy(dir.path())
        .env("SOPS_AGE_KEY_FILE", &key_file)
        .args(["secrets", "decrypt", ".env.encrypted"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), plain);
}

#[test]
fn encrypt_json_to_stdout_then_decrypt() {
    let dir = TempDir::new().unwrap();
    let (public_key, key_file) = age_key(dir.path());
    write_sops_yaml(dir.path(), &public_key);
    std::fs::write(
        dir.path().join("data.json"),
        "{\n  \"token\": \"s3cr3t\"\n}\n",
    )
    .unwrap(); // pragma: allowlist secret

    // Encrypt to stdout (default), then materialize the artifact.
    let enc = sopsy(dir.path())
        .args(["secrets", "encrypt", "data.json"])
        .output()
        .unwrap();
    assert!(
        enc.status.success(),
        "{}",
        String::from_utf8_lossy(&enc.stderr)
    );
    let ciphertext = String::from_utf8_lossy(&enc.stdout);
    assert!(ciphertext.contains("ENC["));
    assert!(ciphertext.contains("token"), "json keys stay visible");
    std::fs::write(
        dir.path().join("data.json.encrypted"),
        ciphertext.as_bytes(),
    )
    .unwrap();

    let dec = sopsy(dir.path())
        .env("SOPS_AGE_KEY_FILE", &key_file)
        .args(["secrets", "decrypt", "data.json.encrypted"])
        .output()
        .unwrap();
    assert!(
        dec.status.success(),
        "{}",
        String::from_utf8_lossy(&dec.stderr)
    );
    assert!(String::from_utf8_lossy(&dec.stdout).contains("\"token\": \"s3cr3t\"")); // pragma: allowlist secret
}

#[test]
fn encrypt_ini_roundtrip() {
    let dir = TempDir::new().unwrap();
    let (public_key, key_file) = age_key(dir.path());
    write_sops_yaml(dir.path(), &public_key);
    std::fs::write(dir.path().join("app.ini"), "[db]\npassword = s3cr3t\n").unwrap(); // pragma: allowlist secret

    sopsy(dir.path())
        .args(["secrets", "encrypt", "app.ini", "-o", "app.ini.encrypted"])
        .assert()
        .success();
    let enc = std::fs::read_to_string(dir.path().join("app.ini.encrypted")).unwrap();
    assert!(
        enc.contains("ENC[") && enc.contains("[db]"),
        "ini structure preserved"
    );

    let dec = sopsy(dir.path())
        .env("SOPS_AGE_KEY_FILE", &key_file)
        .args(["secrets", "decrypt", "app.ini.encrypted"])
        .output()
        .unwrap();
    assert!(
        dec.status.success(),
        "{}",
        String::from_utf8_lossy(&dec.stderr)
    );
    assert!(String::from_utf8_lossy(&dec.stdout).contains("password = s3cr3t")); // pragma: allowlist secret
}

#[test]
fn encrypt_rejects_output_not_ending_in_encrypted() {
    let dir = TempDir::new().unwrap();
    let (public_key, _key_file) = age_key(dir.path());
    write_sops_yaml(dir.path(), &public_key);
    std::fs::write(dir.path().join(".env"), "A=b\n").unwrap();

    sopsy(dir.path())
        .args(["secrets", "encrypt", ".env", "-o", "out.txt"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(".encrypted"));
}

#[test]
fn list_supported_types_lists_all_formats() {
    let dir = TempDir::new().unwrap();
    sopsy(dir.path())
        .arg("list-supported-types")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("dotenv")
                .and(predicate::str::contains("yaml"))
                .and(predicate::str::contains("json"))
                .and(predicate::str::contains("ini"))
                .and(predicate::str::contains("binary")),
        );
}
