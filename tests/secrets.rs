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
    cmd.env("SOPSY_BREW_BIN", "/nonexistent/sopsy-test-brew"); // never run a real `brew` from tests
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

/// A temp repo with a real age key, its `.sops.yaml`, and `SOPS_AGE_KEY_FILE`
/// already set on every command [`WriteRepo::sopsy`] returns.
struct WriteRepo {
    dir: TempDir,
    key_file: PathBuf,
}

impl WriteRepo {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let (public_key, key_file) = age_key(dir.path());
        write_sops_yaml(dir.path(), &public_key);
        Self { dir, key_file }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn sopsy(&self) -> assert_cmd::Command {
        let mut cmd = sopsy(self.dir.path());
        cmd.env("SOPS_AGE_KEY_FILE", &self.key_file);
        cmd.env_remove("SOPSY_ASSUME_YES");
        cmd
    }

    /// Every `.bak` file in the repo.
    fn backups(&self) -> Vec<PathBuf> {
        std::fs::read_dir(self.dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.to_string_lossy().ends_with(".bak"))
            .collect()
    }
}

#[test]
fn write_flag_round_trips_dotenv_yaml_and_json() {
    let cases = [
        (".env", "PASSWORD=hunter2\n"),      // pragma: allowlist secret
        ("app.yaml", "password: hunter2\n"), // pragma: allowlist secret
        ("app.json", "{\n\t\"password\": \"hunter2\"\n}"), // pragma: allowlist secret
    ];
    for (name, plain) in cases {
        let repo = WriteRepo::new();
        std::fs::write(repo.path(name), plain).unwrap();
        repo.sopsy()
            .args(["encrypt", name, "-w"])
            .assert()
            .success();
        let encrypted = format!("{name}.encrypted");
        let ciphertext = std::fs::read_to_string(repo.path(&encrypted)).unwrap();
        assert!(!ciphertext.contains("hunter2"), "{name} must be encrypted");

        std::fs::remove_file(repo.path(name)).unwrap();
        repo.sopsy()
            .args(["decrypt", &encrypted, "--write"])
            .assert()
            .success();
        let restored = std::fs::read_to_string(repo.path(name)).unwrap();
        assert!(restored.contains("hunter2"), "{name}: {restored}");
        if name == ".env" {
            assert_eq!(restored, plain);
        }
    }
}

#[test]
fn secrets_alias_write_flag_behaves_the_same() {
    let repo = WriteRepo::new();
    std::fs::write(repo.path(".env"), "A=1\n").unwrap();
    repo.sopsy()
        .args(["secrets", "encrypt", ".env", "-w"])
        .assert()
        .success();
    std::fs::remove_file(repo.path(".env")).unwrap();
    repo.sopsy()
        .args(["secrets", "decrypt", ".env.encrypted", "-w"])
        .assert()
        .success();
    assert_eq!(std::fs::read_to_string(repo.path(".env")).unwrap(), "A=1\n");
}

#[test]
fn write_flag_rejects_the_wrong_suffix() {
    let repo = WriteRepo::new();
    std::fs::write(repo.path("x.encrypted"), "A=1\n").unwrap();
    std::fs::write(repo.path(".env"), "A=1\n").unwrap();
    repo.sopsy()
        .args(["encrypt", "x.encrypted", "-w"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already ends in"));
    repo.sopsy()
        .args(["decrypt", ".env", "-w"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("use `-o`"));
}

#[test]
fn existing_target_without_a_flag_is_an_error_and_left_untouched() {
    let repo = WriteRepo::new();
    std::fs::write(repo.path(".env"), "A=1\n").unwrap();
    repo.sopsy()
        .args(["encrypt", ".env", "-w"])
        .assert()
        .success();
    std::fs::write(repo.path(".env"), "LOCAL=edit\n").unwrap();

    repo.sopsy()
        .args(["decrypt", ".env.encrypted", "-w"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("pass `--overwrite`"));
    assert_eq!(
        std::fs::read_to_string(repo.path(".env")).unwrap(),
        "LOCAL=edit\n"
    );

    // `-o` follows the same rules.
    repo.sopsy()
        .args(["decrypt", ".env.encrypted", "-o", ".env"])
        .assert()
        .failure();
    let before = std::fs::read(repo.path(".env.encrypted")).unwrap();
    repo.sopsy()
        .args(["encrypt", ".env", "-w"])
        .assert()
        .failure();
    assert_eq!(std::fs::read(repo.path(".env.encrypted")).unwrap(), before);
    assert!(repo.backups().is_empty());
}

#[test]
fn overwrite_on_decrypt_backs_up_the_old_plaintext() {
    let repo = WriteRepo::new();
    std::fs::write(repo.path(".env"), "A=1\n").unwrap();
    repo.sopsy()
        .args(["encrypt", ".env", "-w"])
        .assert()
        .success();
    std::fs::write(repo.path(".env"), "LOCAL=edit\n").unwrap();

    repo.sopsy()
        .args(["decrypt", ".env.encrypted", "-w", "-O"])
        .assert()
        .success();
    assert_eq!(std::fs::read_to_string(repo.path(".env")).unwrap(), "A=1\n");
    let backups = repo.backups();
    assert_eq!(backups.len(), 1, "{backups:?}");
    let name = backups[0]
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert!(
        name.starts_with(".env.") && name.ends_with(".bak"),
        "{name}"
    );
    assert_eq!(
        std::fs::read_to_string(&backups[0]).unwrap(),
        "LOCAL=edit\n"
    );
}

#[test]
fn overwrite_on_encrypt_replaces_without_a_backup() {
    let repo = WriteRepo::new();
    std::fs::write(repo.path(".env"), "A=1\n").unwrap();
    repo.sopsy()
        .args(["encrypt", ".env", "-w"])
        .assert()
        .success();
    std::fs::write(repo.path(".env"), "A=2\n").unwrap();
    repo.sopsy()
        .args(["encrypt", ".env", "-w", "--overwrite"])
        .assert()
        .success();
    assert!(repo.backups().is_empty());
    repo.sopsy()
        .args(["decrypt", ".env.encrypted"])
        .assert()
        .success()
        .stdout("A=2\n");
}

#[test]
fn yes_flag_and_assume_yes_env_overwrite_with_a_backup() {
    let repo = WriteRepo::new();
    std::fs::write(repo.path(".env"), "A=1\n").unwrap();
    repo.sopsy()
        .args(["encrypt", ".env", "-w"])
        .assert()
        .success();

    std::fs::write(repo.path(".env"), "LOCAL=1\n").unwrap();
    repo.sopsy()
        .args(["--yes", "decrypt", ".env.encrypted", "-w"])
        .assert()
        .success();
    assert_eq!(std::fs::read_to_string(repo.path(".env")).unwrap(), "A=1\n");
    assert_eq!(repo.backups().len(), 1);

    std::fs::write(repo.path(".env"), "LOCAL=2\n").unwrap();
    // Backups are stamped to the second; wait so the second one gets a new name.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    repo.sopsy()
        .env("SOPSY_ASSUME_YES", "1")
        .args(["decrypt", ".env.encrypted", "-w"])
        .assert()
        .success();
    assert_eq!(std::fs::read_to_string(repo.path(".env")).unwrap(), "A=1\n");
    assert_eq!(repo.backups().len(), 2);
}

#[test]
fn failed_decrypt_leaves_an_existing_target_unchanged() {
    let repo = WriteRepo::new();
    std::fs::write(repo.path(".env.encrypted"), "not sops at all\n").unwrap();
    std::fs::write(repo.path(".env"), "KEEP=me\n").unwrap();
    repo.sopsy()
        .args(["decrypt", ".env.encrypted", "-w", "-O"])
        .assert()
        .failure();
    assert_eq!(
        std::fs::read_to_string(repo.path(".env")).unwrap(),
        "KEEP=me\n"
    );
    assert!(repo.backups().is_empty());
}
