//! Integration tests for `sopsy recipient {add,remove,list}` against **real**
//! `sops`, `age`, and `git`.
//!
//! Each test builds a real temporary git repository with two real age
//! keypairs, a `.sops.yaml` whose creation rule encrypts `\.env\.encrypted$`
//! files to key A, a matching `.sopsy.yml`, and a real encrypted dotenv
//! (`FOO=bar`). The commands are driven in-process so they observe the test's
//! current directory and environment.
//!
//! `sops` resolves `.sops.yaml` by walking up from the current working
//! directory and reads age secret keys from `SOPS_AGE_KEY_FILE`; both are
//! process-global, so every test is `#[serial]`.

use std::path::{Path, PathBuf};
use std::process::Command;

use assert_fs::TempDir;
use serial_test::serial;
use sopsy::cli::{RecipientAddArgs, RecipientCommand, RecipientRemoveArgs};
use sopsy::commands::recipient;
use sopsy::config::Config;
use sopsy::sops::{self, FileType};
use sopsy::ui::Ui;

/// A non-interactive, color-free UI for driving commands in tests.
fn test_ui() -> Ui {
    Ui::new(false, false, false)
}

/// Generate an age keypair into `dir/<file>`, returning `(public_key, path)`.
fn generate_age_key(dir: &Path, file: &str) -> (String, PathBuf) {
    let key_file = dir.join(file);
    let output = Command::new("age-keygen")
        .arg("-o")
        .arg(&key_file)
        .output()
        .expect("age-keygen should be installed");
    assert!(
        output.status.success(),
        "age-keygen failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let public_key = stderr
        .lines()
        .find_map(|line| line.split("Public key:").nth(1))
        .map(|s| s.trim().to_string())
        .expect("age-keygen should print the public key");
    (public_key, key_file)
}

/// Initialize an empty git repository in `dir`.
fn git_init(dir: &Path) {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .arg("init")
        .output()
        .expect("git should be installed");
    assert!(
        output.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Write a `.sops.yaml` with a single creation rule encrypting
/// `\.env\.encrypted$` to `public_key` (as a YAML list).
fn write_sops_yaml(dir: &Path, public_key: &str) {
    let config = format!(
        "creation_rules:\n  - path_regex: \\.env\\.encrypted$\n    age:\n      - {public_key}\n"
    );
    std::fs::write(dir.join(".sops.yaml"), config).unwrap();
}

/// Write a `.sopsy.yml` listing a single `original` recipient owning `public_key`.
fn write_sopsy_yml(dir: &Path, public_key: &str) {
    let config = format!(
        "recipients:\n  - name: original\n    public_key: {public_key}\n    break_glass: false\n"
    );
    std::fs::write(dir.join(".sopsy.yml"), config).unwrap();
}

/// Set or clear `SOPS_AGE_KEY_FILE`.
///
/// # Safety
/// Callers must be serialized (`#[serial]`) so no other thread races on env.
fn set_age_key_file(path: Option<&Path>) {
    unsafe {
        match path {
            Some(p) => std::env::set_var("SOPS_AGE_KEY_FILE", p),
            None => std::env::remove_var("SOPS_AGE_KEY_FILE"),
        }
    }
}

/// Build the full real-file fixture and return `(repo, key_a, key_b)`.
///
/// The current directory is changed to the repo root (required so `sops` finds
/// `.sops.yaml`); callers restore it via [`restore_cwd`].
fn setup_repo(dir: &Path) -> (PathBuf, KeyPair, KeyPair) {
    let (a_pub, a_file) = generate_age_key(dir, "keyA.txt");
    let (b_pub, b_file) = generate_age_key(dir, "keyB.txt");

    git_init(dir);
    write_sops_yaml(dir, &a_pub);
    write_sopsy_yml(dir, &a_pub);

    std::env::set_current_dir(dir).unwrap();

    // Encrypt FOO=bar to key A (encryption needs no secret key, only `.sops.yaml`).
    let encrypted = dir.join(".env.encrypted");
    std::fs::write(&encrypted, "FOO=bar\n").unwrap();
    sops::encrypt_in_place(&encrypted, FileType::Dotenv).unwrap();

    (
        dir.to_path_buf(),
        KeyPair {
            public: a_pub,
            file: a_file,
        },
        KeyPair {
            public: b_pub,
            file: b_file,
        },
    )
}

struct KeyPair {
    public: String,
    file: PathBuf,
}

/// Restore the process working directory to `original`.
fn restore_cwd(original: &Path) {
    std::env::set_current_dir(original).unwrap();
}

fn add_command(
    name: &str,
    public_key: &str,
    break_glass: bool,
    no_updatekeys: bool,
) -> RecipientCommand {
    RecipientCommand::Add(RecipientAddArgs {
        name_pos: None,
        name: Some(name.to_string()),
        public_key: Some(public_key.to_string()),
        break_glass,
        no_updatekeys,
    })
}

fn remove_command(name: &str, no_updatekeys: bool) -> RecipientCommand {
    RecipientCommand::Remove(RecipientRemoveArgs {
        name_pos: None,
        name: Some(name.to_string()),
        no_updatekeys,
    })
}

#[test]
#[serial]
fn add_registers_recipient_and_rewraps_secrets() {
    let original_cwd = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();
    let (repo, key_a, key_b) = setup_repo(dir.path());

    // `updatekeys` must be able to decrypt the existing file with key A.
    set_age_key_file(Some(&key_a.file));

    recipient::run(
        &test_ui(),
        &add_command("second", &key_b.public, false, false),
    )
    .expect("recipient add should succeed");

    // `.sopsy.yml` records the new recipient.
    let config = Config::load_from_dir(&repo).unwrap();
    assert_eq!(
        config.recipient("second").map(|r| r.public_key.as_str()),
        Some(key_b.public.as_str()),
        "`.sopsy.yml` should list `second` with key B"
    );

    // `.sops.yaml` lists key B.
    let sops_yaml = std::fs::read_to_string(repo.join(".sops.yaml")).unwrap();
    assert!(
        sops_yaml.contains(&key_b.public),
        "`.sops.yaml` should list key B; got:\n{sops_yaml}"
    );

    // After the implicit `updatekeys`, the secret decrypts with key B...
    let encrypted = repo.join(".env.encrypted");
    set_age_key_file(Some(&key_b.file));
    let with_b = sops::decrypt(&encrypted, FileType::Dotenv).unwrap();
    assert!(
        with_b.contains("FOO=bar"),
        "key B should decrypt; got {with_b}"
    );

    // ...and still decrypts with key A.
    set_age_key_file(Some(&key_a.file));
    let with_a = sops::decrypt(&encrypted, FileType::Dotenv).unwrap();
    assert!(
        with_a.contains("FOO=bar"),
        "key A should still decrypt; got {with_a}"
    );

    set_age_key_file(None);
    restore_cwd(&original_cwd);
}

#[test]
#[serial]
fn remove_revokes_recipient_and_rewraps_secrets() {
    let original_cwd = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();
    let (repo, key_a, key_b) = setup_repo(dir.path());

    set_age_key_file(Some(&key_a.file));
    recipient::run(
        &test_ui(),
        &add_command("second", &key_b.public, false, false),
    )
    .expect("recipient add should succeed");

    // Removing only needs an existing key (A) to re-wrap the file.
    set_age_key_file(Some(&key_a.file));
    recipient::run(&test_ui(), &remove_command("second", false))
        .expect("recipient remove should succeed");

    // Key B is gone from both files.
    let config = Config::load_from_dir(&repo).unwrap();
    assert!(
        config.recipient("second").is_none(),
        "`second` should be removed"
    );
    let sops_yaml = std::fs::read_to_string(repo.join(".sops.yaml")).unwrap();
    assert!(
        !sops_yaml.contains(&key_b.public),
        "`.sops.yaml` should no longer list key B; got:\n{sops_yaml}"
    );

    // Key B can no longer decrypt; key A still can.
    let encrypted = repo.join(".env.encrypted");
    set_age_key_file(Some(&key_b.file));
    assert!(
        sops::decrypt(&encrypted, FileType::Dotenv).is_err(),
        "key B must no longer decrypt the secret"
    );
    set_age_key_file(Some(&key_a.file));
    let with_a = sops::decrypt(&encrypted, FileType::Dotenv).unwrap();
    assert!(
        with_a.contains("FOO=bar"),
        "key A should still decrypt; got {with_a}"
    );

    set_age_key_file(None);
    restore_cwd(&original_cwd);
}

#[test]
#[serial]
fn list_prints_recipient_names() {
    let original_cwd = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();
    let (repo, key_a, key_b) = setup_repo(dir.path());

    set_age_key_file(Some(&key_a.file));
    recipient::run(
        &test_ui(),
        &add_command("second", &key_b.public, false, false),
    )
    .expect("recipient add should succeed");
    set_age_key_file(None);
    restore_cwd(&original_cwd);

    // Drive `list` as the real binary so we can capture stdout.
    let output = assert_cmd::Command::cargo_bin("sopsy")
        .unwrap()
        .args(["recipient", "list"])
        .current_dir(&repo)
        .output()
        .unwrap();
    assert!(output.status.success(), "recipient list should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("original"),
        "list should show `original`; got:\n{stdout}"
    );
    assert!(
        stdout.contains("second"),
        "list should show `second`; got:\n{stdout}"
    );
}

#[test]
#[serial]
fn no_updatekeys_skips_reencryption() {
    let original_cwd = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();

    // A minimal repo; no real encryption needed since `sops` is faked here.
    let (a_pub, _a_file) = generate_age_key(dir.path(), "keyA.txt");
    git_init(dir.path());
    write_sops_yaml(dir.path(), &a_pub);
    write_sopsy_yml(dir.path(), &a_pub);
    // A stand-in encrypted file so the re-key walk has something to act on; the
    // fake `sops` below never inspects it.
    std::fs::write(dir.path().join(".env.encrypted"), "FOO=ENC[fake]\n").unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    // Fake `sops` that records each invocation by appending to a marker file.
    let marker = dir.path().join("sops-invoked.log");
    let fake = dir.path().join("fake-sops.sh");
    std::fs::write(
        &fake,
        format!("#!/bin/sh\necho \"$@\" >> {:?}\n", marker.to_string_lossy()),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    unsafe {
        std::env::set_var("SOPSY_SOPS_BIN", &fake);
    }

    let fake_key = "age1fakekeyfortestingxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

    // With `--no-updatekeys`, `sops` is never invoked...
    recipient::run(&test_ui(), &add_command("second", fake_key, false, true))
        .expect("recipient add (--no-updatekeys) should succeed");
    assert!(
        !marker.exists(),
        "`sops updatekeys` must not run with --no-updatekeys"
    );

    // ...but `.sopsy.yml` and `.sops.yaml` are still updated.
    let config = Config::load_from_dir(dir.path()).unwrap();
    assert!(
        config.recipient("second").is_some(),
        "`second` should be recorded"
    );
    let sops_yaml = std::fs::read_to_string(dir.path().join(".sops.yaml")).unwrap();
    assert!(
        sops_yaml.contains(fake_key),
        "`.sops.yaml` should list the new key"
    );

    // Without the flag, the (fake) `sops updatekeys` *is* invoked.
    recipient::run(
        &test_ui(),
        &add_command(
            "third",
            "age1anotherfakexxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            false,
            false,
        ),
    )
    .expect("recipient add should succeed");
    assert!(
        marker.exists(),
        "`sops updatekeys` should run without --no-updatekeys"
    );

    unsafe {
        std::env::remove_var("SOPSY_SOPS_BIN");
    }
    restore_cwd(&original_cwd);
}
