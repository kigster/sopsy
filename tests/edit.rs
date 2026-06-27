//! Integration tests for `sopsy edit` against **real** `sops` + `age`.
//!
//! The headline test performs a true end-to-end round trip: it generates a real
//! age key, writes a `.sops.yaml` pointing at that recipient, creates a real
//! encrypted dotenv file (`FOO=bar`), then runs `sopsy edit` with `EDITOR` set
//! to a tiny shell script that appends `BAZ=qux` to the file sops hands it.
//! After the binary returns, the file is decrypted and **both** keys must be
//! present, proving the edit was persisted and re-encrypted.
//!
//! Decryption needs the age secret key via `SOPS_AGE_KEY_FILE`, and `sops`
//! discovers `.sops.yaml` by walking up from the current working directory.
//! Because both are process-wide, env-mutating tests are `#[serial]`.

use std::path::Path;
use std::process::Command as StdCommand;

use assert_cmd::Command as AssertCommand;
use assert_fs::TempDir;
use predicates::prelude::*;
use serial_test::serial;

/// Generate an age keypair, returning `(public_key, key_file_path)`.
fn generate_age_key(dir: &Path) -> (String, std::path::PathBuf) {
    let key_file = dir.join("age-key.txt");
    let output = StdCommand::new("age-keygen")
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

/// Write a `.sops.yaml` whose single creation rule encrypts everything to
/// `public_key`.
fn write_sops_config(dir: &Path, public_key: &str) {
    let config = format!("creation_rules:\n  - path_regex: .*\n    age: {public_key}\n");
    std::fs::write(dir.join(".sops.yaml"), config).unwrap();
}

/// Write an executable shell script at `path` that appends `line` to the file
/// passed as its first argument (mimicking an interactive editor save).
fn write_appender_editor(path: &Path, line: &str) {
    let script = format!("#!/bin/sh\nprintf '%s\\n' '{line}' >> \"$1\"\n");
    std::fs::write(path, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }
}

/// Build a `Command` for the compiled `sopsy` binary.
fn sopsy() -> AssertCommand {
    AssertCommand::cargo_bin("sopsy").expect("binary `sopsy` should build")
}

#[test]
#[serial]
fn edit_roundtrips_an_encrypted_dotenv() {
    let dir = TempDir::new().unwrap();
    let (public_key, key_file) = generate_age_key(dir.path());
    write_sops_config(dir.path(), &public_key);

    // Create a real encrypted dotenv file containing `FOO=bar`.
    let encrypted = dir.path().join(".env.encrypted");
    std::fs::write(&encrypted, "FOO=bar\n").unwrap();
    let enc = StdCommand::new("sops")
        .args([
            "-e",
            "--input-type",
            "dotenv",
            "--output-type",
            "dotenv",
            "-i",
        ])
        .arg(&encrypted)
        .current_dir(dir.path())
        .env("SOPS_AGE_KEY_FILE", &key_file)
        .output()
        .expect("sops should be installed");
    assert!(
        enc.status.success(),
        "sops encrypt failed: {}",
        String::from_utf8_lossy(&enc.stderr)
    );
    // Sanity: it really is encrypted on disk now.
    let on_disk = std::fs::read_to_string(&encrypted).unwrap();
    assert!(on_disk.contains("ENC["), "fixture was not encrypted");

    // An "editor" that appends `BAZ=qux` to whatever file sops opens.
    let editor = dir.path().join("appender.sh");
    write_appender_editor(&editor, "BAZ=qux");

    // Run `sopsy edit .env.encrypted` with EDITOR pointing at our script.
    sopsy()
        .arg("--non-interactive")
        .arg("edit")
        .arg(".env.encrypted")
        .current_dir(dir.path())
        .env("EDITOR", &editor)
        .env("SOPS_AGE_KEY_FILE", &key_file)
        .assert()
        .success();

    // Decrypt and confirm BOTH the original and the appended keys survived,
    // proving the edit was persisted and re-encrypted.
    let dec = StdCommand::new("sops")
        .args(["-d", "--input-type", "dotenv", "--output-type", "dotenv"])
        .arg(&encrypted)
        .current_dir(dir.path())
        .env("SOPS_AGE_KEY_FILE", &key_file)
        .output()
        .unwrap();
    assert!(
        dec.status.success(),
        "sops decrypt failed: {}",
        String::from_utf8_lossy(&dec.stderr)
    );
    let plaintext = String::from_utf8_lossy(&dec.stdout);
    assert!(
        plaintext.contains("FOO=bar"),
        "original value missing after edit; got:\n{plaintext}"
    );
    assert!(
        plaintext.contains("BAZ=qux"),
        "appended value missing after edit; got:\n{plaintext}"
    );
}

#[test]
fn edit_missing_file_fails_with_friendly_error() {
    let dir = TempDir::new().unwrap();
    sopsy()
        .arg("--non-interactive")
        .arg("edit")
        .arg("does-not-exist.env")
        .current_dir(dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("does-not-exist.env"))
        .stderr(predicate::str::contains("file not found"));
}

#[test]
#[serial]
fn edit_forwards_editor_and_sops_args_to_fake_sops() {
    let dir = TempDir::new().unwrap();

    // A fake `sops` that records its argv and the EDITOR it received, so we can
    // assert sopsy wired everything up correctly without needing real crypto.
    let log = dir.path().join("sops-invocation.log");
    let fake_sops = dir.path().join("fake-sops.sh");
    let script = format!(
        "#!/bin/sh\n{{ echo \"EDITOR=$EDITOR\"; echo \"ARGS=$*\"; }} > '{}'\n",
        log.display()
    );
    std::fs::write(&fake_sops, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&fake_sops).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_sops, perms).unwrap();
    }

    // The target must exist (sopsy checks existence before invoking sops).
    let target = dir.path().join("secrets.env");
    std::fs::write(&target, "FOO=bar\n").unwrap();

    sopsy()
        .arg("--non-interactive")
        .arg("edit")
        .arg("secrets.env")
        .arg("--editor")
        .arg("my-editor")
        .arg("--")
        .arg("--some-sops-flag")
        .current_dir(dir.path())
        .env("SOPSY_SOPS_BIN", &fake_sops)
        .assert()
        .success();

    let recorded = std::fs::read_to_string(&log).expect("fake sops should have logged");
    assert!(
        recorded.contains("EDITOR=my-editor"),
        "--editor not forwarded as EDITOR; got:\n{recorded}"
    );
    assert!(
        recorded.contains("--some-sops-flag"),
        "trailing sops args not forwarded; got:\n{recorded}"
    );
    assert!(
        recorded.contains("secrets.env"),
        "target file not passed to sops; got:\n{recorded}"
    );
}
