//! Integration tests for [`sopsy::sops`] against **real** `sops` + `age`.
//!
//! These generate a real age keypair with `age-keygen`, write a `.sops.yaml`
//! pointing at that recipient, then round-trip YAML, JSON, and dotenv (`.env`)
//! secrets through `encrypt_in_place` / `decrypt`. The dotenv case is the
//! primary use case for sopsy and is mandatory.
//!
//! Decryption needs the age secret key, supplied via the `SOPS_AGE_KEY_FILE`
//! environment variable. Because that is process-wide, the round-trip test is
//! marked `#[serial]`.

use std::path::Path;
use std::process::Command;

use assert_fs::TempDir;
use serial_test::serial;
use sopsy::sops::{self, FileType};

/// Generate an age keypair, returning `(public_key, key_file_path)`.
fn generate_age_key(dir: &Path) -> (String, std::path::PathBuf) {
    generate_age_key_named(dir, "age-key.txt")
}

/// Generate an age keypair written to `dir/<file_name>`, returning
/// `(public_key, key_file_path)`.
fn generate_age_key_named(dir: &Path, file_name: &str) -> (String, std::path::PathBuf) {
    let key_file = dir.join(file_name);
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
    // age-keygen prints `Public key: age1...` to stderr when writing to a file.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let public_key = stderr
        .lines()
        .find_map(|line| line.split("Public key:").nth(1))
        .map(|s| s.trim().to_string())
        .expect("age-keygen should print the public key");
    (public_key, key_file)
}

/// Write a `.sops.yaml` in `dir` whose single creation rule encrypts everything
/// to `public_key`.
fn write_sops_config(dir: &Path, public_key: &str) {
    let config = format!("creation_rules:\n  - path_regex: .*\n    age: {public_key}\n");
    std::fs::write(dir.join(".sops.yaml"), config).unwrap();
}

#[test]
fn ensure_available_succeeds_when_sops_present() {
    sops::ensure_available().unwrap();
}

#[test]
#[serial]
fn roundtrips_all_file_types() {
    let dir = TempDir::new().unwrap();
    let (public_key, key_file) = generate_age_key(dir.path());
    write_sops_config(dir.path(), &public_key);

    // sops discovers `.sops.yaml` by walking up from the current working
    // directory (its real-world behavior: sopsy runs inside the repo). Point
    // cwd at the temp repo for the duration of this serialized test.
    let original_cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    // sops reads the age private key from SOPS_AGE_KEY_FILE for decryption.
    // SAFETY: serialized via `#[serial]`; no other test mutates env concurrently.
    unsafe {
        std::env::set_var("SOPS_AGE_KEY_FILE", &key_file);
    }

    let cases: &[(&str, FileType, &str, &[&str])] = &[
        (
            "secrets.yaml",
            FileType::Yaml,
            "password: hunter2\napi_key: abc123\n",
            &["password", "hunter2", "api_key", "abc123"],
        ),
        (
            "secrets.json",
            FileType::Json,
            "{\n  \"password\": \"hunter2\",\n  \"api_key\": \"abc123\"\n}\n",
            &["password", "hunter2", "api_key", "abc123"],
        ),
        (
            ".env",
            FileType::Dotenv,
            "PASSWORD=hunter2\nAPI_KEY=abc123\n", // pragma: allowlist secret
            &["PASSWORD=hunter2", "API_KEY=abc123"],
        ),
    ];

    for (name, file_type, plaintext, expected) in cases {
        // Sanity: the helper infers the same type from the filename.
        assert_eq!(
            FileType::from_path(Path::new(name)),
            *file_type,
            "from_path mismatch for {name}"
        );

        let path = dir.path().join(name);
        std::fs::write(&path, plaintext).unwrap();

        sops::encrypt_in_place(&path, *file_type).unwrap();

        // Ciphertext on disk must no longer be the plaintext and must carry the
        // sops metadata / encrypted markers.
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_ne!(&on_disk, plaintext, "{name} was not encrypted");
        assert!(on_disk.contains("ENC["), "{name} missing ENC[ markers");
        assert!(
            on_disk.contains("sops"),
            "{name} missing sops metadata block"
        );

        // Round-trip back to plaintext.
        let decrypted = sops::decrypt(&path, *file_type).unwrap();
        for needle in *expected {
            assert!(
                decrypted.contains(needle),
                "decrypted {name} missing `{needle}`; got:\n{decrypted}"
            );
        }
    }

    // dotenv is the headline use case — assert an exact round-trip for it.
    let env_path = dir.path().join(".env");
    let decrypted_env = sops::decrypt(&env_path, FileType::Dotenv).unwrap();
    assert_eq!(decrypted_env, "PASSWORD=hunter2\nAPI_KEY=abc123\n"); // pragma: allowlist secret

    // SAFETY: see above; restore a clean environment for any later test.
    unsafe {
        std::env::remove_var("SOPS_AGE_KEY_FILE");
    }
    std::env::set_current_dir(original_cwd).unwrap();
}

/// Write an executable fake `sops` script to `dir` and return its path.
fn write_fake_sops(dir: &Path, body: &str) -> std::path::PathBuf {
    let script = dir.join("fake-sops");
    std::fs::write(&script, format!("#!/bin/sh\n{body}")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
    }
    script
}

#[test]
#[serial]
fn ensure_available_fails_for_missing_binary() {
    // SAFETY: serialized via `#[serial]`.
    unsafe {
        std::env::set_var(sops::SOPS_BIN_ENV, "/nonexistent/sops-does-not-exist");
    }
    let err = sops::ensure_available().unwrap_err();
    assert!(matches!(err, sopsy::error::Error::ToolNotFound(_)));
    // SAFETY: see above.
    unsafe {
        std::env::remove_var(sops::SOPS_BIN_ENV);
    }
}

#[test]
#[serial]
fn encrypt_maps_nonzero_exit_to_process_failed() {
    let dir = TempDir::new().unwrap();
    let fake = write_fake_sops(dir.path(), "echo 'encrypt boom' 1>&2\nexit 7\n");
    // SAFETY: serialized via `#[serial]`.
    unsafe {
        std::env::set_var(sops::SOPS_BIN_ENV, &fake);
    }

    let file = dir.path().join("secrets.yaml");
    std::fs::write(&file, "k: v\n").unwrap();
    let err = sops::encrypt_in_place(&file, FileType::Yaml).unwrap_err();
    match err {
        sopsy::error::Error::ProcessFailed {
            tool,
            code,
            message,
        } => {
            assert_eq!(tool, "sops");
            assert_eq!(code, 7);
            assert!(message.contains("encrypt boom"), "got: {message}");
        }
        other => panic!("expected ProcessFailed, got {other:?}"),
    }

    // SAFETY: see above.
    unsafe {
        std::env::remove_var(sops::SOPS_BIN_ENV);
    }
}

#[test]
#[serial]
fn decrypt_maps_nonzero_exit_to_process_failed() {
    let dir = TempDir::new().unwrap();
    let fake = write_fake_sops(dir.path(), "echo 'decrypt nope' 1>&2\nexit 5\n");
    // SAFETY: serialized via `#[serial]`.
    unsafe {
        std::env::set_var(sops::SOPS_BIN_ENV, &fake);
    }

    let file = dir.path().join("secrets.json");
    std::fs::write(&file, "{}").unwrap();
    let err = sops::decrypt(&file, FileType::Json).unwrap_err();
    match err {
        sopsy::error::Error::ProcessFailed { code, message, .. } => {
            assert_eq!(code, 5);
            assert!(message.contains("decrypt nope"), "got: {message}");
        }
        other => panic!("expected ProcessFailed, got {other:?}"),
    }

    // SAFETY: see above.
    unsafe {
        std::env::remove_var(sops::SOPS_BIN_ENV);
    }
}

#[test]
#[serial]
fn edit_forwards_editor_and_args() {
    let dir = TempDir::new().unwrap();
    let record = dir.path().join("edit.log");
    let fake = write_fake_sops(
        dir.path(),
        &format!(
            "echo \"EDITOR=$EDITOR args=$*\" > '{}'\nexit 0\n",
            record.display()
        ),
    );
    // SAFETY: serialized via `#[serial]`.
    unsafe {
        std::env::set_var(sops::SOPS_BIN_ENV, &fake);
    }

    let file = dir.path().join("secrets.env");
    std::fs::write(&file, "K=V\n").unwrap();
    sops::edit(&file, Some("my-editor"), &["--idempotent".to_string()]).unwrap();

    let log = std::fs::read_to_string(&record).unwrap();
    assert!(
        log.contains("EDITOR=my-editor"),
        "editor not forwarded: {log}"
    );
    assert!(log.contains("--idempotent"), "args not forwarded: {log}");

    // SAFETY: see above.
    unsafe {
        std::env::remove_var(sops::SOPS_BIN_ENV);
    }
}

#[test]
#[serial]
fn edit_maps_nonzero_exit_to_process_failed() {
    let dir = TempDir::new().unwrap();
    let fake = write_fake_sops(dir.path(), "exit 4\n");
    // SAFETY: serialized via `#[serial]`.
    unsafe {
        std::env::set_var(sops::SOPS_BIN_ENV, &fake);
    }

    let file = dir.path().join("secrets.env");
    std::fs::write(&file, "K=V\n").unwrap();
    let err = sops::edit(&file, None, &[]).unwrap_err();
    match err {
        sopsy::error::Error::ProcessFailed { code, message, .. } => {
            assert_eq!(code, 4);
            assert!(message.contains("editing"), "got: {message}");
        }
        other => panic!("expected ProcessFailed, got {other:?}"),
    }

    // SAFETY: see above.
    unsafe {
        std::env::remove_var(sops::SOPS_BIN_ENV);
    }
}
