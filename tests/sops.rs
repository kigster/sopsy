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
    let key_file = dir.join("age-key.txt");
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
            "PASSWORD=hunter2\nAPI_KEY=abc123\n",
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
    assert_eq!(decrypted_env, "PASSWORD=hunter2\nAPI_KEY=abc123\n");

    // SAFETY: see above; restore a clean environment for any later test.
    unsafe {
        std::env::remove_var("SOPS_AGE_KEY_FILE");
    }
    std::env::set_current_dir(original_cwd).unwrap();
}
