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

/// Turn `dir` into a real git repository with a stable identity and a `main`
/// default branch, plus one initial commit so the index diffs cleanly.
fn init_git_repo(dir: &Path) {
    let run = |args: &[&str]| {
        let status = StdCommand::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .status()
            .expect("git should be available");
        assert!(status.success(), "git {args:?} failed in {}", dir.display());
    };
    run(&["init", "-q", "-b", "main"]);
    run(&["config", "user.email", "test@example.com"]);
    run(&["config", "user.name", "Sopsy Test"]);
    std::fs::write(dir.join("README.md"), "test repo\n").unwrap();
    run(&["add", "README.md"]);
    run(&["commit", "-q", "-m", "initial"]);
}

/// Build a `Command` for the compiled `sopsy` binary.
fn sopsy() -> AssertCommand {
    AssertCommand::cargo_bin("sopsy").expect("binary `sopsy` should build")
}

/// Mark `path` executable (no-op on non-unix).
fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }
}

/// Write a fake `sops` that records the `EDITOR` it received plus its argv to
/// `log`, then exits successfully.
fn write_recording_sops(path: &Path, log: &Path) {
    let script = format!(
        "#!/bin/sh\n{{ echo \"EDITOR=$EDITOR\"; echo \"ARGS=$*\"; }} > '{}'\n",
        log.display()
    );
    std::fs::write(path, script).unwrap();
    make_executable(path);
}

/// Write a fake `sops` that prints to stderr and exits non-zero, simulating a
/// failed edit (e.g. handed a file that isn't sops-encrypted).
fn write_failing_sops(path: &Path) {
    let script = "#!/bin/sh\necho 'boom: not a sops file' >&2\nexit 7\n";
    std::fs::write(path, script).unwrap();
    make_executable(path);
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
#[serial]
fn edit_with_git_stages_the_encrypted_file() {
    let dir = TempDir::new().unwrap();
    init_git_repo(dir.path());
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

    // An "editor" that appends `BAZ=qux` to whatever file sops opens.
    let editor = dir.path().join("appender.sh");
    write_appender_editor(&editor, "BAZ=qux");

    // `--git` must stage the edited ciphertext and print commit/PR advice
    // (including the success line for the edit itself).
    sopsy()
        .arg("--non-interactive")
        .arg("--git")
        .arg("edit")
        .arg(".env.encrypted")
        .current_dir(dir.path())
        .env("EDITOR", &editor)
        .env("SOPS_AGE_KEY_FILE", &key_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("saved changes to .env.encrypted"))
        .stdout(predicate::str::contains("Staged for you"))
        .stdout(predicate::str::contains("git add .env.encrypted"))
        .stdout(predicate::str::contains(
            "Next: commit and open a pull request",
        ))
        .stdout(predicate::str::contains(
            "git commit -m \"Update encrypted .env.encrypted\"",
        ))
        .stdout(predicate::str::contains("git push -u origin main"));

    // The file really is in the git index afterwards.
    let staged = StdCommand::new("git")
        .arg("-C")
        .arg(dir.path())
        .args(["diff", "--cached", "--name-only"])
        .output()
        .expect("git should be available");
    assert!(staged.status.success());
    let staged_files = String::from_utf8_lossy(&staged.stdout);
    assert!(
        staged_files.lines().any(|line| line == ".env.encrypted"),
        "edited file not staged; index diff:\n{staged_files}"
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

#[test]
#[serial]
fn edit_wraps_sops_failure_in_friendly_message() {
    let dir = TempDir::new().unwrap();

    let fake_sops = dir.path().join("failing-sops.sh");
    write_failing_sops(&fake_sops);

    let target = dir.path().join("secrets.env");
    std::fs::write(&target, "FOO=bar\n").unwrap();

    sopsy()
        .arg("--non-interactive")
        .arg("edit")
        .arg("secrets.env")
        .arg("--editor")
        .arg("my-editor")
        .current_dir(dir.path())
        .env("SOPSY_SOPS_BIN", &fake_sops)
        .assert()
        .failure()
        // The sopsy-flavored wrapper text from `commands::edit::run`.
        .stderr(predicate::str::contains(
            "is it a valid sops-encrypted file?",
        ))
        .stderr(predicate::str::contains("secrets.env"));
}

#[test]
#[serial]
fn edit_resolves_editor_from_visual_env() {
    let dir = TempDir::new().unwrap();

    let log = dir.path().join("sops-invocation.log");
    let fake_sops = dir.path().join("recording-sops.sh");
    write_recording_sops(&fake_sops, &log);

    let target = dir.path().join("secrets.env");
    std::fs::write(&target, "FOO=bar\n").unwrap();

    // No `--editor`, no `EDITOR`: resolution must fall through to `$VISUAL`.
    sopsy()
        .arg("--non-interactive")
        .arg("edit")
        .arg("secrets.env")
        .current_dir(dir.path())
        .env("SOPSY_SOPS_BIN", &fake_sops)
        .env_remove("EDITOR")
        .env("VISUAL", "visual-editor")
        .assert()
        .success();

    let recorded = std::fs::read_to_string(&log).expect("fake sops should have logged");
    assert!(
        recorded.contains("EDITOR=visual-editor"),
        "VISUAL not used as the editor; got:\n{recorded}"
    );
}

#[test]
#[serial]
fn edit_falls_back_to_default_editor() {
    let dir = TempDir::new().unwrap();

    let log = dir.path().join("sops-invocation.log");
    let fake_sops = dir.path().join("recording-sops.sh");
    write_recording_sops(&fake_sops, &log);

    let target = dir.path().join("secrets.env");
    std::fs::write(&target, "FOO=bar\n").unwrap();

    // Neither `--editor`, `$EDITOR`, nor `$VISUAL`: must fall back to `vi`.
    sopsy()
        .arg("--non-interactive")
        .arg("edit")
        .arg("secrets.env")
        .current_dir(dir.path())
        .env("SOPSY_SOPS_BIN", &fake_sops)
        .env_remove("EDITOR")
        .env_remove("VISUAL")
        .assert()
        .success();

    let recorded = std::fs::read_to_string(&log).expect("fake sops should have logged");
    assert!(
        recorded.contains("EDITOR=vi"),
        "default editor `vi` not used; got:\n{recorded}"
    );
}
