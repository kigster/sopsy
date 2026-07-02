//! Integration tests for the `sopsy init` command, exercised through the real
//! compiled binary against **real files**.
//!
//! The happy path uses the real `sops` + `age` toolchain: a genuine age keypair
//! (`age-keygen`) is registered as the recipient, the binary encrypts a real
//! `.env.encrypted`, and we decrypt it back with `SOPS_AGE_KEY_FILE`. The Secure
//! Enclave *generate* path cannot run in CI (it needs Apple hardware), so it is
//! driven through a **fake** `age-plugin-se` and a **fake** `sops` injected via
//! `SOPSY_AGE_PLUGIN_SE_BIN` / `SOPSY_SOPS_BIN`. Env-mutating tests are
//! `#[serial]` because those variables are process-wide.

use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use assert_cmd::Command;
use assert_fs::TempDir;
use predicates::prelude::*;
use serial_test::serial;

// ----------------------------------------------------------------------------
// Fixtures (local to this test file)
// ----------------------------------------------------------------------------

/// Initialise a real git repository inside `dir` (config set so commits/ignore
/// checks work deterministically).
fn init_git_repo(dir: &Path) {
    run_git(dir, &["init", "-q"]);
    run_git(dir, &["config", "user.email", "test@example.com"]);
    run_git(dir, &["config", "user.name", "Sopsy Test"]);
}

/// Run a `git` subcommand in `dir`, asserting success.
fn run_git(dir: &Path, args: &[&str]) {
    let status = StdCommand::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .expect("git should be installed");
    assert!(status.success(), "git {args:?} failed");
}

/// Generate a real age keypair, returning `(public_key, key_file_path)`.
fn generate_age_key(dir: &Path) -> (String, PathBuf) {
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

/// Build a `Command` for the compiled `sopsy` binary rooted at `dir`.
fn sopsy_in(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("sopsy").expect("binary `sopsy` should build");
    cmd.current_dir(dir);
    cmd
}

/// Write an executable shell script to `path` with the given body.
fn write_script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }
}

// ----------------------------------------------------------------------------
// Real end-to-end happy path (real sops + age)
// ----------------------------------------------------------------------------

#[test]
#[serial]
fn init_with_public_key_encrypts_real_env() {
    let dir = TempDir::new().unwrap();
    init_git_repo(dir.path());
    let (public_key, key_file) = generate_age_key(dir.path());

    // Seed a real `.env` so we can assert an exact decrypt round-trip.
    let plaintext = "PASSWORD=hunter2\nAPI_KEY=abc123\n"; // pragma: allowlist secret
    std::fs::write(dir.path().join(".env"), plaintext).unwrap();

    sopsy_in(dir.path())
        .args([
            "--non-interactive",
            "init",
            "--no-generate",
            "--public-key",
            &public_key,
            "--recipient-name",
            "admin",
        ])
        .assert()
        .success();

    // All four bootstrap files were created.
    for name in [".sops.yaml", ".env.example", ".env.encrypted", ".sopsy.yml"] {
        assert!(
            dir.path().join(name).exists(),
            "{name} should have been created"
        );
    }

    // `.env.encrypted` carries real sops/age ciphertext.
    let encrypted = std::fs::read_to_string(dir.path().join(".env.encrypted")).unwrap();
    assert!(encrypted.contains("ENC["), "missing ENC[ markers");
    assert!(encrypted.contains("sops"), "missing sops metadata");
    assert_ne!(encrypted, plaintext, "file was not encrypted");

    // It decrypts back to exactly the seed using the private key.
    let decrypted = StdCommand::new("sops")
        .env("SOPS_AGE_KEY_FILE", &key_file)
        .args([
            "--decrypt",
            "--input-type",
            "dotenv",
            "--output-type",
            "dotenv",
        ])
        .arg(dir.path().join(".env.encrypted"))
        .output()
        .unwrap();
    assert!(
        decrypted.status.success(),
        "decrypt failed: {}",
        String::from_utf8_lossy(&decrypted.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&decrypted.stdout), plaintext);

    // `.gitignore` protects plaintext `.env` but the recipient key is recorded.
    let gitignore = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert!(gitignore.lines().any(|l| l == ".env"), "{gitignore}");
    let config = std::fs::read_to_string(dir.path().join(".sopsy.yml")).unwrap();
    assert!(config.contains(&public_key), "recipient key not recorded");
    assert!(config.contains("admin"), "recipient name not recorded");
}

#[test]
#[serial]
fn init_seeds_from_env_example_when_no_dotenv() {
    let dir = TempDir::new().unwrap();
    init_git_repo(dir.path());
    let (public_key, key_file) = generate_age_key(dir.path());

    // Pre-create a custom `.env.example` and provide NO `.env`, so the seed for
    // `.env.encrypted` must come from `.env.example`.
    let example = "FROM_EXAMPLE=yes\nTOKEN=seed-me\n";
    std::fs::write(dir.path().join(".env.example"), example).unwrap();

    sopsy_in(dir.path())
        .args([
            "--non-interactive",
            "init",
            "--no-generate",
            "--public-key",
            &public_key,
        ])
        .assert()
        .success()
        // Confirms init kept the existing `.env.example` (info branch).
        .stdout(predicate::str::contains(".env.example already present"));

    // Decrypting `.env.encrypted` yields exactly the `.env.example` contents.
    let decrypted = StdCommand::new("sops")
        .env("SOPS_AGE_KEY_FILE", &key_file)
        .args([
            "--decrypt",
            "--input-type",
            "dotenv",
            "--output-type",
            "dotenv",
        ])
        .arg(dir.path().join(".env.encrypted"))
        .output()
        .unwrap();
    assert!(
        decrypted.status.success(),
        "decrypt failed: {}",
        String::from_utf8_lossy(&decrypted.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&decrypted.stdout), example);
}

// ----------------------------------------------------------------------------
// Legacy repo: a pre-existing .gitignore must not strand encrypted artifacts
// ----------------------------------------------------------------------------

#[test]
#[serial]
fn init_rescues_encrypted_artifacts_in_legacy_gitignore() {
    let dir = TempDir::new().unwrap();
    init_git_repo(dir.path());
    let (public_key, _key_file) = generate_age_key(dir.path());

    // The canonical real-world dotenv ignore: people almost always have these
    // two lines (and no encrypted-rescue), so `.env.*` already hides every
    // encrypted dotenv artifact.
    std::fs::write(dir.path().join(".gitignore"), ".env\n.env.*\n").unwrap();

    sopsy_in(dir.path())
        .args([
            "--non-interactive",
            "init",
            "--no-generate",
            "--public-key",
            &public_key,
        ])
        .assert()
        .success();

    let gitignore = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    // The negations are appended (after the pre-existing `.env.*`), and the
    // legacy content is preserved (not duplicated).
    assert!(gitignore.contains("!*.encrypted"), "{gitignore}");
    assert_eq!(
        gitignore.matches("\n.env.*").count() + usize::from(gitignore.starts_with(".env.*")),
        1,
        "must not duplicate the pre-existing rule:\n{gitignore}"
    );

    // `git check-ignore` exits 0 when ignored, 1 otherwise. Both the encrypted
    // artifact and the plaintext template must stay committable despite `.env.*`.
    for committable in [".env.example.encrypted", ".env.example"] {
        std::fs::write(dir.path().join(committable), "x").unwrap();
        let ignored = StdCommand::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["check-ignore", committable])
            .status()
            .unwrap()
            .success();
        assert!(
            !ignored,
            "{committable} must be committable, not gitignored"
        );
    }

    // And a real plaintext dotenv stays ignored.
    std::fs::write(dir.path().join(".env.local"), "x").unwrap();
    let env_local_ignored = StdCommand::new("git")
        .arg("-C")
        .arg(dir.path())
        .args(["check-ignore", ".env.local"])
        .status()
        .unwrap()
        .success();
    assert!(env_local_ignored, ".env.local must still be ignored");
}

// ----------------------------------------------------------------------------
// Idempotency
// ----------------------------------------------------------------------------

#[test]
#[serial]
fn rerun_preserves_sops_yaml_unless_forced() {
    let dir = TempDir::new().unwrap();
    init_git_repo(dir.path());
    let (public_key, _key_file) = generate_age_key(dir.path());

    let args = [
        "--non-interactive",
        "init",
        "--no-generate",
        "--public-key",
        public_key.as_str(),
    ];

    sopsy_in(dir.path()).args(args).assert().success();

    // Tag `.sops.yaml` with a sentinel an idempotent re-run must preserve.
    let sops_yaml = dir.path().join(".sops.yaml");
    let original = std::fs::read_to_string(&sops_yaml).unwrap();
    std::fs::write(&sops_yaml, format!("{original}# SENTINEL\n")).unwrap();

    // Re-run without --force: sentinel survives (file left untouched).
    sopsy_in(dir.path()).args(args).assert().success();
    assert!(
        std::fs::read_to_string(&sops_yaml)
            .unwrap()
            .contains("# SENTINEL"),
        "non-forced re-run must not clobber .sops.yaml"
    );

    // Re-run with --force: file is rewritten and the sentinel is gone.
    sopsy_in(dir.path())
        .args(args)
        .arg("--force")
        .assert()
        .success();
    assert!(
        !std::fs::read_to_string(&sops_yaml)
            .unwrap()
            .contains("# SENTINEL"),
        "--force must rewrite .sops.yaml"
    );
}

// ----------------------------------------------------------------------------
// Secure Enclave generate path (fake age-plugin-se + fake sops)
// ----------------------------------------------------------------------------

#[test]
#[serial]
fn init_generates_enclave_identity_with_fakes() {
    let dir = TempDir::new().unwrap();
    init_git_repo(dir.path());

    let fake_pubkey = "age1se1qg8vwwqhztnh3vpt2nf2xwn7famktxlmp0nmkfltp8lkvzp8nafkqleh258";

    // Fake `age-plugin-se keygen` emitting a canned identity file.
    let plugin = dir.path().join("age-plugin-se");
    write_script(
        &plugin,
        &format!("cat <<'EOF'\n# public key: {fake_pubkey}\nAGE-PLUGIN-SE-1QFAKEIDENTITY\nEOF\n"),
    );

    // Fake `sops`: answers --version, otherwise records the invocation and
    // emits ciphertext on stdout (init encrypts to a string via
    // `--filename-override`, capturing stdout — it no longer encrypts in place).
    let record = dir.path().join("sops-invocations.log");
    let sops = dir.path().join("sops");
    write_script(
        &sops,
        &format!(
            "case \"$1\" in\n  --version) echo 'sops 9.9.9 (fake)'; exit 0;;\nesac\n\
             echo \"$@\" >> '{record}'\n\
             echo 'ENC[fake-sops]'\n",
            record = record.display()
        ),
    );

    sopsy_in(dir.path())
        .env("SOPSY_AGE_PLUGIN_SE_BIN", &plugin)
        .env("SOPSY_SOPS_BIN", &sops)
        // Keep the generated (fake) identity out of the real per-user keystore.
        .env("SOPSY_KEYS_FILE", dir.path().join("age-keys.txt"))
        .args(["--non-interactive", "init"])
        .assert()
        .success();

    // The fake identity was stored in the redirected keystore, not the real one.
    let keys = std::fs::read_to_string(dir.path().join("age-keys.txt")).unwrap();
    assert!(
        keys.contains("AGE-PLUGIN-SE-1QFAKEIDENTITY"),
        "identity should be persisted to the keystore so sops can decrypt"
    );

    // The generated enclave public key is recorded in `.sopsy.yml`.
    let config = std::fs::read_to_string(dir.path().join(".sopsy.yml")).unwrap();
    assert!(
        config.contains(fake_pubkey),
        "enclave identity not recorded in .sopsy.yml:\n{config}"
    );

    // sops was actually invoked to encrypt, resolving recipients by the
    // artifact name via `--filename-override` (not in-place on the artifact).
    let log = std::fs::read_to_string(&record).unwrap();
    assert!(log.contains("--encrypt"), "sops encrypt not invoked: {log}");
    assert!(
        log.contains("--filename-override"),
        "sops should resolve recipients via --filename-override: {log}"
    );
    assert!(
        log.contains(".env.encrypted"),
        "the override name should be the .env.encrypted artifact: {log}"
    );
    // The captured ciphertext (stdout) is what lands in the artifact.
    let encrypted = std::fs::read_to_string(dir.path().join(".env.encrypted")).unwrap();
    assert!(
        encrypted.contains("ENC[fake-sops]"),
        "captured ciphertext should be written to .env.encrypted"
    );
}

// ----------------------------------------------------------------------------
// CRITICAL regression: a failed encryption must NOT leave plaintext on disk
// ----------------------------------------------------------------------------

/// If `sops` fails during `init`, the seed plaintext must never be left at the
/// committable `.env.encrypted` path (it is un-ignored by `!*.encrypted`). The
/// fix encrypts from a private temp file straight to a string and writes the
/// artifact only on success, so a failure leaves no artifact at all.
#[test]
#[serial]
fn init_failed_encryption_leaves_no_plaintext_artifact() {
    let dir = TempDir::new().unwrap();
    init_git_repo(dir.path());
    let (public_key, _key_file) = generate_age_key(dir.path());

    // A real `.env` with a real secret as the seed.
    std::fs::write(dir.path().join(".env"), "PASSWORD=supersecret\n").unwrap();

    // Fake `sops`: reports a version (so init preflight/detect pass) but fails
    // on any encrypt invocation, printing nothing usable to stdout.
    let sops = dir.path().join("sops");
    write_script(
        &sops,
        "case \"$1\" in\n  --version) echo 'sops 9.9.9 (fake)'; exit 0;;\nesac\n\
         echo 'boom: cannot encrypt' >&2\nexit 1\n",
    );

    sopsy_in(dir.path())
        .env("SOPSY_SOPS_BIN", &sops)
        .args([
            "--non-interactive",
            "init",
            "--no-generate",
            "--public-key",
            &public_key,
        ])
        .assert()
        .failure();

    // The artifact must not exist at all — and certainly must not contain the
    // plaintext secret.
    let artifact = dir.path().join(".env.encrypted");
    assert!(
        !artifact.exists(),
        "failed encryption must not leave a .env.encrypted artifact"
    );

    // Defense in depth: even if some future change reintroduced the file, the
    // plaintext secret must never be committable. `.gitignore` is written before
    // encryption, but `!*.encrypted` un-ignores this path — so the real
    // guarantee is that the plaintext is never written here in the first place.
    if let Ok(contents) = std::fs::read_to_string(&artifact) {
        assert!(
            !contents.contains("supersecret"),
            "plaintext secret leaked into .env.encrypted:\n{contents}"
        );
    }
}

// ----------------------------------------------------------------------------
// Friendly errors
// ----------------------------------------------------------------------------

#[test]
#[serial]
fn non_interactive_without_key_or_generation_fails_friendly() {
    let dir = TempDir::new().unwrap();
    init_git_repo(dir.path());

    sopsy_in(dir.path())
        .args(["--non-interactive", "init", "--no-generate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--public-key"));

    // Nothing destructive was written when init bailed out early.
    assert!(!dir.path().join(".sops.yaml").exists());
}

#[test]
fn init_outside_git_repo_fails_friendly() {
    let dir = TempDir::new().unwrap();
    // No `git init`: must produce a clear, friendly error.
    sopsy_in(dir.path())
        .args([
            "--non-interactive",
            "init",
            "--no-generate",
            "--public-key",
            "age1abc",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("git repository"));
}

#[test]
#[serial]
fn init_records_username_and_respects_no_break_glass() {
    let dir = TempDir::new().unwrap();
    init_git_repo(dir.path());
    let (public_key, _key_file) = generate_age_key(dir.path());

    sopsy_in(dir.path())
        .args([
            "--non-interactive",
            "init",
            "--no-generate",
            "--public-key",
            &public_key,
            "--username",
            "alice",
            "--no-break-glass",
        ])
        .assert()
        .success();

    let config = std::fs::read_to_string(dir.path().join(".sopsy.yml")).unwrap();
    assert!(
        config.contains("username: alice"),
        "username should be recorded"
    );
    assert!(
        !config.contains("break_glass: true"),
        "--no-break-glass must skip break-glass setup"
    );
}

// ----------------------------------------------------------------------------
// Break-glass during init
// ----------------------------------------------------------------------------

#[test]
#[serial]
fn init_without_break_glass_prints_guidance() {
    let dir = TempDir::new().unwrap();
    init_git_repo(dir.path());
    let (public_key, _key_file) = generate_age_key(dir.path());

    // Non-interactive init skips break-glass but tells the owner how to add it.
    sopsy_in(dir.path())
        .args([
            "--non-interactive",
            "init",
            "--no-generate",
            "--public-key",
            &public_key,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("sopsy recipient break-glass"));

    let config = std::fs::read_to_string(dir.path().join(".sopsy.yml")).unwrap();
    assert!(
        !config.contains("break_glass: true"),
        "no break-glass should be registered without the flag"
    );
}

#[test]
#[serial]
fn init_break_glass_flag_registers_offline_key() {
    let dir = TempDir::new().unwrap();
    init_git_repo(dir.path());
    let (public_key, key_file) = generate_age_key(dir.path());

    // `--break-glass` runs the ceremony; SOPS_AGE_KEY_FILE lets the implicit
    // re-key decrypt with the owner's key, and SOPSY_ASSUME_YES skips the
    // interactive "copy to 1Password, press ENTER" wait.
    sopsy_in(dir.path())
        .env("SOPS_AGE_KEY_FILE", &key_file)
        .env("SOPSY_ASSUME_YES", "1")
        .args([
            "--non-interactive",
            "init",
            "--no-generate",
            "--public-key",
            &public_key,
            "--break-glass",
        ])
        .assert()
        .success();

    // A break-glass recipient is recorded, and the transient files are gone.
    let config = std::fs::read_to_string(dir.path().join(".sopsy.yml")).unwrap();
    assert!(
        config.contains("break_glass: true"),
        "break-glass recipient should be recorded:\n{config}"
    );
    assert!(!dir.path().join("break-glass.private").exists());
    assert!(!dir.path().join("break-glass.public").exists());

    // The owner key is still a recipient, and the secret decrypts with it.
    let sops_yaml = std::fs::read_to_string(dir.path().join(".sops.yaml")).unwrap();
    assert!(
        sops_yaml.contains(&public_key),
        "owner key must remain a recipient"
    );
    let decrypted = StdCommand::new("sops")
        .env("SOPS_AGE_KEY_FILE", &key_file)
        .args([
            "--decrypt",
            "--input-type",
            "dotenv",
            "--output-type",
            "dotenv",
        ])
        .arg(dir.path().join(".env.encrypted"))
        .output()
        .unwrap();
    assert!(
        decrypted.status.success(),
        "owner should still decrypt after break-glass re-key: {}",
        String::from_utf8_lossy(&decrypted.stderr)
    );
}
