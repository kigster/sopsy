//! Integration tests for `sopsy check` against **real** `git`, `sops` and
//! `age`.
//!
//! Each test builds a temporary git repository on disk: a real age keypair, a
//! `.sops.yaml` creation rule, a `.sopsy.yml` (with a break-glass recipient),
//! and a real sops-encrypted dotenv `.env.encrypted`. The healthy fixture must
//! make `sopsy check` exit `0`; every other fixture mutates exactly one
//! invariant and must make it exit non-zero while naming the failure on stdout.
//!
//! `sopsy check` never decrypts, so these tests only need the recipient's
//! public key (encryption), not the private key. They are marked `#[serial]`
//! because they shell out to real tools and to keep the suite deterministic.

use std::path::Path;
use std::process::Command;

use assert_cmd::Command as AssertCommand;
use assert_fs::TempDir;
use predicates::prelude::*;
use serial_test::serial;

/// Generate an age keypair in `dir`, returning the `age1…` public key.
fn generate_age_key(dir: &Path) -> String {
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr
        .lines()
        .find_map(|line| line.split("Public key:").nth(1))
        .map(|s| s.trim().to_string())
        .expect("age-keygen should print the public key")
}

/// Run `git -C <repo> <args…>`, asserting success.
fn git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("git should be installed");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Encrypt `file` (relative to `repo`) in place as a sops dotenv file.
///
/// sops discovers `.sops.yaml` by walking up from the current working
/// directory, so the command runs with its cwd set to `repo`.
fn sops_encrypt_dotenv(repo: &Path, file: &str) {
    let output = Command::new("sops")
        .current_dir(repo)
        .args([
            "--encrypt",
            "--input-type",
            "dotenv",
            "--output-type",
            "dotenv",
            "--in-place",
        ])
        .arg(file)
        .output()
        .expect("sops should be installed");
    assert!(
        output.status.success(),
        "sops encrypt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Build a repository in a fresh temp dir per the [`FixtureOpts`], returning the
/// `TempDir` (kept alive for the duration of the test).
struct FixtureOpts {
    /// Use the healthy `.sops.yaml` rule (`\.encrypted$`). When `false`, the
    /// caller's `sops_yaml_override` is used as the final `.sops.yaml`.
    sops_yaml_override: Option<String>,
    /// Add `.env` to `.gitignore`.
    gitignore_env: bool,
    /// Configure a break-glass recipient in `.sopsy.yml`.
    break_glass: bool,
    /// Force-track a plaintext `.env` file.
    track_plaintext_env: bool,
    /// Track an extra plaintext `server.key` file.
    track_key_file: bool,
    /// Overwrite `.env.encrypted` with plaintext (no sops metadata) after
    /// encryption.
    corrupt_encrypted: bool,
    /// Delete `.sops.yaml` entirely before commit.
    delete_sops_yaml: bool,
}

impl Default for FixtureOpts {
    fn default() -> Self {
        Self {
            sops_yaml_override: None,
            gitignore_env: true,
            break_glass: true,
            track_plaintext_env: false,
            track_key_file: false,
            corrupt_encrypted: false,
            delete_sops_yaml: false,
        }
    }
}

/// Build a repo per `opts` and return its `TempDir`.
fn build_repo(opts: FixtureOpts) -> TempDir {
    let dir = TempDir::new().unwrap();
    let repo = dir.path();

    let public_key = generate_age_key(repo);

    git(repo, &["init", "-q"]);
    git(repo, &["config", "user.email", "ci@example.com"]);
    git(repo, &["config", "user.name", "CI"]);

    // `.sops.yaml` — a single rule covering `*.encrypted` so sops can encrypt.
    let sops_yaml =
        format!("creation_rules:\n  - path_regex: \\.encrypted$\n    age: {public_key}\n");
    std::fs::write(repo.join(".sops.yaml"), &sops_yaml).unwrap();

    // `.sopsy.yml` — sopsy's metadata, with recipients + optional break-glass.
    let mut sopsy = String::from("encrypted_globs:\n  - \"*.encrypted\"\nrecipients:\n");
    sopsy.push_str(&format!("  - name: dev\n    public_key: {public_key}\n"));
    if opts.break_glass {
        sopsy.push_str(&format!(
            "  - name: break-glass\n    public_key: {public_key}\n    break_glass: true\n"
        ));
    }
    std::fs::write(repo.join(".sopsy.yml"), sopsy).unwrap();

    // `.gitignore` — ignore `.env` (the real plaintext secret) by default.
    let gitignore = if opts.gitignore_env {
        ".env\n"
    } else {
        "target\n"
    };
    std::fs::write(repo.join(".gitignore"), gitignore).unwrap();

    // Real sops-encrypted dotenv artifact.
    let encrypted = repo.join(".env.encrypted");
    std::fs::write(&encrypted, "TOKEN=secret123\nAPI_KEY=abc\n").unwrap();
    sops_encrypt_dotenv(repo, ".env.encrypted");

    // `.env.example` — a safe, committed template (must not trip invariant 5).
    std::fs::write(repo.join(".env.example"), "TOKEN=\nAPI_KEY=\n").unwrap();

    // ---- Per-fixture mutations -------------------------------------------
    if let Some(override_yaml) = &opts.sops_yaml_override {
        let rendered = override_yaml.replace("{KEY}", &public_key);
        std::fs::write(repo.join(".sops.yaml"), rendered).unwrap();
    }
    if opts.corrupt_encrypted {
        std::fs::write(&encrypted, "TOKEN=plaintext\nAPI_KEY=plaintext\n").unwrap();
    }
    if opts.delete_sops_yaml {
        std::fs::remove_file(repo.join(".sops.yaml")).unwrap();
    }
    if opts.track_key_file {
        std::fs::write(repo.join("server.key"), "-----BEGIN PRIVATE KEY-----\n").unwrap();
    }

    // Track everything that isn't gitignored.
    git(repo, &["add", "-A"]);

    if opts.track_plaintext_env {
        std::fs::write(repo.join(".env"), "TOKEN=secret123\n").unwrap();
        git(repo, &["add", "-f", ".env"]);
    }

    git(repo, &["commit", "-qm", "fixture"]);
    dir
}

/// Run `sopsy check` inside `repo`, returning the assert.
fn run_check(repo: &Path) -> assert_cmd::assert::Assert {
    AssertCommand::cargo_bin("sopsy")
        .expect("binary `sopsy` should build")
        .arg("check")
        .current_dir(repo)
        .assert()
}

#[test]
#[serial]
fn healthy_repo_passes() {
    let dir = build_repo(FixtureOpts::default());
    run_check(dir.path())
        .success()
        .stdout(predicate::str::contains("all checks passed"));
}

#[test]
#[serial]
fn tracked_env_fails() {
    // (a) `.env` is force-tracked.
    let dir = build_repo(FixtureOpts {
        track_plaintext_env: true,
        ..Default::default()
    });
    run_check(dir.path())
        .failure()
        .stdout(predicate::str::contains(".env is tracked by git"));
}

#[test]
#[serial]
fn env_not_ignored_fails() {
    // (b) `.env` missing from `.gitignore`.
    let dir = build_repo(FixtureOpts {
        gitignore_env: false,
        ..Default::default()
    });
    run_check(dir.path())
        .failure()
        .stdout(predicate::str::contains(".env is not gitignored"));
}

#[test]
#[serial]
fn missing_sops_yaml_fails() {
    // (c) `.sops.yaml` deleted.
    let dir = build_repo(FixtureOpts {
        delete_sops_yaml: true,
        ..Default::default()
    });
    run_check(dir.path())
        .failure()
        .stdout(predicate::str::contains(".sops.yaml is missing"));
}

#[test]
#[serial]
fn corrupt_sops_yaml_fails() {
    // (c') `.sops.yaml` present but not valid YAML.
    let dir = build_repo(FixtureOpts {
        sops_yaml_override: Some("creation_rules: [this: is, not: valid".to_string()),
        ..Default::default()
    });
    run_check(dir.path())
        .failure()
        .stdout(predicate::str::contains(".sops.yaml is not valid YAML"));
}

#[test]
#[serial]
fn unmatched_encrypted_file_fails() {
    // (d) Encrypt normally, then narrow `.sops.yaml` so the rule no longer
    // matches `.env.encrypted` (the file stays valid sops on disk).
    let dir = build_repo(FixtureOpts {
        sops_yaml_override: Some(
            "creation_rules:\n  - path_regex: doesnotmatch\\.encrypted$\n    age: {KEY}\n"
                .to_string(),
        ),
        ..Default::default()
    });
    run_check(dir.path())
        .failure()
        .stdout(predicate::str::contains(
            "matches no .sops.yaml creation rule",
        ));
}

#[test]
#[serial]
fn tracked_key_file_fails() {
    // (e) A `*.key` file is tracked.
    let dir = build_repo(FixtureOpts {
        track_key_file: true,
        ..Default::default()
    });
    run_check(dir.path()).failure().stdout(
        predicate::str::contains("server.key")
            .and(predicate::str::contains("looks like a plaintext secret")),
    );
}

#[test]
#[serial]
fn malformed_encrypted_file_fails() {
    // (f) `.env.encrypted` overwritten with plaintext (no sops metadata).
    let dir = build_repo(FixtureOpts {
        corrupt_encrypted: true,
        ..Default::default()
    });
    run_check(dir.path())
        .failure()
        .stdout(predicate::str::contains("missing sops metadata"));
}

#[test]
#[serial]
fn no_break_glass_recipient_fails() {
    // (g) `.sopsy.yml` has no break-glass recipient.
    let dir = build_repo(FixtureOpts {
        break_glass: false,
        ..Default::default()
    });
    run_check(dir.path())
        .failure()
        .stdout(predicate::str::contains("no break-glass recipient"));
}

/// Build a repository whose `.sops.yaml`, `.sopsy.yml`, and `.gitignore` are
/// committed, then create a real sops-encrypted `.env.encrypted` that is left
/// **untracked** on disk (mirroring the state right after `sopsy init`, before
/// the user commits). The file is always encrypted with a matching rule first;
/// `match_rule`/`valid_meta` then mutate it to drive the failure cases.
fn build_untracked_encrypted(match_rule: bool, valid_meta: bool) -> TempDir {
    let dir = TempDir::new().unwrap();
    let repo = dir.path();
    let public_key = generate_age_key(repo);

    git(repo, &["init", "-q"]);
    git(repo, &["config", "user.email", "ci@example.com"]);
    git(repo, &["config", "user.name", "CI"]);

    std::fs::write(
        repo.join(".sops.yaml"),
        format!("creation_rules:\n  - path_regex: \\.encrypted$\n    age: {public_key}\n"),
    )
    .unwrap();
    std::fs::write(
        repo.join(".sopsy.yml"),
        format!(
            "encrypted_globs:\n  - \"*.encrypted\"\nrecipients:\n  \
             - name: dev\n    public_key: {public_key}\n  \
             - name: break-glass\n    public_key: {public_key}\n    break_glass: true\n"
        ),
    )
    .unwrap();
    std::fs::write(repo.join(".gitignore"), ".env\n").unwrap();

    // Commit only the configuration; the encrypted artifact stays untracked.
    git(repo, &["add", ".sops.yaml", ".sopsy.yml", ".gitignore"]);
    git(repo, &["commit", "-qm", "init"]);

    // Create + encrypt the real artifact (untracked on disk).
    let encrypted = repo.join(".env.encrypted");
    std::fs::write(&encrypted, "TOKEN=secret123\n").unwrap();
    sops_encrypt_dotenv(repo, ".env.encrypted");

    if !match_rule {
        // Narrow the rule so it no longer covers `.env.encrypted`.
        std::fs::write(
            repo.join(".sops.yaml"),
            format!(
                "creation_rules:\n  - path_regex: doesnotmatch\\.encrypted$\n    age: {public_key}\n"
            ),
        )
        .unwrap();
    }
    if !valid_meta {
        // Strip the sops metadata by overwriting with plaintext.
        std::fs::write(&encrypted, "TOKEN=plaintext\n").unwrap();
    }

    dir
}

#[test]
#[serial]
fn untracked_encrypted_file_is_validated() {
    // The real bug: an on-disk `.env.encrypted` that is not yet committed must
    // still be validated (not skipped as "no encrypted files to verify").
    let dir = build_untracked_encrypted(true, true);

    // Sanity: the artifact really is untracked.
    let tracked = Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .args(["ls-files", ".env.encrypted"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&tracked.stdout).trim().is_empty(),
        ".env.encrypted should be untracked for this fixture"
    );

    run_check(dir.path())
        .success()
        .stdout(
            predicate::str::contains("matches a .sops.yaml creation rule")
                .and(predicate::str::contains("contains valid sops metadata"))
                .and(predicate::str::contains("all checks passed")),
        )
        // Must NOT vacuously skip the (untracked) artifact.
        .stdout(predicate::str::contains("no encrypted files to verify").not());
}

#[test]
#[serial]
fn untracked_encrypted_unmatched_rule_fails() {
    // With the old (tracked-only) logic this passed vacuously; it must now fail.
    let dir = build_untracked_encrypted(false, true);
    run_check(dir.path())
        .failure()
        .stdout(predicate::str::contains(
            "matches no .sops.yaml creation rule",
        ));
}

#[test]
#[serial]
fn untracked_encrypted_missing_metadata_fails() {
    // Likewise, a broken (plaintext) untracked artifact must now be caught.
    let dir = build_untracked_encrypted(true, false);
    run_check(dir.path())
        .failure()
        .stdout(predicate::str::contains("missing sops metadata"));
}

/// Build a minimal sopsy-managed repo containing **no** encrypted files at all.
fn build_repo_without_encrypted(sops_yaml: &str, sopsy_yml: &str) -> TempDir {
    let dir = TempDir::new().unwrap();
    let repo = dir.path();
    let public_key = generate_age_key(repo);

    git(repo, &["init", "-q"]);
    git(repo, &["config", "user.email", "ci@example.com"]);
    git(repo, &["config", "user.name", "CI"]);

    std::fs::write(
        repo.join(".sops.yaml"),
        sops_yaml.replace("{KEY}", &public_key),
    )
    .unwrap();
    std::fs::write(
        repo.join(".sopsy.yml"),
        sopsy_yml.replace("{KEY}", &public_key),
    )
    .unwrap();
    std::fs::write(repo.join(".gitignore"), ".env\n").unwrap();
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-qm", "init"]);
    dir
}

#[test]
#[serial]
fn no_encrypted_files_passes_vacuously() {
    // A managed repo with no artifacts: the two "no encrypted files" branches.
    let dir = build_repo_without_encrypted(
        "creation_rules:\n  - path_regex: \\.encrypted$\n    age: {KEY}\n",
        "encrypted_globs:\n  - \"*.encrypted\"\nrecipients:\n  - name: bg\n    public_key: {KEY}\n    break_glass: true\n",
    );
    run_check(dir.path()).success().stdout(
        predicate::str::contains("no encrypted files to verify against creation rules")
            .and(predicate::str::contains("no encrypted files to parse")),
    );
}

#[test]
#[serial]
fn sops_yaml_without_creation_rules_fails() {
    // `.sops.yaml` parses but defines no creation rules.
    let dir = build_repo_without_encrypted(
        "other_key: 1\n",
        "encrypted_globs:\n  - \"*.encrypted\"\nrecipients:\n  - name: bg\n    public_key: {KEY}\n    break_glass: true\n",
    );
    run_check(dir.path())
        .failure()
        .stdout(predicate::str::contains(".sops.yaml has no creation_rules"));
}

#[test]
#[serial]
fn invalid_sopsy_yml_surfaces_error() {
    // A malformed `.sopsy.yml` is a hard error (not a vacuous skip): exercises
    // the non-`FileNotFound` error arm of `Config::load_from_dir`.
    let dir = TempDir::new().unwrap();
    let repo = dir.path();
    git(repo, &["init", "-q"]);
    git(repo, &["config", "user.email", "ci@example.com"]);
    git(repo, &["config", "user.name", "CI"]);
    std::fs::write(repo.join(".sopsy.yml"), "recipients: [unterminated\n").unwrap();
    run_check(repo).failure();
}
