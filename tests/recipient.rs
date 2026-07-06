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
use sopsy::cli::{
    ApproveArgs, JoinArgs, RecipientAddArgs, RecipientBreakGlassArgs, RecipientCiArgs,
    RecipientCommand, RecipientRemoveArgs,
};
use sopsy::commands::{approve, join, recipient};
use sopsy::config::{Config, MemberState};
use sopsy::error::Error;
use sopsy::sops::{self, FileType};
use sopsy::ui::Ui;

/// A non-interactive, color-free UI for driving commands in tests.
fn test_ui() -> Ui {
    Ui::new(false, false, false)
}

/// A non-interactive, color-enabled UI (exercises the colored `list` output).
fn color_ui() -> Ui {
    Ui::new(true, false, false)
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
/// `\.env\.encrypted$` to `public_key` (canonical comma-separated string form).
fn write_sops_yaml(dir: &Path, public_key: &str) {
    let config =
        format!("creation_rules:\n  - path_regex: \\.env\\.encrypted$\n    age: {public_key}\n");
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

/// Write an executable shell script to `path` with the given body.
fn write_script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// Set or clear an arbitrary environment variable (callers must be `#[serial]`).
fn set_env(key: &str, value: Option<&Path>) {
    unsafe {
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
}

// ---------------------------------------------------------------------------
// `recipient keygen` — Secure Enclave identity generation (fake age-plugin-se).
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn keygen_generates_and_prints_enclave_identity() {
    let original = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();

    let fake_pubkey = "age1se1qg8vwwqhztnh3vpt2nf2xwn7famktxlmp0nmkfltp8lkvzp8nafkqleh258";
    // A fake `age-plugin-se` that records its args to a file (so we can assert
    // flag forwarding — its stderr is captured by sopsy, so a file is the only
    // observable channel) and emits a canned identity file.
    let record = dir.path().join("plugin-args.log");
    let plugin = dir.path().join("age-plugin-se");
    write_script(
        &plugin,
        &format!(
            "echo \"$@\" >> '{record}'\n\
             cat <<'EOF'\n# public key: {fake_pubkey}\nAGE-PLUGIN-SE-1QFAKEIDENTITY\nEOF\n",
            record = record.display()
        ),
    );

    let output = assert_cmd::Command::cargo_bin("sopsy")
        .unwrap()
        .env("SOPSY_AGE_PLUGIN_SE_BIN", &plugin)
        .current_dir(dir.path())
        .args([
            "recipient",
            "keygen",
            "--",
            "--access-control=any-biometry-or-passcode",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "keygen should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(fake_pubkey),
        "keygen should print the public key; got:\n{stdout}"
    );
    // The trailing `--` args are forwarded verbatim to age-plugin-se keygen.
    let logged = std::fs::read_to_string(&record).unwrap();
    assert!(
        logged.contains("keygen") && logged.contains("--access-control=any-biometry-or-passcode"),
        "keygen should forward age flags to age-plugin-se; got:\n{logged}"
    );

    restore_cwd(&original);
}

// ---------------------------------------------------------------------------
// `recipient break-glass` — portable emergency key (real age-keygen + sops).
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn break_glass_generates_registers_and_deletes_local_files() {
    let original = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();
    let (repo, key_a, _key_b) = setup_repo(dir.path());

    // updatekeys must decrypt the existing secret with the primary key A.
    set_age_key_file(Some(&key_a.file));
    // Non-interactively confirm the (simulated) offline copy.
    set_env("SOPSY_ASSUME_YES", Some(Path::new("1")));

    let out_prefix = repo.join("break-glass-key");
    recipient::run(
        &test_ui(),
        &RecipientCommand::BreakGlass(RecipientBreakGlassArgs {
            output: out_prefix.clone(),
            name: None,
            force: false,
            no_updatekeys: false,
        }),
    )
    .expect("break-glass should succeed");

    // The local key files were deleted after confirmation.
    assert!(
        !with_suffix_test(&out_prefix, "private").exists(),
        "private key file must be deleted"
    );
    assert!(
        !with_suffix_test(&out_prefix, "public").exists(),
        "public key file must be deleted"
    );

    // The break-glass recipient is recorded with the flag set.
    let config = Config::load_from_dir(&repo).unwrap();
    let bg = config
        .recipient("break-glass")
        .expect("break-glass recipient should be recorded");
    assert!(bg.break_glass, "recipient must be marked break-glass");
    assert!(
        bg.public_key.starts_with("age1"),
        "a real age public key should be recorded; got {}",
        bg.public_key
    );

    // Its key is also in `.sops.yaml`, and the secret still decrypts with key A.
    let sops_yaml = std::fs::read_to_string(repo.join(".sops.yaml")).unwrap();
    assert!(
        sops_yaml.contains(&bg.public_key),
        "break-glass key should be in .sops.yaml"
    );
    let decrypted = sops::decrypt(&repo.join(".env.encrypted"), FileType::Dotenv).unwrap();
    assert!(decrypted.contains("FOO=bar"), "key A should still decrypt");

    set_env("SOPSY_ASSUME_YES", None);
    set_age_key_file(None);
    restore_cwd(&original);
}

#[test]
#[serial]
fn break_glass_non_interactive_without_optin_fails_before_writing() {
    let original = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();
    let (repo, _key_a, _key_b) = setup_repo(dir.path());

    // No SOPSY_ASSUME_YES and a non-interactive UI: must fail fast.
    let out_prefix = repo.join("bg");
    let err = recipient::run(
        &test_ui(),
        &RecipientCommand::BreakGlass(RecipientBreakGlassArgs {
            output: out_prefix.clone(),
            name: None,
            force: false,
            no_updatekeys: false,
        }),
    )
    .expect_err("break-glass must refuse to run non-interactively");
    assert!(matches!(err, Error::NonInteractive { .. }));

    // Nothing was written and no recipient was added.
    assert!(!with_suffix_test(&out_prefix, "private").exists());
    assert!(!with_suffix_test(&out_prefix, "public").exists());
    let config = Config::load_from_dir(&repo).unwrap();
    assert!(config.recipient("break-glass").is_none());

    restore_cwd(&original);
}

// ---------------------------------------------------------------------------
// `recipient ci` — portable CI decryption key (real age-keygen + sops).
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn ci_ceremony_generates_registers_and_deletes_local_files() {
    let original = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();
    let (repo, key_a, _key_b) = setup_repo(dir.path());

    // updatekeys must decrypt the existing secret with the admin key A.
    set_age_key_file(Some(&key_a.file));
    // Non-interactively confirm the (simulated) CI-secret upload.
    set_env("SOPSY_ASSUME_YES", Some(Path::new("1")));

    let out_prefix = repo.join("ci");
    recipient::run(
        &test_ui(),
        &RecipientCommand::Ci(RecipientCiArgs {
            output: out_prefix.clone(),
            name: None,
            force: false,
            no_updatekeys: false,
        }),
    )
    .expect("recipient ci should succeed");

    // The local key files were deleted after confirmation.
    assert!(
        !with_suffix_test(&out_prefix, "private").exists(),
        "private key file must be deleted"
    );
    assert!(
        !with_suffix_test(&out_prefix, "public").exists(),
        "public key file must be deleted"
    );

    // The CI recipient is recorded — active, and NOT break-glass.
    let config = Config::load_from_dir(&repo).unwrap();
    let ci = config
        .recipient("ci")
        .expect("ci recipient should be recorded");
    assert!(!ci.break_glass, "the CI key is not the break-glass key");
    assert!(!ci.is_pending(), "the CI recipient is active immediately");
    assert!(
        ci.public_key.starts_with("age1"),
        "a real age public key should be recorded; got {}",
        ci.public_key
    );

    // Its key is also in `.sops.yaml`, and the secret still decrypts with key A.
    let sops_yaml = std::fs::read_to_string(repo.join(".sops.yaml")).unwrap();
    assert!(
        sops_yaml.contains(&ci.public_key),
        "CI key should be in .sops.yaml"
    );
    let decrypted = sops::decrypt(&repo.join(".env.encrypted"), FileType::Dotenv).unwrap();
    assert!(decrypted.contains("FOO=bar"), "key A should still decrypt");

    set_env("SOPSY_ASSUME_YES", None);
    set_age_key_file(None);
    restore_cwd(&original);
}

#[test]
#[serial]
fn ci_non_interactive_without_optin_fails_before_writing() {
    let original = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();
    let (repo, _key_a, _key_b) = setup_repo(dir.path());

    // No SOPSY_ASSUME_YES and a non-interactive UI: must fail fast.
    let out_prefix = repo.join("ci");
    let err = recipient::run(
        &test_ui(),
        &RecipientCommand::Ci(RecipientCiArgs {
            output: out_prefix.clone(),
            name: None,
            force: false,
            no_updatekeys: false,
        }),
    )
    .expect_err("recipient ci must refuse to run non-interactively");
    assert!(matches!(err, Error::NonInteractive { .. }));

    // Nothing was written and no recipient was added.
    assert!(!with_suffix_test(&out_prefix, "private").exists());
    assert!(!with_suffix_test(&out_prefix, "public").exists());
    let config = Config::load_from_dir(&repo).unwrap();
    assert!(config.recipient("ci").is_none());

    restore_cwd(&original);
}

/// A `.sopsy.yml` with alice (active) and bob (pending), with an optional extra
/// line appended to bob's entry (e.g. a `requested_at` or `state`).
fn sopsy_with_pending_bob(bob_extra: &str) -> String {
    format!(
        "recipients:\n  - name: alice\n    public_key: age1alice\n  \
         - name: bob\n    public_key: age1bob\n    state: pending\n{bob_extra}"
    )
}

#[test]
#[serial]
fn join_empty_name_rejected() {
    with_repo(|dir| {
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        let err = join::run(
            &test_ui(),
            &JoinArgs {
                name: "   ".into(),
                username: None,
                sopsy_file: None,
                public_key: Some("age1x".into()),
                without_touch_id: false,
                age_args: vec![],
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains("must not be empty")));
    });
}

#[test]
#[serial]
fn join_rejects_duplicate_pending_request() {
    with_repo(|dir| {
        flow_repo(
            dir,
            Some(&sopsy_with_pending_bob("")),
            Some(SOPS_ALICE_ONLY),
        );
        let err = join::run(
            &test_ui(),
            &JoinArgs {
                name: "bob".into(),
                username: None,
                sopsy_file: None,
                public_key: Some("age1bobnew".into()),
                without_touch_id: false,
                age_args: vec![],
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains("pending request")));
    });
}

#[test]
#[serial]
fn join_rejects_duplicate_public_key() {
    with_repo(|dir| {
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        // age1alice already belongs to alice in SOPSY_TWO.
        let err = join::run(
            &test_ui(),
            &JoinArgs {
                name: "carol".into(),
                username: None,
                sopsy_file: None,
                public_key: Some("age1alice".into()),
                without_touch_id: false,
                age_args: vec![],
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains("already registered")));
    });
}

#[test]
#[serial]
fn join_with_sopsy_file_targets_custom_path() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("custom-sopsy.yml");
    std::fs::write(
        &file,
        "recipients:\n  - name: alice\n    public_key: age1alice\n",
    )
    .unwrap();

    join::run(
        &test_ui(),
        &JoinArgs {
            name: "bob".into(),
            username: None,
            sopsy_file: Some(file.clone()),
            public_key: Some("age1bobkey".into()),
            without_touch_id: false,
            age_args: vec![],
        },
    )
    .expect("join --sopsy-file should succeed");

    let cfg = Config::load(&file).unwrap();
    let bob = cfg.recipient("bob").unwrap();
    assert!(bob.is_pending());
    assert!(bob.requested_at.is_some());
}

#[test]
fn join_with_missing_sopsy_file_errors() {
    let err = join::run(
        &test_ui(),
        &JoinArgs {
            name: "bob".into(),
            username: None,
            sopsy_file: Some("/nonexistent/dir/custom.yml".into()),
            public_key: Some("age1bobkey".into()),
            without_touch_id: false,
            age_args: vec![],
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::Validation(m) if m.contains("not found")));
}

#[test]
#[serial]
fn join_generates_enclave_identity_with_fake_plugin() {
    let original = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();
    git_init(dir.path());
    std::fs::write(
        dir.path().join(".sopsy.yml"),
        "recipients:\n  - name: alice\n    public_key: age1alice\n",
    )
    .unwrap();

    let fake_pub = "age1se1qg8vwwqhztnh3vpt2nf2xwn7famktxlmp0nmkfltp8lkvzp8nafkqleh258";
    let plugin = dir.path().join("age-plugin-se");
    write_script(
        &plugin,
        &format!("cat <<'EOF'\n# public key: {fake_pub}\nAGE-PLUGIN-SE-1QFAKE\nEOF\n"),
    );
    std::env::set_current_dir(dir.path()).unwrap();

    let output = assert_cmd::Command::cargo_bin("sopsy")
        .unwrap()
        .env("SOPSY_AGE_PLUGIN_SE_BIN", &plugin)
        // Keep the generated (fake) identity out of the real per-user keystore.
        .env("SOPSY_KEYS_FILE", dir.path().join("age-keys.txt"))
        .current_dir(dir.path())
        .args(["--non-interactive", "join", "newbie"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "join (generate) should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cfg = Config::load_from_dir(dir.path()).unwrap();
    let m = cfg.recipient("newbie").expect("newbie recorded");
    assert!(m.is_pending());
    assert_eq!(m.public_key, fake_pub);

    restore_cwd(&original);
}

#[test]
#[serial]
fn approve_proceeds_without_timestamp_and_warns_on_no_age_rule() {
    with_repo(|dir| {
        set_env("SOPSY_ASSUME_YES", Some(Path::new("1")));
        // bob is pending without a timestamp; the .sops.yaml rule has no `age:`,
        // exercising both the missing-timestamp and zero-modified warn branches.
        flow_repo(
            dir,
            Some(&sopsy_with_pending_bob("")),
            Some("creation_rules:\n  - path_regex: \\.enc$\n"),
        );
        approve::run(
            &test_ui(),
            &ApproveArgs {
                names: vec!["bob".into()],
                force: false,
                no_updatekeys: false,
            },
        )
        .expect("approve should succeed");
        let cfg = Config::load_from_dir(dir).unwrap();
        assert_eq!(cfg.recipient("bob").unwrap().state, MemberState::Active);
        set_env("SOPSY_ASSUME_YES", None);
    });
}

#[test]
#[serial]
fn approve_handles_unparseable_and_future_timestamps() {
    // Unparseable timestamp: warns, proceeds.
    with_repo(|dir| {
        set_env("SOPSY_ASSUME_YES", Some(Path::new("1")));
        flow_repo(
            dir,
            Some(&sopsy_with_pending_bob("    requested_at: not-a-date\n")),
            Some(SOPS_ALICE_ONLY),
        );
        approve::run(
            &test_ui(),
            &ApproveArgs {
                names: vec!["bob".into()],
                force: false,
                no_updatekeys: false,
            },
        )
        .expect("approve should proceed past a bad timestamp");
        assert_eq!(
            Config::load_from_dir(dir)
                .unwrap()
                .recipient("bob")
                .unwrap()
                .state,
            MemberState::Active
        );
        set_env("SOPSY_ASSUME_YES", None);
    });
    // Future timestamp: treated as fresh.
    with_repo(|dir| {
        set_env("SOPSY_ASSUME_YES", Some(Path::new("1")));
        flow_repo(
            dir,
            Some(&sopsy_with_pending_bob(
                "    requested_at: 2999-01-01T00:00:00Z\n",
            )),
            Some(SOPS_ALICE_ONLY),
        );
        approve::run(
            &test_ui(),
            &ApproveArgs {
                names: vec!["bob".into()],
                force: false,
                no_updatekeys: false,
            },
        )
        .expect("a future-dated request is fresh");
        set_env("SOPSY_ASSUME_YES", None);
    });
}

#[test]
#[serial]
fn approve_stale_request_with_force_proceeds() {
    with_repo(|dir| {
        set_env("SOPSY_ASSUME_YES", Some(Path::new("1")));
        flow_repo(
            dir,
            Some(&sopsy_with_pending_bob(
                "    requested_at: 2020-01-01T00:00:00Z\njoin_request_ttl: 1h\n",
            )),
            Some(SOPS_ALICE_ONLY),
        );
        approve::run(
            &test_ui(),
            &ApproveArgs {
                names: vec!["bob".into()],
                force: true,
                no_updatekeys: false,
            },
        )
        .expect("--force should approve a stale request");
        assert_eq!(
            Config::load_from_dir(dir)
                .unwrap()
                .recipient("bob")
                .unwrap()
                .state,
            MemberState::Active
        );
        set_env("SOPSY_ASSUME_YES", None);
    });
}

#[test]
#[serial]
fn approve_non_interactive_without_optin_errors_at_vouch() {
    with_repo(|dir| {
        set_env("SOPSY_ASSUME_YES", None); // ensure no automation opt-in
        flow_repo(
            dir,
            Some(&sopsy_with_pending_bob("")),
            Some(SOPS_ALICE_ONLY),
        );
        let err = approve::run(
            &test_ui(),
            &ApproveArgs {
                names: vec!["bob".into()],
                force: false,
                no_updatekeys: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::NonInteractive { .. }));
        // Nothing changed: bob is still pending.
        assert_eq!(
            Config::load_from_dir(dir)
                .unwrap()
                .recipient("bob")
                .unwrap()
                .state,
            MemberState::Pending
        );
    });
}

#[test]
#[serial]
fn approve_rolls_back_when_reencryption_fails() {
    let original = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();
    flow_repo(
        dir.path(),
        Some(&sopsy_with_pending_bob("")),
        Some(SOPS_ALICE_ONLY),
    );
    std::fs::write(dir.path().join("secret.encrypted"), "FOO=ENC[x]\n").unwrap();
    set_env("SOPSY_ASSUME_YES", Some(Path::new("1")));

    let fake = dir.path().join("fake-sops.sh");
    write_script(&fake, "echo 'cannot get data key' >&2\nexit 1\n");
    unsafe {
        std::env::set_var("SOPSY_SOPS_BIN", &fake);
    }

    let err = approve::run(
        &test_ui(),
        &ApproveArgs {
            names: vec!["bob".into()],
            force: false,
            no_updatekeys: false,
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::Validation(m) if m.contains("rolled back")));
    // bob is rolled back to pending.
    assert_eq!(
        Config::load_from_dir(dir.path())
            .unwrap()
            .recipient("bob")
            .unwrap()
            .state,
        MemberState::Pending
    );

    unsafe {
        std::env::remove_var("SOPSY_SOPS_BIN");
    }
    set_env("SOPSY_ASSUME_YES", None);
    restore_cwd(&original);
}

/// Local mirror of the production `with_suffix` helper for assertions.
fn with_suffix_test(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

// ---------------------------------------------------------------------------
// `join` / `approve` — the self-service membership flow.
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn join_records_pending_member_without_granting_access() {
    let original = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();
    let (repo, _key_a, key_b) = setup_repo(dir.path());

    join::run(
        &test_ui(),
        &JoinArgs {
            name: "Bob McMember".into(),
            username: Some("bob".into()),
            sopsy_file: None,
            public_key: Some(key_b.public.clone()),
            without_touch_id: false,
            age_args: vec![],
        },
    )
    .expect("join should succeed");

    let config = Config::load_from_dir(&repo).unwrap();
    let bob = config
        .recipient("Bob McMember")
        .expect("bob should be recorded");
    assert_eq!(bob.state, MemberState::Pending);
    assert!(bob.requested_at.is_some(), "join should stamp a timestamp");
    assert_eq!(
        bob.username.as_deref(),
        Some("bob"),
        "join should record the username alongside the name"
    );

    // A pending member grants nothing: the key must NOT be in `.sops.yaml`.
    let sops_yaml = std::fs::read_to_string(repo.join(".sops.yaml")).unwrap();
    assert!(
        !sops_yaml.contains(&key_b.public),
        "pending key must not appear in .sops.yaml"
    );

    restore_cwd(&original);
}

#[test]
#[serial]
fn join_rejects_existing_member() {
    with_repo(|dir| {
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        let err = join::run(
            &test_ui(),
            &JoinArgs {
                name: "alice".into(),
                username: None,
                sopsy_file: None,
                public_key: Some("age1x".into()),
                without_touch_id: false,
                age_args: vec![],
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains("already an active member")));
    });
}

#[test]
#[serial]
fn approve_activates_pending_member_and_rekeys() {
    let original = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();
    let (repo, key_a, key_b) = setup_repo(dir.path());

    // bob requests access.
    join::run(
        &test_ui(),
        &JoinArgs {
            name: "bob".into(),
            username: None,
            sopsy_file: None,
            public_key: Some(key_b.public.clone()),
            without_touch_id: false,
            age_args: vec![],
        },
    )
    .expect("join should succeed");

    // An existing member (key A) approves; auto-vouch for the test.
    set_age_key_file(Some(&key_a.file));
    set_env("SOPSY_ASSUME_YES", Some(Path::new("1")));
    approve::run(
        &test_ui(),
        &ApproveArgs {
            names: vec!["bob".into()],
            force: false,
            no_updatekeys: false,
        },
    )
    .expect("approve should succeed");

    let config = Config::load_from_dir(&repo).unwrap();
    let bob = config.recipient("bob").unwrap();
    assert_eq!(bob.state, MemberState::Active);
    assert!(
        bob.requested_at.is_some(),
        "requested_at is kept as the audit record of the request"
    );
    assert!(bob.approved_at.is_some(), "approval must stamp approved_at");
    assert!(
        bob.approved_by.is_some(),
        "approval must record the approver"
    );

    let sops_yaml = std::fs::read_to_string(repo.join(".sops.yaml")).unwrap();
    assert!(
        sops_yaml.contains(&key_b.public),
        "approved key must be added to .sops.yaml"
    );

    // bob (key B) can now decrypt the existing secret.
    set_age_key_file(Some(&key_b.file));
    let plain = sops::decrypt(&repo.join(".env.encrypted"), FileType::Dotenv).unwrap();
    assert!(
        plain.contains("FOO=bar"),
        "newly approved member should decrypt"
    );

    set_env("SOPSY_ASSUME_YES", None);
    set_age_key_file(None);
    restore_cwd(&original);
}

#[test]
#[serial]
fn approve_rejects_stale_request() {
    with_repo(|dir| {
        let sopsy = "recipients:\n  - name: alice\n    public_key: age1alice\n  \
            - name: bob\n    public_key: age1bob\n    state: pending\n    \
            requested_at: 2020-01-01T00:00:00Z\njoin_request_ttl: 1h\n";
        flow_repo(dir, Some(sopsy), Some(SOPS_ALICE_ONLY));
        let err = approve::run(
            &test_ui(),
            &ApproveArgs {
                names: vec!["bob".into()],
                force: false,
                no_updatekeys: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains("older than")));
        // bob stays pending; nothing leaked into .sops.yaml.
        let config = Config::load_from_dir(dir).unwrap();
        assert_eq!(config.recipient("bob").unwrap().state, MemberState::Pending);
    });
}

#[test]
#[serial]
fn approve_unknown_and_already_active_error() {
    with_repo(|dir| {
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        let ghost = approve::run(
            &test_ui(),
            &ApproveArgs {
                names: vec!["ghost".into()],
                force: false,
                no_updatekeys: false,
            },
        )
        .unwrap_err();
        assert!(matches!(ghost, Error::Validation(m) if m.contains("no member named")));

        // alice is already active in SOPSY_TWO.
        let active = approve::run(
            &test_ui(),
            &ApproveArgs {
                names: vec!["alice".into()],
                force: false,
                no_updatekeys: false,
            },
        )
        .unwrap_err();
        assert!(matches!(active, Error::Validation(m) if m.contains("already an active member")));
    });
}

#[test]
#[serial]
fn approve_batch_marks_all_named_members_active() {
    with_repo(|dir| {
        set_env("SOPSY_ASSUME_YES", Some(Path::new("1")));
        // alice active; bob and colin both pending (two onboarding PRs merged).
        let sopsy = "recipients:\n  - name: alice\n    public_key: age1alice\n  \
            - name: bob\n    public_key: age1bob\n    state: pending\n  \
            - name: colin\n    public_key: age1colin\n    state: pending\n";
        flow_repo(dir, Some(sopsy), Some(SOPS_ALICE_ONLY));
        approve::run(
            &test_ui(),
            &ApproveArgs {
                names: vec!["bob".into(), "colin".into()],
                force: false,
                no_updatekeys: true,
            },
        )
        .expect("batch approve should succeed");
        let cfg = Config::load_from_dir(dir).unwrap();
        assert_eq!(cfg.recipient("bob").unwrap().state, MemberState::Active);
        assert_eq!(cfg.recipient("colin").unwrap().state, MemberState::Active);
        set_env("SOPSY_ASSUME_YES", None);
    });
}

#[test]
#[serial]
fn approve_interactive_approves_every_pending_member() {
    with_repo(|dir| {
        set_env("SOPSY_ASSUME_YES", Some(Path::new("1")));
        let sopsy = "recipients:\n  - name: alice\n    public_key: age1alice\n  \
            - name: bob\n    public_key: age1bob\n    state: pending\n  \
            - name: colin\n    public_key: age1colin\n    state: pending\n";
        flow_repo(dir, Some(sopsy), Some(SOPS_ALICE_ONLY));
        // No names => walk the whole pending queue and approve each.
        approve::run(
            &test_ui(),
            &ApproveArgs {
                names: vec![],
                force: false,
                no_updatekeys: true,
            },
        )
        .expect("interactive approve of all pending should succeed");
        let cfg = Config::load_from_dir(dir).unwrap();
        assert_eq!(cfg.recipient("bob").unwrap().state, MemberState::Active);
        assert_eq!(cfg.recipient("colin").unwrap().state, MemberState::Active);
        set_env("SOPSY_ASSUME_YES", None);
    });
}

#[test]
#[serial]
fn approve_interactive_skips_stale_and_errors_when_nothing_approved() {
    with_repo(|dir| {
        // bob's request is far older than the 1h window; with no --force the
        // interactive walk skips him, leaving nothing to approve.
        let sopsy = "recipients:\n  - name: alice\n    public_key: age1alice\n  \
            - name: bob\n    public_key: age1bob\n    state: pending\n    \
            requested_at: 2020-01-01T00:00:00Z\njoin_request_ttl: 1h\n";
        flow_repo(dir, Some(sopsy), Some(SOPS_ALICE_ONLY));
        let err = approve::run(
            &test_ui(),
            &ApproveArgs {
                names: vec![],
                force: false,
                no_updatekeys: true,
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains("nothing approved")));
        // bob stays pending; nothing was written.
        let cfg = Config::load_from_dir(dir).unwrap();
        assert_eq!(cfg.recipient("bob").unwrap().state, MemberState::Pending);
    });
}

#[test]
#[serial]
fn approve_deduplicates_repeated_names() {
    with_repo(|dir| {
        set_env("SOPSY_ASSUME_YES", Some(Path::new("1")));
        flow_repo(
            dir,
            Some(&sopsy_with_pending_bob("")),
            Some(SOPS_ALICE_ONLY),
        );
        // The same name passed twice collapses to a single approval.
        approve::run(
            &test_ui(),
            &ApproveArgs {
                names: vec!["bob".into(), "bob".into()],
                force: false,
                no_updatekeys: true,
            },
        )
        .expect("repeated names should dedupe and succeed");
        let cfg = Config::load_from_dir(dir).unwrap();
        assert_eq!(cfg.recipient("bob").unwrap().state, MemberState::Active);
        set_env("SOPSY_ASSUME_YES", None);
    });
}

#[test]
#[serial]
fn join_then_batch_approve_handles_multiword_names() {
    with_repo(|dir| {
        set_env("SOPSY_ASSUME_YES", Some(Path::new("1")));
        // Start from a repo where alice is already an active member.
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));

        // Two engineers request access using their full names (quoted on the CLI).
        for (name, key) in [
            ("Konstantin Gredeskoul", "age1konstantin"),
            ("Colin Powell", "age1colin"),
        ] {
            join::run(
                &test_ui(),
                &JoinArgs {
                    name: name.into(),
                    username: None,
                    sopsy_file: None,
                    public_key: Some(key.into()),
                    without_touch_id: false,
                    age_args: vec![],
                },
            )
            .expect("join with a multi-word name should succeed");
        }
        let cfg = Config::load_from_dir(dir).unwrap();
        assert!(cfg.recipient("Konstantin Gredeskoul").unwrap().is_pending());
        assert!(cfg.recipient("Colin Powell").unwrap().is_pending());

        // An existing engineer approves both in one shot.
        approve::run(
            &test_ui(),
            &ApproveArgs {
                names: vec!["Konstantin Gredeskoul".into(), "Colin Powell".into()],
                force: false,
                no_updatekeys: true,
            },
        )
        .expect("batch approve of multi-word names should succeed");

        let cfg = Config::load_from_dir(dir).unwrap();
        assert_eq!(
            cfg.recipient("Konstantin Gredeskoul").unwrap().state,
            MemberState::Active
        );
        assert_eq!(
            cfg.recipient("Colin Powell").unwrap().state,
            MemberState::Active
        );
        set_env("SOPSY_ASSUME_YES", None);
    });
}

#[test]
#[serial]
fn join_defaults_username_to_system_user() {
    with_repo(|dir| {
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        let saved_user = std::env::var("USER").ok();
        set_env("USER", Some(Path::new("kig")));

        join::run(
            &test_ui(),
            &JoinArgs {
                name: "Konstantin Gredeskoul".into(),
                username: None,
                sopsy_file: None,
                public_key: Some("age1konstantin".into()),
                without_touch_id: false,
                age_args: vec![],
            },
        )
        .expect("join should succeed");

        let cfg = Config::load_from_dir(dir).unwrap();
        assert_eq!(
            cfg.recipient("Konstantin Gredeskoul")
                .unwrap()
                .username
                .as_deref(),
            Some("kig"),
            "with no --username, join records $USER"
        );

        match &saved_user {
            Some(u) => set_env("USER", Some(Path::new(u))),
            None => set_env("USER", None),
        }
    });
}

#[test]
#[serial]
fn approve_records_approver_provenance() {
    with_repo(|dir| {
        // The approver's $USER matches an active member's `username`, so the
        // provenance reads "Full Name (username)".
        let sopsy = "recipients:\n  \
            - name: Konstantin Gredeskoul\n    public_key: age1kig\n    username: kig\n  \
            - name: bob\n    public_key: age1bob\n    state: pending\n";
        flow_repo(dir, Some(sopsy), Some(SOPS_ALICE_ONLY));
        set_env("SOPSY_ASSUME_YES", Some(Path::new("1")));
        let saved_user = std::env::var("USER").ok();
        set_env("USER", Some(Path::new("kig")));

        approve::run(
            &test_ui(),
            &ApproveArgs {
                names: vec!["bob".into()],
                force: false,
                no_updatekeys: true,
            },
        )
        .expect("approve should succeed");

        let cfg = Config::load_from_dir(dir).unwrap();
        let bob = cfg.recipient("bob").unwrap();
        assert_eq!(
            bob.approved_by.as_deref(),
            Some("Konstantin Gredeskoul (kig)"),
            "approver resolves to `Full Name (username)`"
        );
        assert!(bob.approved_at.is_some(), "approval date must be recorded");

        match &saved_user {
            Some(u) => set_env("USER", Some(Path::new(u))),
            None => set_env("USER", None),
        }
        set_env("SOPSY_ASSUME_YES", None);
    });
}

#[test]
#[serial]
fn list_shows_username_and_approval_provenance() {
    let dir = TempDir::new().unwrap();
    git_init(dir.path());
    // A hand-written fixture (no `.sopsy.sha` — legacy configs must still
    // list): one approved member with long name/username to exercise the
    // column caps, and one pending member.
    let body = "recipients:\n  \
        - name: A Very Long Recipient Name Indeed\n    public_key: age1admin\n    \
        username: konstantingredeskoul\n    \
        approved_by: Konstantin Gredeskoul (kig)\n    \
        approved_at: 2026-07-01T12:00:00Z\n  \
        - name: bob\n    public_key: age1bob\n    state: pending\n";
    std::fs::write(dir.path().join(".sopsy.yml"), body).unwrap();

    let output = assert_cmd::Command::cargo_bin("sopsy")
        .unwrap()
        .args(["recipient", "list"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "recipient list should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);

    for header in [
        "NAME",
        "USERNAME",
        "PUBLIC KEY",
        "BREAK-GLASS",
        "APPROVED BY",
    ] {
        assert!(
            stdout.contains(header),
            "missing {header} column:\n{stdout}"
        );
    }
    // Names cap at 21 chars, usernames at 12 — both marked with an ellipsis.
    assert!(
        stdout.contains("A Very Long Recipient…"),
        "name should truncate at 21 chars:\n{stdout}"
    );
    assert!(
        stdout.contains("konstantingr…"),
        "username should truncate at 12 chars:\n{stdout}"
    );
    // Provenance renders as `Full Name (username) on YYYY-MM-DD`.
    assert!(
        stdout.contains("Konstantin Gredeskoul (kig) on 2026-07-01"),
        "approved-by cell should show approver and date:\n{stdout}"
    );
    assert!(
        stdout.contains("(pending)"),
        "pending members should read as awaiting approval:\n{stdout}"
    );
}

#[test]
#[serial]
fn approve_with_no_pending_members_errors() {
    with_repo(|dir| {
        // SOPSY_TWO has only active members; bare `approve` finds nothing to do.
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        let err = approve::run(
            &test_ui(),
            &ApproveArgs {
                names: vec![],
                force: false,
                no_updatekeys: true,
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::Validation(m) if m.contains("no pending requests to approve"))
        );
    });
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

#[test]
#[serial]
fn add_rolls_back_when_reencryption_fails() {
    let original_cwd = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();

    let (a_pub, _a_file) = generate_age_key(dir.path(), "keyA.txt");
    git_init(dir.path());
    write_sops_yaml(dir.path(), &a_pub);
    write_sopsy_yml(dir.path(), &a_pub);
    // A stand-in encrypted file so the re-key walk has something to act on.
    std::fs::write(dir.path().join(".env.encrypted"), "FOO=ENC[fake]\n").unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    // Fake `sops` that fails every invocation, simulating an operator who cannot
    // decrypt the existing secrets (no usable age key for `updatekeys`).
    let fake = dir.path().join("fake-sops.sh");
    std::fs::write(&fake, "#!/bin/sh\necho 'cannot get data key' >&2\nexit 1\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    unsafe {
        std::env::set_var("SOPSY_SOPS_BIN", &fake);
    }

    let new_key = "age1rollbackkeyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    let err = recipient::run(&test_ui(), &add_command("second", new_key, false, false))
        .expect_err("recipient add must fail when re-encryption fails");
    let msg = err.to_string();
    assert!(
        msg.contains("SOPS_AGE_KEY_FILE") && msg.contains("rolled back"),
        "error should guide the operator and mention rollback: {msg}"
    );

    // The repository must be left consistent: neither config file lists the key.
    let config = Config::load_from_dir(dir.path()).unwrap();
    assert!(
        config.recipient("second").is_none(),
        "`second` must not remain in .sopsy.yml after rollback"
    );
    let sops_yaml = std::fs::read_to_string(dir.path().join(".sops.yaml")).unwrap();
    assert!(
        !sops_yaml.contains(new_key),
        ".sops.yaml must not list the new key after rollback"
    );

    unsafe {
        std::env::remove_var("SOPSY_SOPS_BIN");
    }
    restore_cwd(&original_cwd);
}

/// A fake `sops` that re-wraps every file *except* one ending in `b.encrypted`
/// (which it fails on), letting a test drive a mid-loop `updatekeys` failure. On
/// success it overwrites the target with a sentinel, so a test can prove the
/// pre-command bytes were restored (not the re-wrapped ones).
const SELECTIVE_FAKE_SOPS: &str = "for f in \"$@\"; do target=\"$f\"; done\n\
     case \"$target\" in\n\
     \x20 *b.encrypted) echo 'cannot get data key' >&2; exit 1 ;;\n\
     \x20 *) printf 'REWRAPPED-BY-FAKE\\n' > \"$target\"; exit 0 ;;\n\
     esac\n";

#[test]
#[serial]
fn add_rollback_restores_already_rewrapped_bodies() {
    let original_cwd = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();

    let (a_pub, _a_file) = generate_age_key(dir.path(), "keyA.txt");
    git_init(dir.path());
    write_sops_yaml(dir.path(), &a_pub);
    write_sopsy_yml(dir.path(), &a_pub);

    // Two managed encrypted files (both match the default `*.encrypted` glob and
    // carry the `ENC[` marker). `collect_encrypted_files` sorts, so `a.encrypted`
    // is re-wrapped (by the fake `sops`) *before* `b.encrypted` fails.
    std::fs::write(dir.path().join("a.encrypted"), "A=ENC[a]\n").unwrap();
    std::fs::write(dir.path().join("b.encrypted"), "B=ENC[b]\n").unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let fake = dir.path().join("fake-sops.sh");
    write_script(&fake, SELECTIVE_FAKE_SOPS);
    unsafe {
        std::env::set_var("SOPSY_SOPS_BIN", &fake);
    }

    let new_key = "age1rollbackkeyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    let err = recipient::run(&test_ui(), &add_command("second", new_key, false, false))
        .expect_err("recipient add must fail when re-encryption fails");
    assert!(matches!(err, Error::Validation(m) if m.contains("rolled back")));

    // The already-re-wrapped `a.encrypted` must be rolled back to its original
    // bytes — not left carrying the fake's re-wrap (the bug this test guards).
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.encrypted")).unwrap(),
        "A=ENC[a]\n",
        "a.encrypted must be restored to its pre-command bytes after rollback"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("b.encrypted")).unwrap(),
        "B=ENC[b]\n"
    );

    // And the config files are rolled back as before.
    let config = Config::load_from_dir(dir.path()).unwrap();
    assert!(config.recipient("second").is_none());
    let sops_yaml = std::fs::read_to_string(dir.path().join(".sops.yaml")).unwrap();
    assert!(!sops_yaml.contains(new_key));

    unsafe {
        std::env::remove_var("SOPSY_SOPS_BIN");
    }
    restore_cwd(&original_cwd);
}

#[test]
#[serial]
fn remove_rollback_restores_already_rewrapped_bodies() {
    let original_cwd = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();

    let (a_pub, _a_file) = generate_age_key(dir.path(), "keyA.txt");
    git_init(dir.path());
    write_sops_yaml(dir.path(), &a_pub);
    write_sopsy_yml(dir.path(), &a_pub);
    std::env::set_current_dir(dir.path()).unwrap();

    // Register a second recipient (config-only, no re-key) so `remove` clears the
    // "last recipient" safety rail.
    let second_key = "age1secondkeyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    recipient::run(&test_ui(), &add_command("second", second_key, false, true))
        .expect("recipient add (--no-updatekeys) should succeed");

    std::fs::write(dir.path().join("a.encrypted"), "A=ENC[a]\n").unwrap();
    std::fs::write(dir.path().join("b.encrypted"), "B=ENC[b]\n").unwrap();

    let fake = dir.path().join("fake-sops.sh");
    write_script(&fake, SELECTIVE_FAKE_SOPS);
    unsafe {
        std::env::set_var("SOPSY_SOPS_BIN", &fake);
    }

    let err = recipient::run(&test_ui(), &remove_command("second", false))
        .expect_err("recipient remove must fail when re-encryption fails");
    assert!(matches!(err, Error::Validation(m) if m.contains("rolled back")));

    // The already-re-wrapped `a.encrypted` must be restored — otherwise the
    // removed recipient is silently stripped from a subset of files (a partial
    // revocation) while the config claims they are still a member.
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.encrypted")).unwrap(),
        "A=ENC[a]\n",
        "a.encrypted must be restored to its pre-command bytes after rollback"
    );

    // `second` is rolled back into both config files.
    let config = Config::load_from_dir(dir.path()).unwrap();
    assert!(
        config.recipient("second").is_some(),
        "`second` must remain a recipient after rollback"
    );
    let sops_yaml = std::fs::read_to_string(dir.path().join(".sops.yaml")).unwrap();
    assert!(
        sops_yaml.contains(second_key),
        ".sops.yaml must still list `second`'s key after rollback"
    );

    unsafe {
        std::env::remove_var("SOPSY_SOPS_BIN");
    }
    restore_cwd(&original_cwd);
}

// ---------------------------------------------------------------------------
// Config-driven flow tests. These do not need real `sops`: they either pass
// `--no-updatekeys`, exercise pure-config validation that returns before any
// re-encryption, or use a fake `sops` binary. Each builds a tiny git repo and
// drives `recipient::run` in-process so command logic counts toward coverage.
// ---------------------------------------------------------------------------

/// A `.sopsy.yml` with two recipients: `alice` (break-glass) and `bob`.
const SOPSY_TWO: &str = "recipients:\n  \
    - name: alice\n    public_key: age1alice\n    break_glass: true\n  \
    - name: bob\n    public_key: age1bob\n    break_glass: false\n";

/// A `.sops.yaml` whose single rule's `age:` value contains only alice's key
/// (canonical comma-separated string form).
const SOPS_ALICE_ONLY: &str = "creation_rules:\n  - path_regex: \\.enc$\n    age: age1alice\n";

/// Build a git repo in `dir`, optionally writing `.sopsy.yml`/`.sops.yaml`,
/// and switch the process cwd into it.
fn flow_repo(dir: &Path, sopsy_yml: Option<&str>, sops_yaml: Option<&str>) {
    git_init(dir);
    if let Some(body) = sopsy_yml {
        std::fs::write(dir.join(".sopsy.yml"), body).unwrap();
    }
    if let Some(body) = sops_yaml {
        std::fs::write(dir.join(".sops.yaml"), body).unwrap();
    }
    std::env::set_current_dir(dir).unwrap();
}

fn add_args(
    name: Option<&str>,
    key: Option<&str>,
    break_glass: bool,
    no_updatekeys: bool,
) -> RecipientCommand {
    RecipientCommand::Add(RecipientAddArgs {
        name_pos: None,
        name: name.map(str::to_string),
        public_key: key.map(str::to_string),
        break_glass,
        no_updatekeys,
    })
}

fn remove_args(name: Option<&str>, no_updatekeys: bool) -> RecipientCommand {
    RecipientCommand::Remove(RecipientRemoveArgs {
        name_pos: None,
        name: name.map(str::to_string),
        no_updatekeys,
    })
}

/// Restores the process cwd when dropped, so a panicking assertion inside a
/// test body cannot strand later `#[serial]` tests in a deleted temp dir.
struct CwdGuard(PathBuf);

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.0);
    }
}

/// Run a closure with the cwd restored afterwards regardless of the outcome.
///
/// The guard is declared before `dir` so that on unwind `dir` (the `TempDir`)
/// drops first — deleting the temp directory — and the guard then restores the
/// cwd to the original project directory.
fn with_repo(f: impl FnOnce(&Path)) {
    let _guard = CwdGuard(std::env::current_dir().unwrap());
    let dir = TempDir::new().unwrap();
    f(dir.path());
}

#[test]
#[serial]
fn add_without_sopsy_yml_is_friendly_error() {
    with_repo(|dir| {
        flow_repo(dir, None, Some(SOPS_ALICE_ONLY));
        let err = recipient::run(&test_ui(), &add_args(Some("x"), Some("age1x"), false, true))
            .unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains("sopsy init")));
    });
}

#[test]
#[serial]
fn add_with_invalid_sopsy_yml_propagates_parse_error() {
    with_repo(|dir| {
        flow_repo(
            dir,
            Some("recipients: [unterminated\n"),
            Some(SOPS_ALICE_ONLY),
        );
        let err = recipient::run(&test_ui(), &add_args(Some("x"), Some("age1x"), false, true))
            .unwrap_err();
        assert!(matches!(err, Error::Parse { .. }));
    });
}

#[test]
#[serial]
fn add_without_sops_yaml_is_friendly_error() {
    with_repo(|dir| {
        flow_repo(dir, Some(SOPSY_TWO), None);
        let err = recipient::run(&test_ui(), &add_args(Some("x"), Some("age1x"), false, true))
            .unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains(".sops.yaml not found")));
    });
}

#[test]
#[serial]
fn add_missing_name_non_interactive_errors() {
    with_repo(|dir| {
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        let err =
            recipient::run(&test_ui(), &add_args(None, Some("age1x"), false, true)).unwrap_err();
        assert!(matches!(err, Error::NonInteractive { .. }));
    });
}

#[test]
#[serial]
fn add_missing_public_key_non_interactive_errors() {
    with_repo(|dir| {
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        let err =
            recipient::run(&test_ui(), &add_args(Some("carol"), None, false, true)).unwrap_err();
        assert!(matches!(err, Error::NonInteractive { .. }));
    });
}

#[test]
#[serial]
fn add_blank_name_rejected() {
    with_repo(|dir| {
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        let err = recipient::run(
            &test_ui(),
            &add_args(Some("   "), Some("age1x"), false, true),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains("name must not be empty")));
    });
}

#[test]
#[serial]
fn add_blank_public_key_rejected() {
    with_repo(|dir| {
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        let err = recipient::run(
            &test_ui(),
            &add_args(Some("carol"), Some("   "), false, true),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains("public key must not be empty")));
    });
}

#[test]
#[serial]
fn add_duplicate_name_rejected() {
    with_repo(|dir| {
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        let err = recipient::run(
            &test_ui(),
            &add_args(Some("alice"), Some("age1new"), false, true),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains("already exists")));
    });
}

#[test]
#[serial]
fn add_duplicate_key_rejected() {
    with_repo(|dir| {
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        let err = recipient::run(
            &test_ui(),
            &add_args(Some("carol"), Some("age1alice"), false, true),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains("already registered")));
    });
}

#[test]
#[serial]
fn add_warns_when_no_age_rule_matches() {
    with_repo(|dir| {
        // `.sops.yaml` rule has no `age:` list, so the key lands nowhere.
        flow_repo(
            dir,
            Some(SOPSY_TWO),
            Some("creation_rules:\n  - path_regex: \\.enc$\n"),
        );
        recipient::run(
            &test_ui(),
            &add_args(Some("carol"), Some("age1carol"), false, true),
        )
        .expect("add should still record the recipient");
        let config = Config::load_from_dir(dir).unwrap();
        assert!(config.recipient("carol").is_some());
    });
}

#[test]
#[serial]
fn add_break_glass_recipient_records_flag() {
    with_repo(|dir| {
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        recipient::run(
            &test_ui(),
            &add_args(Some("carol"), Some("age1carol"), true, true),
        )
        .expect("add --break-glass should succeed");
        let config = Config::load_from_dir(dir).unwrap();
        assert!(config.recipient("carol").unwrap().break_glass);
    });
}

#[test]
#[serial]
fn remove_missing_name_with_no_recipients_errors() {
    with_repo(|dir| {
        flow_repo(dir, Some("recipients: []\n"), Some(SOPS_ALICE_ONLY));
        let err = recipient::run(&test_ui(), &remove_args(None, true)).unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains("no recipients to remove")));
    });
}

#[test]
#[serial]
fn remove_missing_name_non_interactive_errors() {
    with_repo(|dir| {
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        let err = recipient::run(&test_ui(), &remove_args(None, true)).unwrap_err();
        assert!(matches!(err, Error::NonInteractive { .. }));
    });
}

#[test]
#[serial]
fn remove_unknown_recipient_errors() {
    with_repo(|dir| {
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        let err = recipient::run(&test_ui(), &remove_args(Some("ghost"), true)).unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains("no recipient named")));
    });
}

#[test]
#[serial]
fn remove_last_recipient_refused() {
    with_repo(|dir| {
        flow_repo(
            dir,
            Some("recipients:\n  - name: solo\n    public_key: age1solo\n    break_glass: false\n"),
            Some(SOPS_ALICE_ONLY),
        );
        let err = recipient::run(&test_ui(), &remove_args(Some("solo"), true)).unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains("only remaining recipient")));
    });
}

#[test]
#[serial]
fn remove_sole_break_glass_refused() {
    with_repo(|dir| {
        // alice is the only break-glass recipient; removing her is refused.
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        let err = recipient::run(&test_ui(), &remove_args(Some("alice"), true)).unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains("only break-glass recipient")));
    });
}

#[test]
#[serial]
fn remove_warns_when_key_absent_from_sops_yaml() {
    with_repo(|dir| {
        // bob is removable (not last, not break-glass); his key is not in
        // `.sops.yaml`, exercising the "left unchanged" warning path.
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        recipient::run(&test_ui(), &remove_args(Some("bob"), true))
            .expect("removing bob should succeed");
        let config = Config::load_from_dir(dir).unwrap();
        assert!(config.recipient("bob").is_none());
    });
}

#[test]
#[serial]
fn list_without_sopsy_yml_is_noop() {
    with_repo(|dir| {
        flow_repo(dir, None, None);
        recipient::run(&test_ui(), &RecipientCommand::List).expect("list should succeed");
    });
}

#[test]
#[serial]
fn list_with_invalid_sopsy_yml_errors() {
    with_repo(|dir| {
        flow_repo(dir, Some("recipients: [unterminated\n"), None);
        let err = recipient::run(&test_ui(), &RecipientCommand::List).unwrap_err();
        assert!(matches!(err, Error::Parse { .. }));
    });
}

#[test]
#[serial]
fn list_with_no_recipients_is_noop() {
    with_repo(|dir| {
        flow_repo(dir, Some("recipients: []\n"), None);
        recipient::run(&test_ui(), &RecipientCommand::List).expect("list should succeed");
    });
}

#[test]
#[serial]
fn list_renders_plain_and_colored_tables() {
    with_repo(|dir| {
        // A long key exercises truncation; both UIs render the table in-process.
        let long_key = format!("age1{}", "z".repeat(60));
        let body = format!(
            "recipients:\n  - name: alice\n    public_key: {long_key}\n    break_glass: true\n  \
             - name: bob\n    public_key: age1bob\n    break_glass: false\n"
        );
        flow_repo(dir, Some(&body), None);
        recipient::run(&test_ui(), &RecipientCommand::List).expect("plain list");
        recipient::run(&color_ui(), &RecipientCommand::List).expect("colored list");
    });
}

#[test]
#[serial]
fn add_without_encrypted_files_reports_nothing_to_rekey() {
    with_repo(|dir| {
        // No encrypted files exist, so `run_updatekeys` returns before sops.
        flow_repo(dir, Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
        recipient::run(
            &test_ui(),
            &add_args(Some("carol"), Some("age1carol"), false, false),
        )
        .expect("add should succeed with nothing to re-key");
        let config = Config::load_from_dir(dir).unwrap();
        assert!(config.recipient("carol").is_some());
    });
}

#[test]
#[serial]
fn updatekeys_failure_surfaces_process_error() {
    let original = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();
    flow_repo(dir.path(), Some(SOPSY_TWO), Some(SOPS_ALICE_ONLY));
    // An encrypted file so `run_updatekeys` actually invokes (the fake) sops.
    std::fs::write(dir.path().join("secret.encrypted"), "FOO=ENC[x]\n").unwrap();

    // Fake `sops` that always fails.
    let fake = dir.path().join("fake-sops.sh");
    std::fs::write(&fake, "#!/bin/sh\necho 'boom' >&2\nexit 1\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    unsafe {
        std::env::set_var("SOPSY_SOPS_BIN", &fake);
    }

    let err = recipient::run(
        &test_ui(),
        &add_args(Some("carol"), Some("age1carol"), false, false),
    )
    .unwrap_err();
    // The raw sops failure is wrapped with actionable rollback guidance, and the
    // underlying error text is preserved.
    let msg = err.to_string();
    assert!(
        matches!(err, Error::Validation(_)),
        "updatekeys failure should surface as a rollback validation error: {msg}"
    );
    assert!(
        msg.contains("rolled back") && msg.contains("boom"),
        "error should mention rollback and include the sops error: {msg}"
    );
    // The config change is rolled back: carol is not left behind.
    let config = Config::load_from_dir(dir.path()).unwrap();
    assert!(
        config.recipient("carol").is_none(),
        "carol must be rolled back out of .sopsy.yml"
    );

    unsafe {
        std::env::remove_var("SOPSY_SOPS_BIN");
    }
    restore_cwd(&original);
}
