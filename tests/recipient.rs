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
    std::fs::write(dir.path().join("secret.enc"), "FOO=ENC[x]\n").unwrap();

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
