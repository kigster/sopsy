//! Integration tests for [`sopsy::hardware::yubikey`].
//!
//! Real YubiKey identity generation needs a physical key, a PIN and a touch, so
//! these drive a **fake** `age-plugin-yubikey` shell script injected via the
//! `SOPSY_AGE_PLUGIN_YUBIKEY_BIN` environment variable. The fake records the
//! arguments and locale it was called with so the tests can assert on them.
//! That env var is process-wide, so the tests are `#[serial]`.

use std::path::{Path, PathBuf};

use assert_fs::TempDir;
use serial_test::serial;
use sopsy::error::Error;
use sopsy::hardware::Store;
use sopsy::hardware::yubikey::{self, GenerateOptions, PinPolicy, TouchPolicy};

/// Identity-file output as printed by `--generate` / `--identity`.
const IDENTITY: &str = "\
#       Serial: 12345678, Slot: 3
#         Name: sopsy-kig
#      Created: Wed, 28 Oct 2026 17:00:00 +0000
#   PIN policy: Once   (A PIN is required once per session, if set)
# Touch policy: Cached (A physical touch is required for decryption, and is cached for 15 seconds)
#    Recipient: age1tag1qfakerecipient
AGE-PLUGIN-YUBIKEY-1QFAKESTUB
";

/// Recipient output as printed by `--list`.
const LIST: &str = "\
#       Serial: 12345678, Slot: 1
#         Name: age identity 1a2b3c4d
#      Created: Sun, 01 Jan 2023 00:00:00 +0000
#   PIN policy: Always (A PIN is required for every decryption, if set)
# Touch policy: Always (A physical touch is required for every decryption)
# Legacy recipient: age1yubikey1qlegacy
age1tag1qtagform

";

/// Write an executable fake plugin to `dir`. It logs `LC_ALL` and its
/// arguments to `calls.log`, then runs `body`.
fn write_fake_plugin(dir: &Path, body: &str) -> PathBuf {
    let script = dir.join("age-plugin-yubikey");
    let log = dir.join("calls.log");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\necho \"LC_ALL=$LC_ALL $*\" >> '{}'\n{body}",
            log.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
    }
    script
}

/// A fake that prints `stdout` verbatim and exits 0.
fn fake_printing(dir: &Path, stdout: &str) -> PathBuf {
    write_fake_plugin(dir, &format!("cat <<'EOF'\n{stdout}EOF\n"))
}

fn calls(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("calls.log")).unwrap_or_default()
}

/// Run `f` with the plugin env var pointing at `script`, restoring it after.
fn with_plugin<T>(script: &Path, f: impl FnOnce() -> T) -> T {
    // SAFETY: every caller is `#[serial]`.
    unsafe { std::env::set_var(yubikey::PLUGIN_BIN_ENV, script) };
    let result = f();
    // SAFETY: see above.
    unsafe { std::env::remove_var(yubikey::PLUGIN_BIN_ENV) };
    result
}

#[test]
#[serial]
fn generate_passes_policies_and_parses_identity() {
    let dir = TempDir::new().unwrap();
    let script = fake_printing(dir.path(), IDENTITY);

    let mut opts = GenerateOptions::new("sopsy-kig");
    opts.serial = Some(12345678);
    opts.slot = Some(3);
    let id = with_plugin(&script, || {
        yubikey::ensure_available().unwrap();
        yubikey::generate(&opts, &["--force".to_string()]).unwrap()
    });

    assert_eq!(id.store, Store::YubiKey);
    assert_eq!(id.public_key, "age1tag1qfakerecipient");
    assert_eq!(id.identity, "AGE-PLUGIN-YUBIKEY-1QFAKESTUB");
    assert_eq!(
        calls(dir.path()).trim(),
        "LC_ALL=C --generate --name=sopsy-kig --pin-policy=once --touch-policy=cached \
         --serial=12345678 --slot=3 --force"
    );
}

#[test]
#[serial]
fn identity_for_rederives_an_existing_slot() {
    let dir = TempDir::new().unwrap();
    let script = fake_printing(dir.path(), IDENTITY);

    let id = with_plugin(&script, || yubikey::identity_for(12345678, 3).unwrap());

    assert_eq!(id.identity, "AGE-PLUGIN-YUBIKEY-1QFAKESTUB");
    assert_eq!(
        calls(dir.path()).trim(),
        "LC_ALL=C --identity --serial=12345678 --slot=3"
    );
}

#[test]
#[serial]
fn list_reports_connected_identities() {
    let dir = TempDir::new().unwrap();
    let script = fake_printing(dir.path(), LIST);

    let (list, list_all) = with_plugin(&script, || {
        (yubikey::list(false).unwrap(), yubikey::list(true).unwrap())
    });

    assert_eq!(list, list_all);
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].preferred_recipient(), "age1yubikey1qlegacy");
    assert!(list[0].matches_policies(PinPolicy::Always, TouchPolicy::Always));
    let log = calls(dir.path());
    assert!(log.contains("LC_ALL=C --list\n"), "{log}");
    assert!(log.contains("LC_ALL=C --list-all\n"), "{log}");
}

#[test]
#[serial]
fn list_with_no_yubikey_is_empty() {
    let dir = TempDir::new().unwrap();
    let script = write_fake_plugin(dir.path(), "exit 0\n");

    let list = with_plugin(&script, || yubikey::list(false).unwrap());

    assert!(list.is_empty());
}

#[test]
#[serial]
fn nonzero_exit_surfaces_stderr() {
    let dir = TempDir::new().unwrap();
    let script = write_fake_plugin(dir.path(), "echo 'no YubiKey found' 1>&2\nexit 2\n");

    let err = with_plugin(&script, || {
        yubikey::generate(&GenerateOptions::new("x"), &[]).unwrap_err()
    });

    match err {
        Error::ProcessFailed {
            tool,
            code,
            message,
        } => {
            assert_eq!(tool, yubikey::PLUGIN_BIN);
            assert_eq!(code, 2);
            assert_eq!(message, "no YubiKey found");
        }
        other => panic!("expected ProcessFailed, got {other:?}"),
    }
}

#[test]
#[serial]
fn missing_plugin_is_tool_not_found() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("does-not-exist");

    let err = with_plugin(&missing, || yubikey::ensure_available().unwrap_err());

    match err {
        Error::ToolNotFound(msg) => assert!(msg.contains("brew install age-plugin-yubikey")),
        other => panic!("expected ToolNotFound, got {other:?}"),
    }
}
