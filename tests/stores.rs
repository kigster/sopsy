//! Integration tests for private-key stores (`--store`, `auto`, and the
//! repository's `key_policy.required` allowed set), through the real binary.
//!
//! `file` and `keychain` run against the real `sops` + `age` so a decrypt
//! round-trip proves `sops` finds the key. The keychain itself and the YubiKey
//! are faked (`SOPSY_KEYCHAIN_BIN`, `SOPSY_AGE_PLUGIN_YUBIKEY_BIN`,
//! `SOPSY_USB_LIST_BIN`), so nothing here touches real hardware or keyrings.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use assert_cmd::Command;
use assert_fs::TempDir;
use predicates::prelude::*;

const PLAINTEXT: &str = "PASSWORD=hunter2\n"; // pragma: allowlist secret

fn write_script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn git_repo(dir: &Path) {
    for args in [
        &["init", "-q"][..],
        &["config", "user.email", "test@example.com"],
        &["config", "user.name", "Sopsy Test"],
    ] {
        assert!(
            StdCommand::new("git")
                .arg("-C")
                .arg(dir)
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
}

/// A test sandbox: a git repo with a seed `.env`, its own keys file, no USB
/// YubiKey, and a stateful fake keyring that logs its arguments.
struct Sandbox {
    dir: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        git_repo(dir.path());
        std::fs::write(dir.path().join(".env"), PLAINTEXT).unwrap();
        // Speaks both `security -i` (macOS) and `secret-tool` (Linux), storing
        // a single secret in a file.
        write_script(
            &dir.path().join("fake-keyring"),
            &format!(
                "dir='{d}'\necho \"$@\" >> \"$dir/keyring.log\"\n\
                 case \"$1\" in\n\
                 -i) awk '{{print $NF}}' > \"$dir/keyring.secret\";;\n\
                 store) cat > \"$dir/keyring.secret\";;\n\
                 find-generic-password|lookup) [ -s \"$dir/keyring.secret\" ] && cat \"$dir/keyring.secret\" || exit 44;;\n\
                 esac\n",
                d = dir.path().display()
            ),
        );
        write_script(&dir.path().join("no-usb"), "echo 'Apple Keyboard'\n");
        Self { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn keys_file(&self) -> PathBuf {
        self.path().join("age-keys.txt")
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.path().join(name)).unwrap_or_default()
    }

    fn sopsy(&self) -> Command {
        let mut cmd = Command::cargo_bin("sopsy").unwrap();
        cmd.current_dir(self.path())
            .env("SOPSY_KEYS_FILE", self.keys_file())
            .env("SOPSY_KEYCHAIN_BIN", self.path().join("fake-keyring"))
            .env("SOPSY_USB_LIST_BIN", self.path().join("no-usb"))
            .env(
                "SOPSY_AGE_PLUGIN_SE_BIN",
                self.path().join("no-such-plugin"),
            )
            .env_remove("SOPSY_PRIVATE_KEY_STORE_PRIORITY")
            .env_remove("SOPS_AGE_KEY")
            .env_remove("SOPS_AGE_KEY_FILE")
            .arg("--non-interactive");
        cmd
    }

    /// `secrets decrypt .env.encrypted` must print the seed back.
    fn assert_decrypts(&self) {
        self.sopsy()
            .args(["secrets", "decrypt", ".env.encrypted"])
            .assert()
            .success()
            .stdout(predicate::str::contains("PASSWORD=hunter2"));
    }
}

#[test]
fn file_store_round_trips_and_warns() {
    let sb = Sandbox::new();
    sb.sopsy()
        .args(["init", "--store", "file", "--no-emergency-keys"])
        .assert()
        .success()
        .stdout(predicate::str::contains("PLAINTEXT"));

    assert!(sb.read("age-keys.txt").contains("AGE-SECRET-KEY-1"));
    assert!(sb.read(".sopsy.yml").contains("store: file"));
    assert!(!sb.read(".sopsy.yml").contains("key_policy"));
    sb.assert_decrypts();
}

#[test]
fn keychain_store_keeps_the_secret_off_disk_and_out_of_argv() {
    let sb = Sandbox::new();
    sb.sopsy()
        .args(["init", "--store", "keychain", "--no-emergency-keys"])
        .assert()
        .success();

    let keys = sb.read("age-keys.txt");
    assert!(keys.contains("# sopsy-keychain: age1"), "{keys}");
    assert!(!keys.contains("AGE-SECRET-KEY"), "secret leaked to disk");
    assert!(sb.read("keyring.secret").starts_with("AGE-SECRET-KEY-1"));
    assert!(!sb.read("keyring.log").contains("AGE-SECRET-KEY"));
    assert!(sb.read(".sopsy.yml").contains("store: keychain"));
    // sopsy hands the keyring secret to sops via SOPS_AGE_KEY.
    sb.assert_decrypts();
}

#[test]
fn auto_falls_back_through_the_priority_list() {
    let sb = Sandbox::new();
    // No enclave and no YubiKey here; keychain is next.
    sb.sopsy()
        .env("SOPSY_PRIVATE_KEY_STORE_PRIORITY", "exthardware,software")
        .args(["init", "--no-emergency-keys"])
        .assert()
        .success();
    assert!(sb.read(".sopsy.yml").contains("store: keychain"));

    let sb = Sandbox::new();
    sb.sopsy()
        .env("SOPSY_PRIVATE_KEY_STORE_PRIORITY", "exthardware")
        .args(["init", "--no-emergency-keys"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no usable key store"));
}

#[test]
fn yubikey_store_records_stub_and_recipient() {
    let sb = Sandbox::new();
    let p = sb.path();
    write_script(&p.join("usb"), "echo '+-o YubiKey OTP+FIDO+CCID@1'\n");
    write_script(
        &p.join("age-plugin-yubikey"),
        &format!(
            "echo \"$@\" >> '{log}'\n\
             case \"$*\" in *--list*) exit 0;; esac\n\
             cat <<'EOF'\n\
             #       Serial: 12345678, Slot: 1\n\
             #   PIN policy: Once   (x)\n\
             # Touch policy: Cached (x)\n\
             #    Recipient: age1tag1qfake\n\
             # Legacy recipient: age1yubikey1qfakelegacy\n\
             AGE-PLUGIN-YUBIKEY-1QFAKESTUB\n\
             EOF\n",
            log = p.join("yk.log").display()
        ),
    );
    write_script(
        &p.join("sops"),
        "case \"$1\" in --version) echo 'sops 9.9.9';; *) echo 'ENC[fake]';; esac\n",
    );

    sb.sopsy()
        .env("SOPSY_USB_LIST_BIN", p.join("usb"))
        .env("SOPSY_AGE_PLUGIN_YUBIKEY_BIN", p.join("age-plugin-yubikey"))
        .env("SOPSY_SOPS_BIN", p.join("sops"))
        .args([
            "init",
            "--require",
            "exthardware",
            "--yubikey-pin-policy",
            "always",
            "--no-emergency-keys",
        ])
        .assert()
        .success();

    let config = sb.read(".sopsy.yml");
    assert!(config.contains("age1yubikey1qfakelegacy"), "{config}");
    assert!(config.contains("store: yubikey"));
    assert!(config.contains("key_policy:") && config.contains("- exthardware"));
    assert!(
        sb.read("age-keys.txt")
            .contains("AGE-PLUGIN-YUBIKEY-1QFAKESTUB")
    );
    let calls = sb.read("yk.log");
    assert!(
        calls.contains("--list"),
        "checks for a reusable key: {calls}"
    );
    assert!(calls.contains("--generate") && calls.contains("--pin-policy=always"));
}

#[test]
fn several_yubikeys_need_a_serial_when_not_interactive() {
    let sb = Sandbox::new();
    let p = sb.path();
    write_script(
        &p.join("usb"),
        "echo 'YubiKey OTP+FIDO+CCID@1'\necho 'YubiKey OTP+FIDO+CCID@2'\n",
    );
    write_script(&p.join("age-plugin-yubikey"), "exit 0\n");
    sb.sopsy()
        .env("SOPSY_USB_LIST_BIN", p.join("usb"))
        .env("SOPSY_AGE_PLUGIN_YUBIKEY_BIN", p.join("age-plugin-yubikey"))
        .args(["init", "-s", "yubikey", "--no-emergency-keys"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("2 YubiKeys are plugged in"));
}

#[test]
fn init_rejects_stores_outside_the_allowed_set() {
    let sb = Sandbox::new();
    sb.sopsy()
        .args(["init", "--require", "yubikey,keychain", "--store", "file"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("allows only: yubikey, keychain"));
    assert!(!sb.path().join(".sopsy.yml").exists());

    sb.sopsy()
        .args(["init", "--require", "tpm"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown key store or group `tpm`"));
}

#[test]
fn init_rejects_a_pasted_non_key() {
    let sb = Sandbox::new();
    sb.sopsy()
        .args(["init", "--age-public-key", "n"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not an age public key"));
}

#[test]
fn join_and_approve_honor_the_allowed_set() {
    let sb = Sandbox::new();
    sb.sopsy()
        .args([
            "init",
            "--require",
            "software",
            "--store",
            "file",
            "--no-emergency-keys",
        ])
        .assert()
        .success();

    // A Secure Enclave key is outside `software`.
    sb.sopsy()
        .args(["join", "annie", "--age-public-key", "age1se1qannie"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("allows only: keychain, file"));

    // A plain key must declare its store.
    sb.sopsy()
        .args(["join", "annie", "--age-public-key", "age1qannie"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("pass --store"));

    // Generated in the keychain: allowed, and recorded.
    sb.sopsy()
        .args(["join", "colin", "--store", "keychain"])
        .assert()
        .success();
    assert!(sb.read(".sopsy.yml").contains("store: keychain"));

    // A hand-edited pending entry outside the set is refused at approval.
    let edited = sb
        .read(".sopsy.yml")
        .replace("store: keychain", "store: enclave");
    std::fs::write(sb.path().join(".sopsy.yml"), edited).unwrap();
    std::fs::remove_file(sb.path().join(".sopsy.sha")).unwrap();
    sb.sopsy()
        .env("SOPSY_ASSUME_YES", "1")
        .args(["approve", "colin"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "`colin`: key store `enclave` is not allowed",
        ));
}

#[test]
fn without_touch_id_is_rejected_for_software_stores() {
    let sb = Sandbox::new();
    sb.sopsy()
        .args(["init", "--store", "file", "--no-emergency-keys"])
        .assert()
        .success();
    sb.sopsy()
        .args(["join", "annie", "--store", "keychain", "--without-touch-id"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("hardware stores only"));
}

#[test]
fn keygen_saves_software_keys_instead_of_printing_them() {
    let sb = Sandbox::new();
    sb.sopsy()
        .args(["recipient", "keygen", "--store", "file"])
        .assert()
        .success()
        .stdout(predicate::str::contains("AGE-SECRET-KEY").not());
    assert!(sb.read("age-keys.txt").contains("AGE-SECRET-KEY-1"));
}

#[test]
fn doctor_lists_key_stores() {
    let sb = Sandbox::new();
    sb.sopsy()
        .env("SOPSY_PRIVATE_KEY_STORE_PRIORITY", "keychain,file")
        .arg("doctor")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Key stores")
                .and(predicate::str::contains("yubikey (YubiKey, hardware)"))
                .and(predicate::str::contains("auto would use: keychain")),
        );
}
