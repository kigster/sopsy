//! Integration tests for private-key stores (`--store`, `auto`, and the
//! repository's `key_policy.allowed` allowed set), through the real binary.
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
        cmd.env("SOPSY_BREW_BIN", "/nonexistent/sopsy-test-brew"); // never run a real `brew` from tests
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

/// Sandbox machines have no Enclave plugin and no YubiKey. On Linux that makes
/// both hardware stores Unavailable, so the implicit default must refuse to
/// weaken the policy. Apple Silicon reports the Enclave as MissingTool instead.
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
#[test]
fn init_without_allow_stores_fails_when_no_hardware_store_is_available() {
    let sb = Sandbox::new();
    sb.sopsy()
        .args(["init", "--no-emergency-keys"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--allow-stores any"))
        .stderr(predicate::str::contains("--allow-stores software"));
    assert!(
        !sb.path().join(".sopsy.yml").exists(),
        "must not write an unrestricted policy just because hardware is missing"
    );
}

#[test]
fn file_store_round_trips_and_warns() {
    let sb = Sandbox::new();
    sb.sopsy()
        .args([
            "init",
            "--allow-stores",
            "any",
            "--store",
            "file",
            "--no-emergency-keys",
        ])
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
        .args([
            "init",
            "--allow-stores",
            "software",
            "--store",
            "keychain",
            "--no-emergency-keys",
        ])
        .assert()
        .success();

    // sops < 3.11 rejects a key file with no identity, so the keychain index
    // is a sidecar and no keys file is written at all.
    assert!(!sb.keys_file().exists(), "keychain store wrote a keys file");
    let index = sb.read("sopsy-keychain.txt");
    assert!(index.contains("\nage1"), "{index}");
    assert!(!index.contains("AGE-SECRET-KEY"), "secret leaked to disk");
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
        .args(["init", "--allow-stores", "any", "--no-emergency-keys"])
        .assert()
        .success();
    assert!(sb.read(".sopsy.yml").contains("store: keychain"));

    let sb = Sandbox::new();
    sb.sopsy()
        .env("SOPSY_PRIVATE_KEY_STORE_PRIORITY", "exthardware")
        .args(["init", "--allow-stores", "any", "--no-emergency-keys"])
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
            "--allow-stores",
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
fn init_without_allow_stores_defaults_to_hardware_only() {
    let sb = Sandbox::new();
    let p = sb.path();
    write_script(&p.join("usb"), "echo '+-o YubiKey OTP+FIDO+CCID@1'\n");
    write_script(
        &p.join("age-plugin-yubikey"),
        "case \"$*\" in *--list*) exit 0;; esac\n\
         printf '%s\\n' '#       Serial: 12345678, Slot: 1' \
         '#    Recipient: age1tag1qfake' \
         '# Legacy recipient: age1yubikey1qfakelegacy' \
         'AGE-PLUGIN-YUBIKEY-1QFAKESTUB'\n",
    );
    write_script(
        &p.join("sops"),
        "case \"$1\" in --version) echo 'sops 9.9.9';; *) echo 'ENC[fake]';; esac\n",
    );

    sb.sopsy()
        .env("SOPSY_USB_LIST_BIN", p.join("usb"))
        .env("SOPSY_AGE_PLUGIN_YUBIKEY_BIN", p.join("age-plugin-yubikey"))
        .env("SOPSY_SOPS_BIN", p.join("sops"))
        // Pin the order: on Apple Silicon `enclave` would come first, and its
        // plugin is deliberately missing in the sandbox.
        .env("SOPSY_PRIVATE_KEY_STORE_PRIORITY", "yubikey")
        .args(["init", "--no-emergency-keys"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hardware-only"))
        .stdout(predicate::str::contains("--allow-stores any"))
        .stdout(predicate::str::contains("you must touch the YubiKey"))
        .stdout(predicate::str::contains("[!NOTE] You can cache the PIN"));

    let config = sb.read(".sopsy.yml");
    assert!(
        config.contains("key_policy:")
            && config.contains("- onchip")
            && config.contains("- exthardware"),
        "non-interactive default must record hardware only:\n{config}"
    );
    assert!(config.contains("store: yubikey"), "{config}");
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
fn init_allow_stores_any_cannot_mix_with_stores() {
    let sb = Sandbox::new();
    sb.sopsy()
        .args(["init", "--allow-stores", "any,file", "--no-emergency-keys"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be combined"));
}

#[test]
fn init_rejects_stores_outside_the_allowed_set() {
    let sb = Sandbox::new();
    sb.sopsy()
        .args([
            "init",
            "--allow-stores",
            "yubikey,keychain",
            "--store",
            "file",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("allows only: yubikey, keychain"));
    assert!(!sb.path().join(".sopsy.yml").exists());

    sb.sopsy()
        .args(["init", "--allow-stores", "tpm"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown key store or group `tpm`"));
}

#[test]
fn init_refuses_a_broken_sops_yaml_before_generating_a_key() {
    let sb = Sandbox::new();
    std::fs::write(
        sb.path().join(".sops.yaml"),
        "creation_rules:\n  - path_regex: '\\.encrypted$'\n    age: 'n'\n",
    )
    .unwrap();
    sb.sopsy()
        .args([
            "init",
            "--allow-stores",
            "any",
            "-s",
            "file",
            "--no-emergency-keys",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "lists `n`, which is not an age public key",
        ));
    assert!(!sb.keys_file().exists(), "no key may be generated");
}

#[test]
fn init_adds_its_key_to_an_existing_sops_yaml() {
    let sb = Sandbox::new();
    let other = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
    std::fs::write(
        sb.path().join(".sops.yaml"),
        format!("creation_rules:\n  - path_regex: '\\.encrypted$'\n    age: '{other}'\n"),
    )
    .unwrap();
    sb.sopsy()
        .args([
            "init",
            "--allow-stores",
            "any",
            "-s",
            "file",
            "--no-emergency-keys",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Added your key to the existing .sops.yaml",
        ));
    let rules = sb.read(".sops.yaml");
    let config = sb.read(".sopsy.yml");
    let mine = config
        .split_whitespace()
        .find(|w| w.starts_with("age1") && *w != other)
        .unwrap();
    assert!(rules.contains(other) && rules.contains(mine), "{rules}");
    sb.assert_decrypts();
}

#[test]
fn init_rejects_a_pasted_non_key() {
    let sb = Sandbox::new();
    sb.sopsy()
        .args(["init", "--allow-stores", "any", "--age-public-key", "n"])
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
            "--allow-stores",
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
            "a plain age1… key cannot come from the enclave store",
        ));
}

#[test]
fn a_declared_hardware_store_cannot_launder_a_plain_key() {
    let sb = Sandbox::new();
    sb.sopsy()
        .args([
            "init",
            "--allow-stores",
            "exthardware,software",
            "--store",
            "file",
            "--no-emergency-keys",
        ])
        .assert()
        .success();
    // Narrow the policy to hardware only, as an owner might later.
    let narrowed = sb
        .read(".sopsy.yml")
        .replace("- keychain\n", "")
        .replace("- file\n", "");
    assert!(
        !narrowed.contains("- file"),
        "policy edit applied:\n{narrowed}"
    );
    std::fs::write(sb.path().join(".sopsy.yml"), narrowed).unwrap();
    std::fs::remove_file(sb.path().join(".sopsy.sha")).unwrap();

    // A plain X25519 key declared as a YubiKey is refused.
    sb.sopsy()
        .args([
            "join",
            "annie",
            "--age-public-key",
            "age1qannie",
            "--store",
            "yubikey",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "plain age1… key cannot come from the yubikey store",
        ));
    assert!(!sb.read(".sopsy.yml").contains("annie"));
}

#[test]
fn without_touch_id_is_rejected_for_software_stores() {
    let sb = Sandbox::new();
    sb.sopsy()
        .args([
            "init",
            "--allow-stores",
            "any",
            "--store",
            "file",
            "--no-emergency-keys",
        ])
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

#[test]
fn recipient_add_honors_the_allowed_set() {
    let sb = Sandbox::new();
    sb.sopsy()
        .args([
            "init",
            "--allow-stores",
            "software",
            "--store",
            "file",
            "--no-emergency-keys",
        ])
        .assert()
        .success();
    sb.sopsy()
        .args([
            "recipient",
            "add",
            "annie",
            "--age-public-key",
            "age1se1qannie",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("allows only: keychain, file"));
    // Break-glass keys are portable by design and exempt from the policy.
    sb.sopsy()
        .args([
            "recipient",
            "add",
            "vault",
            "--age-public-key",
            "age1qvault",
            "--break-glass",
        ])
        .env("SOPSY_ASSUME_YES", "1")
        .assert()
        .stderr(predicate::str::contains("allows only").not());
}

/// The repository's allow list is also the default `auto` order: with both a
/// YubiKey and the Secure Enclave ready, `yubikey,enclave` picks the YubiKey.
#[test]
fn allow_stores_order_is_the_default_auto_order() {
    let sb = Sandbox::new();
    let p = sb.path();
    write_script(&p.join("usb"), "echo '+-o YubiKey OTP+FIDO+CCID@1'\n");
    // Present on PATH-equivalent, so the Enclave probes as ready.
    write_script(&p.join("age-plugin-se"), "exit 0\n");
    write_script(
        &p.join("age-plugin-yubikey"),
        "case \"$*\" in *--list*) exit 0;; esac\n\
         cat <<'EOF'\n\
         #       Serial: 12345678, Slot: 1\n\
         #    Recipient: age1tag1qfake\n\
         # Legacy recipient: age1yubikey1qfakelegacy\n\
         AGE-PLUGIN-YUBIKEY-1QFAKESTUB\n\
         EOF\n",
    );
    write_script(
        &p.join("sops"),
        "case \"$1\" in --version) echo 'sops 9.9.9';; *) echo 'ENC[fake]';; esac\n",
    );

    sb.sopsy()
        .env("SOPSY_USB_LIST_BIN", p.join("usb"))
        .env("SOPSY_AGE_PLUGIN_SE_BIN", p.join("age-plugin-se"))
        .env("SOPSY_AGE_PLUGIN_YUBIKEY_BIN", p.join("age-plugin-yubikey"))
        .env("SOPSY_SOPS_BIN", p.join("sops"))
        .args([
            "init",
            "--allow-stores",
            "yubikey,enclave",
            "--no-emergency-keys",
        ])
        .assert()
        .success();

    let config = sb.read(".sopsy.yml");
    assert!(config.contains("store: yubikey"), "{config}");
    assert!(config.contains("allowed:") && config.contains("- yubikey"));
}
