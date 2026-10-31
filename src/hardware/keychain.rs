//! Software age keys kept in the OS keyring.
//!
//! - macOS: the login Keychain, through `security`. The secret is written with
//!   `security -i` reading commands from stdin, so it never appears in a
//!   process's argument list.
//! - Linux: the Secret Service (GNOME Keyring, KWallet), through `secret-tool`,
//!   which reads the secret from stdin.
//!
//! Items are filed under service [`SERVICE`] with the age public key as the
//! account, so a recipient maps to exactly one item. The key is encrypted at
//! rest and unlocked with the login session, which makes it weaker than a
//! hardware store: any process running as the user can read it.
//!
//! The binary is resolved via `SOPSY_KEYCHAIN_BIN` (default `security` on
//! macOS, `secret-tool` elsewhere) so tests can inject a fake.

use std::ffi::OsString;
use std::io::Write;
use std::process::{Command, Stdio};

use super::Availability;
use crate::error::{Error, Result};

/// Environment variable that overrides the keyring binary.
pub const BIN_ENV: &str = "SOPSY_KEYCHAIN_BIN";

/// Keyring service name every sopsy item is filed under.
pub const SERVICE: &str = "sopsy";

#[cfg(target_os = "macos")]
const DEFAULT_BIN: &str = "security";
#[cfg(not(target_os = "macos"))]
const DEFAULT_BIN: &str = "secret-tool";

/// Human name of the keyring on this platform.
#[cfg(target_os = "macos")]
pub const DISPLAY_NAME: &str = "macOS Keychain";
/// Human name of the keyring on this platform.
#[cfg(not(target_os = "macos"))]
pub const DISPLAY_NAME: &str = "Secret Service keyring";

fn bin() -> OsString {
    std::env::var_os(BIN_ENV).unwrap_or_else(|| OsString::from(DEFAULT_BIN))
}

/// Whether the keyring can be used on this machine.
pub fn probe() -> Availability {
    probe_with(
        MACOS,
        which::which(bin()).is_ok(),
        std::env::var_os(BIN_ENV).is_some(),
        std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some(),
    )
}

/// Whether this build targets macOS (the Keychain) rather than the Secret Service.
const MACOS: bool = cfg!(target_os = "macos");

/// [`probe`] for an explicit platform and environment, so both platforms' rules
/// are testable anywhere.
fn probe_with(macos: bool, has_bin: bool, overridden: bool, dbus: bool) -> Availability {
    if !has_bin {
        return if macos {
            Availability::Unavailable {
                reason: "`security` not found".into(),
            }
        } else {
            Availability::MissingTool {
                install: "sudo apt install libsecret-tools (or your distro's libsecret package)"
                    .into(),
            }
        };
    }
    // An explicit override is trusted as-is (tests inject a fake keyring).
    if !macos && !overridden && !dbus {
        return Availability::Unavailable {
            reason: "no D-Bus session for the Secret Service".into(),
        };
    }
    Availability::Ready
}

/// Store `secret` for `public_key`, replacing any existing item.
pub fn store(public_key: &str, secret: &str) -> Result<()> {
    check_token(public_key)?;
    check_token(secret)?;
    let (args, stdin) = store_command(MACOS, public_key, secret);
    run(&args, Some(&stdin))?;
    // `security -i` exits 0 even when a command inside it fails, so confirm.
    match read(public_key)? {
        Some(stored) if stored == secret => Ok(()),
        _ => Err(Error::Validation(format!(
            "could not store the key in the {DISPLAY_NAME}"
        ))),
    }
}

/// Arguments and stdin that store `secret`: the secret only ever goes to stdin.
fn store_command(macos: bool, public_key: &str, secret: &str) -> (Vec<String>, String) {
    if macos {
        (
            vec!["-i".into()],
            format!(
                "add-generic-password -U -s {SERVICE} -a {public_key} -l sopsy-age-key -w {secret}\n"
            ),
        )
    } else {
        (
            vec![
                "store".into(),
                "--label=sopsy age key".into(),
                "service".into(),
                SERVICE.into(),
                "account".into(),
                public_key.into(),
            ],
            secret.to_string(),
        )
    }
}

/// Read the secret for `public_key`, or `None` when there is no such item.
pub fn read(public_key: &str) -> Result<Option<String>> {
    check_token(public_key)?;
    match run(&read_args(MACOS, public_key), None) {
        Ok(stdout) => {
            let secret = stdout.trim().to_string();
            Ok((!secret.is_empty()).then_some(secret))
        }
        Err(Error::ProcessFailed { .. }) => Ok(None),
        Err(other) => Err(other),
    }
}

/// Arguments that print the secret stored for `public_key`.
fn read_args(macos: bool, public_key: &str) -> Vec<String> {
    if macos {
        [
            "find-generic-password",
            "-s",
            SERVICE,
            "-a",
            public_key,
            "-w",
        ]
        .map(String::from)
        .to_vec()
    } else {
        ["lookup", "service", SERVICE, "account", public_key]
            .map(String::from)
            .to_vec()
    }
}

/// Keys and public keys are base32/bech32 plus `-`; refuse anything else so
/// nothing can be smuggled into the `security -i` command line.
fn check_token(value: &str) -> Result<()> {
    if !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        Ok(())
    } else {
        Err(Error::Validation(
            "refusing to pass a malformed key to the keychain".into(),
        ))
    }
}

fn run(args: &[String], stdin: Option<&str>) -> Result<String> {
    let mut child = Command::new(bin())
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(input.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(Error::ProcessFailed {
            tool: bin().to_string_lossy().into_owned(),
            code: output.status.code().unwrap_or(-1),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_must_be_plain_key_characters() {
        assert!(check_token("AGE-SECRET-KEY-1ABC").is_ok());
        assert!(check_token("age1qxyz").is_ok());
        for bad in ["", "a b", "a\nb", "a;b", "a'b"] {
            assert!(check_token(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn probe_rules_for_both_platforms() {
        assert!(matches!(
            probe_with(true, false, false, false),
            Availability::Unavailable { .. }
        ));
        assert!(matches!(
            probe_with(false, false, false, true),
            Availability::MissingTool { .. }
        ));
        assert!(matches!(
            probe_with(false, true, false, false),
            Availability::Unavailable { reason } if reason.contains("D-Bus")
        ));
        assert_eq!(probe_with(false, true, true, false), Availability::Ready);
        assert_eq!(probe_with(false, true, false, true), Availability::Ready);
        assert_eq!(probe_with(true, true, false, false), Availability::Ready);
    }

    #[test]
    fn the_secret_goes_to_stdin_on_both_platforms() {
        let (args, stdin) = store_command(true, "age1qpub", "AGE-SECRET-KEY-1X");
        assert_eq!(args, ["-i"]);
        assert!(stdin.contains("add-generic-password -U -s sopsy -a age1qpub"));
        assert!(stdin.contains("-w AGE-SECRET-KEY-1X"));
        let (args, stdin) = store_command(false, "age1qpub", "AGE-SECRET-KEY-1X");
        assert!(!args.iter().any(|a| a.contains("SECRET")), "{args:?}");
        assert_eq!(stdin, "AGE-SECRET-KEY-1X");
        assert_eq!(
            read_args(true, "age1qpub")[..2],
            ["find-generic-password", "-s"]
        );
        assert_eq!(read_args(false, "age1qpub")[0], "lookup");
    }

    fn fake_keyring(body: &str) -> (tempfile::TempDir, String) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keyring");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = path.to_string_lossy().into_owned();
        (dir, path)
    }

    fn with_bin<T>(bin: &str, f: impl FnOnce() -> T) -> T {
        let old = std::env::var_os(BIN_ENV);
        // SAFETY: serialized.
        unsafe { std::env::set_var(BIN_ENV, bin) };
        let result = f();
        unsafe {
            match old {
                Some(v) => std::env::set_var(BIN_ENV, v),
                None => std::env::remove_var(BIN_ENV),
            }
        }
        result
    }

    #[test]
    #[serial_test::serial]
    fn a_keyring_that_drops_the_item_is_reported() {
        // Accepts every command but stores nothing (like `security -i` on error).
        let (_dir, bin) = fake_keyring("cat >/dev/null; exit 0");
        let err = with_bin(&bin, || store("age1qpub", "AGE-SECRET-KEY-1X")).unwrap_err();
        assert!(err.to_string().contains("could not store the key"));
    }

    #[test]
    #[serial_test::serial]
    fn keyring_failures_surface() {
        // A failing store command is a process error; a failing lookup is "absent".
        let (_dir, bin) = fake_keyring("echo boom >&2; exit 4");
        let err = with_bin(&bin, || store("age1qpub", "AGE-SECRET-KEY-1X")).unwrap_err();
        assert!(matches!(err, Error::ProcessFailed { code: 4, .. }), "{err}");
        assert_eq!(with_bin(&bin, || read("age1qpub")).unwrap(), None);
        // A keyring binary that cannot be started is an error, not "absent".
        assert!(with_bin("/nonexistent/keyring", || read("age1qpub")).is_err());
    }
}
