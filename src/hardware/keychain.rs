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
    if which::which(bin()).is_err() {
        return if cfg!(target_os = "macos") {
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
    if !cfg!(target_os = "macos")
        && std::env::var_os(BIN_ENV).is_none()
        && std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none()
    {
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
    let (args, stdin): (Vec<String>, String) = if cfg!(target_os = "macos") {
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
    };
    run(&args, Some(&stdin))?;
    // `security -i` exits 0 even when a command inside it fails, so confirm.
    match read(public_key)? {
        Some(stored) if stored == secret => Ok(()),
        _ => Err(Error::Validation(format!(
            "could not store the key in the {DISPLAY_NAME}"
        ))),
    }
}

/// Read the secret for `public_key`, or `None` when there is no such item.
pub fn read(public_key: &str) -> Result<Option<String>> {
    check_token(public_key)?;
    let args: Vec<String> = if cfg!(target_os = "macos") {
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
    };
    match run(&args, None) {
        Ok(stdout) => {
            let secret = stdout.trim().to_string();
            Ok((!secret.is_empty()).then_some(secret))
        }
        Err(Error::ProcessFailed { .. }) => Ok(None),
        Err(other) => Err(other),
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
}
