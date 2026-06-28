//! Helpers for generating **portable** age key pairs via external `age-keygen`.
//!
//! Unlike Secure Enclave identities (see [`crate::enclave`]), these are ordinary
//! X25519 age keys whose private half is a portable string. sopsy uses them for
//! the **break-glass** emergency recipient, which must be exportable so it can be
//! stored offline (e.g. in 1Password) rather than bound to a single device.
//!
//! The binary is resolved via the `SOPSY_AGE_KEYGEN_BIN` environment variable
//! (defaulting to `age-keygen`) so tests can inject a fake script that emits
//! canned `keygen` output.

use std::ffi::OsString;
use std::process::Command;

use crate::error::{Error, Result};

/// The default name of the external binary this module drives.
pub const KEYGEN_BIN: &str = "age-keygen";

/// Environment variable that overrides the `age-keygen` binary path (for testing).
pub const KEYGEN_BIN_ENV: &str = "SOPSY_AGE_KEYGEN_BIN";

/// Resolve the `age-keygen` binary to invoke, honoring [`KEYGEN_BIN_ENV`].
fn keygen_bin() -> OsString {
    std::env::var_os(KEYGEN_BIN_ENV).unwrap_or_else(|| OsString::from(KEYGEN_BIN))
}

/// A freshly generated, portable age key pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgeKeypair {
    /// The age recipient (public key), e.g. `age1...`.
    pub public_key: String,
    /// The full identity-file contents, including the `AGE-SECRET-KEY-1...` line
    /// (this is what an operator stores to retain decryption ability).
    pub identity: String,
}

/// Verify the `age-keygen` binary is available on `PATH` (or via
/// [`KEYGEN_BIN_ENV`]), returning a friendly error otherwise.
pub fn ensure_available() -> Result<()> {
    let bin = keygen_bin();
    if which::which(&bin).is_ok() {
        return Ok(());
    }
    Err(Error::ToolNotFound(format!(
        "{} (install it with `brew install age`)",
        bin.to_string_lossy()
    )))
}

/// Generate a portable age key pair by running `age-keygen`.
///
/// `age-keygen` writes the identity file (a header comment block plus the
/// `AGE-SECRET-KEY-1...` line) to standard output and prints `Public key:
/// age1...` to standard error. Both are parsed.
pub fn generate_keypair() -> Result<AgeKeypair> {
    let output = Command::new(keygen_bin()).output()?;
    if !output.status.success() {
        return Err(Error::ProcessFailed {
            tool: KEYGEN_BIN.to_string(),
            code: output.status.code().unwrap_or(-1),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    parse_keygen_output(&stdout, &stderr)
}

/// Parse the public key and identity-file contents from `age-keygen` output.
///
/// The public key is taken from the first line containing `public key:`
/// (case-insensitive) — covering both the `# public key:` comment written to the
/// identity file and the `Public key:` summary on stderr. The identity is the
/// full stdout, which must contain an `AGE-SECRET-KEY` line.
fn parse_keygen_output(stdout: &str, stderr: &str) -> Result<AgeKeypair> {
    let public_key = stdout
        .lines()
        .chain(stderr.lines())
        .find_map(extract_public_key)
        .ok_or_else(|| {
            Error::Validation("could not find a public key in age-keygen output".to_string())
        })?;

    if !stdout.contains("AGE-SECRET-KEY") {
        return Err(Error::Validation(
            "could not find an AGE-SECRET-KEY in age-keygen output".to_string(),
        ));
    }

    Ok(AgeKeypair {
        public_key,
        identity: format!("{}\n", stdout.trim_end()),
    })
}

/// Extract an `age1...` recipient from a line containing `public key:`.
fn extract_public_key(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let idx = lower.find("public key:")?;
    let rest = line[idx + "public key:".len()..].trim();
    let key = rest.split_whitespace().next()?;
    if key.starts_with("age1") {
        Some(key.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_identity_file_and_public_key() {
        let stdout = "# created: 2026-06-27T00:00:00Z\n\
             # public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n\
             AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQ\n";
        let stderr = "Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n";
        let pair = parse_keygen_output(stdout, stderr).unwrap();
        assert_eq!(
            pair.public_key,
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" // pragma: allowlist secret
        );
        assert!(pair.identity.contains("AGE-SECRET-KEY-1"));
        assert!(pair.identity.ends_with('\n'));
    }

    #[test]
    fn missing_public_key_is_an_error() {
        let err = parse_keygen_output("AGE-SECRET-KEY-1QXYZ\n", "").unwrap_err();
        assert!(matches!(err, Error::Validation(_)));
    }

    #[test]
    fn missing_secret_key_is_an_error() {
        let err = parse_keygen_output("# public key: age1abc\n", "").unwrap_err();
        assert!(matches!(err, Error::Validation(_)));
    }

    #[test]
    fn skips_public_key_lines_without_an_age_token() {
        assert!(extract_public_key("Public key: nope").is_none());
        assert_eq!(
            extract_public_key("# public key: age1real").as_deref(),
            Some("age1real")
        );
    }

    /// Write an executable fake `age-keygen` to `dir` and point the override at it.
    ///
    /// # Safety
    /// Callers must be serialized (`#[serial]`) — the env var is process-wide.
    fn install_fake_keygen(dir: &std::path::Path, body: &str) {
        let script = dir.join("fake-age-keygen");
        std::fs::write(&script, format!("#!/bin/sh\n{body}")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // SAFETY: serialized via `#[serial]`.
        unsafe {
            std::env::set_var(KEYGEN_BIN_ENV, &script);
        }
    }

    fn clear_fake_keygen() {
        // SAFETY: serialized via `#[serial]`.
        unsafe {
            std::env::remove_var(KEYGEN_BIN_ENV);
        }
    }

    #[test]
    #[serial_test::serial]
    fn ensure_available_errs_when_binary_missing() {
        // SAFETY: serialized via `#[serial]`.
        unsafe {
            std::env::set_var(KEYGEN_BIN_ENV, "/nonexistent/age-keygen-xyz");
        }
        assert!(matches!(ensure_available(), Err(Error::ToolNotFound(_))));
        clear_fake_keygen();
    }

    #[test]
    #[serial_test::serial]
    fn generate_keypair_parses_fake_success() {
        let dir = assert_fs::TempDir::new().unwrap();
        install_fake_keygen(
            dir.path(),
            "cat <<'EOF'\n\
             # created: 2026-06-27T00:00:00Z\n\
             # public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n\
             AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQ\n\
             EOF\n",
        );
        let pair = generate_keypair().unwrap();
        assert!(pair.public_key.starts_with("age1"));
        assert!(pair.identity.contains("AGE-SECRET-KEY-1"));
        clear_fake_keygen();
    }

    #[test]
    #[serial_test::serial]
    fn generate_keypair_maps_nonzero_exit_to_process_failed() {
        let dir = assert_fs::TempDir::new().unwrap();
        install_fake_keygen(dir.path(), "echo 'boom' >&2\nexit 1\n");
        assert!(matches!(
            generate_keypair(),
            Err(Error::ProcessFailed { .. })
        ));
        clear_fake_keygen();
    }
}
