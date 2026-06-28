//! Helpers for Secure Enclave-backed age identities via `age-plugin-se`.
//!
//! On macOS with Apple Silicon, `age-plugin-se` generates an age identity whose
//! private key is bound to the Secure Enclave and never leaves the device.
//! sopsy shells out to this binary.
//!
//! > [!IMPORTANT]
//! > Real identity generation requires Apple hardware with a Secure Enclave, so
//! > these paths cannot run in CI. Tests exercise them against a **faked**
//! > `age-plugin-se` binary; production use requires the real plugin on macOS.
//!
//! The binary is resolved via the `SOPSY_AGE_PLUGIN_SE_BIN` environment variable
//! (defaulting to `age-plugin-se`) so tests can inject a fake script that emits
//! canned `keygen` output.

use std::ffi::OsString;
use std::process::Command;

use crate::error::{Error, Result};

/// The default name of the external binary this module drives.
pub const PLUGIN_BIN: &str = "age-plugin-se";

/// Environment variable that overrides the `age-plugin-se` binary path.
pub const PLUGIN_BIN_ENV: &str = "SOPSY_AGE_PLUGIN_SE_BIN";

/// Resolve the `age-plugin-se` binary to invoke, honoring [`PLUGIN_BIN_ENV`].
fn plugin_bin() -> OsString {
    std::env::var_os(PLUGIN_BIN_ENV).unwrap_or_else(|| OsString::from(PLUGIN_BIN))
}

/// A freshly generated Secure Enclave identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclaveIdentity {
    /// The age recipient (public key), e.g. `age1se1...`.
    pub public_key: String,
    /// The identity stanza to store (references the Secure Enclave key),
    /// e.g. `AGE-PLUGIN-SE-1...`.
    pub identity: String,
}

/// Verify the `age-plugin-se` binary is available on `PATH` (or via
/// [`PLUGIN_BIN_ENV`]), returning a friendly error otherwise.
pub fn ensure_available() -> Result<()> {
    let bin = plugin_bin();
    if which::which(&bin).is_ok() {
        return Ok(());
    }
    Err(Error::ToolNotFound(format!(
        "{} (install it with `brew install age-plugin-se`)",
        bin.to_string_lossy()
    )))
}

/// Generate a new Secure Enclave-backed identity, returning its public key and
/// identity stanza.
///
/// Runs `age-plugin-se keygen` (adding `--access-control=<value>` when
/// `access_control` is `Some`). The identity is written to standard output,
/// which contains a `# public key: age1se1...` comment line and the
/// `AGE-PLUGIN-SE-...` identity line; the public key may also appear on stderr
/// as `Public key: age1se1...`. Both stdout and stderr are parsed.
pub fn generate_identity(access_control: Option<&str>) -> Result<EnclaveIdentity> {
    let args: Vec<String> = access_control
        .map(|value| vec![format!("--access-control={value}")])
        .unwrap_or_default();
    generate_identity_with_args(&args)
}

/// Generate a new Secure Enclave-backed identity, forwarding `extra_args`
/// verbatim to `age-plugin-se keygen`.
///
/// This is the escape hatch behind `sopsy recipient keygen -- <age flags>`: it
/// lets callers pass arbitrary plugin flags (e.g. `--access-control=...`) while
/// still parsing the public key and identity out of the output.
pub fn generate_identity_with_args(extra_args: &[String]) -> Result<EnclaveIdentity> {
    let mut command = Command::new(plugin_bin());
    command.arg("keygen");
    command.args(extra_args);

    let output = command.output()?;
    if !output.status.success() {
        return Err(Error::ProcessFailed {
            tool: PLUGIN_BIN.to_string(),
            code: output.status.code().unwrap_or(-1),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    parse_keygen_output(&stdout, &stderr)
}

/// Parse the public key and identity from `age-plugin-se keygen` output.
///
/// The public key is taken from the first line containing `public key:`
/// (case-insensitive) — covering both the `# public key:` comment in the
/// identity file and the `Public key:` summary printed to stderr. The identity
/// is the first line beginning with `AGE-PLUGIN-SE`.
fn parse_keygen_output(stdout: &str, stderr: &str) -> Result<EnclaveIdentity> {
    let public_key = stdout
        .lines()
        .chain(stderr.lines())
        .find_map(extract_public_key)
        .ok_or_else(|| {
            Error::Validation("could not find a public key in age-plugin-se output".to_string())
        })?;

    let identity = stdout
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("AGE-PLUGIN-SE"))
        .map(str::to_string)
        .ok_or_else(|| {
            Error::Validation(
                "could not find an AGE-PLUGIN-SE identity in age-plugin-se output".to_string(),
            )
        })?;

    Ok(EnclaveIdentity {
        public_key,
        identity,
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
    fn enclave_identity_is_constructible() {
        let id = EnclaveIdentity {
            public_key: "age1se1qexample".into(),
            identity: "AGE-PLUGIN-SE-1...".into(),
        };
        assert!(id.public_key.starts_with("age1se1"));
    }

    #[test]
    fn parses_identity_file_style_stdout() {
        let stdout = "# created: 2026-06-27T00:00:00Z\n\
             # access control: any biometry or passcode\n\
             # public key: age1se1qg8vwwqhztnh3vpt2nf2xwn7famktxlmp0nmkflt\n\
             AGE-PLUGIN-SE-1QABCDEF\n";
        let id = parse_keygen_output(stdout, "").unwrap();
        assert_eq!(
            id.public_key,
            "age1se1qg8vwwqhztnh3vpt2nf2xwn7famktxlmp0nmkflt"
        );
        assert_eq!(id.identity, "AGE-PLUGIN-SE-1QABCDEF");
    }

    #[test]
    fn parses_public_key_from_stderr() {
        let stdout = "AGE-PLUGIN-SE-1QXYZ\n";
        let stderr = "Public key: age1se1qg8vwwqhztnh3\n";
        let id = parse_keygen_output(stdout, stderr).unwrap();
        assert_eq!(id.public_key, "age1se1qg8vwwqhztnh3");
        assert_eq!(id.identity, "AGE-PLUGIN-SE-1QXYZ");
    }

    #[test]
    fn missing_identity_is_an_error() {
        let err = parse_keygen_output("# public key: age1se1abc\n", "").unwrap_err();
        assert!(matches!(err, Error::Validation(_)));
    }

    #[test]
    fn missing_public_key_is_an_error() {
        let err = parse_keygen_output("AGE-PLUGIN-SE-1QXYZ\n", "").unwrap_err();
        assert!(matches!(err, Error::Validation(_)));
    }

    #[test]
    fn skips_public_key_lines_without_an_age_token() {
        // A `public key:` line whose token is not an `age1...` recipient must be
        // ignored (the non-`age1` branch of `extract_public_key`), so parsing
        // falls through to the next, valid line.
        let stdout = "# public key: not-an-age-key\n\
             # public key: age1se1qrealkey\n\
             AGE-PLUGIN-SE-1QABC\n";
        let id = parse_keygen_output(stdout, "").unwrap();
        assert_eq!(id.public_key, "age1se1qrealkey");

        // And a lone non-age token yields the "no public key" validation error.
        assert!(extract_public_key("Public key: nope").is_none());
    }
}
