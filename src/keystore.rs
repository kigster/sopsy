//! Local age identity store that `sops` reads from.
//!
//! `sops` decrypts (and `updatekeys` re-wraps) a file by finding a matching
//! *identity*. For a Secure Enclave recipient (`age1se1…`) that identity is the
//! `AGE-PLUGIN-SE-1…` handle emitted by `age-plugin-se keygen`. The handle is
//! **not** secret key material — the private key never leaves the Secure Enclave
//! and every use requires Touch ID — so it is safe to keep on disk. But `sops`
//! has to be told where it is, or decryption fails with "identity did not match
//! any of the recipients".
//!
//! This module owns two responsibilities:
//!
//! 1. [`store_identity`] appends a freshly generated identity to the per-user
//!    `keys.txt` that `sops` auto-discovers.
//! 2. [`configure_sops_env`] points every `sops` invocation at that file via
//!    `SOPS_AGE_KEY_FILE` (unless the user already set their own), so discovery
//!    is deterministic across `sops`/`age` versions and platforms. Secrets
//!    listed in the [`keychain_index`] are read from the OS keyring and
//!    passed via `SOPS_AGE_KEY`.
//!
//! Break-glass *portable* keys (`AGE-SECRET-KEY-1…`) are real secret material
//! and are deliberately **not** stored here — they live offline only.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::Result;

/// Environment variable `sops` reads to locate an age identity file.
pub const SOPS_AGE_KEY_FILE_ENV: &str = "SOPS_AGE_KEY_FILE";
/// Environment variable `sops` reads for a literal age identity.
pub const SOPS_AGE_KEY_ENV: &str = "SOPS_AGE_KEY";
/// sopsy-specific override for the keystore path. Takes precedence over
/// everything else; used by tests to keep identities out of the real per-user
/// keys file, and available to anyone who wants sopsy to manage a separate file.
pub const KEYS_FILE_ENV: &str = "SOPSY_KEYS_FILE";

/// The user's home directory, if discoverable.
pub(crate) fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// Resolve the age identity file `sops` uses, mirroring its own lookup.
///
/// Honors the sopsy-specific [`KEYS_FILE_ENV`] override first, then
/// `SOPS_AGE_KEY_FILE`. Otherwise it returns the per-user default that `sops`
/// derives from Go's `os.UserConfigDir`:
/// `~/Library/Application Support/sops/age/keys.txt` on macOS, and
/// `${XDG_CONFIG_HOME:-~/.config}/sops/age/keys.txt` elsewhere.
pub fn keys_file() -> PathBuf {
    if let Some(explicit) = std::env::var_os(KEYS_FILE_ENV) {
        return PathBuf::from(explicit);
    }
    if let Some(explicit) = std::env::var_os(SOPS_AGE_KEY_FILE_ENV) {
        return PathBuf::from(explicit);
    }
    let home = home_dir().unwrap_or_else(|| PathBuf::from("."));

    #[cfg(target_os = "macos")]
    let base = home.join("Library").join("Application Support");
    #[cfg(not(target_os = "macos"))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| home.join(".config"));

    base.join("sops").join("age").join("keys.txt")
}

/// Append `identity` to the [`keys_file`], creating it (and parents) if needed.
///
/// Idempotent: if the exact identity line is already present, the file is left
/// unchanged. `label` and `public_key` are written as comments for humans. The
/// file is restricted to `0600` and its directory to `0700`. Returns the path
/// written so callers can show it.
pub fn store_identity(label: &str, public_key: &str, identity: &str) -> Result<PathBuf> {
    let path = keys_file();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        restrict(parent, 0o700);
    }

    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let identity = identity.trim();
    if existing.lines().any(|line| line.trim() == identity) {
        return Ok(path);
    }

    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&format!(
        "# sopsy: {label}\n# public key: {public_key}\n{identity}\n"
    ));
    std::fs::write(&path, updated)?;
    restrict(&path, 0o600);
    Ok(path)
}

/// The index of public keys whose secrets live in the OS keyring, kept beside
/// the [`keys_file`].
///
/// It is a separate file because `sops` before 3.11 refuses any key file with
/// no identity in it, and a keychain-only setup would leave exactly that.
pub fn keychain_index() -> PathBuf {
    keys_file().with_file_name("sopsy-keychain.txt")
}

/// Record in the [`keychain_index`] that `public_key`'s secret lives in the OS
/// keyring, so [`configure_sops_env`] knows to fetch it. Only the public key
/// is written. Idempotent.
pub fn register_keychain_key(label: &str, public_key: &str) -> Result<PathBuf> {
    let path = keychain_index();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        restrict(parent, 0o700);
    }
    let mut contents = std::fs::read_to_string(&path).unwrap_or_default();
    if keychain_keys_in(&contents).iter().any(|k| k == public_key) {
        return Ok(path);
    }
    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
    contents.push_str(&format!("# sopsy: {label}\n{public_key}\n"));
    std::fs::write(&path, contents)?;
    restrict(&path, 0o600);
    Ok(path)
}

/// Public keys listed in a [`keychain_index`], skipping comments and blanks.
fn keychain_keys_in(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

/// Point `cmd` (a `sops` invocation) at the local identities, unless the user
/// already supplied a literal key.
///
/// - `SOPS_AGE_KEY_FILE` is set to the [`keys_file`] (hardware handles and
///   `file`-store keys), unless the user set it, which removes any ambiguity
///   about the platform default path across `sops`/`age` versions.
/// - Keys kept in the OS keyring are read and handed to this child process
///   only, via `SOPS_AGE_KEY`; `sops` merges them with the key file.
///
/// A user-supplied `SOPS_AGE_KEY` (e.g. a restored break-glass key) is never
/// touched.
pub fn configure_sops_env(cmd: &mut Command) {
    if std::env::var_os(SOPS_AGE_KEY_ENV).is_some() {
        return;
    }
    let path = keys_file();
    if path.exists() && std::env::var_os(SOPS_AGE_KEY_FILE_ENV).is_none() {
        cmd.env(SOPS_AGE_KEY_FILE_ENV, &path);
    }
    let secrets: Vec<String> =
        keychain_keys_in(&std::fs::read_to_string(keychain_index()).unwrap_or_default())
            .iter()
            .filter_map(|pk| crate::hardware::keychain::read(pk).ok().flatten())
            .collect();
    if !secrets.is_empty() {
        cmd.env(SOPS_AGE_KEY_ENV, secrets.join("\n"));
    }
}

/// Restrict `path` to `mode` on Unix; a no-op elsewhere.
fn restrict(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mut perms = metadata.permissions();
            perms.set_mode(mode);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `keys_file` honors an explicit `SOPS_AGE_KEY_FILE`.
    ///
    /// Mutates a process-global env var, so it is `#[serial]` to avoid racing
    /// the other env-touching test.
    #[serial_test::serial]
    #[test]
    fn keys_file_honors_explicit_override() {
        // SAFETY: single-threaded test mutating then restoring the var.
        let prev = std::env::var_os(SOPS_AGE_KEY_FILE_ENV);
        unsafe { std::env::set_var(SOPS_AGE_KEY_FILE_ENV, "/tmp/custom/keys.txt") };
        assert_eq!(keys_file(), PathBuf::from("/tmp/custom/keys.txt"));
        match prev {
            Some(v) => unsafe { std::env::set_var(SOPS_AGE_KEY_FILE_ENV, v) },
            None => unsafe { std::env::remove_var(SOPS_AGE_KEY_FILE_ENV) },
        }
    }

    #[test]
    fn keychain_index_skips_comments_and_blanks() {
        let contents = "# sopsy: kig\nage1abc\n\n  age1def  \n# age1nope\n";
        assert_eq!(keychain_keys_in(contents), ["age1abc", "age1def"]);
    }

    /// `store_identity` writes the handle and is idempotent.
    #[serial_test::serial]
    #[test]
    fn store_identity_appends_once() {
        let dir = assert_fs::TempDir::new().unwrap();
        let keys = dir.path().join("keys.txt");
        // SAFETY: single-threaded test; restored below.
        let prev = std::env::var_os(SOPS_AGE_KEY_FILE_ENV);
        unsafe { std::env::set_var(SOPS_AGE_KEY_FILE_ENV, &keys) };

        let id = "AGE-PLUGIN-SE-1QXAMPLE";
        store_identity("admin", "age1se1abc", id).unwrap();
        store_identity("admin", "age1se1abc", id).unwrap();

        let contents = std::fs::read_to_string(&keys).unwrap();
        assert_eq!(
            contents.matches(id).count(),
            1,
            "identity written exactly once"
        );
        assert!(contents.contains("# public key: age1se1abc"));

        match prev {
            Some(v) => unsafe { std::env::set_var(SOPS_AGE_KEY_FILE_ENV, v) },
            None => unsafe { std::env::remove_var(SOPS_AGE_KEY_FILE_ENV) },
        }
    }
}
