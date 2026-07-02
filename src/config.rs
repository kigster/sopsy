//! Serde model for `.sopsy.yml`, sopsy's internal configuration file.
//!
//! This file records the state sopsy needs to manage a repository: the list of
//! recipients (name + age public key), which recipient is the break-glass
//! emergency key, the globs that identify encrypted files, and the `sops`
//! version the repo was initialised with. It is committed to the repository so
//! the whole team shares the same view.
//!
//! `.sopsy.yml` is sopsy's own metadata; it is distinct from `.sops.yaml`,
//! which is consumed by `sops` itself (its `creation_rules`). Keeping them
//! separate lets sopsy store richer information (human-readable names, the
//! break-glass marker) than `sops` understands.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Default file name for sopsy's internal configuration.
pub const CONFIG_FILE_NAME: &str = ".sopsy.yml";

/// Sidecar file holding the SHA-256 integrity checksum of `.sopsy.yml`
/// (see [`Config::compute_checksum`]). Committed alongside the config so a
/// hand-edit shows up as a mismatch. This is tamper *evidence*, not proof —
/// anyone can recompute it (Enclave age keys cannot sign); git history remains
/// the real audit trail.
pub const CHECKSUM_FILE_NAME: &str = ".sopsy.sha";

/// Fallback join-request validity window when `.sopsy.yml` does not set one.
const DEFAULT_REQUEST_TTL: Duration = Duration::from_secs(72 * 3600);

/// Lifecycle state of a member listed in `.sopsy.yml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberState {
    /// Requested access via `sopsy join` but not yet approved. A pending member
    /// is **not** in `.sops.yaml`, so it grants no decryption ability.
    Pending,
    /// Approved: present in `.sops.yaml` and able to decrypt. This is the
    /// default so legacy entries (written before states existed) read as active.
    #[default]
    Active,
}

/// Whether a member state is the default (`Active`), used to omit it on save.
fn is_active(state: &MemberState) -> bool {
    matches!(state, MemberState::Active)
}

/// A single recipient able to decrypt the repository's secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    /// Human-readable name (e.g. `"alice"` or `"break-glass"`).
    pub name: String,
    /// The age public key, e.g. `age1...` or `age1se1...` for Secure Enclave.
    pub public_key: String,
    /// Username of who generated this key (e.g. `"kig"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Lifecycle state. Omitted from the file when `Active` (the default).
    #[serde(default, skip_serializing_if = "is_active")]
    pub state: MemberState,
    /// RFC3339 timestamp of when a pending join request was made. Used by
    /// `sopsy approve` to reject stale requests, then kept after approval as
    /// the audit record of when access was requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_at: Option<String>,
    /// RFC3339 timestamp of when access was granted (`sopsy approve`). Kept as
    /// the audit record of when this member became able to decrypt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<String>,
    /// Who granted access, as `"Full Name (username)"` (or a bare username when
    /// the approver has no recipient entry). A provenance record, not an
    /// enforcement mechanism — like roles, it is a soft guardrail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    /// Whether this recipient is the emergency "break-glass" key that is stored
    /// offline (e.g. in 1Password) rather than on a developer's machine.
    #[serde(default)]
    pub break_glass: bool,
}

impl Recipient {
    /// Construct a normal, active (non break-glass) recipient.
    pub fn new(name: impl Into<String>, public_key: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            public_key: public_key.into(),
            username: None,
            state: MemberState::Active,
            requested_at: None,
            approved_at: None,
            approved_by: None,
            break_glass: false,
        }
    }

    /// Construct an active recipient with a username.
    pub fn with_username(
        name: impl Into<String>,
        public_key: impl Into<String>,
        username: impl Into<String>,
    ) -> Self {
        Self {
            username: Some(username.into()),
            ..Self::new(name, public_key)
        }
    }

    /// Construct a *pending* member (a join request awaiting approval).
    pub fn pending(
        name: impl Into<String>,
        public_key: impl Into<String>,
        requested_at: impl Into<String>,
    ) -> Self {
        Self {
            state: MemberState::Pending,
            requested_at: Some(requested_at.into()),
            ..Self::new(name, public_key)
        }
    }

    /// Whether this member is awaiting approval.
    pub fn is_pending(&self) -> bool {
        matches!(self.state, MemberState::Pending)
    }
}

/// The full deserialized contents of `.sopsy.yml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// All recipients, including the break-glass key if configured.
    #[serde(default)]
    pub recipients: Vec<Recipient>,

    /// Globs identifying files that sopsy treats as encrypted artifacts
    /// (e.g. `*.encrypted`, `.env.encrypted`, `config/*.encrypted.yaml`).
    #[serde(default = "default_encrypted_globs")]
    pub encrypted_globs: Vec<String>,

    /// The `sops` version present when the repo was initialised, recorded for
    /// diagnostics and reproducibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sops_version: Option<String>,

    /// How long a pending join request stays valid, as a human duration string
    /// (e.g. `"72h"`, `"3d"`). `sopsy approve` refuses older requests unless
    /// `--force` is given; it doubles as a plain-text "approve me promptly"
    /// reminder. Falls back to 72h when unset or unparseable.
    #[serde(
        default = "default_request_ttl",
        skip_serializing_if = "Option::is_none"
    )]
    pub join_request_ttl: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            recipients: Vec::new(),
            encrypted_globs: default_encrypted_globs(),
            sops_version: None,
            join_request_ttl: default_request_ttl(),
        }
    }
}

/// Default join-request validity window written into fresh configs.
fn default_request_ttl() -> Option<String> {
    Some("72h".to_string())
}

/// Default set of globs treated as encrypted artifacts.
fn default_encrypted_globs() -> Vec<String> {
    vec![
        "*.encrypted".to_string(),
        ".env.encrypted".to_string(),
        "config/*.encrypted.yaml".to_string(),
    ]
}

impl Config {
    /// Return the break-glass recipient, if one is configured.
    pub fn break_glass_recipient(&self) -> Option<&Recipient> {
        self.recipients.iter().find(|r| r.break_glass)
    }

    /// Look up a recipient by name.
    pub fn recipient(&self, name: &str) -> Option<&Recipient> {
        self.recipients.iter().find(|r| r.name == name)
    }

    /// The configured join-request validity window, falling back to the default
    /// when unset or unparseable.
    pub fn resolved_request_ttl(&self) -> Duration {
        self.join_request_ttl
            .as_deref()
            .and_then(|s| humantime::parse_duration(s).ok())
            .unwrap_or(DEFAULT_REQUEST_TTL)
    }

    /// The public key the integrity checksum is bound to: the repository's
    /// admin — by convention the first recipient recorded (the one `sopsy init`
    /// creates, named `admin` by default).
    pub fn admin_public_key(&self) -> Option<&str> {
        self.recipients.first().map(|r| r.public_key.as_str())
    }

    /// Compute the integrity checksum for `raw` (the exact on-disk bytes of a
    /// `.sopsy.yml`): the SHA-256, in lowercase hex, of
    /// `raw + "\n" + admin public key`.
    ///
    /// The result lives in the sidecar file [`CHECKSUM_FILE_NAME`], never
    /// inside `.sopsy.yml` itself — hashing the raw bytes avoids any
    /// self-reference and catches *every* edit, formatting included.
    pub fn compute_checksum(&self, raw: &str) -> String {
        use sha2::{Digest, Sha256};
        let admin_key = self.admin_public_key().unwrap_or("");
        let digest = Sha256::digest(format!("{raw}\n{admin_key}").as_bytes());
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The sidecar checksum path for the config at `config_path`
    /// (`.sopsy.sha` in the same directory).
    pub fn checksum_path(config_path: &Path) -> PathBuf {
        config_path.with_file_name(CHECKSUM_FILE_NAME)
    }

    /// Load configuration from `path`, verifying it against the `.sopsy.sha`
    /// sidecar when one exists.
    ///
    /// Returns [`Error::FileNotFound`] if the file does not exist,
    /// [`Error::Parse`] if it cannot be deserialized, and [`Error::Validation`]
    /// if the sidecar checksum does not match (tamper evidence). A missing
    /// sidecar is accepted — repos initialised by older sopsy versions have
    /// none; `sopsy doctor` writes it.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let (config, raw) = Self::load_unverified(path)?;
        if let Ok(stored) = std::fs::read_to_string(Self::checksum_path(path))
            && stored.trim() != config.compute_checksum(&raw)
        {
            return Err(Error::Validation(format!(
                "{} failed its integrity check against {CHECKSUM_FILE_NAME} — \
                 it was edited outside sopsy. If the changes are intentional, \
                 run `sopsy doctor` to repair the checksum; otherwise inspect \
                 `git diff {CONFIG_FILE_NAME}`",
                path.display()
            )));
        }
        Ok(config)
    }

    /// Load configuration from `path` **without** checksum verification,
    /// returning the parsed config together with the raw file contents.
    ///
    /// Reserved for `sopsy doctor`, which must be able to read a tampered or
    /// legacy file in order to repair its checksum. Everything else goes
    /// through [`Config::load`].
    pub fn load_unverified(path: impl AsRef<Path>) -> Result<(Self, String)> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(Error::FileNotFound(path.to_path_buf()));
        }
        let raw = std::fs::read_to_string(path)?;
        let config = serde_yaml_ng::from_str(&raw).map_err(|source| Error::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        Ok((config, raw))
    }

    /// Load configuration from the conventional `.sopsy.yml` inside `dir`.
    pub fn load_from_dir(dir: impl AsRef<Path>) -> Result<Self> {
        Self::load(dir.as_ref().join(CONFIG_FILE_NAME))
    }

    /// Serialize and write the configuration to `path`, then recompute and
    /// write the `.sopsy.sha` sidecar from the exact bytes written — every
    /// save refreshes both files together.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let yaml = serde_yaml_ng::to_string(self)?;
        std::fs::write(path, &yaml)?;
        std::fs::write(
            Self::checksum_path(path),
            format!("{}\n", self.compute_checksum(&yaml)),
        )?;
        Ok(())
    }

    /// Write the configuration to the conventional `.sopsy.yml` inside `dir`.
    pub fn save_to_dir(&self, dir: impl AsRef<Path>) -> Result<PathBuf> {
        let path = dir.as_ref().join(CONFIG_FILE_NAME);
        self.save(&path)?;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_have_encrypted_globs() {
        let cfg = Config::default();
        assert!(cfg.encrypted_globs.iter().any(|g| g == "*.encrypted"));
        assert!(cfg.break_glass_recipient().is_none());
    }

    #[test]
    fn round_trips_through_yaml() {
        let mut cfg = Config::default();
        cfg.recipients.push(Recipient::new("alice", "age1alice"));
        cfg.recipients.push(Recipient {
            break_glass: true,
            ..Recipient::new("break-glass", "age1emergency")
        });
        cfg.sops_version = Some("3.9.0".into());

        let dir = assert_fs::TempDir::new().unwrap();
        let path = cfg.save_to_dir(dir.path()).unwrap();
        let loaded = Config::load(&path).unwrap();

        assert_eq!(cfg, loaded);
        assert_eq!(loaded.break_glass_recipient().unwrap().name, "break-glass");
        assert_eq!(loaded.recipient("alice").unwrap().public_key, "age1alice");
    }

    #[test]
    fn username_round_trips_and_is_omitted_when_absent() {
        let mut cfg = Config::default();
        cfg.recipients
            .push(Recipient::with_username("alice", "age1alice", "kig"));
        cfg.recipients.push(Recipient::new("bob", "age1bob"));

        let dir = assert_fs::TempDir::new().unwrap();
        let path = cfg.save_to_dir(dir.path()).unwrap();

        // The `username` is serialized for alice but skipped entirely for bob.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("username: kig"));
        assert_eq!(raw.matches("username:").count(), 1);

        let loaded = Config::load(&path).unwrap();
        assert_eq!(cfg, loaded);
        assert_eq!(
            loaded.recipient("alice").unwrap().username.as_deref(),
            Some("kig")
        );
        assert!(loaded.recipient("bob").unwrap().username.is_none());
    }

    #[test]
    fn pending_member_round_trips_and_state_defaults_to_active() {
        let mut cfg = Config::default();
        cfg.recipients.push(Recipient::new("alice", "age1alice"));
        cfg.recipients
            .push(Recipient::pending("bob", "age1bob", "2026-06-27T00:00:00Z"));

        let dir = assert_fs::TempDir::new().unwrap();
        let path = cfg.save_to_dir(dir.path()).unwrap();

        // Active state is omitted; pending state + timestamp are written.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("state: pending"));
        assert!(raw.contains("requested_at: 2026-06-27T00:00:00Z"));
        assert_eq!(
            raw.matches("state:").count(),
            1,
            "active state must be omitted"
        );

        let loaded = Config::load(&path).unwrap();
        assert_eq!(cfg, loaded);
        assert!(!loaded.recipient("alice").unwrap().is_pending());
        assert!(loaded.recipient("bob").unwrap().is_pending());
    }

    #[test]
    fn approval_provenance_round_trips_and_is_omitted_when_absent() {
        let mut cfg = Config::default();
        cfg.recipients.push(Recipient {
            requested_at: Some("2026-06-27T00:00:00Z".into()),
            approved_at: Some("2026-06-28T10:00:00Z".into()),
            approved_by: Some("Konstantin Gredeskoul (kig)".into()),
            ..Recipient::new("annie", "age1annie")
        });
        cfg.recipients.push(Recipient::new("bob", "age1bob"));

        let dir = assert_fs::TempDir::new().unwrap();
        let path = cfg.save_to_dir(dir.path()).unwrap();

        // Provenance is written for annie and skipped entirely for bob.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("approved_at: 2026-06-28T10:00:00Z"));
        assert!(raw.contains("approved_by: Konstantin Gredeskoul (kig)"));
        assert!(raw.contains("requested_at: 2026-06-27T00:00:00Z"));
        assert_eq!(raw.matches("approved_by:").count(), 1);

        let loaded = Config::load(&path).unwrap();
        assert_eq!(cfg, loaded);
        assert!(loaded.recipient("bob").unwrap().approved_by.is_none());
    }

    #[test]
    fn resolved_request_ttl_parses_and_falls_back() {
        let mut cfg = Config {
            join_request_ttl: Some("2h".into()),
            ..Config::default()
        };
        assert_eq!(cfg.resolved_request_ttl(), Duration::from_secs(7200));

        // Unparseable or missing → 72h default.
        cfg.join_request_ttl = Some("not-a-duration".into());
        assert_eq!(cfg.resolved_request_ttl(), Duration::from_secs(72 * 3600));
        cfg.join_request_ttl = None;
        assert_eq!(cfg.resolved_request_ttl(), Duration::from_secs(72 * 3600));
    }

    #[test]
    fn save_writes_checksum_sidecar_that_load_verifies() {
        let mut cfg = Config::default();
        cfg.recipients.push(Recipient::new("admin", "age1admin"));

        let dir = assert_fs::TempDir::new().unwrap();
        let path = cfg.save_to_dir(dir.path()).unwrap();

        // The sidecar exists and holds the checksum of the exact bytes written
        // bound to the admin (first) recipient's public key.
        let sha_path = Config::checksum_path(&path);
        let stored = std::fs::read_to_string(&sha_path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert_eq!(stored.trim(), cfg.compute_checksum(&raw));

        // A clean round-trip verifies.
        assert_eq!(Config::load(&path).unwrap(), cfg);
    }

    #[test]
    fn tampered_config_fails_integrity_check() {
        let mut cfg = Config::default();
        cfg.recipients.push(Recipient::new("admin", "age1admin"));
        let dir = assert_fs::TempDir::new().unwrap();
        let path = cfg.save_to_dir(dir.path()).unwrap();

        // Simulate a hand edit swapping in an attacker's key.
        let raw = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, raw.replace("age1admin", "age1attacker")).unwrap();

        let err = Config::load(&path).unwrap_err();
        assert!(
            matches!(&err, Error::Validation(m) if m.contains("integrity")),
            "tampering must fail the integrity check: {err}"
        );

        // `load_unverified` (doctor's path) still reads it.
        let (unverified, _raw) = Config::load_unverified(&path).unwrap();
        assert_eq!(
            unverified.recipient("admin").unwrap().public_key,
            "age1attacker"
        );
    }

    #[test]
    fn missing_checksum_sidecar_is_accepted_as_legacy() {
        let mut cfg = Config::default();
        cfg.recipients.push(Recipient::new("admin", "age1admin"));
        let dir = assert_fs::TempDir::new().unwrap();
        let path = cfg.save_to_dir(dir.path()).unwrap();
        std::fs::remove_file(Config::checksum_path(&path)).unwrap();

        // Repos written before the sidecar existed must keep loading.
        assert_eq!(Config::load(&path).unwrap(), cfg);
    }

    #[test]
    fn missing_file_is_reported() {
        let err = Config::load("/nonexistent/.sopsy.yml").unwrap_err();
        assert!(matches!(err, Error::FileNotFound(_)));
    }

    #[test]
    fn load_from_dir_reads_conventional_file() {
        let dir = assert_fs::TempDir::new().unwrap();
        let mut cfg = Config::default();
        cfg.recipients.push(Recipient::new("alice", "age1alice"));
        cfg.save_to_dir(dir.path()).unwrap();

        let loaded = Config::load_from_dir(dir.path()).unwrap();
        assert_eq!(loaded.recipient("alice").unwrap().public_key, "age1alice");
    }

    #[test]
    fn load_from_dir_missing_file_is_reported() {
        let dir = assert_fs::TempDir::new().unwrap();
        let err = Config::load_from_dir(dir.path()).unwrap_err();
        assert!(matches!(err, Error::FileNotFound(_)));
    }

    #[test]
    fn malformed_yaml_is_a_parse_error() {
        let dir = assert_fs::TempDir::new().unwrap();
        let path = dir.path().join(CONFIG_FILE_NAME);
        // `recipients` must be a sequence; a scalar makes deserialization fail.
        std::fs::write(&path, "recipients: not-a-list\n").unwrap();
        let err = Config::load(&path).unwrap_err();
        assert!(matches!(err, Error::Parse { .. }));
    }

    #[test]
    fn recipient_lookup_misses_return_none() {
        let mut cfg = Config::default();
        cfg.recipients.push(Recipient::new("alice", "age1alice"));
        assert!(cfg.recipient("nobody").is_none());
        assert!(cfg.break_glass_recipient().is_none());
    }
}
