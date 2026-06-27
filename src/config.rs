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

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Default file name for sopsy's internal configuration.
pub const CONFIG_FILE_NAME: &str = ".sopsy.yml";

/// A single recipient able to decrypt the repository's secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    /// Human-readable name (e.g. `"alice"` or `"break-glass"`).
    pub name: String,
    /// The age public key, e.g. `age1...` or `age1se1...` for Secure Enclave.
    pub public_key: String,
    /// Whether this recipient is the emergency "break-glass" key that is stored
    /// offline (e.g. in 1Password) rather than on a developer's machine.
    #[serde(default)]
    pub break_glass: bool,
}

impl Recipient {
    /// Construct a normal (non break-glass) recipient.
    pub fn new(name: impl Into<String>, public_key: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            public_key: public_key.into(),
            break_glass: false,
        }
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            recipients: Vec::new(),
            encrypted_globs: default_encrypted_globs(),
            sops_version: None,
        }
    }
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

    /// Load configuration from `path`.
    ///
    /// Returns [`Error::FileNotFound`] if the file does not exist and
    /// [`Error::Parse`] if it cannot be deserialized.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(Error::FileNotFound(path.to_path_buf()));
        }
        let raw = std::fs::read_to_string(path)?;
        serde_yaml_ng::from_str(&raw).map_err(|source| Error::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Load configuration from the conventional `.sopsy.yml` inside `dir`.
    pub fn load_from_dir(dir: impl AsRef<Path>) -> Result<Self> {
        Self::load(dir.as_ref().join(CONFIG_FILE_NAME))
    }

    /// Serialize and write the configuration to `path`.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let yaml = serde_yaml_ng::to_string(self)?;
        std::fs::write(path.as_ref(), yaml)?;
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
            name: "break-glass".into(),
            public_key: "age1emergency".into(),
            break_glass: true,
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
    fn missing_file_is_reported() {
        let err = Config::load("/nonexistent/.sopsy.yml").unwrap_err();
        assert!(matches!(err, Error::FileNotFound(_)));
    }
}
