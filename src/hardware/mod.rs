//! Private-key stores: where a member's age identity lives.
//!
//! Each store wraps an external tool (sopsy never reimplements the crypto) and
//! yields a [`GeneratedIdentity`]: the public recipient that gets committed to
//! `.sops.yaml`, plus the local identity line `sops` needs to decrypt. For
//! hardware stores that line is a non-secret handle — the private key never
//! leaves the device.
//!
//! See `.plans/001-yubikey-support/plan.md` for the full store model
//! (groups, priority, repo key policy).

pub mod enclave;
pub mod yubikey;

use std::fmt;

/// A place a member's private key can live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Store {
    /// Apple Secure Enclave via `age-plugin-se`.
    Enclave,
    /// YubiKey PIV slot via `age-plugin-yubikey`.
    YubiKey,
}

/// How strongly a store protects the private key, used to rank stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StoreKind {
    /// Generated inside a device and never exportable.
    Hardware,
    /// Software key encrypted at rest (e.g. an OS keychain).
    Software,
    /// Plaintext secret key on disk.
    Plaintext,
}

impl Store {
    /// The store's protection class.
    pub fn kind(self) -> StoreKind {
        match self {
            Store::Enclave | Store::YubiKey => StoreKind::Hardware,
        }
    }

    /// The name used on the command line and in `.sopsy.yml`.
    pub fn as_str(self) -> &'static str {
        match self {
            Store::Enclave => "enclave",
            Store::YubiKey => "yubikey",
        }
    }

    /// Infer the store from an age recipient's prefix, where it is unambiguous.
    ///
    /// Plain `age1…` keys (portable, keychain, break-glass) cannot be told
    /// apart from their prefix, so they return `None`.
    pub fn from_recipient(public_key: &str) -> Option<Self> {
        if public_key.starts_with(enclave::RECIPIENT_PREFIX) {
            Some(Store::Enclave)
        } else if yubikey::is_recipient(public_key) {
            Some(Store::YubiKey)
        } else {
            None
        }
    }
}

impl fmt::Display for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A freshly generated (or re-derived) identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedIdentity {
    /// Which store produced it.
    pub store: Store,
    /// The age recipient (public key) to commit, e.g. `age1se1…`.
    pub public_key: String,
    /// The identity line `sops` reads locally, e.g. `AGE-PLUGIN-SE-1…`.
    pub identity: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardware_stores_rank_above_software() {
        assert_eq!(Store::Enclave.kind(), StoreKind::Hardware);
        assert_eq!(Store::YubiKey.kind(), StoreKind::Hardware);
        assert!(StoreKind::Hardware < StoreKind::Software);
        assert!(StoreKind::Software < StoreKind::Plaintext);
    }

    #[test]
    fn store_names_round_trip_through_display() {
        assert_eq!(Store::Enclave.to_string(), "enclave");
        assert_eq!(Store::YubiKey.to_string(), "yubikey");
    }

    #[test]
    fn infers_store_from_recipient_prefix() {
        assert_eq!(Store::from_recipient("age1se1qabc"), Some(Store::Enclave));
        assert_eq!(
            Store::from_recipient("age1yubikey1qabc"),
            Some(Store::YubiKey)
        );
        assert_eq!(Store::from_recipient("age1tag1qabc"), Some(Store::YubiKey));
        assert_eq!(Store::from_recipient("age1qportable"), None);
    }
}
