//! Private-key stores: where a member's age identity lives.
//!
//! Each store wraps an external tool (sopsy never reimplements the crypto) and
//! yields a [`GeneratedIdentity`]: the public recipient that gets committed to
//! `.sops.yaml`, plus the local identity `sops` needs to decrypt. For hardware
//! stores that identity is a non-secret handle — the private key never leaves
//! the device. For `keychain` and `file` it is the secret key itself.
//!
//! Stores fall into three groups, ranked most secure first:
//!
//! | Group         | Stores               |
//! | ------------- | -------------------- |
//! | `onchip`      | `enclave`            |
//! | `exthardware` | `yubikey`            |
//! | `software`    | `keychain`, `file`   |
//!
//! `auto` walks that order (or `SOPSY_PRIVATE_KEY_STORE_PRIORITY`), filtered by
//! the repository's `key_policy.required` allowed set, and picks the first store
//! this machine can use. See `.plans/001-yubikey-support/plan.md`.

pub mod enclave;
pub mod keychain;
pub mod yubikey;

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::{age, keystore};

/// Environment variable holding a member's personal store order for `auto`.
pub const PRIORITY_ENV: &str = "SOPSY_PRIVATE_KEY_STORE_PRIORITY";

/// A place a member's private key can live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Store {
    /// Apple Secure Enclave via `age-plugin-se`.
    Enclave,
    /// YubiKey PIV slot via `age-plugin-yubikey`.
    YubiKey,
    /// OS keyring: macOS Keychain or Linux Secret Service.
    Keychain,
    /// Plaintext `AGE-SECRET-KEY-1…` in the local `keys.txt` (mode `0600`).
    File,
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

impl StoreKind {
    /// Lowercase label shown in listings.
    pub fn as_str(self) -> &'static str {
        match self {
            StoreKind::Hardware => "hardware",
            StoreKind::Software => "software",
            StoreKind::Plaintext => "plaintext",
        }
    }
}

/// Named groups of stores accepted wherever a store name is.
const GROUPS: &[(&str, &[Store])] = &[
    ("onchip", &[Store::Enclave]),
    ("exthardware", &[Store::YubiKey]),
    ("software", &[Store::Keychain, Store::File]),
];

impl Store {
    /// Every store, most secure first. This is the default `auto` order.
    pub const ALL: [Store; 4] = [Store::Enclave, Store::YubiKey, Store::Keychain, Store::File];

    /// The store's protection class.
    pub fn kind(self) -> StoreKind {
        match self {
            Store::Enclave | Store::YubiKey => StoreKind::Hardware,
            Store::Keychain => StoreKind::Software,
            Store::File => StoreKind::Plaintext,
        }
    }

    /// The name used on the command line and in `.sopsy.yml`.
    pub fn as_str(self) -> &'static str {
        match self {
            Store::Enclave => "enclave",
            Store::YubiKey => "yubikey",
            Store::Keychain => "keychain",
            Store::File => "file",
        }
    }

    /// Human-readable name for messages.
    pub fn display_name(self) -> &'static str {
        match self {
            Store::Enclave => "Secure Enclave",
            Store::YubiKey => "YubiKey",
            Store::Keychain => keychain::DISPLAY_NAME,
            Store::File => "plaintext key file",
        }
    }

    /// Infer the store from an age recipient's prefix, where it is unambiguous.
    ///
    /// Plain `age1…` keys (keychain, file, break-glass) cannot be told apart
    /// from their prefix, so they return `None`.
    pub fn from_recipient(public_key: &str) -> Option<Self> {
        if public_key.starts_with(enclave::RECIPIENT_PREFIX) {
            Some(Store::Enclave)
        } else if yubikey::is_recipient(public_key) {
            Some(Store::YubiKey)
        } else {
            None
        }
    }

    /// Whether this machine can use the store right now.
    pub fn probe(self) -> Availability {
        match self {
            Store::Enclave => enclave::probe(),
            Store::YubiKey => yubikey::probe(),
            Store::Keychain => keychain::probe(),
            Store::File => match age::ensure_available() {
                Ok(()) => Availability::Ready,
                Err(_) => Availability::MissingTool {
                    install: "brew install age".to_string(),
                },
            },
        }
    }
}

impl fmt::Display for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Store {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        let value = value.trim().to_ascii_lowercase();
        Store::ALL
            .into_iter()
            .find(|s| s.as_str() == value)
            .ok_or_else(|| {
                Error::Validation(format!(
                    "unknown key store `{value}` (valid: {})",
                    names(&Store::ALL)
                ))
            })
    }
}

/// Comma-separated store names, for messages.
pub fn names(stores: &[Store]) -> String {
    stores
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Expand store and group names (`onchip`, `exthardware`, `software`) into
/// stores, in order, ignoring duplicates. Case-insensitive; entries may also be
/// comma-separated. Unknown names and an empty result are errors.
pub fn expand_selectors<S: AsRef<str>>(entries: &[S]) -> Result<Vec<Store>> {
    let mut stores = Vec::new();
    for entry in entries
        .iter()
        .flat_map(|e| e.as_ref().split(','))
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty())
    {
        let expanded = match GROUPS.iter().find(|(name, _)| *name == entry) {
            Some((_, group)) => group.to_vec(),
            None => vec![entry.parse::<Store>().map_err(|_| {
                Error::Validation(format!(
                    "unknown key store or group `{entry}` (valid: onchip, exthardware, software, {})",
                    names(&Store::ALL)
                ))
            })?],
        };
        for store in expanded {
            if !stores.contains(&store) {
                stores.push(store);
            }
        }
    }
    if stores.is_empty() {
        return Err(Error::Validation("no key stores listed".into()));
    }
    Ok(stores)
}

/// The member's `auto` order: [`PRIORITY_ENV`] when set, else [`Store::ALL`].
pub fn priority() -> Result<Vec<Store>> {
    match std::env::var(PRIORITY_ENV) {
        Ok(value) if !value.trim().is_empty() => expand_selectors(&[value])
            .map_err(|err| Error::Validation(format!("{PRIORITY_ENV}: {err}"))),
        _ => Ok(Store::ALL.to_vec()),
    }
}

/// Result of probing a store on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    /// Hardware and tooling are both present.
    Ready,
    /// The hardware is present but its tool is not installed.
    MissingTool {
        /// Command that installs the missing tool.
        install: String,
    },
    /// The store cannot work on this machine.
    Unavailable {
        /// Why, for the user.
        reason: String,
    },
}

/// Pick the stores `sopsy` may generate a key in, best first.
///
/// - `requested` is an explicit `--store` (`None` = `auto`).
/// - `allowed` is the repository's allowed set (`None` = no restriction). It
///   filters everything, `--store` included.
/// - `priority` is the member's `auto` order.
///
/// An explicit store must be allowed and ready. `auto` returns every ready
/// allowed store in priority order, but never skips past a store whose hardware
/// is present and only its tool is missing: that is an install-or-fail, not a
/// silent downgrade.
pub fn candidates(
    requested: Option<Store>,
    allowed: Option<&[Store]>,
    priority: &[Store],
    probe: impl Fn(Store) -> Availability,
) -> Result<Vec<Store>> {
    let permitted = |s: Store| allowed.is_none_or(|a| a.contains(&s));
    let policy_note = || {
        allowed
            .map(|a| format!("this repository allows only: {}", names(a)))
            .unwrap_or_default()
    };

    if let Some(store) = requested {
        if !permitted(store) {
            return Err(Error::Validation(format!(
                "key store `{store}` is not allowed; {}",
                policy_note()
            )));
        }
        return match probe(store) {
            Availability::Ready => Ok(vec![store]),
            Availability::MissingTool { install } => Err(Error::ToolNotFound(format!(
                "the {} store needs a tool that is not installed (run `{install}`)",
                store.display_name()
            ))),
            Availability::Unavailable { reason } => Err(Error::Validation(format!(
                "key store `{store}` is unavailable: {reason}"
            ))),
        };
    }

    let order: Vec<Store> = priority.iter().copied().filter(|s| permitted(*s)).collect();
    if order.is_empty() {
        return Err(Error::Validation(format!(
            "no allowed key store is in your priority list ({PRIORITY_ENV}); {}",
            policy_note()
        )));
    }

    let mut ready = Vec::new();
    let mut skipped = Vec::new();
    for store in order {
        match probe(store) {
            Availability::Ready => ready.push(store),
            Availability::MissingTool { install } if ready.is_empty() => {
                return Err(Error::ToolNotFound(format!(
                    "the {} store is available on this machine but its tool is missing; \
                     run `{install}` (or pick another store with --store)",
                    store.display_name()
                )));
            }
            Availability::MissingTool { .. } => {}
            Availability::Unavailable { reason } => skipped.push(format!("{store}: {reason}")),
        }
    }
    if ready.is_empty() {
        let note = policy_note();
        return Err(Error::Validation(format!(
            "no usable key store on this machine ({}){}{note}",
            skipped.join("; "),
            if note.is_empty() { "" } else { "; " }
        )));
    }
    Ok(ready)
}

/// A freshly generated (or re-derived) identity.
#[derive(Clone, PartialEq, Eq)]
pub struct GeneratedIdentity {
    /// Which store produced it.
    pub store: Store,
    /// The age recipient (public key) to commit, e.g. `age1se1…`.
    pub public_key: String,
    /// What `sops` reads locally: a plugin handle (`AGE-PLUGIN-SE-1…`) for
    /// hardware stores, the `AGE-SECRET-KEY-1…` for `keychain` and `file`.
    pub identity: String,
}

impl fmt::Debug for GeneratedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let identity = match self.store.kind() {
            StoreKind::Hardware => self.identity.as_str(),
            _ => "<redacted>",
        };
        f.debug_struct("GeneratedIdentity")
            .field("store", &self.store)
            .field("public_key", &self.public_key)
            .field("identity", &identity)
            .finish()
    }
}

/// Generation options shared by every store; each uses what applies to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyOptions {
    /// Label for the key (recipient name), used in comments and slot names.
    pub label: String,
    /// Drop the presence gate: enclave `--access-control=none`, YubiKey touch `never`.
    pub without_touch: bool,
    /// YubiKey generation and reuse settings.
    pub yubikey: yubikey::GenerateOptions,
    /// Always generate a new YubiKey key rather than reuse a matching one.
    pub new_slot: bool,
}

/// Generate an identity in `store`. `extra_args` are forwarded to the
/// hardware store's plugin.
///
/// YubiKey: an existing sopsy-usable key with matching policies (or in the
/// requested slot) is reused unless [`KeyOptions::new_slot`] is set. The second
/// value is `true` when an existing key was reused.
pub fn generate(
    store: Store,
    options: &KeyOptions,
    extra_args: &[String],
) -> Result<(GeneratedIdentity, bool)> {
    match store {
        Store::Enclave => {
            let mut args = Vec::new();
            if options.without_touch {
                args.push("--access-control=none".to_string());
            }
            args.extend(extra_args.iter().cloned());
            Ok((enclave::generate_identity_with_args(&args)?, false))
        }
        Store::YubiKey => {
            let mut opts = options.yubikey.clone();
            if options.without_touch {
                opts.touch_policy = yubikey::TouchPolicy::Never;
            }
            if !options.new_slot
                && let Some(existing) = yubikey::find_reusable(&yubikey::list(false)?, &opts)
            {
                return Ok((yubikey::identity_for(existing.serial, existing.slot)?, true));
            }
            Ok((yubikey::generate(&opts, extra_args)?, false))
        }
        Store::Keychain | Store::File => {
            let pair = age::generate_keypair()?;
            let secret = pair
                .identity
                .lines()
                .map(str::trim)
                .find(|l| l.starts_with("AGE-SECRET-KEY-"))
                .ok_or_else(|| Error::Validation("age-keygen printed no secret key".into()))?
                .to_string();
            Ok((
                GeneratedIdentity {
                    store,
                    public_key: pair.public_key,
                    identity: secret,
                },
                false,
            ))
        }
    }
}

/// Persist `identity` where `sops` (via sopsy) will find it, returning a
/// human description of where it went.
pub fn persist(label: &str, identity: &GeneratedIdentity) -> Result<String> {
    match identity.store {
        Store::Keychain => {
            keychain::store(&identity.public_key, &identity.identity)?;
            let path = keystore::register_keychain_key(label, &identity.public_key)?;
            Ok(format!(
                "the {} (indexed in {})",
                keychain::DISPLAY_NAME,
                path.display()
            ))
        }
        _ => {
            let path = keystore::store_identity(label, &identity.public_key, &identity.identity)?;
            Ok(path.display().to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_rank_by_kind() {
        assert_eq!(Store::Enclave.kind(), StoreKind::Hardware);
        assert_eq!(Store::YubiKey.kind(), StoreKind::Hardware);
        assert_eq!(Store::Keychain.kind(), StoreKind::Software);
        assert_eq!(Store::File.kind(), StoreKind::Plaintext);
        assert!(StoreKind::Hardware < StoreKind::Software);
        assert!(StoreKind::Software < StoreKind::Plaintext);
        assert_eq!(StoreKind::Plaintext.as_str(), "plaintext");
    }

    #[test]
    fn store_names_round_trip() {
        for store in Store::ALL {
            assert_eq!(store.to_string().parse::<Store>().unwrap(), store);
            assert!(!store.display_name().is_empty());
        }
        assert_eq!(" YubiKey ".parse::<Store>().unwrap(), Store::YubiKey);
        assert!("tpm".parse::<Store>().is_err());
    }

    #[test]
    fn stores_serialize_lowercase() {
        assert_eq!(
            serde_yaml_ng::to_string(&Store::YubiKey).unwrap().trim(),
            "yubikey"
        );
        let s: Store = serde_yaml_ng::from_str("keychain").unwrap();
        assert_eq!(s, Store::Keychain);
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

    #[test]
    fn groups_expand_in_order_without_duplicates() {
        assert_eq!(
            expand_selectors(&["software", "exthardware,keychain", "ONCHIP"]).unwrap(),
            [Store::Keychain, Store::File, Store::YubiKey, Store::Enclave]
        );
        assert!(expand_selectors(&["bogus"]).is_err());
        assert!(expand_selectors(&[",,"]).is_err());
    }

    #[test]
    fn generated_identity_debug_redacts_secrets() {
        let secret = GeneratedIdentity {
            store: Store::File,
            public_key: "age1x".into(),
            identity: "AGE-SECRET-KEY-1SHH".into(),
        };
        assert!(!format!("{secret:?}").contains("SHH"));
        let stub = GeneratedIdentity {
            store: Store::YubiKey,
            ..secret
        };
        assert!(format!("{stub:?}").contains("AGE-SECRET-KEY-1SHH"));
    }

    fn ready_except(
        missing: &'static [Store],
        absent: &'static [Store],
    ) -> impl Fn(Store) -> Availability {
        move |s| {
            if missing.contains(&s) {
                Availability::MissingTool {
                    install: format!("brew install {s}"),
                }
            } else if absent.contains(&s) {
                Availability::Unavailable {
                    reason: "absent".into(),
                }
            } else {
                Availability::Ready
            }
        }
    }

    #[test]
    fn auto_skips_absent_hardware() {
        let got = candidates(
            None,
            None,
            &Store::ALL,
            ready_except(&[], &[Store::Enclave]),
        );
        assert_eq!(got.unwrap(), [Store::YubiKey, Store::Keychain, Store::File]);
    }

    #[test]
    fn auto_never_downgrades_past_a_missing_tool() {
        let err = candidates(
            None,
            None,
            &Store::ALL,
            ready_except(&[Store::YubiKey], &[Store::Enclave]),
        )
        .unwrap_err();
        assert!(matches!(err, Error::ToolNotFound(m) if m.contains("brew install yubikey")));
    }

    #[test]
    fn auto_ignores_missing_tools_below_a_ready_store() {
        let got = candidates(
            None,
            None,
            &Store::ALL,
            ready_except(&[Store::Keychain], &[]),
        );
        assert_eq!(got.unwrap(), [Store::Enclave, Store::YubiKey, Store::File]);
    }

    #[test]
    fn allowed_set_filters_auto_and_explicit() {
        let allowed = [Store::YubiKey, Store::Keychain];
        let got = candidates(None, Some(&allowed), &Store::ALL, ready_except(&[], &[]));
        assert_eq!(got.unwrap(), [Store::YubiKey, Store::Keychain]);

        let err = candidates(
            Some(Store::File),
            Some(&allowed),
            &Store::ALL,
            ready_except(&[], &[]),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::Validation(m) if m.contains("allows only: yubikey, keychain"))
        );
    }

    #[test]
    fn explicit_store_must_be_ready() {
        assert_eq!(
            candidates(Some(Store::File), None, &[], ready_except(&[], &[])).unwrap(),
            [Store::File]
        );
        assert!(matches!(
            candidates(
                Some(Store::Enclave),
                None,
                &[],
                ready_except(&[], &[Store::Enclave])
            ),
            Err(Error::Validation(_))
        ));
        assert!(matches!(
            candidates(
                Some(Store::YubiKey),
                None,
                &[],
                ready_except(&[Store::YubiKey], &[])
            ),
            Err(Error::ToolNotFound(_))
        ));
    }

    #[test]
    fn nothing_usable_is_an_error_with_reasons() {
        let err = candidates(
            None,
            Some(&[Store::Enclave]),
            &Store::ALL,
            ready_except(&[], &[Store::Enclave]),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains("enclave: absent")));

        let err = candidates(
            None,
            Some(&[Store::Enclave]),
            &[Store::File],
            ready_except(&[], &[]),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains(PRIORITY_ENV)));
    }
}
