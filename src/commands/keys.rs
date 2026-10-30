//! Member key generation shared by `init`, `join` and `recipient keygen`:
//! pick a store (`--store`, the member's priority, the repo's allowed set),
//! generate the identity there, and persist it where `sops` will find it.

use crate::cli::StoreArgs;
use crate::error::{Error, Result};
use crate::hardware::{
    self, Availability, GeneratedIdentity, KeyOptions, Store, StoreKind, yubikey,
};
use crate::ui::Ui;

/// Choose a store, generate a key in it and, with `persist`, save the local
/// identity. `label` names the key (recipient name).
pub(crate) fn generate(
    ui: &Ui,
    key: &StoreArgs,
    label: &str,
    allowed: Option<&[Store]>,
    without_touch: bool,
    extra_args: &[String],
    persist: bool,
) -> Result<GeneratedIdentity> {
    let store = choose_store(ui, key, allowed)?;
    if without_touch && store.kind() != StoreKind::Hardware {
        return Err(Error::Validation(format!(
            "--without-touch-id applies to hardware stores only, not `{store}`"
        )));
    }
    warn_if_weak(ui, store);

    let mut yubikey_opts = yubikey::GenerateOptions::new(format!("sopsy-{label}"));
    yubikey_opts.serial = key.yubikey_serial;
    yubikey_opts.slot = key.yubikey_slot;
    if let Some(pin) = key.pin_policy {
        yubikey_opts.pin_policy = pin;
    }
    if let Some(touch) = key.touch_policy {
        yubikey_opts.touch_policy = touch;
    }
    let options = KeyOptions {
        label: label.to_string(),
        without_touch,
        yubikey: yubikey_opts,
        new_slot: key.new_slot,
    };

    let (identity, reused) = match store {
        // The YubiKey plugin prompts for the PIN and a touch on the terminal,
        // so it must not run under a spinner.
        Store::YubiKey => {
            ui.info("Talking to your YubiKey: enter its PIN and touch it when it blinks.");
            hardware::generate(store, &options, extra_args)?
        }
        _ => {
            let spinner = ui.spinner(format!(
                "Generating a {} identity{}…",
                store.display_name(),
                if store == Store::Enclave && !without_touch {
                    " (Touch ID may prompt)"
                } else {
                    ""
                }
            ));
            let result = hardware::generate(store, &options, extra_args);
            spinner.finish_and_clear();
            result?
        }
    };
    if reused {
        ui.success("Reusing the existing age key on your YubiKey (pass --new-slot for a new one).");
    } else {
        ui.success(format!(
            "Created a {}-backed identity.",
            store.display_name()
        ));
    }
    ui.info(match store.kind() {
        StoreKind::Hardware => format!(
            "The private key stays in the {} and never leaves it.",
            store.display_name()
        ),
        StoreKind::Software => format!(
            "The private key is encrypted in the {}; any program running as you can read it.",
            store.display_name()
        ),
        StoreKind::Plaintext => "The private key is stored unencrypted on this machine.".into(),
    });

    if persist {
        let location = hardware::persist(label, &identity)?;
        ui.success(format!("Stored your identity in {location}."));
    }
    Ok(identity)
}

/// Resolve the store: explicit `--store`, else the ready stores in priority
/// order (prompting when interactive and there is a real choice).
fn choose_store(ui: &Ui, key: &StoreArgs, allowed: Option<&[Store]>) -> Result<Store> {
    let priority = hardware::priority()?;
    let ready = hardware::candidates(key.store.store(), allowed, &priority, Store::probe)?;
    if ready.len() == 1 || !ui.is_interactive() {
        return Ok(ready[0]);
    }
    let options: Vec<String> = ready
        .iter()
        .map(|s| format!("{s} — {} ({})", s.display_name(), s.kind().as_str()))
        .collect();
    let picked = ui.select("Where should your private key live?", "--store", options)?;
    let name = picked.split_whitespace().next().unwrap_or_default();
    name.parse()
}

/// Say so when the chosen store keeps the secret in software.
fn warn_if_weak(ui: &Ui, store: Store) {
    match store.kind() {
        StoreKind::Hardware => {}
        StoreKind::Software => ui.warn(format!(
            "Using the {}: a software key, weaker than a Secure Enclave or YubiKey.",
            store.display_name()
        )),
        StoreKind::Plaintext => {
            ui.banner_warn("Your private key will be a PLAINTEXT file on this machine.");
            for s in Store::ALL.into_iter().filter(|s| *s != Store::File) {
                if let Availability::Unavailable { reason }
                | Availability::MissingTool { install: reason } = s.probe()
                {
                    ui.warn(format!("  {s} not used: {reason}"));
                }
            }
        }
    }
}

/// Check a supplied public key against the repo's allowed set, returning the
/// store to record: `declared` (from `--store`), else what the key's prefix
/// implies.
pub(crate) fn check_allowed(
    allowed: Option<&[Store]>,
    public_key: &str,
    declared: Option<Store>,
) -> Result<Option<Store>> {
    let store = declared.or_else(|| Store::from_recipient(public_key));
    let Some(allowed) = allowed else {
        return Ok(store);
    };
    match store {
        Some(s) if allowed.contains(&s) => Ok(Some(s)),
        Some(s) => Err(Error::Validation(format!(
            "key store `{s}` is not allowed; this repository allows only: {}",
            hardware::names(allowed)
        ))),
        None => Err(Error::Validation(format!(
            "cannot tell where this key is stored; this repository allows only: {} \
             (pass --store to declare it)",
            hardware::names(allowed)
        ))),
    }
}

/// Reject anything that is not an age recipient.
pub(crate) fn validate_public_key(key: &str) -> Result<String> {
    let key = key.trim();
    if key.starts_with("age1") && key.len() > 4 && !key.contains(char::is_whitespace) {
        Ok(key.to_string())
    } else {
        Err(Error::Validation(format!(
            "`{key}` is not an age public key (expected age1…)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_set_admits_known_stores_only() {
        let allowed = [Store::YubiKey, Store::Keychain];
        assert_eq!(
            check_allowed(Some(&allowed), "age1yubikey1qx", None).unwrap(),
            Some(Store::YubiKey)
        );
        assert_eq!(
            check_allowed(Some(&allowed), "age1qplain", Some(Store::Keychain)).unwrap(),
            Some(Store::Keychain)
        );
        assert!(check_allowed(Some(&allowed), "age1se1qx", None).is_err());
        assert!(check_allowed(Some(&allowed), "age1qplain", None).is_err());
        assert_eq!(check_allowed(None, "age1qplain", None).unwrap(), None);
        assert_eq!(
            check_allowed(None, "age1se1qx", None).unwrap(),
            Some(Store::Enclave)
        );
    }

    #[test]
    fn public_keys_must_look_like_age_recipients() {
        assert!(validate_public_key(" age1qqqqqqqqqqqq ").is_ok());
        for bad in ["n", "", "age1", "AGE-SECRET-KEY-1X", "age1 qqqqqqqqqq"] {
            assert!(validate_public_key(bad).is_err(), "{bad:?}");
        }
    }
}
