//! Member key generation shared by `init`, `join` and `recipient keygen`:
//! pick a store (`--store`, the member's priority, the repo's allowed set),
//! generate the identity there, and persist it where `sops` will find it.

use crate::cli::StoreArgs;
use crate::error::{Error, Result};
use crate::hardware::{
    self, Availability, GeneratedIdentity, KeyOptions, Store, StoreKind, yubikey,
};
use crate::ui::Ui;
use clap::ValueEnum;

/// Printed before `age-plugin-yubikey` takes the terminal: its own prompts
/// ask for a PUK without saying what one is.
const YUBIKEY_PROMPTS: [&str; 7] = [
    "Talking to your YubiKey: enter its PIN, and touch it when it blinks.",
    "Nothing is shown while you type a PIN or PUK; the plugin prints [hidden] afterwards.",
    "On a YubiKey still at factory settings (PIN 123456), the plugin makes you choose a",
    "  new PIN: 6 to 8 characters (letters, digits or symbols). It also asks for the PUK",
    "  (PIN Unblock Key), which resets a PIN locked by 3 wrong tries. The factory PUK is",
    "  12345678; if your organization set up the key, ask them. The plugin then sets the",
    "  PUK to your new PIN. 3 wrong PUKs lock it for good (only a PIV reset recovers).",
];

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
    let mut new_slot = key.new_slot;
    let mut pin_changed = false;
    if store == Store::YubiKey {
        if yubikey_opts.serial.is_none() {
            yubikey_opts.serial = choose_yubikey(ui)?;
        }
        if yubikey_opts.slot.is_none() && !new_slot && ui.is_interactive() {
            match choose_slot(ui, &yubikey_opts)? {
                Some(slot) => yubikey_opts.slot = Some(slot),
                None => new_slot = true,
            }
        }
        if new_slot && ui.is_interactive() {
            pin_changed = offer_separate_puk(ui, yubikey_opts.serial)?;
        }
    }
    let options = KeyOptions {
        label: label.to_string(),
        without_touch,
        yubikey: yubikey_opts,
        new_slot,
    };

    let (identity, reused) = match store {
        // The YubiKey plugin prompts for the PIN and a touch on the terminal,
        // so it must not run under a spinner.
        Store::YubiKey => {
            // Reusing a chosen slot only reads its stub: no PIN, no touch.
            // After sopsy changed the PIN and PUK, the factory-settings part is moot.
            if options.yubikey.slot.is_none() {
                let shown = if pin_changed {
                    2
                } else {
                    YUBIKEY_PROMPTS.len()
                };
                for line in &YUBIKEY_PROMPTS[..shown] {
                    ui.info(line);
                }
            }
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
        ui.success(
            "Reusing the existing age key on your YubiKey (pass --always-new-slot for a new one).",
        );
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

/// With several YubiKeys plugged in, ask which one to use. `None` means
/// there is only one, so the plugin needs no `--serial`.
fn choose_yubikey(ui: &Ui) -> Result<Option<u32>> {
    let count = yubikey::device_count();
    if count <= 1 {
        return Ok(None);
    }
    if !ui.is_interactive() {
        return Err(Error::Validation(format!(
            "{count} YubiKeys are plugged in; unplug all but one, or pass --yubikey-serial"
        )));
    }
    let serials = yubikey::known_serials();
    let prompt = format!("{count} YubiKeys are plugged in. Which one should hold your key?");
    let typed = if serials.len() >= count {
        let options = serials.iter().map(u32::to_string).collect();
        ui.select(&prompt, "--yubikey-serial", options)?
    } else {
        // YubiKeys hide their serial from USB, so some may be unknown.
        ui.info(
            "The serial number is printed on each YubiKey (`ykman list --serials` shows it too).",
        );
        if !serials.is_empty() {
            ui.info(format!("Serials sopsy can see: {}", join(&serials)));
        }
        ui.text(&format!("{prompt} Serial number:"), "--yubikey-serial")?
    };
    typed.trim().parse().map(Some).map_err(|_| {
        Error::Validation(format!("`{}` is not a YubiKey serial number", typed.trim()))
    })
}

/// The plugin sets a factory-default PUK to the new PIN. Offer to give the
/// PUK its own value first, with `ykman`; the PIN must change too, or the
/// plugin would still see the factory PIN and overwrite the PUK again.
/// Returns whether the PIN and PUK were changed.
fn offer_separate_puk(ui: &Ui, serial: Option<u32>) -> Result<bool> {
    const SEPARATE: &str = "Yes, set PUK separately.";
    const SAME: &str = "No, it's ok to keep them the same, just not the factory value.";
    let picked = ui.select(
        "If your YubiKey has a default factory PUK (the 'forgot PIN' special recovery PIN), \
         would you like to set it to something different than your YubiKey PIN?",
        "--yubikey-serial",
        vec![SEPARATE.into(), SAME.into()],
    )?;
    if picked != SEPARATE {
        return Ok(false);
    }
    if !yubikey::ykman_available() {
        ui.warn("Setting the PUK separately needs ykman (YubiKey Manager): brew install ykman");
        if ui.confirm(
            "Continue with the PUK set to your PIN instead?",
            "--yubikey-serial",
            false,
        )? {
            return Ok(false);
        }
        return Err(Error::Validation(
            "install ykman (`brew install ykman`) and run this again".into(),
        ));
    }
    ui.info("First the PUK: ykman asks for the current one (factory: 12345678), then the new one twice.");
    ui.info("Use 6 to 8 characters, and keep it somewhere safe, apart from your PIN.");
    yubikey::ykman_change(serial, yubikey::Credential::Puk)?;
    ui.info("Now the PIN: the current one (factory: 123456), then the new one twice (6 to 8 characters).");
    yubikey::ykman_change(serial, yubikey::Credential::Pin)?;
    ui.success("PUK and PIN changed; the plugin will ask only for your new PIN.");
    Ok(true)
}

/// Offer the age keys already on the YubiKey, matching policies first.
/// `None` means generate a new key.
fn choose_slot(ui: &Ui, opts: &yubikey::GenerateOptions) -> Result<Option<u8>> {
    let mut existing: Vec<_> = yubikey::list(false)?
        .into_iter()
        .filter(|id| opts.serial.is_none_or(|s| s == id.serial))
        .collect();
    if existing.is_empty() {
        return Ok(None);
    }
    existing.sort_by_key(|id| !id.matches_policies(opts.pin_policy, opts.touch_policy));
    const NEW: &str = "Generate a new key in the next free slot";
    let mut options: Vec<String> = existing
        .iter()
        .map(|id| {
            format!(
                "slot {} — {} (serial {}, PIN {}, touch {})",
                id.slot,
                id.name,
                id.serial,
                policy_name(id.pin_policy),
                policy_name(id.touch_policy)
            )
        })
        .collect();
    options.push(NEW.into());
    let picked = ui.select(
        "Your YubiKey already holds age keys. Reuse one?",
        "--always-new-slot",
        options,
    )?;
    Ok(picked
        .strip_prefix("slot ")
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|slot| slot.parse().ok()))
}

fn policy_name<P: ValueEnum>(policy: Option<P>) -> String {
    policy
        .and_then(|p| p.to_possible_value())
        .map_or_else(|| "unknown".into(), |v| v.get_name().to_string())
}

fn join(serials: &[u32]) -> String {
    serials
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
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
/// store to record.
///
/// The key's prefix wins over a declared store (`--store`, or `store:` in a
/// member's own `.sopsy.yml` entry): both are self-reported, so a declaration
/// that contradicts the key is rejected rather than trusted.
pub(crate) fn check_allowed(
    allowed: Option<&[Store]>,
    public_key: &str,
    declared: Option<Store>,
) -> Result<Option<Store>> {
    if let Some(declared) = declared
        && !Store::admits(public_key, declared)
    {
        return Err(Error::Validation(match Store::from_recipient(public_key) {
            Some(implied) => {
                format!("this is a {implied} key (from its prefix), not a {declared} key")
            }
            None => format!(
                "a plain age1… key cannot come from the {declared} store; \
                 hardware keys have their own prefix (age1se1…, age1yubikey1…)"
            ),
        }));
    }
    let store = Store::from_recipient(public_key).or(declared);
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
    fn a_declared_store_cannot_contradict_the_key() {
        let hardware = [Store::Enclave, Store::YubiKey];
        // A plain key claiming to be hardware is refused, allowed set or not.
        for declared in hardware {
            let err = check_allowed(Some(&hardware), "age1qplain", Some(declared)).unwrap_err();
            assert!(err.to_string().contains("plain age1… key cannot come from"));
            assert!(check_allowed(None, "age1qplain", Some(declared)).is_err());
        }
        // A hardware prefix fixes the store.
        let err = check_allowed(None, "age1se1qx", Some(Store::YubiKey)).unwrap_err();
        assert!(
            err.to_string()
                .contains("enclave key (from its prefix), not a yubikey")
        );
        assert!(check_allowed(None, "age1yubikey1qx", Some(Store::Keychain)).is_err());
        // Consistent declarations still pass.
        assert_eq!(
            check_allowed(None, "age1qplain", Some(Store::File)).unwrap(),
            Some(Store::File)
        );
        assert_eq!(
            check_allowed(None, "age1yubikey1qx", Some(Store::YubiKey)).unwrap(),
            Some(Store::YubiKey)
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
