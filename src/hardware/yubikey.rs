//! YubiKey-backed age identities via `age-plugin-yubikey`.
//!
//! The plugin generates a P-256 key inside one of the YubiKey's 20 retired PIV
//! slots. The private key never leaves the device; what sopsy stores locally is
//! an `AGE-PLUGIN-YUBIKEY-1…` *stub* (serial + slot + tag), which is not secret.
//!
//! Recipient formats:
//!
//! - `age1yubikey1…` — printed by `age-plugin-yubikey` 0.5.x and earlier.
//! - `age1tag1…` — printed by newer releases. Encrypting to it needs a client
//!   with built-in support, or the plugin reachable on `PATH` as
//!   `age-plugin-tag`. Identities created by 0.5.x still carry the legacy
//!   `age1yubikey1…` recipient in a `# Legacy recipient:` comment, which sopsy
//!   prefers because every `sops` release understands it.
//!
//! The plugin's output is localized, so every invocation runs with `LC_ALL=C`
//! to get the English (parseable) strings.
//!
//! The binary is resolved via `SOPSY_AGE_PLUGIN_YUBIKEY_BIN` (default
//! `age-plugin-yubikey`) so tests can inject a fake that emits canned output.

use std::ffi::OsString;
use std::process::{Command, Output};

use super::{GeneratedIdentity, Store};
use crate::error::{Error, Result};

/// The default name of the external binary this module drives.
pub const PLUGIN_BIN: &str = "age-plugin-yubikey";

/// Environment variable that overrides the `age-plugin-yubikey` binary path.
pub const PLUGIN_BIN_ENV: &str = "SOPSY_AGE_PLUGIN_YUBIKEY_BIN";

/// Prefix of every YubiKey identity stub.
pub const IDENTITY_PREFIX: &str = "AGE-PLUGIN-YUBIKEY-";

/// Recipient prefix used by `age-plugin-yubikey` 0.5.x and earlier.
pub const LEGACY_RECIPIENT_PREFIX: &str = "age1yubikey1";

/// Recipient prefix used by newer `age-plugin-yubikey` releases.
pub const TAG_RECIPIENT_PREFIX: &str = "age1tag1";

/// Highest usable retired PIV slot (the plugin numbers them 1–20).
pub const MAX_SLOT: u8 = 20;

/// Whether `public_key` is a YubiKey recipient in either format.
pub fn is_recipient(public_key: &str) -> bool {
    public_key.starts_with(LEGACY_RECIPIENT_PREFIX) || public_key.starts_with(TAG_RECIPIENT_PREFIX)
}

/// When the YubiKey asks for its PIN. Fixed at generation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinPolicy {
    /// Every decryption.
    Always,
    /// Once per session (until the key is unplugged).
    Once,
    /// Never.
    Never,
}

/// When the YubiKey requires a physical touch. Fixed at generation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchPolicy {
    /// Every decryption.
    Always,
    /// Cached by the firmware for 15 seconds.
    Cached,
    /// Never.
    Never,
}

impl PinPolicy {
    /// The value the plugin accepts on `--pin-policy`.
    pub fn as_str(self) -> &'static str {
        match self {
            PinPolicy::Always => "always",
            PinPolicy::Once => "once",
            PinPolicy::Never => "never",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match first_word_lowercase(value).as_str() {
            "always" => Some(PinPolicy::Always),
            "once" => Some(PinPolicy::Once),
            "never" => Some(PinPolicy::Never),
            _ => None,
        }
    }
}

impl TouchPolicy {
    /// The value the plugin accepts on `--touch-policy`.
    pub fn as_str(self) -> &'static str {
        match self {
            TouchPolicy::Always => "always",
            TouchPolicy::Cached => "cached",
            TouchPolicy::Never => "never",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match first_word_lowercase(value).as_str() {
            "always" => Some(TouchPolicy::Always),
            "cached" => Some(TouchPolicy::Cached),
            "never" => Some(TouchPolicy::Never),
            _ => None,
        }
    }
}

/// One age identity found in a YubiKey slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotIdentity {
    /// YubiKey serial number.
    pub serial: u32,
    /// Retired slot, 1-indexed as the plugin shows it.
    pub slot: u8,
    /// Name given at generation time.
    pub name: String,
    /// Creation timestamp as printed by the plugin.
    pub created: String,
    /// PIN policy, if the plugin could read it.
    pub pin_policy: Option<PinPolicy>,
    /// Touch policy, if the plugin could read it.
    pub touch_policy: Option<TouchPolicy>,
    /// The recipient the plugin printed (`age1tag1…` or `age1yubikey1…`).
    pub recipient: String,
    /// The `age1yubikey1…` recipient, for identities created by plugin ≤ 0.5.
    pub legacy_recipient: Option<String>,
    /// The `AGE-PLUGIN-YUBIKEY-1…` stub, when the output included one.
    pub identity: Option<String>,
}

impl SlotIdentity {
    /// The recipient sopsy should commit: the legacy `age1yubikey1…` form when
    /// available (universally supported by `sops`), else the printed one.
    pub fn preferred_recipient(&self) -> &str {
        self.legacy_recipient.as_deref().unwrap_or(&self.recipient)
    }

    /// Whether this identity was generated with exactly these policies.
    pub fn matches_policies(&self, pin: PinPolicy, touch: TouchPolicy) -> bool {
        self.pin_policy == Some(pin) && self.touch_policy == Some(touch)
    }
}

/// Options for [`generate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateOptions {
    /// Name stored in the slot's certificate (e.g. `sopsy-kig`).
    pub name: String,
    /// Which YubiKey to use when several are connected.
    pub serial: Option<u32>,
    /// Which retired slot (1–20) to use; the plugin picks a free one if `None`.
    pub slot: Option<u8>,
    /// PIN policy for the new key.
    pub pin_policy: PinPolicy,
    /// Touch policy for the new key.
    pub touch_policy: TouchPolicy,
}

impl GenerateOptions {
    /// Options with sopsy's `convenience` defaults: PIN once, touch cached.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            serial: None,
            slot: None,
            pin_policy: PinPolicy::Once,
            touch_policy: TouchPolicy::Cached,
        }
    }

    fn to_args(&self) -> Result<Vec<String>> {
        let mut args = vec![
            "--generate".to_string(),
            format!("--name={}", self.name),
            format!("--pin-policy={}", self.pin_policy.as_str()),
            format!("--touch-policy={}", self.touch_policy.as_str()),
        ];
        if let Some(serial) = self.serial {
            args.push(format!("--serial={serial}"));
        }
        if let Some(slot) = self.slot {
            args.push(format!("--slot={}", validate_slot(slot)?));
        }
        Ok(args)
    }
}

/// Resolve the `age-plugin-yubikey` binary to invoke, honoring [`PLUGIN_BIN_ENV`].
fn plugin_bin() -> OsString {
    std::env::var_os(PLUGIN_BIN_ENV).unwrap_or_else(|| OsString::from(PLUGIN_BIN))
}

/// Verify `age-plugin-yubikey` is available, returning a friendly error otherwise.
pub fn ensure_available() -> Result<()> {
    let bin = plugin_bin();
    if which::which(&bin).is_ok() {
        return Ok(());
    }
    Err(Error::ToolNotFound(format!(
        "{} (install it with `brew install age-plugin-yubikey`; on Linux also run `pcscd`)",
        bin.to_string_lossy()
    )))
}

/// List the age identities on every connected YubiKey (`--list`).
///
/// With `all`, includes slots whose metadata could not be fully read
/// (`--list-all`). An empty vector means no YubiKey or no identities.
pub fn list(all: bool) -> Result<Vec<SlotIdentity>> {
    let flag = if all { "--list-all" } else { "--list" };
    let output = run(&[flag.to_string()])?;
    Ok(parse_blocks(&String::from_utf8_lossy(&output.stdout)))
}

/// Generate a new identity in a free (or the given) slot (`--generate`).
///
/// The plugin itself prompts for the PIN (and to change a default PIN/PUK on
/// first use) and asks for a touch, so this must run attached to a terminal.
pub fn generate(options: &GenerateOptions, extra_args: &[String]) -> Result<GeneratedIdentity> {
    let mut args = options.to_args()?;
    args.extend(extra_args.iter().cloned());
    let output = run(&args)?;
    single_identity(&String::from_utf8_lossy(&output.stdout))
}

/// Re-derive the identity stub for an existing key (`--identity`), without
/// consuming a new slot.
pub fn identity_for(serial: u32, slot: u8) -> Result<GeneratedIdentity> {
    let args = vec![
        "--identity".to_string(),
        format!("--serial={serial}"),
        format!("--slot={}", validate_slot(slot)?),
    ];
    let output = run(&args)?;
    single_identity(&String::from_utf8_lossy(&output.stdout))
}

/// Run the plugin with `args` in the C locale, mapping a non-zero exit to
/// [`Error::ProcessFailed`].
fn run(args: &[String]) -> Result<Output> {
    let output = Command::new(plugin_bin())
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .output()?;
    if !output.status.success() {
        return Err(Error::ProcessFailed {
            tool: PLUGIN_BIN.to_string(),
            code: output.status.code().unwrap_or(-1),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(output)
}

fn validate_slot(slot: u8) -> Result<u8> {
    if (1..=MAX_SLOT).contains(&slot) {
        Ok(slot)
    } else {
        Err(Error::Validation(format!(
            "YubiKey slot must be between 1 and {MAX_SLOT} (got {slot})"
        )))
    }
}

/// Turn identity-file output into exactly one [`GeneratedIdentity`].
fn single_identity(stdout: &str) -> Result<GeneratedIdentity> {
    let block = parse_blocks(stdout).into_iter().next().ok_or_else(|| {
        Error::Validation("could not find a YubiKey identity in age-plugin-yubikey output".into())
    })?;
    let identity = block.identity.clone().ok_or_else(|| {
        Error::Validation(format!(
            "could not find an {IDENTITY_PREFIX} identity in age-plugin-yubikey output"
        ))
    })?;
    Ok(GeneratedIdentity {
        store: Store::YubiKey,
        public_key: block.preferred_recipient().to_string(),
        identity,
    })
}

/// Parse the plugin's slot blocks. Each block starts at a
/// `#       Serial: N, Slot: M` line and looks like:
///
/// ```text
/// #       Serial: 12345678, Slot: 1
/// #         Name: age identity 1a2b3c4d
/// #      Created: Sun, 28 Oct 2026 17:00:00 +0000
/// #   PIN policy: Once   (A PIN is required once per session, if set)
/// # Touch policy: Cached (A physical touch is required for decryption, ...)
/// #    Recipient: age1tag1…            (identity output)
/// # Legacy recipient: age1yubikey1…    (plugin ≤ 0.5 keys only)
/// AGE-PLUGIN-YUBIKEY-1…                (identity output)
/// age1tag1…                            (list output)
/// ```
///
/// Blocks without any recipient are dropped.
fn parse_blocks(stdout: &str) -> Vec<SlotIdentity> {
    let mut blocks = Vec::new();
    let mut current: Option<SlotIdentity> = None;

    for line in stdout.lines().map(str::trim) {
        if let Some((serial, slot)) = parse_serial_slot(line) {
            if let Some(done) = current.take() {
                blocks.push(done);
            }
            current = Some(SlotIdentity {
                serial,
                slot,
                name: String::new(),
                created: String::new(),
                pin_policy: None,
                touch_policy: None,
                recipient: String::new(),
                legacy_recipient: None,
                identity: None,
            });
            continue;
        }
        let Some(block) = current.as_mut() else {
            continue;
        };
        if let Some(value) = comment_value(line, "Name:") {
            block.name = value.to_string();
        } else if let Some(value) = comment_value(line, "Created:") {
            block.created = value.to_string();
        } else if let Some(value) = comment_value(line, "PIN policy:") {
            block.pin_policy = PinPolicy::parse(value);
        } else if let Some(value) = comment_value(line, "Touch policy:") {
            block.touch_policy = TouchPolicy::parse(value);
        } else if let Some(value) = comment_value(line, "Legacy recipient:") {
            block.legacy_recipient = Some(value.to_string());
        } else if let Some(value) = comment_value(line, "Recipient:") {
            block.recipient = value.to_string();
        } else if line.starts_with(IDENTITY_PREFIX) {
            block.identity = Some(line.to_string());
        } else if is_recipient(line) && block.recipient.is_empty() {
            block.recipient = line.to_string();
        }
    }
    if let Some(done) = current {
        blocks.push(done);
    }

    blocks
        .into_iter()
        .filter(|b| !b.recipient.is_empty() || b.legacy_recipient.is_some())
        .map(|mut b| {
            if b.recipient.is_empty() {
                b.recipient = b.legacy_recipient.clone().unwrap_or_default();
            }
            b
        })
        .collect()
}

/// Parse `#       Serial: 12345678, Slot: 1`.
fn parse_serial_slot(line: &str) -> Option<(u32, u8)> {
    let rest = comment_value(line, "Serial:")?;
    let (serial, slot) = rest.split_once(',')?;
    let slot = slot.trim().strip_prefix("Slot:")?.trim();
    Some((serial.trim().parse().ok()?, slot.parse().ok()?))
}

/// For a `# <label> <value>` comment line, return the trimmed value.
fn comment_value<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    let body = line.strip_prefix('#')?.trim_start();
    body.strip_prefix(label).map(str::trim)
}

fn first_word_lowercase(value: &str) -> String {
    value
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTITY_NEW: &str = "\
#       Serial: 12345678, Slot: 3
#         Name: sopsy-kig
#      Created: Wed, 28 Oct 2026 17:00:00 +0000
#   PIN policy: Once   (A PIN is required once per session, if set)
# Touch policy: Cached (A physical touch is required for decryption, and is cached for 15 seconds)
#    Recipient: age1tag1qnewrecipient
AGE-PLUGIN-YUBIKEY-1QNEWSTUB
";

    const IDENTITY_LEGACY: &str = "\
#       Serial: 12345678, Slot: 1
#         Name: age identity 1a2b3c4d
#      Created: Sun, 01 Jan 2023 00:00:00 +0000
#   PIN policy: Always (A PIN is required for every decryption, if set)
# Touch policy: Always (A physical touch is required for every decryption)
#    Recipient: age1tag1qtagform
# Legacy recipient: age1yubikey1qlegacyform
AGE-PLUGIN-YUBIKEY-1QLEGACYSTUB
";

    const LIST_TWO: &str = "\
#       Serial: 12345678, Slot: 1
#         Name: age identity 1a2b3c4d
#      Created: Sun, 01 Jan 2023 00:00:00 +0000
#   PIN policy: Always (A PIN is required for every decryption, if set)
# Touch policy: Always (A physical touch is required for every decryption)
# Legacy recipient: age1yubikey1qlegacyform
age1tag1qtagform

#       Serial: 87654321, Slot: 2
#         Name: sopsy-kig
#      Created: Wed, 28 Oct 2026 17:00:00 +0000
#   PIN policy: Unknown
# Touch policy: Never  (A physical touch is NOT required to decrypt)
age1tag1qsecond


";

    #[test]
    fn parses_new_identity_output() {
        let id = single_identity(IDENTITY_NEW).unwrap();
        assert_eq!(id.store, Store::YubiKey);
        assert_eq!(id.public_key, "age1tag1qnewrecipient");
        assert_eq!(id.identity, "AGE-PLUGIN-YUBIKEY-1QNEWSTUB");
    }

    #[test]
    fn prefers_legacy_recipient_when_present() {
        let id = single_identity(IDENTITY_LEGACY).unwrap();
        assert_eq!(id.public_key, "age1yubikey1qlegacyform");
        assert_eq!(id.identity, "AGE-PLUGIN-YUBIKEY-1QLEGACYSTUB");
    }

    #[test]
    fn parses_metadata_and_policies() {
        let block = &parse_blocks(IDENTITY_NEW)[0];
        assert_eq!(block.serial, 12345678);
        assert_eq!(block.slot, 3);
        assert_eq!(block.name, "sopsy-kig");
        assert_eq!(block.created, "Wed, 28 Oct 2026 17:00:00 +0000");
        assert!(block.matches_policies(PinPolicy::Once, TouchPolicy::Cached));
        assert!(!block.matches_policies(PinPolicy::Always, TouchPolicy::Cached));
    }

    #[test]
    fn parses_list_output_with_several_keys() {
        let blocks = parse_blocks(LIST_TWO);
        assert_eq!(blocks.len(), 2);

        assert_eq!(blocks[0].recipient, "age1tag1qtagform");
        assert_eq!(blocks[0].preferred_recipient(), "age1yubikey1qlegacyform");
        assert_eq!(blocks[0].identity, None);

        assert_eq!(blocks[1].serial, 87654321);
        assert_eq!(blocks[1].slot, 2);
        assert_eq!(blocks[1].pin_policy, None, "Unknown is not a policy");
        assert_eq!(blocks[1].touch_policy, Some(TouchPolicy::Never));
        assert_eq!(blocks[1].preferred_recipient(), "age1tag1qsecond");
    }

    #[test]
    fn empty_output_means_no_identities() {
        assert!(parse_blocks("").is_empty());
        assert!(parse_blocks("\n\n").is_empty());
    }

    #[test]
    fn blocks_without_a_recipient_are_dropped() {
        let out = "#       Serial: 1, Slot: 1\n#         Name: half\n";
        assert!(parse_blocks(out).is_empty());
    }

    #[test]
    fn legacy_only_block_uses_legacy_as_recipient() {
        let out = "#       Serial: 1, Slot: 4\n# Legacy recipient: age1yubikey1qonly\n";
        let blocks = parse_blocks(out);
        assert_eq!(blocks[0].recipient, "age1yubikey1qonly");
    }

    #[test]
    fn lines_before_the_first_block_are_ignored() {
        let out = format!("noise\nage1tag1qstray\n{IDENTITY_NEW}");
        let blocks = parse_blocks(&out);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].recipient, "age1tag1qnewrecipient");
    }

    #[test]
    fn missing_stub_is_an_error() {
        let out = "#       Serial: 1, Slot: 1\n#    Recipient: age1tag1qx\n";
        let err = single_identity(out).unwrap_err();
        assert!(matches!(err, Error::Validation(m) if m.contains(IDENTITY_PREFIX)));
    }

    #[test]
    fn no_block_is_an_error() {
        assert!(matches!(
            single_identity("garbage\n").unwrap_err(),
            Error::Validation(_)
        ));
    }

    #[test]
    fn malformed_serial_lines_are_not_blocks() {
        assert_eq!(parse_serial_slot("#       Serial: abc, Slot: 1"), None);
        assert_eq!(parse_serial_slot("#       Serial: 1"), None);
        assert_eq!(parse_serial_slot("#       Serial: 1, Port: 2"), None);
        assert_eq!(parse_serial_slot("Serial: 1, Slot: 2"), None);
    }

    #[test]
    fn generate_options_build_plugin_args() {
        let mut opts = GenerateOptions::new("sopsy-kig");
        assert_eq!(
            opts.to_args().unwrap(),
            [
                "--generate",
                "--name=sopsy-kig",
                "--pin-policy=once",
                "--touch-policy=cached"
            ]
        );

        opts.serial = Some(42);
        opts.slot = Some(20);
        opts.pin_policy = PinPolicy::Always;
        opts.touch_policy = TouchPolicy::Never;
        let args = opts.to_args().unwrap();
        assert!(args.contains(&"--serial=42".to_string()));
        assert!(args.contains(&"--slot=20".to_string()));
        assert!(args.contains(&"--pin-policy=always".to_string()));
        assert!(args.contains(&"--touch-policy=never".to_string()));
    }

    #[test]
    fn slots_outside_1_to_20_are_rejected() {
        let mut opts = GenerateOptions::new("x");
        for bad in [0, 21] {
            opts.slot = Some(bad);
            assert!(matches!(opts.to_args(), Err(Error::Validation(_))));
        }
        assert!(matches!(identity_for(1, 0), Err(Error::Validation(_))));
    }

    #[test]
    fn recipient_prefixes_are_recognised() {
        assert!(is_recipient("age1yubikey1qabc"));
        assert!(is_recipient("age1tag1qabc"));
        assert!(!is_recipient("age1se1qabc"));
        assert!(!is_recipient("age1qabc"));
    }

    #[test]
    fn policy_names_match_plugin_flags() {
        assert_eq!(PinPolicy::Never.as_str(), "never");
        assert_eq!(TouchPolicy::Always.as_str(), "always");
        assert_eq!(
            PinPolicy::parse("Never  (A PIN is NOT required)"),
            Some(PinPolicy::Never)
        );
        assert_eq!(TouchPolicy::parse(""), None);
    }
}
