//! `sopsy join` — request membership in an encrypted repository.
//!
//! A newcomer runs this after cloning an already-initialised repo. It generates
//! their Secure Enclave identity (private key never leaves the device) and
//! records a **pending** entry in `.sopsy.yml` with a timestamp. A pending entry
//! is *not* added to `.sops.yaml`, so it grants no decryption ability — it is
//! purely a request. An existing member later runs [`crate::commands::approve`]
//! to grant access.
//!
//! The flow is intentionally newcomer-driven: the public key travels *to* the
//! repo (via a pull request), so no busy manager has to chase anyone for a key.

use std::path::PathBuf;
use std::time::SystemTime;

use crate::cli::JoinArgs;
use crate::commands::recipient;
use crate::config::{CONFIG_FILE_NAME, Config, MemberState, Recipient};
use crate::enclave;
use crate::error::{Error, Result};
use crate::keystore;
use crate::ui::Ui;

/// Run `sopsy join`.
pub fn run(ui: &Ui, args: &JoinArgs) -> Result<()> {
    ui.header("sopsy join — requesting membership");

    let name = args.name.trim().to_string();
    if name.is_empty() {
        return Err(Error::Validation("member name must not be empty".into()));
    }

    let (config_path, mut config) = load_target(args)?;

    // Refuse to clobber an existing entry.
    if let Some(existing) = config.recipient(&name) {
        return Err(Error::Validation(match existing.state {
            MemberState::Active => format!("`{name}` is already an active member"),
            MemberState::Pending => {
                format!("`{name}` already has a pending request; remove it before re-requesting")
            }
        }));
    }

    // Acquire the public key: an explicit one, or a freshly generated identity.
    let public_key = acquire_public_key(ui, args)?;

    // Reject the same key registered under another name.
    if let Some(other) = config
        .recipients
        .iter()
        .find(|r| r.public_key == public_key)
    {
        return Err(Error::Validation(format!(
            "this public key is already registered as `{}`",
            other.name
        )));
    }

    let now = humantime::format_rfc3339_seconds(SystemTime::now()).to_string();
    config
        .recipients
        .push(Recipient::pending(&name, &public_key, &now));
    config.save(&config_path)?;
    ui.success(format!(
        "recorded `{name}` as pending in {}",
        config_path.display()
    ));
    ui.info(format!("requested at {now}"));

    print_next_steps(ui, &name, &config);
    Ok(())
}

/// Resolve the `.sopsy.yml` to update and load it: an explicit `--sopsy-file`,
/// otherwise the conventional file in the repository root.
fn load_target(args: &JoinArgs) -> Result<(PathBuf, Config)> {
    if let Some(file) = &args.sopsy_file {
        let config = Config::load(file).map_err(|err| match err {
            Error::FileNotFound(path) => Error::Validation(format!(
                "{} not found — point --sopsy-file at an existing config",
                path.display()
            )),
            other => other,
        })?;
        Ok((file.clone(), config))
    } else {
        let repo = recipient::current_repo_root()?;
        let config = recipient::load_config(&repo)?;
        Ok((repo.join(CONFIG_FILE_NAME), config))
    }
}

/// Obtain the member's public key: use `--public-key`, else generate a Secure
/// Enclave identity and show it.
fn acquire_public_key(ui: &Ui, args: &JoinArgs) -> Result<String> {
    if let Some(key) = args.public_key.as_deref() {
        let key = key.trim().to_string();
        if key.is_empty() {
            return Err(Error::Validation("--public-key must not be empty".into()));
        }
        ui.success("Using supplied age public key.");
        return Ok(key);
    }

    enclave::ensure_available()?;
    let spinner = ui.spinner("Generating Secure Enclave identity (Touch ID may prompt)…");
    let identity = enclave::generate_identity_with_args(&args.age_args);
    spinner.finish_and_clear();
    let identity = identity?;
    ui.success("Created a Secure Enclave-backed identity.");
    ui.info("The private key stays in the Secure Enclave and never leaves this device.");

    // Persist the identity handle now so that, once an approver grants access,
    // `sopsy edit`/`secrets decrypt` can find it (behind Touch ID) to unlock the
    // repo. The handle is not secret key material.
    let keys_path =
        keystore::store_identity(args.name.trim(), &identity.public_key, &identity.identity)?;
    ui.success(format!("Stored your identity in {}.", keys_path.display()));

    ui.header("Your public key");
    ui.animated_line(&identity.public_key);
    Ok(identity.public_key)
}

/// Print what the newcomer does next, and what an approver will do.
fn print_next_steps(ui: &Ui, name: &str, config: &Config) {
    ui.header("Next steps");
    ui.info("You (the new member):");
    ui.info(format!(
        "  1. Commit the change:  git add {CONFIG_FILE_NAME} && git commit -m \"join: request access for {name}\""
    ));
    ui.info("  2. Push the branch and open a pull request.");
    ui.info("  3. Ask any current member to approve you.");
    ui.info("An approver (any active member) then runs, on your PR branch:");
    ui.info(format!("     sopsy approve {name}"));
    ui.info(
        "After they commit and merge, pull main and run `sopsy edit <file>` — Touch ID unlocks it.",
    );
    ui.warn(format!(
        "Approve promptly: this request expires after {} (set by join_request_ttl).",
        humantime::format_duration(config.resolved_request_ttl())
    ));
}
