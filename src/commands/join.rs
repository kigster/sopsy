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
use crate::commands::keys;
use crate::commands::recipient;
use crate::config::{CHECKSUM_FILE_NAME, CONFIG_FILE_NAME, Config, MemberState, Recipient};
use crate::error::{Error, Result};
use crate::hardware::Store;
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

    // Acquire the public key: an explicit one, or a freshly generated identity
    // in a store the repository allows.
    let allowed = config.allowed_stores()?;
    let (public_key, store) = acquire_public_key(ui, args, allowed.as_deref())?;

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

    // Record both halves of the requester's identity: the human name (the
    // positional argument) and the system username (`--username` or `$USER`).
    let username = args
        .username
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(str::to_string)
        .or_else(recipient::system_username);

    let now = humantime::format_rfc3339_seconds(SystemTime::now()).to_string();
    config.recipients.push(Recipient {
        username,
        ..Recipient::pending(&name, &public_key, &now).with_store(store)
    });
    config.save(&config_path)?;
    ui.banner_success(format!(
        "recorded `{name}` as pending in {}",
        config_path.display()
    ));
    ui.info(format!("requested at {now}"));

    let staged = ui.stage_requested();
    if staged {
        // `join` touches only its `.sopsy.yml` and the `.sopsy.sha` sidecar. Stage
        // relative to that file's directory (the repo root, or wherever an
        // explicit `--sopsy-file` lives).
        let repo = config_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let files = [config_path.clone(), Config::checksum_path(&config_path)];
        crate::git::stage_and_advise(
            ui,
            repo,
            &files,
            &format!("Request sopsy access for {name}"),
        )?;
    }
    print_next_steps(ui, &name, &config, staged);
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

/// Obtain the member's public key and its store: use `--public-key`, else
/// generate an identity (in an allowed store) and show it.
fn acquire_public_key(
    ui: &Ui,
    args: &JoinArgs,
    allowed: Option<&[Store]>,
) -> Result<(String, Option<Store>)> {
    if let Some(key) = args.public_key.as_deref() {
        if key.trim().is_empty() {
            return Err(Error::Validation("--public-key must not be empty".into()));
        }
        let key = keys::validate_public_key(key)?;
        let store = keys::check_allowed(allowed, &key, args.key.store.store())?;
        ui.success("Using supplied age public key.");
        return Ok((key, store));
    }

    // Persist the identity now so that, once an approver grants access,
    // `sopsy edit`/`secrets decrypt` can find it to unlock the repo.
    let identity = keys::generate(
        ui,
        &args.key,
        args.name.trim(),
        allowed,
        args.without_touch_id,
        &args.age_args,
        true,
    )?;

    ui.header("Your public key");
    ui.animated_line(&identity.public_key);
    Ok((identity.public_key, Some(identity.store)))
}

/// Print what the newcomer does next, and what an approver will do.
///
/// When `staged` is set (the `--git` flow), the commit/push commands were
/// already printed by [`crate::git::stage_and_advise`], so step 1 points at them
/// instead of repeating a manual `git add`.
fn print_next_steps(ui: &Ui, name: &str, config: &Config, staged: bool) {
    ui.header("Next steps");
    ui.info("You (the new member):");
    if staged {
        ui.info("  1. Commit and push the staged change (commands shown above).");
    } else {
        ui.info(format!(
            "  1. Commit the change:  git add {CONFIG_FILE_NAME} {CHECKSUM_FILE_NAME} && git commit -m \"join: request access for {name}\""
        ));
        ui.info("     (or re-run with --git to stage it automatically)");
    }
    ui.info("  2. Push the branch and open a pull request.");
    ui.info("  3. Ask any current member to approve you.");
    ui.info("An approver (any active member) then runs, on your PR branch:");
    ui.info(format!("     sopsy approve {name}"));
    ui.info("After they commit and merge, pull main and run `sopsy edit <file>` to unlock it.");
    ui.warn(format!(
        "Approve promptly: this request expires after {} (set by join_request_ttl).",
        humantime::format_duration(config.resolved_request_ttl())
    ));
}
