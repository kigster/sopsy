//! `sopsy approve` — grant a pending member access to the repository's secrets.
//!
//! Any **active** member can approve (not just the owner): the cryptography
//! requires only that the approver can already decrypt, so they can re-wrap the
//! data key to include the newcomer. Approving:
//!
//! 1. verifies the join request is fresh (within `join_request_ttl`),
//! 2. asks the approver to *vouch* that the key really belongs to the person,
//! 3. adds the key to `.sops.yaml` and flips the member to `active`,
//! 4. runs `sops updatekeys` so every encrypted file gains a stanza the newcomer
//!    can open (the file bodies are not re-encrypted, only the wrapped key).
//!
//! If the re-key fails, all changes are rolled back (see [`recipient`]).

use std::time::{Duration, SystemTime};

use crate::cli::ApproveArgs;
use crate::commands::recipient::{
    ConfigSnapshot, SOPS_CONFIG_FILE_NAME, add_key_to_sops_yaml, assume_yes, current_repo_root,
    load_config, rewrap_error, run_updatekeys, sops_config_path,
};
use crate::config::{CONFIG_FILE_NAME, MemberState};
use crate::error::{Error, Result};
use crate::ui::Ui;

/// Run `sopsy approve`.
pub fn run(ui: &Ui, args: &ApproveArgs) -> Result<()> {
    ui.header("sopsy approve — granting membership");

    let repo = current_repo_root()?;
    let mut config = load_config(&repo)?;
    let sops_config = sops_config_path(&repo)?;

    let name = args.name.trim().to_string();
    let member = config.recipient(&name).cloned().ok_or_else(|| {
        Error::Validation(format!(
            "no member named `{name}` — did they run `sopsy join`?"
        ))
    })?;
    if !member.is_pending() {
        return Err(Error::Validation(format!(
            "`{name}` is already an active member"
        )));
    }

    // 1. Freshness: reject stale requests unless --force.
    check_freshness(
        ui,
        member.requested_at.as_deref(),
        config.resolved_request_ttl(),
        args.force,
    )?;

    // 2. Vouch for identity. This is the human trust anchor no crypto replaces.
    confirm_vouch(ui, &name, &member.public_key)?;

    // 3+4. Snapshot, mutate both files, re-key; roll back on failure.
    let snapshot = ConfigSnapshot::capture(&repo, &sops_config);

    for recipient in config.recipients.iter_mut() {
        if recipient.name == name {
            recipient.state = MemberState::Active;
            recipient.requested_at = None;
        }
    }
    config.save_to_dir(&repo)?;
    ui.success(format!("marked `{name}` active in {CONFIG_FILE_NAME}"));

    let modified = add_key_to_sops_yaml(&sops_config, &member.public_key)?;
    if modified == 0 {
        ui.warn(format!(
            "no `age:` creation_rules matched in {SOPS_CONFIG_FILE_NAME}; left unchanged"
        ));
    } else {
        ui.success(format!(
            "added the key to {modified} creation rule(s) in {SOPS_CONFIG_FILE_NAME}"
        ));
    }

    if let Err(err) = run_updatekeys(ui, &repo, args.no_updatekeys) {
        snapshot.restore()?;
        ui.warn(format!("rolled back — `{name}` was not approved"));
        return Err(rewrap_error(err));
    }

    ui.success(format!(
        "`{name}` approved and added to all encrypted files"
    ));
    print_next_steps(ui, &name);
    Ok(())
}

/// Warn/refuse based on the age of the join request.
fn check_freshness(ui: &Ui, requested_at: Option<&str>, ttl: Duration, force: bool) -> Result<()> {
    let Some(requested_at) = requested_at else {
        ui.warn("request has no timestamp; cannot verify freshness");
        return Ok(());
    };

    match request_age(requested_at) {
        Ok(age) => {
            ui.info(format!(
                "request submitted {} ago",
                humantime::format_duration(Duration::from_secs(age.as_secs()))
            ));
            if age > ttl && !force {
                return Err(Error::Validation(format!(
                    "this request is older than the allowed window ({}); ask them to re-run \
                     `sopsy join`, or pass --force to approve anyway",
                    humantime::format_duration(ttl)
                )));
            }
            if age > ttl {
                ui.warn("request is stale, but --force was given; approving anyway");
            }
        }
        Err(_) => ui.warn(format!(
            "could not parse request timestamp `{requested_at}`; proceeding"
        )),
    }
    Ok(())
}

/// How long ago `requested_at` (RFC3339) was, relative to now.
fn request_age(requested_at: &str) -> Result<Duration> {
    let when = humantime::parse_rfc3339(requested_at)
        .map_err(|err| Error::Validation(format!("bad timestamp: {err}")))?;
    SystemTime::now()
        .duration_since(when)
        // A future timestamp means a clock skew / bogus request; treat as fresh.
        .or(Ok(Duration::ZERO))
}

/// Ask the approver to vouch that the key belongs to the named person.
fn confirm_vouch(ui: &Ui, name: &str, public_key: &str) -> Result<()> {
    ui.header("Verify before you vouch");
    ui.info(format!("name: {name}"));
    ui.info(format!("key:  {public_key}"));
    ui.warn("Confirm out-of-band (Slack/in person) that this key is really theirs.");

    if assume_yes() {
        ui.info("SOPSY_ASSUME_YES set — vouching automatically.");
        return Ok(());
    }
    if !ui.is_interactive() {
        return Err(Error::NonInteractive {
            prompt: format!("vouch that this key belongs to {name}"),
            flag: "an interactive terminal (or set SOPSY_ASSUME_YES for automation)".to_string(),
        });
    }
    let vouched = ui.confirm(
        &format!("Do you vouch that this key belongs to `{name}`?"),
        "--non-interactive",
        false,
    )?;
    if !vouched {
        return Err(Error::Validation(
            "approval cancelled — nothing changed".into(),
        ));
    }
    Ok(())
}

/// Print what the approver does next, and what the newcomer does after merge.
fn print_next_steps(ui: &Ui, name: &str) {
    ui.header("Next steps");
    ui.info("You (the approver):");
    ui.info(format!(
        "  1. Commit the changes:  git add -A && git commit -m \"approve: {name}\""
    ));
    ui.info("  2. Push to the PR branch and merge it (rebase first if main moved).");
    ui.info(format!(
        "{name} then pulls main and can `sopsy edit`/`sopsy decrypt` — Touch ID unlocks it."
    ));
}
