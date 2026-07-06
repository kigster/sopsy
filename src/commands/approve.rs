//! `sopsy approve` — grant a pending member access to the repository's secrets.
//!
//! Any **active** member can approve (not just the owner): the cryptography
//! requires only that the approver can already decrypt, so they can re-wrap the
//! data key to include the newcomer. Approving:
//!
//! 1. verifies the join request is fresh (within `join_request_ttl`),
//! 2. asks the approver to *vouch* that the key really belongs to the person,
//! 3. adds the key to `.sops.yaml`, flips the member to `active`, and records
//!    the provenance (`approved_by`, `approved_at`; `requested_at` is kept),
//! 4. runs `sops updatekeys` so every encrypted file gains a stanza the newcomer
//!    can open (the file bodies are not re-encrypted, only the wrapped key).
//!
//! If the re-key fails, all changes are rolled back (see [`recipient`]).

use std::time::{Duration, SystemTime};

use crate::cli::ApproveArgs;
use crate::commands::recipient::{
    ConfigSnapshot, SOPS_CONFIG_FILE_NAME, add_key_to_sops_yaml, assume_yes, current_repo_root,
    load_config, membership_paths, rewrap_error, run_updatekeys, sops_config_path,
};
use crate::config::{CONFIG_FILE_NAME, Config, MemberState, Recipient};
use crate::error::{Error, Result};
use crate::ui::Ui;

/// Run `sopsy approve`.
///
/// Approves one, several, or — interactively — every pending member. Each member
/// is resolved and vouched for *before* anything is written, then all approved
/// keys are added and a single `sops updatekeys` re-wraps the secrets once for
/// the whole batch — so the approved set lands together, or rolls back together.
///
/// With explicit names, each must resolve to a pending member and a declined
/// vouch aborts the run (strict). With no names, every pending member is walked
/// interactively and a declined or stale member is skipped, not fatal.
pub fn run(ui: &Ui, args: &ApproveArgs) -> Result<()> {
    ui.header("sopsy approve — granting membership");

    let repo = current_repo_root()?;
    let mut config = load_config(&repo)?;
    let sops_config = sops_config_path(&repo)?;
    let ttl = config.resolved_request_ttl();

    let interactive = args.names.is_empty();
    let candidates = resolve_candidates(&config, &args.names, interactive)?;
    if candidates.is_empty() {
        return Err(Error::Validation(
            "no pending requests to approve found".into(),
        ));
    }

    // Freshness + vouch, per member. Vouching is a human trust decision that no
    // crypto replaces, so it is never batched away.
    let mut approved: Vec<Recipient> = Vec::new();
    for member in &candidates {
        if !check_freshness(
            ui,
            &member.name,
            member.requested_at.as_deref(),
            ttl,
            args.force,
            interactive,
        )? {
            continue;
        }
        if confirm_vouch(ui, &member.name, &member.public_key)? {
            approved.push(member.clone());
        } else if interactive {
            ui.info(format!("skipped `{}`", member.name));
        } else {
            return Err(Error::Validation(
                "approval cancelled — nothing changed".into(),
            ));
        }
    }
    if approved.is_empty() {
        return Err(Error::Validation(
            "nothing approved — no changes made".into(),
        ));
    }

    // Snapshot once, mark every approved member active, add their keys, re-key once.
    let snapshot = ConfigSnapshot::capture(&repo, &sops_config);
    let approved_names: Vec<String> = approved.iter().map(|m| m.name.clone()).collect();

    // Provenance: who granted access and when. `requested_at` is deliberately
    // kept — together the two timestamps record the full request→grant history.
    let approver = resolve_approver(&config);
    let approved_at = humantime::format_rfc3339_seconds(SystemTime::now()).to_string();
    for member in &approved {
        for recipient in config.recipients.iter_mut() {
            if recipient.name == member.name {
                recipient.state = MemberState::Active;
                recipient.approved_at = Some(approved_at.clone());
                recipient.approved_by = approver.clone();
            }
        }
    }
    config.save_to_dir(&repo)?;
    let names = approved_names
        .iter()
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ");
    ui.success(format!("marked {names} active in {CONFIG_FILE_NAME}"));

    for member in &approved {
        let modified = add_key_to_sops_yaml(&sops_config, &member.public_key)?;
        if modified == 0 {
            ui.warn(format!(
                "no `age:` creation_rules matched in {SOPS_CONFIG_FILE_NAME}; left unchanged"
            ));
        } else {
            ui.success(format!(
                "added `{}`'s key to {modified} creation rule(s) in {SOPS_CONFIG_FILE_NAME}",
                member.name
            ));
        }
    }

    // A single re-wrap for the whole batch; roll the whole thing back on failure.
    if let Err(err) = run_updatekeys(ui, &repo, args.no_updatekeys) {
        snapshot.restore()?;
        ui.warn(format!("rolled back — {names} were not approved"));
        return Err(rewrap_error(err));
    }

    ui.success(format!("{names} approved and added to all encrypted files"));

    // Stage first (so "commands shown above" in the next-steps refers to them),
    // then print the human narrative.
    let staged = ui.stage_requested();
    if staged {
        let subject = format!("Approve sopsy access for {}", approved_names.join(", "));
        crate::git::stage_and_advise(ui, &repo, &membership_paths(&repo), &subject)?;
    }
    print_next_steps(ui, &approved_names, staged);
    Ok(())
}

/// Identify the approver for the provenance record, as `"Full Name (username)"`.
///
/// The system username (`$USER`/`$LOGNAME`) is matched against the *active*
/// recipients' `username` fields to recover the approver's recorded name; with
/// no match the bare username is used. Like member roles, this is a soft
/// audit record — Enclave age keys cannot sign, so it is not proof.
fn resolve_approver(config: &Config) -> Option<String> {
    let username = crate::commands::recipient::system_username()?;
    let named = config
        .recipients
        .iter()
        .find(|r| !r.is_pending() && r.username.as_deref() == Some(username.as_str()));
    Some(match named {
        Some(recipient) => format!("{} ({username})", recipient.name),
        None => username,
    })
}

/// Resolve the candidate set of pending members. With no names (interactive),
/// every pending member is a candidate. With explicit names, each must resolve
/// to a pending member — unknown or already-active is an error — and duplicates
/// are collapsed so `approve annie annie` is harmless.
fn resolve_candidates(
    config: &Config,
    names: &[String],
    interactive: bool,
) -> Result<Vec<Recipient>> {
    if interactive {
        return Ok(config
            .recipients
            .iter()
            .filter(|recipient| recipient.is_pending())
            .cloned()
            .collect());
    }

    let mut out = Vec::new();
    let mut seen = Vec::new();
    for raw in names {
        let name = raw.trim().to_string();
        if name.is_empty() || seen.contains(&name) {
            continue;
        }
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
        seen.push(name);
        out.push(member);
    }
    Ok(out)
}

/// Log a request's age and decide whether to proceed with it. Returns `Ok(false)`
/// only in interactive mode for a stale request (it is skipped); in strict mode a
/// stale request without `--force` is a hard error.
fn check_freshness(
    ui: &Ui,
    name: &str,
    requested_at: Option<&str>,
    ttl: Duration,
    force: bool,
    interactive: bool,
) -> Result<bool> {
    let Some(requested_at) = requested_at else {
        ui.warn(format!(
            "`{name}` request has no timestamp; cannot verify freshness"
        ));
        return Ok(true);
    };

    match request_age(requested_at) {
        Ok(age) => {
            ui.info(format!(
                "`{name}` requested {} ago",
                humantime::format_duration(Duration::from_secs(age.as_secs()))
            ));
            if age > ttl && !force {
                if interactive {
                    ui.warn(format!(
                        "`{name}` request is stale; skipping (pass --force to approve stale requests)"
                    ));
                    return Ok(false);
                }
                return Err(Error::Validation(format!(
                    "`{name}`'s request is older than the allowed window ({}); ask them to re-run \
                     `sopsy join`, or pass --force to approve anyway",
                    humantime::format_duration(ttl)
                )));
            }
            if age > ttl {
                ui.warn(format!(
                    "`{name}` request is stale, but --force was given; approving anyway"
                ));
            }
        }
        Err(_) => ui.warn(format!(
            "could not parse request timestamp `{requested_at}`; proceeding"
        )),
    }
    Ok(true)
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

/// Ask the approver to vouch that the key belongs to the named person, returning
/// whether they did. `SOPSY_ASSUME_YES` auto-vouches; a non-interactive terminal
/// without it is an error (there is no safe way to vouch unattended).
fn confirm_vouch(ui: &Ui, name: &str, public_key: &str) -> Result<bool> {
    ui.header("Verify before you vouch");
    ui.info(format!("name: {name}"));
    ui.info(format!("key:  {public_key}"));
    ui.warn("Confirm out-of-band (Slack/in person) that this key is really theirs.");

    if assume_yes() {
        ui.info("SOPSY_ASSUME_YES set — vouching automatically.");
        return Ok(true);
    }
    if !ui.is_interactive() {
        return Err(Error::NonInteractive {
            prompt: format!("vouch that this key belongs to {name}"),
            flag: "an interactive terminal (or set SOPSY_ASSUME_YES for automation)".to_string(),
        });
    }
    ui.confirm(
        &format!("Do you vouch that this key belongs to `{name}`?"),
        "--non-interactive",
        false,
    )
}

/// Print what the approver does next, and what the newcomer(s) do after merge.
///
/// When `staged` is set (the `--git` flow), the concrete commit/push commands
/// were already printed by [`crate::git::stage_and_advise`], so the manual
/// `git add` line is replaced with a pointer to them.
fn print_next_steps(ui: &Ui, names: &[String], staged: bool) {
    let joined = names.join(", ");
    ui.header("Next steps");
    ui.info("You (the approver):");
    if staged {
        ui.info("  1. Commit and push the staged changes (commands shown above).");
    } else {
        ui.info(format!(
            "  1. Commit the changes:  git add -A && git commit -m \"approve: {joined}\""
        ));
        ui.info("     (or re-run with --git to stage them automatically)");
    }
    ui.info("  2. Push to the PR branch and merge it (rebase first if main moved).");
    ui.info(format!(
        "{joined} then pull main and can `sopsy edit`/`sopsy decrypt` — Touch ID unlocks it."
    ));
}
