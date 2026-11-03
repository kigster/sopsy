//! `sopsy recipient rotate`: swap a member's key for a new one under the same
//! name, optionally under a new data key as well.

use super::*;
use crate::cli::RecipientRotateArgs;

/// Replace a member's key with a freshly generated (or reused YubiKey) key
/// under the same name, then re-wrap every secret for the new key.
///
/// The old key still decrypts during `updatekeys` (it is in `keys.txt`), and
/// is no longer a recipient afterwards. `updatekeys` keeps the data key, so
/// `--new-data-key` also re-encrypts every file under a fresh one. A failed
/// re-key rolls the config back.
pub(super) fn rotate(ui: &Ui, args: &RecipientRotateArgs) -> Result<()> {
    ui.header("sopsy recipient rotate");

    let repo = current_repo_root()?;
    let mut config = load_config(&repo)?;
    let sops_config = sops_config_path(&repo)?;
    let user = system_username();

    let name = rotate_target(ui, &config, args.name.as_deref(), user.as_deref())?;
    let old = config
        .recipient(&name)
        .cloned()
        .ok_or_else(|| Error::Validation(format!("no recipient named `{name}`")))?;
    if old.break_glass {
        return Err(Error::Validation(format!(
            "`{name}` is the break-glass key; make a new one with `sopsy recipient break-glass`, \
             then remove this one with `sopsy recipient remove {name}`"
        )));
    }
    if old.state != MemberState::Active {
        return Err(Error::Validation(format!(
            "`{name}` is not active yet; a pending member runs `sopsy join` again instead"
        )));
    }
    check_owner(&old, user.as_deref(), args.skip_owner_check)?;

    let allowed = config.allowed_stores()?;
    let identity = keys::generate(
        ui,
        &args.key,
        &name,
        allowed.as_deref(),
        args.presence.without_touch_id,
        &args.age_args,
        true,
    )?;
    if identity.public_key == old.public_key {
        ui.info(format!("that is already `{name}`'s key; nothing to rotate"));
        return Ok(());
    }
    if let Some(other) = config
        .recipients
        .iter()
        .find(|r| r.public_key == identity.public_key)
    {
        return Err(Error::Validation(format!(
            "that key is already registered as `{}`",
            other.name
        )));
    }

    let snapshot = ConfigSnapshot::capture(&repo, &sops_config);
    if let Some(member) = config.recipients.iter_mut().find(|r| r.name == name) {
        member.public_key = identity.public_key.clone();
        member.store = Some(identity.store);
    }
    config.save_to_dir(&repo)?;
    add_key_to_sops_yaml(&sops_config, &identity.public_key)?;
    remove_key_from_sops_yaml(&sops_config, &old.public_key)?;
    ui.success(format!(
        "replaced `{name}`'s key in {CONFIG_FILE_NAME} and {SOPS_CONFIG_FILE_NAME}"
    ));

    if let Err(err) = run_updatekeys(ui, &repo, false) {
        return Err(snapshot.roll_back(ui, err, "the old key is still in use"));
    }
    ui.success(format!(
        "rotated `{name}` to a {} key",
        identity.store.display_name()
    ));

    if args.new_data_key {
        new_data_key(ui, &repo)?;
        ui.info(
            "The old key is no longer a recipient, and the files are encrypted under a new \
             data key it never saw. Old versions in git history still open with it: if it \
             was lost or stolen, change the secret values themselves.",
        );
    } else {
        ui.info(
            "The old key is no longer a recipient. The data key itself is unchanged, so \
             anyone who held the old key can still read these files and their git history. \
             If it was lost or stolen, run `sopsy recipient rotate --new-data-key` (or \
             `sops rotate`) and change the secret values.",
        );
    }
    maybe_stage(ui, &repo, &format!("Rotate sopsy key for {name}"))?;
    Ok(())
}

/// Which recipient `rotate` replaces: the named one, else the caller's own
/// active key (asking when there are several).
fn rotate_target(
    ui: &Ui,
    config: &Config,
    name: Option<&str>,
    user: Option<&str>,
) -> Result<String> {
    if let Some(name) = name {
        return Ok(name.trim().to_string());
    }
    let mine: Vec<String> = config
        .recipients
        .iter()
        .filter(|r| !r.break_glass && r.state == MemberState::Active)
        .filter(|r| user.is_some() && r.username.as_deref() == user)
        .map(|r| r.name.clone())
        .collect();
    match mine.len() {
        0 => Err(Error::Validation(format!(
            "no active key of yours (`{}`) in {CONFIG_FILE_NAME}; pass the recipient name",
            user.unwrap_or("unknown user")
        ))),
        1 => Ok(mine[0].clone()),
        _ => ui.select("Which of your keys should be rotated?", "NAME", mine),
    }
}

/// Only the key's owner may rotate it. An unknown owner (an older config with
/// no `username`) or an unknown caller (`$USER` unreadable) is refused too,
/// unless `--skip-owner-check` says the caller has checked.
fn check_owner(old: &Recipient, me: Option<&str>, skip: bool) -> Result<()> {
    if skip {
        return Ok(());
    }
    let name = &old.name;
    match (old.username.as_deref(), me) {
        (Some(owner), Some(me)) if owner == me => Ok(()),
        (Some(owner), Some(_)) => Err(Error::Validation(format!(
            "`{name}` belongs to `{owner}`; only they can rotate it, on their own machine"
        ))),
        (None, _) => Err(Error::Validation(format!(
            "`{name}` has no recorded owner in {CONFIG_FILE_NAME}; if it is yours, \
             pass --skip-owner-check"
        ))),
        (Some(_), None) => Err(Error::Validation(
            "cannot tell who you are ($USER is not set); pass --skip-owner-check if this \
             key is yours"
                .into(),
        )),
    }
}

/// Re-encrypt every managed file under a new data key (`sops rotate -i`).
fn new_data_key(ui: &Ui, repo: &Path) -> Result<()> {
    let globs = load_config(repo)?.encrypted_globs;
    for file in collect_encrypted_files(repo, &globs)? {
        sops::rotate_in_place(&file, sops::FileType::from_path(&file))?;
        ui.success(format!(
            "new data key for {}",
            file.strip_prefix(repo).unwrap_or(&file).display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(username: Option<&str>) -> Recipient {
        let mut recipient = Recipient::new("ada", "age1ada");
        recipient.username = username.map(String::from);
        recipient
    }

    #[test]
    fn only_a_known_owner_may_rotate() {
        assert!(check_owner(&member(Some("ada")), Some("ada"), false).is_ok());
        for (owner, me) in [
            (Some("ada"), Some("alan")),
            (None, Some("ada")),
            (Some("ada"), None),
            (None, None),
        ] {
            assert!(
                check_owner(&member(owner), me, false).is_err(),
                "{owner:?} {me:?}"
            );
            assert!(check_owner(&member(owner), me, true).is_ok());
        }
    }
}
