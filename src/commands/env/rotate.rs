//! `sopsy rotate-data-key`: re-encrypt files under a new data key
//! (`sops rotate --in-place`).

use std::path::{Path, PathBuf};

use super::encrypted_file_type;
use crate::cli::RotateDataKeyArgs;
use crate::commands::keys::prompt_for_yubikey_if_needed;
use crate::commands::recipient::{
    LinkPolicy, current_repo_root, discover_and_warn, verify_before_rewrite,
};
use crate::error::{Error, Result};
use crate::sops;
use crate::ui::Ui;

/// Re-encrypt files under a new data key. With no files given, every
/// encrypted file the repository's `encrypted_globs` match.
///
/// A failing file does not stop the others: each is a separate, complete
/// rotation, so sopsy rotates what it can and then names what failed.
pub fn rotate_data_key(ui: &Ui, args: &RotateDataKeyArgs) -> Result<()> {
    ui.header("sopsy rotate-data-key");
    sops::ensure_available()?;
    // Files discovered from the globs are re-checked before each rewrite;
    // files named on the command line are the operator's explicit choice.
    let (files, repo) = if args.files.is_empty() {
        let repo = current_repo_root()?;
        (repository_files(ui, &repo)?, Some(repo))
    } else {
        (args.files.clone(), None)
    };
    if files.is_empty() {
        ui.warn("no encrypted files found; nothing to rotate");
        return Ok(());
    }
    prompt_for_yubikey_if_needed(ui)?;

    let mut failed = Vec::new();
    for file in &files {
        let rotated = repo
            .as_deref()
            .map_or(Ok(()), |repo| {
                verify_before_rewrite(repo, file, LinkPolicy::from_ui(ui))
            })
            .and_then(|()| encrypted_file_type(file, None))
            .and_then(|ty| sops::rotate_in_place(file, ty));
        match rotated {
            Ok(()) => ui.success(format!("new data key for {}", file.display())),
            Err(err) => {
                ui.warn(format!("{}: {err}", file.display()));
                failed.push(file.display().to_string());
            }
        }
    }
    let done = files.len() - failed.len();
    if !failed.is_empty() {
        return Err(Error::Validation(format!(
            "{} of {} files were not rotated: {}. The other {done} now use a new data key; \
             fix these and run `sopsy rotate-data-key` on them again",
            failed.len(),
            files.len(),
            failed.join(", ")
        )));
    }
    ui.info("Commit the re-encrypted files; every current recipient can still decrypt them.");
    Ok(())
}

/// Every managed encrypted file under `repo`, warning about the paths skipped.
fn repository_files(ui: &Ui, repo: &Path) -> Result<Vec<PathBuf>> {
    let globs = crate::config::Config::load_from_dir(repo)?.encrypted_globs;
    Ok(discover_and_warn(ui, repo, &globs))
}
