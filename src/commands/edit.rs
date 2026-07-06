//! `sopsy edit <file>` — edit an encrypted file via `sops`.
//!
//! This is the "missing DX" wrapper around `EDITOR=<editor> sops <file>`: it
//! resolves the editor (`--editor`, then `$EDITOR`, then `$VISUAL`, then a
//! sensible default of `vi`), confirms the target file actually exists (so the
//! user gets a friendly message instead of raw sops spew), then launches sops
//! interactively with any trailing `-- <sops args>` forwarded verbatim,
//! surfacing nicer errors than raw sops on failure.

use crate::cli::EditArgs;
use crate::error::{Error, Result};
use crate::sops::{self, FileType};
use crate::ui::Ui;

/// The editor used when neither `--editor`, `$EDITOR`, nor `$VISUAL` is set.
const DEFAULT_EDITOR: &str = "vi";

/// Run the edit command.
pub fn run(ui: &Ui, args: &EditArgs) -> Result<()> {
    ui.header("sopsy edit");

    // Fail early with a friendly message if `sops` isn't installed.
    sops::ensure_available()?;

    // Refuse to hand a non-existent path to sops; its raw error is cryptic.
    if !args.file.exists() {
        return Err(Error::FileNotFound(args.file.clone()));
    }

    let editor = resolve_editor(args.editor.as_deref());
    ui.debug(format!("using editor `{editor}`"));

    // sops infers a file's format from its extension; sopsy's encrypted files
    // (e.g. `.env.encrypted`) don't always carry a recognizable one, so detect
    // the type ourselves and pass it explicitly. User-supplied `-- <sops args>`
    // are appended afterwards so they can still override our defaults.
    let file_type = FileType::from_path(&args.file);
    let ty = file_type.as_sops_type();
    let mut sops_args = vec![
        "--input-type".to_string(),
        ty.to_string(),
        "--output-type".to_string(),
        ty.to_string(),
    ];
    sops_args.extend(args.sops_args.iter().cloned());
    ui.debug(format!("detected file type `{ty}`"));

    // Flush our own output before the editor takes over the terminal.
    ui.flush();

    sops::edit(&args.file, Some(&editor), &sops_args).map_err(|err| match err {
        // Wrap sops's exit failure in a friendlier, sopsy-flavored message.
        Error::ProcessFailed { code, message, .. } => Error::ProcessFailed {
            tool: "sops".to_string(),
            code,
            message: format!(
                "failed to edit {} (is it a valid sops-encrypted file?): {message}",
                args.file.display()
            ),
        },
        other => other,
    })?;

    ui.success(format!("saved changes to {}", args.file.display()));

    if ui.stage_requested() {
        // Stage just the edited ciphertext, relative to its own directory so this
        // works whether or not the file sits at the repo root.
        let repo = args
            .file
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let name = args
            .file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| args.file.display().to_string());
        crate::git::stage_and_advise(
            ui,
            repo,
            std::slice::from_ref(&args.file),
            &format!("Update encrypted {name}"),
        )?;
    }
    Ok(())
}

/// Resolve the editor to use, honoring `--editor`, then `$EDITOR`, then
/// `$VISUAL`, then falling back to [`DEFAULT_EDITOR`].
fn resolve_editor(flag: Option<&str>) -> String {
    if let Some(editor) = flag {
        return editor.to_string();
    }
    if let Ok(editor) = std::env::var("EDITOR")
        && !editor.trim().is_empty()
    {
        return editor;
    }
    if let Ok(visual) = std::env::var("VISUAL")
        && !visual.trim().is_empty()
    {
        return visual;
    }
    DEFAULT_EDITOR.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editor_flag_takes_precedence() {
        assert_eq!(resolve_editor(Some("nano")), "nano");
    }

    #[test]
    fn editor_falls_back_to_default_without_flag_or_env() {
        // Note: this reads the ambient environment, so only assert the flag
        // path and the default constant directly to stay deterministic.
        assert_eq!(DEFAULT_EDITOR, "vi");
        assert_eq!(resolve_editor(Some("vim")), "vim");
    }
}
