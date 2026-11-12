//! `sopsy recipient break-glass` and `sopsy recipient ci`: the portable-key
//! ceremony. Generate an exportable age key, let the operator store it out of
//! band, delete the local copies, then register the recipient and re-key.

use super::*;
use crate::cli::{RecipientBreakGlassArgs, RecipientCiArgs};

/// The two portable-key ceremonies. Both generate an *exportable* age keypair
/// (not a Secure Enclave identity), hand it to the operator for out-of-band
/// storage, delete the local copies, and register the public key as a
/// recipient — they differ only in where the private key is meant to live and
/// how the recipient is marked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortableKeyKind {
    /// Offline emergency key (e.g. 1Password); marked `break_glass`.
    BreakGlass,
    /// CI decryption key, stored in the CI provider's secret store and read by
    /// `sops` via the `SOPS_AGE_KEY` environment variable.
    Ci,
}

impl PortableKeyKind {
    /// The recipient name used when `--name` is not given.
    fn default_name(self) -> &'static str {
        match self {
            PortableKeyKind::BreakGlass => "break-glass",
            PortableKeyKind::Ci => "ci",
        }
    }

    /// Short human label used in progress and success messages.
    fn label(self) -> &'static str {
        match self {
            PortableKeyKind::BreakGlass => "break-glass",
            PortableKeyKind::Ci => "CI",
        }
    }
}

/// Generate a portable break-glass emergency key, hand it to the operator for
/// offline storage, then delete it locally and register it as a recipient.
///
/// The break-glass key is an ordinary (exportable) age key — *not* a Secure
/// Enclave identity — precisely because it must survive the loss of any single
/// device.
pub(super) fn break_glass(ui: &Ui, args: &RecipientBreakGlassArgs) -> Result<()> {
    portable_key_ceremony(
        ui,
        PortableKeyKind::BreakGlass,
        &args.output,
        args.name.as_deref(),
        args.force,
        args.no_updatekeys,
    )
}

/// Generate a portable CI decryption key, hand it to the operator to store as
/// a CI secret (`SOPS_AGE_KEY`), then delete it locally and register it as a
/// recipient.
///
/// CI runners have no Secure Enclave, so this is how automation decrypts:
/// `sops` reads the identity from `SOPS_AGE_KEY`, which sopsy never overrides
/// (see [`crate::keystore::configure_sops_env`]).
pub(super) fn ci(ui: &Ui, args: &RecipientCiArgs) -> Result<()> {
    portable_key_ceremony(
        ui,
        PortableKeyKind::Ci,
        &args.output,
        args.name.as_deref(),
        args.force,
        args.no_updatekeys,
    )
}

/// Paths to shred if the process is terminated by a signal mid-ceremony. A
/// portable key's private half must never survive the ceremony, so it is
/// registered here the moment it touches disk (see [`KeyFileGuard`]).
static CEREMONY_CLEANUP: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

/// Install a one-shot SIGINT/SIGTERM/SIGHUP handler that shreds every path
/// registered in [`CEREMONY_CLEANUP`], then exits. Idempotent: installed at most
/// once per process, so repeated ceremonies (e.g. in tests) reuse the handler.
///
/// `ctrlc` runs the handler on its own thread rather than in raw async-signal
/// context, so file I/O and locking here are safe.
fn arm_ceremony_signal_cleanup() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        // Best-effort: if a handler is somehow already installed, the
        // `KeyFileGuard` Drop still covers every non-signal exit path.
        let _ = ctrlc::set_handler(|| {
            if let Ok(paths) = CEREMONY_CLEANUP.lock() {
                for path in paths.iter() {
                    let _ = std::fs::remove_file(path);
                }
            }
            // 128 + SIGINT(2): conventional "terminated by Ctrl-C" exit status.
            std::process::exit(130);
        });
    });
}

/// RAII guard ensuring the on-disk halves of a portable key never outlive the
/// ceremony — the Rust equivalent of a shell `trap … EXIT` over the key files.
///
/// `Drop` shreds both halves on every normal return, error (`?`), and panic;
/// the signal handler armed by [`arm_ceremony_signal_cleanup`] covers
/// SIGINT/SIGTERM/SIGHUP, which terminate the process without running `Drop`.
struct KeyFileGuard {
    paths: [PathBuf; 2],
}

impl KeyFileGuard {
    /// Register the two key-file paths for signal cleanup and arm the handler.
    fn arm(private: &Path, public: &Path) -> Self {
        arm_ceremony_signal_cleanup();
        let paths = [private.to_path_buf(), public.to_path_buf()];
        if let Ok(mut registry) = CEREMONY_CLEANUP.lock() {
            registry.extend(paths.iter().cloned());
        }
        KeyFileGuard { paths }
    }
}

impl Drop for KeyFileGuard {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = std::fs::remove_file(path);
        }
        if let Ok(mut registry) = CEREMONY_CLEANUP.lock() {
            registry.retain(|p| !self.paths.contains(p));
        }
    }
}

/// The shared portable-key ceremony: generate → write to disk → operator
/// stores it out-of-band → press ENTER → delete local copies → register the
/// recipient and re-wrap secrets (rolling back atomically on failure).
///
/// The flow is deliberately interactive: the local files exist only for the
/// operator to copy from, and are removed the moment storage is confirmed.
fn portable_key_ceremony(
    ui: &Ui,
    kind: PortableKeyKind,
    output: &Path,
    name: Option<&str>,
    force: bool,
    no_updatekeys: bool,
) -> Result<()> {
    let label = kind.label();
    ui.header(format!("sopsy recipient {}", kind.default_name()));

    let repo = current_repo_root()?;
    let mut config = load_config(&repo)?;
    let sops_config = sops_config_path(&repo)?;

    let name = name.unwrap_or(kind.default_name()).trim().to_string();
    if name.is_empty() {
        return Err(Error::Validation("recipient name must not be empty".into()));
    }
    if config.recipient(&name).is_some() {
        return Err(Error::Validation(format!(
            "a recipient named `{name}` already exists"
        )));
    }

    // This flow blocks on an interactive confirmation. Fail fast — before any
    // key material touches disk — when we cannot prompt (and automation has not
    // opted in via SOPSY_ASSUME_YES).
    let assume_yes = assume_yes();
    if !ui.is_interactive() && !assume_yes {
        return Err(Error::NonInteractive {
            prompt: format!("press ENTER to confirm the {label} key is stored safely"),
            flag: format!("an interactive terminal (or set {ASSUME_YES_ENV} for automation)"),
        });
    }

    // Resolve the two output paths and refuse to clobber existing files.
    let private_path = with_suffix(output, "private");
    let public_path = with_suffix(output, "public");
    for path in [&private_path, &public_path] {
        if path.exists() && !force {
            return Err(Error::Validation(format!(
                "{} already exists (pass --force to overwrite)",
                path.display()
            )));
        }
    }

    // Generate a portable age key pair.
    age::ensure_available()?;
    let spinner = ui.spinner(format!("Generating a portable age key pair for {label}…"));
    let keypair = age::generate_keypair();
    spinner.finish_and_clear();
    let keypair = keypair?;

    // The private key is about to exist on disk. Guarantee it never survives
    // the ceremony: this guard shreds both halves on any normal/error return or
    // panic, and the signal handler it arms shreds them on SIGINT/SIGTERM/SIGHUP
    // (e.g. Ctrl-C at the prompt below), which bypass `Drop`. It is armed before
    // the first write, so a failure part-way through (the public half cannot be
    // written, say) leaves no orphan private key behind.
    let _cleanup = KeyFileGuard::arm(&private_path, &public_path);

    // Write both halves to disk. The private key is owner-only from the moment
    // the file is created (see `write_private_key`).
    write_private_key(&private_path, &keypair.identity)?;
    std::fs::write(&public_path, format!("{}\n", keypair.public_key))?;

    ui.success(format!("wrote private key to {}", private_path.display()));
    ui.success(format!("wrote public key to {}", public_path.display()));

    // Hand off to the operator and block until they confirm safe storage.
    let press_enter_prompt = match kind {
        PortableKeyKind::BreakGlass => {
            ui.banner_warn("ACTION REQUIRED — store the break-glass key offline");
            ui.warn(
                "Please copy these files and place them in 1Password (or another secure, offline store):",
            );
            ui.info(format!("  • {}", private_path.display()));
            ui.info(format!("  • {}", public_path.display()));
            "Please press ENTER when you copied the keys to a secure storage (eg 1Password):"
        }
        PortableKeyKind::Ci => {
            ui.banner_warn("ACTION REQUIRED — add the CI key to your CI provider's secret store");
            ui.warn("Go to your CI settings and add ONE secret:");
            ui.info(format!(
                "  • SOPS_AGE_KEY — the contents of {} (the name `sops` reads identities from)",
                private_path.display()
            ));
            ui.info(format!(
                "    GitHub CLI:  gh secret set SOPS_AGE_KEY < {}",
                private_path.display()
            ));
            ui.info(
                "    GitHub UI:   Settings → Secrets and variables → Actions → New repository secret",
            );
            ui.info(format!(
                "The public half needs no CI secret: it is not sensitive and is being \
                 committed to {CONFIG_FILE_NAME} and {SOPS_CONFIG_FILE_NAME} as the recipient."
            ));
            ui.warn(
                "This key can decrypt ALL sopsy-managed secrets — treat a compromised runner \
                 like a lost laptop: remove the recipient and rotate the secret values.",
            );
            "Please press ENTER once SOPS_AGE_KEY is stored in your CI secrets:"
        }
    };
    ui.warn("Both files will be DELETED from this machine as soon as you continue.");
    if assume_yes {
        ui.info(format!(
            "{ASSUME_YES_ENV} set — assuming the keys are stored; continuing."
        ));
    } else {
        ui.press_enter(press_enter_prompt)?;
    }

    // Remove the local copies; the only surviving private key now lives in the
    // out-of-band store (vault or CI secrets).
    std::fs::remove_file(&private_path)?;
    std::fs::remove_file(&public_path)?;
    ui.success("removed the local key files");

    // Register the recipient in both config files and re-wrap secrets, rolling
    // back atomically if the re-encryption fails (see `add`).
    let snapshot = ConfigSnapshot::capture(&repo, &sops_config);
    config.recipients.push(Recipient {
        break_glass: kind == PortableKeyKind::BreakGlass,
        ..Recipient::new(&name, &keypair.public_key)
    });
    config.save_to_dir(&repo)?;
    ui.success(format!("recorded `{name}` ({label}) in {CONFIG_FILE_NAME}"));

    let modified = add_key_to_sops_yaml(&sops_config, &keypair.public_key)?;
    if modified == 0 {
        ui.warn(format!(
            "no `age:` creation_rules matched in {SOPS_CONFIG_FILE_NAME}; left unchanged"
        ));
    } else {
        ui.success(format!(
            "added the key to {modified} creation rule(s) in {SOPS_CONFIG_FILE_NAME}"
        ));
    }

    if let Err(err) = run_updatekeys(ui, &repo, no_updatekeys) {
        return Err(snapshot.roll_back(ui, err, &format!("the {label} recipient was not added")));
    }

    ui.success(format!("{label} recipient `{name}` added"));
    if kind == PortableKeyKind::Ci {
        ui.info("Expose the secret to the jobs that decrypt, e.g. in GitHub Actions:");
        ui.info("    env:");
        ui.info("      SOPS_AGE_KEY: ${{ secrets.SOPS_AGE_KEY }}");
        ui.info("Then decrypt with: sopsy secrets decrypt .env.encrypted");
    }

    let subject = match kind {
        PortableKeyKind::BreakGlass => "Add sopsy break-glass recipient",
        PortableKeyKind::Ci => "Add sopsy CI recipient",
    };
    maybe_stage(ui, &repo, subject)?;
    Ok(())
}

/// Return `path` with `.<suffix>` appended (e.g. `key` + `private` → `key.private`).
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

/// Create the private-key file at `path`, readable and writable by its owner
/// only (unix).
///
/// The mode is part of the `open` call, so the key is never on disk with the
/// permissions a permissive umask would give it, not even for the moment
/// between a write and a later `chmod`. A path that already exists (reachable
/// only with `--force`) is removed first and created fresh: a planted symlink is
/// replaced, never followed, and an old file's looser mode is not inherited.
fn write_private_key(path: &Path, identity: &str) -> std::io::Result<()> {
    use std::io::Write;

    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(identity.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn write_private_key_creates_an_owner_only_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bg.private");
        write_private_key(&path, "AGE-SECRET-KEY-1TEST\n").unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "AGE-SECRET-KEY-1TEST\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_private_key_does_not_inherit_an_existing_files_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bg.private");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private_key(&path, "new").unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }

    #[cfg(unix)]
    #[test]
    fn write_private_key_replaces_a_symlink_without_following_it() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, "untouched").unwrap();
        let path = dir.path().join("bg.private");
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();

        write_private_key(&path, "AGE-SECRET-KEY-1TEST\n").unwrap();

        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "untouched");
        assert!(!std::fs::symlink_metadata(&path).unwrap().is_symlink());
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn with_suffix_appends_dotted_extension() {
        assert_eq!(
            with_suffix(Path::new("key"), "private"),
            PathBuf::from("key.private")
        );
        assert_eq!(
            with_suffix(Path::new("/tmp/bg"), "public"),
            PathBuf::from("/tmp/bg.public")
        );
        // An existing extension is preserved, not replaced.
        assert_eq!(
            with_suffix(Path::new("bg.key"), "private"),
            PathBuf::from("bg.key.private")
        );
    }
}
