//! `sopsy recipient` — manage repository recipients.
//!
//! These subcommands keep two files in sync:
//!
//! - `.sopsy.yml` — sopsy's own metadata (human-readable names + the
//!   break-glass marker), modelled by [`crate::config::Config`].
//! - `.sops.yaml` — consumed by `sops` itself; each `creation_rules` entry's
//!   `age:` list must contain every recipient's public key so they can decrypt.
//!
//! After mutating both files, sopsy re-wraps the existing encrypted files for
//! the new recipient set (unless `--no-updatekeys`). `sops updatekeys` (3.x)
//! operates on one file at a time and has no recursive mode, so sopsy
//! discovers the managed files and runs `sops updatekeys -y` on each.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use owo_colors::OwoColorize;
use serde_yaml_ng::Value;

use crate::cli::{
    RecipientAddArgs, RecipientBreakGlassArgs, RecipientCiArgs, RecipientCommand,
    RecipientKeygenArgs, RecipientRemoveArgs,
};
use crate::config::{CONFIG_FILE_NAME, Config, Recipient};
use crate::error::{Error, Result};
use crate::ui::Ui;
use crate::{age, enclave, git, sops};

/// Conventional name of the `sops` configuration file.
pub(crate) const SOPS_CONFIG_FILE_NAME: &str = ".sops.yaml";

/// When set, interactive confirmations (`break-glass`'s press-ENTER, `approve`'s
/// vouch prompt) are assumed. Intended for automation and tests; in real use the
/// operator should confirm interactively.
pub(crate) const ASSUME_YES_ENV: &str = "SOPSY_ASSUME_YES";

/// Whether the [`ASSUME_YES_ENV`] automation opt-in is set.
pub(crate) fn assume_yes() -> bool {
    std::env::var_os(ASSUME_YES_ENV).is_some()
}

/// Best-effort current system username from `$USER` / `$LOGNAME`.
///
/// Shared by `init` (default key owner), `join` (recorded as the requester's
/// `username`), and `approve` (identifies the approver for provenance).
pub(crate) fn system_username() -> Option<String> {
    for var in ["USER", "LOGNAME"] {
        if let Ok(value) = std::env::var(var) {
            let value = value.trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// Dispatch a `recipient` subcommand.
pub fn run(ui: &Ui, command: &RecipientCommand) -> Result<()> {
    match command {
        RecipientCommand::Add(args) => add(ui, args),
        RecipientCommand::Remove(args) => remove(ui, args),
        RecipientCommand::List => list(ui),
        RecipientCommand::Keygen(args) => keygen(ui, args),
        RecipientCommand::BreakGlass(args) => break_glass(ui, args),
        RecipientCommand::Ci(args) => ci(ui, args),
    }
}

/// Locate the repository root containing the current directory.
pub(crate) fn current_repo_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    git::repo_root(&cwd)
}

/// Load `.sopsy.yml`, turning a missing file into a friendly hint.
pub(crate) fn load_config(repo: &Path) -> Result<Config> {
    match Config::load_from_dir(repo) {
        Ok(config) => Ok(config),
        Err(Error::FileNotFound(_)) => Err(Error::Validation(format!(
            "{CONFIG_FILE_NAME} not found in {} — run `sopsy init` first",
            repo.display()
        ))),
        Err(other) => Err(other),
    }
}

/// Resolve and validate the path to `.sops.yaml` inside `repo`.
/// Every committable file a membership change touches: the three config files
/// (`.sops.yaml`, `.sopsy.yml`, `.sopsy.sha`) plus every managed encrypted file
/// (which `sops updatekeys` re-wraps). Handed to [`crate::git::stage_and_advise`]
/// for the `--git` flow; absent entries are skipped there.
pub(crate) fn membership_paths(repo: &Path) -> Vec<PathBuf> {
    let sopsy = repo.join(CONFIG_FILE_NAME);
    let mut paths = vec![
        repo.join(SOPS_CONFIG_FILE_NAME),
        sopsy.clone(),
        Config::checksum_path(&sopsy),
    ];
    let globs = load_config(repo)
        .map(|c| c.encrypted_globs)
        .unwrap_or_else(|_| Config::default().encrypted_globs);
    paths.extend(collect_encrypted_files(repo, &globs).unwrap_or_default());
    paths
}

/// When `--git` was passed, `git add` the membership file set and print
/// commit/PR instructions. A no-op otherwise. Errors propagate: staging is the
/// user's explicit request, so a failure to stage should be surfaced.
pub(crate) fn maybe_stage(ui: &Ui, repo: &Path, subject: &str) -> Result<()> {
    if ui.stage_requested() {
        crate::git::stage_and_advise(ui, repo, &membership_paths(repo), subject)?;
    }
    Ok(())
}

pub(crate) fn sops_config_path(repo: &Path) -> Result<PathBuf> {
    let path = repo.join(SOPS_CONFIG_FILE_NAME);
    if !path.exists() {
        return Err(Error::Validation(format!(
            "{SOPS_CONFIG_FILE_NAME} not found in {} — run `sopsy init` first",
            repo.display()
        )));
    }
    Ok(path)
}

/// Add a recipient to both configuration files and re-encrypt existing secrets.
fn add(ui: &Ui, args: &RecipientAddArgs) -> Result<()> {
    ui.header("sopsy recipient add");

    let repo = current_repo_root()?;
    let mut config = load_config(&repo)?;
    let sops_config = sops_config_path(&repo)?;

    // Resolve the name and public key from flags, or prompt interactively.
    let name = match args.resolved_name() {
        Some(name) => name.to_string(),
        None => ui.text("Recipient name:", "--name")?,
    };
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err(Error::Validation("recipient name must not be empty".into()));
    }

    let public_key = match args.public_key.as_deref() {
        Some(key) => key.to_string(),
        None => ui.text("Recipient age public key (age1…):", "--public-key")?,
    };
    let public_key = public_key.trim().to_string();
    if public_key.is_empty() {
        return Err(Error::Validation(
            "recipient public key must not be empty".into(),
        ));
    }

    // Reject duplicates by name or by key.
    if config.recipient(&name).is_some() {
        return Err(Error::Validation(format!(
            "a recipient named `{name}` already exists"
        )));
    }
    if let Some(existing) = config
        .recipients
        .iter()
        .find(|r| r.public_key == public_key)
    {
        return Err(Error::Validation(format!(
            "public key is already registered as `{}`",
            existing.name
        )));
    }

    // Snapshot the config files so a failed re-encryption rolls back cleanly,
    // never leaving a recipient listed that the secrets were not re-wrapped for.
    let snapshot = ConfigSnapshot::capture(&repo, &sops_config);

    // Append to `.sopsy.yml`.
    let recipient = Recipient {
        break_glass: args.break_glass,
        ..Recipient::new(&name, &public_key)
    };
    config.recipients.push(recipient);
    config.save_to_dir(&repo)?;
    ui.success(format!("recorded `{name}` in {CONFIG_FILE_NAME}"));

    // Append to every age-based creation rule in `.sops.yaml`.
    let modified = add_key_to_sops_yaml(&sops_config, &public_key)?;
    if modified == 0 {
        ui.warn(format!(
            "no `age:` creation_rules matched in {SOPS_CONFIG_FILE_NAME}; left unchanged"
        ));
    } else {
        ui.success(format!(
            "added the key to {modified} creation rule(s) in {SOPS_CONFIG_FILE_NAME}"
        ));
    }

    if args.break_glass {
        ui.info(format!("`{name}` is marked as the break-glass recipient"));
    }

    if let Err(err) = run_updatekeys(ui, &repo, args.no_updatekeys) {
        snapshot.restore()?;
        ui.warn("rolled back configuration changes — no recipient was added");
        return Err(rewrap_error(err));
    }

    ui.success(format!("recipient `{name}` added"));
    maybe_stage(ui, &repo, &format!("Add sopsy recipient {name}"))?;
    Ok(())
}

/// Remove a recipient from both configuration files and re-encrypt secrets.
fn remove(ui: &Ui, args: &RecipientRemoveArgs) -> Result<()> {
    ui.header("sopsy recipient remove");

    let repo = current_repo_root()?;
    let mut config = load_config(&repo)?;
    let sops_config = sops_config_path(&repo)?;

    let name = match args.resolved_name() {
        Some(name) => name.to_string(),
        None => {
            let options: Vec<String> = config.recipients.iter().map(|r| r.name.clone()).collect();
            if options.is_empty() {
                return Err(Error::Validation(
                    "there are no recipients to remove".into(),
                ));
            }
            ui.select("Recipient to remove:", "--name", options)?
        }
    };
    let name = name.trim().to_string();

    let recipient = config
        .recipient(&name)
        .cloned()
        .ok_or_else(|| Error::Validation(format!("no recipient named `{name}`")))?;

    // Safety rails: never strand the repository.
    if config.recipients.len() == 1 {
        ui.warn("refusing to remove the last recipient — the repo would become undecryptable");
        return Err(Error::Validation(
            "cannot remove the only remaining recipient".into(),
        ));
    }
    if recipient.break_glass && config.recipients.iter().filter(|r| r.break_glass).count() == 1 {
        ui.warn("refusing to remove the sole break-glass recipient");
        return Err(Error::Validation(
            "cannot remove the only break-glass recipient".into(),
        ));
    }

    // Snapshot for rollback if re-encryption fails (see `add`).
    let snapshot = ConfigSnapshot::capture(&repo, &sops_config);

    config.recipients.retain(|r| r.name != name);
    config.save_to_dir(&repo)?;
    ui.success(format!("removed `{name}` from {CONFIG_FILE_NAME}"));

    let modified = remove_key_from_sops_yaml(&sops_config, &recipient.public_key)?;
    if modified == 0 {
        ui.warn(format!(
            "key was not present in {SOPS_CONFIG_FILE_NAME}; left unchanged"
        ));
    } else {
        ui.success(format!(
            "removed the key from {modified} creation rule(s) in {SOPS_CONFIG_FILE_NAME}"
        ));
    }

    if let Err(err) = run_updatekeys(ui, &repo, args.no_updatekeys) {
        snapshot.restore()?;
        ui.warn("rolled back configuration changes — no recipient was removed");
        return Err(rewrap_error(err));
    }

    ui.success(format!("recipient `{name}` removed"));
    maybe_stage(ui, &repo, &format!("Remove sopsy recipient {name}"))?;
    Ok(())
}

/// A snapshot of everything a recipient mutation touches, used to roll a partial
/// mutation back. Updating recipients rewrites the config files (`.sopsy.yml`,
/// its `.sopsy.sha` sidecar, `.sops.yaml`) *and then* has `sops updatekeys`
/// re-wrap the encrypted secrets one file at a time. If that re-wrap fails
/// partway (most often because the operator's age key is not available to
/// decrypt), restoring this snapshot returns the repository to its exact
/// pre-command state — both the config files *and* every encrypted body that was
/// already re-wrapped — so it never lists a recipient the secrets were not
/// re-wrapped for, nor silently re-wraps a subset before claiming a rollback.
///
/// The captured encrypted set is the same one `run_updatekeys` re-wraps: these
/// commands never change `encrypted_globs`, so the file set is stable across the
/// mutation. Bodies are held in memory (secrets are small, matching the config
/// snapshots); capture is best-effort and infallible.
pub(crate) struct ConfigSnapshot {
    /// The three config files, `None` when absent at capture time.
    files: [(PathBuf, Option<Vec<u8>>); 3],
    /// Every managed encrypted file and its pre-command bytes. Only files that
    /// existed and were readable at capture are recorded, so bytes are always
    /// present (no `Option`).
    encrypted: Vec<(PathBuf, Vec<u8>)>,
}

impl ConfigSnapshot {
    /// Capture the current bytes of the config files (`None` if absent) —
    /// `.sopsy.yml`, its `.sopsy.sha` integrity sidecar, and `.sops.yaml` — plus
    /// the bytes of every managed encrypted file that `run_updatekeys` will touch.
    pub(crate) fn capture(repo: &Path, sops_config: &Path) -> Self {
        let sopsy = repo.join(CONFIG_FILE_NAME);
        let sha = Config::checksum_path(&sopsy);
        // Resolve globs the same way `run_updatekeys` does (falling back to the
        // defaults when `.sopsy.yml` is absent/unreadable, e.g. mid-init), then
        // snapshot each encrypted body so a failed re-wrap can be undone.
        let globs = load_config(repo)
            .map(|c| c.encrypted_globs)
            .unwrap_or_else(|_| Config::default().encrypted_globs);
        let encrypted = collect_encrypted_files(repo, &globs)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|path| std::fs::read(&path).ok().map(|bytes| (path, bytes)))
            .collect();
        ConfigSnapshot {
            files: [
                (sopsy.clone(), std::fs::read(&sopsy).ok()),
                (sha.clone(), std::fs::read(&sha).ok()),
                (sops_config.to_path_buf(), std::fs::read(sops_config).ok()),
            ],
            encrypted,
        }
    }

    /// Restore everything to its captured contents. Encrypted bodies are written
    /// first (the security-critical data), then the config files (removing any
    /// that did not exist when captured). The first write error propagates.
    pub(crate) fn restore(&self) -> Result<()> {
        for (path, bytes) in &self.encrypted {
            std::fs::write(path, bytes)?;
        }
        for (path, contents) in &self.files {
            match contents {
                Some(bytes) => std::fs::write(path, bytes)?,
                None => {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        Ok(())
    }
}

/// Wrap a `sops updatekeys` failure with actionable guidance. Updating
/// recipients requires decrypting the existing secrets, so the operator must be
/// an existing recipient with their key available.
pub(crate) fn rewrap_error(source: Error) -> Error {
    Error::Validation(format!(
        "could not re-encrypt secrets for the updated recipient set, so the change \
         was rolled back. Updating recipients requires decrypting the existing \
         secrets — make your age key available (unlock your Secure Enclave \
         identity, or set SOPS_AGE_KEY_FILE to a key that is already a recipient), \
         or pass --no-updatekeys to update configuration only. Underlying error: {source}"
    ))
}

/// Print all configured recipients as a colorful aligned table.
fn list(ui: &Ui) -> Result<()> {
    ui.header("sopsy recipient list");

    let repo = current_repo_root()?;
    let config = match Config::load_from_dir(&repo) {
        Ok(config) => config,
        Err(Error::FileNotFound(_)) => {
            ui.info(format!(
                "no {CONFIG_FILE_NAME} found — run `sopsy init` to get started"
            ));
            return Ok(());
        }
        Err(other) => return Err(other),
    };

    if config.recipients.is_empty() {
        ui.info("no recipients are configured yet");
        return Ok(());
    }

    let headers = [
        "NAME",
        "USERNAME",
        "PUBLIC KEY",
        "BREAK-GLASS",
        "APPROVED BY",
    ];
    let rows: Vec<[String; 5]> = config
        .recipients
        .iter()
        .map(|r| {
            [
                truncate(&r.name, NAME_COL_MAX),
                truncate(r.username.as_deref().unwrap_or(""), USERNAME_COL_MAX),
                truncate(&r.public_key, KEY_COL_MAX),
                if r.break_glass { "★ yes" } else { "" }.to_string(),
                approved_cell(r),
            ]
        })
        .collect();

    // Each column is as wide as its widest cell or header; cells and widths are
    // measured in characters, matching how `format!` pads strings.
    let mut widths = headers.map(str::len);
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row.iter()) {
            *width = (*width).max(cell.chars().count());
        }
    }
    // The last column never needs trailing padding.
    let pad = |cells: [&str; 5]| -> Vec<String> {
        let mut out: Vec<String> = cells
            .iter()
            .zip(widths.iter())
            .map(|(cell, w)| format!("{cell:<w$}"))
            .collect();
        out[4] = cells[4].to_string();
        out
    };

    let header_cells = pad(headers);
    if ui.color_enabled() {
        println!("{}", header_cells.join("  ").bold().cyan());
    } else {
        println!("{}", header_cells.join("  "));
    }

    for row in &rows {
        let cells = pad([&row[0], &row[1], &row[2], &row[3], &row[4]]);
        if ui.color_enabled() {
            println!(
                "{}  {}  {}  {}  {}",
                cells[0].green().bold(),
                cells[1].cyan(),
                cells[2].dimmed(),
                cells[3].yellow().bold(),
                cells[4]
            );
        } else {
            println!("{}", cells.join("  ").trim_end());
        }
    }

    Ok(())
}

/// Column caps (in characters) for `recipient list` cells; longer values are
/// truncated with an ellipsis.
const NAME_COL_MAX: usize = 21;
const USERNAME_COL_MAX: usize = 12;
const KEY_COL_MAX: usize = 24;

/// Render the `APPROVED BY` cell: `"Full Name (username) on YYYY-MM-DD"`,
/// degrading gracefully when either half of the provenance is missing. Pending
/// members show `(pending)` so the audit column reads complete.
fn approved_cell(recipient: &Recipient) -> String {
    if recipient.is_pending() {
        return "(pending)".to_string();
    }
    match (
        recipient.approved_by.as_deref(),
        recipient.approved_at.as_deref(),
    ) {
        (Some(by), Some(at)) => format!("{by} on {}", date_only(at)),
        (Some(by), None) => by.to_string(),
        (None, Some(at)) => format!("on {}", date_only(at)),
        (None, None) => String::new(),
    }
}

/// The `YYYY-MM-DD` prefix of an RFC3339 timestamp (the input unchanged when it
/// has no time component).
fn date_only(rfc3339: &str) -> &str {
    rfc3339.split('T').next().unwrap_or(rfc3339)
}

/// Generate a fresh Secure Enclave identity and print it.
///
/// This is a stateless helper: it does **not** touch `.sopsy.yml` or
/// `.sops.yaml`. Use the printed public key with `sopsy recipient add` to
/// register it. Trailing args after `--` are forwarded to `age-plugin-se keygen`.
fn keygen(ui: &Ui, args: &RecipientKeygenArgs) -> Result<()> {
    ui.header("sopsy recipient keygen");

    enclave::ensure_available()?;
    let spinner = ui.spinner("Generating Secure Enclave identity (Touch ID may prompt)…");
    let identity = enclave::generate_identity_with_args(&args.age_args);
    spinner.finish_and_clear();
    let identity = identity?;

    ui.success("Generated a Secure Enclave-backed identity.");
    ui.info("The private key stays in the Secure Enclave and never leaves this device.");

    ui.header("Public key (share this; register with `sopsy recipient add`)");
    ui.animated_line(&identity.public_key);

    ui.header("Identity reference (store this where you keep your age identities)");
    println!("{}", identity.identity);

    Ok(())
}

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
fn break_glass(ui: &Ui, args: &RecipientBreakGlassArgs) -> Result<()> {
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
fn ci(ui: &Ui, args: &RecipientCiArgs) -> Result<()> {
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

    // Write both halves to disk (private key locked down on unix).
    std::fs::write(&private_path, &keypair.identity)?;
    std::fs::write(&public_path, format!("{}\n", keypair.public_key))?;
    restrict_permissions(&private_path);

    // The private key now exists on disk. Guarantee it never survives the
    // ceremony: this guard shreds both halves on any normal/error return or
    // panic, and the signal handler it arms shreds them on SIGINT/SIGTERM/SIGHUP
    // (e.g. Ctrl-C at the prompt below), which bypass `Drop`.
    let _cleanup = KeyFileGuard::arm(&private_path, &public_path);

    ui.success(format!("wrote private key to {}", private_path.display()));
    ui.success(format!("wrote public key to {}", public_path.display()));

    // Hand off to the operator and block until they confirm safe storage.
    let press_enter_prompt = match kind {
        PortableKeyKind::BreakGlass => {
            ui.header("ACTION REQUIRED — store the break-glass key offline");
            ui.warn(
                "Please copy these files and place them in 1Password (or another secure, offline store):",
            );
            ui.info(format!("  • {}", private_path.display()));
            ui.info(format!("  • {}", public_path.display()));
            "Please press ENTER when you copied the keys to a secure storage (eg 1Password):"
        }
        PortableKeyKind::Ci => {
            ui.header("ACTION REQUIRED — add the CI key to your CI provider's secret store");
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
        snapshot.restore()?;
        ui.warn(format!(
            "rolled back configuration changes — {label} recipient was not added"
        ));
        return Err(rewrap_error(err));
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

/// Best-effort tighten of a private-key file to owner read/write only (unix).
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Re-wrap every encrypted file in `repo` for the current recipient set, unless
/// skipping was requested.
///
/// This is the moral equivalent of `sops updatekeys -r .`, but performed
/// file-by-file: `sops updatekeys` (3.x) operates on a single file and has no
/// recursive mode, so sopsy discovers the managed files itself and runs
/// `sops updatekeys -y --input-type T <file>` for each.
pub(crate) fn run_updatekeys(ui: &Ui, repo: &Path, skip: bool) -> Result<()> {
    if skip {
        ui.info("skipping re-encryption (`--no-updatekeys`)");
        return Ok(());
    }
    // Bound the scan to files git knows about (tracked + untracked-not-ignored),
    // filtered by the repo's encrypted globs. Falls back to the built-in default
    // globs when `.sopsy.yml` is absent or unreadable (e.g. during `init`,
    // before it is written).
    let globs = load_config(repo)
        .map(|c| c.encrypted_globs)
        .unwrap_or_else(|_| Config::default().encrypted_globs);
    let files = collect_encrypted_files(repo, &globs)?;
    if files.is_empty() {
        ui.info("no encrypted files found to re-encrypt");
        return Ok(());
    }
    ui.info("re-encrypting secrets for the updated recipient set (Touch ID may prompt)…");
    for file in &files {
        updatekeys_file(file)?;
    }
    ui.success(format!(
        "re-encrypted {} file(s) for the updated recipient set",
        files.len()
    ));
    Ok(())
}

/// Build a `sops` command, honoring the [`crate::sops::SOPS_BIN_ENV`] override
/// (used by tests to inject a fake binary).
fn sops_command() -> Command {
    let bin =
        std::env::var_os(sops::SOPS_BIN_ENV).unwrap_or_else(|| OsString::from(sops::SOPS_BIN));
    let mut command = Command::new(bin);
    crate::keystore::configure_sops_env(&mut command);
    command
}

/// Run `sops updatekeys -y --input-type T <file>` for a single file.
fn updatekeys_file(file: &Path) -> Result<()> {
    let ty = sops::FileType::from_path(file).as_sops_type();
    let output = sops_command()
        .arg("updatekeys")
        .arg("-y")
        .args(["--input-type", ty])
        .arg(file)
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(Error::ProcessFailed {
        tool: sops::SOPS_BIN.to_string(),
        code: output.status.code().unwrap_or(-1),
        message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

/// Collect the sops-encrypted files in `repo` that need re-keying.
///
/// The repo's `encrypted_globs` (from `.sopsy.yml`) are expanded against the
/// working tree directly, so **every** matching artifact is found regardless of
/// git status — a not-yet-committed or even `.gitignore`d `*.encrypted` still
/// has to be re-keyed when membership changes, or the new member can't decrypt
/// it. Expansion is bounded (see [`expand_glob`]): `*` never crosses `/`, so a
/// glob like `*.encrypted` lists one directory, never a recursive walk of (say)
/// `$HOME`. Each match must also carry the `ENC[` marker to count.
fn collect_encrypted_files(repo: &Path, globs: &[String]) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    for pattern in globs {
        for path in expand_glob(repo, pattern) {
            if path.is_file() && is_encrypted_file(&path) {
                found.push(path);
            }
        }
    }
    found.sort();
    found.dedup();
    Ok(found)
}

/// Expand a glob `pattern` against the filesystem under `repo`, one path segment
/// at a time. A literal segment is joined without listing a directory; a segment
/// containing `*`/`?` lists exactly its parent directory and keeps the matches.
/// There is no `**`, and `*` never crosses `/`, so the work is bounded to the
/// directories the pattern actually names — no recursive descent.
fn expand_glob(repo: &Path, pattern: &str) -> Vec<PathBuf> {
    let mut current = vec![repo.to_path_buf()];
    for segment in pattern.split('/').filter(|s| !s.is_empty()) {
        let mut next = Vec::new();
        if segment.contains(['*', '?']) {
            for dir in &current {
                let Ok(entries) = std::fs::read_dir(dir) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    if glob_match(segment, &name.to_string_lossy()) {
                        next.push(dir.join(&name));
                    }
                }
            }
        } else {
            for dir in &current {
                let candidate = dir.join(segment);
                if candidate.exists() {
                    next.push(candidate);
                }
            }
        }
        current = next;
    }
    current
}

/// Minimal glob matcher: `*` matches any run of characters except `/`, `?`
/// matches a single non-`/` character, everything else is literal. This avoids
/// a glob-crate dependency; the encrypted-artifact patterns never need `**`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut resume) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' && t[ti] != '/' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            resume = ti;
            pi += 1;
        } else if let Some(s) = star {
            // Backtrack: let the last `*` consume one more char — but never `/`.
            if t[resume] == '/' {
                return false;
            }
            pi = s + 1;
            resume += 1;
            ti = resume;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Whether `path` looks like a sops-encrypted file (ignores `.sops.yaml`).
fn is_encrypted_file(path: &Path) -> bool {
    if path.file_name().is_some_and(|n| n == ".sops.yaml") {
        return false;
    }
    match std::fs::read_to_string(path) {
        Ok(contents) => contents.contains("ENC["),
        Err(_) => false,
    }
}

/// Truncate `text` to at most `max` characters for display, appending an
/// ellipsis when something was cut.
fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() > max {
        let head: String = text.chars().take(max).collect();
        format!("{head}…")
    } else {
        text.to_string()
    }
}

/// Add `key` to the `age:` list of every age-based creation rule in the
/// `.sops.yaml` at `path`, preserving all other YAML. Returns how many rules
/// were modified.
pub(crate) fn add_key_to_sops_yaml(path: &Path, key: &str) -> Result<usize> {
    mutate_sops_yaml(path, |keys| {
        if keys.iter().any(|k| k == key) {
            false
        } else {
            keys.push(key.to_string());
            true
        }
    })
}

/// Remove `key` from the `age:` list of every creation rule in the `.sops.yaml`
/// at `path`. Returns how many rules were modified.
fn remove_key_from_sops_yaml(path: &Path, key: &str) -> Result<usize> {
    mutate_sops_yaml(path, |keys| {
        let before = keys.len();
        keys.retain(|k| k != key);
        keys.len() != before
    })
}

/// Parse `.sops.yaml`, apply `edit` to each creation rule's age-key list, and
/// write the result back. `edit` returns whether it changed the list.
fn mutate_sops_yaml<F>(path: &Path, mut edit: F) -> Result<usize>
where
    F: FnMut(&mut Vec<String>) -> bool,
{
    let raw = std::fs::read_to_string(path)?;
    let mut doc: Value = serde_yaml_ng::from_str(&raw).map_err(|source| Error::Parse {
        path: path.to_path_buf(),
        source,
    })?;

    let mut modified = 0usize;
    if let Some(rules) = doc
        .get_mut("creation_rules")
        .and_then(Value::as_sequence_mut)
    {
        for rule in rules.iter_mut() {
            let Some(map) = rule.as_mapping_mut() else {
                continue;
            };
            let Some(age_val) = map.get_mut("age") else {
                continue;
            };
            let mut keys = parse_age_keys(age_val);
            if edit(&mut keys) {
                modified += 1;
            }
            *age_val = age_keys_to_value(&keys);
        }
    }

    let serialized = serde_yaml_ng::to_string(&doc)?;
    std::fs::write(path, serialized)?;
    Ok(modified)
}

/// Extract the individual age keys from an `age:` value, which may be a YAML
/// sequence or a string of comma/whitespace/newline-separated keys.
fn parse_age_keys(value: &Value) -> Vec<String> {
    match value {
        Value::Sequence(seq) => seq
            .iter()
            .filter_map(Value::as_str)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        Value::String(s) => s
            .split([',', '\n', ' ', '\t'])
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// Render a list of age keys as the canonical sops `age:` value: a single
/// comma-separated string. sops accepts both a string and a YAML sequence here,
/// but only the string form is portable across sops versions (older releases
/// reject a sequence with "cannot unmarshal !!seq into string"), so sopsy always
/// writes the string form — matching what `sopsy init` generates.
fn age_keys_to_value(keys: &[String]) -> Value {
    Value::String(keys.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::TempDir;

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

    #[test]
    fn truncate_shortens_only_long_values() {
        // Short values pass through unchanged; long ones get an ellipsis.
        assert_eq!(truncate("age1short", KEY_COL_MAX), "age1short");
        let long = "age1".to_string() + &"x".repeat(60);
        let out = truncate(&long, KEY_COL_MAX);
        assert!(out.ends_with('…'));
        assert_eq!(out.chars().count(), KEY_COL_MAX + 1); // cap + ellipsis
        // The name/username caps requested for `recipient list`.
        assert_eq!(truncate("Konstantin Gredeskoul", NAME_COL_MAX).len(), 21);
        assert_eq!(
            truncate("a-very-long-username", USERNAME_COL_MAX)
                .chars()
                .count(),
            13
        );
    }

    #[test]
    fn approved_cell_renders_provenance_and_pending() {
        let mut r = Recipient::new("annie", "age1annie");
        assert_eq!(approved_cell(&r), "");

        r.approved_by = Some("Konstantin Gredeskoul (kig)".into());
        assert_eq!(approved_cell(&r), "Konstantin Gredeskoul (kig)");

        r.approved_at = Some("2026-07-01T12:34:56Z".into());
        assert_eq!(
            approved_cell(&r),
            "Konstantin Gredeskoul (kig) on 2026-07-01"
        );

        r.approved_by = None;
        assert_eq!(approved_cell(&r), "on 2026-07-01");

        // Pending members read as awaiting approval regardless of other fields.
        let pending = Recipient::pending("bob", "age1bob", "2026-07-01T00:00:00Z");
        assert_eq!(approved_cell(&pending), "(pending)");
    }

    #[test]
    #[serial_test::serial]
    fn system_username_falls_back_to_none_when_unset() {
        // Snapshot and clear both vars, then restore them afterwards.
        let saved: Vec<(&str, Option<String>)> = ["USER", "LOGNAME"]
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect();
        // SAFETY: serialized via `#[serial]`.
        unsafe {
            std::env::remove_var("USER");
            std::env::remove_var("LOGNAME");
        }
        assert_eq!(system_username(), None);
        // An empty value is also treated as absent.
        // SAFETY: serialized via `#[serial]`.
        unsafe {
            std::env::set_var("USER", "   ");
        }
        assert_eq!(system_username(), None);
        // SAFETY: restore the original environment.
        unsafe {
            for (k, v) in saved {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn parse_age_keys_handles_each_yaml_shape() {
        // Sequence form.
        let seq: Value = serde_yaml_ng::from_str("- age1a\n- age1b\n").unwrap();
        assert_eq!(parse_age_keys(&seq), vec!["age1a", "age1b"]);
        // Comma/whitespace-delimited string form.
        let s: Value = serde_yaml_ng::from_str("\"age1a, age1b\\nage1c\"").unwrap();
        assert_eq!(parse_age_keys(&s), vec!["age1a", "age1b", "age1c"]);
        // Anything else (e.g. a mapping) yields no keys.
        let other: Value = serde_yaml_ng::from_str("{a: b}").unwrap();
        assert!(parse_age_keys(&other).is_empty());
    }

    #[test]
    fn age_keys_to_value_round_trips() {
        let keys = vec!["age1a".to_string(), "age1b".to_string()];
        let value = age_keys_to_value(&keys);
        assert_eq!(parse_age_keys(&value), keys);
    }

    /// Write `body` to a fresh `.sops.yaml` and return its path (kept alive by
    /// the returned `TempDir`).
    fn sops_yaml(body: &str) -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".sops.yaml");
        std::fs::write(&path, body).unwrap();
        (dir, path)
    }

    #[test]
    fn add_key_preserves_unrelated_yaml_and_dedupes() {
        let (_dir, path) = sops_yaml(
            "creation_rules:\n  - path_regex: \\.enc$\n    age:\n      - age1a\nother: keep-me\n",
        );

        // First add appends the key to the one matching rule.
        assert_eq!(add_key_to_sops_yaml(&path, "age1b").unwrap(), 1);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("age1a") && raw.contains("age1b"));
        assert!(raw.contains("other: keep-me"), "unrelated keys preserved");
        assert!(raw.contains("path_regex"), "rule metadata preserved");

        // Re-adding an existing key changes nothing (the `already present` arm).
        assert_eq!(add_key_to_sops_yaml(&path, "age1b").unwrap(), 0);
    }

    #[test]
    fn remove_key_drops_only_the_named_key() {
        let (_dir, path) = sops_yaml(
            "creation_rules:\n  - path_regex: \\.enc$\n    age:\n      - age1a\n      - age1b\n",
        );
        assert_eq!(remove_key_from_sops_yaml(&path, "age1a").unwrap(), 1);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("age1a") && raw.contains("age1b"));
        // Removing an absent key reports no modification.
        assert_eq!(remove_key_from_sops_yaml(&path, "age1zzz").unwrap(), 0);
    }

    #[test]
    fn mutate_skips_non_mapping_and_age_less_rules() {
        // A scalar rule (not a mapping) and a rule without `age:` are skipped;
        // an `age:` given as a delimited string is parsed and rewritten.
        let (_dir, path) = sops_yaml(
            "creation_rules:\n  - just-a-scalar\n  - path_regex: \\.no-age$\n  \
             - path_regex: \\.enc$\n    age: \"age1a, age1b\"\n",
        );
        assert_eq!(add_key_to_sops_yaml(&path, "age1c").unwrap(), 1);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("age1a") && raw.contains("age1b") && raw.contains("age1c"));
    }

    #[test]
    fn mutate_reports_parse_errors() {
        let (_dir, path) = sops_yaml("creation_rules: [unterminated\n");
        let err = add_key_to_sops_yaml(&path, "age1a").unwrap_err();
        assert!(matches!(err, Error::Parse { .. }));
    }

    #[test]
    fn is_encrypted_file_detects_marker_and_skips_sops_yaml() {
        let dir = TempDir::new().unwrap();
        let enc = dir.path().join("secret.encrypted");
        std::fs::write(&enc, "FOO=ENC[data]\n").unwrap();
        assert!(is_encrypted_file(&enc));

        let plain = dir.path().join("plain.txt");
        std::fs::write(&plain, "FOO=bar\n").unwrap();
        assert!(!is_encrypted_file(&plain));

        // `.sops.yaml` is never treated as an artifact, even with an ENC marker.
        let sops = dir.path().join(".sops.yaml");
        std::fs::write(&sops, "ENC[x]\n").unwrap();
        assert!(!is_encrypted_file(&sops));

        // An unreadable path yields `false` rather than erroring.
        assert!(!is_encrypted_file(&dir.path().join("does-not-exist")));
    }

    #[test]
    fn glob_match_handles_stars_and_slashes() {
        assert!(glob_match("*.encrypted", "deep.encrypted"));
        assert!(glob_match(".env.encrypted", ".env.encrypted"));
        assert!(glob_match(
            "config/*.encrypted.yaml",
            "config/db.encrypted.yaml"
        ));
        // `*` must not cross a path separator.
        assert!(!glob_match("*.encrypted", "nested/deep.encrypted"));
        assert!(!glob_match("*.encrypted", "deep.txt"));
        assert!(!glob_match("config/*.yaml", "config/sub/db.yaml"));
    }

    #[test]
    fn expand_glob_is_bounded_and_segment_wise() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::write(repo.join(".env.encrypted"), "x").unwrap();
        std::fs::create_dir(repo.join("config")).unwrap();
        std::fs::write(repo.join("config/db.encrypted.yaml"), "x").unwrap();
        std::fs::create_dir(repo.join("nested")).unwrap();
        std::fs::write(repo.join("nested/deep.encrypted"), "x").unwrap();

        // `*` stays within one directory level — it must NOT reach nested/.
        let mut top = expand_glob(repo, "*.encrypted");
        top.sort();
        assert_eq!(top, vec![repo.join(".env.encrypted")]);

        // A literal directory segment followed by a wildcard.
        assert_eq!(
            expand_glob(repo, "config/*.encrypted.yaml"),
            vec![repo.join("config/db.encrypted.yaml")]
        );

        // A fully literal pattern just checks existence.
        assert_eq!(
            expand_glob(repo, ".env.encrypted"),
            vec![repo.join(".env.encrypted")]
        );
        assert!(expand_glob(repo, "missing.encrypted").is_empty());
    }

    #[test]
    fn collect_encrypted_files_finds_artifacts_regardless_of_git_status() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        // Dotfile artifact and a same-prefix one that a greedy `.env.*`
        // .gitignore would have hidden — both must be found (the join/approve
        // re-key bug). Detection is filesystem-based, so git status is irrelevant.
        std::fs::write(repo.join(".env.encrypted"), "A=ENC[x]\n").unwrap();
        std::fs::write(repo.join(".env.example.encrypted"), "B=ENC[y]\n").unwrap();
        std::fs::write(repo.join("plain.env"), "A=b\n").unwrap();
        std::fs::write(repo.join(".sops.yaml"), "ENC[ignored]\n").unwrap();
        std::fs::create_dir(repo.join("config")).unwrap();
        std::fs::write(repo.join("config/db.encrypted.yaml"), "k: ENC[z]\n").unwrap();
        // A `*.encrypted` file with no ENC marker must be excluded.
        std::fs::write(repo.join("decoy.encrypted"), "not really encrypted\n").unwrap();

        let globs = vec![
            "*.encrypted".to_string(),
            "config/*.encrypted.yaml".to_string(),
        ];
        let found = collect_encrypted_files(repo, &globs).unwrap();
        assert_eq!(
            found,
            vec![
                repo.join(".env.encrypted"),
                repo.join(".env.example.encrypted"),
                repo.join("config/db.encrypted.yaml"),
            ],
            "all ENC artifacts matching the globs; plain/.sops.yaml/decoy excluded"
        );
    }
}
