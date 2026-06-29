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
    RecipientAddArgs, RecipientBreakGlassArgs, RecipientCommand, RecipientKeygenArgs,
    RecipientRemoveArgs,
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

/// Dispatch a `recipient` subcommand.
pub fn run(ui: &Ui, command: &RecipientCommand) -> Result<()> {
    match command {
        RecipientCommand::Add(args) => add(ui, args),
        RecipientCommand::Remove(args) => remove(ui, args),
        RecipientCommand::List => list(ui),
        RecipientCommand::Keygen(args) => keygen(ui, args),
        RecipientCommand::BreakGlass(args) => break_glass(ui, args),
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
    Ok(())
}

/// A snapshot of the two recipient-config files (`.sopsy.yml` and `.sops.yaml`),
/// used to roll a partial mutation back. Updating recipients touches both files
/// *before* `sops updatekeys` re-wraps the encrypted secrets; if that re-wrap
/// fails (most often because the operator's age key is not available to decrypt
/// the existing secrets), restoring this snapshot keeps the repository
/// consistent — it never lists a recipient the secrets were not re-wrapped for.
pub(crate) struct ConfigSnapshot {
    files: [(PathBuf, Option<Vec<u8>>); 2],
}

impl ConfigSnapshot {
    /// Capture the current bytes of both config files (`None` if absent).
    pub(crate) fn capture(repo: &Path, sops_config: &Path) -> Self {
        let sopsy = repo.join(CONFIG_FILE_NAME);
        ConfigSnapshot {
            files: [
                (sopsy.clone(), std::fs::read(&sopsy).ok()),
                (sops_config.to_path_buf(), std::fs::read(sops_config).ok()),
            ],
        }
    }

    /// Restore both files to their captured contents (removing any that did not
    /// exist when captured).
    pub(crate) fn restore(&self) -> Result<()> {
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

    let name_header = "NAME";
    let key_header = "PUBLIC KEY";
    let flag_header = "BREAK-GLASS";

    let name_w = config
        .recipients
        .iter()
        .map(|r| r.name.chars().count())
        .chain(std::iter::once(name_header.len()))
        .max()
        .unwrap_or(name_header.len());

    let truncated: Vec<String> = config
        .recipients
        .iter()
        .map(|r| truncate_key(&r.public_key))
        .collect();
    let key_w = truncated
        .iter()
        .map(|k| k.chars().count())
        .chain(std::iter::once(key_header.len()))
        .max()
        .unwrap_or(key_header.len());

    let header = format!("{name_header:<name_w$}  {key_header:<key_w$}  {flag_header}");
    if ui.color_enabled() {
        println!("{}", header.bold().cyan());
    } else {
        println!("{header}");
    }

    for (recipient, key) in config.recipients.iter().zip(truncated.iter()) {
        let marker = if recipient.break_glass { "★ yes" } else { "" };
        let name_cell = format!("{:<name_w$}", recipient.name);
        let key_cell = format!("{key:<key_w$}");
        if ui.color_enabled() {
            println!(
                "{}  {}  {}",
                name_cell.green().bold(),
                key_cell.dimmed(),
                marker.yellow().bold()
            );
        } else {
            println!("{name_cell}  {key_cell}  {marker}");
        }
    }

    Ok(())
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

/// Generate a portable break-glass emergency key, hand it to the operator for
/// offline storage, then delete it locally and register it as a recipient.
///
/// The break-glass key is an ordinary (exportable) age key — *not* a Secure
/// Enclave identity — precisely because it must survive the loss of any single
/// device. The flow is deliberately interactive: we write the key to disk, wait
/// for the operator to copy it into a secure store (e.g. 1Password), then remove
/// the local copies so the only surviving private key lives offline.
fn break_glass(ui: &Ui, args: &RecipientBreakGlassArgs) -> Result<()> {
    ui.header("sopsy recipient break-glass");

    let repo = current_repo_root()?;
    let mut config = load_config(&repo)?;
    let sops_config = sops_config_path(&repo)?;

    let name = args
        .name
        .as_deref()
        .unwrap_or("break-glass")
        .trim()
        .to_string();
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
            prompt: "press ENTER to confirm the break-glass key is stored safely".to_string(),
            flag: format!("an interactive terminal (or set {ASSUME_YES_ENV} for automation)"),
        });
    }

    // Resolve the two output paths and refuse to clobber existing files.
    let private_path = with_suffix(&args.output, "private");
    let public_path = with_suffix(&args.output, "public");
    for path in [&private_path, &public_path] {
        if path.exists() && !args.force {
            return Err(Error::Validation(format!(
                "{} already exists (pass --force to overwrite)",
                path.display()
            )));
        }
    }

    // Generate a portable age key pair.
    age::ensure_available()?;
    let spinner = ui.spinner("Generating a portable age key pair for break-glass…");
    let keypair = age::generate_keypair();
    spinner.finish_and_clear();
    let keypair = keypair?;

    // Write both halves to disk (private key locked down on unix).
    std::fs::write(&private_path, &keypair.identity)?;
    std::fs::write(&public_path, format!("{}\n", keypair.public_key))?;
    restrict_permissions(&private_path);
    ui.success(format!("wrote private key to {}", private_path.display()));
    ui.success(format!("wrote public key to {}", public_path.display()));

    // Hand off to the operator and block until they confirm safe storage.
    ui.header("ACTION REQUIRED — store the break-glass key offline");
    ui.warn(
        "Please copy these files and place them in 1Password (or another secure, offline store):",
    );
    ui.info(format!("  • {}", private_path.display()));
    ui.info(format!("  • {}", public_path.display()));
    ui.warn("Both files will be DELETED from this machine as soon as you continue.");
    if assume_yes {
        ui.info(format!(
            "{ASSUME_YES_ENV} set — assuming the keys are stored; continuing."
        ));
    } else {
        ui.press_enter(
            "Please press ENTER when you copied the keys to a secure storage (eg 1Password):",
        )?;
    }

    // Remove the local copies; the only surviving private key is now offline.
    std::fs::remove_file(&private_path)?;
    std::fs::remove_file(&public_path)?;
    ui.success("removed the local key files");

    // Register the break-glass recipient in both config files and re-wrap
    // secrets, rolling back atomically if the re-encryption fails (see `add`).
    let snapshot = ConfigSnapshot::capture(&repo, &sops_config);
    config.recipients.push(Recipient {
        break_glass: true,
        ..Recipient::new(&name, &keypair.public_key)
    });
    config.save_to_dir(&repo)?;
    ui.success(format!(
        "recorded `{name}` (break-glass) in {CONFIG_FILE_NAME}"
    ));

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

    if let Err(err) = run_updatekeys(ui, &repo, args.no_updatekeys) {
        snapshot.restore()?;
        ui.warn("rolled back configuration changes — break-glass recipient was not added");
        return Err(rewrap_error(err));
    }

    ui.success(format!("break-glass recipient `{name}` added"));
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

/// Truncate a (long) age public key for display.
fn truncate_key(key: &str) -> String {
    const MAX: usize = 24;
    if key.chars().count() > MAX {
        let head: String = key.chars().take(MAX).collect();
        format!("{head}…")
    } else {
        key.to_string()
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
    fn truncate_key_shortens_only_long_keys() {
        // Short keys pass through unchanged; long ones get an ellipsis.
        assert_eq!(truncate_key("age1short"), "age1short");
        let long = "age1".to_string() + &"x".repeat(60);
        let out = truncate_key(&long);
        assert!(out.ends_with('…'));
        assert_eq!(out.chars().count(), 25); // 24 chars + ellipsis
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
