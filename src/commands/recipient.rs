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

use crate::cli::{RecipientAddArgs, RecipientCommand, RecipientRemoveArgs};
use crate::config::{CONFIG_FILE_NAME, Config, Recipient};
use crate::error::{Error, Result};
use crate::git;
use crate::sops;
use crate::ui::Ui;

/// Conventional name of the `sops` configuration file.
const SOPS_CONFIG_FILE_NAME: &str = ".sops.yaml";

/// Dispatch a `recipient` subcommand.
pub fn run(ui: &Ui, command: &RecipientCommand) -> Result<()> {
    match command {
        RecipientCommand::Add(args) => add(ui, args),
        RecipientCommand::Remove(args) => remove(ui, args),
        RecipientCommand::List => list(ui),
    }
}

/// Locate the repository root containing the current directory.
fn current_repo_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    git::repo_root(&cwd)
}

/// Load `.sopsy.yml`, turning a missing file into a friendly hint.
fn load_config(repo: &Path) -> Result<Config> {
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
fn sops_config_path(repo: &Path) -> Result<PathBuf> {
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
        None => ui.text("Recipient name", "--name")?,
    };
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err(Error::Validation("recipient name must not be empty".into()));
    }

    let public_key = match args.public_key.as_deref() {
        Some(key) => key.to_string(),
        None => ui.text("Recipient age public key (age1…)", "--public-key")?,
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

    run_updatekeys(ui, &repo, args.no_updatekeys)?;

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
            ui.select("Recipient to remove", "--name", options)?
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

    run_updatekeys(ui, &repo, args.no_updatekeys)?;

    ui.success(format!("recipient `{name}` removed"));
    Ok(())
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

/// Re-wrap every encrypted file in `repo` for the current recipient set, unless
/// skipping was requested.
///
/// This is the moral equivalent of `sops updatekeys -r .`, but performed
/// file-by-file: `sops updatekeys` (3.x) operates on a single file and has no
/// recursive mode, so sopsy discovers the managed files itself and runs
/// `sops updatekeys -y --input-type T <file>` for each.
fn run_updatekeys(ui: &Ui, repo: &Path, skip: bool) -> Result<()> {
    if skip {
        ui.info("skipping re-encryption (`--no-updatekeys`)");
        return Ok(());
    }
    let files = collect_encrypted_files(repo)?;
    if files.is_empty() {
        ui.info("no encrypted files found to re-encrypt");
        return Ok(());
    }
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
    Command::new(bin)
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

/// Recursively collect sops-encrypted files under `repo`.
///
/// A file is considered encrypted if it contains the `ENC[` marker that sops
/// writes around every encrypted value. The `.git` directory and `.sops.yaml`
/// itself are skipped.
fn collect_encrypted_files(repo: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut stack = vec![repo.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                if path.file_name().is_some_and(|n| n == ".git") {
                    continue;
                }
                stack.push(path);
            } else if file_type.is_file() && is_encrypted_file(&path) {
                found.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
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
fn add_key_to_sops_yaml(path: &Path, key: &str) -> Result<usize> {
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
    fn collect_encrypted_files_walks_recursively_and_skips_git() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::write(repo.join("top.encrypted"), "A=ENC[x]\n").unwrap();
        std::fs::write(repo.join("plain.env"), "A=b\n").unwrap();
        std::fs::write(repo.join(".sops.yaml"), "ENC[ignored]\n").unwrap();
        std::fs::create_dir(repo.join("nested")).unwrap();
        std::fs::write(repo.join("nested/deep.encrypted"), "B=ENC[y]\n").unwrap();
        // A `.git` directory whose contents must be ignored.
        std::fs::create_dir(repo.join(".git")).unwrap();
        std::fs::write(repo.join(".git/obj.encrypted"), "C=ENC[z]\n").unwrap();

        let found = collect_encrypted_files(repo).unwrap();
        assert_eq!(
            found,
            vec![
                repo.join("nested/deep.encrypted"),
                repo.join("top.encrypted")
            ],
            "expected the two ENC artifacts, sorted, with .git and .sops.yaml excluded"
        );
    }
}
