//! `sopsy run`, `sopsy set`, `sopsy unset` and `sopsy rotate-data-key`: the
//! everyday `sops` operations, with sopsy's file-type detection, YubiKey
//! prompts and no plaintext on disk.
//!
//! - `run` decrypts through `sops --output-type dotenv` and starts the command
//!   with those values in its environment. (`sops exec-env` cannot be told the
//!   type of a `.env.encrypted` file, so sopsy does not use it.)
//! - `set` / `unset` wrap `sops set --value-stdin` / `sops unset`.
//! - `rotate-data-key` wraps `sops rotate --in-place`.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::{RotateDataKeyArgs, RunArgs, SetArgs, UnsetArgs};
use crate::commands::keys::prompt_for_yubikey_if_needed;
use crate::error::{Error, Result};
use crate::sops::{self, FileType};
use crate::ui::Ui;

/// Run a command with the decrypted values of every `--file` in its
/// environment. On Unix sopsy replaces itself with the command, so its exit
/// status and signals are the command's own.
pub fn run(ui: &Ui, args: &RunArgs) -> Result<()> {
    sops::ensure_available()?;
    prompt_for_yubikey_if_needed(ui)?;

    let mut vars: Vec<(String, String)> = Vec::new();
    for file in &args.files {
        let file_type = encrypted_file_type(file, None)?;
        let dotenv = sops::decrypt_as_dotenv(file, file_type)?;
        for (key, value) in parse_dotenv(&dotenv) {
            vars.retain(|(k, _)| *k != key);
            vars.push((key, value));
        }
    }

    let (program, rest) = args
        .command
        .split_first()
        .ok_or_else(|| Error::Validation("no command given".into()))?;
    let mut command = Command::new(program);
    command.args(rest);
    if args.pristine {
        command.env_clear();
    }
    command.envs(vars);
    ui.flush();
    exec(command, program)
}

#[cfg(unix)]
fn exec(mut command: Command, program: &str) -> Result<()> {
    use std::os::unix::process::CommandExt;
    // Only returns on failure to start the program.
    let err = command.exec();
    Err(start_error(program, err))
}

#[cfg(not(unix))]
fn exec(mut command: Command, program: &str) -> Result<()> {
    let status = command.status().map_err(|e| start_error(program, e))?;
    std::process::exit(status.code().unwrap_or(1));
}

fn start_error(program: &str, err: std::io::Error) -> Error {
    if err.kind() == std::io::ErrorKind::NotFound {
        Error::ToolNotFound(program.to_string())
    } else {
        Error::Io(err)
    }
}

/// Set one value. Asks for it (hidden) when omitted at a terminal, and reads
/// stdin without one, so secrets need not appear on the command line.
pub fn set(ui: &Ui, args: &SetArgs) -> Result<()> {
    sops::ensure_available()?;
    let file_type = editable_file_type(&args.file, args.file_type)?;
    let value = match &args.value {
        Some(value) => value.clone(),
        None if ui.is_interactive() => ui.secret(&format!("Value for {}:", args.key), "VALUE")?,
        None => read_stdin_value()?,
    };
    prompt_for_yubikey_if_needed(ui)?;
    sops::set_value(
        &args.file,
        file_type,
        &tree_path(&args.key),
        &json_string(&value),
    )?;
    ui.success(format!("set `{}` in {}", args.key, args.file.display()));
    Ok(())
}

/// Remove one value.
pub fn unset(ui: &Ui, args: &UnsetArgs) -> Result<()> {
    sops::ensure_available()?;
    let file_type = editable_file_type(&args.file, args.file_type)?;
    prompt_for_yubikey_if_needed(ui)?;
    sops::unset_value(&args.file, file_type, &tree_path(&args.key))?;
    ui.success(format!(
        "removed `{}` from {}",
        args.key,
        args.file.display()
    ));
    Ok(())
}

/// Re-encrypt files under a new data key. With no files given, every
/// encrypted file the repository's `encrypted_globs` match.
pub fn rotate_data_key(ui: &Ui, args: &RotateDataKeyArgs) -> Result<()> {
    ui.header("sopsy rotate-data-key");
    sops::ensure_available()?;
    let files = if args.files.is_empty() {
        repository_files()?
    } else {
        args.files.clone()
    };
    if files.is_empty() {
        ui.warn("no encrypted files found; nothing to rotate");
        return Ok(());
    }
    prompt_for_yubikey_if_needed(ui)?;
    for file in &files {
        let file_type = encrypted_file_type(file, None)?;
        sops::rotate_in_place(file, file_type)?;
        ui.success(format!("new data key for {}", file.display()));
    }
    ui.info("Commit the re-encrypted files; every current recipient can still decrypt them.");
    Ok(())
}

fn repository_files() -> Result<Vec<PathBuf>> {
    let repo = crate::commands::recipient::current_repo_root()?;
    let globs = crate::config::Config::load_from_dir(&repo)?.encrypted_globs;
    crate::commands::recipient::collect_encrypted_files(&repo, &globs)
}

fn encrypted_file_type(file: &Path, explicit: Option<FileType>) -> Result<FileType> {
    if !file.exists() {
        return Err(Error::FileNotFound(file.to_path_buf()));
    }
    Ok(explicit.unwrap_or_else(|| FileType::from_path(file)))
}

/// `set` and `unset` address keys, which a binary file does not have.
fn editable_file_type(file: &Path, explicit: Option<FileType>) -> Result<FileType> {
    let file_type = encrypted_file_type(file, explicit)?;
    if file_type == FileType::Binary {
        return Err(Error::Validation(format!(
            "{} is a binary file and has no keys; edit it with `sopsy edit`",
            file.display()
        )));
    }
    Ok(file_type)
}

fn read_stdin_value() -> Result<String> {
    use std::io::Read;
    let mut value = String::new();
    std::io::stdin().read_to_string(&mut value)?;
    Ok(value.strip_suffix('\n').unwrap_or(&value).to_string())
}

/// A top-level key as a sops tree path (`API_KEY` → `["API_KEY"]`); a path
/// that already starts with `[` is used as given.
fn tree_path(key: &str) -> String {
    let key = key.trim();
    if key.starts_with('[') {
        key.to_string()
    } else {
        format!("[{}]", json_string(key))
    }
}

/// `value` as a JSON string literal, which is what `sops set` expects.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Parse `sops --output-type dotenv` output. sops writes one `KEY=value` per
/// line, unquoted, with newlines in a value escaped as `\n`.
fn parse_dotenv(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .filter(|(key, _)| !key.trim().is_empty())
        .map(|(key, value)| (key.trim().to_string(), value.replace("\\n", "\n")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_become_sops_tree_paths() {
        assert_eq!(tree_path("API_KEY"), r#"["API_KEY"]"#);
        assert_eq!(tree_path(r#"["db"]["password"]"#), r#"["db"]["password"]"#);
    }

    #[test]
    fn values_are_json_strings() {
        assert_eq!(json_string("plain"), r#""plain""#);
        assert_eq!(json_string("a\"b\\c\nd"), r#""a\"b\\c\nd""#);
        assert_eq!(json_string("\u{1}"), r#""\u0001""#);
    }

    #[test]
    fn dotenv_output_is_parsed_with_escaped_newlines() {
        let parsed = parse_dotenv("# comment\nA=1\nB=x=y\nC=line1\\nline2\n\n");
        assert_eq!(
            parsed,
            [
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "x=y".to_string()),
                ("C".to_string(), "line1\nline2".to_string()),
            ]
        );
    }
}
