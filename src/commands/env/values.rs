//! `sopsy set` / `sopsy unset`: change one value in an encrypted file through
//! `sops set --value-stdin` / `sops unset`.

use std::path::Path;

use super::encrypted_file_type;
use crate::cli::{SetArgs, UnsetArgs};
use crate::commands::keys::prompt_for_yubikey_if_needed;
use crate::error::{Error, Result};
use crate::sops::{self, FileType};
use crate::ui::Ui;

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
    Ok(without_line_ending(&value).to_string())
}

/// Drop the one line ending a pipe or a heredoc adds (`\n` or `\r\n`); any
/// other trailing whitespace is part of the value.
fn without_line_ending(value: &str) -> &str {
    value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value)
}

/// A top-level key as a sops tree path (`API_KEY` → `["API_KEY"]`). A key that
/// starts with `[` is taken as a full sops path and passed through as given.
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
        assert_eq!(json_string("a\"b\\c\nd\r\te"), r#""a\"b\\c\nd\r\te""#);
        assert_eq!(json_string("\u{1}"), r#""\u0001""#);
    }

    #[test]
    fn only_one_line_ending_is_dropped() {
        assert_eq!(without_line_ending("v\n"), "v");
        assert_eq!(without_line_ending("v\r\n"), "v");
        assert_eq!(without_line_ending("v\n\n"), "v\n");
        assert_eq!(without_line_ending("v "), "v ");
        assert_eq!(without_line_ending("v"), "v");
    }
}
