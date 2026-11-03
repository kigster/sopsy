//! `sopsy run`: start a command with decrypted values in its environment.
//!
//! sopsy decrypts each file to JSON through `sops` and replaces itself with the
//! command. `sops exec-env` is not used because it cannot be told the type of a
//! `.env.encrypted` file.

use std::process::Command;

use serde_yaml_ng::Value;

use super::encrypted_file_type;
use crate::cli::RunArgs;
use crate::commands::keys::prompt_for_yubikey_if_needed;
use crate::error::{Error, Result};
use crate::sops;
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
        let json = sops::decrypt_as_json(file, file_type)?;
        for (key, value) in parse_variables(&json, &file.display().to_string())? {
            vars.retain(|(k, _)| *k != key);
            vars.push((key, value));
        }
    }
    check_variables(&vars)?;
    if vars.iter().any(|(k, _)| k == "PATH") {
        // stdout belongs to the command, so this goes to stderr.
        eprintln!("sopsy: warning: the encrypted file sets PATH for this command");
    }

    let (program, command) = build_command(args, vars)?;
    ui.flush();
    exec(command, &program)
}

/// The command to start: `args.command` with `vars` added to its environment
/// (or as its whole environment with `--pristine`).
fn build_command(args: &RunArgs, vars: Vec<(String, String)>) -> Result<(String, Command)> {
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
    Ok((program.clone(), command))
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

/// The top-level values of a decrypted file, as environment variables.
/// Strings pass through unchanged, numbers and booleans become their text, and
/// `null` becomes empty. A nested map or list has no environment form, so it
/// is an error naming the key.
fn parse_variables(json: &str, file: &str) -> Result<Vec<(String, String)>> {
    let value: Value = serde_yaml_ng::from_str(json)
        .map_err(|e| Error::Validation(format!("could not read decrypted {file}: {e}")))?;
    let Value::Mapping(map) = value else {
        return Err(Error::Validation(format!(
            "{file} does not decrypt to a map of names to values"
        )));
    };
    map.into_iter()
        .map(|(key, value)| {
            let key = match key {
                Value::String(key) => key,
                other => scalar(&other).unwrap_or_default(),
            };
            let value = scalar(&value).ok_or_else(|| {
                Error::Validation(format!(
                    "`{key}` in {file} is a nested value; `sopsy run` passes only \
                     top-level names and values"
                ))
            })?;
            Ok((key, value))
        })
        .collect()
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => Some(String::new()),
        _ => None,
    }
}

/// Refuse variables that change which code the command loads. Anyone who can
/// edit the encrypted file could otherwise run code on every machine that
/// runs `sopsy run`.
fn check_variables(vars: &[(String, String)]) -> Result<()> {
    let loader = vars
        .iter()
        .map(|(k, _)| k.as_str())
        .find(|k| k.starts_with("LD_") || k.starts_with("DYLD_"));
    match loader {
        Some(name) => Err(Error::Validation(format!(
            "the encrypted file sets `{name}`, which changes the code a program loads; \
             sopsy run refuses it"
        ))),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn values_keep_backslashes_and_newlines_apart() {
        let json = r#"{"WIN": "C:\\new\\dir", "ML": "a\nb", "N": 3, "B": true, "E": null}"#;
        assert_eq!(
            parse_variables(json, "f").unwrap(),
            pairs(&[
                ("WIN", r"C:\new\dir"),
                ("ML", "a\nb"),
                ("N", "3"),
                ("B", "true"),
                ("E", ""),
            ])
        );
    }

    #[test]
    fn nested_values_and_non_maps_are_errors() {
        let err = parse_variables(r#"{"db": {"password": "x"}}"#, "f").unwrap_err();
        assert!(
            err.to_string().contains("`db` in f is a nested value"),
            "{err}"
        );
        assert!(parse_variables("[1, 2]", "f").is_err());
        assert!(parse_variables("{", "f").is_err());
    }

    #[test]
    fn loader_variables_are_refused() {
        assert!(check_variables(&pairs(&[("PATH", "/bin"), ("A", "1")])).is_ok());
        for name in ["LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES"] {
            let err = check_variables(&pairs(&[(name, "x")])).unwrap_err();
            assert!(err.to_string().contains(name), "{err}");
        }
    }

    #[test]
    fn an_empty_command_is_an_error() {
        let args = RunArgs {
            files: vec![],
            pristine: false,
            command: vec![],
        };
        assert!(build_command(&args, vec![]).is_err());
    }

    #[test]
    fn a_missing_program_is_reported_by_name() {
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert!(matches!(start_error("nope", missing), Error::ToolNotFound(p) if p == "nope"));
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(matches!(start_error("nope", denied), Error::Io(_)));
    }
}
