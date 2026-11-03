//! `sopsy run`: start a command with decrypted values in its environment.
//!
//! sopsy decrypts each file to JSON through `sops` and replaces itself with the
//! command. `sops exec-env` is not used because it cannot be told the type of a
//! `.env.encrypted` file.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use serde_yaml_ng::Value;

use super::blocked::check_variables;
use super::{encrypted_file_type, program};
use crate::cli::RunArgs;
use crate::commands::keys::prompt_for_yubikey_if_needed;
use crate::error::{Error, Result};
use crate::sops;
use crate::ui::Ui;

/// Run a command with the decrypted values of every `--file` in its
/// environment. On Unix sopsy replaces itself with the command, so its exit
/// status and signals are the command's own.
pub fn run(ui: &Ui, args: &RunArgs) -> Result<()> {
    // Find the program first, with sopsy's own PATH: nothing decrypted may
    // change which program starts.
    let (name, rest) = args
        .command
        .split_first()
        .ok_or_else(|| Error::Validation("no command given".into()))?;
    let path = program::resolve(name, std::env::var_os("PATH").as_deref())
        .ok_or_else(|| Error::ToolNotFound(name.clone()))?;

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

    if args.pristine {
        // stdout belongs to the command, so this goes to stderr. sopsy is
        // replaced by the command, so this is the last chance to explain a
        // failure that the cleared environment causes later.
        eprintln!(
            "sopsy: {}",
            pristine_notice(name, vars.len(), &dropped_basics())
        );
    }
    let command = build_command(path, name, rest, args.pristine, vars);
    ui.flush();
    exec(command, name, args.pristine)
}

/// The command to start: the resolved `path`, shown to itself as `name`, with
/// `vars` added to its environment (or as its whole environment when
/// `pristine`).
fn build_command(
    path: PathBuf,
    name: &str,
    rest: &[String],
    pristine: bool,
    vars: Vec<(String, String)>,
) -> Command {
    let mut command = Command::new(path);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.arg0(name);
    }
    #[cfg(not(unix))]
    let _ = name;
    command.args(rest);
    if pristine {
        command.env_clear();
    }
    command.envs(vars);
    command
}

/// Inherited variables most programs expect, which `--pristine` drops.
const BASICS: &[&str] = &["PATH", "HOME", "USER", "TMPDIR", "TERM", "LANG"];

/// The [`BASICS`] (and `LC_*`) set in sopsy's own environment.
fn dropped_basics() -> Vec<String> {
    let mut names: Vec<String> = BASICS
        .iter()
        .filter(|n| std::env::var_os(n).is_some())
        .map(|n| n.to_string())
        .collect();
    let mut locale: Vec<String> = std::env::vars_os()
        .filter_map(|(k, _): (OsString, OsString)| k.into_string().ok())
        .filter(|k| k.starts_with("LC_"))
        .collect();
    locale.sort();
    names.extend(locale);
    names
}

fn pristine_notice(name: &str, count: usize, dropped: &[String]) -> String {
    let values = if count == 1 { "value" } else { "values" };
    let mut line = format!("--pristine: starting {name} with only the {count} decrypted {values}");
    if !dropped.is_empty() {
        line.push_str(&format!("; dropped {}", dropped.join(", ")));
    }
    line
}

#[cfg(unix)]
fn exec(mut command: Command, name: &str, pristine: bool) -> Result<()> {
    use std::os::unix::process::CommandExt;
    // Only returns on failure to start the program.
    let err = command.exec();
    Err(start_error(name, err, pristine))
}

#[cfg(not(unix))]
fn exec(mut command: Command, name: &str, pristine: bool) -> Result<()> {
    let status = command
        .status()
        .map_err(|e| start_error(name, e, pristine))?;
    std::process::exit(status.code().unwrap_or(1));
}

fn start_error(name: &str, err: std::io::Error, pristine: bool) -> Error {
    if pristine {
        return Error::Validation(format!(
            "could not start `{name}`: {err}; the environment was cleared by --pristine"
        ));
    }
    if err.kind() == std::io::ErrorKind::NotFound {
        Error::ToolNotFound(name.to_string())
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
    fn an_empty_command_is_an_error() {
        let args = RunArgs {
            files: vec![],
            pristine: false,
            command: vec![],
        };
        let ui = Ui::new(false, false, false);
        assert!(run(&ui, &args).is_err());
    }

    #[test]
    fn the_command_runs_by_full_path_and_keeps_its_name() {
        let rest = vec!["-c".to_string()];
        let cmd = build_command("/bin/sh".into(), "sh", &rest, true, pairs(&[("A", "1")]));
        assert_eq!(cmd.get_program(), "/bin/sh");
        let envs: Vec<_> = cmd.get_envs().collect();
        assert!(
            envs.iter()
                .any(|(k, v)| *k == "A" && *v == Some("1".as_ref()))
        );
    }

    #[test]
    fn start_errors_name_the_program_and_pristine() {
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert!(
            matches!(start_error("nope", missing, false), Error::ToolNotFound(p) if p == "nope")
        );
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(matches!(start_error("nope", denied, false), Error::Io(_)));
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        let err = start_error("rails", missing, true).to_string();
        assert!(
            err.contains("`rails`") && err.contains("cleared by --pristine"),
            "{err}"
        );
    }

    #[test]
    fn the_pristine_notice_counts_values_and_names_what_was_dropped() {
        let dropped = vec!["PATH".to_string(), "HOME".to_string()];
        assert_eq!(
            pristine_notice("rails", 3, &dropped),
            "--pristine: starting rails with only the 3 decrypted values; dropped PATH, HOME"
        );
        assert_eq!(
            pristine_notice("env", 1, &[]),
            "--pristine: starting env with only the 1 decrypted value"
        );
    }
}
