//! Environment variables `sopsy run` refuses to take from an encrypted file.
//!
//! Each one changes which code a program loads or which program runs. Anyone
//! who can edit an encrypted file is a recipient, but a value they set must not
//! become code that runs on every other member's machine.

use crate::error::{Error, Result};

/// The refused names. An entry ending in `*` is a prefix: `LD_*` matches
/// `LD_PRELOAD`, `LD_LIBRARY_PATH` and the rest.
pub const BLOCKED_VARIABLES: &[&str] = &[
    // the dynamic loader
    "LD_*",
    "DYLD_*",
    // program lookup, including `#!/usr/bin/env` interpreters
    "PATH",
    // interpreters that load code named in a variable
    "RUBYOPT",
    "RUBYLIB",
    "NODE_OPTIONS",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PERL5OPT",
    "PERL5LIB",
    "JAVA_TOOL_OPTIONS",
    // shell startup files
    "BASH_ENV",
    "ENV",
];

/// Whether `name` matches an entry of [`BLOCKED_VARIABLES`].
pub fn is_blocked(name: &str) -> bool {
    BLOCKED_VARIABLES
        .iter()
        .any(|entry| match entry.strip_suffix('*') {
            Some(prefix) => name.starts_with(prefix),
            None => name == *entry,
        })
}

/// Refuse the first blocked variable in `vars`, naming it.
pub fn check_variables(vars: &[(String, String)]) -> Result<()> {
    match vars.iter().find(|(name, _)| is_blocked(name)) {
        Some((name, _)) => Err(Error::Validation(format!(
            "the encrypted file sets `{name}`, which changes the code a program loads; \
             sopsy run refuses it"
        ))),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(name: &str) -> Vec<(String, String)> {
        vec![(name.to_string(), "x".to_string())]
    }

    #[test]
    fn every_listed_name_and_prefix_is_refused_by_name() {
        for entry in BLOCKED_VARIABLES {
            let name = entry.replace('*', "PRELOAD");
            let err = check_variables(&one(&name)).unwrap_err();
            assert!(err.to_string().contains(&format!("`{name}`")), "{err}");
            assert!(err.to_string().contains("changes the code a program loads"));
        }
    }

    #[test]
    fn ordinary_and_lookalike_names_pass() {
        for name in [
            "DATABASE_URL",
            "API_KEY",
            "MYPATH",
            "PATH_INFO",
            "ENVIRONMENT",
            "RUBY_VERSION",
        ] {
            assert!(check_variables(&one(name)).is_ok(), "{name}");
        }
    }
}
