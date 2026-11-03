//! Where `encrypt`/`decrypt` write: stdout, `-o <path>`, or the `-w` name.
//!
//! The `-w` convention pairs `FILE` with `FILE.encrypted`: encrypt appends the
//! suffix, decrypt strips it.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// The suffix every encrypted artifact carries.
const SUFFIX: &str = ".encrypted";

/// Which way the payload is going.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Direction {
    /// Plaintext in, ciphertext out.
    Encrypt,
    /// Ciphertext in, plaintext out.
    Decrypt,
}

/// Resolve the destination: `None` means stdout, `Some` a file.
///
/// `-o -` and no flag both mean stdout. `-w` derives the name from `input`.
pub(super) fn destination(
    direction: Direction,
    input: &Path,
    output: Option<&Path>,
    write: bool,
) -> Result<Option<PathBuf>> {
    if write {
        return conventional_name(direction, input).map(Some);
    }
    Ok(output
        .filter(|path| path.as_os_str() != "-")
        .map(Path::to_path_buf))
}

/// The `-w` name: `FILE` ↔ `FILE.encrypted`.
pub(super) fn conventional_name(direction: Direction, input: &Path) -> Result<PathBuf> {
    match direction {
        Direction::Encrypt if ends_with_encrypted(input) => Err(Error::Validation(format!(
            "`{}` already ends in `{SUFFIX}`; refusing to write `{}{SUFFIX}`",
            input.display(),
            input.display()
        ))),
        Direction::Encrypt => Ok(with_encrypted_suffix(input)),
        Direction::Decrypt => without_encrypted_suffix(input).ok_or_else(|| {
            Error::Validation(format!(
                "can't derive a plaintext name from `{}`: it does not end in `{SUFFIX}`; use `-o`",
                input.display()
            ))
        }),
    }
}

/// Whether `path` ends in `.encrypted` (case-insensitive).
pub(super) fn ends_with_encrypted(path: &Path) -> bool {
    path.to_string_lossy()
        .to_ascii_lowercase()
        .ends_with(SUFFIX)
}

/// Append `.encrypted` to `path` (`config.json` → `config.json.encrypted`).
pub(super) fn with_encrypted_suffix(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(SUFFIX);
    PathBuf::from(name)
}

/// Strip a trailing `.encrypted` (`.env.encrypted` → `.env`), case-insensitive.
///
/// `None` when there is no such suffix, or nothing is left of the file name.
pub(super) fn without_encrypted_suffix(path: &Path) -> Option<PathBuf> {
    let text = path.to_str()?;
    if !ends_with_encrypted(path) {
        return None;
    }
    let stem = &text[..text.len() - SUFFIX.len()];
    if stem.is_empty() || stem.ends_with(std::path::is_separator) {
        return None;
    }
    Some(PathBuf::from(stem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ends_with_encrypted_is_case_insensitive() {
        assert!(ends_with_encrypted(Path::new(".env.encrypted")));
        assert!(ends_with_encrypted(Path::new("config.json.ENCRYPTED")));
        assert!(!ends_with_encrypted(Path::new("config.json")));
        assert!(!ends_with_encrypted(Path::new("notes.encrypted.txt")));
    }

    #[test]
    fn with_encrypted_suffix_appends() {
        assert_eq!(
            with_encrypted_suffix(Path::new("config.json")),
            PathBuf::from("config.json.encrypted")
        );
        assert_eq!(
            with_encrypted_suffix(Path::new(".env")),
            PathBuf::from(".env.encrypted")
        );
    }

    #[test]
    fn without_encrypted_suffix_strips_it() {
        assert_eq!(
            without_encrypted_suffix(Path::new(".env.encrypted")),
            Some(PathBuf::from(".env"))
        );
        assert_eq!(
            without_encrypted_suffix(Path::new("config/app.yaml.ENCRYPTED")),
            Some(PathBuf::from("config/app.yaml"))
        );
    }

    #[test]
    fn without_encrypted_suffix_rejects_other_names() {
        assert_eq!(without_encrypted_suffix(Path::new(".env")), None);
        assert_eq!(without_encrypted_suffix(Path::new(".encrypted")), None);
        assert_eq!(without_encrypted_suffix(Path::new("dir/.encrypted")), None);
    }

    #[test]
    fn conventional_name_in_both_directions() {
        assert_eq!(
            conventional_name(Direction::Encrypt, Path::new(".env")).unwrap(),
            PathBuf::from(".env.encrypted")
        );
        assert_eq!(
            conventional_name(Direction::Decrypt, Path::new(".env.encrypted")).unwrap(),
            PathBuf::from(".env")
        );
    }

    #[test]
    fn conventional_name_rejects_the_wrong_suffix() {
        let err = conventional_name(Direction::Encrypt, Path::new("a.encrypted")).unwrap_err();
        assert!(err.to_string().contains("already ends in"), "{err}");
        let err = conventional_name(Direction::Decrypt, Path::new(".env")).unwrap_err();
        assert!(err.to_string().contains("use `-o`"), "{err}");
    }

    #[test]
    fn destination_resolves_stdout_output_and_write() {
        let input = Path::new(".env");
        assert_eq!(
            destination(Direction::Encrypt, input, None, false).unwrap(),
            None
        );
        assert_eq!(
            destination(Direction::Encrypt, input, Some(Path::new("-")), false).unwrap(),
            None
        );
        assert_eq!(
            destination(
                Direction::Encrypt,
                input,
                Some(Path::new("x.encrypted")),
                false
            )
            .unwrap(),
            Some(PathBuf::from("x.encrypted"))
        );
        assert_eq!(
            destination(Direction::Encrypt, input, None, true).unwrap(),
            Some(PathBuf::from(".env.encrypted"))
        );
    }
}
