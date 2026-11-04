//! The `.encrypted` suffix every encrypted artifact carries.
//!
//! One owner for the naming convention: file-type detection
//! ([`super::FileType::from_path`]) and the `-w` target names in
//! `commands::secrets` both go through these helpers, so they cannot disagree.

use std::path::{Path, PathBuf};

/// The suffix every encrypted artifact carries.
pub(crate) const ENCRYPTED_SUFFIX: &str = ".encrypted";

/// Whether `path` ends in `.encrypted` (case-insensitive).
pub(crate) fn ends_with_encrypted(path: &Path) -> bool {
    path.to_string_lossy()
        .to_ascii_lowercase()
        .ends_with(ENCRYPTED_SUFFIX)
}

/// Append `.encrypted` to `path` (`config.json` → `config.json.encrypted`).
pub(crate) fn with_encrypted_suffix(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(ENCRYPTED_SUFFIX);
    PathBuf::from(name)
}

/// Strip a trailing `.encrypted` (`.env.encrypted` → `.env`), case-insensitive.
///
/// `None` when there is no such suffix, or nothing is left of the file name.
pub(crate) fn without_encrypted_suffix(path: &Path) -> Option<PathBuf> {
    let text = path.to_str()?;
    if !ends_with_encrypted(path) {
        return None;
    }
    let stem = &text[..text.len() - ENCRYPTED_SUFFIX.len()];
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
}
