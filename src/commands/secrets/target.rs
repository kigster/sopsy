//! Where `encrypt`/`decrypt` write: stdout, `-o <path>`, or the `-w` name.
//!
//! The `-w` convention pairs `FILE` with `FILE.encrypted`: encrypt appends the
//! suffix, decrypt strips it.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::sops::suffix::{
    ENCRYPTED_SUFFIX as SUFFIX, ends_with_encrypted, with_encrypted_suffix,
    without_encrypted_suffix,
};

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
    let Some(path) = output.filter(|path| path.as_os_str() != "-") else {
        return Ok(None);
    };
    if same_file(input, path) {
        return Err(Error::Validation(format!(
            "`-o {}` names the input file; refusing to overwrite it",
            path.display()
        )));
    }
    Ok(Some(path.to_path_buf()))
}

/// Whether `a` and `b` name one existing file, through `..`, `.` or symlinks.
fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn destination_refuses_the_input_as_output() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join(".env.encrypted");
        std::fs::write(&input, "x").unwrap();
        let aliased = dir.path().join(".").join(".env.encrypted");
        for output in [&input, &aliased] {
            let err = destination(Direction::Decrypt, &input, Some(output), false).unwrap_err();
            assert!(err.to_string().contains("names the input file"), "{err}");
        }
        let other = dir.path().join(".env");
        assert_eq!(
            destination(Direction::Decrypt, &input, Some(&other), false).unwrap(),
            Some(other)
        );
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
