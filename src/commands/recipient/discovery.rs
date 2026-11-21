//! Find the managed encrypted files under a repository.
//!
//! Every membership change and data-key rotation hands each file found here to
//! `sops`, which rewrites it in place, so this module decides which files sopsy
//! is allowed to touch.

use std::path::{Path, PathBuf};

use crate::error::Result;

/// Collect the sops-encrypted files in `repo` that need re-keying.
///
/// The repo's `encrypted_globs` (from `.sopsy.yml`) are expanded against the
/// working tree directly, so **every** matching artifact is found regardless of
/// git status — a not-yet-committed or even `.gitignore`d `*.encrypted` still
/// has to be re-keyed when membership changes, or the new member can't decrypt
/// it. Expansion is bounded (see [`expand_glob_into`]): `*` never crosses `/`,
/// so a glob like `*.encrypted` lists one directory, never a recursive walk of
/// (say) `$HOME`. Each match must also carry the `ENC[` marker to count.
///
/// Symbolic links are never selected and never entered; see
/// [`discover_encrypted_files`].
pub(crate) fn collect_encrypted_files(repo: &Path, globs: &[String]) -> Result<Vec<PathBuf>> {
    Ok(discover_encrypted_files(repo, globs).files)
}

/// What [`discover_encrypted_files`] found under a repository.
pub(crate) struct Discovery {
    /// Regular files that match an encrypted glob and carry sops ciphertext.
    pub(crate) files: Vec<PathBuf>,
    /// Symbolic links met while expanding the globs. They were left alone.
    pub(crate) skipped_symlinks: Vec<PathBuf>,
}

/// Expand `globs` under `repo` into the managed encrypted files, reporting the
/// symbolic links that were refused on the way.
///
/// A membership change hands every selected path to `sops updatekeys`, which
/// rewrites the file it is given. A symlink that matches a glob, or a symlinked
/// directory on the way to a match, would let a planted link point that rewrite
/// at ciphertext outside the repository and grant the new recipient a stanza
/// there. So no path component below `repo` may be a symlink: links are
/// recorded in `skipped_symlinks`, not followed. With no link ever crossed,
/// every selected file is inside `repo`.
///
/// The check and the later `sops` run are separate steps, so a link swapped in
/// between them is not covered here.
pub(crate) fn discover_encrypted_files(repo: &Path, globs: &[String]) -> Discovery {
    let mut files = Vec::new();
    let mut skipped_symlinks = Vec::new();
    for pattern in globs {
        for path in expand_glob_into(repo, pattern, &mut skipped_symlinks) {
            if is_regular_file(&path) && is_encrypted_file(&path) {
                files.push(path);
            }
        }
    }
    files.sort();
    files.dedup();
    skipped_symlinks.sort();
    skipped_symlinks.dedup();
    Discovery {
        files,
        skipped_symlinks,
    }
}

/// Whether `path` is a regular file, judged without following a symlink.
fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file())
}

/// [`expand_glob_into`] without the symlink report.
#[cfg(test)]
fn expand_glob(repo: &Path, pattern: &str) -> Vec<PathBuf> {
    expand_glob_into(repo, pattern, &mut Vec::new())
}

/// Expand a glob `pattern` against the filesystem under `repo`, one path segment
/// at a time. A literal segment is joined without listing a directory; a segment
/// containing `*`/`?` lists exactly its parent directory and keeps the matches.
/// There is no `**`, and `*` never crosses `/`, so the work is bounded to the
/// directories the pattern actually names — no recursive descent.
///
/// A segment that resolves to a symbolic link is pushed onto `symlinks` and
/// dropped, so a link is neither returned nor used as a directory to list.
fn expand_glob_into(repo: &Path, pattern: &str, symlinks: &mut Vec<PathBuf>) -> Vec<PathBuf> {
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
                    if !glob_match(segment, &name.to_string_lossy()) {
                        continue;
                    }
                    // `DirEntry::file_type` does not follow symlinks.
                    match entry.file_type() {
                        Ok(kind) if kind.is_symlink() => symlinks.push(dir.join(&name)),
                        Ok(_) => next.push(dir.join(&name)),
                        Err(_) => {}
                    }
                }
            }
        } else {
            for dir in &current {
                let candidate = dir.join(segment);
                match std::fs::symlink_metadata(&candidate) {
                    Ok(meta) if meta.file_type().is_symlink() => symlinks.push(candidate),
                    Ok(_) => next.push(candidate),
                    Err(_) => {}
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

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::TempDir;

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

    /// The symlinks discovery refused under `repo` for `globs`.
    #[cfg(unix)]
    fn skipped_symlinks(repo: &Path, globs: &[String]) -> Vec<PathBuf> {
        discover_encrypted_files(repo, globs).skipped_symlinks
    }

    /// Issue #39: a matching symlink must never be selected, wherever it points.
    #[cfg(unix)]
    #[test]
    fn collect_encrypted_files_skips_a_symlink_to_a_file_outside_the_repo() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path().join("repo");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(repo.join(".env.encrypted"), "A=ENC[x]\n").unwrap();
        std::fs::write(outside.join("victim.env.encrypted"), "B=ENC[y]\n").unwrap();
        std::os::unix::fs::symlink(
            outside.join("victim.env.encrypted"),
            repo.join("planted.env.encrypted"),
        )
        .unwrap();

        let globs = vec!["*.encrypted".to_string()];
        assert_eq!(
            collect_encrypted_files(&repo, &globs).unwrap(),
            vec![repo.join(".env.encrypted")]
        );
        assert_eq!(
            skipped_symlinks(&repo, &globs),
            vec![repo.join("planted.env.encrypted")]
        );
    }

    /// Issue #39: a symlinked directory on the way to a match is not entered,
    /// whether the pattern names it literally or reaches it through a wildcard.
    #[cfg(unix)]
    #[test]
    fn collect_encrypted_files_does_not_descend_into_a_symlinked_directory() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path().join("repo");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("db.encrypted.yaml"), "k: ENC[z]\n").unwrap();
        std::os::unix::fs::symlink(&outside, repo.join("config")).unwrap();

        for pattern in ["config/*.encrypted.yaml", "*/db.encrypted.yaml"] {
            let globs = vec![pattern.to_string()];
            assert_eq!(
                collect_encrypted_files(&repo, &globs).unwrap(),
                Vec::<PathBuf>::new(),
                "pattern `{pattern}` reached through the symlinked directory"
            );
            assert_eq!(skipped_symlinks(&repo, &globs), vec![repo.join("config")]);
        }
    }

    /// A symlink that stays inside the repository is skipped too: its target is
    /// re-keyed under its own name when that name matches a glob.
    #[cfg(unix)]
    #[test]
    fn collect_encrypted_files_skips_a_symlink_inside_the_repo() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::write(repo.join(".env.encrypted"), "A=ENC[x]\n").unwrap();
        std::os::unix::fs::symlink(repo.join(".env.encrypted"), repo.join("alias.encrypted"))
            .unwrap();

        let globs = vec!["*.encrypted".to_string()];
        assert_eq!(
            collect_encrypted_files(repo, &globs).unwrap(),
            vec![repo.join(".env.encrypted")]
        );
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
