//! Find the managed encrypted files under a repository.
//!
//! Every membership change and data-key rotation hands each file found here to
//! `sops`, which rewrites it in place, so this module decides which files sopsy
//! is allowed to touch.
//!
//! The rule, under the default [`LinkPolicy::RepoOnly`]:
//!
//! - A glob with a `..` or `.` segment, or an absolute one, selects nothing.
//!   [`crate::config::Config::load`] refuses such a config outright.
//! - A symbolic link is followed only when it resolves inside the repository
//!   and, for a file, when git tracks the file it resolves to.
//! - A file with more than one hard link is skipped, since its other names may
//!   live outside the repository.
//! - Every selected file must canonicalize to a path inside the repository.
//!
//! `--external-symlinks` ([`LinkPolicy::AllowExternal`]) lifts the link and
//! hard-link rules. The glob rule always holds.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::config::encrypted_glob_problem;
use crate::error::{Error, Result};
use crate::ui::Ui;

/// Which links discovery may follow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum LinkPolicy {
    /// Follow a symlink only to a git-tracked file inside the repository, and
    /// skip files with more than one hard link. The default.
    #[default]
    RepoOnly,
    /// Follow every symlink and accept hard links (`--external-symlinks`).
    AllowExternal,
}

impl LinkPolicy {
    /// The policy the global `--[no-]external-symlinks` flag selected.
    pub(crate) fn from_ui(ui: &Ui) -> Self {
        if ui.follows_external_symlinks() {
            Self::AllowExternal
        } else {
            Self::RepoOnly
        }
    }
}

/// Why discovery left a path alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SkipReason {
    /// A symlink that resolves outside the repository.
    ExternalSymlink,
    /// A symlink to a file inside the repository that git does not track.
    UntrackedSymlinkTarget(PathBuf),
    /// A symlink whose target does not exist.
    BrokenSymlink,
    /// A regular file with more than one hard link.
    HardLink,
}

/// A path discovery refused, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Skipped {
    /// The path as the glob reached it.
    pub(crate) path: PathBuf,
    /// Why it was refused.
    pub(crate) reason: SkipReason,
}

impl Skipped {
    /// A one-line explanation for the operator, with `path` shown relative to
    /// `repo`.
    pub(crate) fn describe(&self, repo: &Path) -> String {
        let shown = relative(repo, &self.path);
        match &self.reason {
            SkipReason::ExternalSymlink => format!(
                "skipping `{shown}`: it is a symlink that leaves the repository \
                 (pass --external-symlinks to follow it)"
            ),
            SkipReason::UntrackedSymlinkTarget(target) => format!(
                "skipping `{shown}`: it links to `{}`, which git does not track \
                 (commit it, or pass --external-symlinks)",
                relative(repo, target)
            ),
            SkipReason::BrokenSymlink => {
                format!("skipping `{shown}`: it is a symlink to nothing")
            }
            SkipReason::HardLink => format!(
                "skipping `{shown}`: it has other hard links, which may live outside \
                 the repository (pass --external-symlinks to include it)"
            ),
        }
    }
}

/// `path` relative to `repo` for display, or as given when it is elsewhere.
fn relative(repo: &Path, path: &Path) -> String {
    path.strip_prefix(repo)
        .unwrap_or(path)
        .display()
        .to_string()
}

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
/// Links are handled as the module documentation describes; see
/// [`discover_encrypted_files`].
pub(crate) fn collect_encrypted_files(
    repo: &Path,
    globs: &[String],
    policy: LinkPolicy,
) -> Result<Vec<PathBuf>> {
    Ok(discover_encrypted_files(repo, globs, policy).files)
}

/// [`discover_encrypted_files`], warning about every skipped path on `ui`.
/// For the commands that are about to rewrite the files it returns.
pub(crate) fn discover_and_warn(ui: &Ui, repo: &Path, globs: &[String]) -> Vec<PathBuf> {
    let Discovery { files, skipped } =
        discover_encrypted_files(repo, globs, LinkPolicy::from_ui(ui));
    for skip in &skipped {
        ui.warn(skip.describe(repo));
    }
    files
}

/// What [`discover_encrypted_files`] found under a repository.
#[derive(Debug, Default)]
pub(crate) struct Discovery {
    /// Files that match an encrypted glob, carry sops ciphertext and pass the
    /// [`LinkPolicy`]. A file reached through a symlink is listed under the path
    /// it resolves to, so each file appears once.
    pub(crate) files: Vec<PathBuf>,
    /// Paths that were refused, and why.
    pub(crate) skipped: Vec<Skipped>,
}

/// A path reached while expanding a glob, and whether a symlink was crossed to
/// reach it.
struct Candidate {
    path: PathBuf,
    via_link: bool,
}

/// Expand `globs` under `repo` into the managed encrypted files, reporting what
/// was refused on the way.
///
/// A membership change hands every selected path to `sops updatekeys`, which
/// rewrites the file it is given. A planted link (symbolic or hard) or a `..`
/// glob could otherwise point that rewrite at ciphertext outside the repository
/// and grant the new recipient a stanza there (#39).
///
/// The check and the later `sops` run are separate steps; [`verify_before_rewrite`]
/// repeats the check immediately before each file is rewritten.
pub(crate) fn discover_encrypted_files(
    repo: &Path,
    globs: &[String],
    policy: LinkPolicy,
) -> Discovery {
    let canonical_repo = std::fs::canonicalize(repo).unwrap_or_else(|_| repo.to_path_buf());
    let mut skipped = Vec::new();
    let mut files = BTreeSet::new();
    for pattern in globs {
        if encrypted_glob_problem(pattern).is_some() {
            continue;
        }
        for candidate in expand_glob_into(repo, &canonical_repo, pattern, policy, &mut skipped) {
            if let Some(file) = admit(repo, &canonical_repo, candidate, policy, &mut skipped) {
                files.insert(file);
            }
        }
    }
    // A link to a file that was also selected under its own name costs nothing:
    // that file is re-keyed either way, so there is nothing to warn about.
    skipped.retain(|skip| match &skip.reason {
        SkipReason::UntrackedSymlinkTarget(target) => !files.contains(target),
        _ => true,
    });
    skipped.sort_by(|a, b| a.path.cmp(&b.path));
    skipped.dedup();
    Discovery {
        files: files.into_iter().collect(),
        skipped,
    }
}

/// Decide whether a glob match is a managed encrypted file, returning the path
/// to rewrite. Non-files and files without ciphertext are dropped silently;
/// anything the [`LinkPolicy`] refuses is recorded in `skipped`.
fn admit(
    repo: &Path,
    canonical_repo: &Path,
    candidate: Candidate,
    policy: LinkPolicy,
    skipped: &mut Vec<Skipped>,
) -> Option<PathBuf> {
    let Candidate { path, via_link } = candidate;
    let mut skip = |reason| {
        skipped.push(Skipped {
            path: path.clone(),
            reason,
        });
        None
    };
    // `metadata` follows links; a link that was crossed has already been vetted.
    let Ok(meta) = std::fs::metadata(&path) else {
        return if via_link {
            skip(SkipReason::BrokenSymlink)
        } else {
            None
        };
    };
    if !meta.is_file() || !is_encrypted_file(&path) {
        return None;
    }
    let Ok(canonical) = std::fs::canonicalize(&path) else {
        return skip(SkipReason::BrokenSymlink);
    };
    let Some(inside) = canonical
        .strip_prefix(canonical_repo)
        .ok()
        .map(|rel| repo.join(rel))
    else {
        return match policy {
            LinkPolicy::AllowExternal => Some(canonical),
            LinkPolicy::RepoOnly => skip(SkipReason::ExternalSymlink),
        };
    };
    if policy == LinkPolicy::AllowExternal {
        return Some(inside);
    }
    if has_other_hard_links(&meta) {
        return skip(SkipReason::HardLink);
    }
    if via_link && !crate::git::is_tracked(repo, &inside).unwrap_or(false) {
        return skip(SkipReason::UntrackedSymlinkTarget(inside));
    }
    Some(inside)
}

/// Whether the file behind `meta` has more than one name on its filesystem.
#[cfg(unix)]
fn has_other_hard_links(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.nlink() > 1
}

/// Hard-link counts are not checked off Unix.
#[cfg(not(unix))]
fn has_other_hard_links(_meta: &std::fs::Metadata) -> bool {
    false
}

/// Re-check `file` immediately before `sops` rewrites it, narrowing the window
/// in which a file vetted by [`discover_encrypted_files`] could be swapped for a
/// link. Under [`LinkPolicy::RepoOnly`] the file must still be a regular file
/// with one hard link, inside `repo`, with no symlink anywhere below `repo`.
///
/// `sops` opens the file by name itself, so the window cannot be closed from
/// here, only narrowed.
pub(crate) fn verify_before_rewrite(repo: &Path, file: &Path, policy: LinkPolicy) -> Result<()> {
    if policy == LinkPolicy::AllowExternal {
        return Ok(());
    }
    let refused = || {
        Error::Validation(format!(
            "`{}` changed after sopsy selected it (it is now a link, or has left the \
             repository); refusing to rewrite it",
            relative(repo, file)
        ))
    };
    let meta = std::fs::symlink_metadata(file).map_err(|_| refused())?;
    if !meta.is_file() || has_other_hard_links(&meta) {
        return Err(refused());
    }
    let canonical_repo = std::fs::canonicalize(repo)?;
    let rel = file.strip_prefix(repo).map_err(|_| refused())?;
    match std::fs::canonicalize(file) {
        Ok(canonical) if canonical == canonical_repo.join(rel) => Ok(()),
        _ => Err(refused()),
    }
}

/// [`expand_glob_into`] under the default policy, without the skip report.
#[cfg(test)]
fn expand_glob(repo: &Path, pattern: &str) -> Vec<PathBuf> {
    let canonical_repo = std::fs::canonicalize(repo).unwrap();
    expand_glob_into(
        repo,
        &canonical_repo,
        pattern,
        LinkPolicy::RepoOnly,
        &mut Vec::new(),
    )
    .into_iter()
    .map(|candidate| candidate.path)
    .collect()
}

/// Expand a glob `pattern` against the filesystem under `repo`, one path segment
/// at a time. A literal segment is joined without listing a directory; a segment
/// containing `*`/`?` lists exactly its parent directory and keeps the matches.
/// There is no `**`, and `*` never crosses `/`, so the work is bounded to the
/// directories the pattern actually names — no recursive descent.
///
/// A segment that is a symbolic link is crossed only when the policy allows its
/// target (see [`follow_link`]); otherwise it is recorded in `skipped` and
/// neither returned nor listed. Callers have already refused `..` and `.`
/// segments, so without a link nothing leaves `repo`.
fn expand_glob_into(
    repo: &Path,
    canonical_repo: &Path,
    pattern: &str,
    policy: LinkPolicy,
    skipped: &mut Vec<Skipped>,
) -> Vec<Candidate> {
    let mut current = vec![Candidate {
        path: repo.to_path_buf(),
        via_link: false,
    }];
    for segment in pattern.split('/').filter(|s| !s.is_empty()) {
        let mut next = Vec::new();
        let mut keep = |parent: &Candidate, path: PathBuf, is_link: bool| {
            if !is_link {
                next.push(Candidate {
                    path,
                    via_link: parent.via_link,
                });
            } else if let Some(reason) = follow_link(canonical_repo, &path, policy) {
                skipped.push(Skipped { path, reason });
            } else {
                next.push(Candidate {
                    path,
                    via_link: true,
                });
            }
        };
        if segment.contains(['*', '?']) {
            for dir in &current {
                let Ok(entries) = std::fs::read_dir(&dir.path) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    if !glob_match(segment, &name.to_string_lossy()) {
                        continue;
                    }
                    // `DirEntry::file_type` does not follow symlinks.
                    if let Ok(kind) = entry.file_type() {
                        keep(dir, dir.path.join(&name), kind.is_symlink());
                    }
                }
            }
        } else {
            for dir in &current {
                let candidate = dir.path.join(segment);
                if let Ok(meta) = std::fs::symlink_metadata(&candidate) {
                    keep(dir, candidate, meta.file_type().is_symlink());
                }
            }
        }
        current = next;
    }
    current
}

/// Whether the symlink at `link` may be crossed, as `None`, or why not.
///
/// Under [`LinkPolicy::RepoOnly`] the link must resolve inside the repository.
/// Whether a file it reaches is tracked is decided later, in [`admit`].
fn follow_link(canonical_repo: &Path, link: &Path, policy: LinkPolicy) -> Option<SkipReason> {
    let Ok(target) = std::fs::canonicalize(link) else {
        return Some(SkipReason::BrokenSymlink);
    };
    match policy {
        LinkPolicy::AllowExternal => None,
        LinkPolicy::RepoOnly if target.starts_with(canonical_repo) => None,
        LinkPolicy::RepoOnly => Some(SkipReason::ExternalSymlink),
    }
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

    /// A repository under a fresh temporary directory, with an `outside/`
    /// sibling, both created. Returns `(tempdir, repo, outside)`.
    fn repo_and_outside() -> (TempDir, PathBuf, PathBuf) {
        let dir = TempDir::new().unwrap();
        let repo = dir.path().join("repo");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        (dir, repo, outside)
    }

    /// Run `git <args>` in `repo`, panicking on failure.
    fn git(repo: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    /// `git init` `repo` and track `paths` (relative to it).
    fn track(repo: &Path, paths: &[&str]) {
        git(repo, &["init", "-q"]);
        let mut args = vec!["add", "--"];
        args.extend_from_slice(paths);
        git(repo, &args);
    }

    fn globs(patterns: &[&str]) -> Vec<String> {
        patterns.iter().map(|p| p.to_string()).collect()
    }

    /// The paths and reasons discovery refused.
    fn skips(repo: &Path, patterns: &[&str], policy: LinkPolicy) -> Vec<(PathBuf, SkipReason)> {
        discover_encrypted_files(repo, &globs(patterns), policy)
            .skipped
            .into_iter()
            .map(|skip| (skip.path, skip.reason))
            .collect()
    }

    fn found(repo: &Path, patterns: &[&str], policy: LinkPolicy) -> Vec<PathBuf> {
        collect_encrypted_files(repo, &globs(patterns), policy).unwrap()
    }

    /// Issue #39: a matching symlink that leaves the repository is never
    /// selected by default.
    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_file_outside_the_repo_is_skipped() {
        let (_dir, repo, outside) = repo_and_outside();
        std::fs::write(repo.join(".env.encrypted"), "A=ENC[x]\n").unwrap();
        std::fs::write(outside.join("victim.env.encrypted"), "B=ENC[y]\n").unwrap();
        let link = repo.join("planted.env.encrypted");
        std::os::unix::fs::symlink(outside.join("victim.env.encrypted"), &link).unwrap();

        let policy = LinkPolicy::RepoOnly;
        assert_eq!(
            found(&repo, &["*.encrypted"], policy),
            vec![repo.join(".env.encrypted")]
        );
        assert_eq!(
            skips(&repo, &["*.encrypted"], policy),
            vec![(link, SkipReason::ExternalSymlink)]
        );
    }

    /// `--external-symlinks` follows the same link, to the file it resolves to.
    #[cfg(unix)]
    #[test]
    fn external_symlinks_are_followed_when_allowed() {
        let (_dir, repo, outside) = repo_and_outside();
        let victim = outside.join("victim.env.encrypted");
        std::fs::write(&victim, "B=ENC[y]\n").unwrap();
        std::os::unix::fs::symlink(&victim, repo.join("planted.env.encrypted")).unwrap();

        let policy = LinkPolicy::AllowExternal;
        assert_eq!(
            found(&repo, &["*.encrypted"], policy),
            vec![std::fs::canonicalize(&victim).unwrap()]
        );
        assert!(skips(&repo, &["*.encrypted"], policy).is_empty());
    }

    /// Issue #39: a symlinked directory that leaves the repository is not
    /// entered, whether the pattern names it literally or through a wildcard.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_outside_the_repo_is_not_entered() {
        let (_dir, repo, outside) = repo_and_outside();
        std::fs::write(outside.join("db.encrypted.yaml"), "k: ENC[z]\n").unwrap();
        std::os::unix::fs::symlink(&outside, repo.join("config")).unwrap();

        for pattern in ["config/*.encrypted.yaml", "*/db.encrypted.yaml"] {
            let policy = LinkPolicy::RepoOnly;
            assert!(
                found(&repo, &[pattern], policy).is_empty(),
                "pattern `{pattern}` reached through the symlinked directory"
            );
            assert_eq!(
                skips(&repo, &[pattern], policy),
                vec![(repo.join("config"), SkipReason::ExternalSymlink)]
            );
        }
    }

    /// A symlink to a tracked file inside the repository is followed, and the
    /// file is listed once, under its own name.
    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_tracked_file_inside_the_repo_is_followed() {
        let (_dir, repo, _outside) = repo_and_outside();
        std::fs::create_dir(repo.join("secrets")).unwrap();
        std::fs::write(repo.join("secrets/app.yaml"), "k: ENC[x]\n").unwrap();
        track(&repo, &["secrets/app.yaml"]);
        std::os::unix::fs::symlink("secrets/app.yaml", repo.join("app.encrypted")).unwrap();

        let policy = LinkPolicy::RepoOnly;
        assert_eq!(
            found(&repo, &["*.encrypted"], policy),
            vec![repo.join("secrets/app.yaml")]
        );
        assert!(skips(&repo, &["*.encrypted"], policy).is_empty());
    }

    /// A symlinked directory inside the repository is entered, and each file
    /// reached through it must be tracked.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_inside_the_repo_is_entered() {
        let (_dir, repo, _outside) = repo_and_outside();
        std::fs::create_dir(repo.join("shared")).unwrap();
        std::fs::write(repo.join("shared/db.encrypted.yaml"), "k: ENC[x]\n").unwrap();
        std::fs::write(repo.join("shared/new.encrypted.yaml"), "k: ENC[y]\n").unwrap();
        track(&repo, &["shared/db.encrypted.yaml"]);
        std::os::unix::fs::symlink("shared", repo.join("config")).unwrap();

        let policy = LinkPolicy::RepoOnly;
        let pattern = "config/*.encrypted.yaml";
        assert_eq!(
            found(&repo, &[pattern], policy),
            vec![repo.join("shared/db.encrypted.yaml")]
        );
        assert_eq!(
            skips(&repo, &[pattern], policy),
            vec![(
                repo.join("config/new.encrypted.yaml"),
                SkipReason::UntrackedSymlinkTarget(repo.join("shared/new.encrypted.yaml"))
            )]
        );
    }

    /// A symlink to an untracked file inside the repository is skipped, unless
    /// that file is selected under its own name anyway.
    #[cfg(unix)]
    #[test]
    fn a_symlink_to_an_untracked_file_is_skipped_unless_already_selected() {
        let (_dir, repo, _outside) = repo_and_outside();
        git(&repo, &["init", "-q"]);
        std::fs::write(repo.join(".env.encrypted"), "A=ENC[x]\n").unwrap();
        std::fs::write(repo.join("loose.yaml"), "k: ENC[y]\n").unwrap();
        std::os::unix::fs::symlink(".env.encrypted", repo.join("alias.encrypted")).unwrap();
        std::os::unix::fs::symlink("loose.yaml", repo.join("loose.encrypted")).unwrap();

        let policy = LinkPolicy::RepoOnly;
        assert_eq!(
            found(&repo, &["*.encrypted"], policy),
            vec![repo.join(".env.encrypted")]
        );
        assert_eq!(
            skips(&repo, &["*.encrypted"], policy),
            vec![(
                repo.join("loose.encrypted"),
                SkipReason::UntrackedSymlinkTarget(repo.join("loose.yaml"))
            )]
        );
        // Allowed explicitly, both are re-keyed, each once.
        assert_eq!(
            found(&repo, &["*.encrypted"], LinkPolicy::AllowExternal),
            vec![repo.join(".env.encrypted"), repo.join("loose.yaml")]
        );
    }

    /// A dangling symlink is reported, never followed.
    #[cfg(unix)]
    #[test]
    fn a_broken_symlink_is_reported() {
        let (_dir, repo, _outside) = repo_and_outside();
        let link = repo.join("gone.encrypted");
        std::os::unix::fs::symlink("nowhere.encrypted", &link).unwrap();

        assert!(found(&repo, &["*.encrypted"], LinkPolicy::AllowExternal).is_empty());
        assert_eq!(
            skips(&repo, &["*.encrypted"], LinkPolicy::RepoOnly),
            vec![(link, SkipReason::BrokenSymlink)]
        );
    }

    /// A hard link may share its inode with a file outside the repository,
    /// which `sops` would rewrite too, so it is skipped by default.
    #[cfg(unix)]
    #[test]
    fn a_hard_linked_file_is_skipped_unless_allowed() {
        let (_dir, repo, outside) = repo_and_outside();
        let victim = outside.join("victim.env.encrypted");
        std::fs::write(&victim, "B=ENC[y]\n").unwrap();
        let link = repo.join("planted.env.encrypted");
        std::fs::hard_link(&victim, &link).unwrap();

        assert!(found(&repo, &["*.encrypted"], LinkPolicy::RepoOnly).is_empty());
        assert_eq!(
            skips(&repo, &["*.encrypted"], LinkPolicy::RepoOnly),
            vec![(link.clone(), SkipReason::HardLink)]
        );
        assert_eq!(
            found(&repo, &["*.encrypted"], LinkPolicy::AllowExternal),
            vec![link]
        );
    }

    /// Review of #39: a `..`, `.` or absolute glob selects nothing, even with
    /// `--external-symlinks`, and no link involved.
    #[test]
    fn a_glob_that_leaves_the_repo_selects_nothing() {
        let (_dir, repo, outside) = repo_and_outside();
        std::fs::write(outside.join("victim.encrypted"), "B=ENC[y]\n").unwrap();
        std::fs::write(repo.join("own.encrypted"), "A=ENC[x]\n").unwrap();
        let absolute = format!("{}/*.encrypted", outside.display());

        for pattern in ["../outside/*.encrypted", "./*.encrypted", absolute.as_str()] {
            for policy in [LinkPolicy::RepoOnly, LinkPolicy::AllowExternal] {
                assert!(
                    found(&repo, &[pattern], policy).is_empty(),
                    "`{pattern}` selected a file"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn verify_before_rewrite_refuses_a_file_swapped_for_a_link() {
        let (_dir, repo, outside) = repo_and_outside();
        let file = repo.join("own.encrypted");
        std::fs::write(&file, "A=ENC[x]\n").unwrap();
        let strict = LinkPolicy::RepoOnly;
        assert!(verify_before_rewrite(&repo, &file, strict).is_ok());

        // Swapped for a symlink after discovery.
        let victim = outside.join("victim.encrypted");
        std::fs::write(&victim, "B=ENC[y]\n").unwrap();
        std::fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink(&victim, &file).unwrap();
        let err = verify_before_rewrite(&repo, &file, strict).unwrap_err();
        assert!(err.to_string().contains("refusing to rewrite"), "{err}");
        assert!(verify_before_rewrite(&repo, &file, LinkPolicy::AllowExternal).is_ok());

        // Swapped for a hard link.
        std::fs::remove_file(&file).unwrap();
        std::fs::hard_link(&victim, &file).unwrap();
        assert!(verify_before_rewrite(&repo, &file, strict).is_err());

        // A parent directory swapped for a symlink.
        std::fs::create_dir(repo.join("config")).unwrap();
        let nested = repo.join("config/db.encrypted");
        std::fs::write(&nested, "k: ENC[z]\n").unwrap();
        assert!(verify_before_rewrite(&repo, &nested, strict).is_ok());
        std::fs::rename(repo.join("config"), outside.join("config")).unwrap();
        std::os::unix::fs::symlink(outside.join("config"), repo.join("config")).unwrap();
        assert!(verify_before_rewrite(&repo, &nested, strict).is_err());

        // Gone altogether.
        assert!(verify_before_rewrite(&repo, &repo.join("missing"), strict).is_err());
    }

    #[test]
    fn every_skip_explains_itself() {
        let repo = Path::new("/repo");
        let describe = |reason| {
            Skipped {
                path: repo.join("a.encrypted"),
                reason,
            }
            .describe(repo)
        };
        let external = describe(SkipReason::ExternalSymlink);
        assert!(external.contains("`a.encrypted`") && external.contains("--external-symlinks"));
        let untracked = describe(SkipReason::UntrackedSymlinkTarget(repo.join("b.yaml")));
        assert!(untracked.contains("`b.yaml`") && untracked.contains("does not track"));
        assert!(describe(SkipReason::BrokenSymlink).contains("symlink to nothing"));
        assert!(describe(SkipReason::HardLink).contains("hard links"));
    }

    #[test]
    fn the_policy_follows_the_global_flag() {
        let ui = Ui::new(false, false, false);
        assert_eq!(LinkPolicy::from_ui(&ui), LinkPolicy::RepoOnly);
        let ui = ui.with_external_symlinks(true);
        assert_eq!(LinkPolicy::from_ui(&ui), LinkPolicy::AllowExternal);
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
        let found = collect_encrypted_files(repo, &globs, LinkPolicy::RepoOnly).unwrap();
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
