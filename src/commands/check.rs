//! `sopsy check` — CI gate verifying encrypted-secrets hygiene.
//!
//! Runs a fixed set of invariants over the current repository, printing a
//! colorful pass/fail checklist, and exits non-zero (via [`Error::Validation`])
//! if any invariant fails. Intended for pre-commit hooks and CI. It never needs
//! decryption keys: encrypted files are validated by their on-disk sops
//! metadata, not by decrypting them.
//!
//! Invariants:
//! 1. `.env` is **not** tracked by git.
//! 2. `.env` **is** gitignored.
//! 3. `.sops.yaml` exists and parses with at least one `creation_rules` entry.
//! 4. Every encrypted file (matching `.sopsy.yml` `encrypted_globs`) matches at
//!    least one `.sops.yaml` creation-rule `path_regex`.
//! 5. No plaintext secrets are tracked (`.env`/`.env.*` that isn't
//!    `.env.example`/`*.encrypted`, or any `*.key`/`*.pem`).
//! 6. Every encrypted file carries sops metadata (`sops` section + `ENC[`).
//! 7. A break-glass recipient exists in `.sopsy.yml`.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::git;
use crate::ui::Ui;

/// Minimal serde view of `.sops.yaml` — we only need the `path_regex` of each
/// creation rule to verify that encrypted files are covered (invariant 4).
#[derive(Debug, Deserialize)]
struct SopsConfig {
    #[serde(default)]
    creation_rules: Vec<CreationRule>,
}

/// A single `.sops.yaml` creation rule (only its `path_regex` is relevant here).
#[derive(Debug, Deserialize)]
struct CreationRule {
    #[serde(default)]
    path_regex: Option<String>,
}

/// Record a simple boolean invariant: print a `✔`/`✗` line and remember the
/// failure key so the caller can fail the process with a useful summary.
fn report(ui: &Ui, ok: bool, pass: &str, fail: &str, key: &str, failures: &mut Vec<String>) {
    if ok {
        ui.success(pass);
    } else {
        ui.failure(fail);
        failures.push(key.to_string());
    }
}

/// Run the CI check command.
///
/// Returns `Ok(())` when every invariant passes, or [`Error::Validation`]
/// (mapped to a non-zero process exit by the binary) when one or more fail.
/// The full checklist is printed regardless of the outcome.
pub fn run(ui: &Ui) -> Result<()> {
    ui.header("sopsy check");

    let cwd = std::env::current_dir()?;
    let repo = git::repo_root(&cwd)?;

    // `.sopsy.yml` is sopsy's own metadata. If it is absent the repository was
    // never initialised with sopsy, so there is nothing for the CI gate to
    // verify — report it and pass rather than failing unrelated repos.
    let config = match Config::load_from_dir(&repo) {
        Ok(cfg) => cfg,
        Err(Error::FileNotFound(_)) => {
            ui.warn("no `.sopsy.yml` found; repository is not sopsy-managed, skipping check");
            return Ok(());
        }
        Err(err) => return Err(err),
    };

    let mut failures: Vec<String> = Vec::new();

    // 1. `.env` must not be tracked by git.
    let env_tracked = git::is_tracked(&repo, Path::new(".env"))?;
    report(
        ui,
        !env_tracked,
        ".env is not tracked by git",
        ".env is tracked by git (plaintext secrets must never be committed)",
        "env-tracked",
        &mut failures,
    );

    // 2. `.env` must be gitignored.
    let env_ignored = git::is_ignored(&repo, Path::new(".env"))?;
    report(
        ui,
        env_ignored,
        ".env is gitignored",
        ".env is not gitignored (add it to .gitignore)",
        "env-not-ignored",
        &mut failures,
    );

    // 3. `.sops.yaml` must exist and parse with at least one creation rule.
    let sops_rules = load_sops_rules(ui, &repo, &mut failures);

    // Gather the set of files sopsy considers encrypted artifacts. We look at
    // BOTH the git-tracked files AND the files present on disk that match the
    // configured `encrypted_globs`. The on-disk pass matters immediately after
    // `sopsy init`: the freshly created `.env.encrypted` is not committed yet,
    // so without it invariants 4 and 6 would pass vacuously ("no encrypted
    // files to verify") even when the real artifact is broken.
    let tracked = git::tracked_files(&repo)?;
    let encrypted_files = gather_encrypted_files(&repo, &config, &tracked)?;

    // 4. Every encrypted file must match at least one creation-rule path_regex.
    if encrypted_files.is_empty() {
        ui.success("no encrypted files to verify against creation rules");
    } else {
        for file in &encrypted_files {
            let s = file.to_string_lossy();
            let matched = sops_rules.iter().any(|re| regex_is_match(re, &s));
            report(
                ui,
                matched,
                &format!("encrypted file `{s}` matches a .sops.yaml creation rule"),
                &format!("encrypted file `{s}` matches no .sops.yaml creation rule"),
                "unmatched-rule",
                &mut failures,
            );
        }
    }

    // 5. No plaintext secrets tracked.
    check_plaintext_secrets(ui, &tracked, &mut failures);

    // 6. Every encrypted file must carry sops metadata (no decryption needed).
    if encrypted_files.is_empty() {
        ui.success("no encrypted files to parse");
    } else {
        for file in &encrypted_files {
            let s = file.to_string_lossy();
            let content = std::fs::read_to_string(repo.join(file)).unwrap_or_default();
            let is_sops = content.contains("ENC[") && content.contains("sops");
            report(
                ui,
                is_sops,
                &format!("encrypted file `{s}` contains valid sops metadata"),
                &format!("encrypted file `{s}` is missing sops metadata (not encrypted?)"),
                "unparseable",
                &mut failures,
            );
        }
    }

    // 7. A break-glass recipient must be configured.
    report(
        ui,
        config.break_glass_recipient().is_some(),
        "a break-glass recipient is configured in .sopsy.yml",
        "no break-glass recipient configured in .sopsy.yml",
        "no-break-glass",
        &mut failures,
    );

    if failures.is_empty() {
        ui.banner_success("all checks passed");
        Ok(())
    } else {
        ui.banner_alert(format!("{} check(s) failed", failures.len()));
        Err(Error::Validation(format!(
            "{} check(s) failed: {}",
            failures.len(),
            failures.join(", ")
        )))
    }
}

/// Collect every file sopsy treats as an encrypted artifact: the union of
/// git-tracked files and on-disk files (anywhere under `repo`, excluding
/// `.git/`) whose repo-relative path matches one of `config.encrypted_globs`.
///
/// Tracked and on-disk paths are both repo-relative, so storing them in a
/// [`BTreeSet`] both deduplicates the two sources and yields a deterministic
/// order for the printed checklist.
fn gather_encrypted_files(
    repo: &Path,
    config: &Config,
    tracked: &[PathBuf],
) -> Result<Vec<PathBuf>> {
    use std::collections::BTreeSet;

    let matches_glob = |rel: &Path| {
        let s = rel.to_string_lossy();
        config
            .encrypted_globs
            .iter()
            .any(|glob| glob_is_match(glob, &s))
    };

    let mut found: BTreeSet<PathBuf> = BTreeSet::new();

    // Source 1: committed files matching an encrypted glob.
    for path in tracked {
        if matches_glob(path) {
            found.insert(path.clone());
        }
    }

    // Source 2: on-disk files matching an encrypted glob (skip the `.git`
    // directory; the plaintext secrets we care about are gitignored and never
    // match the encrypted globs anyway).
    let mut stack = vec![repo.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                if path.file_name().is_some_and(|n| n == ".git") {
                    continue;
                }
                stack.push(path);
            } else if file_type.is_file()
                && let Ok(rel) = path.strip_prefix(repo)
                && matches_glob(rel)
            {
                found.insert(rel.to_path_buf());
            }
        }
    }

    Ok(found.into_iter().collect())
}

/// Invariant 3: load `.sops.yaml`, print its pass/fail line, and return the list
/// of `path_regex` strings (empty when the file is missing or invalid).
fn load_sops_rules(ui: &Ui, repo: &Path, failures: &mut Vec<String>) -> Vec<String> {
    let sops_path = repo.join(".sops.yaml");
    let raw = match std::fs::read_to_string(&sops_path) {
        Ok(raw) => raw,
        Err(_) => {
            report(
                ui,
                false,
                "",
                ".sops.yaml is missing",
                "sops.yaml",
                failures,
            );
            return Vec::new();
        }
    };

    match serde_yaml_ng::from_str::<SopsConfig>(&raw) {
        Ok(cfg) if !cfg.creation_rules.is_empty() => {
            ui.success(".sops.yaml is valid and defines creation rules");
            cfg.creation_rules
                .into_iter()
                .filter_map(|r| r.path_regex)
                .collect()
        }
        Ok(_) => {
            report(
                ui,
                false,
                "",
                ".sops.yaml has no creation_rules",
                "sops.yaml",
                failures,
            );
            Vec::new()
        }
        Err(_) => {
            report(
                ui,
                false,
                "",
                ".sops.yaml is not valid YAML",
                "sops.yaml",
                failures,
            );
            Vec::new()
        }
    }
}

/// Invariant 5: flag tracked files that look like plaintext secrets.
fn check_plaintext_secrets(ui: &Ui, tracked: &[PathBuf], failures: &mut Vec<String>) {
    let mut offenders: Vec<String> = Vec::new();
    for file in tracked {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let suspect_env = (name == ".env" || name.starts_with(".env."))
            && name != ".env.example"
            && !name.ends_with(".encrypted");
        let suspect_key = name.ends_with(".key") || name.ends_with(".pem");

        if suspect_env || suspect_key {
            offenders.push(file.to_string_lossy().to_string());
        }
    }

    if offenders.is_empty() {
        ui.success("no plaintext secret files are tracked by git");
    } else {
        for offender in &offenders {
            ui.failure(format!(
                "tracked file `{offender}` looks like a plaintext secret"
            ));
        }
        failures.push("plaintext-secret".to_string());
    }
}

/// Match `text` against an anchored shell-style `glob`.
///
/// Supports `*` (any run of non-`/` characters) and `?` (a single non-`/`
/// character); all other characters match literally. The whole `text` must be
/// consumed. This is deliberately tiny — enough for `.sopsy.yml` encrypted
/// globs like `*.encrypted` or `config/*.encrypted.yaml` without pulling in a
/// glob dependency.
fn glob_is_match(glob: &str, text: &str) -> bool {
    let pat: Vec<char> = glob.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    glob_match(&pat, &txt)
}

fn glob_match(pat: &[char], txt: &[char]) -> bool {
    match pat.first() {
        None => txt.is_empty(),
        Some('*') => {
            if glob_match(&pat[1..], txt) {
                return true;
            }
            match txt.first() {
                Some(&c) if c != '/' => glob_match(pat, &txt[1..]),
                _ => false,
            }
        }
        Some('?') => match txt.first() {
            Some(&c) if c != '/' => glob_match(&pat[1..], &txt[1..]),
            _ => false,
        },
        Some(&c) => match txt.first() {
            Some(&t) if t == c => glob_match(&pat[1..], &txt[1..]),
            _ => false,
        },
    }
}

/// Report whether `pattern` matches anywhere in `text`.
///
/// A compact, dependency-free regex matcher (the classic Kernighan/Pike
/// algorithm extended with `\` escapes) supporting `^`, `$`, `.`, `*`, and
/// escaped literals (e.g. `\.`). This covers the path regexes sops creation
/// rules use in practice (`.*`, `\.encrypted$`, `\.env\.encrypted$`) without a
/// regex dependency.
fn regex_is_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    if pat.first() == Some(&'^') {
        return match_here(&pat[1..], &txt);
    }
    let mut start: &[char] = &txt;
    loop {
        if match_here(&pat, start) {
            return true;
        }
        if start.is_empty() {
            return false;
        }
        start = &start[1..];
    }
}

/// Does `pat` match at the beginning of `txt`?
fn match_here(pat: &[char], txt: &[char]) -> bool {
    match pat.first() {
        None => true,
        Some('\\') if pat.len() >= 2 => {
            let lit = pat[1];
            if pat.get(2) == Some(&'*') {
                return match_star(lit, false, &pat[3..], txt);
            }
            match txt.first() {
                Some(&c) if c == lit => match_here(&pat[2..], &txt[1..]),
                _ => false,
            }
        }
        Some(&c) if pat.get(1) == Some(&'*') => match_star(c, c == '.', &pat[2..], txt),
        Some('$') if pat.len() == 1 => txt.is_empty(),
        Some(&c) => match txt.first() {
            Some(&t) if c == '.' || c == t => match_here(&pat[1..], &txt[1..]),
            _ => false,
        },
    }
}

/// Match zero or more of `c` (or any char when `any` is set), then `pat`.
fn match_star(c: char, any: bool, pat: &[char], txt: &[char]) -> bool {
    let mut rest: &[char] = txt;
    loop {
        if match_here(pat, rest) {
            return true;
        }
        match rest.first() {
            Some(&t) if any || t == c => rest = &rest[1..],
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_basenames_and_paths() {
        assert!(glob_is_match("*.encrypted", ".env.encrypted"));
        assert!(glob_is_match(".env.encrypted", ".env.encrypted"));
        assert!(glob_is_match(
            "config/*.encrypted.yaml",
            "config/db.encrypted.yaml"
        ));
        assert!(!glob_is_match("*.encrypted", "config/db.encrypted"));
        assert!(!glob_is_match("*.encrypted", ".env"));
    }

    #[test]
    fn glob_question_mark_matches_single_non_slash() {
        // `?` matches exactly one non-`/` character.
        assert!(glob_is_match("a?c", "abc"));
        assert!(!glob_is_match("a?c", "ac")); // too short
        assert!(!glob_is_match("a?c", "a/c")); // `?` never crosses `/`
        assert!(!glob_is_match("a?c", "abbc")); // too long
    }

    #[test]
    fn regex_matches_sops_path_regexes() {
        assert!(regex_is_match(".*", ".env.encrypted"));
        assert!(regex_is_match(r"\.encrypted$", ".env.encrypted"));
        assert!(regex_is_match(r"\.env\.encrypted$", ".env.encrypted"));
        assert!(!regex_is_match(r"\.env\.encrypted$", "secrets.encrypted"));
        assert!(!regex_is_match(
            r"doesnotmatch\.encrypted$",
            ".env.encrypted"
        ));
        assert!(regex_is_match("^secret", "secret.encrypted"));
        assert!(!regex_is_match("^secret", "a-secret"));
    }

    #[test]
    fn regex_literal_star_repeats_and_backtracks() {
        // `b*` with a literal `b` must repeat and then match the rest.
        assert!(regex_is_match("ab*c", "abbbc"));
        assert!(regex_is_match("ab*c", "ac")); // zero repetitions
        assert!(!regex_is_match("ab*c", "axc")); // cannot reach the trailing `c`
    }

    #[test]
    fn regex_escaped_literal_star_repeats() {
        // `\.*` is a repeated literal dot (the escaped form exercised by the
        // `match_star` branch reached through a `\`-escape).
        assert!(regex_is_match(r"x\.*y", "x..y"));
        assert!(regex_is_match(r"x\.*y", "xy")); // zero dots
        assert!(!regex_is_match(r"x\.*y", "xay"));
    }

    #[test]
    fn gather_unions_tracked_and_on_disk_files() {
        let dir = assert_fs::TempDir::new().unwrap();
        let repo = dir.path();

        // A tracked, on-disk artifact (present in both sources → deduped).
        std::fs::write(repo.join(".env.encrypted"), "x: ENC[v]\n").unwrap();
        // A nested, *untracked* artifact only on disk.
        std::fs::create_dir(repo.join("config")).unwrap();
        std::fs::write(repo.join("config/db.encrypted.yaml"), "y: ENC[v]\n").unwrap();
        // A non-matching file is ignored.
        std::fs::write(repo.join("README.md"), "hello\n").unwrap();
        // `.git/` is skipped even if it contains a matching name.
        std::fs::create_dir(repo.join(".git")).unwrap();
        std::fs::write(repo.join(".git/HEAD.encrypted"), "z: ENC[v]\n").unwrap();

        let config = Config::default();
        let tracked = vec![PathBuf::from(".env.encrypted")];
        let found = gather_encrypted_files(repo, &config, &tracked).unwrap();

        assert_eq!(
            found,
            vec![
                PathBuf::from(".env.encrypted"),
                PathBuf::from("config/db.encrypted.yaml"),
            ],
            "expected the deduped union of tracked + on-disk artifacts, .git skipped"
        );
    }
}
