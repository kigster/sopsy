//! `sopsy init` — bootstrap an encrypted repository.
//!
//! `init` is the command people paste into a fresh repo. It verifies the
//! toolchain, acquires an age recipient (an existing public key or a freshly
//! generated Secure Enclave identity), then writes the files that make a repo
//! SOPS-ready: `.sops.yaml` (creation rules), `.env.example`, an encrypted
//! `.env.encrypted`, `.gitignore` safety rules, and sopsy's own `.sopsy.yml`.
//!
//! Every step is idempotent: existing files are preserved unless `--force` is
//! given, so re-running `init` is always safe.

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::cli::{InitArgs, RecipientBreakGlassArgs, RecipientCommand};
use crate::commands::keys;
use crate::commands::recipient::system_username;
use crate::config::KeyPolicy;
use crate::config::{CONFIG_FILE_NAME, Config, Recipient};
use crate::error::{Error, Result};
use crate::hardware::{self, Availability, Store};
use crate::sops::{self, FileType};
use crate::ui::Ui;
use crate::{git, keystore};

/// Default recipient name when none is supplied. The init-time recipient is
/// the repository's *admin*: the first entry in `.sopsy.yml`, whose public key
/// also anchors the `.sopsy.sha` integrity checksum.
const DEFAULT_RECIPIENT_NAME: &str = "admin";

/// Placeholder contents for a freshly created `.env.example`.
const ENV_EXAMPLE_TEMPLATE: &str = "\
# Example environment variables for this project.
# Copy this file to `.env`, fill in real values, then encrypt with sopsy.
# `.env` itself is gitignored and must never be committed in plaintext.
DATABASE_URL=postgres://localhost:5432/myapp
API_KEY=replace-me
";

/// Run repository initialization.
pub fn run(ui: &Ui, args: &InitArgs) -> Result<()> {
    ui.header("sopsy init — bootstrapping your encrypted repository");

    // 1. Resolve the repository root from the current directory.
    let cwd = std::env::current_dir()?;
    let root = git::repo_root(&cwd).map_err(|_| {
        Error::Validation(
            "sopsy init must run inside a git repository (run `git init` first)".to_string(),
        )
    })?;
    guard_repo_root(ui, &cwd, &root, args)?;
    ui.success(format!("Git repository: {}", root.display()));

    // 2. Preflight the tools we depend on.
    sops::ensure_available()?;
    ui.success("Found `sops`.");

    // 3. Decide which key stores members may use, then acquire the admin's
    //    recipient (an existing key, or one generated in an allowed store).
    let required = resolve_required(ui, args)?;
    let allowed = if required.is_empty() {
        None
    } else {
        Some(hardware::expand_selectors(&required)?)
    };
    let recipient = acquire_recipient(ui, args, allowed.as_deref())?;

    // 4. Print the public recipient prominently.
    ui.header("Your repository recipient");
    ui.info(format!("name: {}", recipient.name));
    if let Some(username) = &recipient.username {
        ui.info(format!("owner: {username}"));
    }
    ui.animated_line(&recipient.public_key);

    // 5. `.sops.yaml` creation rules.
    let sops_yaml = root.join(".sops.yaml");
    if sops_yaml.exists() && !args.force {
        ui.warn(".sops.yaml already exists; leaving it untouched (pass --force to overwrite).");
    } else {
        std::fs::write(&sops_yaml, render_sops_yaml(&recipient.public_key))?;
        ui.success("Wrote .sops.yaml creation rules.");
    }

    // 6. `.env.example` with placeholder variables.
    let env_example = root.join(".env.example");
    if env_example.exists() {
        ui.info(".env.example already present; keeping it.");
    } else {
        std::fs::write(&env_example, ENV_EXAMPLE_TEMPLATE)?;
        ui.success("Created .env.example.");
    }

    // 7. Keep plaintext secrets out of git *before* any ciphertext is created,
    //    so even a crash mid-encryption lands in an ignored-by-default state.
    //    `.env.*` is broad, so explicitly un-ignore the plaintext template and
    //    *all* encrypted artifacts — every `*.encrypted` file (e.g.
    //    `.env.encrypted`, `.env.example.encrypted`, `config/foo.encrypted`) is
    //    meant to be committed and must stay visible to git, or membership
    //    changes can't re-key it.
    let mut gitignore_changed = false;
    for pattern in [
        ".env",
        ".env.*",
        "!.env.example",
        "!*.encrypted",
        "*.key",
        "*.pem",
        // Break-glass halves are written transiently and deleted after storage,
        // but ignore them so an interrupted ceremony can never commit a key.
        "*.private",
        "*.public",
    ] {
        gitignore_changed |= git::ensure_gitignored(&root, pattern)?;
    }
    if gitignore_changed {
        ui.success("Updated .gitignore to keep plaintext secrets out of git.");
    } else {
        ui.info(".gitignore already protects plaintext secrets.");
    }

    // 8. `.env.encrypted`, seeded from `.env` if present else `.env.example`.
    //    The seed is encrypted from a private temp file straight to a string, so
    //    plaintext is *never* written to the committable artifact path — a failed
    //    `sops` run can no longer leave a plaintext `.env.encrypted` behind (and
    //    `!*.encrypted` un-ignores that path, so a leak there would be
    //    committable). The ciphertext is written only on success.
    let env_encrypted = root.join(".env.encrypted");
    if env_encrypted.exists() && !args.force {
        ui.info(".env.encrypted already present; leaving it untouched (pass --force to recreate).");
    } else {
        let seed = read_seed(&root)?;
        // NamedTempFile is created 0600 in the system temp dir (outside the repo)
        // and removed when it drops, so the plaintext seed never lands anywhere
        // committable.
        let seed_file = tempfile::NamedTempFile::new()?;
        std::fs::write(seed_file.path(), &seed)?;
        let spinner = ui.spinner("Encrypting .env.encrypted with sops…");
        let ciphertext =
            sops::encrypt_to_string(seed_file.path(), FileType::Dotenv, &env_encrypted);
        spinner.finish_and_clear();
        std::fs::write(&env_encrypted, ciphertext?)?;
        ui.success("Encrypted .env.encrypted.");
    }

    // 9. Record sopsy's own state in `.sopsy.yml`.
    let config = Config {
        recipients: vec![recipient.clone()],
        sops_version: detect_sops_version(),
        key_policy: (!required.is_empty()).then_some(KeyPolicy { required }),
        ..Config::default()
    };
    let config_path = config.save_to_dir(&root)?;
    ui.success(format!("Wrote {}.", config_path.display()));

    // 10. Offer to create the break-glass emergency key while we're here — this
    //     is the moment the owner is most likely to actually do it. Run with
    //     staging suppressed so init emits a single --git summary at the end
    //     rather than the ceremony advising separately (step 12).
    maybe_setup_break_glass(&ui.without_git(), &root, args)?;

    // 11. Final, colorful health summary.
    print_summary(ui, &recipient);

    // 12. With --git, stage exactly the files init creates and print commit/PR
    //     steps. This is the whole set (the break-glass ceremony above ran with
    //     staging suppressed, so it lands here once, not twice).
    if ui.stage_requested() {
        let sopsy_yml = root.join(CONFIG_FILE_NAME);
        let files = [
            root.join(".sops.yaml"),
            root.join(".env.example"),
            root.join(".env.encrypted"),
            root.join(".gitignore"),
            sopsy_yml.clone(),
            Config::checksum_path(&sopsy_yml),
        ];
        git::stage_and_advise(ui, &root, &files, "Add sopsy-managed encrypted secrets")?;
    }
    Ok(())
}

/// Generate the break-glass emergency key during init, if appropriate.
///
/// Resolution: `--no-break-glass` skips; `--break-glass` forces; otherwise we
/// prompt in interactive mode and skip (with guidance) when non-interactive.
/// Delegates to `sopsy recipient break-glass` so the ceremony (write → copy to
/// 1Password → delete → register + re-key) is identical to the standalone path.
fn maybe_setup_break_glass(ui: &Ui, root: &Path, args: &InitArgs) -> Result<()> {
    let want = if args.no_break_glass {
        false
    } else if args.break_glass {
        true
    } else if ui.is_interactive() {
        ui.confirm(
            "Set up a break-glass emergency key now? (strongly recommended)",
            "--break-glass",
            true,
        )?
    } else {
        false
    };

    if !want {
        ui.warn("No break-glass key yet. Create one ASAP with:");
        ui.warn("    sopsy recipient break-glass -o break-glass");
        return Ok(());
    }

    let break_glass_args = RecipientBreakGlassArgs {
        output: root.join("break-glass"),
        name: None,
        force: false,
        no_updatekeys: false,
    };
    crate::commands::recipient::run(ui, &RecipientCommand::BreakGlass(break_glass_args))
}

/// Determine the age recipient for this repository.
///
/// Resolution order: an explicit `--public-key`, then `--no-generate`
/// (which errors, since no key is available), otherwise a generated Secure
/// Enclave identity. In interactive mode the user may opt to paste a key
/// instead of generating one.
/// Refuse to silently adopt an *ancestor* git repository as the secrets repo.
///
/// If you run `sopsy init` in a directory you forgot to `git init`, git walks
/// upward and finds the nearest enclosing repo — which can be your entire `$HOME`.
/// sopsy would then write `.sops.yaml`/`.sopsy.yml` there and try to scan it.
/// When the resolved root is not the current directory, warn (loudly if it is
/// `$HOME`) and require confirmation (or `--force`).
fn guard_repo_root(ui: &Ui, cwd: &Path, root: &Path, args: &InitArgs) -> Result<()> {
    let same = std::fs::canonicalize(cwd).ok() == std::fs::canonicalize(root).ok();
    if same {
        return Ok(());
    }

    ui.warn(format!(
        "{} is not a git repository; the nearest one is {}.",
        cwd.display(),
        root.display()
    ));
    if keystore::home_dir().and_then(|h| std::fs::canonicalize(h).ok())
        == std::fs::canonicalize(root).ok()
    {
        ui.warn("That is your HOME directory — sopsy would manage all of it as a secrets repo.");
    }
    ui.warn("If you meant to start a new repo here, run `git init` in this directory first.");

    let proceed = if args.force {
        true
    } else if ui.is_interactive() {
        ui.confirm(
            &format!("Initialise sopsy in {} anyway?", root.display()),
            "--force",
            false,
        )?
    } else {
        false
    };
    if !proceed {
        return Err(Error::Validation(format!(
            "aborted: {} is not a git repository — run `git init` here first",
            cwd.display()
        )));
    }
    Ok(())
}

/// The repository's allowed key stores: `--require`, else (interactively) a
/// multi-select over every store. Empty means unrestricted.
fn resolve_required(ui: &Ui, args: &InitArgs) -> Result<Vec<String>> {
    if !args.require.is_empty() {
        // Validate now so a typo fails before anything is written.
        hardware::expand_selectors(&args.require)?;
        return Ok(args
            .require
            .iter()
            .map(|r| r.trim().to_ascii_lowercase())
            .filter(|r| !r.is_empty())
            .collect());
    }
    if !ui.is_interactive() {
        return Ok(Vec::new());
    }
    let options: Vec<String> = Store::ALL
        .iter()
        .map(|s| {
            let here = match s.probe() {
                Availability::Ready => "available here".to_string(),
                Availability::MissingTool { install } => format!("needs `{install}`"),
                Availability::Unavailable { reason } => format!("not here: {reason}"),
            };
            format!("{s} — {} ({}; {here})", s.display_name(), s.kind().as_str())
        })
        .collect();
    let picked = ui.multi_select_all(
        "Which key stores may members of this repository use? (space toggles)",
        "--require",
        options,
    )?;
    let picked: Vec<String> = picked
        .iter()
        .filter_map(|p| p.split_whitespace().next().map(str::to_string))
        .collect();
    if picked.is_empty() {
        return Err(Error::Validation(
            "select at least one key store (or pass --require)".into(),
        ));
    }
    // Everything selected is the same as no restriction; don't record it.
    Ok(if picked.len() == Store::ALL.len() {
        Vec::new()
    } else {
        picked
    })
}

fn acquire_recipient(ui: &Ui, args: &InitArgs, allowed: Option<&[Store]>) -> Result<Recipient> {
    let name = args
        .recipient_name
        .clone()
        .unwrap_or_else(|| DEFAULT_RECIPIENT_NAME.to_string());

    if let Some(public_key) = args.public_key.as_deref() {
        let public_key = keys::validate_public_key(public_key)?;
        let store = keys::check_allowed(allowed, &public_key, args.key.store.store())?;
        ui.success(format!("Using supplied age public key for `{name}`."));
        return Ok(
            recipient_with_optional_username(name, public_key, args.username.clone())
                .with_store(store),
        );
    }

    if args.no_generate {
        return Err(Error::Validation(
            "no recipient key available: pass --public-key <age1...>, \
             or drop --no-generate to create an identity"
                .to_string(),
        ));
    }

    // Interactive escape hatch: let the user paste an existing key.
    if ui.is_interactive() {
        let generate = ui.confirm(
            "Generate a new identity for this repository? (No = paste an existing public key)",
            "--public-key",
            true,
        )?;
        if !generate {
            let public_key = keys::validate_public_key(
                &ui.text("Paste your age public key (age1...):", "--public-key")?,
            )?;
            let store = keys::check_allowed(allowed, &public_key, args.key.store.store())?;
            return Ok(
                recipient_with_optional_username(name, public_key, args.username.clone())
                    .with_store(store),
            );
        }
    }

    // Generate the identity and persist its local half so `sops` can find it
    // to decrypt/re-key; without it `sops updatekeys` fails with "identity did
    // not match any of the recipients", which breaks the break-glass step below.
    let identity = keys::generate(ui, &args.key, &name, allowed, false, &[], true)?;

    // Make it obvious a key was generated: show the public key, then pause so
    // the user can take it in before the bootstrap output scrolls on.
    ui.header("Your newly generated public key");
    ui.animated_line(&identity.public_key);
    ui.pause(Duration::from_secs(2));

    // Record who generated this key (default to the system user at the prompt).
    let username = resolve_username(ui, args)?;
    Ok(make_recipient(name, identity.public_key, username).with_store(Some(identity.store)))
}

/// Build a [`Recipient`], attaching `username` only when it is `Some`.
fn make_recipient(name: String, public_key: String, username: Option<String>) -> Recipient {
    match username {
        Some(username) => Recipient::with_username(name, public_key, username),
        None => Recipient::new(name, public_key),
    }
}

/// Build a recipient for a *supplied* key, recording `--username` if given.
fn recipient_with_optional_username(
    name: String,
    public_key: impl Into<String>,
    username: Option<String>,
) -> Recipient {
    let username = username.and_then(|u| {
        let u = u.trim().to_string();
        (!u.is_empty()).then_some(u)
    });
    make_recipient(name, public_key.into(), username)
}

/// Resolve the username to record for a freshly generated identity.
///
/// Interactively, the prompt defaults to `--username` (if given) or the system
/// user, so pressing ENTER records that. Non-interactively, the same default is
/// used without prompting.
fn resolve_username(ui: &Ui, args: &InitArgs) -> Result<Option<String>> {
    let default = args
        .username
        .clone()
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .or_else(system_username);

    if ui.is_interactive() {
        let default_str = default.clone().unwrap_or_default();
        let entered = ui.text_with_default(
            "Your name (recorded as this key's owner):",
            "--username",
            &default_str,
        )?;
        let entered = entered.trim().to_string();
        Ok((!entered.is_empty()).then_some(entered))
    } else {
        Ok(default)
    }
}

/// Render a `.sops.yaml` whose creation rules encrypt the project's encrypted
/// files to `age_recipients` (a comma-separated list of age public keys).
fn render_sops_yaml(age_recipients: &str) -> String {
    format!(
        "# Managed by sopsy. Maps encrypted files to their age recipients.\n\
         creation_rules:\n\
         \x20\x20- path_regex: '\\.env\\.encrypted$'\n\
         \x20\x20\x20\x20age: '{age_recipients}'\n\
         \x20\x20- path_regex: '\\.encrypted$'\n\
         \x20\x20\x20\x20age: '{age_recipients}'\n"
    )
}

/// Read the plaintext to seed `.env.encrypted`: the existing `.env` if present,
/// otherwise the `.env.example` template.
fn read_seed(root: &Path) -> Result<String> {
    let dotenv = root.join(".env");
    if dotenv.exists() {
        return Ok(std::fs::read_to_string(dotenv)?);
    }
    let example = root.join(".env.example");
    if example.exists() {
        return Ok(std::fs::read_to_string(example)?);
    }
    Ok(ENV_EXAMPLE_TEMPLATE.to_string())
}

/// Best-effort detection of the installed `sops` version (honoring the
/// `SOPSY_SOPS_BIN` override). Returns `None` if it cannot be determined.
fn detect_sops_version() -> Option<String> {
    let bin =
        std::env::var_os(sops::SOPS_BIN_ENV).unwrap_or_else(|| OsString::from(sops::SOPS_BIN));
    let output = Command::new(bin).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    // e.g. "sops 3.13.1 (latest)" -> "3.13.1"
    text.split_whitespace().nth(1).map(str::to_string)
}

/// Print the closing health summary and the break-glass reminder.
fn print_summary(ui: &Ui, recipient: &Recipient) {
    ui.banner_success("All set — your repository is ready");
    ui.success("sops configured (.sops.yaml)");
    ui.success("plaintext .env ignored by git");
    ui.success("secrets encrypted (.env.encrypted)");
    ui.success(format!(
        "recipient `{}` recorded in .sopsy.yml",
        recipient.name
    ));
    ui.banner_warn(
        "IMPORTANT — Break-glass: create a separate emergency age key pair and store it \
         offline (e.g. in 1Password), shared with only a few admins, then register it via \
         `sopsy recipient add break-glass --break-glass`. Without it, losing your Secure \
         Enclave device means losing access to every secret.",
    );
    ui.animated_line("Happy encrypting!");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn render_sops_yaml_embeds_recipients() {
        let yaml = render_sops_yaml("age1aaa,age1bbb");
        assert!(yaml.contains("creation_rules:"));
        assert!(yaml.contains("age1aaa,age1bbb"));
        assert!(yaml.contains(r"\.env\.encrypted$"));
    }

    #[test]
    fn read_seed_prefers_dotenv_then_example_then_template() {
        let dir = assert_fs::TempDir::new().unwrap();
        let root = dir.path();

        // Neither file present → the built-in template.
        assert_eq!(read_seed(root).unwrap(), ENV_EXAMPLE_TEMPLATE);

        // `.env.example` present (no `.env`) → its contents.
        std::fs::write(root.join(".env.example"), "EXAMPLE=1\n").unwrap();
        assert_eq!(read_seed(root).unwrap(), "EXAMPLE=1\n");

        // `.env` present → it wins over `.env.example`.
        std::fs::write(root.join(".env"), "REAL=2\n").unwrap();
        assert_eq!(read_seed(root).unwrap(), "REAL=2\n");
    }

    /// Write an executable fake `sops` script and return its path.
    fn write_fake_sops(dir: &Path, body: &str) -> std::path::PathBuf {
        let script = dir.join("fake-sops");
        std::fs::write(&script, format!("#!/bin/sh\n{body}")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script, perms).unwrap();
        }
        script
    }

    #[test]
    #[serial]
    fn detect_sops_version_parses_real_output() {
        let dir = assert_fs::TempDir::new().unwrap();
        let fake = write_fake_sops(dir.path(), "echo 'sops 3.13.1 (latest)'\n");
        // SAFETY: serialized via `#[serial]`.
        unsafe {
            std::env::set_var(sops::SOPS_BIN_ENV, &fake);
        }
        assert_eq!(detect_sops_version().as_deref(), Some("3.13.1"));
        // SAFETY: see above.
        unsafe {
            std::env::remove_var(sops::SOPS_BIN_ENV);
        }
    }

    #[test]
    #[serial]
    fn detect_sops_version_handles_failures() {
        let dir = assert_fs::TempDir::new().unwrap();

        // Non-zero exit → None.
        let failing = write_fake_sops(dir.path(), "exit 1\n");
        // SAFETY: serialized via `#[serial]`.
        unsafe {
            std::env::set_var(sops::SOPS_BIN_ENV, &failing);
        }
        assert!(detect_sops_version().is_none());

        // Success but no version token → None.
        let blank = write_fake_sops(dir.path(), "echo ''\n");
        // SAFETY: serialized via `#[serial]`.
        unsafe {
            std::env::set_var(sops::SOPS_BIN_ENV, &blank);
        }
        assert!(detect_sops_version().is_none());

        // Missing binary → None.
        // SAFETY: serialized via `#[serial]`.
        unsafe {
            std::env::set_var(sops::SOPS_BIN_ENV, "/nonexistent/sops-xyz");
        }
        assert!(detect_sops_version().is_none());

        // SAFETY: see above.
        unsafe {
            std::env::remove_var(sops::SOPS_BIN_ENV);
        }
    }
}
