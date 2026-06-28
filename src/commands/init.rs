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
use crate::config::{Config, Recipient};
use crate::error::{Error, Result};
use crate::sops::{self, FileType};
use crate::ui::Ui;
use crate::{enclave, git};

/// Default recipient name when none is supplied.
const DEFAULT_RECIPIENT_NAME: &str = "primary";

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
    ui.success(format!("Git repository: {}", root.display()));

    // 2. Preflight the tools we depend on.
    sops::ensure_available()?;
    ui.success("Found `sops`.");

    // 3. Acquire the recipient (existing key or generated Secure Enclave one).
    let recipient = acquire_recipient(ui, args)?;

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

    // 7. `.env.encrypted`, seeded from `.env` if present else `.env.example`.
    let env_encrypted = root.join(".env.encrypted");
    if env_encrypted.exists() && !args.force {
        ui.info(".env.encrypted already present; leaving it untouched (pass --force to recreate).");
    } else {
        let seed = read_seed(&root)?;
        std::fs::write(&env_encrypted, seed)?;
        let spinner = ui.spinner("Encrypting .env.encrypted with sops…");
        let result = sops::encrypt_in_place(&env_encrypted, FileType::Dotenv);
        spinner.finish_and_clear();
        result?;
        ui.success("Encrypted .env.encrypted.");
    }

    // 8. Keep plaintext secrets out of git. `.env.*` is broad, so explicitly
    //    un-ignore the two files we *do* want committed.
    let mut gitignore_changed = false;
    for pattern in [
        ".env",
        ".env.*",
        "!.env.example",
        "!.env.encrypted",
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

    // 9. Record sopsy's own state in `.sopsy.yml`.
    let config = Config {
        recipients: vec![recipient.clone()],
        sops_version: detect_sops_version(),
        ..Config::default()
    };
    let config_path = config.save_to_dir(&root)?;
    ui.success(format!("Wrote {}.", config_path.display()));

    // 10. Offer to create the break-glass emergency key while we're here — this
    //     is the moment the owner is most likely to actually do it.
    maybe_setup_break_glass(ui, &root, args)?;

    // 11. Final, colorful health summary.
    print_summary(ui, &recipient);
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
fn acquire_recipient(ui: &Ui, args: &InitArgs) -> Result<Recipient> {
    let name = args
        .recipient_name
        .clone()
        .unwrap_or_else(|| DEFAULT_RECIPIENT_NAME.to_string());

    if let Some(public_key) = args.public_key.as_deref() {
        ui.success(format!("Using supplied age public key for `{name}`."));
        return Ok(recipient_with_optional_username(
            name,
            public_key,
            args.username.clone(),
        ));
    }

    if args.no_generate {
        return Err(Error::Validation(
            "no recipient key available: pass --public-key <age1...>, \
             or drop --no-generate to create a Secure Enclave identity"
                .to_string(),
        ));
    }

    // Interactive escape hatch: let the user paste an existing key.
    if ui.is_interactive() {
        let generate = ui.confirm(
            "Generate a new Secure Enclave-backed identity? (No = paste an existing public key)",
            "--public-key",
            true,
        )?;
        if !generate {
            let public_key = ui.text("Paste your age public key (age1...):", "--public-key")?;
            return Ok(recipient_with_optional_username(
                name,
                public_key,
                args.username.clone(),
            ));
        }
    }

    // Generate a Secure Enclave-backed identity.
    enclave::ensure_available()?;
    let spinner = ui.spinner("Generating Secure Enclave identity (Touch ID may prompt)…");
    let identity = enclave::generate_identity(None);
    spinner.finish_and_clear();
    let identity = identity?;
    ui.success("Created a Secure Enclave-backed identity.");
    ui.info("The private key stays in the Secure Enclave and never leaves this device.");

    // Make it obvious a key was generated: show the public key, then pause so
    // the user can take it in before the bootstrap output scrolls on.
    ui.header("Your newly generated public key");
    ui.animated_line(&identity.public_key);
    ui.pause(Duration::from_secs(2));

    // Record who generated this key (default to the system user at the prompt).
    let username = resolve_username(ui, args)?;
    Ok(make_recipient(name, identity.public_key, username))
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

/// Best-effort current system username from `$USER` / `$LOGNAME`.
fn system_username() -> Option<String> {
    for var in ["USER", "LOGNAME"] {
        if let Ok(value) = std::env::var(var) {
            let value = value.trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
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
    ui.header("All set — your repository is ready");
    ui.success("sops configured (.sops.yaml)");
    ui.success("plaintext .env ignored by git");
    ui.success("secrets encrypted (.env.encrypted)");
    ui.success(format!(
        "recipient `{}` recorded in .sopsy.yml",
        recipient.name
    ));
    println!();
    ui.warn("> [!IMPORTANT] Break-glass: create a separate emergency age key pair and");
    ui.warn("> store it offline (e.g. in 1Password), shared with only a few admins, then");
    ui.warn("> register it via `sopsy recipient add break-glass --break-glass`. Without it,");
    ui.warn("> losing your Secure Enclave device means losing access to every secret.");
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
    #[serial]
    fn system_username_falls_back_to_none_when_unset() {
        // Snapshot and clear both vars, then restore them afterwards.
        let saved: Vec<(&str, Option<String>)> = ["USER", "LOGNAME"]
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect();
        // SAFETY: serialized via `#[serial]`.
        unsafe {
            std::env::remove_var("USER");
            std::env::remove_var("LOGNAME");
        }
        assert_eq!(system_username(), None);
        // An empty value is also treated as absent.
        // SAFETY: serialized via `#[serial]`.
        unsafe {
            std::env::set_var("USER", "   ");
        }
        assert_eq!(system_username(), None);
        // SAFETY: restore the original environment.
        unsafe {
            for (k, v) in saved {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
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
