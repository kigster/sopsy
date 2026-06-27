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

use crate::cli::InitArgs;
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

    // 10. Final, colorful health summary.
    print_summary(ui, &recipient);
    Ok(())
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
        return Ok(Recipient::new(name, public_key));
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
            let public_key = ui.text("Paste your age public key (age1...)", "--public-key")?;
            return Ok(Recipient::new(name, public_key));
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
    Ok(Recipient::new(name, identity.public_key))
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
