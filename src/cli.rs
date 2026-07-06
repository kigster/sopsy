//! Command-line interface definition (clap derive).
//!
//! Every interactive prompt in sopsy has an equivalent flag here so the tool is
//! fully scriptable. Global flags ([`GlobalArgs`]) control color, verbosity and
//! interactivity and are flattened into the top-level [`Cli`].
//!
//! Non-interactivity is auto-enabled when stdout is not a TTY; see
//! [`GlobalArgs::resolve_interactive`].

use std::io::IsTerminal;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::sops::FileType;

/// Top-level CLI parser.
#[derive(Debug, Parser)]
#[command(name = "sopsy")]
#[command(version)]
#[command(about = "The missing developer experience for SOPS")]
#[command(propagate_version = true)]
// Wrap help output at 100 columns (capped, so narrower terminals still wrap to
// their width). Set on the root command, this applies to every subcommand too.
#[command(max_term_width = 100)]
// The canonical shape shown at the top of `sopsy --help`; rendering (own line,
// bold yellow) is handled by `crate::help`.
#[command(override_usage = "sopsy [OPTIONS] command [COMMAND-OPTIONS]")]
pub struct Cli {
    /// Global flags shared by every subcommand.
    #[command(flatten)]
    pub global: GlobalArgs,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Flags available on every subcommand.
#[derive(Debug, Args, Clone)]
pub struct GlobalArgs {
    /// Disable all interactive prompts; fail instead of asking. Also enabled
    /// automatically when stdout is not a TTY. Aliased as `--yes`/`-y`.
    #[arg(long, short = 'y', visible_alias = "yes", global = true)]
    pub non_interactive: bool,

    /// Disable colored output (also honors the `NO_COLOR` environment variable).
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Increase output verbosity (show debug detail).
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,

    /// After a command changes files, `git add` exactly those files and print
    /// ready-to-paste commit and pull-request instructions. A no-op for commands
    /// that don't modify committed files.
    #[arg(long, global = true)]
    pub git: bool,
}

impl GlobalArgs {
    /// Resolve whether interactive prompting is allowed, accounting for the
    /// explicit flag and TTY detection.
    pub fn resolve_interactive(&self) -> bool {
        !self.non_interactive && std::io::stdout().is_terminal()
    }

    /// Resolve whether color should be used (subject to further `NO_COLOR`/TTY
    /// checks performed inside [`crate::ui::Ui::new`]).
    pub fn resolve_color(&self) -> bool {
        !self.no_color
    }
}

/// All sopsy subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Bootstrap an encrypted repository (tools, identity, `.sops.yaml`, …).
    Init(InitArgs),

    /// Run health checks on the local setup and repository.
    Doctor,

    /// Edit an encrypted file with your editor via `sops`.
    Edit(EditArgs),

    /// Request membership: generate an identity and record a pending entry.
    #[command(visible_alias = "request-access")]
    Join(JoinArgs),

    /// Approve a pending member: re-key secrets so they can decrypt.
    Approve(ApproveArgs),

    /// Manage repository recipients (add/remove/list).
    #[command(subcommand)]
    Recipient(RecipientCommand),

    /// Deprecated alias for the top-level `encrypt`/`decrypt` commands, kept
    /// (hidden) for backwards compatibility with scripts written before they
    /// existed. Prefer `sopsy encrypt` / `sopsy decrypt`.
    #[command(subcommand, hide = true)]
    Secrets(SecretsCommand),

    /// Encrypt a plaintext file to stdout (or a file).
    Encrypt(SecretsEncryptArgs),

    /// Decrypt an encrypted file to stdout (or a file).
    Decrypt(SecretsDecryptArgs),

    /// List the file types sopsy understands (for `--type`).
    #[command(name = "types", visible_alias = "list-supported-types")]
    ListSupportedTypes,

    /// CI gate: verify the repo's encrypted-secrets hygiene (exit 0/1).
    Check,

    /// Install sopsy's external tools (sops, age, age-plugin-se) via Homebrew.
    Deps(DepsArgs),

    /// Generate a shell completion script (bash, zsh, fish, …).
    Completion(CompletionArgs),
}

/// Arguments for `sopsy init`.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Name to record for the recipient created/registered during init.
    #[arg(long)]
    pub recipient_name: Option<String>,

    /// Username of who is generating the key (recorded in `.sopsy.yml`). When a
    /// new identity is generated interactively, this is the default offered at
    /// the prompt; falls back to the current system user.
    #[arg(long)]
    pub username: Option<String>,

    /// Use an existing age public key instead of generating a new identity.
    #[arg(long)]
    pub public_key: Option<String>,

    /// Skip Secure Enclave identity generation (e.g. when supplying a key).
    #[arg(long)]
    pub no_generate: bool,

    /// Generate a break-glass emergency key as part of init (the default in
    /// interactive mode is to prompt). Mutually exclusive with `--no-break-glass`.
    #[arg(long, conflicts_with = "no_break_glass")]
    pub break_glass: bool,

    /// Skip break-glass key generation during init.
    #[arg(long)]
    pub no_break_glass: bool,

    /// Proceed even if some doctor checks fail.
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `sopsy edit`.
#[derive(Debug, Args)]
pub struct EditArgs {
    /// The encrypted file to edit.
    pub file: PathBuf,

    /// Editor to use (overrides `$EDITOR`); falls back to a sensible default.
    #[arg(long)]
    pub editor: Option<String>,

    /// Extra arguments forwarded verbatim to `sops` after `--`.
    #[arg(last = true)]
    pub sops_args: Vec<String>,
}

/// Arguments for `sopsy join`.
#[derive(Debug, Args)]
pub struct JoinArgs {
    /// Your name as recorded in `.sopsy.yml` (full name or first name,
    /// e.g. `"Konstantin Gredeskoul"` or `annie`).
    pub name: String,

    /// System username recorded alongside the name (defaults to `$USER`).
    #[arg(long)]
    pub username: Option<String>,

    /// Path to the `.sopsy.yml` to update (defaults to the one in the repo root).
    #[arg(long)]
    pub sopsy_file: Option<PathBuf>,

    /// Use this existing age public key instead of generating a new identity.
    #[arg(long)]
    pub public_key: Option<String>,

    /// Generate the Secure Enclave identity without a Touch ID / passcode gate,
    /// by passing `--access-control none` to `age-plugin-se keygen`. The private
    /// key still never leaves the Enclave (and is device-bound), but unlocking it
    /// no longer prompts for a fingerprint or passcode — handy for scripted or
    /// headless setups. Ignored when `--public-key` is supplied.
    #[arg(short = 't', long = "without-touch-id")]
    pub without_touch_id: bool,

    /// Extra arguments forwarded verbatim to `age-plugin-se keygen` after `--`.
    #[arg(last = true)]
    pub age_args: Vec<String>,
}

/// Arguments for `sopsy approve`.
#[derive(Debug, Args)]
pub struct ApproveArgs {
    /// The pending member(s) to approve. Pass several to approve them together
    /// and re-key once: `sopsy approve annie colin`. With no names, walk every
    /// pending member interactively and approve the ones you confirm.
    #[arg(num_args = 0..)]
    pub names: Vec<String>,

    /// Approve even if a join request is older than the configured window.
    #[arg(long)]
    pub force: bool,

    /// Skip running `sops updatekeys` after editing `.sops.yaml`.
    #[arg(long)]
    pub no_updatekeys: bool,
}

/// `sopsy secrets` subcommands.
#[derive(Debug, Subcommand)]
pub enum SecretsCommand {
    /// Encrypt a plaintext file (`.env`/YAML/JSON) to stdout (or `-o <file>`).
    Encrypt(SecretsEncryptArgs),

    /// Decrypt an encrypted file to stdout (or `-o <file>`).
    Decrypt(SecretsDecryptArgs),
}

/// Arguments for `sopsy secrets encrypt`.
#[derive(Debug, Args)]
pub struct SecretsEncryptArgs {
    /// The plaintext file to encrypt (e.g. `.env`, `config.yaml`, `data.json`).
    pub file: PathBuf,

    /// Write the ciphertext to this file (must end in `.encrypted`) instead of
    /// stdout. The committed artifact, e.g. `-o .env.encrypted`.
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// Override the file type (inferred from `<file>`'s extension otherwise).
    #[arg(long = "type", value_enum)]
    pub file_type: Option<FileType>,
}

/// Arguments for `sopsy secrets decrypt`.
#[derive(Debug, Args)]
pub struct SecretsDecryptArgs {
    /// The encrypted file to decrypt.
    pub file: PathBuf,

    /// Write the plaintext here instead of stdout.
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// Override the detected file type (when the name has no usable extension).
    #[arg(long = "type", value_enum)]
    pub file_type: Option<FileType>,
}

/// Arguments for `sopsy deps`.
#[derive(Debug, Args)]
pub struct DepsArgs {
    /// Only report which dependencies are missing; do not install anything.
    /// Exits non-zero if any are missing (handy in CI / pre-flight checks).
    #[arg(long)]
    pub check: bool,

    /// Print the `brew install` command that would run, without executing it.
    #[arg(long)]
    pub dry_run: bool,
}

/// Arguments for `sopsy completion`.
#[derive(Debug, Args)]
pub struct CompletionArgs {
    /// The shell to generate a completion script for.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

/// `sopsy recipient` subcommands.
#[derive(Debug, Subcommand)]
pub enum RecipientCommand {
    /// Add a recipient and re-encrypt secrets (`sops updatekeys -r .`).
    Add(RecipientAddArgs),

    /// Remove a recipient and re-encrypt secrets.
    Remove(RecipientRemoveArgs),

    /// List configured recipients.
    List,

    /// Generate a new Secure Enclave identity and print its public key.
    Keygen(RecipientKeygenArgs),

    /// Generate a portable break-glass emergency key for offline storage.
    BreakGlass(RecipientBreakGlassArgs),

    /// Generate a portable CI decryption key and register it as a recipient
    /// (store the private half as a CI secret named `SOPS_AGE_KEY`).
    Ci(RecipientCiArgs),
}

/// Arguments for `sopsy recipient keygen`.
#[derive(Debug, Args)]
pub struct RecipientKeygenArgs {
    /// Extra arguments forwarded verbatim to `age-plugin-se keygen` after `--`
    /// (e.g. `--access-control=any-biometry-or-passcode`).
    #[arg(last = true)]
    pub age_args: Vec<String>,
}

/// Arguments for `sopsy recipient break-glass`.
#[derive(Debug, Args)]
pub struct RecipientBreakGlassArgs {
    /// Output path prefix; writes `<output>.private` and `<output>.public`.
    /// Both files are deleted from disk after you confirm they are stored safely.
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,

    /// Recipient name to record (defaults to `break-glass`).
    #[arg(long = "name")]
    pub name: Option<String>,

    /// Overwrite the `<output>.private` / `<output>.public` files if they exist.
    #[arg(long)]
    pub force: bool,

    /// Skip running `sops updatekeys` after editing `.sops.yaml`.
    #[arg(long)]
    pub no_updatekeys: bool,
}

/// Arguments for `sopsy recipient ci`.
#[derive(Debug, Args)]
pub struct RecipientCiArgs {
    /// Output path prefix; writes `<output>.private` and `<output>.public`.
    /// Both files are deleted from disk after you confirm the private key is
    /// stored in your CI provider's secret store.
    #[arg(short = 'o', long = "output", default_value = "ci")]
    pub output: PathBuf,

    /// Recipient name to record (defaults to `ci`).
    #[arg(long = "name")]
    pub name: Option<String>,

    /// Overwrite the `<output>.private` / `<output>.public` files if they exist.
    #[arg(long)]
    pub force: bool,

    /// Skip running `sops updatekeys` after editing `.sops.yaml`.
    #[arg(long)]
    pub no_updatekeys: bool,
}

/// Arguments for `sopsy recipient add`.
#[derive(Debug, Args)]
pub struct RecipientAddArgs {
    /// Positional recipient name (equivalent to `--name`).
    pub name_pos: Option<String>,

    /// Recipient name.
    #[arg(long = "name")]
    pub name: Option<String>,

    /// The recipient's age public key (`age1...`).
    #[arg(long)]
    pub public_key: Option<String>,

    /// Mark this recipient as the break-glass emergency key.
    #[arg(long)]
    pub break_glass: bool,

    /// Skip running `sops updatekeys` after editing `.sops.yaml`.
    #[arg(long)]
    pub no_updatekeys: bool,
}

impl RecipientAddArgs {
    /// The effective recipient name from either the positional or `--name`.
    pub fn resolved_name(&self) -> Option<&str> {
        self.name.as_deref().or(self.name_pos.as_deref())
    }
}

/// Arguments for `sopsy recipient remove`.
#[derive(Debug, Args)]
pub struct RecipientRemoveArgs {
    /// Positional recipient name (equivalent to `--name`).
    pub name_pos: Option<String>,

    /// Recipient name to remove.
    #[arg(long = "name")]
    pub name: Option<String>,

    /// Skip running `sops updatekeys` after editing `.sops.yaml`.
    #[arg(long)]
    pub no_updatekeys: bool,
}

impl RecipientRemoveArgs {
    /// The effective recipient name from either the positional or `--name`.
    pub fn resolved_name(&self) -> Option<&str> {
        self.name.as_deref().or(self.name_pos.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        // clap's debug assertions catch malformed derive definitions.
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_recipient_add_with_flags() {
        let cli = Cli::try_parse_from([
            "sopsy",
            "--non-interactive",
            "recipient",
            "add",
            "--name",
            "alice",
            "--public-key",
            "age1alice",
        ])
        .unwrap();
        assert!(cli.global.non_interactive);
        match cli.command {
            Command::Recipient(RecipientCommand::Add(args)) => {
                assert_eq!(args.resolved_name(), Some("alice"));
                assert_eq!(args.public_key.as_deref(), Some("age1alice"));
            }
            _ => panic!("expected recipient add"),
        }
    }

    #[test]
    fn yes_alias_enables_non_interactive() {
        let cli = Cli::try_parse_from(["sopsy", "-y", "doctor"]).unwrap();
        assert!(cli.global.non_interactive);
    }

    #[test]
    fn request_access_is_an_alias_for_join() {
        let cli = Cli::try_parse_from(["sopsy", "request-access", "annie"]).unwrap();
        assert!(matches!(cli.command, Command::Join(args) if args.name == "annie"));
    }

    #[test]
    fn join_accepts_username_flag() {
        let cli = Cli::try_parse_from([
            "sopsy",
            "join",
            "Konstantin Gredeskoul",
            "--username",
            "kig",
        ])
        .unwrap();
        match cli.command {
            Command::Join(args) => {
                assert_eq!(args.name, "Konstantin Gredeskoul");
                assert_eq!(args.username.as_deref(), Some("kig"));
            }
            _ => panic!("expected join"),
        }
    }

    #[test]
    fn join_without_touch_id_flag_parses() {
        // Long and short forms both set the flag; it defaults to false.
        for argv in [
            vec!["sopsy", "join", "annie", "--without-touch-id"],
            vec!["sopsy", "join", "annie", "-t"],
        ] {
            let cli = Cli::try_parse_from(argv).unwrap();
            assert!(matches!(cli.command, Command::Join(a) if a.without_touch_id));
        }
        let cli = Cli::try_parse_from(["sopsy", "join", "annie"]).unwrap();
        assert!(matches!(cli.command, Command::Join(a) if !a.without_touch_id));
    }

    #[test]
    fn hidden_secrets_alias_still_parses() {
        // `secrets encrypt`/`secrets decrypt` remain functional (hidden from
        // help) so pre-existing scripts keep working after the top-level verbs.
        let cli = Cli::try_parse_from(["sopsy", "secrets", "decrypt", ".env.encrypted"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Secrets(SecretsCommand::Decrypt(a)) if a.file == *std::path::Path::new(".env.encrypted")
        ));
        let cli = Cli::try_parse_from(["sopsy", "secrets", "encrypt", ".env"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Secrets(SecretsCommand::Encrypt(_))
        ));
    }

    #[test]
    fn top_level_encrypt_decrypt_are_shorthands() {
        let cli = Cli::try_parse_from(["sopsy", "decrypt", ".env.encrypted"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Decrypt(a) if a.file == *std::path::Path::new(".env.encrypted")
        ));

        let cli =
            Cli::try_parse_from(["sopsy", "encrypt", ".env", "-o", ".env.encrypted"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Encrypt(a) if a.output == Some(PathBuf::from(".env.encrypted"))
        ));
    }

    #[test]
    fn approve_accepts_multiple_names() {
        let cli = Cli::try_parse_from(["sopsy", "approve", "annie", "colin"]).unwrap();
        assert!(matches!(cli.command, Command::Approve(args) if args.names == ["annie", "colin"]));
    }

    #[test]
    fn approve_accepts_no_names_for_interactive_mode() {
        let cli = Cli::try_parse_from(["sopsy", "approve"]).unwrap();
        assert!(matches!(cli.command, Command::Approve(args) if args.names.is_empty()));
    }

    #[test]
    fn approve_keeps_multiword_names_intact() {
        // The shell delivers each quoted name as one argv element, so spaces in a
        // name must survive as a single positional, not split into extra names.
        let cli =
            Cli::try_parse_from(["sopsy", "approve", "Konstantin Gredeskoul", "Colin Powell"])
                .unwrap();
        assert!(matches!(
            cli.command,
            Command::Approve(args) if args.names == ["Konstantin Gredeskoul", "Colin Powell"]
        ));
    }
}
