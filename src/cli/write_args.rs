//! `-w`/`--write` and `-O`/`--overwrite`, shared by `encrypt` and `decrypt`.
//!
//! Flattened into [`super::SecretsEncryptArgs`] and
//! [`super::SecretsDecryptArgs`], so `sopsy encrypt|decrypt` and the hidden
//! `sopsy secrets encrypt|decrypt` aliases accept the same flags.

use clap::Args;

/// The clap id of the group holding `--write` and `--output`; `--overwrite`
/// requires one of them, since stdout has nothing to overwrite.
pub const DESTINATION_GROUP: &str = "destination";

/// Where to write by naming convention, and what to do when the target exists.
#[derive(Debug, Args, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriteArgs {
    /// Write next to the input by convention: `encrypt FILE` writes
    /// `FILE.encrypted`, `decrypt FILE.encrypted` writes `FILE`.
    #[arg(short = 'w', long = "write", conflicts_with = "output")]
    pub write: bool,

    /// Replace an existing target without asking. Decrypt first backs the
    /// old plaintext up as `FILE.YYYY-MM-DD.HHMMSS.bak`.
    #[arg(short = 'O', long = "overwrite", requires = DESTINATION_GROUP)]
    pub overwrite: bool,
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use clap::error::ErrorKind;

    use crate::cli::{Cli, Command, SecretsCommand};

    fn parse(argv: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(argv)
    }

    #[test]
    fn write_and_overwrite_parse_on_both_directions() {
        let cli = parse(&["sopsy", "encrypt", ".env", "-w", "-O"]).unwrap();
        let Command::Encrypt(args) = cli.command else {
            panic!("expected encrypt")
        };
        assert!(args.write.write && args.write.overwrite);

        let cli = parse(&["sopsy", "decrypt", ".env.encrypted", "--write"]).unwrap();
        let Command::Decrypt(args) = cli.command else {
            panic!("expected decrypt")
        };
        assert!(args.write.write && !args.write.overwrite);
    }

    #[test]
    fn secrets_aliases_accept_the_same_flags() {
        let cli = parse(&[
            "sopsy",
            "secrets",
            "decrypt",
            "x.encrypted",
            "-w",
            "--overwrite",
        ])
        .unwrap();
        let Command::Secrets(SecretsCommand::Decrypt(args)) = cli.command else {
            panic!("expected secrets decrypt")
        };
        assert!(args.write.write && args.write.overwrite);
    }

    #[test]
    fn write_conflicts_with_output() {
        for cmd in ["encrypt", "decrypt"] {
            let err = parse(&["sopsy", cmd, "f", "-w", "-o", "x.encrypted"]).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::ArgumentConflict, "{cmd}");
        }
    }

    #[test]
    fn overwrite_needs_a_file_destination() {
        for cmd in ["encrypt", "decrypt"] {
            let err = parse(&["sopsy", cmd, "f", "-O"]).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument, "{cmd}");
        }
    }

    #[test]
    fn overwrite_is_accepted_with_output() {
        let cli = parse(&["sopsy", "encrypt", ".env", "-o", ".env.encrypted", "-O"]).unwrap();
        let Command::Encrypt(args) = cli.command else {
            panic!("expected encrypt")
        };
        assert!(args.write.overwrite && !args.write.write);
    }
}
