//! `sopsy completion` — generate a shell completion script.
//!
//! Completions are derived directly from the clap [`Cli`](crate::cli::Cli)
//! definition via [`clap_complete`], so they always stay in sync with the real
//! commands and flags. The script is written to **stdout** only (no decoration),
//! so it can be redirected to a file or sourced directly, e.g.:
//!
//! ```text
//! # zsh
//! sopsy completion zsh > "${fpath[1]}/_sopsy"
//! # bash
//! sopsy completion bash > /usr/local/etc/bash_completion.d/sopsy
//! # or, ephemerally, in your shell rc:
//! eval "$(sopsy completion zsh)"
//! ```

use std::io;

use clap::CommandFactory;

use crate::cli::{Cli, CompletionArgs};
use crate::error::Result;

/// Write the completion script for the requested shell to stdout.
///
/// Takes no [`Ui`](crate::ui::Ui): the output is a machine-consumed script, so
/// nothing else may be printed to stdout.
pub fn run(args: &CompletionArgs) -> Result<()> {
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_string();
    clap_complete::generate(args.shell, &mut cmd, bin_name, &mut io::stdout());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap_complete::Shell;

    /// Generating a script for every supported shell succeeds and the CLI
    /// definition is valid for completion generation.
    #[test]
    fn generates_for_each_shell() {
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Elvish,
        ] {
            run(&CompletionArgs { shell }).expect("completion generation should succeed");
        }
    }
}
