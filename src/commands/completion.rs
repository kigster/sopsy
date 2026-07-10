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
//!
//! One wrinkle: clap_complete's static generators ignore `hide = true` and
//! would advertise deprecated commands (e.g. `secrets`) in the completion
//! menu. [`strip_hidden_menu_entries`] removes just the *menu* entries for
//! hidden subcommands while keeping their handler arms, so `sopsy <TAB>` does
//! not offer them but `sopsy secrets <TAB>` still completes for old scripts.

use std::io::{self, Write};

use clap::CommandFactory;
use clap_complete::Shell;

use crate::cli::{Cli, CompletionArgs};
use crate::error::Result;

/// Write the completion script for the requested shell to stdout.
///
/// Takes no [`Ui`](crate::ui::Ui): the output is a machine-consumed script, so
/// nothing else may be printed to stdout.
pub fn run(args: &CompletionArgs) -> Result<()> {
    io::stdout().write_all(generate_script(args.shell).as_bytes())?;
    Ok(())
}

/// Generate the completion script for `shell`, with hidden subcommands
/// removed from the completion menus.
fn generate_script(shell: Shell) -> String {
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_string();
    let hidden: Vec<String> = cmd
        .get_subcommands()
        .filter(|sc| sc.is_hide_set())
        .map(|sc| sc.get_name().to_string())
        .collect();

    let mut buf = Vec::new();
    clap_complete::generate(shell, &mut cmd, bin_name, &mut buf);
    let script = String::from_utf8(buf).expect("completion scripts are UTF-8");
    strip_hidden_menu_entries(&script, &hidden, shell)
}

/// Remove the completion-*menu* entries for `hidden` subcommands from a
/// generated `script`, per shell dialect.
///
/// Only the lines that offer a hidden command as a candidate are dropped
/// (zsh `'name:desc'` items, fish `-a "name"` registrations, PowerShell
/// `CompletionResult` entries, elvish `cand` lines, and the word inside
/// bash `opts=` lists). The case arms and helper functions that complete a
/// hidden command's own arguments are intentionally kept: typing the
/// deprecated name still completes its subcommands and flags.
fn strip_hidden_menu_entries(script: &str, hidden: &[String], shell: Shell) -> String {
    if hidden.is_empty() {
        return script.to_string();
    }

    let mut out: Vec<String> = Vec::with_capacity(script.lines().count());
    'lines: for line in script.lines() {
        for name in hidden {
            let is_menu_entry = match shell {
                Shell::Zsh => line.trim_start().starts_with(&format!("'{name}:")),
                Shell::Fish => line.contains(&format!("-a \"{name}\"")),
                Shell::PowerShell => line.contains(&format!("[CompletionResult]::new('{name}'")),
                Shell::Elvish => line.trim_start().starts_with(&format!("cand {name} ")),
                // Bash keeps the line but loses the word (handled below);
                // future shells fall through unfiltered.
                _ => false,
            };
            if is_menu_entry {
                continue 'lines;
            }
        }

        let mut kept = line.to_string();
        if shell == Shell::Bash && kept.trim_start().starts_with("opts=") {
            for name in hidden {
                kept = kept
                    .replace(&format!(" {name} "), " ")
                    .replace(&format!("\"{name} "), "\"")
                    .replace(&format!(" {name}\""), "\"");
            }
        }
        out.push(kept);
    }

    let mut result = out.join("\n");
    result.push('\n');
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_SHELLS: [Shell; 5] = [
        Shell::Bash,
        Shell::Zsh,
        Shell::Fish,
        Shell::PowerShell,
        Shell::Elvish,
    ];

    /// Generating a script for every supported shell succeeds and the CLI
    /// definition is valid for completion generation.
    #[test]
    fn generates_for_each_shell() {
        for shell in ALL_SHELLS {
            run(&CompletionArgs { shell }).expect("completion generation should succeed");
        }
    }

    /// Every shell's script offers the current commands. The deprecated
    /// `list-supported-types` spelling is a *hidden* alias: it must not be
    /// offered anywhere (clap_complete only emits visible aliases).
    #[test]
    fn scripts_offer_current_commands() {
        for shell in ALL_SHELLS {
            let script = generate_script(shell);
            for name in ["encrypt", "decrypt", "types"] {
                assert!(
                    script.contains(name),
                    "{shell:?} script should offer `{name}`"
                );
            }
            assert!(
                !script.contains("list-supported-types"),
                "{shell:?} script should not offer the hidden alias"
            );
        }
    }

    /// The hidden, deprecated `secrets` command must not be *advertised* in
    /// any shell's completion menu.
    #[test]
    fn hidden_secrets_is_not_advertised() {
        for (shell, menu_marker) in [
            (Shell::Zsh, "'secrets:"),
            (Shell::Fish, "-a \"secrets\""),
            (Shell::PowerShell, "[CompletionResult]::new('secrets'"),
            (Shell::Elvish, "cand secrets "),
        ] {
            let script = generate_script(shell);
            assert!(
                !script.contains(menu_marker),
                "{shell:?} script should not advertise `secrets`"
            );
        }

        // Bash lists commands in `opts=` words: no standalone `secrets` word
        // may remain on those lines.
        let bash = generate_script(Shell::Bash);
        for line in bash.lines().filter(|l| l.trim_start().starts_with("opts=")) {
            assert!(
                !line.split(['"', ' ']).any(|word| word == "secrets"),
                "bash opts should not list `secrets`: {line}"
            );
        }
    }

    /// Back-compat: the handler arm for `sopsy secrets <TAB>` stays in the
    /// zsh script so the deprecated spelling still completes its
    /// subcommands, it just isn't offered at the top level.
    #[test]
    fn hidden_secrets_arm_is_kept_for_back_compat() {
        let zsh = generate_script(Shell::Zsh);
        assert!(zsh.contains("(secrets)"));
        assert!(zsh.contains("_sopsy__secrets_commands") || zsh.contains("secrets_commands"));
    }
}
