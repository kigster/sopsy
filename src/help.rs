//! Post-processing colorizer for clap's help screens.
//!
//! clap styles subcommand names and option flags with a single shared
//! "literal" style, so it cannot render commands and options in different
//! colors. sopsy therefore lets clap produce *plain* help text
//! ([`clap::Error`] renders unstyled via `Display`) and repaints it here:
//!
//! - section headings (`Usage:`, `Commands:`, `Options:`, `Arguments:`) become
//!   ALL CAPS in bold green;
//! - the usage line moves onto its own line, indented two spaces to match the
//!   other entries, in bold bright yellow;
//! - command names render in bold blue;
//! - option flags and argument placeholders render in bold magenta.
//!
//! Headings are re-cased even when color is disabled; ANSI codes are only
//! emitted when `color` is `true` (see [`color_wanted`]).

use std::io::IsTerminal;

use owo_colors::{OwoColorize, Style};

/// Which help section the line walker is currently inside.
#[derive(PartialEq)]
enum Section {
    None,
    Usage,
    Commands,
    Options,
    Arguments,
}

/// Whether help output should be colorized: stdout must be a terminal, the
/// `NO_COLOR` convention must be unset, and `--no-color` must not appear in
/// argv (help renders during parsing, before the flag is formally parsed).
pub fn color_wanted() -> bool {
    std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && !std::env::args().any(|arg| arg == "--no-color")
}

/// Re-case and colorize a plain clap help screen (see the module docs).
pub fn render(help: &str, color: bool) -> String {
    let heading = Style::new().green().bold();
    let usage = Style::new().bright_yellow().bold();
    let command = Style::new().blue().bold();
    let option = Style::new().magenta().bold();

    let mut out = String::new();
    let mut section = Section::None;
    for line in help.lines() {
        // Heading lines sit at column zero; everything else is indented.
        if let Some(rest) = line.strip_prefix("Usage:") {
            section = Section::Usage;
            out.push_str(&paint("USAGE:", heading, color));
            out.push('\n');
            let body = rest.trim();
            if !body.is_empty() {
                out.push_str("  ");
                out.push_str(&paint(body, usage, color));
            }
        } else if line == "Commands:" {
            section = Section::Commands;
            out.push_str(&paint("COMMANDS:", heading, color));
        } else if line == "Options:" {
            section = Section::Options;
            out.push_str(&paint("OPTIONS:", heading, color));
        } else if line == "Arguments:" {
            section = Section::Arguments;
            out.push_str(&paint("ARGUMENTS:", heading, color));
        } else if line.trim().is_empty() {
            // A blank line ends the (indentation-driven) usage block.
            if section == Section::Usage {
                section = Section::None;
            }
            out.push_str(line);
        } else {
            out.push_str(&paint_entry(line, &section, usage, command, option, color));
        }
        out.push('\n');
    }
    out
}

/// Colorize one indented line according to the section it belongs to.
fn paint_entry(
    line: &str,
    section: &Section,
    usage: Style,
    command: Style,
    option: Style,
    color: bool,
) -> String {
    let indent_len = line.len() - line.trim_start().len();
    let (indent, body) = line.split_at(indent_len);
    match section {
        // Multi-line usage continuations stay yellow.
        Section::Usage => format!("{indent}{}", paint(body, usage, color)),
        // "  join        Request membership ..." — the first token is the
        // command name; deeper-indented continuation lines are description
        // wrap and stay plain.
        Section::Commands if indent_len == 2 => match body.split_once(' ') {
            Some((name, rest)) => format!("{indent}{} {rest}", paint(name, command, color)),
            None => format!("{indent}{}", paint(body, command, color)),
        },
        // "  -y, --non-interactive  Disable ..." / "  <FILE>  The file ..." —
        // the flag cluster (or placeholder) runs until the two-space gap
        // before the description. Wrapped descriptions are indented deeper
        // and stay plain.
        Section::Options | Section::Arguments
            if indent_len <= 6 && body.starts_with(['-', '<', '[']) =>
        {
            match body.split_once("  ") {
                Some((flags, rest)) => {
                    format!("{indent}{}  {rest}", paint(flags, option, color))
                }
                None => format!("{indent}{}", paint(body, option, color)),
            }
        }
        _ => line.to_string(),
    }
}

/// Apply `style` to `text` when color is enabled; pass it through otherwise.
fn paint(text: &str, style: Style, color: bool) -> String {
    if color {
        text.style(style).to_string()
    } else {
        text.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A miniature clap help screen with every section the walker handles.
    /// A verbatim (non-escaped) literal: the leading two-space indents are
    /// load-bearing, and `\n\` continuations would swallow them.
    const SAMPLE: &str = "The missing developer experience for SOPS

Usage: sopsy [OPTIONS] <COMMAND> [COMMAND-OPTIONS]

Commands:
  init        Bootstrap an encrypted repository
  join        Request membership [aliases:
              request-access]

Arguments:
  <FILE>          The encrypted file to edit
  [SOPS_ARGS]...  Extra arguments forwarded to `sops`

Options:
  -y, --non-interactive  Disable all interactive prompts; fail instead of asking. Also
                         enabled automatically when stdout is not a TTY
      --no-color         Disable colored output
";

    #[test]
    fn headings_are_recased_even_without_color() {
        let plain = render(SAMPLE, false);
        assert!(plain.contains("USAGE:\n  sopsy [OPTIONS] <COMMAND> [COMMAND-OPTIONS]"));
        assert!(plain.contains("COMMANDS:"));
        assert!(plain.contains("OPTIONS:"));
        assert!(plain.contains("ARGUMENTS:"));
        // No ANSI escapes leak into plain mode.
        assert!(!plain.contains('\u{1b}'));
        // Body text is untouched.
        assert!(plain.contains("  init        Bootstrap an encrypted repository"));
    }

    #[test]
    fn usage_body_moves_to_its_own_line() {
        let plain = render(SAMPLE, false);
        assert!(
            plain
                .lines()
                .any(|l| l == "  sopsy [OPTIONS] <COMMAND> [COMMAND-OPTIONS]"),
            "usage body should sit alone on a two-space-indented line:\n{plain}"
        );
    }

    #[test]
    fn colored_render_paints_each_section_kind() {
        let colored = render(SAMPLE, true);
        // Every painted region carries ANSI escapes...
        for painted in ["USAGE:", "COMMANDS:", "OPTIONS:", "ARGUMENTS:"] {
            let line = colored
                .lines()
                .find(|l| l.contains(painted))
                .unwrap_or_else(|| panic!("missing {painted}"));
            assert!(line.contains('\u{1b}'), "{painted} should be styled");
        }
        // ...as do command names, flags, and placeholders.
        for (needle, label) in [
            ("init", "command name"),
            ("-y, --non-interactive", "flag cluster"),
            ("--no-color", "long-only flag"),
            ("<FILE>", "argument placeholder"),
        ] {
            let line = colored
                .lines()
                .find(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("missing {needle}"));
            assert!(
                line.contains('\u{1b}'),
                "{label} `{needle}` should be styled"
            );
        }
        // Wrapped continuation lines stay plain (both command and option wraps).
        for continuation in ["request-access]", "enabled automatically"] {
            let line = colored
                .lines()
                .find(|l| l.contains(continuation))
                .unwrap_or_else(|| panic!("missing {continuation}"));
            assert!(
                !line.contains('\u{1b}'),
                "continuation `{continuation}` must stay plain: {line}"
            );
        }
    }

    #[test]
    fn commands_are_blue_options_are_magenta() {
        let colored = render(SAMPLE, true);
        let init = colored.lines().find(|l| l.contains("init")).unwrap();
        let no_color = colored.lines().find(|l| l.contains("--no-color")).unwrap();
        // owo_colors encodes blue as SGR 34 and magenta as SGR 35.
        assert!(init.contains("34m") || init.contains("34;"), "{init}");
        assert!(
            no_color.contains("35m") || no_color.contains("35;"),
            "{no_color}"
        );
    }

    #[test]
    fn description_text_after_the_flag_gap_stays_plain() {
        let colored = render(SAMPLE, true);
        let line = colored
            .lines()
            .find(|l| l.contains("Disable colored output"))
            .unwrap();
        // The style reset must occur before the description begins.
        let reset = line.find("\u{1b}[0m").expect("styled flag should reset");
        let desc = line.find("Disable colored output").unwrap();
        assert!(
            reset < desc,
            "description should not inherit the flag style: {line}"
        );
    }
}
