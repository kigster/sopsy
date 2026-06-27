//! The colorful, playful presentation layer for `sopsy`.
//!
//! This module centralises *all* terminal output and interactive prompting so
//! that command implementations stay focused on logic. It provides:
//!
//! - A [`Ui`] handle carrying global presentation flags (color, verbosity,
//!   interactivity).
//! - Status symbols ([`Ui::success`], [`Ui::failure`], [`Ui::warn`], …) using
//!   `owo_colors`.
//! - Section headers and an [`Ui::animated_line`] helper that cycles colors for
//!   a touch of delight (non-blocking and test-friendly).
//! - A spinner/progress helper backed by `indicatif`.
//! - Thin wrappers over `inquire` ([`Ui::select`], [`Ui::multi_select`],
//!   [`Ui::confirm`], [`Ui::text`]) that return a clear [`Error::NonInteractive`]
//!   when called in `--non-interactive` mode instead of blocking forever.
//!
//! Color is suppressed when `--no-color` is passed, when the `NO_COLOR`
//! environment variable is set, or when stdout is not a TTY.

use std::io::{IsTerminal, Write};
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use inquire::{Confirm, MultiSelect, Select, Text};
use owo_colors::{OwoColorize, Style};

use crate::error::{Error, Result};

/// Presentation handle threaded through commands.
///
/// Construct via [`Ui::new`] (usually from parsed global CLI flags).
#[derive(Debug, Clone)]
pub struct Ui {
    /// Whether ANSI color is enabled.
    color: bool,
    /// Whether verbose/debug output is enabled.
    verbose: bool,
    /// Whether interactive prompting is allowed. When `false`, prompt helpers
    /// return [`Error::NonInteractive`] rather than blocking.
    interactive: bool,
}

impl Ui {
    /// Build a [`Ui`] from the resolved global flags.
    ///
    /// `color` and `interactive` reflect the user's requested preference; this
    /// constructor additionally downgrades them based on the runtime
    /// environment (TTY detection and the `NO_COLOR` convention).
    pub fn new(color: bool, verbose: bool, interactive: bool) -> Self {
        let stdout_tty = std::io::stdout().is_terminal();
        let no_color_env = std::env::var_os("NO_COLOR").is_some();
        Self {
            color: color && stdout_tty && !no_color_env,
            verbose,
            // Interactive prompting only makes sense on a real terminal.
            interactive: interactive && stdout_tty,
        }
    }

    /// Whether color output is currently enabled.
    pub fn color_enabled(&self) -> bool {
        self.color
    }

    /// Whether interactive prompting is currently allowed.
    pub fn is_interactive(&self) -> bool {
        self.interactive
    }

    /// Whether verbose output is enabled.
    pub fn is_verbose(&self) -> bool {
        self.verbose
    }

    /// Apply a style only when color is enabled, returning a plain string
    /// otherwise.
    fn paint(&self, text: &str, style: Style) -> String {
        if self.color {
            text.style(style).to_string()
        } else {
            text.to_string()
        }
    }

    /// Print a green `✔` success line.
    pub fn success(&self, msg: impl AsRef<str>) {
        println!(
            "{} {}",
            self.paint("✔", Style::new().green().bold()),
            msg.as_ref()
        );
    }

    /// Print a red `✗` failure line.
    pub fn failure(&self, msg: impl AsRef<str>) {
        println!(
            "{} {}",
            self.paint("✗", Style::new().red().bold()),
            msg.as_ref()
        );
    }

    /// Print a yellow `⚠` warning line.
    pub fn warn(&self, msg: impl AsRef<str>) {
        println!(
            "{} {}",
            self.paint("⚠", Style::new().yellow().bold()),
            msg.as_ref()
        );
    }

    /// Print a blue `ℹ` informational line.
    pub fn info(&self, msg: impl AsRef<str>) {
        println!(
            "{} {}",
            self.paint("ℹ", Style::new().blue().bold()),
            msg.as_ref()
        );
    }

    /// Print a dimmed line, only when verbose mode is enabled.
    pub fn debug(&self, msg: impl AsRef<str>) {
        if self.verbose {
            println!("{}", self.paint(msg.as_ref(), Style::new().dimmed()));
        }
    }

    /// Print a bold, underlined section header with surrounding spacing.
    pub fn header(&self, title: impl AsRef<str>) {
        println!();
        println!(
            "{}",
            self.paint(title.as_ref(), Style::new().bold().underline().cyan())
        );
    }

    /// Print a line whose characters cycle through a rainbow of colors.
    ///
    /// This is the "animated color line" the spec calls for, rendered as a
    /// single static (but multi-colored) line so it stays non-blocking and
    /// fully test-friendly. When color is disabled the text is printed plainly.
    pub fn animated_line(&self, text: impl AsRef<str>) {
        let text = text.as_ref();
        if !self.color {
            println!("{text}");
            return;
        }
        // A small palette cycled per-character for a playful gradient effect.
        let palette = [
            Style::new().red(),
            Style::new().yellow(),
            Style::new().green(),
            Style::new().cyan(),
            Style::new().blue(),
            Style::new().magenta(),
        ];
        let mut out = String::new();
        for (i, ch) in text.chars().enumerate() {
            let style = palette[i % palette.len()];
            out.push_str(&ch.to_string().style(style).to_string());
        }
        println!("{out}");
    }

    /// Create an `indicatif` spinner with a playful message.
    ///
    /// The returned [`ProgressBar`] should be finished by the caller (e.g. via
    /// [`ProgressBar::finish_and_clear`]). In non-interactive / no-color mode a
    /// hidden spinner is returned so output stays clean in CI logs.
    pub fn spinner(&self, message: impl Into<String>) -> ProgressBar {
        if !self.color {
            return ProgressBar::hidden();
        }
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner())
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✔"]),
        );
        pb.set_message(message.into());
        pb.enable_steady_tick(Duration::from_millis(80));
        pb
    }

    /// Flush stdout (useful before launching a child process that writes to the
    /// terminal, e.g. an editor).
    pub fn flush(&self) {
        let _ = std::io::stdout().flush();
    }

    // ----- Interactive prompt wrappers ------------------------------------

    /// Ask the user to pick one option from `options`.
    ///
    /// Returns [`Error::NonInteractive`] when prompting is disabled.
    pub fn select(&self, prompt: &str, flag: &str, options: Vec<String>) -> Result<String> {
        self.ensure_interactive(prompt, flag)?;
        // Irreducible interactive tail: requires a real TTY, so it stays thin and
        // untested while all guarding logic above is unit-tested.
        Select::new(prompt, options).prompt().map_err(into_other)
    }

    /// Ask the user to pick zero or more options from `options`.
    ///
    /// Returns [`Error::NonInteractive`] when prompting is disabled.
    pub fn multi_select(
        &self,
        prompt: &str,
        flag: &str,
        options: Vec<String>,
    ) -> Result<Vec<String>> {
        self.ensure_interactive(prompt, flag)?;
        MultiSelect::new(prompt, options)
            .prompt()
            .map_err(into_other)
    }

    /// Ask the user a yes/no question with a default.
    ///
    /// Returns [`Error::NonInteractive`] when prompting is disabled.
    pub fn confirm(&self, prompt: &str, flag: &str, default: bool) -> Result<bool> {
        self.ensure_interactive(prompt, flag)?;
        Confirm::new(prompt)
            .with_default(default)
            .prompt()
            .map_err(into_other)
    }

    /// Ask the user for a free-form text value.
    ///
    /// Returns [`Error::NonInteractive`] when prompting is disabled.
    pub fn text(&self, prompt: &str, flag: &str) -> Result<String> {
        self.ensure_interactive(prompt, flag)?;
        Text::new(prompt).prompt().map_err(into_other)
    }

    /// Guard that converts a disallowed prompt into a clear error.
    fn ensure_interactive(&self, prompt: &str, flag: &str) -> Result<()> {
        if self.interactive {
            Ok(())
        } else {
            Err(Error::NonInteractive {
                prompt: prompt.to_string(),
                flag: flag.to_string(),
            })
        }
    }
}

/// Convert an `inquire` (or any standard) error into our catch-all
/// [`Error::Other`] variant.
///
/// Extracted from the prompt wrappers so the error-mapping is a named, directly
/// testable function rather than an inline closure buried behind the
/// TTY-requiring `inquire` call.
fn into_other<E>(error: E) -> Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    Error::Other(error.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noninteractive_ui() -> Ui {
        Ui {
            color: false,
            verbose: false,
            interactive: false,
        }
    }

    #[test]
    fn prompts_error_in_non_interactive_mode() {
        let ui = noninteractive_ui();
        let err = ui
            .confirm("Proceed?", "--yes", true)
            .expect_err("should refuse to prompt");
        assert!(matches!(err, Error::NonInteractive { .. }));
    }

    #[test]
    fn animated_line_is_plain_without_color() {
        // Smoke test: must not panic and must handle empty input.
        let ui = noninteractive_ui();
        ui.animated_line("");
        ui.animated_line("hello sopsy");
    }

    #[test]
    fn hidden_spinner_when_no_color() {
        let ui = noninteractive_ui();
        let pb = ui.spinner("working");
        pb.finish_and_clear();
    }
}
