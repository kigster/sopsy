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
    /// Whether the user asked sopsy to stage its changes with `git add` and print
    /// commit/PR instructions (the global `--git` flag). Carried here because it
    /// is a resolved global flag like the others; consumed by
    /// [`crate::git::stage_and_advise`].
    git: bool,
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
        Self::resolve(color, verbose, interactive, stdout_tty, no_color_env)
    }

    /// Apply the runtime downgrade rules. Factored out of [`Ui::new`] so the
    /// logic can be tested deterministically with explicit `stdout_tty` /
    /// `no_color_env` values, rather than depending on whether the test
    /// process's own stdout happens to be a terminal.
    fn resolve(
        color: bool,
        verbose: bool,
        interactive: bool,
        stdout_tty: bool,
        no_color_env: bool,
    ) -> Self {
        Self {
            color: color && stdout_tty && !no_color_env,
            verbose,
            // Interactive prompting only makes sense on a real terminal.
            interactive: interactive && stdout_tty,
            // Enabled explicitly via `with_git`; off by default so every test and
            // nested call starts without staging behavior.
            git: false,
        }
    }

    /// Enable the `--git` staging behavior on this handle. Consuming builder,
    /// used once in [`crate::run`] from the parsed global flag.
    pub fn with_git(mut self, git: bool) -> Self {
        self.git = git;
        self
    }

    /// A clone of this handle with `--git` disabled, for nested command calls
    /// that must not emit their own staging advice — e.g. `sopsy init` invoking
    /// the break-glass ceremony, since `init` stages the whole file set once at
    /// the end.
    pub fn without_git(&self) -> Self {
        Self {
            git: false,
            ..self.clone()
        }
    }

    /// Whether the user requested `git add` + commit/PR advice (`--git`).
    pub fn stage_requested(&self) -> bool {
        self.git
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

    /// Print a copy-pasteable shell command, indented and highlighted.
    ///
    /// Unlike [`Ui::info`] it carries no leading status glyph, so the line can be
    /// selected and run as-is. Used to present the `git`/`gh` commands the
    /// `--git` flow suggests.
    pub fn command(&self, cmd: impl AsRef<str>) {
        println!("  {}", self.paint(cmd.as_ref(), Style::new().bold().cyan()));
    }

    // ----- Full-width banner boxes -----------------------------------------

    /// Print a green full-width success banner (major happy endings: `init`
    /// finished, members approved, all checks passed).
    pub fn banner_success(&self, msg: impl AsRef<str>) {
        self.banner("✔", msg.as_ref(), Style::new().black().on_green().bold());
    }

    /// Print a blue full-width informational banner.
    pub fn banner_info(&self, msg: impl AsRef<str>) {
        self.banner("ℹ", msg.as_ref(), Style::new().white().on_blue().bold());
    }

    /// Print a yellow full-width warning banner (action required, but nothing
    /// is broken).
    pub fn banner_warn(&self, msg: impl AsRef<str>) {
        self.banner("⚠", msg.as_ref(), Style::new().black().on_yellow().bold());
    }

    /// Print a red full-width alert banner (something failed or is unsafe).
    pub fn banner_alert(&self, msg: impl AsRef<str>) {
        self.banner("✗", msg.as_ref(), Style::new().white().on_red().bold());
    }

    /// Render a screen-wide banner box: with color, padded lines on a solid
    /// background; without color (pipes, CI, `NO_COLOR`), a plain bordered box
    /// so the emphasis still survives in logs. The message is word-wrapped to
    /// the terminal width.
    fn banner(&self, glyph: &str, msg: &str, style: Style) {
        let width = term_width().max(20);
        let lines = wrap_text(msg, width - 6);
        println!();
        if self.color {
            let pad = " ".repeat(width);
            println!("{}", self.paint(&pad, style));
            for (i, line) in lines.iter().enumerate() {
                let lead = if i == 0 {
                    format!("  {glyph} ")
                } else {
                    "    ".into()
                };
                let used = lead.chars().count() + line.chars().count();
                let text = format!("{lead}{line}{}", " ".repeat(width.saturating_sub(used)));
                println!("{}", self.paint(&text, style));
            }
            println!("{}", self.paint(&pad, style));
        } else {
            println!("┌{}┐", "─".repeat(width - 2));
            for (i, line) in lines.iter().enumerate() {
                let lead = if i == 0 {
                    format!("{glyph} ")
                } else {
                    "  ".into()
                };
                let used = 4 + lead.chars().count() + line.chars().count();
                println!("│ {lead}{line}{} │", " ".repeat(width.saturating_sub(used)));
            }
            println!("└{}┘", "─".repeat(width - 2));
        }
        println!();
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

    /// Pause for `duration` so the user can read what was just printed.
    ///
    /// Only sleeps in interactive mode; in non-interactive runs (CI, pipes) the
    /// pause is skipped so scripts never block on a cosmetic delay.
    pub fn pause(&self, duration: Duration) {
        if self.interactive {
            std::thread::sleep(duration);
        }
    }

    /// Wait for the user to press ENTER, displaying `prompt` first.
    ///
    /// Returns [`Error::NonInteractive`] when prompting is disabled: this is a
    /// blocking confirmation that cannot be satisfied without a terminal.
    pub fn press_enter(&self, prompt: &str) -> Result<()> {
        if !self.interactive {
            return Err(Error::NonInteractive {
                prompt: prompt.to_string(),
                flag: "an interactive terminal (this step cannot be scripted)".to_string(),
            });
        }
        println!();
        print!("{} ", self.paint(prompt, Style::new().bold().cyan()));
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(())
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

    /// Ask the user for a free-form text value, offering `default` when they
    /// press ENTER without typing anything.
    ///
    /// Returns [`Error::NonInteractive`] when prompting is disabled.
    pub fn text_with_default(&self, prompt: &str, flag: &str, default: &str) -> Result<String> {
        self.ensure_interactive(prompt, flag)?;
        Text::new(prompt)
            .with_default(default)
            .prompt()
            .map_err(into_other)
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

/// The terminal width in columns, falling back to 80 when stdout is not a
/// terminal (pipes, CI logs) so banners stay a sane width in captured output.
fn term_width() -> usize {
    terminal_size::terminal_size()
        .map(|(w, _)| w.0 as usize)
        .unwrap_or(80)
}

/// Word-wrap `text` to at most `max` characters per line, preserving explicit
/// newlines and hard-splitting words longer than a whole line.
fn wrap_text(text: &str, max: usize) -> Vec<String> {
    let max = max.max(1);
    let mut lines = Vec::new();
    for raw in text.lines() {
        let mut current = String::new();
        let mut count = 0usize;
        for word in raw.split_whitespace() {
            // Hard-split words that cannot fit on any line by themselves.
            let chars: Vec<char> = word.chars().collect();
            for piece in chars.chunks(max) {
                let piece: String = piece.iter().collect();
                let sep = usize::from(count > 0);
                if count + sep + piece.chars().count() > max {
                    lines.push(std::mem::take(&mut current));
                    count = 0;
                }
                if count > 0 {
                    current.push(' ');
                    count += 1;
                }
                count += piece.chars().count();
                current.push_str(&piece);
            }
        }
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
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

    /// A `Ui` with everything off (the typical CI / `--non-interactive` shape).
    fn noninteractive_ui() -> Ui {
        Ui {
            color: false,
            verbose: false,
            interactive: false,
            git: false,
        }
    }

    /// A `Ui` with color, verbosity, and interactivity all forced on.
    ///
    /// Constructed directly (bypassing [`Ui::new`], which downgrades these based
    /// on TTY detection) so the color-on rendering paths are exercised even when
    /// tests run with stdout redirected to a pipe.
    fn color_ui() -> Ui {
        Ui {
            color: true,
            verbose: true,
            interactive: true,
            git: false,
        }
    }

    #[test]
    fn resolve_applies_tty_and_no_color_downgrades() {
        // No TTY: color and interactivity are disabled regardless of request,
        // but verbosity (terminal-independent) is preserved.
        let ui = Ui::resolve(true, true, true, false, false);
        assert!(!ui.color_enabled());
        assert!(!ui.is_interactive());
        assert!(ui.is_verbose());

        // TTY, no NO_COLOR: both honored.
        let ui = Ui::resolve(true, false, true, true, false);
        assert!(ui.color_enabled());
        assert!(ui.is_interactive());

        // NO_COLOR disables color even on a TTY; interactivity is unaffected.
        let ui = Ui::resolve(true, false, true, true, true);
        assert!(!ui.color_enabled());
        assert!(ui.is_interactive());

        // The caller opting out is always honored.
        let ui = Ui::resolve(false, false, false, true, false);
        assert!(!ui.color_enabled());
        assert!(!ui.is_interactive());
    }

    #[test]
    fn new_constructs_from_ambient_environment() {
        // Exercises `Ui::new`'s real TTY/NO_COLOR detection. The resolved color
        // and interactivity depend on the environment, so we only assert it
        // builds and preserves the terminal-independent verbosity flag.
        assert!(Ui::new(true, true, true).is_verbose());
        assert!(!Ui::new(true, false, true).is_verbose());
    }

    #[test]
    fn accessors_reflect_constructed_flags() {
        let ui = color_ui();
        assert!(ui.color_enabled());
        assert!(ui.is_verbose());
        assert!(ui.is_interactive());
    }

    #[test]
    fn git_flag_is_off_by_default_and_toggled_by_builder() {
        // Fresh handles never stage; `with_git` opts in; `without_git` opts a
        // clone back out (the nested-call path) while preserving other flags.
        assert!(!color_ui().stage_requested());
        let staging = color_ui().with_git(true);
        assert!(staging.stage_requested());
        let nested = staging.without_git();
        assert!(!nested.stage_requested());
        assert!(nested.color_enabled());
        assert!(nested.is_interactive());
    }

    #[test]
    fn command_prints_without_a_status_glyph() {
        // Smoke test for the copy-pasteable command line in both color modes.
        noninteractive_ui().command("git commit -m \"x\"");
        color_ui().command("git push -u origin HEAD");
    }

    #[test]
    fn all_prompts_error_in_non_interactive_mode() {
        let ui = noninteractive_ui();
        assert!(matches!(
            ui.select("Pick one", "--choice", vec!["a".into(), "b".into()])
                .expect_err("select should refuse to prompt"),
            Error::NonInteractive { .. }
        ));
        assert!(matches!(
            ui.multi_select("Pick some", "--choices", vec!["a".into()])
                .expect_err("multi_select should refuse to prompt"),
            Error::NonInteractive { .. }
        ));
        assert!(matches!(
            ui.confirm("Proceed?", "--yes", true)
                .expect_err("confirm should refuse to prompt"),
            Error::NonInteractive { .. }
        ));
        assert!(matches!(
            ui.text("Name?", "--name")
                .expect_err("text should refuse to prompt"),
            Error::NonInteractive { .. }
        ));
        assert!(matches!(
            ui.text_with_default("Name?", "--name", "default")
                .expect_err("text_with_default should refuse to prompt"),
            Error::NonInteractive { .. }
        ));
        assert!(matches!(
            ui.press_enter("Press ENTER:")
                .expect_err("press_enter should refuse without a terminal"),
            Error::NonInteractive { .. }
        ));
    }

    #[test]
    fn pause_is_a_noop_when_not_interactive() {
        // Must return immediately (no sleep) in non-interactive mode.
        noninteractive_ui().pause(Duration::from_secs(3600));
    }

    #[test]
    fn ensure_interactive_is_ok_when_interactive() {
        let ui = color_ui();
        assert!(ui.ensure_interactive("Proceed?", "--yes").is_ok());
    }

    #[test]
    fn formatters_render_plainly_without_color() {
        let ui = noninteractive_ui();
        ui.success("done");
        ui.failure("nope");
        ui.warn("careful");
        ui.info("fyi");
        ui.header("Section");
        // `debug` is a no-op when verbose is off; assert it stays silent-safe.
        ui.debug("hidden");
        assert_eq!(ui.paint("plain", Style::new().red()), "plain");
    }

    #[test]
    fn formatters_render_with_color() {
        let ui = color_ui();
        ui.success("done");
        ui.failure("nope");
        ui.warn("careful");
        ui.info("fyi");
        ui.header("Section");
        // With verbose on, `debug` actually prints (covering its body).
        ui.debug("verbose detail");
        // The colored `paint` branch must wrap the text in ANSI escapes.
        let painted = ui.paint("plain", Style::new().red());
        assert!(painted.contains("plain"));
        assert_ne!(painted, "plain");
    }

    #[test]
    fn animated_line_is_plain_without_color() {
        // Smoke test: must not panic and must handle empty input.
        let ui = noninteractive_ui();
        ui.animated_line("");
        ui.animated_line("hello sopsy");
    }

    #[test]
    fn animated_line_colorizes_each_character() {
        // Covers the per-character palette loop; with more than the palette's
        // length of characters it also exercises the wrap-around indexing.
        let ui = color_ui();
        ui.animated_line("");
        ui.animated_line("the quick brown fox jumps");
    }

    #[test]
    fn hidden_spinner_when_no_color() {
        let ui = noninteractive_ui();
        let pb = ui.spinner("working");
        pb.finish_and_clear();
    }

    #[test]
    fn real_spinner_when_color_enabled() {
        let ui = color_ui();
        let pb = ui.spinner("working");
        pb.finish_and_clear();
    }

    #[test]
    fn flush_does_not_panic() {
        noninteractive_ui().flush();
    }

    #[test]
    fn wrap_text_wraps_at_word_boundaries() {
        assert_eq!(wrap_text("a bb ccc", 5), vec!["a bb", "ccc"]);
        // A short message stays on one line.
        assert_eq!(wrap_text("hello", 80), vec!["hello"]);
        // Explicit newlines (and blank lines) are preserved.
        assert_eq!(wrap_text("one\n\ntwo", 80), vec!["one", "", "two"]);
        // Empty input still yields a single (blank) banner line.
        assert_eq!(wrap_text("", 80), vec![""]);
    }

    #[test]
    fn wrap_text_hard_splits_overlong_words() {
        assert_eq!(wrap_text("abcdefghij", 4), vec!["abcd", "efgh", "ij"]);
        // ...also when surrounded by normal words.
        assert_eq!(wrap_text("x abcdefgh y", 4), vec!["x", "abcd", "efgh", "y"]);
    }

    #[test]
    fn banners_render_in_both_color_modes() {
        // Smoke tests: every banner kind must render without panicking, both as
        // a bordered box (no color) and as a background-painted block (color),
        // including messages long enough to wrap.
        let plain = noninteractive_ui();
        let color = color_ui();
        for ui in [&plain, &color] {
            ui.banner_success("all set");
            ui.banner_info("for your information");
            ui.banner_warn("action required — store the key offline");
            ui.banner_alert(
                "this message is intentionally long enough that it must wrap onto \
                 several lines inside the banner box regardless of terminal width",
            );
        }
    }

    #[test]
    fn into_other_wraps_standard_errors() {
        let err = into_other(std::io::Error::other("boom"));
        assert!(matches!(err, Error::Other(_)));
        assert!(err.to_string().contains("boom"));
    }
}
