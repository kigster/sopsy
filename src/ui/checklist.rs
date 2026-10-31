//! A checklist prompt (pick any number of options), drawn with `crossterm`.
//!
//! `inquire`'s multi-select styles every unchecked row alike, so it cannot
//! colour a row by whether it is checked. Here the row under the cursor is
//! bold yellow behind a `❯` ([`POINTER_ENV`] picks another one-cell glyph,
//! such as a Nerd Font arrow), checked rows are green with `[✔]`, and unchecked rows are
//! plain with `[ ]`. An optional column after the checkbox marks each option
//! supported by this machine (✅) or not (🟥), under a header that points at
//! both columns:
//!
//! ```text
//!   Which key stores may members of this repository use?
//!     Select or deselect with a space bar.
//!       ┃   Method supported by this hardware?
//!       ┃   ┃    (If this machine lacks a method other machines may support)
//!   ━━━━┻━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//!    ❯ [✔]  🟥   enclave — Secure Enclave (MacOS, Silicon CPU)
//!      [✔]  ✅   yubikey — YubiKey (hardware)
//! ```
//!
//! [`Checklist::single`] is the pick-one variant: the same pointer and
//! colours, no checkboxes, and Enter (or Space) chooses the row.
//!
//! The state machine ([`Checklist::apply`]) and rendering ([`Checklist::lines`])
//! are plain functions and unit-tested; [`run`] is the thin raw-mode loop
//! around them that needs a real terminal.

use std::io::{self, Write};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::{cursor, queue, terminal};
use owo_colors::{OwoColorize, Style};

/// Marks the row under the cursor, in the indent before its checkbox.
const POINTER: char = '❯';
/// Environment variable naming another pointer glyph. Whether the font can
/// draw it is up to the user: a terminal can't report a missing glyph.
pub(crate) const POINTER_ENV: &str = "SOPSY_POINTER";
const HINT: &str = "    Select or deselect with a space bar.";
const SINGLE_HINT: &str = "    Move with ↑↓ and press Enter to choose.";
/// Header over the availability column, its `┃`s above the ✔ and the mark.
const COLUMN_HEADER: [&str; 3] = [
    "      ┃   Method supported by this hardware?",
    "      ┃   ┃    (If this machine lacks a method other machines may support)",
    "  ━━━━┻━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
];
/// Terminal cells before an option's text: `     [✔]  ✅   `, or without the
/// availability column `     [✔]  `.
const TEXT_COLUMN: usize = 15;
const TEXT_COLUMN_NO_MARK: usize = 10;
/// Terminal cells before an option's text in a pick-one list: `   ❯ `.
const TEXT_COLUMN_SINGLE: usize = 5;

/// A key press, as far as the checklist cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Key {
    Up,
    Down,
    Toggle,
    All,
    None,
    Submit,
    Cancel,
    Other,
}

impl From<KeyEvent> for Key {
    fn from(key: KeyEvent) -> Self {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('c' | 'd') if ctrl => Key::Cancel,
            KeyCode::Esc => Key::Cancel,
            KeyCode::Up | KeyCode::Char('k') => Key::Up,
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => Key::Down,
            KeyCode::Char(' ') => Key::Toggle,
            KeyCode::Right => Key::All,
            KeyCode::Left => Key::None,
            KeyCode::Enter => Key::Submit,
            _ => Key::Other,
        }
    }
}

/// What a key press means for the prompt as a whole.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Continue,
    Submit,
    Cancel,
}

/// Options, which of them are checked, and the cursor.
#[derive(Debug)]
pub(crate) struct Checklist {
    options: Vec<String>,
    checked: Vec<bool>,
    /// Per-option availability column; empty for no column.
    available: Vec<bool>,
    cursor: usize,
    pointer: char,
    /// Pick exactly one: no checkboxes, Enter chooses the cursor row.
    single: bool,
    /// Confirmed: drop the cursor so the rows show only what was picked.
    done: bool,
}

impl Checklist {
    pub(crate) fn new(options: Vec<String>, checked: &[usize], available: Vec<bool>) -> Self {
        let mut flags = vec![false; options.len()];
        for &i in checked.iter().filter(|&&i| i < options.len()) {
            flags[i] = true;
        }
        Self {
            options,
            checked: flags,
            available,
            cursor: 0,
            pointer: POINTER,
            single: false,
            done: false,
        }
    }

    /// A pick-one list.
    pub(crate) fn single(options: Vec<String>) -> Self {
        Self {
            single: true,
            ..Self::new(options, &[], Vec::new())
        }
    }

    pub(crate) fn apply(&mut self, key: Key) -> Outcome {
        let len = self.options.len();
        if self.single && matches!(key, Key::Toggle | Key::Submit) && len > 0 {
            self.checked.fill(false);
            self.checked[self.cursor] = true;
            self.done = true;
            return Outcome::Submit;
        }
        match key {
            Key::Up if len > 0 => self.cursor = (self.cursor + len - 1) % len,
            Key::Down if len > 0 => self.cursor = (self.cursor + 1) % len,
            Key::Toggle if len > 0 => self.checked[self.cursor] ^= true,
            Key::All if !self.single => self.checked.fill(true),
            Key::None if !self.single => self.checked.fill(false),
            Key::Submit => {
                self.done = true;
                return Outcome::Submit;
            }
            Key::Cancel => return Outcome::Cancel,
            _ => {}
        }
        Outcome::Continue
    }

    /// Everything printed: prompt, hint, column header (with an availability
    /// column) and one row per option, each cut to `width` cells (0 = no limit).
    pub(crate) fn lines(&self, prompt: &str, color: bool, width: usize) -> Vec<String> {
        let hint = if self.single { SINGLE_HINT } else { HINT };
        // The question wraps (never truncates); every other line is cut to fit.
        let question: Vec<String> = if width == 0 {
            vec![prompt.to_string()]
        } else {
            super::wrap_text(prompt, width.saturating_sub(2))
        }
        .into_iter()
        .map(|l| {
            let l = format!("  {l}");
            if color { l.green().to_string() } else { l }
        })
        .collect();
        let mut lines = vec![hint.to_string()];
        if !self.available.is_empty() {
            lines.extend(COLUMN_HEADER.iter().map(|l| l.to_string()));
        }
        let mut lines: Vec<String> = question
            .into_iter()
            .chain(lines.iter().map(|l| truncate(l, width)))
            .collect();
        lines.extend(self.rows(color, width));
        lines
    }

    fn rows(&self, color: bool, width: usize) -> Vec<String> {
        let text_column = if self.single {
            TEXT_COLUMN_SINGLE
        } else if self.available.is_empty() {
            TEXT_COLUMN_NO_MARK
        } else {
            TEXT_COLUMN
        };
        self.options
            .iter()
            .enumerate()
            .map(|(i, option)| {
                let here = !self.done && i == self.cursor;
                let checked = self.checked[i];
                let pointer = if here { self.pointer } else { ' ' };
                let head = if self.single {
                    format!("   {pointer} ")
                } else {
                    format!("   {pointer} [{}]  ", if checked { '✔' } else { ' ' })
                };
                let mark = match self.available.get(i) {
                    None => "",
                    Some(true) => "✅   ",
                    Some(false) => "🟥   ",
                };
                let text = if width == 0 {
                    option.clone()
                } else {
                    truncate(option, width.saturating_sub(text_column).max(1))
                };
                let style = match (here, checked) {
                    (true, _) => Some(Style::new().bold().yellow()),
                    (false, true) => Some(Style::new().green()),
                    (false, false) => None,
                };
                match style.filter(|_| color) {
                    // The emoji carry their own colour; style around them.
                    Some(style) => format!("{}{mark}{}", head.style(style), text.style(style)),
                    None => format!("{head}{mark}{text}"),
                }
            })
            .collect()
    }

    pub(crate) fn selected(&self) -> Vec<String> {
        self.options
            .iter()
            .zip(&self.checked)
            .filter(|(_, checked)| **checked)
            .map(|(option, _)| option.clone())
            .collect()
    }
}

fn truncate(row: &str, width: usize) -> String {
    if width == 0 || row.chars().count() <= width {
        return row.to_string();
    }
    let mut cut: String = row.chars().take(width.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

/// Leaves raw mode and shows the cursor again, even on an early return.
struct RawMode;

impl RawMode {
    fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        queue!(io::stderr(), cursor::Hide)?;
        Ok(Self)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = queue!(io::stderr(), cursor::Show);
        let _ = io::stderr().flush();
        let _ = terminal::disable_raw_mode();
    }
}

/// Show the checklist on stderr until the user confirms (`Some(selected)`)
/// or cancels (`None`).
pub(crate) fn run(prompt: &str, list: Checklist, color: bool) -> io::Result<Option<Vec<String>>> {
    let _raw = RawMode::enter()?;
    drive(
        prompt,
        list,
        color,
        &mut io::stderr(),
        || terminal::size().map_or(0, |(w, _)| w as usize),
        read_key,
    )
}

/// The next key press from the terminal, skipping releases and non-key events.
fn read_key() -> io::Result<Key> {
    loop {
        if let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            return Ok(Key::from(key));
        }
    }
}

/// Draw the checklist to `out` and apply keys from `next_key` until the user
/// confirms or cancels. Terminal-free, so tests can script the keys.
pub(crate) fn drive(
    prompt: &str,
    mut list: Checklist,
    color: bool,
    out: &mut impl Write,
    width: impl Fn() -> usize,
    mut next_key: impl FnMut() -> io::Result<Key>,
) -> io::Result<Option<Vec<String>>> {
    if let Some(glyph) = std::env::var(POINTER_ENV)
        .ok()
        .and_then(|v| v.trim().chars().next())
    {
        list.pointer = glyph;
    }
    let mut drawn = 0u16;
    loop {
        redraw(out, &mut drawn, &list.lines(prompt, color, width()))?;
        match list.apply(next_key()?) {
            Outcome::Continue => {}
            Outcome::Submit => {
                // Leave the checklist on screen as it was confirmed.
                redraw(out, &mut drawn, &list.lines(prompt, color, width()))?;
                return Ok(Some(list.selected()));
            }
            Outcome::Cancel => {
                redraw(out, &mut drawn, &[format!("  {prompt} <canceled>")])?;
                return Ok(None);
            }
        }
    }
}

/// Replace the `drawn` lines printed last time with `lines`.
fn redraw(out: &mut impl Write, drawn: &mut u16, lines: &[String]) -> io::Result<()> {
    if *drawn > 0 {
        queue!(out, cursor::MoveUp(*drawn))?;
    }
    queue!(
        out,
        cursor::MoveToColumn(0),
        terminal::Clear(terminal::ClearType::FromCursorDown)
    )?;
    for line in lines {
        // Raw mode does not turn `\n` into a carriage return.
        write!(out, "{line}\r\n")?;
    }
    *drawn = lines.len() as u16;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list() -> Checklist {
        Checklist::new(
            vec!["enclave".into(), "yubikey".into(), "file".into()],
            &[1],
            Vec::new(),
        )
    }

    #[test]
    fn space_toggles_and_arrows_select_all_or_none() {
        let mut l = list();
        assert_eq!(l.selected(), ["yubikey"]);
        assert_eq!(l.apply(Key::Toggle), Outcome::Continue);
        assert_eq!(l.selected(), ["enclave", "yubikey"]);
        l.apply(Key::Down);
        l.apply(Key::Toggle);
        assert_eq!(l.selected(), ["enclave"]);
        l.apply(Key::All);
        assert_eq!(l.selected().len(), 3);
        l.apply(Key::None);
        assert!(l.selected().is_empty());
        assert_eq!(l.apply(Key::Submit), Outcome::Submit);
        assert_eq!(l.apply(Key::Cancel), Outcome::Cancel);
    }

    #[test]
    fn confirmed_rows_keep_their_marks_but_lose_the_highlight() {
        let mut l = list();
        l.apply(Key::Submit);
        assert_eq!(l.rows(false, 0)[0], "     [ ]  enclave");
        let rows = l.rows(true, 0);
        assert!(!rows[0].contains('\x1b'), "{:?}", rows[0]);
        assert!(rows[1].starts_with("\x1b[32m"), "{:?}", rows[1]);
    }

    #[test]
    fn availability_layout_matches_the_design() {
        let l = Checklist::new(
            vec!["enclave".into(), "yubikey".into()],
            &[0, 1],
            vec![false, true],
        );
        assert_eq!(
            l.lines("Which key stores?", false, 0),
            [
                "  Which key stores?",
                "    Select or deselect with a space bar.",
                "      ┃   Method supported by this hardware?",
                "      ┃   ┃    (If this machine lacks a method other machines may support)",
                "  ━━━━┻━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                "   ❯ [✔]  🟥   enclave",
                "     [✔]  ✅   yubikey",
            ]
        );
    }

    #[test]
    fn pointer_glyph_can_be_swapped() {
        let mut l = list();
        l.pointer = '\u{e0b0}';
        assert_eq!(l.rows(false, 0)[0], "   \u{e0b0} [ ]  enclave");
    }

    #[test]
    fn single_choice_has_no_checkboxes_and_enter_picks_the_row() {
        let mut l = Checklist::single(vec!["auto".into(), "file".into()]);
        assert_eq!(
            l.lines("Where?", false, 0),
            [
                "  Where?",
                "    Move with ↑↓ and press Enter to choose.",
                "   ❯ auto",
                "     file",
            ]
        );
        l.apply(Key::All);
        assert!(l.selected().is_empty());
        l.apply(Key::Down);
        assert_eq!(l.apply(Key::Submit), Outcome::Submit);
        assert_eq!(l.selected(), ["file"]);
        // Confirmed: the pick stays green, the cursor goes.
        let rows = l.rows(true, 0);
        assert!(!rows[0].contains('\x1b'), "{:?}", rows[0]);
        assert!(rows[1].starts_with("\x1b[32m"), "{:?}", rows[1]);
    }

    #[test]
    fn the_question_is_green() {
        assert_eq!(list().lines("Pick?", true, 0)[0], "\x1b[32m  Pick?\x1b[39m");
    }

    #[test]
    fn a_long_question_wraps_instead_of_being_cut() {
        let lines = list().lines("one two three four", false, 14);
        assert_eq!(&lines[..3], ["  one two", "  three four", "    Select or…"]);
    }

    #[test]
    fn cursor_wraps_around() {
        let mut l = list();
        l.apply(Key::Up);
        assert_eq!(l.cursor, 2);
        l.apply(Key::Down);
        assert_eq!(l.cursor, 0);
    }

    #[test]
    fn rows_without_the_availability_column() {
        assert_eq!(
            list().rows(false, 0),
            ["   ❯ [ ]  enclave", "     [✔]  yubikey", "     [ ]  file"]
        );
    }

    #[test]
    fn rows_are_bold_yellow_under_the_cursor_green_when_checked_else_plain() {
        let rows = list().rows(true, 0);
        assert!(rows[0].starts_with("\x1b[33;1m"), "{:?}", rows[0]);
        assert!(rows[1].starts_with("\x1b[32m"), "{:?}", rows[1]);
        assert!(!rows[2].contains('\x1b'), "{:?}", rows[2]);
    }

    #[test]
    fn long_rows_are_cut_to_the_terminal_width() {
        assert_eq!(truncate("[ ] enclave", 6), "[ ] e…");
        assert_eq!(truncate("short", 80), "short");
    }

    #[test]
    fn keys_map_to_actions() {
        let key = |code| Key::from(KeyEvent::new(code, KeyModifiers::NONE));
        assert_eq!(key(KeyCode::Char(' ')), Key::Toggle);
        assert_eq!(key(KeyCode::Enter), Key::Submit);
        assert_eq!(key(KeyCode::Right), Key::All);
        assert_eq!(
            Key::from(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Key::Cancel
        );
    }

    fn drive_keys(list: Checklist, keys: &[Key]) -> (Option<Vec<String>>, String) {
        let mut out = Vec::new();
        let mut keys = keys.iter().copied();
        let picked = drive(
            "Pick",
            list,
            false,
            &mut out,
            || 60,
            || Ok(keys.next().unwrap_or(Key::Cancel)),
        )
        .unwrap();
        (picked, String::from_utf8(out).unwrap())
    }

    #[test]
    fn drive_redraws_and_returns_the_confirmed_selection() {
        let list = Checklist::new(vec!["a".into(), "b".into()], &[0], Vec::new());
        let (picked, out) = drive_keys(list, &[Key::Down, Key::Toggle, Key::Submit]);
        assert_eq!(picked.unwrap(), ["a", "b"]);
        // Three frames: the first draw, after Down/Toggle… and the final one.
        assert!(out.matches("Pick").count() >= 3, "{out}");
        assert!(
            out.contains("\r\n"),
            "raw mode needs explicit carriage returns"
        );
    }

    #[test]
    #[serial_test::serial]
    fn drive_cancels_and_honors_the_pointer_override() {
        // SAFETY: serialized.
        unsafe { std::env::set_var(POINTER_ENV, ">") };
        let list = Checklist::single(vec!["a".into()]);
        let (picked, out) = drive_keys(list, &[Key::Other, Key::Cancel]);
        unsafe { std::env::remove_var(POINTER_ENV) };
        assert!(picked.is_none());
        assert!(out.contains("> "), "{out}");
        assert!(out.contains("Pick <canceled>"));
    }
}
