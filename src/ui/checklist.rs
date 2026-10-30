//! A checklist prompt (pick any number of options), drawn with `crossterm`.
//!
//! `inquire`'s multi-select styles every unchecked row alike, so it cannot
//! colour a row by whether it is checked. Here the row under the cursor is
//! bold yellow, checked rows are green with `[✔]`, and unchecked rows are
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
//!      [✔]  🟥   enclave — Secure Enclave (MacOS, Silicon CPU)
//!      [✔]  ✅   yubikey — YubiKey (hardware)
//! ```
//!
//! The state machine ([`Checklist::apply`]) and rendering ([`Checklist::lines`])
//! are plain functions and unit-tested; [`run`] is the thin raw-mode loop
//! around them that needs a real terminal.

use std::io::{self, Write};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::{cursor, queue, terminal};
use owo_colors::{OwoColorize, Style};

const HINT: &str = "    Select or deselect with a space bar.";
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
            done: false,
        }
    }

    pub(crate) fn apply(&mut self, key: Key) -> Outcome {
        let len = self.options.len();
        match key {
            Key::Up if len > 0 => self.cursor = (self.cursor + len - 1) % len,
            Key::Down if len > 0 => self.cursor = (self.cursor + 1) % len,
            Key::Toggle if len > 0 => self.checked[self.cursor] ^= true,
            Key::All => self.checked.fill(true),
            Key::None => self.checked.fill(false),
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
        let mut lines = vec![format!("  {prompt}"), HINT.to_string()];
        if !self.available.is_empty() {
            lines.extend(COLUMN_HEADER.iter().map(|l| l.to_string()));
        }
        let mut lines: Vec<String> = lines.iter().map(|l| truncate(l, width)).collect();
        lines.extend(self.rows(color, width));
        lines
    }

    fn rows(&self, color: bool, width: usize) -> Vec<String> {
        let text_column = if self.available.is_empty() {
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
                let head = format!("     [{}]  ", if checked { "✔" } else { " " });
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
pub(crate) fn run(
    prompt: &str,
    options: Vec<String>,
    checked: &[usize],
    available: Vec<bool>,
    color: bool,
) -> io::Result<Option<Vec<String>>> {
    let mut list = Checklist::new(options, checked, available);
    let mut out = io::stderr();
    let _raw = RawMode::enter()?;
    let mut drawn = 0u16;
    loop {
        redraw(&mut out, &mut drawn, &frame(&list, prompt, color))?;

        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match list.apply(Key::from(key)) {
            Outcome::Continue => {}
            Outcome::Submit => {
                // Leave the checklist on screen as it was confirmed.
                redraw(&mut out, &mut drawn, &frame(&list, prompt, color))?;
                return Ok(Some(list.selected()));
            }
            Outcome::Cancel => {
                redraw(&mut out, &mut drawn, &[format!("  {prompt} <canceled>")])?;
                return Ok(None);
            }
        }
    }
}

fn frame(list: &Checklist, prompt: &str, color: bool) -> Vec<String> {
    let width = terminal::size().map_or(0, |(w, _)| w as usize);
    list.lines(prompt, color, width)
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
                "     [✔]  🟥   enclave",
                "     [✔]  ✅   yubikey",
            ]
        );
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
            ["     [ ]  enclave", "     [✔]  yubikey", "     [ ]  file"]
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
}
