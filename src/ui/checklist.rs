//! A checklist prompt (pick any number of options), drawn with `crossterm`.
//!
//! `inquire`'s multi-select styles every unchecked row alike, so it cannot
//! colour a row by whether it is checked. Here the row under the cursor is
//! bold yellow behind a `❯`, checked rows are bold green with `[✔]`, and
//! unchecked rows are bold black with `[ ]`. An optional column after the
//! checkbox, headed [`AVAILABLE_HEADER`], marks each option available (✅) or
//! not (`[ｘ]`, white on red).
//!
//! The state machine ([`Checklist::apply`]) and row rendering
//! ([`Checklist::rows`]) are plain functions and unit-tested; [`run`] is the
//! thin raw-mode loop around them that needs a real terminal.

use std::io::{self, Write};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::{cursor, queue, terminal};
use owo_colors::{OwoColorize, Style};

const POINTER: &str = "❯";
const AVAILABLE_HEADER: &str = "Available on this machine?";
/// Cells before the availability column: `❯ [✔] `.
const MARK_COLUMN: usize = 6;
const HELP: &str = "[↑↓ move, space toggles, → all, ← none, enter confirms]";

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

    /// The header over the availability column, if there is one.
    pub(crate) fn header(&self, color: bool, width: usize) -> Option<String> {
        if self.available.is_empty() {
            return None;
        }
        let text = if width == 0 {
            AVAILABLE_HEADER.to_string()
        } else {
            truncate(AVAILABLE_HEADER, width.saturating_sub(MARK_COLUMN).max(1))
        };
        let text = if color { text.bold().to_string() } else { text };
        Some(format!("{}{text}", " ".repeat(MARK_COLUMN)))
    }

    /// The rows as printed, each cut to `width` characters.
    pub(crate) fn rows(&self, color: bool, width: usize) -> Vec<String> {
        self.options
            .iter()
            .enumerate()
            .map(|(i, option)| {
                let here = !self.done && i == self.cursor;
                let checked = self.checked[i];
                let head = format!(
                    "{} [{}] ",
                    if here { POINTER } else { " " },
                    if checked { "✔" } else { " " }
                );
                // Both marks are four terminal cells wide, so the text lines up.
                let mark = self.available.get(i).copied();
                let used = MARK_COLUMN + mark.map_or(0, |_| 5);
                let text = if width == 0 {
                    option.clone()
                } else {
                    truncate(option, width.saturating_sub(used).max(1))
                };
                let style = match (here, checked) {
                    (true, _) => Style::new().bold().yellow(),
                    (false, true) => Style::new().bold().green(),
                    (false, false) => Style::new().bold().black(),
                };
                let paint = |part: &str| {
                    if color {
                        part.style(style).to_string()
                    } else {
                        part.to_string()
                    }
                };
                let mark = match (mark, color) {
                    (None, _) => String::new(),
                    (Some(true), false) => "✅   ".into(),
                    (Some(false), false) => "[ｘ] ".into(),
                    (Some(true), true) => format!("{}   ", "✅".style(Style::new().bright_green())),
                    (Some(false), true) => {
                        format!("{} ", "[ｘ]".style(Style::new().white().on_red()))
                    }
                };
                format!("{}{mark}{}", paint(&head), paint(&text))
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
        redraw(&mut out, &mut drawn, &frame(&list, prompt, color, true))?;

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
                redraw(&mut out, &mut drawn, &frame(&list, prompt, color, false))?;
                return Ok(Some(list.selected()));
            }
            Outcome::Cancel => {
                redraw(&mut out, &mut drawn, &[format!("? {prompt} <canceled>")])?;
                return Ok(None);
            }
        }
    }
}

/// The prompt on its own line, the rows, and (while active) the key help.
fn frame(list: &Checklist, prompt: &str, color: bool, help: bool) -> Vec<String> {
    let width = terminal::size().map_or(0, |(w, _)| w as usize);
    let mut lines = vec![truncate(&format!("? {prompt}"), width)];
    lines.extend(list.header(color, width));
    lines.extend(list.rows(color, width));
    if help {
        lines.push(truncate(HELP, width));
    }
    lines
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
    fn confirmed_rows_keep_their_marks_but_lose_the_cursor() {
        let mut l = list();
        l.apply(Key::Submit);
        assert_eq!(
            l.rows(false, 0),
            ["  [ ] enclave", "  [✔] yubikey", "  [ ] file"]
        );
    }

    #[test]
    fn availability_column_has_a_header_and_lines_up() {
        let l = Checklist::new(
            vec!["enclave".into(), "file".into()],
            &[],
            vec![false, true],
        );
        assert_eq!(
            l.header(false, 0).as_deref(),
            Some("      Available on this machine?")
        );
        assert_eq!(l.rows(false, 0), ["❯ [ ] [ｘ] enclave", "  [ ] ✅   file"]);
        let rows = l.rows(true, 0);
        assert!(rows[0].contains("\x1b[37;41m[ｘ]"), "{:?}", rows[0]);
        assert!(rows[1].contains("\x1b[92m✅"), "{:?}", rows[1]);
        assert!(list().header(false, 0).is_none());
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
    fn rows_mark_the_cursor_and_checked_options() {
        assert_eq!(
            list().rows(false, 0),
            ["❯ [ ] enclave", "  [✔] yubikey", "  [ ] file"]
        );
    }

    #[test]
    fn rows_are_yellow_under_the_cursor_green_when_checked_else_black() {
        let rows = list().rows(true, 0);
        let bold = |code: &str| format!("\x1b[{code};1m");
        assert!(rows[0].starts_with(&bold("33")), "{:?}", rows[0]);
        assert!(rows[1].starts_with(&bold("32")), "{:?}", rows[1]);
        assert!(rows[2].starts_with(&bold("30")), "{:?}", rows[2]);
    }

    #[test]
    fn long_rows_are_cut_to_the_terminal_width() {
        assert_eq!(truncate("❯ [ ] enclave", 8), "❯ [ ] e…");
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
