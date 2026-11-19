//! Small dialogs on top of a screen: a yes/no question, a question with a
//! text field (hidden for passwords), a message, and the help.
//!
//! SECURITY: a hidden field shows one dot per character typed and nothing
//! else; the text itself is a `Zeroizing` buffer, wiped with the dialog.

use std::cell::Cell;

use zeroize::Zeroizing;

use cakepass::crypto::SecurityLevel;

use super::super::grid::{Grid, Rect, str_width, wrap};
use super::super::input::TextInput;
use super::super::keys::{Event, Key};
use super::super::theme::Style;
use super::Hint;

/// What a yes/no question is about.
pub enum ConfirmAction {
    Delete(String),
    /// Close the form without saving.
    Discard,
    /// Read the vault again after another window changed it.
    Reload,
    /// Share this item: also its 2FA secret? (default no)
    ShareTotp(String),
    /// After an import: overwrite and delete the file? (default no)
    DeleteFile(std::path::PathBuf),
}

pub struct Confirm {
    pub title: String,
    pub lines: Vec<String>,
    pub yes: &'static str,
    pub no: &'static str,
    /// The highlighted button: true = yes.
    pub choice: bool,
    pub action: ConfirmAction,
}

/// A box in the middle of `area` for `lines` of text plus `extra` rows.
/// Returns the inner area and the first row after the text.
fn text_box(
    g: &mut Grid,
    area: Rect,
    title: &str,
    lines: &[String],
    extra: u16,
    warning: bool,
) -> (Rect, u16) {
    let w = area.w.saturating_sub(4).min(66);
    let text_w = w.saturating_sub(4) as usize;
    let wrapped: Vec<String> = lines.iter().flat_map(|l| wrap(l, text_w)).collect();
    let h = (wrapped.len() as u16 + extra + 4).min(area.h);
    let r = area.centered(w, h);
    g.dialog(r, title);
    if warning {
        // Same place as the title the frame drew, in the warning colour.
        g.print(r.x + 3, r.y, r.w.saturating_sub(6), title, Style::WARN);
    }
    let inner = r.inner();
    let mut y = inner.y + 1;
    for l in &wrapped {
        if y >= inner.bottom() {
            break;
        }
        g.print(inner.x + 1, y, inner.w.saturating_sub(2), l, Style::PLAIN);
        y += 1;
    }
    (inner, y)
}

fn buttons(g: &mut Grid, x: u16, y: u16, labels: &[&str], selected: usize) {
    let mut x = x;
    for (i, l) in labels.iter().enumerate() {
        let style = if i == selected { Style::SELECTED } else { Style::BOLD };
        x += g.print(x, y, 20, &format!("[ {l} ]"), style) + 2;
    }
}

impl Confirm {
    pub fn new(
        title: &str,
        lines: Vec<String>,
        yes: &'static str,
        no: &'static str,
        default_yes: bool,
        action: ConfirmAction,
    ) -> Confirm {
        Confirm { title: title.into(), lines, yes, no, choice: default_yes, action }
    }

    /// `Some(true)`: yes, `Some(false)`: no, `None`: still deciding.
    pub fn handle(&mut self, key: Key) -> Option<bool> {
        match key {
            Key::Left | Key::Right | Key::Tab | Key::BackTab | Key::Up | Key::Down => {
                self.choice = !self.choice;
                None
            }
            Key::Char('y' | 'Y') => Some(true),
            Key::Char('n' | 'N') | Key::Esc => Some(false),
            Key::Enter | Key::Char(' ') => Some(self.choice),
            _ => None,
        }
    }

    pub fn draw(&self, g: &mut Grid, area: Rect) -> Vec<Hint> {
        let (inner, y) = text_box(g, area, &self.title, &self.lines, 2, false);
        buttons(g, inner.x + 1, y + 1, &[self.yes, self.no], usize::from(!self.choice));
        vec![("←→", "choose"), ("Enter", "confirm"), ("y", "yes"), ("n/Esc", "no")]
    }
}

/// What a question with a text field is for (the answer is handled in `app.rs`).
pub enum PromptPurpose {
    /// The name for a generated password, saved as a new login.
    SaveGenerated,
    OwnPassword,
    OwnPasswordRepeat(Zeroizing<String>),
    /// A word of your own for the generator (empty removes it).
    OwnWord,
    /// The current master password, before changing it.
    Reconfirm,
    NewMaster,
    RepeatMaster(Zeroizing<String>),
    /// The master password, to read the vault again.
    Reload,
    /// The current master password, before switching to this security level.
    ConfirmLevel(SecurityLevel),
    /// Where to write the share file for this item (and whether its 2FA
    /// secret goes along).
    ShareTo(String, bool),
    /// Which export or share file to add.
    ImportFrom,
    /// The password of this export or share file.
    ImportPassword(std::path::PathBuf),
}

pub struct Prompt {
    pub title: String,
    pub lines: Vec<String>,
    pub label: &'static str,
    pub input: TextInput,
    pub masked: bool,
    pub purpose: PromptPurpose,
    pub error: Option<String>,
    /// Shown while the slow work runs (Argon2); keys are ignored then.
    pub busy: Option<&'static str>,
}

impl Prompt {
    pub fn new(
        title: &str,
        lines: Vec<String>,
        label: &'static str,
        masked: bool,
        purpose: PromptPurpose,
    ) -> Prompt {
        Prompt {
            title: title.into(),
            lines,
            label,
            input: TextInput::new(false),
            masked,
            purpose,
            error: None,
            busy: None,
        }
    }

    /// `Some(true)`: submitted, `Some(false)`: cancelled.
    pub fn handle(&mut self, ev: Event) -> Option<bool> {
        if self.busy.is_some() {
            return None;
        }
        match ev {
            Event::Paste(text) => {
                self.input.insert_str(&text);
            }
            Event::Key(Key::Enter) => return Some(true),
            Event::Key(Key::Esc) => return Some(false),
            Event::Key(k) => {
                if self.input.edit(k) {
                    self.error = None;
                }
            }
        }
        None
    }

    pub fn draw(&self, g: &mut Grid, area: Rect) -> Vec<Hint> {
        let (inner, y) = text_box(g, area, &self.title, &self.lines, 4, false);
        let y = y + 1;
        let lw = str_width(self.label) as u16 + 1;
        g.print(inner.x + 1, y, lw, self.label, Style::ACCENT_BOLD);
        let fx = inner.x + 2 + lw;
        let fw = inner.w.saturating_sub(lw + 4);
        g.fill(Rect::new(fx, y, fw, 1), Style::PLAIN);
        g.hline(fx, y + 1, fw, Style::DIM);
        let mask = self.masked.then_some(g.g.dot);
        let cursor = self.input.draw(g, Rect::new(fx, y, fw, 1), Style::BOLD, mask);
        if let Some(b) = self.busy {
            g.print(inner.x + 1, y + 2, inner.w.saturating_sub(2), b, Style::ACCENT);
        } else if let Some(e) = &self.error {
            g.print(inner.x + 1, y + 2, inner.w.saturating_sub(2), e, Style::ERROR);
            g.set_cursor(Some(cursor));
        } else {
            g.set_cursor(Some(cursor));
        }
        if self.busy.is_some() {
            vec![("", "please wait…")]
        } else {
            vec![("Enter", "OK"), ("Esc", "cancel")]
        }
    }
}

/// What was chosen in a [`Picker`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Picked {
    /// The first row: a new item instead of an existing one.
    New,
    Name(String),
}

/// Choose an item by its name: typing narrows the list, ↑ ↓ choose, Enter
/// takes it. The first row is always "a new item". Only names are shown
/// (they are not secret; `cakepass list` prints them too).
pub struct Picker {
    pub title: String,
    pub lines: Vec<String>,
    pub new_label: &'static str,
    pub names: Vec<String>,
    pub filter: TextInput,
    /// The selected row of `visible()` (0 = the new-item row).
    pub sel: usize,
}

impl Picker {
    /// Rows of the list at most (the dialog grows up to this).
    const ROWS: u16 = 8;

    pub fn new(title: &str, lines: Vec<String>, new_label: &'static str, names: Vec<String>) -> Picker {
        Picker { title: title.into(), lines, new_label, names, filter: TextInput::new(false), sel: 0 }
    }

    /// The names that match what was typed (case-insensitive, anywhere).
    pub fn visible(&self) -> Vec<&str> {
        let f = self.filter.as_str().trim().to_lowercase();
        self.names.iter().map(String::as_str).filter(|n| n.to_lowercase().contains(&f)).collect()
    }

    /// `Some(Some(_))`: chosen, `Some(None)`: cancelled, `None`: still choosing.
    pub fn handle(&mut self, ev: Event) -> Option<Option<Picked>> {
        let rows = self.visible().len() + 1;
        let key = match ev {
            Event::Paste(text) => {
                if self.filter.insert_str(&text) {
                    self.sel = 0;
                }
                return None;
            }
            Event::Key(k) => k,
        };
        match key {
            Key::Esc => return Some(None),
            Key::Up => self.sel = self.sel.saturating_sub(1),
            Key::Down => self.sel = (self.sel + 1).min(rows - 1),
            Key::PageUp => self.sel = self.sel.saturating_sub(Self::ROWS as usize),
            Key::PageDown => self.sel = (self.sel + Self::ROWS as usize).min(rows - 1),
            Key::Enter => {
                return Some(Some(match self.sel {
                    0 => Picked::New,
                    i => Picked::Name(self.visible()[i - 1].to_string()),
                }));
            }
            k => {
                if self.filter.edit(k) {
                    // The first match, or the new-item row when nothing matches.
                    self.sel = usize::from(!self.visible().is_empty());
                }
            }
        }
        None
    }

    pub fn draw(&self, g: &mut Grid, area: Rect) -> Vec<Hint> {
        let visible = self.visible();
        let rows = (visible.len() as u16 + 1).min(Self::ROWS);
        let (inner, y) = text_box(g, area, &self.title, &self.lines, rows + 3, false);
        // The search line.
        let y = y + 1;
        let label = "Find";
        g.print(inner.x + 1, y, 5, label, Style::ACCENT_BOLD);
        let fx = inner.x + 7;
        let fw = inner.w.saturating_sub(9);
        let cursor = self.filter.draw(g, Rect::new(fx, y, fw, 1), Style::BOLD, None);
        g.hline(fx, y + 1, fw, Style::DIM);
        g.set_cursor(Some(cursor));
        // The list, scrolled so the selection is visible (in a small window
        // the box may have room for fewer rows than asked for).
        let rows = rows.min(inner.bottom().saturating_sub(y + 2)).max(1);
        let top = self.sel.saturating_sub(rows as usize - 1);
        let names = std::iter::once(self.new_label).chain(visible.iter().copied());
        let lw = inner.w.saturating_sub(2);
        for (row, (i, name)) in names.enumerate().skip(top).take(rows as usize).enumerate() {
            let ly = y + 2 + row as u16;
            if ly >= inner.bottom() {
                break;
            }
            let style = match (i == self.sel, i == 0) {
                (true, _) => Style::SELECTED,
                (false, true) => Style::ACCENT_BOLD,
                (false, false) => Style::PLAIN,
            };
            g.fill(Rect::new(inner.x + 1, ly, lw, 1), style);
            g.print(inner.x + 2, ly, lw.saturating_sub(1), name, style);
        }
        vec![("type", "to find"), ("↑↓", "choose"), ("Enter", "OK"), ("Esc", "cancel")]
    }
}

/// A message with an OK button.
pub struct Message {
    pub title: String,
    pub lines: Vec<String>,
    pub warning: bool,
}

/// A message may show a secret once (the share password): its text is
/// wiped when the dialog closes.
impl Drop for Message {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.lines.iter_mut().for_each(Zeroize::zeroize);
    }
}

impl Message {
    pub fn new(title: &str, lines: Vec<String>, warning: bool) -> Message {
        Message { title: title.into(), lines, warning }
    }

    pub fn draw(&self, g: &mut Grid, area: Rect) -> Vec<Hint> {
        let (inner, y) = text_box(g, area, &self.title, &self.lines, 2, self.warning);
        buttons(g, inner.x + 1, y + 1, &["OK"], 0);
        vec![("Enter", "close")]
    }
}

/// Which help to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpPage {
    Main,
    Form,
    Generator,
    Settings,
}

impl HelpPage {
    fn content(self) -> (&'static str, &'static [(&'static str, &'static str)]) {
        match self {
            HelpPage::Main => (
                "Keys: the list",
                &[
                    ("↑ ↓  PgUp PgDn  Home End", "choose an item"),
                    ("← →  Tab", "All · Logins · API keys · Cards · IDs · SSH · Notes · 2FA (hide some: s)"),
                    ("/", "search (name, type, tags, username, e-mail, URL)"),
                    ("", "any key that is not a shortcut (a capital, a digit) starts the search too"),
                    ("Esc", "clear the search"),
                    ("Enter  v", "show / hide the secrets and notes (hides itself after 10 s)"),
                    (
                        "c",
                        "copy the password, API key, note, card number, private key or document number \
                         (cleared after the clip-time: 20 s unless set otherwise)",
                    ),
                    ("u  m", "copy the username / the e-mail address"),
                    (
                        "t",
                        "copy the two-factor (TOTP) code and show it live (a new one every 30 s) until you move on",
                    ),
                    (
                        "",
                        "the 2FA tab lists every item with a code; there Enter or c copies it, a adds one, s scans a QR code",
                    ),
                    ("p", "copy the public key of an SSH key"),
                    ("f", "pin or unpin as a favorite (★; favorites come first)"),
                    ("x", "share the item: an encrypted file plus a generated password for someone else"),
                    ("i", "add the items of a file someone shared with you (or an export)"),
                    ("a  n", "add an item"),
                    ("e", "edit the selected item"),
                    ("d  Del", "delete it (asks first)"),
                    ("g", "password generator"),
                    ("s", "settings: animation, auto-lock, tabs, master password"),
                    ("l", "lock: wipe the key from memory and close"),
                    ("q  Ctrl+C", "quit (locks too)"),
                ],
            ),
            HelpPage::Form => (
                "Keys: the form",
                &[
                    ("↑ ↓  Tab  Shift+Tab", "move between the fields"),
                    ("← →  Home End", "move in the text; on Type: choose the type"),
                    ("Backspace  Del", "delete a character"),
                    ("Ctrl+U", "clear the field"),
                    ("Enter", "next field (in Notes and a private key: a new line)"),
                    ("Ctrl+R", "show / hide the password (and the other hidden fields)"),
                    ("2FA secret", "paste the secret under a site's QR code; Ctrl+U there removes the code"),
                    ("Ctrl+G", "password generator"),
                    ("Ctrl+S", "save"),
                    ("Esc", "cancel (asks first when you changed something)"),
                ],
            ),
            HelpPage::Generator => (
                "Keys: the generator",
                &[
                    ("↑ ↓", "choose an option"),
                    ("← →  Space", "change it"),
                    ("PgUp PgDn", "length or words +8 / -8"),
                    ("r", "a new password"),
                    ("v", "show / hide it"),
                    ("e", "type your own instead (asked twice)"),
                    (
                        "w",
                        "a word of your own, put in at a random place (it adds no strength; empty removes it)",
                    ),
                    ("c", "copy it (the clipboard is cleared after the clip-time, 20 s by default)"),
                    ("Enter", "use it (from the list: save it as a new login)"),
                    ("Esc", "cancel"),
                ],
            ),
            HelpPage::Settings => (
                "Keys: settings",
                &[
                    ("↑ ↓", "choose a setting"),
                    (
                        "← →",
                        "change it (saved right away); on Tabs: choose a type; on Security level: a level",
                    ),
                    ("PgUp PgDn", "auto-lock +10 / -10 minutes"),
                    ("Enter", "switch / change the master password / apply the chosen security level"),
                    ("Enter  Space", "on Tabs: show or hide the tab of that type (its items stay under All)"),
                    ("", "the unlock time of a level is measured on this computer when you choose it"),
                    ("Esc", "back to the list"),
                ],
            ),
        }
    }
}

/// The help dialog; it scrolls when the terminal is too short for it.
pub struct Help {
    pub page: HelpPage,
    scroll: Cell<usize>,
}

impl Help {
    pub fn new(page: HelpPage) -> Help {
        Help { page, scroll: Cell::new(0) }
    }

    /// Scroll keys; returns true when the help should close.
    pub fn handle(&mut self, key: Key) -> bool {
        let s = self.scroll.get();
        match key {
            Key::Up => self.scroll.set(s.saturating_sub(1)),
            Key::Down => self.scroll.set(s + 1),
            Key::PageUp => self.scroll.set(s.saturating_sub(10)),
            Key::PageDown => self.scroll.set(s + 10),
            Key::Esc | Key::Enter | Key::Char('q' | '?' | ' ') | Key::F(1) => return true,
            _ => {}
        }
        false
    }

    pub fn draw(&self, g: &mut Grid, area: Rect) -> Vec<Hint> {
        let (title, rows) = self.page.content();
        let w = area.w.saturating_sub(4).min(80);
        let kw = rows.iter().map(|r| str_width(r.0)).max().unwrap_or(0).min(24) as u16;
        let dw = w.saturating_sub(kw + 6) as usize;
        // One entry per screen line: (keys or "", text).
        let lines: Vec<(&str, String)> = rows
            .iter()
            .flat_map(|&(k, d)| {
                wrap(d, dw).into_iter().enumerate().map(move |(i, l)| (if i == 0 { k } else { "" }, l))
            })
            .collect();
        let r = area.centered(w, lines.len() as u16 + 4);
        g.dialog(r, title);
        let inner = r.inner();
        let visible = inner.h.saturating_sub(2) as usize;
        let max_scroll = lines.len().saturating_sub(visible);
        let scroll = self.scroll.get().min(max_scroll);
        self.scroll.set(scroll);
        for (i, (k, d)) in lines.iter().skip(scroll).take(visible).enumerate() {
            let y = inner.y + 1 + i as u16;
            g.print(inner.x + 1, y, kw, k, Style::ACCENT_BOLD);
            g.print(inner.x + 3 + kw, y, dw as u16, d, Style::PLAIN);
        }
        if max_scroll > 0 {
            let pos = format!(" {}-{} of {} ", scroll + 1, scroll + visible.min(lines.len()), lines.len());
            g.print(
                r.x + r.w.saturating_sub(pos.len() as u16 + 2),
                r.bottom() - 1,
                pos.len() as u16,
                &pos,
                Style::ACCENT,
            );
            vec![("↑↓", "scroll"), ("Esc", "close")]
        } else {
            vec![("Esc", "close")]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirm_defaults_and_keys() {
        let mut c = Confirm::new("Delete", vec![], "Delete", "Keep", false, ConfirmAction::Discard);
        assert_eq!(c.handle(Key::Enter), Some(false), "the default is no");
        assert_eq!(c.handle(Key::Right), None);
        assert_eq!(c.handle(Key::Enter), Some(true));
        assert_eq!(c.handle(Key::Char('n')), Some(false));
        assert_eq!(c.handle(Key::Char('y')), Some(true));
        assert_eq!(c.handle(Key::Esc), Some(false));
        assert_eq!(c.handle(Key::Char('x')), None);
    }

    #[test]
    fn prompt_typing_and_busy() {
        let mut p = Prompt::new("t", vec![], "Password", true, PromptPurpose::Reconfirm);
        for c in "pw".chars() {
            p.handle(Event::Key(Key::Char(c)));
        }
        p.handle(Event::Paste(Zeroizing::new("123\n".into())));
        assert_eq!(p.input.as_str(), "pw123");
        p.busy = Some("…");
        assert_eq!(p.handle(Event::Key(Key::Enter)), None, "keys wait while busy");
        p.busy = None;
        assert_eq!(p.handle(Event::Key(Key::Enter)), Some(true));
    }
}
