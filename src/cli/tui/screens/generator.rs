//! The password generator (a dialog): a live preview, the options to tune
//! it, and "type your own". It uses the same generator and settings as
//! `cakepass generate` (see `commands::Recipe`).
//!
//! From the main screen, Enter asks for a name and saves the password as a
//! new login (the same code path as `generate --save`); from the form, Enter
//! puts it in the password field.
//!
//! SECURITY: the password lives in a `Zeroizing` buffer and is replaced (the
//! old one wiped) on every change. It is shown as dots unless you press v.

use cakepass::generator::{self, PassphraseOptions, PasswordOptions};
use zeroize::Zeroizing;

use super::super::super::{commands, prompt};
use super::super::app::error_text;
use super::super::grid::{Grid, Rect};
use super::super::keys::Key;
use super::super::theme::Style;
use super::Hint;
use commands::Recipe;

/// Where an accepted password goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenTarget {
    /// Into the password field of the open form.
    Form,
    /// Saved as a new login (asks for a name).
    NewLogin,
}

/// The generator settings; remembered while CakePass is open (never saved).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct GenPrefs {
    pub passphrase: bool,
    pub password: PasswordOptions,
    pub phrase: PassphraseOptions,
    /// A word of your own, put in at a random place; empty = none. Wiped
    /// when dropped; not in `Debug`.
    pub own_word: Zeroizing<String>,
}

impl std::fmt::Debug for GenPrefs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenPrefs")
            .field("passphrase", &self.passphrase)
            .field("password", &self.password)
            .field("phrase", &self.phrase)
            .field("own_word", &(!self.own_word.is_empty()))
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Row {
    Kind,
    Length,
    Upper,
    Lower,
    Digits,
    Symbols,
    Lookalikes,
    Words,
    Separator,
    OwnWord,
}

const PASSWORD_ROWS: [Row; 8] = [
    Row::Kind,
    Row::Length,
    Row::Upper,
    Row::Lower,
    Row::Digits,
    Row::Symbols,
    Row::Lookalikes,
    Row::OwnWord,
];
const PHRASE_ROWS: [Row; 4] = [Row::Kind, Row::Words, Row::Separator, Row::OwnWord];
const SEPARATORS: [&str; 6] = ["-", ".", "_", "+", ",", " "];

pub enum Action {
    None,
    Accept,
    Cancel,
    Copy,
    TypeOwn,
    /// Ask for a word of your own (`w`, or ←→ on its row).
    OwnWord,
    Help,
}

pub struct Generator {
    pub target: GenTarget,
    pub prefs: GenPrefs,
    pub value: Zeroizing<String>,
    /// Strength in bits of a generated password; `None` for your own.
    pub bits: Option<f64>,
    pub shown: bool,
    row: usize,
    /// A remark under the options (an error, a weak own password).
    pub note: Option<(Style, String)>,
}

impl Generator {
    pub fn new(target: GenTarget, prefs: GenPrefs) -> Generator {
        let mut g = Generator {
            target,
            prefs,
            value: Zeroizing::new(String::new()),
            bits: None,
            shown: false,
            row: 0,
            note: None,
        };
        g.regenerate();
        g
    }

    fn rows(&self) -> &'static [Row] {
        if self.prefs.passphrase { &PHRASE_ROWS } else { &PASSWORD_ROWS }
    }

    pub fn recipe(&self) -> Recipe {
        if self.prefs.passphrase {
            Recipe::Passphrase(self.prefs.phrase.clone())
        } else {
            Recipe::Password(self.prefs.password)
        }
    }

    /// Make a new password with the current settings.
    pub fn regenerate(&mut self) {
        let own = Some(self.prefs.own_word.as_str()).filter(|w| !w.is_empty());
        match self.recipe().generate(own) {
            Ok((value, bits)) => {
                self.value = value; // the old one is wiped
                self.bits = Some(bits);
                self.note =
                    own.map(|_| (Style::DIM, "Your word is at a random place; it adds no strength.".into()));
            }
            Err(e) => self.note = Some((Style::ERROR, error_text(&e))),
        }
    }

    /// Use this word of your own from now on (empty: none), and make a new
    /// password with it. A word that is not allowed changes nothing.
    pub fn set_own_word(&mut self, word: &str) {
        if let Err(e) = Some(word).filter(|w| !w.is_empty()).map_or(Ok(()), generator::check_own_word) {
            self.note = Some((Style::ERROR, error_text(&e)));
            return;
        }
        self.prefs.own_word = Zeroizing::new(word.to_string());
        self.regenerate();
    }

    /// Use a password the user typed (twice) instead.
    pub fn set_own(&mut self, pw: &str) {
        self.value = Zeroizing::new(pw.to_string());
        self.bits = None;
        self.note = if prompt::strength(pw).0 < prompt::MIN_SCORE {
            Some((Style::WARN, "This password is on the weak side. You can still use it, or press r.".into()))
        } else {
            Some((Style::SUCCESS, "Your own password is set.".into()))
        };
    }

    pub fn handle(&mut self, key: Key) -> Action {
        match key {
            Key::Enter if !self.value.is_empty() => return Action::Accept,
            Key::Esc => return Action::Cancel,
            Key::Char('c') => return Action::Copy,
            Key::Char('e') => return Action::TypeOwn,
            Key::Char('w') => return Action::OwnWord,
            Key::Left | Key::Right | Key::Char(' ') if self.rows()[self.row] == Row::OwnWord => {
                return Action::OwnWord;
            }
            Key::Char('?') | Key::F(1) => return Action::Help,
            Key::Char('r') => self.regenerate(),
            Key::Char('v') => self.shown = !self.shown,
            Key::Up => self.row = self.row.saturating_sub(1),
            Key::Down | Key::Tab => self.row = (self.row + 1).min(self.rows().len() - 1),
            Key::BackTab => self.row = self.row.saturating_sub(1),
            Key::Left => self.adjust(-1),
            Key::Right | Key::Char(' ') => self.adjust(1),
            Key::PageUp => self.adjust(8),
            Key::PageDown => self.adjust(-8),
            _ => {}
        }
        Action::None
    }

    fn adjust(&mut self, d: i64) {
        let row = self.rows()[self.row];
        let p = &mut self.prefs;
        let step = |v: usize, lo: usize, hi: usize| (v as i64 + d).clamp(lo as i64, hi as i64) as usize;
        match row {
            Row::Kind => {
                p.passphrase = !p.passphrase;
                self.row = 0;
            }
            Row::Length => {
                p.password.length = step(p.password.length, generator::MIN_LENGTH, generator::MAX_LENGTH)
            }
            Row::Words => p.phrase.words = step(p.phrase.words, generator::MIN_WORDS, generator::MAX_WORDS),
            Row::Separator => {
                let i = SEPARATORS.iter().position(|s| *s == p.phrase.separator).unwrap_or(0) as i64;
                let n = SEPARATORS.len() as i64;
                p.phrase.separator = SEPARATORS[(i + d.signum()).rem_euclid(n) as usize].to_string();
            }
            Row::Lookalikes => p.password.exclude_lookalikes = !p.password.exclude_lookalikes,
            Row::OwnWord => return, // a dialog: see `handle`
            row => {
                let o = &mut p.password;
                let on = [o.uppercase, o.lowercase, o.digits, o.symbols].iter().filter(|&&b| b).count();
                let flag = match row {
                    Row::Upper => &mut o.uppercase,
                    Row::Lower => &mut o.lowercase,
                    Row::Digits => &mut o.digits,
                    _ => &mut o.symbols,
                };
                if *flag && on == 1 {
                    self.note = Some((Style::WARN, "Keep at least one kind of characters.".into()));
                    return;
                }
                *flag = !*flag;
            }
        }
        self.regenerate();
    }

    pub fn draw(&self, g: &mut Grid, area: Rect) -> Vec<Hint> {
        let w = area.w.saturating_sub(4).min(64);
        let rows = self.rows();
        let n = rows.len() as u16;
        // Roomy: blank lines and two lines for the password; else compact.
        let roomy = area.h >= n + 10;
        let h = if roomy { n + 10 } else { (n + 5).min(area.h) };
        let r = area.centered(w, h);
        g.dialog(r, "Password generator");
        let inner = r.inner();
        let (x, iw) = (inner.x + 2, inner.w.saturating_sub(4));
        let pw_y = inner.y + u16::from(roomy);
        let pw_lines: u16 = if roomy { 2 } else { 1 };
        // The password: dots (one per character) unless shown.
        let text: Zeroizing<String> = if self.shown {
            Zeroizing::new(self.value.to_string())
        } else {
            Zeroizing::new(std::iter::repeat_n(g.g.dot, self.value.chars().count()).collect())
        };
        let mut chars = text.chars();
        for line in 0..pw_lines {
            let mut col = 0;
            while col < iw {
                let Some(c) = chars.next() else { break };
                col += g.put_char(x + col, pw_y + line, c, Style::ACCENT_BOLD);
            }
        }
        if chars.next().is_some() {
            g.set(x + iw.saturating_sub(1), pw_y + pw_lines - 1, g.g.ellipsis, Style::DIM);
        }
        let strength = commands::strength_text(&self.value, self.bits);
        let show = if self.shown { "v hides" } else { "v shows" };
        g.print(x, pw_y + pw_lines, iw, &format!("{strength} · {show}"), Style::DIM);
        // The options.
        let o = &self.prefs.password;
        let check = |b: bool| if b { "[x]" } else { "[ ]" };
        let (l, rt) = (g.g.left, g.g.right);
        let top = pw_y + pw_lines + 1 + u16::from(roomy);
        for (i, row) in rows.iter().enumerate() {
            let y = top + i as u16;
            if y >= inner.bottom() {
                break;
            }
            let focused = i == self.row;
            let (label, value) = match row {
                Row::Kind => (
                    "Kind",
                    format!("{l} {} {rt}", if self.prefs.passphrase { "passphrase" } else { "password" }),
                ),
                Row::Length => ("Length", format!("{l} {} {rt}", o.length)),
                Row::Upper => ("Uppercase A-Z", check(o.uppercase).to_string()),
                Row::Lower => ("Lowercase a-z", check(o.lowercase).to_string()),
                Row::Digits => ("Digits 0-9", check(o.digits).to_string()),
                Row::Symbols => ("Symbols !#$%", check(o.symbols).to_string()),
                Row::Lookalikes => {
                    ("No look-alikes", format!("{} (0 O 1 l I |)", check(o.exclude_lookalikes)))
                }
                Row::Words => ("Words", format!("{l} {} {rt}", self.prefs.phrase.words)),
                Row::Separator => {
                    let sep = match self.prefs.phrase.separator.as_str() {
                        " " => "space",
                        s => s,
                    };
                    ("Separator", format!("{l} {sep} {rt}"))
                }
                // Like the password: dots unless shown with v.
                Row::OwnWord => (
                    "Own word",
                    match (self.prefs.own_word.chars().count(), self.shown) {
                        (0, _) => "(none) · w adds one".to_string(),
                        (_, true) => format!("{} · w changes", self.prefs.own_word.as_str()),
                        (n, false) => format!("{} · w changes", g.g.dot.to_string().repeat(n)),
                    },
                ),
            };
            if focused {
                g.set(inner.x + 1, y, g.g.marker, Style::ACCENT_BOLD);
            }
            let ls = if focused { Style::ACCENT_BOLD } else { Style::BOLD };
            g.print(x, y, 16, label, ls);
            g.print(
                x + 17,
                y,
                iw.saturating_sub(17),
                &value,
                if focused { Style::SELECTED } else { Style::PLAIN },
            );
        }
        if let Some((style, text)) = &self.note {
            g.print(x, inner.bottom() - 1, iw, text, *style);
        }
        let use_label = if self.target == GenTarget::Form { "use it" } else { "save as login" };
        vec![
            ("Enter", use_label),
            ("Esc", "cancel"),
            ("r", "new"),
            ("v", "show"),
            ("e", "own"),
            ("w", "own word"),
            ("c", "copy"),
            ("↑↓", "option"),
            ("←→", "change"),
            ("?", "help"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_change_the_password() {
        let mut g = Generator::new(GenTarget::Form, GenPrefs::default());
        assert_eq!(g.value.chars().count(), 24);
        g.handle(Key::Down); // length
        g.handle(Key::Right);
        assert_eq!(g.value.chars().count(), 25);
        g.handle(Key::PageDown);
        assert_eq!(g.value.chars().count(), 17);
        for _ in 0..10 {
            g.handle(Key::Left);
        }
        assert_eq!(g.prefs.password.length, generator::MIN_LENGTH, "never below the minimum");
        // Digits only: switching off the last kind is refused.
        for row in [2, 3, 5] {
            g.row = row;
            g.handle(Key::Char(' '));
        }
        assert!(g.value.chars().all(|c| c.is_ascii_digit()), "{}", g.value.as_str());
        g.row = 4;
        g.handle(Key::Char(' '));
        assert!(g.prefs.password.digits && g.note.is_some());
        // Passphrase mode.
        g.row = 0;
        g.handle(Key::Right);
        assert!(g.prefs.passphrase);
        assert!(g.value.split('-').count() >= 6, "six words (some words contain a dash)");
        g.handle(Key::Down);
        g.handle(Key::Right);
        g.handle(Key::Down);
        g.handle(Key::Right);
        assert_eq!(g.value.split('.').count(), 7);
        assert!(matches!(g.handle(Key::Enter), Action::Accept));
    }

    #[test]
    fn a_word_of_your_own() {
        let mut g = Generator::new(GenTarget::Form, GenPrefs::default());
        g.row = PASSWORD_ROWS.len() - 1;
        assert!(matches!(g.handle(Key::Right), Action::OwnWord), "←→ on its row asks for it");
        assert!(matches!(g.handle(Key::Char('w')), Action::OwnWord));
        let bits = g.bits;
        g.set_own_word("Justin");
        assert!(g.value.contains("Justin") && g.value.chars().count() == 30, "{}", g.value.as_str());
        assert_eq!(g.bits, bits, "the word adds no strength");
        assert!(matches!(&g.note, Some((Style::DIM, n)) if n.contains("random place")));
        g.handle(Key::Char('r'));
        assert!(g.value.contains("Justin"), "kept for the next one");
        // Not allowed: nothing changes.
        g.set_own_word("bad\u{1b}word");
        assert!(matches!(&g.note, Some((Style::ERROR, _))) && g.prefs.own_word.as_str() == "Justin");
        // In a passphrase it is one more word.
        g.row = 0;
        g.handle(Key::Right);
        assert!(g.value.split('-').any(|w| w == "Justin"), "{}", g.value.as_str());
        // Empty removes it.
        g.set_own_word("");
        assert!(!g.value.contains("Justin") && g.note.is_none());
        assert!(!format!("{:?}", g.prefs).contains("Justin"), "not in Debug");
    }

    #[test]
    fn regenerating_and_own_password() {
        let mut g = Generator::new(GenTarget::NewLogin, GenPrefs::default());
        let first = g.value.to_string();
        g.handle(Key::Char('r'));
        assert_ne!(g.value.as_str(), first);
        g.set_own("abc");
        assert_eq!((g.value.as_str(), g.bits), ("abc", None));
        assert!(matches!(&g.note, Some((Style::WARN, _))), "a weak own password gets a warning");
        assert!(matches!(g.handle(Key::Char('c')), Action::Copy));
        assert!(matches!(g.handle(Key::Esc), Action::Cancel));
    }
}
