//! Colors and line-drawing characters of the screen mode.
//!
//! The colors are those of the rest of CakePass (pink 211/205 on a
//! 256-color terminal). With `--no-color` or `NO_COLOR` only bold, underline
//! and reverse video are used: a selected row or the title bar is then shown
//! in reverse video instead of pink. Box-drawing characters (`┌─┐`) are used
//! when the locale is UTF-8, otherwise plain ASCII (`+-|`).

use cakepass::vault::Kind;

/// How one cell looks. `fg`/`bg` are 256-color palette indexes, 0 = the
/// terminal's default color.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Style {
    pub fg: u8,
    pub bg: u8,
    pub attrs: u8,
}

pub const BOLD: u8 = 1;
pub const UNDERLINE: u8 = 2;
pub const REVERSE: u8 = 4;

const PINK: u8 = 211;
const HOT_PINK: u8 = 205;
const SOFT_PINK: u8 = 175;
const BLACK: u8 = 16;
const WHITE: u8 = 231;
const GRAY: u8 = 245;
const RED: u8 = 203;
const GREEN: u8 = 114;
const YELLOW: u8 = 221;
const BLUE: u8 = 117;
const SAND: u8 = 222;

impl Style {
    const fn new(fg: u8, bg: u8, attrs: u8) -> Style {
        Style { fg, bg, attrs }
    }
    pub const PLAIN: Style = Style::new(0, 0, 0);
    pub const BOLD: Style = Style::new(0, 0, BOLD);
    /// Pink text (the CakePass accent).
    pub const ACCENT: Style = Style::new(PINK, 0, 0);
    pub const ACCENT_BOLD: Style = Style::new(HOT_PINK, 0, BOLD);
    /// Gray text for hints and less important information.
    pub const DIM: Style = Style::new(GRAY, 0, 0);
    pub const BORDER: Style = Style::new(SOFT_PINK, 0, 0);
    /// The selected row or button: a pink bar (reverse video without color).
    pub const SELECTED: Style = Style::new(BLACK, PINK, BOLD);
    pub const TITLE: Style = Style::new(WHITE, HOT_PINK, BOLD);
    pub const ERROR: Style = Style::new(RED, 0, BOLD);
    pub const SUCCESS: Style = Style::new(GREEN, 0, BOLD);
    pub const WARN: Style = Style::new(YELLOW, 0, BOLD);
    pub const ACTIVE_TAB: Style = Style::new(HOT_PINK, 0, BOLD | UNDERLINE);
    /// The text field you are typing in.
    pub const FIELD: Style = Style::new(0, 0, UNDERLINE);

    /// The color of an item type (as in `cakepass list`).
    pub fn kind(kind: Kind) -> Style {
        match kind {
            Kind::Login => Style::new(PINK, 0, 0),
            Kind::Api => Style::new(BLUE, 0, 0),
            Kind::Note => Style::new(SAND, 0, 0),
        }
    }
}

/// The characters used for lines, masks and markers.
#[derive(Debug)]
pub struct Glyphs {
    pub h: char,
    pub v: char,
    pub tl: char,
    pub tr: char,
    pub bl: char,
    pub br: char,
    /// ┬ ┴ ├ ┤
    pub tee_down: char,
    pub tee_up: char,
    pub tee_right: char,
    pub tee_left: char,
    /// The masking dot for hidden secrets.
    pub dot: char,
    pub ellipsis: char,
    pub left: char,
    pub right: char,
    pub marker: char,
    pub check: char,
    pub cross: char,
    pub up_down: &'static str,
    pub left_right: &'static str,
    /// Plain ASCII only: other symbols are replaced when drawn (see `ascii_for`).
    pub ascii: bool,
}

pub static UNICODE: Glyphs = Glyphs {
    h: '─',
    v: '│',
    tl: '┌',
    tr: '┐',
    bl: '└',
    br: '┘',
    tee_down: '┬',
    tee_up: '┴',
    tee_right: '├',
    tee_left: '┤',
    dot: '•',
    ellipsis: '…',
    left: '‹',
    right: '›',
    marker: '▌',
    check: '✔',
    cross: '✖',
    up_down: "↑↓",
    left_right: "←→",
    ascii: false,
};

pub static ASCII: Glyphs = Glyphs {
    h: '-',
    v: '|',
    tl: '+',
    tr: '+',
    bl: '+',
    br: '+',
    tee_down: '+',
    tee_up: '+',
    tee_right: '+',
    tee_left: '+',
    dot: '*',
    ellipsis: '~',
    left: '<',
    right: '>',
    marker: '>',
    check: '+',
    cross: 'x',
    up_down: "Up/Down",
    left_right: "Left/Right",
    ascii: true,
};

/// An ASCII stand-in for the symbols the screens use, for terminals
/// without UTF-8. Other characters are left alone.
pub fn ascii_for(c: char) -> char {
    match c {
        '↑' => '^',
        '↓' => 'v',
        '←' | '‹' => '<',
        '→' | '›' => '>',
        '·' | '│' => '|',
        '…' => '~',
        '×' => 'x',
        '–' | '—' | '─' => '-',
        '•' => '*',
        '✔' => '+',
        '✖' => 'x',
        '▌' => '>',
        c => c,
    }
}

/// Color and character set, chosen once at startup.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub color: bool,
    pub unicode: bool,
}

impl Theme {
    /// `color`: whether colors are allowed (see `ui::init`).
    pub fn detect(color: bool) -> Theme {
        Theme { color, unicode: locale_is_utf8(|k| std::env::var(k).ok()) }
    }

    pub fn glyphs(&self) -> &'static Glyphs {
        if self.unicode { &UNICODE } else { &ASCII }
    }

    /// Append the escape sequence that selects `style`. Always starts from a
    /// reset, so the result never depends on what came before.
    pub fn sgr(&self, style: Style, out: &mut Vec<u8>) {
        let mut attrs = style.attrs;
        if !self.color && style.bg != 0 {
            attrs |= REVERSE;
        }
        out.extend_from_slice(b"\x1b[0");
        for (bit, code) in [(BOLD, &b";1"[..]), (UNDERLINE, b";4"), (REVERSE, b";7")] {
            if attrs & bit != 0 {
                out.extend_from_slice(code);
            }
        }
        if self.color {
            for (layer, c) in [("38", style.fg), ("48", style.bg)] {
                if c != 0 {
                    out.extend_from_slice(format!(";{layer};5;{c}").as_bytes());
                }
            }
        }
        out.push(b'm');
    }
}

/// Whether the locale says UTF-8 (LC_ALL, then LC_CTYPE, then LANG: the first
/// one that is set decides, as in the C library).
fn locale_is_utf8(var: impl Fn(&str) -> Option<String>) -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"].iter().find_map(|k| var(k).filter(|v| !v.is_empty())).is_some_and(|v| {
        let v = v.to_lowercase();
        v.contains("utf-8") || v.contains("utf8")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sgr(theme: Theme, s: Style) -> String {
        let mut out = Vec::new();
        theme.sgr(s, &mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn colors_and_no_color() {
        let color = Theme { color: true, unicode: true };
        let mono = Theme { color: false, unicode: true };
        assert_eq!(sgr(color, Style::ACCENT), "\x1b[0;38;5;211m");
        assert_eq!(sgr(color, Style::SELECTED), "\x1b[0;1;38;5;16;48;5;211m");
        assert_eq!(sgr(mono, Style::ACCENT), "\x1b[0m", "no color: plain text");
        assert_eq!(sgr(mono, Style::SELECTED), "\x1b[0;1;7m", "no color: reverse video");
        assert_eq!(sgr(mono, Style::ACTIVE_TAB), "\x1b[0;1;4m");
    }

    #[test]
    fn utf8_locale_detection() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
        };
        assert!(locale_is_utf8(env(&[("LANG", "en_US.UTF-8")])));
        assert!(locale_is_utf8(env(&[("LC_ALL", "C.utf8"), ("LANG", "C")])));
        assert!(!locale_is_utf8(env(&[("LC_ALL", "C"), ("LANG", "en_US.UTF-8")])), "LC_ALL wins");
        assert!(locale_is_utf8(env(&[("LC_ALL", ""), ("LANG", "nl_NL.UTF-8")])), "empty is unset");
        assert!(!locale_is_utf8(env(&[("LANG", "POSIX")])));
        assert!(!locale_is_utf8(env(&[])));
    }
}
