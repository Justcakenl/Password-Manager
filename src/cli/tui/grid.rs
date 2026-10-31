//! The frame buffer: an in-memory grid of cells that every screen draws
//! into, and the diff that turns the previous and the next frame into the
//! bytes for the terminal (only the cells that changed are sent, in one
//! `write(2)`, so the screen never flickers).
//!
//! SECURITY: a frame can hold a secret the user revealed. Every cell is
//! overwritten with volatile writes (which the compiler cannot leave out)
//! whenever the grid is cleared and when it is dropped. The terminal code
//! keeps only the frame that is on screen; the other one is cleared right
//! after each frame is sent.

use zeroize::Zeroize;

use super::theme::{Glyphs, Style, Theme, ascii_for};

/// Marks the second column of a double-width character.
pub const CONT: char = '\0';

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cell {
    pub ch: char,
    pub style: Style,
}

const BLANK: Cell = Cell { ch: ' ', style: Style::PLAIN };

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

impl Rect {
    pub fn new(x: u16, y: u16, w: u16, h: u16) -> Rect {
        Rect { x, y, w, h }
    }
    /// The area inside a one-cell border.
    pub fn inner(self) -> Rect {
        Rect::new(self.x + 1, self.y + 1, self.w.saturating_sub(2), self.h.saturating_sub(2))
    }
    pub fn bottom(self) -> u16 {
        self.y + self.h
    }
    /// A `w` × `h` rectangle centered in this one.
    pub fn centered(self, w: u16, h: u16) -> Rect {
        let (w, h) = (w.min(self.w), h.min(self.h));
        Rect::new(self.x + (self.w - w) / 2, self.y + (self.h - h) / 2, w, h)
    }
}

pub struct Grid {
    w: u16,
    h: u16,
    cells: Vec<Cell>,
    cursor: Option<(u16, u16)>,
    pub g: &'static Glyphs,
}

impl Grid {
    pub fn new(w: u16, h: u16, g: &'static Glyphs) -> Grid {
        Grid { w, h, cells: vec![BLANK; w as usize * h as usize], cursor: None, g }
    }

    pub fn width(&self) -> u16 {
        self.w
    }

    pub fn height(&self) -> u16 {
        self.h
    }

    #[cfg(test)]
    pub fn area(&self) -> Rect {
        Rect::new(0, 0, self.w, self.h)
    }

    /// Make every cell blank again, wiping what was there.
    pub fn clear(&mut self) {
        for c in &mut self.cells {
            c.ch.zeroize();
            *c = BLANK;
        }
        self.cursor = None;
    }

    pub fn get(&self, x: u16, y: u16) -> Cell {
        self.cells[y as usize * self.w as usize + x as usize]
    }

    fn put(&mut self, x: u16, y: u16, ch: char, style: Style) {
        if x < self.w && y < self.h {
            self.cells[y as usize * self.w as usize + x as usize] = Cell { ch, style };
        }
    }

    /// Put one (single-width) character.
    pub fn set(&mut self, x: u16, y: u16, ch: char, style: Style) {
        self.put(x, y, ch, style);
    }

    /// Put one character; a wide one takes two columns. Returns its width.
    pub fn put_char(&mut self, x: u16, y: u16, ch: char, style: Style) -> u16 {
        let cw = char_width(ch) as u16;
        if cw == 2 && x + 1 < self.w {
            self.put(x, y, ch, style);
            self.put(x + 1, y, CONT, style);
        } else if cw == 1 {
            self.put(x, y, ch, style);
        }
        cw
    }

    /// Where the text cursor should be shown (only in a text field).
    pub fn set_cursor(&mut self, pos: Option<(u16, u16)>) {
        self.cursor = pos.filter(|&(x, y)| x < self.w && y < self.h);
    }

    #[cfg(test)]
    pub fn cursor(&self) -> Option<(u16, u16)> {
        self.cursor
    }

    /// Draw `text` from column `x`, at most `max` columns wide. Text that
    /// does not fit ends in "…". A tab becomes a space; other control
    /// characters are shown as "?" (stored fields cannot contain them, this
    /// is a safety net) and zero-width characters are left out. Returns the
    /// number of columns used.
    pub fn print(&mut self, x: u16, y: u16, max: u16, text: &str, style: Style) -> u16 {
        let max = max.min(self.w.saturating_sub(x));
        if max == 0 || y >= self.h {
            return 0;
        }
        let fits = str_width(text) <= max as usize;
        let limit = if fits { max } else { max - 1 };
        let mut col = 0u16;
        for ch in text.chars() {
            let ch = match ch {
                '\t' => ' ',
                c if c.is_control() => '?',
                c if self.g.ascii => ascii_for(c),
                c => c,
            };
            let cw = char_width(ch) as u16;
            if cw == 0 {
                continue;
            }
            if col + cw > limit {
                break;
            }
            self.put(x + col, y, ch, style);
            if cw == 2 {
                self.put(x + col + 1, y, CONT, style);
            }
            col += cw;
        }
        if !fits {
            // Pad a gap left by a wide character, then the ellipsis.
            while col < limit {
                self.put(x + col, y, ' ', style);
                col += 1;
            }
            self.put(x + col, y, self.g.ellipsis, style);
            col += 1;
        }
        col
    }

    /// Fill a rectangle with blanks in `style`.
    pub fn fill(&mut self, r: Rect, style: Style) {
        for y in r.y..r.bottom().min(self.h) {
            for x in r.x..(r.x + r.w).min(self.w) {
                self.put(x, y, ' ', style);
            }
        }
    }

    /// A horizontal line from `x` over `w` columns.
    pub fn hline(&mut self, x: u16, y: u16, w: u16, style: Style) {
        for i in 0..w {
            self.put(x + i, y, self.g.h, style);
        }
    }

    /// A box around `r`, with an optional title in the top border.
    pub fn frame(&mut self, r: Rect, title: &str, style: Style, title_style: Style) {
        if r.w < 2 || r.h < 2 {
            return;
        }
        let (right, bottom) = (r.x + r.w - 1, r.y + r.h - 1);
        self.hline(r.x + 1, r.y, r.w - 2, style);
        self.hline(r.x + 1, bottom, r.w - 2, style);
        for y in r.y + 1..bottom {
            self.put(r.x, y, self.g.v, style);
            self.put(right, y, self.g.v, style);
        }
        self.put(r.x, r.y, self.g.tl, style);
        self.put(right, r.y, self.g.tr, style);
        self.put(r.x, bottom, self.g.bl, style);
        self.put(right, bottom, self.g.br, style);
        if !title.is_empty() && r.w > 7 {
            self.put(r.x + 2, r.y, ' ', style);
            let n = self.print(r.x + 3, r.y, r.w - 6, title, title_style);
            self.put(r.x + 3 + n, r.y, ' ', style);
        }
    }

    /// A box with a blank inside and a blank margin around it (for dialogs
    /// on top of the screen).
    pub fn dialog(&mut self, r: Rect, title: &str) {
        let x = r.x.saturating_sub(1);
        let y = r.y.saturating_sub(1);
        self.fill(Rect::new(x, y, r.x + r.w + 1 - x, r.y + r.h + 1 - y), Style::PLAIN);
        self.frame(r, title, Style::ACCENT, Style::ACCENT_BOLD);
    }

    /// One row as text (for tests and the pseudo-terminal checks).
    #[cfg(test)]
    pub fn row(&self, y: u16) -> String {
        (0..self.w).map(|x| self.get(x, y).ch).filter(|&c| c != CONT).collect()
    }

    /// The whole frame as text, one line per row.
    #[cfg(test)]
    pub fn text(&self) -> String {
        (0..self.h).map(|y| self.row(y).trim_end().to_string()).collect::<Vec<_>>().join("\n")
    }
}

impl Drop for Grid {
    fn drop(&mut self) {
        for c in &mut self.cells {
            c.ch.zeroize();
        }
    }
}

/// Columns a character takes in a terminal: 0 (combining marks and other
/// zero-width characters), 2 (East Asian wide, most emoji) or 1.
pub fn char_width(c: char) -> usize {
    let u = c as u32;
    const ZERO: &[(u32, u32)] = &[
        (0x0300, 0x036F),
        (0x0483, 0x0489),
        (0x0591, 0x05BD),
        (0x0610, 0x061A),
        (0x064B, 0x065F),
        (0x0E31, 0x0E31),
        (0x0E34, 0x0E3A),
        (0x1AB0, 0x1AFF),
        (0x1DC0, 0x1DFF),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x2064),
        (0x20D0, 0x20FF),
        (0xFE00, 0xFE0F),
        (0xFE20, 0xFE2F),
        (0xFEFF, 0xFEFF),
        (0xE0000, 0xE0FFF),
    ];
    const WIDE: &[(u32, u32)] = &[
        (0x1100, 0x115F),
        (0x231A, 0x231B),
        (0x2329, 0x232A),
        (0x23E9, 0x23EC),
        (0x25FD, 0x25FE),
        (0x2614, 0x2615),
        (0x2648, 0x2653),
        (0x26AA, 0x26AB),
        (0x26BD, 0x26BE),
        (0x26C4, 0x26C5),
        (0x26F2, 0x26F5),
        (0x26FA, 0x26FD),
        (0x2705, 0x2705),
        (0x270A, 0x270B),
        (0x274C, 0x274C),
        (0x2753, 0x2757),
        (0x2795, 0x2797),
        (0x2B1B, 0x2B1C),
        (0x2E80, 0x303E),
        (0x3041, 0x33FF),
        (0x3400, 0x4DBF),
        (0x4E00, 0x9FFF),
        (0xA000, 0xA4CF),
        (0xA960, 0xA97F),
        (0xAC00, 0xD7A3),
        (0xF900, 0xFAFF),
        (0xFE10, 0xFE19),
        (0xFE30, 0xFE6F),
        (0xFF00, 0xFF60),
        (0xFFE0, 0xFFE6),
        (0x1F004, 0x1F004),
        (0x1F0CF, 0x1F0CF),
        (0x1F18E, 0x1F18E),
        (0x1F191, 0x1F19A),
        (0x1F200, 0x1F251),
        (0x1F300, 0x1F64F),
        (0x1F680, 0x1F6FF),
        (0x1F7E0, 0x1F7EB),
        (0x1F90C, 0x1F9FF),
        (0x1FA70, 0x1FAFF),
        (0x20000, 0x3FFFD),
    ];
    let within = |table: &[(u32, u32)]| table.iter().any(|&(lo, hi)| (lo..=hi).contains(&u));
    if u < 0x20 || (0x7F..0xA0).contains(&u) || within(ZERO) {
        0
    } else if within(WIDE) {
        2
    } else {
        1
    }
}

/// Columns a string takes (see [`char_width`]; control characters count as 1).
pub fn str_width(s: &str) -> usize {
    s.chars().map(|c| if c.is_control() { 1 } else { char_width(c) }).sum()
}

/// Append to `out` the bytes that change the terminal from `prev` to `next`
/// (both the same size). With `full` the screen is cleared and drawn again.
pub fn diff(prev: &Grid, next: &Grid, full: bool, theme: &Theme, out: &mut Vec<u8>) {
    debug_assert!(prev.w == next.w && prev.h == next.h);
    out.extend_from_slice(b"\x1b[?25l");
    if full {
        out.extend_from_slice(b"\x1b[0m\x1b[H\x1b[2J");
    }
    let mut style: Option<Style> = None;
    let mut at: Option<(u16, u16)> = None;
    let mut utf8 = [0u8; 4];
    for y in 0..next.h {
        let mut x = 0;
        while x < next.w {
            let cell = next.get(x, y);
            if cell.ch == CONT || (!full && prev.get(x, y) == cell) {
                x += 1;
                continue;
            }
            if at != Some((x, y)) {
                out.extend_from_slice(format!("\x1b[{};{}H", y + 1, x + 1).as_bytes());
            }
            if style != Some(cell.style) {
                theme.sgr(cell.style, out);
                style = Some(cell.style);
            }
            out.extend_from_slice(cell.ch.encode_utf8(&mut utf8).as_bytes());
            x += char_width(cell.ch).max(1) as u16;
            at = Some((x, y));
        }
    }
    utf8.zeroize();
    out.extend_from_slice(b"\x1b[0m");
    if let Some((x, y)) = next.cursor {
        out.extend_from_slice(format!("\x1b[{};{}H\x1b[?25h", y + 1, x + 1).as_bytes());
    }
}

/// Split `text` into lines of at most `width` columns, breaking at spaces
/// where possible.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    for para in text.split('\n') {
        let mut line = String::new();
        let mut line_w = 0;
        for word in para.split(' ') {
            let ww = str_width(word);
            if line_w > 0 && line_w + 1 + ww > width {
                lines.push(std::mem::take(&mut line));
                line_w = 0;
            }
            if line_w > 0 {
                line.push(' ');
                line_w += 1;
            }
            // A word longer than the line is cut into pieces.
            for c in word.chars() {
                let cw = char_width(c);
                if line_w + cw > width && line_w > 0 {
                    lines.push(std::mem::take(&mut line));
                    line_w = 0;
                }
                line.push(c);
                line_w += cw;
            }
        }
        lines.push(line);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::super::theme::{ASCII, UNICODE};
    use super::*;

    const MONO: Theme = Theme { color: false, unicode: true };

    #[test]
    fn widths() {
        assert_eq!(char_width('a'), 1);
        assert_eq!(char_width('é'), 1);
        assert_eq!(char_width('\u{301}'), 0, "combining accent");
        assert_eq!(char_width('中'), 2);
        assert_eq!(char_width('🍰'), 2);
        assert_eq!(char_width('•'), 1);
        assert_eq!(str_width("ab中"), 4);
    }

    #[test]
    fn printing_clips_and_marks_truncation() {
        let mut g = Grid::new(10, 2, &UNICODE);
        assert_eq!(g.print(0, 0, 10, "hello", Style::PLAIN), 5);
        assert_eq!(g.row(0), "hello     ");
        assert_eq!(g.print(0, 1, 6, "truncated", Style::PLAIN), 6);
        assert_eq!(g.row(1), "trunc…    ");
        // A wide character never ends up half outside the area.
        let mut g = Grid::new(6, 1, &ASCII);
        g.print(0, 0, 4, "中中中", Style::PLAIN);
        assert_eq!(g.row(0), "中 ~  ");
        let mut g = Grid::new(10, 1, &ASCII);
        g.print(2, 0, 10, "a\u{1b}[2Jb\u{301}", Style::PLAIN);
        assert_eq!(g.row(0), "  a?[2Jb  ", "escape made harmless, combining mark dropped");
    }

    #[test]
    fn frames_and_text() {
        let mut g = Grid::new(12, 3, &UNICODE);
        g.frame(g.area(), "Items", Style::PLAIN, Style::PLAIN);
        assert_eq!(g.text(), "┌─ Items ──┐\n│          │\n└──────────┘");
        let mut a = Grid::new(5, 3, &ASCII);
        a.frame(a.area(), "", Style::PLAIN, Style::PLAIN);
        assert_eq!(a.text(), "+---+\n|   |\n+---+");
    }

    fn diff_text(prev: &Grid, next: &Grid, full: bool) -> String {
        let mut out = Vec::new();
        diff(prev, next, full, &MONO, &mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn diff_sends_only_changes() {
        let a = Grid::new(10, 3, &UNICODE);
        let mut b = Grid::new(10, 3, &UNICODE);
        assert_eq!(diff_text(&a, &b, false), "\x1b[?25l\x1b[0m", "nothing changed: nothing drawn");
        b.print(2, 1, 8, "hi", Style::PLAIN);
        assert_eq!(diff_text(&a, &b, false), "\x1b[?25l\x1b[2;3H\x1b[0mhi\x1b[0m");
        // Two separate changes on a row: two cursor moves, the style is set once.
        b.print(7, 1, 3, "x", Style::PLAIN);
        let d = diff_text(&a, &b, false);
        assert_eq!(d, "\x1b[?25l\x1b[2;3H\x1b[0mhi\x1b[2;8Hx\x1b[0m");
        // A full redraw clears first and writes every cell.
        let full = diff_text(&a, &b, true);
        assert!(full.starts_with("\x1b[?25l\x1b[0m\x1b[H\x1b[2J\x1b[1;1H"));
        assert_eq!(full.matches(' ').count(), 30 - 3);
        // The cursor is shown only when a text field asks for it.
        b.set_cursor(Some((4, 1)));
        assert!(diff_text(&a, &b, false).ends_with("\x1b[2;5H\x1b[?25h"));
    }

    #[test]
    fn diff_handles_wide_characters() {
        let mut a = Grid::new(6, 1, &UNICODE);
        a.print(0, 0, 6, "中x", Style::PLAIN);
        let mut b = Grid::new(6, 1, &UNICODE);
        b.print(0, 0, 6, "ab", Style::PLAIN);
        // Replacing a wide character rewrites both of its columns.
        assert_eq!(diff_text(&a, &b, false), "\x1b[?25l\x1b[1;1H\x1b[0mab \x1b[0m");
        let d = diff_text(&b, &a, false);
        assert_eq!(d, "\x1b[?25l\x1b[1;1H\x1b[0m中x\x1b[0m", "the cursor advances two columns");
    }

    #[test]
    fn clearing_wipes_the_cells() {
        let mut g = Grid::new(8, 1, &UNICODE);
        g.print(0, 0, 8, "s3cret", Style::PLAIN);
        g.clear();
        assert_eq!(g.row(0), "        ");
        assert!(g.cursor().is_none());
    }

    #[test]
    fn wrapping() {
        assert_eq!(wrap("the quick brown fox", 9), ["the quick", "brown fox"]);
        assert_eq!(wrap("abcdefghij", 4), ["abcd", "efgh", "ij"]);
        assert_eq!(wrap("a\nb", 10), ["a", "b"]);
        assert_eq!(Rect::new(0, 0, 80, 24).centered(20, 4), Rect::new(30, 10, 20, 4));
    }
}
