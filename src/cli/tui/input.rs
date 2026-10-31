//! A text field: single-line (names, passwords, the search) or multi-line
//! (notes), with the usual editing keys.
//!
//! The text is UTF-8 and the cursor is a byte offset that is always on a
//! character boundary; moving and deleting go one character at a time.
//!
//! SECURITY: the text lives in `Zeroizing` memory. When characters are
//! deleted, the bytes they leave behind at the end of the buffer are wiped
//! right away, not only when the field is dropped.

use std::cell::Cell;

use zeroize::{Zeroize, Zeroizing};

use super::grid::{Grid, Rect, char_width};
use super::keys::Key;
use super::theme::Style;

/// The largest text a field accepts (the limit of the vault, 64 KiB).
const MAX_BYTES: usize = 64 * 1024;

pub struct TextInput {
    text: Zeroizing<String>,
    cursor: usize,
    multiline: bool,
    /// First visible column / line, kept between frames so the view does
    /// not jump while you move the cursor.
    scroll_x: Cell<usize>,
    scroll_y: Cell<usize>,
}

impl TextInput {
    pub fn new(multiline: bool) -> TextInput {
        TextInput {
            text: Zeroizing::new(String::with_capacity(64)),
            cursor: 0,
            multiline,
            scroll_x: Cell::new(0),
            scroll_y: Cell::new(0),
        }
    }

    #[cfg(test)]
    pub fn with_text(text: &str, multiline: bool) -> TextInput {
        let mut t = TextInput::new(multiline);
        t.set(text);
        t
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Replace the text (the old text is wiped); the cursor goes to the end.
    pub fn set(&mut self, text: &str) {
        self.clear();
        self.insert_str(text);
    }

    pub fn clear(&mut self) {
        self.text.zeroize();
        self.cursor = 0;
        self.scroll_x.set(0);
        self.scroll_y.set(0);
    }

    /// Wipe the unused part of the buffer (after deleting characters).
    fn wipe_spare(&mut self) {
        let mut bytes = std::mem::take(&mut *self.text).into_bytes();
        bytes.spare_capacity_mut().zeroize();
        *self.text = String::from_utf8(bytes).expect("the text stays valid UTF-8");
    }

    /// Type one character. Control characters are refused, except a
    /// newline or tab in a multi-line field.
    pub fn insert(&mut self, c: char) -> bool {
        let allowed = !c.is_control() || (self.multiline && (c == '\n' || c == '\t'));
        if !allowed || self.text.len() + c.len_utf8() > MAX_BYTES {
            return false;
        }
        self.text.insert(self.cursor, c);
        self.cursor += c.len_utf8();
        true
    }

    /// Insert pasted text. In a single-line field line breaks and tabs
    /// become spaces and a final line break is dropped; other control
    /// characters are always left out.
    pub fn insert_str(&mut self, s: &str) -> bool {
        let s = if self.multiline { s } else { s.trim_end_matches(['\r', '\n']) };
        let mut changed = false;
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            let c = match c {
                '\r' => {
                    if chars.peek() == Some(&'\n') {
                        chars.next(); // \r\n counts as one line break
                    }
                    if self.multiline { '\n' } else { ' ' }
                }
                '\n' | '\t' if !self.multiline => ' ',
                c => c,
            };
            changed |= self.insert(c);
        }
        changed
    }

    pub fn backspace(&mut self) -> bool {
        let Some(c) = self.text[..self.cursor].chars().next_back() else { return false };
        self.cursor -= c.len_utf8();
        self.text.remove(self.cursor);
        self.wipe_spare();
        true
    }

    pub fn delete(&mut self) -> bool {
        if self.cursor >= self.text.len() {
            return false;
        }
        self.text.remove(self.cursor);
        self.wipe_spare();
        true
    }

    pub fn left(&mut self) {
        if let Some(c) = self.text[..self.cursor].chars().next_back() {
            self.cursor -= c.len_utf8();
        }
    }

    pub fn right(&mut self) {
        if let Some(c) = self.text[self.cursor..].chars().next() {
            self.cursor += c.len_utf8();
        }
    }

    fn line_start(&self) -> usize {
        self.text[..self.cursor].rfind('\n').map_or(0, |i| i + 1)
    }

    fn line_end(&self) -> usize {
        self.text[self.cursor..].find('\n').map_or(self.text.len(), |i| self.cursor + i)
    }

    /// To the start of the (current) line.
    pub fn home(&mut self) {
        self.cursor = if self.multiline { self.line_start() } else { 0 };
    }

    pub fn end(&mut self) {
        self.cursor = if self.multiline { self.line_end() } else { self.text.len() };
    }

    /// Display column of the cursor within its line.
    fn column(&self) -> usize {
        self.text[self.line_start()..self.cursor].chars().map(char_width).sum()
    }

    /// Put the cursor in the line that starts at byte `start`, as close to
    /// display column `col` as possible.
    fn goto_column(&mut self, start: usize, col: usize) {
        let mut pos = start;
        let mut w = 0;
        for c in self.text[start..].chars() {
            if c == '\n' || w + char_width(c) > col {
                break;
            }
            w += char_width(c);
            pos += c.len_utf8();
        }
        self.cursor = pos;
    }

    /// One line up (multi-line only). False when already on the first line.
    pub fn up(&mut self) -> bool {
        let start = self.line_start();
        if !self.multiline || start == 0 {
            return false;
        }
        let col = self.column();
        let prev_start = self.text[..start - 1].rfind('\n').map_or(0, |i| i + 1);
        self.goto_column(prev_start, col);
        true
    }

    /// One line down (multi-line only). False when already on the last line.
    pub fn down(&mut self) -> bool {
        let end = self.line_end();
        if !self.multiline || end >= self.text.len() {
            return false;
        }
        let col = self.column();
        self.goto_column(end + 1, col);
        true
    }

    /// Handle an editing key. Returns whether the text changed.
    /// (Up and Down are left to the caller, which may move to another field.)
    pub fn edit(&mut self, key: Key) -> bool {
        match key {
            Key::Char(c) => self.insert(c),
            Key::Enter if self.multiline => self.insert('\n'),
            Key::Backspace => self.backspace(),
            Key::Delete => self.delete(),
            Key::Left => {
                self.left();
                false
            }
            Key::Right => {
                self.right();
                false
            }
            Key::Home | Key::Ctrl('a') => {
                self.home();
                false
            }
            Key::End | Key::Ctrl('e') => {
                self.end();
                false
            }
            Key::Ctrl('u') => {
                let had = !self.text.is_empty();
                self.clear();
                had
            }
            _ => false,
        }
    }

    /// Draw the field into `r`. With `mask`, every character is shown as
    /// that character (one per character typed, nothing else). Returns
    /// where the cursor is, for a focused field.
    pub fn draw(&self, grid: &mut Grid, r: Rect, style: Style, mask: Option<char>) -> (u16, u16) {
        let width = r.w.max(1) as usize;
        let lines: Vec<&str> =
            if self.multiline { self.text.split('\n').collect() } else { vec![&self.text] };
        let cur_line = if self.multiline { self.text[..self.cursor].matches('\n').count() } else { 0 };
        let col = match mask {
            Some(_) => self.text[..self.cursor].chars().count(),
            None => self.column(),
        };
        // Keep the cursor inside the visible window.
        let (mut sx, mut sy) = (self.scroll_x.get(), self.scroll_y.get());
        if col < sx {
            sx = col;
        } else if col >= sx + width {
            sx = col + 1 - width;
        }
        let rows = r.h.max(1) as usize;
        if cur_line < sy {
            sy = cur_line;
        } else if cur_line >= sy + rows {
            sy = cur_line + 1 - rows;
        }
        self.scroll_x.set(sx);
        self.scroll_y.set(sy);
        for (row, line) in lines.iter().skip(sy).take(rows).enumerate() {
            let y = r.y + row as u16;
            let mut x = 0usize; // display column within the line
            for c in line.chars() {
                let c = match (mask, c) {
                    (Some(m), _) => m,
                    (None, '\t') => ' ',
                    (None, c) => c,
                };
                let cw = char_width(c);
                if x >= sx && x + cw <= sx + width {
                    grid.put_char(r.x + (x - sx) as u16, y, c, style);
                } else if x >= sx + width {
                    break;
                }
                x += cw;
            }
        }
        (r.x + (col - sx) as u16, r.y + (cur_line - sy) as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::super::theme::UNICODE;
    use super::*;

    fn typed(s: &str) -> TextInput {
        let mut t = TextInput::new(false);
        for c in s.chars() {
            t.insert(c);
        }
        t
    }

    #[test]
    fn editing_respects_utf8_boundaries() {
        let mut t = typed("aé中🍰");
        assert_eq!(t.as_str(), "aé中🍰");
        t.left();
        t.backspace();
        assert_eq!(t.as_str(), "aé🍰");
        t.home();
        t.right();
        t.delete();
        assert_eq!(t.as_str(), "a🍰");
        t.insert('ö');
        assert_eq!(t.as_str(), "aö🍰");
        t.end();
        t.right(); // at the end: stays
        assert!(!t.delete());
        assert!(t.backspace());
        assert_eq!(t.as_str(), "aö");
        t.home();
        assert!(!t.backspace(), "nothing before the start");
        assert!(!t.insert('\u{1b}'), "control characters are refused");
        assert!(!t.insert('\n'), "no newline in a single-line field");
    }

    #[test]
    fn pasting() {
        let mut t = TextInput::new(false);
        t.insert_str("sk-live-123\r\n");
        assert_eq!(t.as_str(), "sk-live-123", "final line break dropped");
        t.set("a\tb\nc\x07d");
        assert_eq!(t.as_str(), "a b cd");
        let mut m = TextInput::new(true);
        m.insert_str("line 1\r\nline 2\rline 3\n\ttab\x1b");
        assert_eq!(m.as_str(), "line 1\nline 2\nline 3\n\ttab");
    }

    #[test]
    fn multiline_movement() {
        let mut m = TextInput::with_text("first line\nab\nthird", true);
        assert!(!m.down(), "already on the last line");
        m.end();
        assert!(m.up());
        assert_eq!(&m.as_str()[..m.cursor], "first line\nab", "column clamped to the short line");
        assert!(m.up());
        assert_eq!(m.cursor, 2);
        assert!(!m.up());
        m.home();
        assert!(m.down() && m.down());
        m.edit(Key::Enter);
        m.edit(Key::Char('x'));
        assert_eq!(m.as_str(), "first line\nab\n\nxthird");
        assert!(!TextInput::with_text("x", false).up());
    }

    #[test]
    fn deleted_bytes_are_wiped() {
        let mut t = typed("hunter2");
        while t.backspace() {}
        let spare: Vec<u8> = {
            let mut bytes = std::mem::take(&mut *t.text).into_bytes();
            let cap = bytes.capacity();
            // SAFETY: wipe_spare wrote zeros over the whole spare capacity.
            unsafe { bytes.set_len(cap) };
            bytes.into_iter().take(7).collect()
        };
        assert_eq!(spare, [0; 7]);
    }

    #[test]
    fn drawing_scrolls_and_masks() {
        let mut g = Grid::new(10, 3, &UNICODE);
        let t = typed("abcdefghijkl");
        let cur = t.draw(&mut g, Rect::new(0, 0, 5, 1), Style::PLAIN, None);
        assert_eq!(g.row(0), "ijkl      ", "the end (and the cursor after it) is visible");
        assert_eq!(cur, (4, 0));
        let mut g = Grid::new(10, 1, &UNICODE);
        let pw = typed("s3cr€t");
        pw.draw(&mut g, Rect::new(0, 0, 10, 1), Style::PLAIN, Some('•'));
        assert_eq!(g.row(0), "••••••    ", "one dot per character, never the text");
        let mut g = Grid::new(8, 2, &UNICODE);
        let mut m = TextInput::with_text("one\ntwo\nthree", true);
        m.up();
        let cur = m.draw(&mut g, Rect::new(1, 0, 6, 2), Style::PLAIN, None);
        assert_eq!(g.text(), " one\n two");
        assert_eq!(cur, (4, 1));
    }
}
