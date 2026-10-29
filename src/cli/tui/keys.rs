//! Turning the bytes a terminal sends into key presses.
//!
//! A terminal in raw mode sends plain bytes for letters, control bytes for
//! Ctrl+letter, and escape sequences for the other keys (`ESC [ A` for ↑,
//! `ESC [ 3 ~` for Delete, ...). The tricky part is the Esc key itself: it
//! sends a lone `ESC`, which is also how every sequence starts. The parser
//! therefore keeps an unfinished sequence until more bytes arrive; when none
//! arrive within a short time the main loop calls [`Parser::flush`], and a
//! lone `ESC` becomes the Esc key.
//!
//! Pasted text arrives between `ESC [ 200 ~` and `ESC [ 201 ~` (bracketed
//! paste, switched on by the terminal code) and becomes one [`Event::Paste`],
//! so a pasted API key is typed into the field and never runs shortcuts.
//!
//! SECURITY: typed and pasted secrets pass through this buffer. Consumed
//! bytes are wiped at once, and pasted text is kept in `Zeroizing` memory.

use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// A printable character (including space).
    Char(char),
    /// Ctrl + a letter (lowercase), e.g. `Ctrl('s')`.
    Ctrl(char),
    /// Alt + a character (ESC followed by the character).
    Alt(char),
    Enter,
    Tab,
    /// Shift+Tab.
    BackTab,
    Backspace,
    Delete,
    Insert,
    Esc,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    F(u8),
}

#[derive(PartialEq, Eq)]
pub enum Event {
    Key(Key),
    /// Text pasted in one go (bracketed paste).
    Paste(Zeroizing<String>),
}

impl std::fmt::Debug for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Event::Key(k) => write!(f, "Key({k:?})"),
            // Never print what was pasted.
            Event::Paste(p) => write!(f, "Paste([{} bytes])", p.len()),
        }
    }
}

/// What the parser is still waiting for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pending {
    Nothing,
    /// An unfinished escape sequence or character: wait a few milliseconds.
    Sequence,
    /// The middle of a paste: wait for the rest.
    Paste,
}

const PASTE_END: &[u8] = b"\x1b[201~";
/// Pasted text beyond this size is dropped (the largest field is 64 KiB).
const MAX_PASTE: usize = 64 * 1024;
/// An escape sequence longer than this is garbage and is skipped.
const MAX_SEQUENCE: usize = 32;

enum Parsed {
    Key(Key, usize),
    PasteStart(usize),
    Skip(usize),
    Incomplete,
}

#[derive(Default)]
pub struct Parser {
    buf: Zeroizing<Vec<u8>>,
    paste: Option<Zeroizing<Vec<u8>>>,
}

impl Parser {
    pub fn new() -> Parser {
        Parser::default()
    }

    /// Add bytes read from the terminal.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn pending(&self) -> Pending {
        if self.paste.is_some() {
            Pending::Paste
        } else if self.buf.is_empty() {
            Pending::Nothing
        } else {
            Pending::Sequence
        }
    }

    /// Remove the first `n` bytes and wipe the space they leave behind.
    fn consume(&mut self, n: usize) {
        self.buf.drain(..n);
        self.buf.spare_capacity_mut().zeroize();
    }

    /// The next complete event, or `None` when more bytes are needed.
    pub fn next_event(&mut self) -> Option<Event> {
        loop {
            if let Some(paste) = self.paste.as_mut() {
                let (take, end) = match find(&self.buf, PASTE_END) {
                    Some(i) => (i, Some(i + PASTE_END.len())),
                    // Keep a tail that may be the start of the end marker.
                    None => (self.buf.len() - partial_suffix(&self.buf, PASTE_END), None),
                };
                let room = MAX_PASTE.saturating_sub(paste.len());
                paste.extend_from_slice(&self.buf[..take.min(room)]);
                self.consume(end.unwrap_or(take));
                end?; // the end marker has not arrived yet
                return self.paste.take().map(|p| Event::Paste(into_text(p)));
            }
            if self.buf.is_empty() {
                return None;
            }
            match parse(&self.buf) {
                Parsed::Key(k, n) => {
                    self.consume(n);
                    return Some(Event::Key(k));
                }
                Parsed::PasteStart(n) => {
                    self.consume(n);
                    self.paste = Some(Zeroizing::new(Vec::new()));
                }
                Parsed::Skip(n) => self.consume(n),
                Parsed::Incomplete => return None,
            }
        }
    }

    /// No more bytes came: settle what is waiting. A lone ESC is the Esc
    /// key, an unfinished paste is delivered as it is, a broken character
    /// is dropped.
    pub fn flush(&mut self) -> Option<Event> {
        if let Some(mut paste) = self.paste.take() {
            let room = MAX_PASTE.saturating_sub(paste.len());
            paste.extend_from_slice(&self.buf[..self.buf.len().min(room)]);
            let n = self.buf.len();
            self.consume(n);
            return Some(Event::Paste(into_text(paste)));
        }
        match self.buf.first() {
            None => None,
            Some(0x1b) => {
                self.consume(1);
                Some(Event::Key(Key::Esc))
            }
            Some(_) => {
                let n = self.buf.len();
                self.consume(n);
                None
            }
        }
    }
}

fn into_text(mut bytes: Zeroizing<Vec<u8>>) -> Zeroizing<String> {
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(s) => Zeroizing::new(s),
        Err(e) => {
            let raw = Zeroizing::new(e.into_bytes());
            Zeroizing::new(String::from_utf8_lossy(&raw).into_owned())
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Length of the longest end of `hay` that is a start of `needle`.
fn partial_suffix(hay: &[u8], needle: &[u8]) -> usize {
    (1..needle.len().min(hay.len() + 1)).rev().find(|&n| hay.ends_with(&needle[..n])).unwrap_or(0)
}

fn parse(b: &[u8]) -> Parsed {
    match b[0] {
        0x1b => parse_escape(b),
        b'\r' | b'\n' => Parsed::Key(Key::Enter, 1),
        b'\t' => Parsed::Key(Key::Tab, 1),
        0x7f | 0x08 => Parsed::Key(Key::Backspace, 1),
        0x00 => Parsed::Key(Key::Ctrl(' '), 1),
        c @ 0x01..=0x1a => Parsed::Key(Key::Ctrl((b'a' + c - 1) as char), 1),
        0x1c..=0x1f => Parsed::Skip(1),
        c if c < 0x80 => Parsed::Key(Key::Char(c as char), 1),
        lead => {
            let need = match lead {
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => return Parsed::Skip(1),
            };
            if b.len() < need {
                // Wait for the rest, unless what is there is already wrong.
                return if b[1..].iter().all(|&c| c & 0xc0 == 0x80) {
                    Parsed::Incomplete
                } else {
                    Parsed::Skip(1)
                };
            }
            match std::str::from_utf8(&b[..need]) {
                Ok(s) => Parsed::Key(Key::Char(s.chars().next().expect("one character")), need),
                Err(_) => Parsed::Skip(1),
            }
        }
    }
}

fn parse_escape(b: &[u8]) -> Parsed {
    let Some(&second) = b.get(1) else { return Parsed::Incomplete };
    match second {
        b'[' => parse_csi(b),
        b'O' => match b.get(2) {
            None => Parsed::Incomplete,
            Some(&c) => match ss3_key(c) {
                Some(k) => Parsed::Key(k, 3),
                None => Parsed::Skip(3),
            },
        },
        // A printable character after ESC: Alt+character.
        c @ 0x20..=0x7e => Parsed::Key(Key::Alt(c as char), 2),
        // ESC ESC, or ESC before a control or multi-byte character: the
        // first ESC was the Esc key on its own.
        _ => Parsed::Key(Key::Esc, 1),
    }
}

fn ss3_key(c: u8) -> Option<Key> {
    Some(match c {
        b'A' => Key::Up,
        b'B' => Key::Down,
        b'C' => Key::Right,
        b'D' => Key::Left,
        b'H' => Key::Home,
        b'F' => Key::End,
        b'M' => Key::Enter,
        b'P'..=b'S' => Key::F(c - b'P' + 1),
        _ => return None,
    })
}

fn parse_csi(b: &[u8]) -> Parsed {
    // The Linux console sends F1–F5 as ESC [ [ A … E.
    if b.get(2) == Some(&b'[') {
        return match b.get(3) {
            None => Parsed::Incomplete,
            Some(&c @ b'A'..=b'E') => Parsed::Key(Key::F(c - b'A' + 1), 4),
            Some(_) => Parsed::Skip(4),
        };
    }
    // ESC [ parameters (0x30–0x3f) intermediates (0x20–0x2f) final (0x40–0x7e).
    let mut i = 2;
    while i < b.len() {
        match b[i] {
            0x20..=0x3f => i += 1,
            0x40..=0x7e => break,
            _ => return Parsed::Skip(i), // malformed: drop it, keep the odd byte
        }
    }
    if i >= b.len() {
        return if b.len() > MAX_SEQUENCE { Parsed::Skip(b.len()) } else { Parsed::Incomplete };
    }
    let len = i + 1;
    let params = &b[2..i];
    let first: u32 = params
        .split(|&c| c == b';')
        .next()
        .and_then(|p| std::str::from_utf8(p).ok())
        .and_then(|p| p.parse().ok())
        .unwrap_or(1);
    let key = match b[i] {
        b'A' => Key::Up,
        b'B' => Key::Down,
        b'C' => Key::Right,
        b'D' => Key::Left,
        b'H' => Key::Home,
        b'F' => Key::End,
        b'Z' => Key::BackTab,
        c @ b'P'..=b'S' => Key::F(c - b'P' + 1),
        b'~' => match first {
            1 | 7 => Key::Home,
            2 => Key::Insert,
            3 => Key::Delete,
            4 | 8 => Key::End,
            5 => Key::PageUp,
            6 => Key::PageDown,
            11..=15 => Key::F((first - 10) as u8),
            17..=21 => Key::F((first - 11) as u8),
            23 | 24 => Key::F((first - 12) as u8),
            200 => return Parsed::PasteStart(len),
            _ => return Parsed::Skip(len),
        },
        _ => return Parsed::Skip(len),
    };
    Parsed::Key(key, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(bytes: &[u8]) -> Vec<Event> {
        let mut p = Parser::new();
        p.feed(bytes);
        let mut out = Vec::new();
        while let Some(e) = p.next_event() {
            out.push(e);
        }
        if let Some(e) = p.flush() {
            out.push(e);
            while let Some(e) = p.next_event() {
                out.push(e);
            }
        }
        out
    }

    fn k(key: Key) -> Event {
        Event::Key(key)
    }

    fn paste(s: &str) -> Event {
        Event::Paste(Zeroizing::new(s.to_string()))
    }

    #[test]
    fn plain_keys_and_control_bytes() {
        assert_eq!(
            keys(b"aZ 1"),
            [k(Key::Char('a')), k(Key::Char('Z')), k(Key::Char(' ')), k(Key::Char('1'))]
        );
        assert_eq!(
            keys(b"\r\n\t\x7f\x08"),
            [k(Key::Enter), k(Key::Enter), k(Key::Tab), k(Key::Backspace), k(Key::Backspace)]
        );
        assert_eq!(
            keys(b"\x03\x13\x07\x12"),
            [k(Key::Ctrl('c')), k(Key::Ctrl('s')), k(Key::Ctrl('g')), k(Key::Ctrl('r'))]
        );
    }

    #[test]
    fn arrows_and_navigation_keys() {
        let all = keys(b"\x1b[A\x1b[B\x1b[C\x1b[D\x1bOA\x1bOD\x1b[H\x1b[F\x1b[1~\x1b[4~\x1bOH\x1bOF");
        assert_eq!(
            all,
            [
                k(Key::Up),
                k(Key::Down),
                k(Key::Right),
                k(Key::Left),
                k(Key::Up),
                k(Key::Left),
                k(Key::Home),
                k(Key::End),
                k(Key::Home),
                k(Key::End),
                k(Key::Home),
                k(Key::End)
            ]
        );
        assert_eq!(
            keys(b"\x1b[5~\x1b[6~\x1b[3~\x1b[2~\x1b[Z\x1b[7~\x1b[8~"),
            [
                k(Key::PageUp),
                k(Key::PageDown),
                k(Key::Delete),
                k(Key::Insert),
                k(Key::BackTab),
                k(Key::Home),
                k(Key::End)
            ]
        );
        // Modifiers (Ctrl+→, Shift+Del) are accepted and ignored.
        assert_eq!(keys(b"\x1b[1;5C\x1b[3;2~"), [k(Key::Right), k(Key::Delete)]);
        assert_eq!(
            keys(b"\x1bOP\x1b[15~\x1b[24~\x1b[[A"),
            [k(Key::F(1)), k(Key::F(5)), k(Key::F(12)), k(Key::F(1))]
        );
    }

    #[test]
    fn escape_alone_alt_and_unknown_sequences() {
        assert_eq!(keys(b"\x1b"), [k(Key::Esc)], "a lone ESC is the Esc key");
        assert_eq!(keys(b"\x1b\x1b[A"), [k(Key::Esc), k(Key::Up)]);
        assert_eq!(keys(b"\x1bx"), [k(Key::Alt('x'))]);
        assert_eq!(keys(b"\x1b\r"), [k(Key::Esc), k(Key::Enter)]);
        // Unknown or mouse sequences are skipped without side effects.
        assert_eq!(keys(b"\x1b[<0;10;5Mq\x1b[99~\x1bO~"), [k(Key::Char('q'))]);
        // A stray paste end marker does nothing.
        assert_eq!(keys(b"\x1b[201~a"), [k(Key::Char('a'))]);
    }

    #[test]
    fn utf8_characters() {
        assert_eq!(keys("é中🍰".as_bytes()), [k(Key::Char('é')), k(Key::Char('中')), k(Key::Char('🍰'))]);
        // Invalid bytes are dropped; what follows still works.
        assert_eq!(keys(b"\xff\xc3x"), [k(Key::Char('x'))]);
    }

    #[test]
    fn partial_reads_are_put_together() {
        let mut p = Parser::new();
        let mut got = Vec::new();
        for b in b"\x1b[3~\x1b[200~ab\x1b[201~".iter().chain("€".as_bytes()) {
            p.feed(&[*b]);
            while let Some(e) = p.next_event() {
                got.push(e);
            }
        }
        assert_eq!(got, [k(Key::Delete), paste("ab"), k(Key::Char('€'))]);
        // Half a sequence waits; Esc is only decided on the flush.
        p.feed(b"\x1b[");
        assert_eq!(p.next_event(), None);
        assert_eq!(p.pending(), Pending::Sequence);
        p.feed(b"B");
        assert_eq!(p.next_event(), Some(k(Key::Down)));
        assert_eq!(p.pending(), Pending::Nothing);
        // Half a UTF-8 character waits too.
        p.feed(&"中".as_bytes()[..2]);
        assert_eq!(p.next_event(), None);
        p.feed(&"中".as_bytes()[2..]);
        assert_eq!(p.next_event(), Some(k(Key::Char('中'))));
    }

    #[test]
    fn bracketed_paste() {
        // Shortcut letters and control bytes inside a paste are just text.
        assert_eq!(
            keys(b"\x1b[200~sk-q\x1b[Adel\r\n\x1b[201~x"),
            [paste("sk-q\x1b[Adel\r\n"), k(Key::Char('x'))]
        );
        // The end marker split over two reads.
        let mut p = Parser::new();
        p.feed(b"\x1b[200~key-123\x1b[2");
        assert_eq!(p.next_event(), None);
        assert_eq!(p.pending(), Pending::Paste);
        p.feed(b"01~");
        assert_eq!(p.next_event(), Some(paste("key-123")));
        // A paste that never ends is delivered on the flush.
        let mut p = Parser::new();
        p.feed(b"\x1b[200~unfinished");
        assert_eq!(p.next_event(), None);
        assert_eq!(p.flush(), Some(paste("unfinished")));
        // A huge paste is cut off at 64 KiB, and the keys after it still work.
        let mut big = b"\x1b[200~".to_vec();
        big.extend(std::iter::repeat_n(b'a', 70_000));
        big.extend_from_slice(b"\x1b[201~q");
        let ev = keys(&big);
        assert!(matches!(&ev[0], Event::Paste(p) if p.len() == MAX_PASTE));
        assert_eq!(ev[1], k(Key::Char('q')));
        // Invalid UTF-8 in a paste is replaced, not fatal.
        assert_eq!(keys(b"\x1b[200~a\xffb\x1b[201~"), [paste("a\u{fffd}b")]);
    }

    #[test]
    fn debug_never_shows_pasted_text() {
        assert_eq!(format!("{:?}", paste("hunter2")), "Paste([7 bytes])");
    }

    #[test]
    fn consumed_bytes_are_wiped() {
        let mut p = Parser::new();
        p.feed(b"secret");
        while p.next_event().is_some() {}
        assert!(p.buf.is_empty());
        let spare: Vec<u8> =
            p.buf.spare_capacity_mut().iter().map(|b| unsafe { b.assume_init() }).take(6).collect();
        assert_eq!(spare, [0; 6]);
    }
}
