//! The real terminal: raw mode, the alternate screen, signals, reading
//! input and writing frames. This is the only part of the screen mode that
//! talks to the terminal (tests/tui.rs drives it through a pseudo-terminal).
//!
//! SECURITY:
//! - Frames go out with `write(2)` from a buffer that is wiped right after;
//!   nothing goes through Rust's buffered stdout.
//! - Everything is drawn on the alternate screen, so nothing secret lands on
//!   the normal screen or in its scrollback.
//! - The terminal is always restored: on a normal exit, an error (`Drop`), a
//!   panic (a panic hook; the release build aborts on a panic, but the hook
//!   runs first), and SIGINT, SIGTERM, SIGHUP and SIGQUIT. The signal handlers
//!   only set a flag (async-signal-safe); `poll` is interrupted, so the main
//!   loop sees the flag at once and cleans up properly.
//! - Restoring discards keys typed ahead (TCSAFLUSH), so they never reach
//!   the shell; that matters when a password was being pasted.
//! - A watchdog thread locks even when the main loop is stuck (for example on
//!   a hanging clipboard tool), like the one of `cakepass shell`.

use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::time::Duration;

use zeroize::{Zeroize, Zeroizing};

use super::super::prompt;
use super::grid::{self, Grid};
use super::theme::Theme;

/// Alternate screen, no line wrap, bracketed paste, hidden cursor, clear.
const ENTER: &[u8] = b"\x1b[?1049h\x1b[?7l\x1b[?2004h\x1b[?25l\x1b[0m\x1b[H\x1b[2J";
/// Undo all of that and go back to the normal screen.
const LEAVE: &[u8] = b"\x1b[0m\x1b[?2004l\x1b[?7h\x1b[?25h\x1b[?1049l";
/// Clear the normal screen and its scrollback.
const CLEAR_ALL: &[u8] = b"\x1b[2J\x1b[3J\x1b[H";

static ACTIVE: AtomicBool = AtomicBool::new(false);
static SIGNAL: AtomicI32 = AtomicI32::new(0);
static RESIZED: AtomicBool = AtomicBool::new(false);
static LOCK_SECS: AtomicU64 = AtomicU64::new(u64::MAX);
/// The terminal settings from before, for the panic hook and the watchdog.
static SAVED: Mutex<Option<libc::termios>> = Mutex::new(None);

const STOP_SIGNALS: [libc::c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

extern "C" fn on_signal(sig: libc::c_int) {
    // Only atomics here: they are async-signal-safe.
    if sig == libc::SIGWINCH {
        RESIZED.store(true, Ordering::SeqCst);
    } else {
        SIGNAL.store(sig, Ordering::SeqCst);
    }
}

/// A stop signal that arrived (and is now handled).
pub fn take_signal() -> Option<i32> {
    match SIGNAL.swap(0, Ordering::SeqCst) {
        0 => None,
        s => Some(s),
    }
}

/// Tell the watchdog the current lock timeout.
pub fn set_lock_secs(secs: u64) {
    LOCK_SECS.store(secs, Ordering::Relaxed);
}

/// Write everything, retrying after interruptions. No buffer in between.
fn write_all(fd: libc::c_int, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        // SAFETY: a valid buffer with the given length.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    let mut p = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
                    // SAFETY: one valid pollfd.
                    unsafe { libc::poll(&mut p, 1, 100) };
                    continue;
                }
                _ => return Err(err),
            }
        }
        bytes = &bytes[n as usize..];
    }
    Ok(())
}

/// Size of the terminal (columns, rows), from stdout or stdin.
pub fn size() -> Option<(u16, u16)> {
    for fd in [1, 0] {
        // SAFETY: winsize is a plain C struct that ioctl fills in.
        let ws = unsafe {
            let mut ws: libc::winsize = std::mem::zeroed();
            (libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) == 0).then_some(ws)
        };
        if let Some(ws) = ws.filter(|w| w.ws_col > 0 && w.ws_row > 0) {
            return Some((ws.ws_col, ws.ws_row));
        }
    }
    None
}

/// Put the terminal back without needing the `Terminal` (panic hook, watchdog).
fn restore_now() {
    if ACTIVE.swap(false, Ordering::SeqCst) {
        let _ = write_all(1, LEAVE);
        if let Ok(saved) = SAVED.try_lock()
            && let Some(t) = *saved
        {
            // SAFETY: a termios we read ourselves.
            unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &t) };
        }
    }
}

fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_now();
            previous(info);
        }));
    });
}

/// Lock even when the main loop is stuck: after the lock timeout plus a few
/// seconds without input, restore the terminal and exit. (Exiting releases
/// all memory; the kernel wipes pages before another process gets them.)
pub fn start_watchdog() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::thread::spawn(|| {
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let limit = LOCK_SECS.load(Ordering::Relaxed).saturating_add(3);
                if ACTIVE.load(Ordering::SeqCst) && prompt::idle_secs() > limit {
                    restore_now();
                    let _ = write_all(1, CLEAR_ALL);
                    // Not eprintln!: that panics when the terminal is gone.
                    let _ = write_all(
                        2,
                        "🔒 Locked automatically; the key has been wiped from memory.\n".as_bytes(),
                    );
                    std::process::exit(0);
                }
            }
        });
    });
}

pub enum Input {
    Data(usize),
    Timeout,
    Interrupted,
    Closed,
}

pub struct Terminal {
    saved: libc::termios,
    old_actions: Vec<(libc::c_int, libc::sigaction)>,
    front: Grid,
    back: Grid,
    out: Zeroizing<Vec<u8>>,
    full: bool,
    theme: Theme,
}

impl Terminal {
    /// Raw mode, signal handlers, the alternate screen.
    pub fn enter(theme: Theme) -> io::Result<Terminal> {
        // SAFETY: termios is a plain C struct that tcgetattr fills in.
        let saved = unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut t) != 0 {
                return Err(io::Error::last_os_error());
            }
            t
        };
        let mut raw = saved;
        raw.c_iflag &= !(libc::BRKINT | libc::ICRNL | libc::INPCK | libc::ISTRIP | libc::IXON);
        raw.c_oflag &= !libc::OPOST;
        raw.c_cflag |= libc::CS8;
        raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::IEXTEN | libc::ISIG);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        if let Ok(mut s) = SAVED.lock() {
            *s = Some(saved);
        }
        install_panic_hook();
        let mut old_actions = Vec::new();
        for sig in STOP_SIGNALS.into_iter().chain([libc::SIGWINCH]) {
            // SAFETY: a handler that only touches atomics; the old action is kept to restore it.
            unsafe {
                let mut new: libc::sigaction = std::mem::zeroed();
                new.sa_sigaction = on_signal as *const () as libc::sighandler_t;
                libc::sigemptyset(&mut new.sa_mask);
                new.sa_flags = 0; // no SA_RESTART: poll returns at once
                let mut old: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(sig, &new, &mut old) == 0 {
                    old_actions.push((sig, old));
                }
            }
        }
        // SAFETY: a termios derived from the one we read.
        if unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &raw) } != 0 {
            let err = io::Error::last_os_error();
            restore_actions(&mut old_actions);
            return Err(err);
        }
        ACTIVE.store(true, Ordering::SeqCst);
        let (w, h) = size().unwrap_or((80, 24));
        let term = Terminal {
            saved,
            old_actions,
            front: Grid::new(w, h, theme.glyphs()),
            back: Grid::new(w, h, theme.glyphs()),
            out: Zeroizing::new(Vec::with_capacity(64 * 1024)),
            full: true,
            theme,
        };
        write_all(1, ENTER)?;
        Ok(term)
    }

    pub fn size(&self) -> (u16, u16) {
        size().unwrap_or((self.front.width(), self.front.height()))
    }

    /// Draw a frame: `paint` fills a blank grid, and only what differs from
    /// the frame on screen is sent. The frame that is no longer on screen is
    /// wiped right away, and so is the output buffer.
    pub fn draw(&mut self, paint: impl FnOnce(&mut Grid)) -> io::Result<()> {
        let (w, h) = self.size();
        if RESIZED.swap(false, Ordering::SeqCst) {
            self.full = true;
        }
        if (w, h) != (self.front.width(), self.front.height()) {
            // The old grids are dropped, which wipes them.
            self.front = Grid::new(w, h, self.theme.glyphs());
            self.back = Grid::new(w, h, self.theme.glyphs());
            self.full = true;
        }
        paint(&mut self.back);
        grid::diff(&self.front, &self.back, self.full, &self.theme, &mut self.out);
        let written = write_all(1, &self.out);
        self.out.zeroize();
        std::mem::swap(&mut self.front, &mut self.back);
        self.back.clear();
        self.full = written.is_err();
        written
    }

    /// Wait at most `timeout_ms` for input and read what is there.
    pub fn read(&self, timeout_ms: i32, buf: &mut [u8]) -> io::Result<Input> {
        let mut p = libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 };
        // SAFETY: one valid pollfd.
        let r = unsafe { libc::poll(&mut p, 1, timeout_ms) };
        if r < 0 {
            let err = io::Error::last_os_error();
            return if err.kind() == io::ErrorKind::Interrupted { Ok(Input::Interrupted) } else { Err(err) };
        }
        if r == 0 {
            return Ok(Input::Timeout);
        }
        if p.revents & libc::POLLIN == 0 {
            return Ok(Input::Closed); // POLLHUP / POLLERR: the terminal is gone
        }
        // SAFETY: we read at most buf.len() bytes into buf.
        let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
        match n {
            0 => Ok(Input::Closed),
            n if n > 0 => Ok(Input::Data(n as usize)),
            _ => {
                let err = io::Error::last_os_error();
                match err.kind() {
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => Ok(Input::Interrupted),
                    _ => Err(err),
                }
            }
        }
    }

    fn restore(&mut self) {
        if ACTIVE.swap(false, Ordering::SeqCst) {
            let _ = write_all(1, LEAVE);
            // SAFETY: the termios we read in `enter`.
            unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &self.saved) };
        }
        restore_actions(&mut self.old_actions);
    }

    /// Back to the normal terminal; with `clear`, also clear the screen and
    /// the scrollback (after locking, like `cakepass shell`).
    pub fn leave(mut self, clear: bool) {
        self.restore();
        if clear {
            let _ = write_all(1, CLEAR_ALL);
        }
    }
}

fn restore_actions(old: &mut Vec<(libc::c_int, libc::sigaction)>) {
    for (sig, act) in old.drain(..) {
        // SAFETY: an action we received from sigaction earlier.
        unsafe { libc::sigaction(sig, &act, std::ptr::null_mut()) };
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        self.restore();
    }
}
