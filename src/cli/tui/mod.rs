//! The screen mode: `cakepass` without a command opens the login screen and
//! then a full-screen view of the vault that you use with the arrow keys,
//! Enter, Esc and a few letters (a list with details, a form to add and edit,
//! a password generator, settings). `cakepass shell` keeps the line mode.
//!
//! No TUI library is used, only `libc` and plain ANSI/VT escape codes, so
//! the program stays small:
//! - [`term`]: raw mode, the alternate screen, signals, input and output;
//! - [`keys`]: bytes from the terminal → key presses (and pasted text);
//! - [`grid`]: the frame buffer and the diff that sends only what changed;
//! - [`input`]: text fields; [`theme`]: colors and line characters;
//! - [`app`] and [`screens`]: what is shown and what every key does.
//!
//! Everything except `term` is plain logic that is tested without a terminal.
//!
//! SECURITY (in short; details in the modules):
//! - Nothing is decrypted for the whole vault at once. The list decrypts the
//!   username of the rows on screen, the details pane the selected item; a
//!   password, API key or note only when you reveal or copy it. Decrypted
//!   text lives in `Zeroizing` buffers and is wiped right after drawing.
//! - Secrets show as dots until you reveal them; a revealed secret hides
//!   itself after 10 seconds, on another selection or screen, and on locking.
//! - The frame buffer and the output buffer are wiped; frames go to the
//!   terminal with `write(2)`, not through Rust's buffered stdout.
//! - Everything is drawn on the alternate screen; on leaving, the normal
//!   screen and its scrollback are cleared as well.
//! - After the configured idle time CakePass locks: the key and everything
//!   decrypted are wiped and the program ends, as in `cakepass shell`.
//! - The terminal is always restored (exit, error, panic, signals).

pub mod app;
pub mod grid;
pub mod input;
pub mod keys;
pub mod screens;
pub mod term;
pub mod theme;

use std::io::IsTerminal;
use std::time::{Duration, Instant};

use zeroize::Zeroize;

use cakepass::storage::{UnlockedVault, VaultPaths};
use cakepass::{Error, Result};

use super::commands::{self, Notice};
use super::config::{self, Config};
use super::{prompt, shell, ui};
use app::{App, Exit};
use keys::{Parser, Pending};
use term::{Input, Terminal};
use theme::Theme;

/// The smallest terminal the screen mode draws in.
pub const MIN_WIDTH: u16 = 60;
pub const MIN_HEIGHT: u16 = 16;

/// Why the screen mode cannot be used (then the line mode is used).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unavailable {
    /// Input or output is a pipe or a file.
    NotATerminal,
    /// `TERM` is missing or `dumb`.
    DumbTerminal,
    TooSmall(u16, u16),
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unavailable::NotATerminal => write!(f, "not a terminal"),
            Unavailable::DumbTerminal => write!(f, "this terminal (TERM) cannot show the arrow-key screen"),
            Unavailable::TooSmall(w, h) => {
                write!(
                    f,
                    "the window is {w}×{h}; the arrow-key screen needs at least {MIN_WIDTH}×{MIN_HEIGHT}"
                )
            }
        }
    }
}

/// Can the screen mode run here?
pub fn check() -> std::result::Result<(), Unavailable> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(Unavailable::NotATerminal);
    }
    if std::env::var("TERM").map_or(true, |t| t.is_empty() || t == "dumb") {
        return Err(Unavailable::DumbTerminal);
    }
    match term::size() {
        Some((w, h)) if w < MIN_WIDTH || h < MIN_HEIGHT => Err(Unavailable::TooSmall(w, h)),
        _ => Ok(()),
    }
}

/// The lock timeout. Debug builds (the tests) may shorten it with
/// `CAKEPASS_TEST_LOCK_SECS`; release builds ignore that.
fn lock_secs(cfg: &Config) -> u64 {
    let secs = cfg.lock_timeout_secs();
    #[cfg(any(debug_assertions, feature = "test-hooks"))]
    if let Some(s) = std::env::var("CAKEPASS_TEST_LOCK_SECS").ok().and_then(|v| v.parse::<u64>().ok()) {
        return secs.min(s.max(1));
    }
    secs
}

/// Login screen (3 attempts, the 3D logo), then the screen mode.
pub fn run(paths: &VaultPaths, cfg: &Config) -> Result<()> {
    let mut uv = commands::login(paths)?;
    let notices = commands::unlock_notices(&mut uv);
    run_unlocked(uv, notices, cfg)
}

/// The screen mode for a vault that is already open.
pub fn run_unlocked(uv: UnlockedVault, notices: Vec<Notice>, cfg: &Config) -> Result<()> {
    let theme = Theme::detect(ui::color_on_stdout());
    let lock = lock_secs(cfg);
    let copier: app::Copier = Box::new(commands::copy_secret);
    let now = Instant::now();
    let mut app = App::new(uv, cfg.clone(), config::path(), Duration::from_secs(lock), copier, now);
    app.key_file = commands::key_file_path();
    app.show_notices(notices);
    prompt::mark_activity();
    term::set_lock_secs(lock);
    term::start_watchdog();
    let mut terminal = Terminal::enter(theme)?;
    let result = event_loop(&mut app, &mut terminal);
    let human = shell::describe(app.lock_secs());
    drop(app); // wipes the key and everything decrypted
    terminal.leave(true);
    match result? {
        Exit::Quit | Exit::Lock => ui::success("🔒 CakePass locked; the key has been wiped from memory."),
        Exit::Idle => {
            ui::info(&format!("🔒 Locked automatically after {human} without input."));
            ui::success("CakePass locked; the key has been wiped from memory.");
        }
        Exit::Signal => {
            ui::info("🔒 CakePass was closed; the key has been wiped from memory.");
            return Err(Error::Cancelled);
        }
        Exit::Hangup => {}
    }
    Ok(())
}

/// Draw, wait for keys (or time), handle them; until the app or a signal ends it.
fn event_loop(app: &mut App, terminal: &mut Terminal) -> Result<Exit> {
    let mut parser = Parser::new();
    let mut buf = [0u8; 4096];
    let result = loop {
        match term::take_signal() {
            // The terminal is gone: nothing can be shown any more.
            Some(libc::SIGHUP) => break Ok(Exit::Hangup),
            Some(_) => break Ok(Exit::Signal),
            None => {}
        }
        let now = Instant::now();
        // Wall-clock idle time too: the monotonic clock stops while a laptop
        // sleeps, and the vault must still be locked when it wakes up.
        if prompt::idle_secs() >= app.lock_secs() {
            app.lock_idle();
        }
        app.tick(now);
        if let Some(exit) = app.exit() {
            break Ok(exit);
        }
        term::set_lock_secs(app.lock_secs());
        app.resize(terminal.size());
        if let Err(e) = terminal.draw(|g| app.draw(g, now)) {
            break Err(Error::Io(e));
        }
        if app.run_task() {
            continue;
        }
        let wait = match parser.pending() {
            Pending::Sequence => 30,
            Pending::Paste => 500,
            Pending::Nothing => app.wait_ms(now),
        };
        match terminal.read(wait, &mut buf) {
            Ok(Input::Data(n)) => {
                parser.feed(&buf[..n]);
                buf[..n].zeroize();
            }
            Ok(Input::Timeout) => {
                if let Some(ev) = parser.flush() {
                    app.handle(ev, Instant::now());
                }
            }
            Ok(Input::Interrupted) => {}
            Ok(Input::Closed) => break Ok(Exit::Hangup),
            Err(e) => break Err(Error::Io(e)),
        }
        while app.exit().is_none()
            && let Some(ev) = parser.next_event()
        {
            app.handle(ev, Instant::now());
        }
    };
    buf.zeroize();
    result
}
