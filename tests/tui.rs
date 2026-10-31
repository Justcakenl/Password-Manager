//! The screen mode (`cakepass` without a command) driven like a person
//! would: the real program runs in a pseudo-terminal, the test types keys
//! and reads the screen through a tiny terminal emulator. Afterwards the
//! normal commands check what was saved.
//!
//! Light Argon2 settings keep this fast, and the settings directory is a
//! temporary one. The idle lock uses `CAKEPASS_TEST_LOCK_SECS`, which only
//! debug builds (tests) honour.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::Command as Cmd;
use predicates::prelude::*;
use predicates::str::contains;

const PW: &str = "tq8#vLp2!mZr9wXe";
const FAST_KDF: [&str; 6] = ["--kdf-memory", "8", "--kdf-iterations", "1", "--kdf-parallelism", "1"];
const DOWN: &str = "\x1b[B";

struct Vault {
    dir: tempfile::TempDir,
}

impl Vault {
    fn new() -> Vault {
        let v = Vault { dir: tempfile::tempdir().unwrap() };
        v.cmd().arg("init").args(FAST_KDF).write_stdin(format!("{PW}\n{PW}\n")).assert().success();
        v
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("vault.enc")
    }

    fn envs(&self) -> Vec<(&'static str, String)> {
        vec![
            ("CAKEPASS_VAULT", self.path().display().to_string()),
            ("XDG_CONFIG_HOME", self.dir.path().join("config-home").display().to_string()),
            ("CAKEPASS_NO_ANIMATION", "1".into()),
            ("TERM", "xterm-256color".into()),
            ("LANG", "C.UTF-8".into()),
        ]
    }

    fn cmd(&self) -> Cmd {
        let mut c = Cmd::new(env!("CARGO_BIN_EXE_cakepass"));
        c.envs(self.envs()).env("NO_COLOR", "1").env_remove("WAYLAND_DISPLAY").env_remove("DISPLAY");
        c.timeout(Duration::from_secs(60));
        c
    }

    /// Run `cakepass <args>` in a new pseudo-terminal of `w` × `h`.
    fn pty(&self, args: &[&str], extra_env: &[(&str, &str)], w: u16, h: u16) -> Pty {
        Pty::spawn(args, &self.envs(), extra_env, w, h)
    }
}

/// A just-enough terminal emulator: cursor moves, clearing, text, and the
/// switch to the alternate screen. Enough to read what is on screen.
struct Screen {
    w: usize,
    h: usize,
    alt: bool,
    main: Vec<Vec<char>>,
    other: Vec<Vec<char>>,
    x: usize,
    y: usize,
}

impl Screen {
    fn new(w: u16, h: u16) -> Screen {
        let blank = vec![vec![' '; w as usize]; h as usize];
        Screen { w: w as usize, h: h as usize, alt: false, main: blank.clone(), other: blank, x: 0, y: 0 }
    }

    fn buf(&mut self) -> &mut Vec<Vec<char>> {
        if self.alt { &mut self.other } else { &mut self.main }
    }

    fn feed(&mut self, text: &str) {
        let c: Vec<char> = text.chars().collect();
        let mut i = 0;
        while i < c.len() {
            match c[i] {
                '\x1b' if c.get(i + 1) == Some(&'[') => {
                    let mut j = i + 2;
                    while j < c.len() && !('@'..='~').contains(&c[j]) {
                        j += 1;
                    }
                    if j >= c.len() {
                        return;
                    }
                    let params: String = c[i + 2..j].iter().collect();
                    self.csi(&params, c[j]);
                    i = j + 1;
                    continue;
                }
                '\x1b' => i += 1,
                '\r' => self.x = 0,
                '\n' => self.y = (self.y + 1).min(self.h - 1),
                ch if ch >= ' ' => {
                    let (x, y, w) = (self.x, self.y, self.w);
                    if x < w {
                        self.buf()[y][x] = ch;
                    }
                    self.x += 1;
                }
                _ => {}
            }
            i += 1;
        }
    }

    fn csi(&mut self, params: &str, fin: char) {
        let nums: Vec<usize> =
            params.trim_start_matches('?').split(';').map(|p| p.parse().unwrap_or(0)).collect();
        let (w, h) = (self.w, self.h);
        match (params.starts_with('?'), fin) {
            (true, 'h' | 'l') if nums.contains(&1049) => {
                self.alt = fin == 'h';
                if self.alt {
                    self.other = vec![vec![' '; w]; h];
                }
            }
            (false, 'H') => {
                self.y = nums.first().copied().unwrap_or(1).max(1).min(h) - 1;
                self.x = nums.get(1).copied().unwrap_or(1).max(1) - 1;
            }
            (false, 'J') if nums.first().is_some_and(|&n| n >= 2) => *self.buf() = vec![vec![' '; w]; h],
            (false, 'K') => {
                let (x, y) = (self.x, self.y);
                for cell in self.buf()[y].iter_mut().skip(x) {
                    *cell = ' ';
                }
            }
            (false, 'A') => self.y = self.y.saturating_sub(nums.first().copied().unwrap_or(1).max(1)),
            _ => {}
        }
    }

    fn text(&self) -> String {
        let buf = if self.alt { &self.other } else { &self.main };
        buf.iter().map(|r| r.iter().collect::<String>().trim_end().to_string()).collect::<Vec<_>>().join("\n")
    }
}

struct Pty {
    master: std::fs::File,
    child: Child,
    raw: Vec<u8>,
    size: (u16, u16),
}

fn set_size(fd: i32, w: u16, h: u16) {
    let ws = libc::winsize { ws_row: h, ws_col: w, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: a valid winsize for a valid descriptor.
    assert_eq!(unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) }, 0);
}

impl Pty {
    fn spawn(args: &[&str], env: &[(&str, String)], extra: &[(&str, &str)], w: u16, h: u16) -> Pty {
        // SAFETY: plain libc calls on descriptors we own; checked below.
        let (master, slave) = unsafe {
            let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(m >= 0, "no pseudo-terminal available");
            assert_eq!(libc::grantpt(m), 0);
            assert_eq!(libc::unlockpt(m), 0);
            let mut name = [0 as libc::c_char; 128];
            assert_eq!(libc::ptsname_r(m, name.as_mut_ptr(), name.len()), 0);
            let s = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
            assert!(s >= 0);
            // Never leak the controlling side into a child (ours or another test's),
            // or closing it would not hang up the terminal.
            assert_eq!(libc::fcntl(m, libc::F_SETFD, libc::FD_CLOEXEC), 0);
            (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s))
        };
        set_size(master.as_raw_fd(), w, h);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cakepass"));
        cmd.args(args)
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("DISPLAY")
            .env_remove("NO_COLOR")
            .env_remove("LC_ALL")
            .env_remove("LC_CTYPE")
            .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
            .envs(extra.iter().copied())
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave));
        // SAFETY: setsid and ioctl are async-signal-safe; this makes the
        // pseudo-terminal the controlling terminal (/dev/tty), as in a real login.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                libc::ioctl(0, libc::TIOCSCTTY, 0);
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap();
        drop(cmd); // closes our copies of the terminal side
        // SAFETY: making our own descriptor non-blocking.
        unsafe {
            let fl = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(master.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
        Pty { master: std::fs::File::from(master), child, raw: Vec::new(), size: (w, h) }
    }

    /// Read whatever the program wrote.
    fn pump(&mut self) {
        let mut buf = [0u8; 65536];
        loop {
            match self.master.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => self.raw.extend_from_slice(&buf[..n]),
                Err(_) => break, // WouldBlock, or EIO once the program has exited
            }
        }
    }

    fn screen(&self) -> String {
        let mut s = Screen::new(self.size.0, self.size.1);
        s.feed(&String::from_utf8_lossy(&self.raw));
        s.text()
    }

    fn output(&self) -> String {
        String::from_utf8_lossy(&self.raw).into_owned()
    }

    fn wait_for(&mut self, text: &str) {
        let start = Instant::now();
        loop {
            self.pump();
            if self.screen().contains(text) {
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "waiting for {text:?}; the screen:\n{}",
                self.screen()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Wait for text in the raw output (for the line-mode parts, which scroll).
    fn wait_raw(&mut self, text: &str) {
        let start = Instant::now();
        loop {
            self.pump();
            if self.output().contains(text) {
                return;
            }
            assert!(start.elapsed() < Duration::from_secs(30), "waiting for {text:?}:\n{}", self.output());
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn send(&mut self, keys: &str) {
        self.master.write_all(keys.as_bytes()).unwrap();
        // Give the program a moment, so a lone Esc is not glued to the next key.
        std::thread::sleep(Duration::from_millis(60));
        self.pump();
    }

    fn resize(&mut self, w: u16, h: u16) {
        set_size(self.master.as_raw_fd(), w, h);
        self.size = (w, h);
        // SAFETY: signalling our own child.
        unsafe { libc::kill(self.child.id() as i32, libc::SIGWINCH) };
    }

    fn wait_exit(&mut self) -> i32 {
        let start = Instant::now();
        loop {
            self.pump();
            if let Some(status) = self.child.try_wait().unwrap() {
                self.pump();
                return status.code().unwrap_or(-1);
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "the program did not exit:\n{}",
                self.screen()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Close the terminal side, like closing the window; returns the exit code.
    fn hang_up(&mut self) -> i32 {
        self.master = std::fs::File::open("/dev/null").unwrap(); // drops (closes) the real one
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code().unwrap_or(-1); // -1: killed by a signal (e.g. an abort)
            }
            assert!(start.elapsed() < Duration::from_secs(30), "the program kept running without a terminal");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Log in and close the notice about the light (test) Argon2 settings.
    fn login(&mut self) {
        self.wait_for("Master password");
        self.send(&format!("{PW}\r"));
        self.wait_for("lighter Argon2");
        self.send("\r");
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The terminal was put back the way it was: normal screen, cursor visible,
/// no bracketed paste, and the screen cleared after the secrets were shown.
fn assert_restored(out: &str) {
    let leave = out.rfind("\x1b[?1049l").expect("the alternate screen was left");
    assert!(leave > out.rfind("\x1b[?1049h").expect("the alternate screen was used"));
    let tail = &out[out.rfind("\x1b[?2004l").expect("bracketed paste off")..];
    assert!(tail.contains("\x1b[?25h"), "the cursor is shown again");
    assert!(out[leave..].contains("\x1b[2J\x1b[3J"), "screen and scrollback cleared");
}

#[test]
fn add_an_item_with_the_arrow_keys_then_read_it_with_the_cli() {
    let v = Vault::new();
    let mut t = v.pty(&[], &[], 80, 24);
    t.login();
    t.wait_for("Your vault is empty");
    t.send("a");
    t.wait_for("Add an item");
    t.send("GitHub");
    t.send(DOWN);
    t.send(DOWN);
    t.send("john");
    t.send(DOWN);
    t.send("john@example.org");
    t.send(DOWN);
    t.send("https://github.com");
    t.send(DOWN);
    t.send("work, code");
    t.send(DOWN);
    t.send("Tui-Secret-42!");
    t.send(DOWN);
    t.send("line one\rline two");
    t.wait_for("line two");
    assert!(!t.screen().contains("Tui-Secret-42!"), "the password is masked while typing");
    t.send("\x13"); // Ctrl+S
    t.wait_for("Login 'GitHub' saved (encrypted).");
    // An API key, pasted (the shortcut letters in it must not do anything).
    t.send("a");
    t.send("OpenAI");
    t.send(DOWN);
    t.send("\x1b[C"); // → API key
    t.send(&DOWN.repeat(5));
    t.send("\x1b[200~sk-q-del-a-123\x1b[201~");
    t.send("\x13");
    t.wait_for("API key 'OpenAI' saved");
    // Reveal and hide, then quit.
    t.send("\r");
    t.wait_for("sk-q-del-a-123");
    t.send("\r");
    t.send("q");
    assert_eq!(t.wait_exit(), 0);
    let out = t.output();
    assert_restored(&out);
    assert!(out[out.rfind("\x1b[?1049l").unwrap()..].contains("the key has been wiped from memory"));

    v.cmd().args(["get", "github", "--show"]).write_stdin(format!("{PW}\n")).assert().success().stdout(
        contains("john@example.org")
            .and(contains("https://github.com"))
            .and(contains("work, code"))
            .and(contains("Tui-Secret-42!"))
            .and(contains("line one")),
    );
    v.cmd()
        .args(["get", "openai", "--show"])
        .write_stdin(format!("{PW}\n"))
        .assert()
        .success()
        .stdout(contains("api key").and(contains("sk-q-del-a-123")));
}

#[test]
fn locks_itself_when_idle() {
    let v = Vault::new();
    let mut t = v.pty(&[], &[("CAKEPASS_TEST_LOCK_SECS", "2")], 80, 24);
    t.login();
    let start = Instant::now();
    assert_eq!(t.wait_exit(), 0);
    assert!(start.elapsed() < Duration::from_secs(15));
    let out = t.output();
    assert_restored(&out);
    assert!(out.contains("Locked automatically after 2 s without input"), "{out}");
}

#[test]
fn ctrl_c_and_signals_restore_the_terminal() {
    let v = Vault::new();
    let mut t = v.pty(&[], &[], 80, 24);
    t.login();
    t.send("\x03");
    assert_eq!(t.wait_exit(), 0);
    assert_restored(&t.output());

    let mut t = v.pty(&[], &[], 80, 24);
    t.login();
    t.wait_for("Your vault is empty");
    // SAFETY: signalling our own child.
    unsafe { libc::kill(t.child.id() as i32, libc::SIGTERM) };
    assert_eq!(t.wait_exit(), 130);
    let out = t.output();
    assert_restored(&out);
    assert!(out.contains("the key has been wiped from memory"));

    // Closing the window: the program ends by itself, without crashing.
    let mut t = v.pty(&[], &[], 80, 24);
    t.login();
    t.wait_for("Your vault is empty");
    assert_eq!(t.hang_up(), 0);
}

#[test]
fn resizing_and_a_too_small_window() {
    let v = Vault::new();
    let mut t = v.pty(&[], &[], 80, 24);
    t.login();
    t.wait_for("Your vault is empty");
    t.resize(50, 12);
    t.wait_for("Terminal too small");
    t.resize(100, 30);
    t.wait_for("Your vault is empty");
    t.send("q");
    assert_eq!(t.wait_exit(), 0);
}

#[test]
fn the_line_mode_is_used_when_asked_or_needed() {
    let v = Vault::new();
    // --no-tui: the old line mode, no alternate screen.
    let mut t = v.pty(&["--no-tui"], &[], 80, 24);
    t.wait_for("Master password");
    t.send(&format!("{PW}\r"));
    t.wait_for("cakepass ❯");
    t.send("exit\r");
    assert_eq!(t.wait_exit(), 0);
    assert!(!t.output().contains("\x1b[?1049h"));
    // A terminal that cannot do it, or a window that is too small.
    for (env, size, why) in [
        (&[("TERM", "dumb")][..], (80, 24), "cannot show the arrow-key screen"),
        (&[][..], (50, 12), "needs at least 60×16"),
    ] {
        let mut t = v.pty(&[], env, size.0, size.1);
        t.wait_for("Master password");
        assert!(t.output().contains(why), "{}", t.output());
        t.send(&format!("{PW}\r"));
        t.wait_for("cakepass ❯");
        t.send("exit\r");
        assert_eq!(t.wait_exit(), 0);
    }
    // Not a terminal (a pipe): the line mode, as before.
    v.cmd().write_stdin(format!("{PW}\nlist\nexit\n")).assert().success().stderr(contains("Vault unlocked"));
}

#[test]
fn the_settings_row_switches_the_security_level() {
    let v = Vault::new();
    let mut t = v.pty(&[], &[], 100, 30);
    t.login();
    t.wait_for("Your vault is empty");
    t.send("s");
    t.wait_for("Startup animation");
    t.send(DOWN);
    t.send(DOWN);
    assert!(!t.screen().contains("Unlock here"), "nothing measured yet");
    t.send(DOWN);
    // The High level is measured for real on this computer (256 MiB).
    t.wait_for("needs 342 MiB free");
    t.send("\x1b[D"); // ← Standard
    t.wait_for("needs 86 MiB free");
    t.send("\r");
    t.wait_for("Change the security level");
    t.send("wrong\r");
    t.wait_for("Wrong master password");
    t.send(&format!("{PW}\r"));
    t.wait_for("Security level changed");
    t.send("\r");
    t.wait_for("(current)");
    t.send("\x1b"); // back to the list
    t.send("q");
    assert_eq!(t.wait_exit(), 0);
    v.cmd().arg("info").assert().success().stdout(contains("Security level:   standard"));
    v.cmd().arg("list").write_stdin(format!("{PW}\n")).assert().success();
}

#[test]
fn logging_in_to_a_vault_with_a_key_file() {
    let v = Vault { dir: tempfile::tempdir().unwrap() };
    let kf = v.dir.path().join("usb.key");
    v.cmd().args(["keyfile", "create", kf.to_str().unwrap()]).assert().success();
    v.cmd()
        .args(["--keyfile", kf.to_str().unwrap(), "init"])
        .args(FAST_KDF)
        .write_stdin(format!("{PW}\n{PW}\n"))
        .assert()
        .success();
    // The settings remember the key file: logging in works as always.
    let mut t = v.pty(&[], &[], 80, 24);
    t.login();
    t.wait_for("Your vault is empty");
    t.send("s");
    t.wait_for("required:");
    t.send("\x1b");
    t.send("q");
    assert_eq!(t.wait_exit(), 0);
    // With the key file in the environment instead of the settings.
    v.cmd().args(["config", "set", "keyfile", "none"]).assert().success();
    let mut t = v.pty(&[], &[("CAKEPASS_KEYFILE", kf.to_str().unwrap())], 80, 24);
    t.login();
    t.wait_for("Your vault is empty");
    t.send("q");
    assert_eq!(t.wait_exit(), 0);
    // Without it: a clear message, and no password is asked.
    let mut t = v.pty(&[], &[], 80, 24);
    assert_eq!(t.wait_exit(), 1);
    let out = t.output();
    assert!(out.contains("needs its key file") && out.contains("--keyfile"), "{out}");
    assert!(!out.contains("Master password"), "{out}");
    // A wrong key file: three attempts, the same message as a wrong password.
    let other = v.dir.path().join("other.key");
    v.cmd().args(["keyfile", "create", other.to_str().unwrap()]).assert().success();
    let mut t = v.pty(&[], &[("CAKEPASS_KEYFILE", other.to_str().unwrap())], 80, 24);
    t.wait_for("Master password");
    t.send(&format!("{PW}\r"));
    t.wait_for("Wrong master password or key file. 2 attempt(s) left.");
    drop(t);
}

#[test]
fn first_run_wizard_in_a_terminal_then_the_screen() {
    // No vault yet: `cakepass` starts the wizard, then offers the screen.
    let v = Vault { dir: tempfile::tempdir().unwrap() };
    let kf = v.dir.path().join("usb.key");
    let mut t = v.pty(&[], &[], 100, 40);
    t.wait_raw("Play the animation");
    t.send("n\r");
    t.wait_raw("Lock after");
    t.send("\r");
    t.wait_raw("Choose 1, 2 or 3");
    t.send("x\r");
    t.wait_raw("Type 1, 2 or 3"); // in a terminal a typo can be corrected
    t.send("1\r");
    t.wait_raw("unlocking takes about");
    t.wait_raw("Make a strong passphrase for me?");
    t.send("\r");
    t.wait_raw("Type it again to confirm");
    let out = t.output();
    let shown =
        out[..out.find("Type it again").unwrap()].lines().rev().map(str::trim).find(|l| {
            l.len() > 20 && l.contains('-') && l.chars().all(|c| c.is_ascii_lowercase() || c == '-')
        });
    let phrase = shown.expect("the passphrase is shown").to_string();
    t.send("wrong-words\r");
    t.wait_raw("does not match");
    t.send(&format!("{phrase}\r"));
    t.wait_raw("Passphrase confirmed");
    let out = t.output();
    assert!(
        out[out.find("Type it again").unwrap()..].contains("\x1b[2J\x1b[3J"),
        "screen and scrollback cleared"
    );
    t.wait_raw("Create a key file?");
    t.send("y\r");
    t.wait_raw("Where should it go?");
    t.send(&format!("{}\r", kf.display()));
    t.wait_raw("Vault created");
    t.wait_raw("Open CakePass now?");
    t.send("\r");
    t.wait_for("Your vault is empty");
    assert!(!t.screen().contains(&phrase));
    // The key file recorded by the wizard is used at once (re-check in settings).
    t.send("s");
    t.wait_for("Startup animation");
    t.send(&format!("{DOWN}{DOWN}\r"));
    t.wait_for("current master password");
    t.send(&format!("{phrase}\r"));
    t.wait_for("Choose a new master password");
    t.send("\x1b");
    t.send("\x1b");
    t.send("q");
    assert_eq!(t.wait_exit(), 0);
    v.cmd()
        .arg("info")
        .assert()
        .success()
        .stdout(contains("Security level:   standard").and(contains("required:")));
    v.cmd().arg("list").write_stdin(format!("{phrase}\n")).assert().success();
}
