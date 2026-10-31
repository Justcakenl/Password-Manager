//! `cakepass shell`: unlock once, then type commands.
//!
//! SECURITY: when no input arrives for `timeout` seconds, the vault is
//! locked automatically: the key and all decrypted data are wiped from memory
//! and the program exits. For `passwd` and `export` the shell asks for the
//! master password again.

use std::io::{self, Write};

use clap::FromArgMatches;

use cakepass::storage::VaultPaths;
use cakepass::{Error, Result};

use super::args::{ShellLine, shell_command};
use super::{commands, prompt, ui};

const MAX_TIMEOUT: u64 = 24 * 60 * 60;

enum Wait {
    Ready,
    TimedOut,
}

/// Wait at most `secs` seconds until there is input on stdin.
fn wait_for_input(secs: u64) -> Result<Wait> {
    let mut fds = libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 };
    let ms = i32::try_from(secs * 1000).unwrap_or(i32::MAX);
    loop {
        // SAFETY: one valid pollfd struct.
        let r = unsafe { libc::poll(&mut fds, 1, ms) };
        if r > 0 {
            return Ok(Wait::Ready); // input, or end of input (POLLHUP)
        }
        if r == 0 {
            return Ok(Wait::TimedOut);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err.into());
        }
    }
}

/// Watchdog: also locks when you walk away in the middle of a question (e.g.
/// "Username:" or a hidden password prompt). The process then exits at once;
/// the operating system releases all memory (and wipes pages before another
/// process gets them). The terminal settings are restored first.
fn start_watchdog(timeout: u64, human: String) {
    // SAFETY: termios is a plain C struct; tcgetattr fills it in.
    let saved = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        (libc::isatty(0) == 1 && libc::tcgetattr(0, &mut t) == 0).then_some(t)
    };
    prompt::mark_activity();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            // Slightly more generous than the timeout, so at the normal prompt
            // the clean route (with explicit wiping) gets its turn first.
            if prompt::idle_secs() > timeout + 2 {
                if let Some(t) = saved {
                    // SAFETY: a valid termios that we read ourselves earlier.
                    unsafe {
                        libc::tcsetattr(0, libc::TCSANOW, &t);
                    }
                }
                ui::clear_screen();
                eprintln!();
                ui::info(&format!("🔒 Locked automatically after {human} without input."));
                std::process::exit(0);
            }
        }
    });
}

/// Convenience inside the interactive mode: `get my bank` means `get "my bank"`.
/// Applies to commands with a single name and only on/off options.
fn join_name_words(words: Vec<String>) -> Vec<String> {
    const SIMPLE: [&str; 7] = ["get", "show", "rm", "remove", "delete", "search", "find"];
    match words.first() {
        Some(cmd) if SIMPLE.contains(&cmd.as_str()) => {
            let (flags, names): (Vec<String>, Vec<String>) =
                words[1..].iter().cloned().partition(|w| w.starts_with('-'));
            let mut out = vec![cmd.clone()];
            if !names.is_empty() {
                out.push(names.join(" "));
            }
            out.extend(flags);
            out
        }
        _ => words,
    }
}

fn print_help() {
    let help = shell_command().render_help();
    eprintln!("{help}");
    eprintln!("Also: help, exit/quit/lock (lock, clear the screen and quit).");
    eprintln!(
        "Put names with spaces in quotes: get \"My Bank\" (get, rm and search also accept plain words)"
    );
}

/// "5 min" or "90 s".
pub(super) fn describe(timeout: u64) -> String {
    if timeout.is_multiple_of(60) { format!("{} min", timeout / 60) } else { format!("{timeout} s") }
}

pub fn run(paths: &VaultPaths, timeout: u64) -> Result<()> {
    if timeout == 0 || timeout > MAX_TIMEOUT {
        return Err(Error::InvalidInput("the timeout must be between 1 and 86400 seconds".into()));
    }
    let mut uv = commands::login_screen(paths)?;
    let human = describe(timeout);
    ui::success(&format!("Vault unlocked — {}.", commands::vault_summary(&uv.vault)));
    ui::info(&format!(
        "  Type 'help' for the commands or 'exit' to lock. \
         After {human} without input CakePass locks itself."
    ));

    start_watchdog(timeout, human.clone());
    loop {
        eprint!("{} ", ui::pink_bold("cakepass ❯"));
        io::stderr().flush()?;
        if let Wait::TimedOut = wait_for_input(timeout)? {
            eprintln!();
            ui::info(&format!("Locked automatically after {human} without input."));
            break;
        }
        let Some(line) = prompt::read_raw_line()? else {
            eprintln!();
            break; // Ctrl+D or end of input
        };
        let line = line.trim();
        match line {
            "" => continue,
            "exit" | "quit" | "lock" | "q" => break,
            "help" | "?" => {
                print_help();
                continue;
            }
            _ => {}
        }
        let Some(words) = shlex::split(line) else {
            ui::error("invalid quotes");
            continue;
        };
        let argv = std::iter::once("cakepass".to_string()).chain(join_name_words(words));
        let parsed = shell_command().try_get_matches_from(argv).and_then(|m| ShellLine::from_arg_matches(&m));
        match parsed {
            Ok(parsed) => match commands::execute(&mut uv, parsed.command, true) {
                Ok(()) => {}
                Err(Error::Cancelled) => ui::info("Cancelled."),
                Err(Error::ConcurrentModification) => {
                    ui::error(
                        "the vault was changed outside this shell. Close the shell (exit) and open \
                         it again; your last change was not saved.",
                    );
                }
                Err(e) => ui::error(&e.to_string()),
            },
            Err(e) => {
                let _ = e.print();
            }
        }
    }
    drop(uv);
    // Clear the screen (and scrollback), so secrets that were shown are gone.
    ui::clear_screen();
    ui::success("🔒 CakePass locked; the key has been wiped from memory.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<String> {
        shlex::split(s).unwrap()
    }

    #[test]
    fn loose_words_become_one_name() {
        assert_eq!(join_name_words(w("get my bank --show")), w("get 'my bank' --show"));
        assert_eq!(join_name_words(w("rm old site -y")), w("rm 'old site' -y"));
        assert_eq!(join_name_words(w("get \"already fine\"")), w("get 'already fine'"));
        assert_eq!(join_name_words(w("edit a --username b")), w("edit a --username b"), "leave edit alone");
        assert_eq!(join_name_words(w("list")), w("list"));
    }

    #[test]
    fn timeout_description() {
        assert_eq!(describe(300), "5 min");
        assert_eq!(describe(90), "90 s");
    }
}
