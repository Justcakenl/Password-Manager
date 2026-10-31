//! User input.
//!
//! SECURITY-CRITICAL.
//! - Secrets are NEVER read from arguments or environment variables.
//! - In a terminal we use a hidden prompt (rpassword, via `/dev/tty`);
//!   characters are not echoed.
//! - When stdin is not a terminal (e.g. `generator | cakepass add x`) we read
//!   one line per question from stdin.
//! - We read stdin without a buffer, byte by byte. This leaves no secrets in
//!   a hidden read buffer, and makes the inactivity timer of `cakepass shell`
//!   (poll) reliable.

use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicU64, Ordering};

use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use cakepass::{Error, Result};

const MAX_LINE: usize = 1024 * 1024;
const MAX_MASTER_LEN: usize = 1024;
/// Minimum zxcvbn score (0–4) for a master or export password.
pub const MIN_SCORE: u8 = 3;

/// Time (seconds since 1970) of the last input; for the inactivity
/// watchdog of `cakepass shell`.
static LAST_ACTIVITY: AtomicU64 = AtomicU64::new(0);

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Record that the user entered something.
pub fn mark_activity() {
    LAST_ACTIVITY.store(now_secs(), Ordering::Relaxed);
}

/// Seconds since the last input.
pub fn idle_secs() -> u64 {
    now_secs().saturating_sub(LAST_ACTIVITY.load(Ordering::Relaxed))
}

pub fn stdin_is_tty() -> bool {
    io::stdin().is_terminal()
}

/// Read one line from stdin (fd 0), without a buffer. `None` = end of input.
pub fn read_raw_line() -> Result<Option<Zeroizing<String>>> {
    let mut buf = Zeroizing::new(Vec::with_capacity(256));
    loop {
        let mut byte = [0u8; 1];
        // SAFETY: we read at most 1 byte into a valid buffer of 1 byte.
        let n = unsafe { libc::read(0, byte.as_mut_ptr().cast(), 1) };
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err.into());
        }
        if byte[0] == b'\n' {
            break;
        }
        if buf.len() >= MAX_LINE {
            return Err(Error::InvalidInput("input line is too long".into()));
        }
        buf.push(byte[0]);
    }
    mark_activity();
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    match String::from_utf8(std::mem::take(&mut *buf)) {
        Ok(s) => Ok(Some(Zeroizing::new(s))),
        Err(e) => {
            e.into_bytes().zeroize();
            Err(Error::InvalidInput("input is not valid UTF-8 text".into()))
        }
    }
}

/// Ask for an ordinary (visible) line of text.
pub fn line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    match read_raw_line()? {
        Some(s) => Ok(s.trim().to_string()),
        None => {
            eprintln!();
            Err(Error::Cancelled)
        }
    }
}

/// Ask for multi-line text (for notes). In a terminal you finish with a line
/// containing only a dot (`.`) or with Ctrl+D.
pub fn multiline(intro: &str) -> Result<Zeroizing<String>> {
    let tty = stdin_is_tty();
    if tty {
        super::ui::info(intro);
        super::ui::info(&super::ui::dim_err(
            "  Finish with a line containing only a dot (.) or press Ctrl+D.",
        ));
    }
    let mut out = Zeroizing::new(String::new());
    loop {
        if tty {
            eprint!("{} ", super::ui::pink("│"));
            io::stderr().flush()?;
        }
        match read_raw_line()? {
            None => {
                if tty {
                    eprintln!();
                }
                break;
            }
            Some(line) if line.as_str() == "." => break,
            Some(line) => {
                if out.len() + line.len() > 64 * 1024 {
                    return Err(Error::InvalidInput("the text is too long (max. 64 KiB)".into()));
                }
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(&line);
            }
        }
    }
    Ok(out)
}

/// Ask yes/no. The default is "no".
pub fn confirm(prompt: &str) -> Result<bool> {
    ask_yes_no(prompt, false)
}

/// Ask yes/no with a chosen default (shown as `[Y/n]` or `[y/N]`).
pub fn ask_yes_no(prompt: &str, default: bool) -> Result<bool> {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    let answer = line(&format!("{prompt} {hint} "))?.to_lowercase();
    Ok(match answer.as_str() {
        "" => default,
        "y" | "yes" => true,
        _ => false,
    })
}

/// Ask for a secret (hidden input).
pub fn secret(prompt: &str) -> Result<SecretString> {
    if stdin_is_tty() {
        let result = rpassword::prompt_password(prompt);
        mark_activity();
        match result {
            Ok(s) => Ok(SecretString::from(s)),
            Err(e) if matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::UnexpectedEof) => {
                Err(Error::Cancelled)
            }
            Err(e) => Err(e.into()),
        }
    } else {
        eprint!("{prompt}");
        io::stderr().flush()?;
        let s = read_raw_line()?.ok_or(Error::Cancelled)?;
        eprintln!();
        Ok(SecretString::from(s.to_string()))
    }
}

/// Compare two secrets in constant time.
pub fn secrets_equal(a: &SecretString, b: &SecretString) -> bool {
    bool::from(a.expose_secret().as_bytes().ct_eq(b.expose_secret().as_bytes()))
}

/// Judge the strength of a password with zxcvbn. Returns (score, advice).
pub fn strength(password: &str) -> (u8, Option<String>) {
    // zxcvbn gets slow on very long input; the first 100 characters are
    // plenty for a reliable lower bound.
    let prefix: Zeroizing<String> = Zeroizing::new(password.chars().take(100).collect());
    let estimate = zxcvbn::zxcvbn(&prefix, &["cakepass", "password"]);
    let score = u8::from(estimate.score());
    let advice = estimate.feedback().and_then(|f| f.warning()).map(|w| w.to_string());
    (score, advice)
}

/// Ask (twice) for a new, strong password.
///
/// `what` is for example "master password" or "export password".
pub fn new_strong_password(what: &str) -> Result<SecretString> {
    let interactive = stdin_is_tty();
    for _ in 0..3 {
        let first = secret(&format!("New {what}: "))?;
        let pw = first.expose_secret();
        if pw.is_empty() {
            super::ui::warn("The password must not be empty.");
        } else if pw.len() > MAX_MASTER_LEN {
            super::ui::warn("The password is too long (max. 1024 bytes).");
        } else {
            let (score, advice) = strength(pw);
            if score < MIN_SCORE {
                super::ui::warn(&format!(
                    "This {what} is too weak (strength {score}/4, at least {MIN_SCORE} required)."
                ));
                if let Some(a) = advice {
                    super::ui::info(&format!("  zxcvbn: {a}"));
                }
                super::ui::info(
                    "  Tip: use 5 or more random words, e.g. from `cakepass generate --passphrase --show`.",
                );
            } else {
                let again = secret(&format!("Repeat {what}: "))?;
                if secrets_equal(&first, &again) {
                    return Ok(first);
                }
                super::ui::warn("The passwords do not match.");
            }
        }
        if !interactive {
            break;
        }
    }
    Err(Error::InvalidInput(format!("no valid {what} entered")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strength_check() {
        assert!(strength("password").0 < MIN_SCORE);
        assert!(strength("123456789").0 < MIN_SCORE);
        assert!(strength("Welcome2026!").0 < 4);
        assert!(strength("tq8#vLp2!mZr9wXe").0 >= MIN_SCORE);
        assert!(strength("grape-lantern-oyster-bulky-scenic-dwarf").0 >= MIN_SCORE);
        assert!(strength(&"a".repeat(5000)).0 < MIN_SCORE, "long input is fast and weak");
    }

    #[test]
    fn comparing() {
        let a = SecretString::from("abc".to_string());
        assert!(secrets_equal(&a, &SecretString::from("abc".to_string())));
        assert!(!secrets_equal(&a, &SecretString::from("abd".to_string())));
        assert!(!secrets_equal(&a, &SecretString::from("abcd".to_string())));
    }
}
