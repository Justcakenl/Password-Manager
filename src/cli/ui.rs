//! Terminal output, with color only when it is possible and allowed.
//!
//! Messages go to stderr; data (lists, `--show`) goes to stdout.
//! Color is off with `--no-color`, the `NO_COLOR` environment variable,
//! `TERM=dumb`, or when the output is not a terminal (pipe or file).

use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

static COLOR_STDERR: AtomicBool = AtomicBool::new(false);
static COLOR_STDOUT: AtomicBool = AtomicBool::new(false);

pub fn init(no_color_flag: bool) {
    let allowed = !no_color_flag
        && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
        && std::env::var("TERM").map_or(true, |t| t != "dumb");
    COLOR_STDERR.store(allowed && std::io::stderr().is_terminal(), Ordering::Relaxed);
    COLOR_STDOUT.store(allowed && std::io::stdout().is_terminal(), Ordering::Relaxed);
}

fn paint(stdout: bool, code: &str, text: &str) -> String {
    let on = if stdout { &COLOR_STDOUT } else { &COLOR_STDERR };
    if on.load(Ordering::Relaxed) { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_string() }
}

/// Whether color is used on stderr (messages, logo).
pub fn color_on_stderr() -> bool {
    COLOR_STDERR.load(Ordering::Relaxed)
}

/// Whether color is used on stdout (lists, the screen mode).
pub fn color_on_stdout() -> bool {
    COLOR_STDOUT.load(Ordering::Relaxed)
}

/// Gray (for stderr).
pub fn dim_err(text: &str) -> String {
    paint(false, "2", text)
}

/// CakePass pink (for stderr).
pub fn pink(text: &str) -> String {
    paint(false, "38;5;211", text)
}

/// CakePass pink and bold (for stderr), e.g. for the prompt.
pub fn pink_bold(text: &str) -> String {
    paint(false, "1;38;5;205", text)
}

/// A colored label per item type (for stdout).
pub fn kind_label(kind: cakepass::vault::Kind) -> String {
    use cakepass::vault::Kind;
    let code = match kind {
        Kind::Login => "38;5;211",
        Kind::Api => "38;5;117",
        Kind::Note => "38;5;222",
    };
    paint(true, code, kind.label())
}

/// Clear the screen and the scrollback (e.g. after locking), so secrets
/// that were shown are no longer visible. Terminal only.
pub fn clear_screen() {
    use std::io::Write;
    if std::io::stderr().is_terminal() {
        let mut err = std::io::stderr();
        let _ = err.write_all(b"\x1b[2J\x1b[3J\x1b[H");
        let _ = err.flush();
    }
}

/// Bold (for stdout).
pub fn bold(text: &str) -> String {
    paint(true, "1", text)
}

/// Gray (for stdout).
pub fn dim(text: &str) -> String {
    paint(true, "2", text)
}

pub fn success(msg: &str) {
    eprintln!("{} {msg}", paint(false, "32;1", "✔"));
}

pub fn info(msg: &str) {
    eprintln!("{msg}");
}

pub fn warn(msg: &str) {
    eprintln!("{} {msg}", paint(false, "33;1", "warning:"));
}

pub fn error(msg: &str) {
    eprintln!("{} {msg}", paint(false, "31;1", "error:"));
}

/// A conspicuous box for important warnings.
pub fn banner(lines: &[&str]) {
    let width = lines.iter().map(|l| l.chars().count()).max().unwrap_or(0);
    let bar = "─".repeat(width + 2);
    eprintln!("{}", paint(false, "33;1", &format!("┌{bar}┐")));
    for l in lines {
        let pad = " ".repeat(width - l.chars().count());
        eprintln!("{}", paint(false, "33;1", &format!("│ {l}{pad} │")));
    }
    eprintln!("{}", paint(false, "33;1", &format!("└{bar}┘")));
}

/// Make text safe to display: control characters (such as ANSI escapes that
/// can manipulate your terminal) are made visible as `\u{1b}`.
/// Newlines and tabs are kept when `keep_newlines` is true.
pub fn safe(s: &str, keep_newlines: bool) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() && !(keep_newlines && (c == '\n' || c == '\t')) {
                format!("\\u{{{:x}}}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Write a line containing a secret straight to stdout (fd 1).
///
/// SECURITY: `println!` goes through an internal Rust buffer that is never
/// released and therefore never wiped; the last password shown would stay
/// there. Here we build the line in a `Zeroizing` buffer and write it out
/// without an intermediate buffer, after which it is wiped.
pub fn print_secret_line(label: &str, value: &str) -> std::io::Result<()> {
    use std::io::Write;
    std::io::stdout().flush()?;
    let mut line = zeroize::Zeroizing::new(String::with_capacity(label.len() + value.len() + 8));
    line.push_str(label);
    line.push_str(value);
    line.push('\n');
    let mut bytes = line.as_bytes();
    while !bytes.is_empty() {
        // SAFETY: a valid buffer with the given length.
        let n = unsafe { libc::write(1, bytes.as_ptr().cast(), bytes.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        bytes = &bytes[n as usize..];
    }
    Ok(())
}

/// Unix time → "2026-10-29 14:03 UTC".
pub fn format_time(secs: u64) -> String {
    if secs == 0 {
        return "-".into();
    }
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", rem / 3600, (rem % 3600) / 60)
}

/// Days since 1970-01-01 → (year, month, day). Algorithm by Howard Hinnant.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Truncate text to `max` characters (for tables).
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Pad text with spaces up to `width` characters.
pub fn pad(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n >= width { s.to_string() } else { format!("{s}{}", " ".repeat(width - n)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(format_time(0), "-");
        assert_eq!(format_time(86_400), "1970-01-02 00:00 UTC");
        assert_eq!(format_time(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(format_time(1_793_284_980), "2026-10-29 14:43 UTC");
    }

    #[test]
    fn control_characters_are_made_harmless() {
        assert_eq!(safe("a\u{1b}[2Jb", false), "a\\u{1b}[2Jb");
        assert_eq!(safe("r1\nr2", true), "r1\nr2");
        assert_eq!(safe("r1\nr2", false), "r1\\u{a}r2");
        assert_eq!(safe("p@ss wörd", false), "p@ss wörd");
    }

    #[test]
    fn text_helpers() {
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("abc", 4), "abc");
        assert_eq!(pad("é", 3), "é  ");
    }
}
