//! Uitvoer naar de terminal, met kleur alleen als dat kan en mag.
//!
//! Meldingen gaan naar stderr; gegevens (lijsten, `--show`) naar stdout.
//! Kleur staat uit bij `--no-color`, de omgevingsvariabele `NO_COLOR`,
//! `TERM=dumb`, of als de uitvoer geen terminal is (pipe of bestand).

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

/// Of er kleur gebruikt wordt op stderr (meldingen, logo).
pub fn color_on_stderr() -> bool {
    COLOR_STDERR.load(Ordering::Relaxed)
}

/// Grijs (voor stderr).
pub fn dim_err(text: &str) -> String {
    paint(false, "2", text)
}

/// CakePass-roze (voor stderr).
pub fn pink(text: &str) -> String {
    paint(false, "38;5;211", text)
}

/// CakePass-roze en vet (voor stderr), bijv. voor de prompt.
pub fn pink_bold(text: &str) -> String {
    paint(false, "1;38;5;205", text)
}

/// Een gekleurd label per soort item (voor stdout).
pub fn kind_label(kind: kluis::vault::Kind) -> String {
    use kluis::vault::Kind;
    let code = match kind {
        Kind::Login => "38;5;211",
        Kind::Api => "38;5;117",
        Kind::Note => "38;5;222",
    };
    paint(true, code, kind.label())
}

/// Wis het scherm én de scrollback (bijv. na vergrendelen), zodat getoonde
/// geheimen niet meer zichtbaar zijn. Alleen in een terminal.
pub fn clear_screen() {
    use std::io::Write;
    if std::io::stderr().is_terminal() {
        let mut err = std::io::stderr();
        let _ = err.write_all(b"\x1b[2J\x1b[3J\x1b[H");
        let _ = err.flush();
    }
}

/// Vetgedrukt (voor stdout).
pub fn bold(text: &str) -> String {
    paint(true, "1", text)
}

/// Grijs (voor stdout).
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
    eprintln!("{} {msg}", paint(false, "33;1", "waarschuwing:"));
}

pub fn error(msg: &str) {
    eprintln!("{} {msg}", paint(false, "31;1", "fout:"));
}

/// Een opvallend kader voor belangrijke waarschuwingen.
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

/// Maak tekst veilig om te tonen: stuurtekens (zoals ANSI-escapes die je
/// terminal kunnen manipuleren) worden zichtbaar gemaakt als `\u{1b}`.
/// Regeleinden en tabs blijven staan als `keep_newlines` waar is.
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

/// Schrijf een regel met een geheim rechtstreeks naar stdout (fd 1).
///
/// BEVEILIGING: `println!` gaat via een interne buffer van Rust die nooit
/// wordt vrijgegeven en dus ook niet gewist; het laatst getoonde wachtwoord
/// zou daar blijven staan. Hier bouwen we de regel in een `Zeroizing`-buffer
/// en schrijven die zonder tussenbuffer weg, waarna hij gewist wordt.
pub fn print_secret_line(label: &str, value: &str) -> std::io::Result<()> {
    use std::io::Write;
    std::io::stdout().flush()?;
    let mut line = zeroize::Zeroizing::new(String::with_capacity(label.len() + value.len() + 8));
    line.push_str(label);
    line.push_str(value);
    line.push('\n');
    let mut bytes = line.as_bytes();
    while !bytes.is_empty() {
        // SAFETY: geldige buffer met de opgegeven lengte.
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

/// Unix-tijd → "2026-10-29 14:03 UTC".
pub fn format_time(secs: u64) -> String {
    if secs == 0 {
        return "-".into();
    }
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", rem / 3600, (rem % 3600) / 60)
}

/// Dagen sinds 1970-01-01 → (jaar, maand, dag). Algoritme van Howard Hinnant.
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

/// Kap tekst af op `max` tekens (voor tabellen).
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Vul tekst aan met spaties tot `width` tekens.
pub fn pad(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n >= width { s.to_string() } else { format!("{s}{}", " ".repeat(width - n)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datums() {
        assert_eq!(format_time(0), "-");
        assert_eq!(format_time(86_400), "1970-01-02 00:00 UTC");
        assert_eq!(format_time(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(format_time(1_793_284_980), "2026-10-29 14:43 UTC");
    }

    #[test]
    fn stuurtekens_onschadelijk() {
        assert_eq!(safe("a\u{1b}[2Jb", false), "a\\u{1b}[2Jb");
        assert_eq!(safe("r1\nr2", true), "r1\nr2");
        assert_eq!(safe("r1\nr2", false), "r1\\u{a}r2");
        assert_eq!(safe("p@ss wörd", false), "p@ss wörd");
    }

    #[test]
    fn tekst_hulpjes() {
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("abc", 4), "abc");
        assert_eq!(pad("é", 3), "é  ");
    }
}
