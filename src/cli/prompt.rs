//! Invoer van de gebruiker.
//!
//! BEVEILIGINGSKRITIEK.
//! - Geheimen worden NOOIT via argumenten of omgevingsvariabelen gelezen.
//! - In een terminal gebruiken we een verborgen prompt (rpassword, via
//!   `/dev/tty`); tekens worden niet getoond.
//! - Als stdin geen terminal is (bijv. `generator | kluis add x`), lezen we
//!   één regel per vraag van stdin.
//! - We lezen stdin zonder buffer, byte voor byte. Zo blijven er geen
//!   geheimen in een verborgen leesbuffer hangen, en werkt de inactiviteits-
//!   timer van `kluis shell` (poll) betrouwbaar.

use std::io::{self, IsTerminal, Write};

use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use kluis::{Error, Result};

const MAX_LINE: usize = 1024 * 1024;
const MAX_MASTER_LEN: usize = 1024;
/// Minimale zxcvbn-score (0–4) voor een hoofd- of exportwachtwoord.
pub const MIN_SCORE: u8 = 3;

pub fn stdin_is_tty() -> bool {
    io::stdin().is_terminal()
}

/// Lees één regel van stdin (fd 0), zonder buffer. `None` = einde invoer.
pub fn read_raw_line() -> Result<Option<Zeroizing<String>>> {
    let mut buf = Zeroizing::new(Vec::with_capacity(256));
    loop {
        let mut byte = [0u8; 1];
        // SAFETY: we lezen hoogstens 1 byte in een geldige buffer van 1 byte.
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
            return Err(Error::InvalidInput("invoerregel is te lang".into()));
        }
        buf.push(byte[0]);
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    match String::from_utf8(std::mem::take(&mut *buf)) {
        Ok(s) => Ok(Some(Zeroizing::new(s))),
        Err(e) => {
            e.into_bytes().zeroize();
            Err(Error::InvalidInput("invoer is geen geldige UTF-8-tekst".into()))
        }
    }
}

/// Vraag om een gewone (zichtbare) regel tekst.
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

/// Vraag om ja/nee. Standaard is "nee".
pub fn confirm(prompt: &str) -> Result<bool> {
    let answer = line(&format!("{prompt} [j/N] "))?.to_lowercase();
    Ok(matches!(answer.as_str(), "j" | "ja" | "y" | "yes"))
}

/// Vraag om een geheim (verborgen invoer).
pub fn secret(prompt: &str) -> Result<SecretString> {
    if stdin_is_tty() {
        match rpassword::prompt_password(prompt) {
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

/// Twee geheimen vergelijken in constante tijd.
pub fn secrets_equal(a: &SecretString, b: &SecretString) -> bool {
    bool::from(a.expose_secret().as_bytes().ct_eq(b.expose_secret().as_bytes()))
}

/// Beoordeel de sterkte van een wachtwoord met zxcvbn. Geeft (score, advies).
pub fn strength(password: &str) -> (u8, Option<String>) {
    // zxcvbn wordt traag bij zeer lange invoer; de eerste 100 tekens zijn
    // ruim voldoende voor een betrouwbare ondergrens.
    let prefix: Zeroizing<String> = Zeroizing::new(password.chars().take(100).collect());
    let estimate = zxcvbn::zxcvbn(&prefix, &["kluis", "wachtwoord", "password"]);
    let score = u8::from(estimate.score());
    let advice = estimate.feedback().and_then(|f| f.warning()).map(|w| w.to_string());
    (score, advice)
}

/// Vraag (twee keer) om een nieuw, sterk wachtwoord.
///
/// `what` is bijvoorbeeld "hoofdwachtwoord" of "exportwachtwoord".
pub fn new_strong_password(what: &str) -> Result<SecretString> {
    let interactive = stdin_is_tty();
    for _ in 0..3 {
        let first = secret(&format!("Nieuw {what}: "))?;
        let pw = first.expose_secret();
        if pw.is_empty() {
            super::ui::warn("Het wachtwoord mag niet leeg zijn.");
        } else if pw.len() > MAX_MASTER_LEN {
            super::ui::warn("Het wachtwoord is te lang (max. 1024 bytes).");
        } else {
            let (score, advice) = strength(pw);
            if score < MIN_SCORE {
                super::ui::warn(&format!(
                    "Dit {what} is te zwak (sterkte {score}/4, minimaal {MIN_SCORE} nodig)."
                ));
                if let Some(a) = advice {
                    super::ui::info(&format!("  zxcvbn: {a}"));
                }
                super::ui::info(
                    "  Tip: neem 5 of meer willekeurige woorden, bijv. uit `kluis generate --passphrase --show`.",
                );
            } else {
                let again = secret(&format!("Herhaal {what}: "))?;
                if secrets_equal(&first, &again) {
                    return Ok(first);
                }
                super::ui::warn("De wachtwoorden komen niet overeen.");
            }
        }
        if !interactive {
            break;
        }
    }
    Err(Error::InvalidInput(format!("geen geldig {what} ingevoerd")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sterktecontrole() {
        assert!(strength("wachtwoord").0 < MIN_SCORE);
        assert!(strength("123456789").0 < MIN_SCORE);
        assert!(strength("Welkom2026!").0 < 4);
        assert!(strength("tq8#vLp2!mZr9wXe").0 >= MIN_SCORE);
        assert!(strength("grape-lantern-oyster-bulky-scenic-dwarf").0 >= MIN_SCORE);
        assert!(strength(&"a".repeat(5000)).0 < MIN_SCORE, "lange invoer is snel en zwak");
    }

    #[test]
    fn vergelijken() {
        let a = SecretString::from("abc".to_string());
        assert!(secrets_equal(&a, &SecretString::from("abc".to_string())));
        assert!(!secrets_equal(&a, &SecretString::from("abd".to_string())));
        assert!(!secrets_equal(&a, &SecretString::from("abcd".to_string())));
    }
}
