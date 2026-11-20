//! Read a 2FA QR code from the screen: `slurp` (you drag a box around the
//! QR code), `grim` (a picture of that box) and `zbarimg` (reads the code).
//!
//! SECURITY:
//! - No image code runs inside CakePass: the picture is decoded by the
//!   separate program `zbarimg`, so a hostile image cannot reach the process
//!   that holds the vault key. Its output is untrusted text: only an
//!   `otpauth://totp/` link of limited size gets through, and it is checked
//!   again by `Totp::parse_new` like a typed secret.
//! - No shell: every program is its own `Command`; the picture goes from
//!   `grim` to `zbarimg` through pipes, in `Zeroizing` memory. It never
//!   touches the disk or the clipboard.
//! - Every program has a time limit and a size limit on what it writes, so
//!   a program that hangs cannot hang CakePass.
//! - Offline: nothing here uses the network.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use cakepass::{Error, Result};
use zeroize::Zeroizing;

/// The most a selection (`x,y wxh`) from `slurp` may be.
const MAX_GEOMETRY: usize = 64;
/// The most a picture from `grim` may be.
const MAX_PICTURE: usize = 32 * 1024 * 1024;
/// The most text read from `zbarimg`.
const MAX_DECODED: usize = 4 * 1024;
/// The longest link that is accepted.
const MAX_LINK: usize = 2 * 1024;

/// What the user is told when a program is missing.
pub const NEEDS_TOOLS: &str =
    "Scanning a QR code needs grim, slurp and zbar (sudo pacman -S grim slurp zbar) and a Wayland desktop.";

/// Drag a box around a QR code on the screen and read it. `Ok(None)` when
/// the selection was cancelled (Esc). The link is an `otpauth://totp/`
/// link, still to be checked with `Totp::parse_new`.
///
/// SECURITY: never from the clipboard. A clipboard history (Omarchy's keeps
/// every picture as a PNG file) would store a screenshot of the QR code, and
/// with it the secret, on disk; the picture from `grim` only goes through a
/// pipe.
pub fn scan_screen() -> Result<Option<Zeroizing<String>>> {
    if std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return Err(Error::InvalidInput(NEEDS_TOOLS.into()));
    }
    // 1. Where is the QR code? (Esc in slurp: it exits with an error.)
    let (ok, geometry) = run("slurp", &[], None, MAX_GEOMETRY, Duration::from_secs(120))?;
    let geometry = String::from_utf8_lossy(&geometry).trim().to_string();
    if !ok || geometry.is_empty() {
        return Ok(None);
    }
    if !valid_geometry(&geometry) {
        return Err(Error::InvalidInput("the selected area was not understood".into()));
    }
    // 2. A picture of it, into memory.
    let (ok, picture) = run("grim", &["-g", &geometry, "-"], None, MAX_PICTURE, Duration::from_secs(30))?;
    if !ok || picture.is_empty() {
        return Err(Error::InvalidInput("could not take a picture of the screen (grim)".into()));
    }
    // 3. Read the code (zbarimg exits with 4 when it finds none).
    let (_, decoded) =
        run("zbarimg", &["--raw", "-q", "-"], Some(&picture), MAX_DECODED, Duration::from_secs(30))?;
    drop(picture);
    pick_link(&decoded).map(Some)
}

/// Whether this computer sets its clock automatically (`timedatectl`:
/// NTPSynchronized). 2FA codes come from the clock, so a clock that is off
/// by half a minute gives codes that sites refuse. `None` when it cannot be
/// told (no systemd): then nothing is said. Local only, no network.
pub fn clock_synced() -> Option<bool> {
    let (ok, out) =
        run("timedatectl", &["show", "-p", "NTPSynchronized", "--value"], None, 64, Duration::from_secs(3))
            .ok()?;
    match (ok, String::from_utf8_lossy(&out).trim()) {
        (true, "yes") => Some(true),
        (true, "no") => Some(false),
        _ => None,
    }
}

/// A selection from `slurp`: `X,Y WxH`. X and Y may be negative (a monitor
/// left of or above the main one); W and H are positive numbers.
fn valid_geometry(g: &str) -> bool {
    fn int(s: &str) -> bool {
        let digits = s.strip_prefix('-').unwrap_or(s);
        !digits.is_empty() && digits.len() <= 6 && digits.bytes().all(|b| b.is_ascii_digit())
    }
    fn size(s: &str) -> bool {
        !s.is_empty() && s.len() <= 6 && s.bytes().all(|b| b.is_ascii_digit()) && s.bytes().any(|b| b != b'0')
    }
    if g.len() > MAX_GEOMETRY {
        return false;
    }
    let Some((pos, dims)) = g.split_once(' ') else { return false };
    let (Some((x, y)), Some((w, h))) = (pos.split_once(','), dims.split_once('x')) else { return false };
    int(x) && int(y) && size(w) && size(h)
}

/// The 2FA link in what `zbarimg` read: the first line that is an
/// `otpauth://totp/` link. A Google Authenticator export holds every
/// secret at once and is refused as a whole.
fn pick_link(decoded: &[u8]) -> Result<Zeroizing<String>> {
    let text = Zeroizing::new(String::from_utf8_lossy(decoded).into_owned());
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    if text.trim().is_empty() {
        return Err(Error::InvalidInput(
            "no QR code found in that area; drag the box around the whole code".into(),
        ));
    }
    if lines.clone().any(|l| starts_with_ci(l, "otpauth-migration://")) {
        return Err(Error::InvalidInput(
            "this is an export of Google Authenticator (all codes at once); move the codes one by one: \
             on each site, show the QR code of its 2FA setting"
                .into(),
        ));
    }
    let link = lines.find(|l| starts_with_ci(l, "otpauth://totp/")).ok_or_else(|| {
        Error::InvalidInput("that QR code is not a 2FA code (no otpauth://totp/ link)".into())
    })?;
    if link.len() > MAX_LINK || link.chars().any(char::is_control) {
        return Err(Error::InvalidInput("that QR code is not a 2FA code CakePass can use".into()));
    }
    Ok(Zeroizing::new(link.to_string()))
}

fn starts_with_ci(text: &str, prefix: &str) -> bool {
    text.get(..prefix.len()).is_some_and(|p| p.eq_ignore_ascii_case(prefix))
}

/// The account in a 2FA link (`otpauth://totp/Issuer:account?…`, or the
/// `issuer=` field), as a suggested item name: plain characters only, at
/// most 40. `None` when there is nothing usable.
pub fn suggested_name(link: &str) -> Option<String> {
    let rest = &link["otpauth://totp/".len().min(link.len())..];
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let issuer = query
        .split('&')
        .find_map(|p| p.split_once('=').filter(|(k, _)| k.eq_ignore_ascii_case("issuer")).map(|(_, v)| v));
    let raw = issuer.unwrap_or_else(|| label.split(':').next().unwrap_or(""));
    let decoded = percent_decode_lossy(raw);
    let name: String = decoded
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}'))
        .take(40)
        .collect();
    let name = name.trim().to_string();
    (!name.is_empty()).then_some(name)
}

/// `%41` → `A` and `+` → space; anything else stays as it is.
fn percent_decode_lossy(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = b.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok());
        match (b[i], hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(v)) => {
                out.push(v);
                i += 3;
                continue;
            }
            (b'+', _) => out.push(b' '),
            (c, _) => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Run `program args`, give it `input` on stdin, and read at most `max`
/// bytes of its stdout within `limit`. Returns (exited with success, output).
/// A program that is missing gives the "needs grim, slurp and zbar" error;
/// one that runs too long is killed.
fn run(
    program: &str,
    args: &[&str],
    input: Option<&[u8]>,
    max: usize,
    limit: Duration,
) -> Result<(bool, Zeroizing<Vec<u8>>)> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::InvalidInput(NEEDS_TOOLS.into()),
            _ => Error::Io(e),
        })?;
    let result = std::thread::scope(|s| {
        if let (Some(data), Some(mut stdin)) = (input, child.stdin.take()) {
            s.spawn(move || {
                let _ = stdin.write_all(data); // a program that stops reading: fine
            });
        }
        let mut stdout = child.stdout.take().expect("piped");
        let reader = s.spawn(move || {
            let mut out = Zeroizing::new(Vec::new());
            let mut buf = Zeroizing::new([0u8; 8192]);
            loop {
                match stdout.read(&mut buf[..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) if out.len() + n > max => return Err(()),
                    Ok(n) => out.extend_from_slice(&buf[..n]),
                }
            }
            Ok(out)
        });
        let status = wait_or_kill(&mut child, limit);
        let out = reader.join().unwrap_or(Err(()));
        (status, out)
    });
    match result {
        (None, _) => Err(Error::InvalidInput(format!("{program} took too long and was stopped"))),
        (_, Err(())) => {
            let _ = child.kill();
            Err(Error::InvalidInput(format!("{program} gave more output than expected")))
        }
        (Some(ok), Ok(out)) => Ok((ok, out)),
    }
}

/// Wait for `child` until `limit`; then kill it. `None` when it was killed.
fn wait_or_kill(child: &mut Child, limit: Duration) -> Option<bool> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status.success()),
            Ok(None) if start.elapsed() >= limit => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return Some(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_2fa_link_gets_through() {
        let ok = pick_link(b"otpauth://totp/GitHub:john?secret=GEZDGNBVGY3TQOJQ&issuer=GitHub\n").unwrap();
        assert!(ok.starts_with("otpauth://totp/GitHub"));
        assert!(pick_link(b"  \n").unwrap_err().to_string().contains("no QR code found"));
        assert!(pick_link(b"https://example.org\n").unwrap_err().to_string().contains("not a 2FA code"));
        assert!(pick_link(b"otpauth://hotp/x?secret=AAAA&counter=1").is_err(), "counter-based codes");
        let google = pick_link(b"otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8").unwrap_err();
        assert!(google.to_string().contains("Google Authenticator"), "{google}");
        let long = format!("otpauth://totp/x?secret={}", "A".repeat(MAX_LINK));
        assert!(pick_link(long.as_bytes()).is_err());
        assert!(pick_link(b"otpauth://totp/x?secret=GEZD\x1b]0;t\x07").is_err(), "escape codes");
    }

    #[test]
    fn a_selection_is_only_numbers() {
        assert!(valid_geometry("10,20 300x400"));
        assert!(valid_geometry("-1920,-100 300x300"), "a monitor to the left");
        for bad in [
            "",
            "10,20",
            "10,20 30x40; rm -rf ~",
            "-g 1",
            "1,2 3x4 5",
            "1,2 0x4",
            "1,2 -3x4",
            "--1,2 3x4",
            "1,,2 3x4",
        ] {
            assert!(!valid_geometry(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_suggested_name_is_plain_text() {
        let n = |l: &str| suggested_name(l);
        assert_eq!(n("otpauth://totp/GitHub:john?secret=X&issuer=GitHub").as_deref(), Some("GitHub"));
        assert_eq!(n("otpauth://totp/My%20Bank:j?secret=X").as_deref(), Some("My Bank"));
        assert_eq!(n("otpauth://totp/x?secret=X&issuer=Evil%1B%5D0%3Bt%07Co").as_deref(), Some("Evil]0;tCo"));
        assert_eq!(n("otpauth://totp/?secret=X"), None);
        assert_eq!(n(&format!("otpauth://totp/{}?secret=X", "a".repeat(80))).unwrap().len(), 40);
    }

    /// The real zbarimg on a real QR code (made with qrencode), when both
    /// are installed: the picture goes in through the pipe, the link out.
    #[test]
    fn zbarimg_reads_a_2fa_qr_code_from_a_pipe() {
        let link = "otpauth://totp/GitHub:john?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub";
        let Ok((true, png)) =
            run("qrencode", &["-o", "-", "-s", "6", link], None, MAX_PICTURE, Duration::from_secs(10))
        else {
            eprintln!("qrencode is not installed; skipped");
            return;
        };
        let Ok((_, decoded)) =
            run("zbarimg", &["--raw", "-q", "-"], Some(&png), MAX_DECODED, Duration::from_secs(30))
        else {
            eprintln!("zbarimg is not installed; skipped");
            return;
        };
        assert_eq!(pick_link(&decoded).unwrap().as_str(), link);
    }

    /// The real pipeline with stand-ins for slurp, grim and zbarimg.
    #[test]
    fn the_programs_run_with_limits() {
        let dir = tempfile::tempdir().unwrap();
        let script = |name: &str, body: &str| {
            use std::os::unix::fs::PermissionsExt;
            let p = dir.path().join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        let cat = script("echo-input", "cat");
        let (ok, out) =
            run(cat.to_str().unwrap(), &[], Some(b"picture"), 100, Duration::from_secs(5)).unwrap();
        assert!(ok && out.as_slice() == b"picture");
        let slow = script("slow", "exec sleep 5");
        let e = run(slow.to_str().unwrap(), &[], None, 100, Duration::from_millis(200)).unwrap_err();
        assert!(e.to_string().contains("took too long"), "{e}");
        let big = script("big", "yes");
        let e = run(big.to_str().unwrap(), &[], None, 1000, Duration::from_secs(5)).unwrap_err();
        assert!(e.to_string().contains("more output"), "{e}");
        let e = run("cakepass-no-such-program", &[], None, 10, Duration::from_secs(1)).unwrap_err();
        assert!(e.to_string().contains("grim, slurp and zbar"), "{e}");
    }
}
