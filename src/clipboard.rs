//! Klembord via `wl-copy` (Wayland) of `xclip` (X11), met automatisch wissen.
//!
//! BEVEILIGINGSKRITIEK.
//! - Het geheim gaat via stdin naar `wl-copy`/`xclip`, nooit als argument
//!   (argumenten zijn voor iedereen zichtbaar in `ps`).
//! - Na het kopiëren start een los hulpproces (`kluis __clipboard-clear <tool>`) dat
//!   na 20 seconden het klembord wist. Het hulpproces krijgt alleen een
//!   BLAKE2b-hash van het geheim (via stdin) en wist het klembord alleen als
//!   het daar nog steeds in staat (vergelijking in constante tijd). Zo wissen
//!   we niet iets wat je daarna zelf gekopieerd hebt.
//!
//! Beperking: klembordbeheerders (Klipper, cliphist, enz.) kunnen een eigen
//! geschiedenis bijhouden; die kunnen wij niet wissen.

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Duration;

use blake2::{Blake2b512, Digest};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Na zoveel seconden wordt het klembord gewist.
pub const CLEAR_AFTER_SECS: u64 = 20;
/// Eerste argument waarmee `kluis` als wis-hulpproces start.
pub const HELPER_ARG: &str = "__clipboard-clear";
const HASH_LEN: usize = 64;

/// Welk klembordprogramma we gebruiken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    WlCopy,
    Xclip,
}

impl Tool {
    pub fn name(self) -> &'static str {
        match self {
            Tool::WlCopy => "wl-copy",
            Tool::Xclip => "xclip",
        }
    }

    pub fn from_name(s: &str) -> Option<Tool> {
        match s {
            "wl-copy" => Some(Tool::WlCopy),
            "xclip" => Some(Tool::Xclip),
            _ => None,
        }
    }
}

/// Kies een klembordprogramma op basis van de sessie en wat er geïnstalleerd is.
pub fn detect() -> Option<Tool> {
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty());
    let x11 = std::env::var_os("DISPLAY").is_some_and(|v| !v.is_empty());
    choose(wayland, x11, find_in_path)
}

fn choose(wayland: bool, x11: bool, installed: impl Fn(&str) -> bool) -> Option<Tool> {
    if wayland && installed("wl-copy") && installed("wl-paste") {
        Some(Tool::WlCopy)
    } else if x11 && installed("xclip") {
        // Ook onder Wayland met XWayland als wl-clipboard ontbreekt.
        Some(Tool::Xclip)
    } else {
        None
    }
}

fn find_in_path(prog: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| {
            std::fs::metadata(dir.join(prog))
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
    })
}

fn hash(data: &[u8]) -> [u8; HASH_LEN] {
    Blake2b512::digest(data).into()
}

/// Zet `secret` op het klembord.
pub fn copy(tool: Tool, secret: &[u8]) -> Result<()> {
    let mut cmd = match tool {
        Tool::WlCopy => Command::new("wl-copy"),
        Tool::Xclip => {
            let mut c = Command::new("xclip");
            c.args(["-selection", "clipboard", "-in"]);
            c
        }
    };
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    {
        let mut stdin = child.stdin.take().expect("stdin is piped");
        stdin.write_all(secret)?;
    } // stdin sluiten = einde invoer
    let status = child.wait()?;
    if !status.success() {
        return Err(Error::InvalidInput(format!("{} gaf een fout", tool.name())));
    }
    Ok(())
}

/// Lees de huidige klembordinhoud (alleen voor de wis-controle).
fn paste(tool: Tool) -> Result<Zeroizing<Vec<u8>>> {
    let mut cmd = match tool {
        Tool::WlCopy => {
            let mut c = Command::new("wl-paste");
            c.arg("--no-newline");
            c
        }
        Tool::Xclip => {
            let mut c = Command::new("xclip");
            c.args(["-selection", "clipboard", "-out"]);
            c
        }
    };
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;
    let mut out = Zeroizing::new(Vec::new());
    child.stdout.take().expect("stdout is piped").read_to_end(&mut out)?;
    child.wait()?;
    Ok(out)
}

/// Maak het klembord leeg.
pub fn clear(tool: Tool) -> Result<()> {
    let mut cmd = match tool {
        Tool::WlCopy => {
            let mut c = Command::new("wl-copy");
            c.arg("--clear");
            c
        }
        Tool::Xclip => {
            let mut c = Command::new("xclip");
            c.args(["-selection", "clipboard", "-in"]);
            c
        }
    };
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status()?;
    Ok(())
}

/// Kopieer `secret` en start het hulpproces dat het na 20 s wist.
pub fn copy_with_auto_clear(tool: Tool, secret: &[u8]) -> Result<()> {
    copy(tool, secret)?;
    let digest = hash(secret);
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.args([HELPER_ARG, tool.name()]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null());
    // SAFETY: setsid() is async-signal-safe en raakt geen geheugen van de
    // ouder aan. Een eigen sessie zorgt dat Ctrl+C of het sluiten van de
    // terminal het hulpproces niet stopt.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    child.stdin.take().expect("stdin is piped").write_all(&digest)?;
    // We wachten niet op het hulpproces; het draait zelfstandig verder.
    Ok(())
}

/// Hoofdroutine van het verborgen hulpproces `kluis __clipboard-clear`.
pub fn run_clear_helper(tool: Tool, seconds: u64) -> Result<()> {
    // SAFETY: een signaal negeren is altijd veilig.
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }
    let mut expected = [0u8; HASH_LEN];
    std::io::stdin().read_exact(&mut expected)?;
    std::thread::sleep(Duration::from_secs(seconds));
    let still_ours = match paste(tool) {
        Ok(current) => bool::from(hash(&current).ct_eq(&expected)),
        // Kunnen we niet controleren? Dan wissen we voor de zekerheid.
        Err(_) => true,
    };
    if still_ours {
        clear(tool)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keuze_van_klembordprogramma() {
        let all = |_: &str| true;
        let none = |_: &str| false;
        let only_xclip = |p: &str| p == "xclip";
        assert_eq!(choose(true, false, all), Some(Tool::WlCopy));
        assert_eq!(choose(true, true, all), Some(Tool::WlCopy));
        assert_eq!(choose(false, true, all), Some(Tool::Xclip));
        assert_eq!(choose(true, true, only_xclip), Some(Tool::Xclip));
        assert_eq!(choose(true, false, only_xclip), None);
        assert_eq!(choose(true, true, none), None);
        assert_eq!(choose(false, false, all), None);
    }

    #[test]
    fn hash_vergelijking() {
        assert!(bool::from(hash(b"abc").ct_eq(&hash(b"abc"))));
        assert!(!bool::from(hash(b"abc").ct_eq(&hash(b"abd"))));
        assert_eq!(Tool::from_name("xclip"), Some(Tool::Xclip));
        assert_eq!(Tool::from_name("iets"), None);
    }
}
