//! Clipboard via `wl-copy` (Wayland) or `xclip` (X11), with automatic clearing.
//!
//! SECURITY-CRITICAL.
//! - The secret goes to `wl-copy`/`xclip` via stdin, never as an argument
//!   (arguments are visible to everyone in `ps`).
//! - After copying, a detached helper process (`cakepass __clipboard-clear <tool>`)
//!   clears the clipboard after 20 seconds. The helper only receives a
//!   BLAKE2b hash of the secret (via stdin) and only clears the clipboard if
//!   it still holds that secret (compared in constant time). This way we never
//!   wipe something you copied yourself afterwards.
//!
//! Limitation: clipboard managers (Klipper, cliphist, etc.) may keep their own
//! history; we cannot clear that.

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Duration;

use blake2::{Blake2b512, Digest};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// The clipboard is cleared after this many seconds.
pub const CLEAR_AFTER_SECS: u64 = 20;
/// First argument with which `cakepass` starts as the clearing helper process.
pub const HELPER_ARG: &str = "__clipboard-clear";
const HASH_LEN: usize = 64;

/// Which clipboard program we use.
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

/// Pick a clipboard program based on the session and what is installed.
pub fn detect() -> Option<Tool> {
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty());
    let x11 = std::env::var_os("DISPLAY").is_some_and(|v| !v.is_empty());
    choose(wayland, x11, find_in_path)
}

fn choose(wayland: bool, x11: bool, installed: impl Fn(&str) -> bool) -> Option<Tool> {
    if wayland && installed("wl-copy") && installed("wl-paste") {
        Some(Tool::WlCopy)
    } else if x11 && installed("xclip") {
        // Also under Wayland with XWayland when wl-clipboard is missing.
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

/// Put `secret` on the clipboard.
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
    } // closing stdin = end of input
    let status = child.wait()?;
    if !status.success() {
        return Err(Error::InvalidInput(format!("{} reported an error", tool.name())));
    }
    Ok(())
}

/// Read the current clipboard contents (only for the clearing check).
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

/// Empty the clipboard.
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

/// Copy `secret` and start the helper process that clears it after 20 s.
pub fn copy_with_auto_clear(tool: Tool, secret: &[u8]) -> Result<()> {
    copy(tool, secret)?;
    // If starting the clearing helper fails we clear immediately:
    // a password must never stay on the clipboard indefinitely.
    if let Err(e) = spawn_clear_helper(tool, &hash(secret)) {
        let _ = clear(tool);
        return Err(e);
    }
    Ok(())
}

fn spawn_clear_helper(tool: Tool, digest: &[u8; HASH_LEN]) -> Result<()> {
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.args([HELPER_ARG, tool.name()]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null());
    // SAFETY: setsid() is async-signal-safe and touches no memory of the
    // parent. A session of its own makes sure Ctrl+C or closing the
    // terminal does not stop the helper process.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    child.stdin.take().expect("stdin is piped").write_all(digest)?;
    // The helper keeps running on its own. A background thread reaps the
    // process if it finishes before we do (e.g. inside `cakepass shell`).
    std::thread::spawn(move || child.wait());
    Ok(())
}

/// Main routine of the hidden helper process `cakepass __clipboard-clear`.
pub fn run_clear_helper(tool: Tool, seconds: u64) -> Result<()> {
    // SAFETY: ignoring a signal is always safe.
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }
    let mut expected = [0u8; HASH_LEN];
    std::io::stdin().read_exact(&mut expected)?;
    std::thread::sleep(Duration::from_secs(seconds));
    let still_ours = match paste(tool) {
        Ok(current) => bool::from(hash(&current).ct_eq(&expected)),
        // Cannot check? Then we clear to be safe.
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
    fn clipboard_program_choice() {
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
    fn hash_comparison() {
        assert!(bool::from(hash(b"abc").ct_eq(&hash(b"abc"))));
        assert!(!bool::from(hash(b"abc").ct_eq(&hash(b"abd"))));
        assert_eq!(Tool::from_name("xclip"), Some(Tool::Xclip));
        assert_eq!(Tool::from_name("something"), None);
    }
}
