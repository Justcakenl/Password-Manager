//! `cakepass --update`: update CakePass to the newest version on GitHub.
//!
//! SECURITY-CRITICAL – how this works and why it is as safe as possible:
//!
//! - The program itself contains NO network code. Only this command starts
//!   the program `git`, and `git` uses your own GitHub access (SSH key or
//!   login). `cakepass` never stores a token or password for GitHub.
//! - The command does NOT unlock your vault: while updating there is no key
//!   or password in memory.
//! - Your vault (`~/.local/share/cakepass/`) lives outside the installation and
//!   is never overwritten. Beforehand we make an extra copy (`.pre-update-…`).
//!   Newer versions read older vault formats and write the newest format on
//!   the next save (CakePass 0.4 writes format 3, which 0.3 cannot read); an
//!   older version cleanly refuses a newer format.
//! - We only fetch new commits with `git merge --ff-only`. That never rewrites
//!   your history. If you have changes of your own in the folder, we stop.
//! - You first see what is new (the commit titles) and where it comes from,
//!   and must confirm.
//! - Building is done with `makepkg` (including all tests). If anything
//!   fails, we restore the folder as it was; your current version keeps
//!   working.
//!
//! The daily check (`--check`, via a systemd timer) only fetches and reports
//! that an update exists; you install it yourself. A password manager that
//! replaces itself without you looking is too big a risk: anyone who can get
//! into your GitHub account could then run code on your computer that has
//! access to your vault.

use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use cakepass::storage::{self, VaultPaths};
use cakepass::{Error, Result};
use clap::ValueEnum;

use super::{prompt, ui};

/// The commit this program was built from (see build.rs).
pub const INSTALLED_COMMIT: &str = env!("CAKEPASS_GIT_COMMIT");
/// Where the PKGBUILD records the source folder of the installation.
const SOURCE_DIR_FILE: &str = "/usr/share/cakepass/source-dir";
const FETCH_TIMEOUT: Duration = Duration::from_secs(120);
const TIMER: &str = "cakepass-update.timer";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AutoMode {
    /// Check automatically every day
    On,
    /// Stop checking automatically
    Off,
    /// Show whether it is on
    Status,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub check_only: bool,
    pub yes: bool,
    pub notify: bool,
    pub source: Option<PathBuf>,
    pub auto: Option<AutoMode>,
}

// ───────────────────────── git ─────────────────────────

/// Run `git` in `dir`. `unattended` = never ask for a password.
fn git(dir: &Path, args: &[&str], unattended: bool) -> Result<String> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(dir).arg("--no-pager").args(args).env("LC_ALL", "C");
    if unattended {
        cmd.env("GIT_TERMINAL_PROMPT", "0").stdin(Stdio::null());
        if std::env::var_os("GIT_SSH_COMMAND").is_none() {
            cmd.env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes -o ConnectTimeout=20");
        }
    } else {
        cmd.stdin(Stdio::inherit());
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(if unattended { Stdio::piped() } else { Stdio::inherit() })
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                Error::InvalidInput("`git` is not installed (sudo pacman -S git)".into())
            }
            _ => Error::Io(e),
        })?;
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take();
    // Drain the output in separate threads, so a full pipe blocks nothing.
    let out_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stdout.read_to_string(&mut buf);
        buf
    });
    let err_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(e) = stderr.as_mut() {
            let _ = e.read_to_string(&mut buf);
        }
        buf
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if unattended && start.elapsed() > FETCH_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::InvalidInput("git took too long (network or GitHub access?)".into()));
        }
        std::thread::sleep(Duration::from_millis(40));
    };
    let out = out_thread.join().unwrap_or_default();
    let err = err_thread.join().unwrap_or_default();
    if status.success() {
        Ok(out.trim().to_string())
    } else {
        let why = err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("unknown error");
        Err(Error::InvalidInput(format!(
            "git {} failed: {}",
            args.first().unwrap_or(&""),
            ui::safe(why, false)
        )))
    }
}

fn git_ok(dir: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// ───────────────────────── source folder and status ─────────────────────────

/// The folder with the source code CakePass was built from.
fn source_dir(arg: Option<&Path>) -> Result<PathBuf> {
    let dir = match arg {
        Some(p) => p.to_path_buf(),
        None => {
            let text = fs::read_to_string(SOURCE_DIR_FILE).map_err(|_| {
                Error::InvalidInput(format!(
                    "I do not know where the source code is (no {SOURCE_DIR_FILE}). \
                     Give the folder with --source <dir>, or reinstall with makepkg."
                ))
            })?;
            PathBuf::from(text.lines().next().unwrap_or("").trim())
        }
    };
    if !dir.is_absolute() || !dir.join(".git").exists() || !dir.join("packaging/arch/PKGBUILD").is_file() {
        return Err(Error::InvalidInput(format!(
            "{} is not a CakePass source folder (a git checkout with packaging/arch/PKGBUILD). \
             Give the right folder with --source <dir>.",
            dir.display()
        )));
    }
    Ok(dir)
}

fn cache_file() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from) {
        Some(p) if p.is_absolute() => p,
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".cache"),
    };
    Some(storage::app_dir(&base).join("update-status"))
}

/// What the last check found (stored in `~/.cache/cakepass/update-status`).
#[derive(Debug, Default, PartialEq, Eq)]
struct CachedStatus {
    remote: String,
    notified: String,
}

impl CachedStatus {
    fn parse(text: &str) -> CachedStatus {
        let mut s = CachedStatus::default();
        for line in text.lines() {
            match line.split_once('=') {
                Some(("remote", v)) if is_hex(v) && v.len() <= 64 => s.remote = v.into(),
                Some(("notified", v)) if is_hex(v) && v.len() <= 64 => s.notified = v.into(),
                _ => {}
            }
        }
        s
    }

    fn read() -> CachedStatus {
        cache_file()
            .and_then(|p| fs::read_to_string(p).ok())
            .map(|t| CachedStatus::parse(&t))
            .unwrap_or_default()
    }

    fn write(&self) {
        let Some(path) = cache_file() else { return };
        let text = format!("remote={}\nnotified={}\n", self.remote, self.notified);
        let _ = (|| -> std::io::Result<()> {
            if let Some(dir) = path.parent() {
                fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
            }
            let tmp = path.with_extension("tmp");
            let _ = fs::remove_file(&tmp);
            let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
            std::io::Write::write_all(&mut f, text.as_bytes())?;
            fs::rename(tmp, path)
        })();
    }

    /// Is there a newer version according to the last check?
    fn update_available(&self) -> bool {
        !self.remote.is_empty() && !is_installed(&self.remote)
    }
}

/// Does this (full) commit match the installed program?
fn is_installed(commit: &str) -> bool {
    installed_commit().is_some_and(|i| commit.starts_with(i.as_str()))
}

/// The installed commit; can be overridden in debug builds for tests.
fn installed_commit() -> Option<String> {
    #[cfg(any(debug_assertions, feature = "test-hooks"))]
    if let Ok(c) = std::env::var("CAKEPASS_TEST_INSTALLED_COMMIT") {
        return is_hex(&c).then_some(c);
    }
    is_hex(INSTALLED_COMMIT).then(|| INSTALLED_COMMIT.to_string())
}

fn running_as_root() -> bool {
    #[cfg(any(debug_assertions, feature = "test-hooks"))]
    if std::env::var_os("CAKEPASS_TEST_ALLOW_ROOT").is_some() {
        return false;
    }
    // SAFETY: geteuid is always safe.
    unsafe { libc::geteuid() == 0 }
}

/// Short notice for `cakepass info` and the login screen (no network: only
/// reads the result of the last check).
pub fn pending_notice() -> Option<String> {
    CachedStatus::read()
        .update_available()
        .then(|| "🍰 A new version of CakePass is available. Type in your terminal: cakepass --update".into())
}

// ───────────────────────── the command ─────────────────────────

struct Situation {
    dir: PathBuf,
    branch: String,
    local_head: String,
    remote_tip: String,
    origin: String,
}

/// Check GitHub: fetch the latest commits and work out where we stand.
fn inspect(dir: &Path, unattended: bool) -> Result<Situation> {
    let branch = git(dir, &["rev-parse", "--abbrev-ref", "HEAD"], true)?;
    if branch == "HEAD" || branch.is_empty() {
        return Err(Error::InvalidInput(
            "the source folder is not on a branch (detached commit). Go back to main with `git checkout main`."
                .into(),
        ));
    }
    let origin = git(dir, &["remote", "get-url", "origin"], true).map_err(|_| {
        Error::InvalidInput("the source folder has no GitHub address (remote 'origin')".into())
    })?;
    let spec = format!("refs/heads/{branch}:refs/remotes/origin/{branch}");
    git(dir, &["fetch", "--quiet", "origin", &spec], unattended)?;
    let remote_tip = git(dir, &["rev-parse", "--verify", &format!("refs/remotes/origin/{branch}")], true)?;
    let local_head = git(dir, &["rev-parse", "HEAD"], true)?;
    if !is_hex(&remote_tip) || !is_hex(&local_head) {
        return Err(Error::InvalidInput("unexpected output from git".into()));
    }
    Ok(Situation { dir: dir.to_path_buf(), branch, local_head, remote_tip, origin })
}

/// The titles of the new commits (at most 12), safe to display.
fn changelog(s: &Situation) -> (usize, Vec<String>) {
    let base = installed_commit().filter(|c| git_ok(&s.dir, &["cat-file", "-e", &format!("{c}^{{commit}}")]));
    let range = match &base {
        Some(c) => format!("{c}..{}", s.remote_tip),
        None => s.remote_tip.clone(),
    };
    let count =
        git(&s.dir, &["rev-list", "--count", &range], true).ok().and_then(|c| c.parse().ok()).unwrap_or(0);
    let log = git(&s.dir, &["log", "--no-merges", "--pretty=format:%h %s", "-n", "12", &range], true)
        .unwrap_or_default();
    let lines = log.lines().map(|l| ui::safe(l, false)).collect();
    (count, lines)
}

pub fn run(opts: &Options, vault: &VaultPaths) -> Result<()> {
    if let Some(mode) = opts.auto {
        return auto(mode);
    }
    let dir = source_dir(opts.source.as_deref())?;
    let unattended = opts.check_only && !prompt::stdin_is_tty();
    if opts.check_only {
        ui::info("Checking for a new version…");
    } else {
        ui::info(&format!("Checking GitHub via git ({}).", dir.display()));
        ui::info(&ui::dim_err("  Nothing from your vault is read or sent; only git talks to GitHub."));
    }
    let s = inspect(&dir, unattended)?;
    let up_to_date = is_installed(&s.remote_tip);
    CachedStatus { remote: s.remote_tip.clone(), ..CachedStatus::read() }
        .write_if(!up_to_date, &s.remote_tip);

    if up_to_date {
        ui::success(&format!(
            "You already have the newest version of CakePass (commit {}).",
            &s.remote_tip[..12.min(s.remote_tip.len())]
        ));
        return Ok(());
    }
    let (count, lines) = changelog(&s);
    if opts.check_only {
        ui::info(&format!("🍰 Update available ({count} new change(s)). Install it with: cakepass --update"));
        if opts.notify {
            notify(&s.remote_tip);
        }
        return Ok(());
    }
    apply(&s, count, &lines, opts, vault)
}

impl CachedStatus {
    /// Store the result; when "up to date" the notice is cleared.
    fn write_if(self, available: bool, remote: &str) {
        let mut s = self;
        s.remote = if available { remote.to_string() } else { String::new() };
        s.write();
    }
}

/// Send one desktop notification per new version (if notify-send exists).
fn notify(remote: &str) {
    let mut st = CachedStatus::read();
    if st.notified == remote {
        return;
    }
    let sent = Command::new("notify-send")
        .args(["-a", "CakePass", "-i", "dialog-information", "CakePass update available"])
        .arg("Type in a terminal: cakepass --update")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if sent {
        st.notified = remote.to_string();
        st.remote = remote.to_string();
        st.write();
    }
}

fn apply(s: &Situation, count: usize, lines: &[String], opts: &Options, vault: &VaultPaths) -> Result<()> {
    // 1. Preconditions
    if running_as_root() {
        return Err(Error::InvalidInput(
            "run this as a normal user, not as root (makepkg refuses root). \
             You will be asked for your password for the installation."
                .into(),
        ));
    }
    if Command::new("makepkg").arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_err()
    {
        return Err(Error::InvalidInput("`makepkg` is missing (sudo pacman -S base-devel)".into()));
    }
    let dirty = git(&s.dir, &["status", "--porcelain"], true)?;
    if !dirty.is_empty() {
        return Err(Error::InvalidInput(format!(
            "there are local changes in {} that are not on GitHub. I will not update, so you do \
             not lose them. Look at them with `git -C {} status`.",
            s.dir.display(),
            s.dir.display()
        )));
    }
    let behind = s.local_head != s.remote_tip;
    if behind && !git_ok(&s.dir, &["merge-base", "--is-ancestor", &s.local_head, &s.remote_tip]) {
        return Err(Error::InvalidInput(
            "your copy differs from GitHub (you made commits yourself). I will not update; \
             sort that out with git first."
                .into(),
        ));
    }

    // 2. Show what will happen and ask for confirmation
    let short = |c: &str| c[..12.min(c.len())].to_string();
    ui::banner(&[
        "There is a new version of CakePass.",
        "",
        &format!("New:  {count} change(s)  (branch {})", ui::safe(&s.branch, false)),
        &format!("From: {}", ui::safe(&s.origin, false)),
        &format!(
            "Now:  {}  →  after: {}",
            installed_commit().map_or("unknown".into(), |c| short(&c)),
            short(&s.remote_tip)
        ),
    ]);
    for l in lines {
        eprintln!("  • {l}");
    }
    if count > lines.len() {
        eprintln!("  … and {} older", count - lines.len());
    }
    ui::info("\nYour vault and your settings stay untouched; an extra backup is made first.");
    ui::warn(
        "You are installing code from GitHub on your computer. Only do this if you (or someone \
         you trust) pushed those changes.",
    );
    if !opts.yes && !prompt::confirm("Update now?")? {
        ui::info("Nothing changed.");
        return Ok(());
    }

    // 3. Extra backup of the vault
    match storage::backup_before_update(vault)? {
        Some(path) => ui::success(&format!("Extra backup of your vault: {}", path.display())),
        None => ui::info("There is no vault yet; no backup needed."),
    }

    // 4. Fetch the new code (forward only, never rewrite)
    if behind {
        git(&s.dir, &["merge", "--ff-only", "--quiet", &s.remote_tip], false)?;
        ui::success("New code fetched.");
    }

    // 5. Build, test and install
    ui::info(
        "Building and testing (this takes a minute); you will be asked for your password for the installation…",
    );
    let pkg_dir = s.dir.join("packaging/arch");
    remove_old_packages(&pkg_dir);
    let mut makepkg = Command::new("makepkg");
    makepkg.args(["-s", "-i", "-f"]).current_dir(&pkg_dir);
    if opts.yes {
        makepkg.arg("--noconfirm");
    }
    let built = makepkg.status().is_ok_and(|st| st.success());
    if !built {
        if behind {
            // The folder was clean and we only did a fast-forward: restoring is safe.
            let back = git(&s.dir, &["reset", "--hard", "--quiet", &s.local_head], true);
            if back.is_err() {
                ui::warn(&format!(
                    "Restoring the source folder failed. Do it yourself: git -C {} reset --hard {}",
                    s.dir.display(),
                    short(&s.local_head)
                ));
            }
        }
        return Err(Error::InvalidInput(
            "the update failed (build, test or install). Nothing changed about your installed \
             version; your vault is safe."
                .into(),
        ));
    }

    // 6. Done
    CachedStatus::default().write_if(false, "");
    ui::success("CakePass has been updated. Start `cakepass` again to use the new version.");
    ui::info(
        "Your vault was not touched. If there is a new vault format, your vault is converted automatically \
         the next time it is saved (the extra backup above keeps the old format).",
    );
    Ok(())
}

/// Remove previously built packages, so makepkg certainly builds again.
fn remove_old_packages(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with("cakepass-") && name.contains(".pkg.tar") {
            let _ = fs::remove_file(e.path());
        }
    }
}

// ───────────────────────── automatic checking ─────────────────────────

fn systemctl(args: &[&str]) -> Result<(bool, String)> {
    let out =
        Command::new("systemctl").arg("--user").args(args).stdin(Stdio::null()).output().map_err(|_| {
            Error::InvalidInput("`systemctl` not found; systemd is needed for the automatic check".into())
        })?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), text.trim().to_string()))
}

fn auto(mode: AutoMode) -> Result<()> {
    match mode {
        AutoMode::Status => {
            let (_, enabled) = systemctl(&["is-enabled", TIMER])?;
            let (_, next) = systemctl(&["list-timers", TIMER, "--no-pager", "--no-legend"])?;
            ui::info(&format!(
                "Automatic check: {}",
                ui::safe(enabled.lines().next().unwrap_or("unknown"), false)
            ));
            if !next.is_empty() {
                ui::info(&format!("  {}", ui::safe(next.lines().next().unwrap_or(""), false)));
            }
            Ok(())
        }
        AutoMode::On => {
            let (ok, why) = systemctl(&["enable", "--now", TIMER])?;
            if !ok {
                return Err(Error::InvalidInput(format!(
                    "could not turn it on: {}. Was CakePass installed with makepkg?",
                    ui::safe(why.lines().last().unwrap_or(""), false)
                )));
            }
            ui::success(
                "Every day CakePass checks whether there is a new version. You get a notification; you install it yourself with `cakepass --update`.",
            );
            ui::info(&ui::dim_err(
                "  Tip: the check only works without a password prompt if your GitHub access works automatically \
                 (an SSH key without passphrase, or `gh auth setup-git`).",
            ));
            Ok(())
        }
        AutoMode::Off => {
            let (_, _) = systemctl(&["disable", "--now", TIMER])?;
            ui::success(
                "The automatic check is off. You can still update manually with `cakepass --update`.",
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_file_is_read_strictly() {
        let s = CachedStatus::parse("remote=abc123def456\nnotified=0123abcd\n");
        assert_eq!((s.remote.as_str(), s.notified.as_str()), ("abc123def456", "0123abcd"));
        // Junk, escape codes and over-long values are ignored.
        let bad = CachedStatus::parse("remote=zzz\nnotified=\x1b[2J\nremote=\njunk\nremote=ab cd\n");
        assert_eq!(bad, CachedStatus::default());
        let long = format!("remote={}", "a".repeat(65));
        assert_eq!(CachedStatus::parse(&long), CachedStatus::default());
    }

    #[test]
    fn hex_check() {
        assert!(is_hex("0123abcdefABCDEF"));
        assert!(!is_hex("") && !is_hex("xyz") && !is_hex("ab;rm"));
    }

    #[test]
    fn installed_comparison() {
        // The built-in commit is hex (or "unknown", then never equal).
        let commit = installed_commit();
        if let Some(c) = commit {
            assert!(is_installed(&format!("{c}0000000000000000000000000000")[..40]));
            assert!(!is_installed("ffffffffffffffffffffffffffffffffffffffff") || c.chars().all(|x| x == 'f'));
        }
        assert!(!is_installed(""), "empty never matches");
    }
}
