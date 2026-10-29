//! Tests for `install.sh`.
//!
//! The installer is run for real (as `curl ... | bash` would run it: the script
//! arrives on stdin), but with fake `pacman`, `sudo`, `makepkg` and `cakepass`
//! commands that only write down that they were called, and a local bare git
//! repository standing in for GitHub. So no network, no root and no real
//! package installation are needed.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const SCRIPT: &str = include_str!("../install.sh");

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.org")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.org")
        .output()
        .expect("git runs");
    assert!(out.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn write_script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

struct World {
    t: tempfile::TempDir,
}

struct Run {
    out: Output,
}

impl Run {
    fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.out.stdout).into_owned()
    }
    fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.out.stderr).into_owned()
    }
    fn ok(&self) -> bool {
        self.out.status.success()
    }
}

impl World {
    fn new() -> World {
        let w = World { t: tempfile::tempdir().unwrap() };
        // Fake GitHub with a project that has a PKGBUILD.
        let origin = w.path("origin.git");
        fs::create_dir(&origin).unwrap();
        git(&origin, &["init", "--bare", "--quiet", "-b", "main"]);
        let dev = w.path("dev");
        git(w.t.path(), &["clone", "--quiet", origin.to_str().unwrap(), "dev"]);
        git(&dev, &["checkout", "--quiet", "-b", "main"]);
        fs::create_dir_all(dev.join("packaging/arch")).unwrap();
        fs::write(dev.join("packaging/arch/PKGBUILD"), "# fake\n").unwrap();
        fs::write(dev.join("README.md"), "version 1\n").unwrap();
        git(&dev, &["add", "-A"]);
        git(&dev, &["commit", "--quiet", "-m", "First version"]);
        git(&dev, &["push", "--quiet", "-u", "origin", "main"]);

        // Fake commands.
        let bin = w.path("bin");
        fs::create_dir(&bin).unwrap();
        let log = w.path("calls.log");
        let log = log.display();
        write_script(
            &bin.join("pacman"),
            &format!(
                "echo \"pacman $*\" >> '{log}'\ncase \"$1\" in -Q) if [ \"$2\" = kluis ]; then [ -f '{old}' ] && exit 0 || exit 1; fi; [ -f '{m}' ] && exit 0 || exit 1 ;; esac\nexit 0",
                m = w.path("everything-installed").display(),
                old = w.path("old-kluis-installed").display()
            ),
        );
        write_script(&bin.join("sudo"), &format!("echo \"sudo $*\" >> '{log}'\nexec \"$@\""));
        write_script(
            &bin.join("makepkg"),
            &format!(
                "echo \"makepkg $* | $(pwd)\" >> '{log}'\n[ -f '{f}' ] && exit 1\nexit 0",
                f = w.path("makepkg-fails").display()
            ),
        );
        write_script(
            &bin.join("cakepass"),
            &format!(
                "case \"$1\" in\n  --version) echo 'cakepass 9.9.9 (commit abc123abc123)' ;;\n  setup) echo 'cakepass setup ran' >> '{log}' ;;\n  *) echo \"cakepass $*\" >> '{log}' ;;\nesac\nexit 0"
            ),
        );
        fs::create_dir(w.path("home")).unwrap();
        w
    }

    fn path(&self, p: &str) -> PathBuf {
        self.t.path().join(p)
    }

    fn source_dir(&self) -> PathBuf {
        self.path("home/cakepass")
    }

    fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.path("calls.log")).unwrap_or_default().lines().map(String::from).collect()
    }

    fn publish(&self, subject: &str) -> String {
        let dev = self.path("dev");
        git(&dev, &["pull", "--quiet", "--ff-only"]);
        let n = fs::read_to_string(dev.join("README.md")).unwrap().lines().count() + 1;
        fs::write(dev.join("README.md"), format!("version {n}\n")).unwrap();
        git(&dev, &["add", "-A"]);
        git(&dev, &["commit", "--quiet", "-m", subject]);
        git(&dev, &["push", "--quiet", "origin", "main"]);
        git(&dev, &["rev-parse", "HEAD"])
    }

    fn command(&self, extra_env: &[(&str, &str)]) -> Command {
        let mut c = Command::new("bash");
        let path = format!("{}:{}", self.path("bin").display(), std::env::var("PATH").unwrap_or_default());
        c.env("PATH", path)
            .env("HOME", self.path("home"))
            .env("NO_COLOR", "1")
            .env("CAKEPASS_REPO_URL", self.path("origin.git"))
            .env("CAKEPASS_INSTALL_ALLOW_ROOT", "1")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("DISPLAY")
            .env_remove("CAKEPASS_DIR")
            .env_remove("CAKEPASS_BRANCH");
        for (k, v) in extra_env {
            c.env(k, v);
        }
        c
    }

    /// Run the installer the way `curl ... | bash -s -- ARGS` does: script on stdin.
    fn piped(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Run {
        self.piped_script(SCRIPT, args, extra_env)
    }

    fn piped_script(&self, script: &str, args: &[&str], extra_env: &[(&str, &str)]) -> Run {
        let mut child = self
            .command(extra_env)
            .args(["-s", "--"])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(script.as_bytes()).unwrap();
        Run { out: child.wait_with_output().unwrap() }
    }
}

#[test]
fn fresh_install_from_a_pipe() {
    let w = World::new();
    let r = w.piped(&["--yes", "--no-setup"], &[("WAYLAND_DISPLAY", "wayland-0")]);
    assert!(r.ok(), "stdout: {}\nstderr: {}", r.stdout(), r.stderr());
    assert!(r.stdout().contains("All done"), "{}", r.stdout());
    assert!(r.stdout().contains("installed: cakepass 9.9.9"), "{}", r.stdout());

    let calls = w.calls();
    // Packages: missing ones are installed with sudo pacman, including the Wayland clipboard tool.
    let install = calls.iter().find(|c| c.starts_with("pacman -S")).expect("pacman -S was called");
    assert_eq!(install, "pacman -S --needed --noconfirm base-devel git rust wl-clipboard");
    assert!(calls.iter().any(|c| c.starts_with("sudo pacman -S")));
    // The package is built from the cloned source folder.
    let build = calls.iter().find(|c| c.starts_with("makepkg")).expect("makepkg was called");
    assert!(build.starts_with("makepkg -si -f --noconfirm | "), "{build}");
    assert!(build.ends_with("cakepass/packaging/arch"), "{build}");
    assert!(w.source_dir().join(".git").exists());
    assert!(!calls.iter().any(|c| c.contains("setup ran")), "--no-setup skips the wizard");
}

#[test]
fn the_old_kluis_package_is_replaced() {
    let w = World::new();
    fs::write(w.path("old-kluis-installed"), "").unwrap();
    assert!(w.piped(&["--yes", "--no-setup"], &[]).ok());
    let calls = w.calls();
    let removed = calls.iter().position(|c| c == "pacman -R --noconfirm kluis").expect("old package removed");
    let built = calls.iter().position(|c| c.starts_with("makepkg")).expect("new package built");
    assert!(removed < built, "remove the old one before installing: {calls:?}");
    // Nothing to remove on a normal install.
    let fresh = World::new();
    assert!(fresh.piped(&["--yes", "--no-setup"], &[]).ok());
    assert!(fresh.calls().iter().all(|c| c != "pacman -R --noconfirm kluis"));
}

#[test]
fn clipboard_tool_follows_the_session_type() {
    let x11 = World::new();
    let r = x11.piped(&["--yes", "--no-setup"], &[("DISPLAY", ":0")]);
    assert!(r.ok(), "{}", r.stderr());
    assert!(x11.calls().iter().any(|c| c == "pacman -S --needed --noconfirm base-devel git rust xclip"));

    let headless = World::new();
    let r = headless.piped(&["--yes", "--no-setup"], &[]);
    assert!(r.ok(), "{}", r.stderr());
    assert!(headless.calls().iter().any(|c| c == "pacman -S --needed --noconfirm base-devel git rust"));
    assert!(r.stdout().contains("No desktop session detected"));

    // Nothing to install when everything is already there.
    let done = World::new();
    fs::write(done.path("everything-installed"), "").unwrap();
    let r = done.piped(&["--yes", "--no-setup"], &[("WAYLAND_DISPLAY", "wayland-0")]);
    assert!(r.ok(), "{}", r.stderr());
    assert!(!done.calls().iter().any(|c| c.starts_with("pacman -S")));
}

#[test]
fn running_again_updates_the_existing_copy() {
    let w = World::new();
    assert!(w.piped(&["--yes", "--no-setup"], &[]).ok());
    let new = w.publish("Second version");
    let r = w.piped(&["--yes", "--no-setup"], &[]);
    assert!(r.ok(), "{}\n{}", r.stdout(), r.stderr());
    assert!(r.stdout().contains("Found an existing copy"));
    assert_eq!(git(&w.source_dir(), &["rev-parse", "HEAD"]), new);
    assert_eq!(w.calls().iter().filter(|c| c.starts_with("makepkg")).count(), 2);
}

#[test]
fn local_changes_and_other_folders_are_never_overwritten() {
    let w = World::new();
    assert!(w.piped(&["--yes", "--no-setup"], &[]).ok());
    fs::write(w.source_dir().join("README.md"), "my own edit\n").unwrap();
    w.publish("Second version");
    let r = w.piped(&["--yes", "--no-setup"], &[]);
    assert!(!r.ok());
    assert!(r.stderr().contains("local changes"), "{}", r.stderr());
    assert_eq!(fs::read_to_string(w.source_dir().join("README.md")).unwrap(), "my own edit\n");
    assert_eq!(w.calls().iter().filter(|c| c.starts_with("makepkg")).count(), 1, "no second build");

    // A folder that is not a CakePass copy is refused.
    let other = World::new();
    fs::create_dir_all(other.path("home/cakepass")).unwrap();
    fs::write(other.path("home/cakepass/important.txt"), "mine").unwrap();
    let r = other.piped(&["--yes", "--no-setup"], &[]);
    assert!(!r.ok());
    assert!(r.stderr().contains("is not a CakePass copy"), "{}", r.stderr());
    assert!(other.path("home/cakepass/important.txt").exists());
    assert!(other.calls().iter().all(|c| !c.starts_with("makepkg")));
}

#[test]
fn a_failed_build_is_reported() {
    let w = World::new();
    fs::write(w.path("makepkg-fails"), "").unwrap();
    let r = w.piped(&["--yes", "--no-setup"], &[]);
    assert!(!r.ok());
    assert!(r.stderr().contains("the build or installation failed"), "{}", r.stderr());
    assert!(!r.stdout().contains("All done"));
}

#[test]
fn custom_folder_and_branch_options() {
    let w = World::new();
    let dir = w.path("elsewhere");
    let r = w.piped(&["--yes", "--no-setup", "--dir", dir.to_str().unwrap()], &[]);
    assert!(r.ok(), "{}", r.stderr());
    assert!(dir.join("packaging/arch/PKGBUILD").exists());
    assert!(!w.source_dir().exists());

    let bad = w.piped(
        &["--yes", "--no-setup", "--branch", "no-such-branch", "--dir", w.path("b").to_str().unwrap()],
        &[],
    );
    assert!(!bad.ok(), "an unknown branch must fail");
}

#[test]
fn uninstall_keeps_the_vault() {
    let w = World::new();
    let r = w.piped(&["--uninstall", "--yes"], &[]);
    assert!(r.ok(), "{}", r.stderr());
    assert!(w.calls().iter().any(|c| c == "pacman -R --noconfirm cakepass"));
    assert!(r.stdout().contains("was NOT removed"));
    assert!(w.calls().iter().all(|c| !c.starts_with("makepkg")));
}

#[test]
fn help_and_bad_options() {
    let w = World::new();
    let r = w.piped(&["--help"], &[]);
    assert!(r.ok());
    assert!(r.stdout().contains("--no-setup") && r.stdout().contains("--uninstall"));
    assert!(w.calls().is_empty(), "--help does nothing else");
    let r = w.piped(&["--bogus"], &[]);
    assert!(!r.ok());
    assert!(r.stderr().contains("unknown option"));
    assert!(w.calls().is_empty());
}

#[test]
fn refuses_to_run_as_root() {
    // Only meaningful when the tests themselves run as root (e.g. in a container).
    let is_root =
        String::from_utf8_lossy(&Command::new("id").arg("-u").output().unwrap().stdout).trim() == "0";
    if !is_root {
        return;
    }
    let w = World::new();
    let r = w.piped(&["--yes", "--no-setup"], &[("CAKEPASS_INSTALL_ALLOW_ROOT", "")]);
    assert!(!r.ok());
    assert!(r.stderr().contains("do not run this as root"), "{}", r.stderr());
    assert!(w.calls().is_empty());
}

#[test]
fn a_cut_off_download_never_runs_half_a_script() {
    let w = World::new();
    // Cut the script off in the middle of main().
    let cut = SCRIPT.len() * 6 / 10;
    let cut = SCRIPT[..cut].rfind('\n').unwrap();
    let r = w.piped_script(&SCRIPT[..cut], &["--yes", "--no-setup"], &[]);
    assert!(!r.ok(), "a truncated script must not succeed");
    assert!(w.calls().is_empty(), "nothing may have run: {:?}", w.calls());
    assert!(!w.source_dir().exists());
}

#[test]
fn setup_runs_in_a_real_terminal() {
    // `script` gives the installer a real terminal, like a person typing at a prompt.
    if Command::new("script").arg("--version").output().is_err() {
        return;
    }
    let w = World::new();
    let line = format!("bash {} --yes", w.path("install.sh").display());
    fs::write(w.path("install.sh"), SCRIPT).unwrap();
    let out = w
        .command(&[])
        .args(["-c", &format!("script -qefc '{line}' /dev/null")])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}\n{}", String::from_utf8_lossy(&out.stderr));
    assert!(w.calls().iter().any(|c| c == "cakepass setup ran"), "setup should run: {:?}", w.calls());
    assert!(text.contains("A short wizard follows"), "{text}");
}

#[test]
fn the_script_is_clean() {
    // Syntax check, and the safety habits that matter for a script people pipe into bash.
    let st = Command::new("bash").args(["-n", "-c", SCRIPT]).status().unwrap();
    assert!(st.success());
    assert!(SCRIPT.contains("set -euo pipefail"));
    assert!(SCRIPT.trim_end().ends_with("main \"$@\""), "main must be the very last line");
    assert!(
        !SCRIPT.contains("curl ") || !SCRIPT.contains("| sh"),
        "the installer downloads nothing and pipes nothing into a shell"
    );
    assert!(!SCRIPT.contains("rm -rf /"), "no dangerous deletes");
}
