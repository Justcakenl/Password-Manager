//! Integration tests for `cakepass --update`.
//!
//! "GitHub" here is a local bare git repo; `makepkg` is a fake script that
//! only records that it was called. This tests the real logic (git fetch,
//! fast-forward, backup, restoring after a failure) without network, root or
//! pacman. The tests only work in debug builds, where the installed commit
//! can be simulated through CAKEPASS_TEST_INSTALLED_COMMIT.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command as Proc;
use std::time::Duration;

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

const PW: &str = "tq8#vLp2!mZr9wXe";
const FAST_KDF: [&str; 6] = ["--kdf-memory", "8", "--kdf-iterations", "1", "--kdf-parallelism", "1"];

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Proc::new("git")
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
        .expect("git draait");
    assert!(out.status.success(), "git {args:?} faalde: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

struct World {
    t: tempfile::TempDir,
}

impl World {
    /// Fake GitHub + source folder (`src`) + developer copy (`dev`) + fake makepkg.
    fn new() -> World {
        let w = World { t: tempfile::tempdir().unwrap() };
        let origin = w.path("origin.git");
        fs::create_dir(&origin).unwrap();
        git(&origin, &["init", "--bare", "--quiet", "-b", "main"]);
        git(w.t.path(), &["clone", "--quiet", origin.to_str().unwrap(), "src"]);
        let src = w.src();
        git(&src, &["checkout", "--quiet", "-b", "main"]);
        fs::create_dir_all(src.join("packaging/arch")).unwrap();
        fs::write(src.join("packaging/arch/PKGBUILD"), "# fake\n").unwrap();
        fs::write(src.join("README.md"), "version 1\n").unwrap();
        git(&src, &["add", "-A"]);
        git(&src, &["commit", "--quiet", "-m", "First version"]);
        git(&src, &["push", "--quiet", "-u", "origin", "main"]);
        git(w.t.path(), &["clone", "--quiet", "-b", "main", origin.to_str().unwrap(), "dev"]);

        fs::create_dir(w.path("bin")).unwrap();
        let script = format!(
            "#!/bin/sh\necho \"$@ | $(pwd)\" >> '{log}'\n[ \"$1\" = \"--version\" ] && exit 0\n[ -f '{fail}' ] && exit 1\nexit 0\n",
            log = w.path("makepkg.log").display(),
            fail = w.path("makepkg-fail").display()
        );
        let bin = w.path("bin/makepkg");
        fs::write(&bin, script).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        w
    }

    fn path(&self, p: &str) -> PathBuf {
        self.t.path().join(p)
    }
    fn src(&self) -> PathBuf {
        self.path("src")
    }
    fn vault(&self) -> PathBuf {
        self.path("data/vault.enc")
    }

    /// The commit that is "installed" (now the head of the source folder).
    fn installed(&self) -> String {
        git(&self.src(), &["rev-parse", "--short=12", "HEAD"])
    }

    /// Put a new version "on GitHub".
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

    fn cakepass(&self, installed: &str) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_cakepass"));
        let path = format!("{}:{}", self.path("bin").display(), std::env::var("PATH").unwrap_or_default());
        c.env("PATH", path)
            .env("NO_COLOR", "1")
            .env("CAKEPASS_VAULT", self.vault())
            .env("XDG_CACHE_HOME", self.path("cache"))
            .env("XDG_CONFIG_HOME", self.path("config-home"))
            .env("CAKEPASS_TEST_ALLOW_ROOT", "1")
            .env("CAKEPASS_TEST_INSTALLED_COMMIT", installed)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("DISPLAY")
            .timeout(Duration::from_secs(60));
        c
    }

    fn update(&self, installed: &str, args: &[&str]) -> Command {
        let mut c = self.cakepass(installed);
        c.args(["--update", "--source"]).arg(self.src()).args(args);
        c
    }

    fn init_vault(&self, installed: &str) {
        self.cakepass(installed)
            .arg("init")
            .args(FAST_KDF)
            .write_stdin(format!("{PW}\n{PW}\n"))
            .assert()
            .success();
        self.cakepass(installed)
            .args(["add", "Bank", "-u", "john", "-e", "", "--url", "https://bank.nl", "-t", "money"])
            .write_stdin(format!("{PW}\nSecret-Bank-PW-1!\n"))
            .assert()
            .success();
    }

    fn makepkg_calls(&self) -> Vec<String> {
        fs::read_to_string(self.path("makepkg.log"))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.starts_with("--version"))
            .map(String::from)
            .collect()
    }

    fn backups(&self) -> Vec<String> {
        fs::read_dir(self.path("data"))
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.starts_with("vault.enc.pre-update-"))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn assert_vault_works(&self, installed: &str) {
        self.cakepass(installed)
            .args(["get", "bank", "--show"])
            .write_stdin(format!("{PW}\n"))
            .assert()
            .success()
            .stdout(contains("Secret-Bank-PW-1!"));
    }
}

#[test]
fn newest_version_gives_no_update() {
    let w = World::new();
    let installed = w.installed();
    w.update(&installed, &["--check"]).assert().success().stderr(contains("already have the newest version"));
    assert!(w.makepkg_calls().is_empty());
}

#[test]
fn checking_finds_an_update_and_remembers_it() {
    let w = World::new();
    let installed = w.installed();
    let new = w.publish("Nice new feature");
    w.update(&installed, &["--check"])
        .assert()
        .success()
        .stderr(contains("Update available (1 new change(s))"));
    // Nothing was installed or pulled into the working folder.
    assert!(w.makepkg_calls().is_empty());
    assert_eq!(git(&w.src(), &["rev-parse", "HEAD"]), git(&w.src(), &["rev-parse", "origin/main~1"]));
    // The result is in the cache, and `cakepass info` shows it (without network).
    let cache = fs::read_to_string(w.path("cache/cakepass/update-status")).unwrap();
    assert!(cache.contains(&format!("remote={new}")));
    w.cakepass(&installed).arg("info").assert().success().stdout(contains("cakepass --update"));
    // After a new check with no news the notice disappears again.
    w.update(&new[..12], &["--check"]).assert().success();
    w.cakepass(&new[..12]).arg("info").assert().success().stdout(contains("no new version known"));
    // --notify without notify-send in PATH is not an error.
    w.update(&installed, &["--check", "--notify"]).assert().success();
}

#[test]
fn full_update_leaves_the_vault_alone() {
    let w = World::new();
    let installed = w.installed();
    w.init_vault(&installed);
    let before = fs::read(w.vault()).unwrap();
    let new = w.publish("New feature");

    w.update(&installed, &["--yes"])
        .assert()
        .success()
        .stderr(contains("There is a new version").and(contains("New feature")).and(contains("Extra backup")))
        .stderr(contains("CakePass has been updated"));

    // New code was pulled in (forward only), and makepkg ran in packaging/arch.
    assert_eq!(git(&w.src(), &["rev-parse", "HEAD"]), new);
    let calls = w.makepkg_calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(
        calls[0].starts_with("-s -i -f --noconfirm | ") && calls[0].ends_with("packaging/arch"),
        "{calls:?}"
    );
    // The vault is byte for byte the same, there is an identical extra backup (permissions 600), and everything still opens.
    assert_eq!(fs::read(w.vault()).unwrap(), before);
    let backups = w.backups();
    assert_eq!(backups.len(), 1);
    let backup = w.path("data").join(&backups[0]);
    assert_eq!(fs::read(&backup).unwrap(), before);
    assert_eq!(fs::metadata(&backup).unwrap().permissions().mode() & 0o777, 0o600);
    w.assert_vault_works(&new[..12]);
    // The backup opens on its own as well.
    Command::new(env!("CARGO_BIN_EXE_cakepass"))
        .args(["--vault", backup.to_str().unwrap(), "list"])
        .write_stdin(format!("{PW}\n"))
        .assert()
        .success()
        .stdout(contains("Bank"));
    // After that there is nothing left to do.
    w.update(&new[..12], &[]).assert().success().stderr(contains("already have the newest version"));
}

#[test]
fn without_yes_nothing_happens() {
    let w = World::new();
    let installed = w.installed();
    w.init_vault(&installed);
    w.publish("New feature");
    let head = git(&w.src(), &["rev-parse", "HEAD"]);
    w.update(&installed, &[]).write_stdin("n\n").assert().success().stderr(contains("Nothing changed"));
    assert_eq!(git(&w.src(), &["rev-parse", "HEAD"]), head);
    assert!(w.makepkg_calls().is_empty() && w.backups().is_empty());
    // With "y" it goes ahead (without --noconfirm: pacman still asks itself).
    w.update(&installed, &[]).write_stdin("y\n").assert().success().stderr(contains("updated"));
    assert_eq!(w.makepkg_calls().len(), 1);
    assert!(!w.makepkg_calls()[0].contains("--noconfirm"));
}

#[test]
fn failed_build_restores_everything() {
    let w = World::new();
    let installed = w.installed();
    w.init_vault(&installed);
    let before = fs::read(w.vault()).unwrap();
    let head = git(&w.src(), &["rev-parse", "HEAD"]);
    w.publish("Broken version");
    fs::write(w.path("makepkg-fail"), "").unwrap();

    w.update(&installed, &["--yes"])
        .assert()
        .failure()
        .stderr(contains("the update failed").and(contains("your vault is safe")));
    assert_eq!(git(&w.src(), &["rev-parse", "HEAD"]), head, "source folder was restored");
    assert_eq!(fs::read(w.vault()).unwrap(), before);
    assert_eq!(w.backups().len(), 1, "backup was made before trying");
    w.assert_vault_works(&installed);
    // If it works later, a new attempt works.
    fs::remove_file(w.path("makepkg-fail")).unwrap();
    w.update(&installed, &["--yes"]).assert().success();
}

#[test]
fn local_changes_are_never_overwritten() {
    let w = World::new();
    let installed = w.installed();
    w.publish("New feature");
    fs::write(w.src().join("README.md"), "my own change\n").unwrap();
    w.update(&installed, &["--yes"]).assert().failure().stderr(contains("local changes"));
    assert_eq!(fs::read_to_string(w.src().join("README.md")).unwrap(), "my own change\n");
    assert!(w.makepkg_calls().is_empty() && w.backups().is_empty());
}

#[test]
fn diverging_history_is_never_rewritten() {
    let w = World::new();
    let installed = w.installed();
    fs::write(w.src().join("own.txt"), "local\n").unwrap();
    git(&w.src(), &["add", "-A"]);
    git(&w.src(), &["commit", "--quiet", "-m", "My own commit"]);
    let mine = git(&w.src(), &["rev-parse", "HEAD"]);
    w.publish("Something else on GitHub");
    w.update(&installed, &["--yes"]).assert().failure().stderr(contains("differs from GitHub"));
    assert_eq!(git(&w.src(), &["rev-parse", "HEAD"]), mine);
    assert!(w.makepkg_calls().is_empty());
}

#[test]
fn unsafe_characters_in_commits_are_neutralized() {
    let w = World::new();
    let installed = w.installed();
    w.publish("Nasty \u{1b}[2J\u{1b}[31m title \u{7}");
    let out = w.update(&installed, &["--yes"]).assert().success();
    let o = out.get_output();
    assert!(!o.stderr.contains(&0x1b) && !o.stderr.contains(&0x07), "no control characters in the output");
    assert!(String::from_utf8_lossy(&o.stderr).contains("Nasty"));
}

#[test]
fn reachability_and_source_folder_errors() {
    let w = World::new();
    let installed = w.installed();
    // Invalid source folder.
    w.cakepass(&installed)
        .args(["--update", "--source", "/tmp"])
        .assert()
        .failure()
        .stderr(contains("not a CakePass source folder"));
    // GitHub unreachable: a clean error, nothing changes.
    git(&w.src(), &["remote", "set-url", "origin", w.path("does-not-exist.git").to_str().unwrap()]);
    w.update(&installed, &["--check"]).assert().failure().stderr(contains("git fetch failed"));
    assert!(w.makepkg_calls().is_empty());
}

#[test]
fn not_inside_the_vault_shell() {
    let w = World::new();
    let installed = w.installed();
    w.init_vault(&installed);
    w.cakepass(&installed)
        .arg("shell")
        .write_stdin(format!("{PW}\nupdate\nexit\n"))
        .assert()
        .success()
        .stderr(contains("close the vault first"));
}

#[test]
fn update_never_opens_the_vault() {
    // Without a vault and without a password prompt: update works, and never asks for a password.
    let w = World::new();
    let installed = w.installed();
    w.publish("New feature");
    w.update(&installed, &["--yes"])
        .assert()
        .success()
        .stderr(contains("Master password").not().and(contains("no backup needed")));
}

#[test]
fn version_contains_the_commit() {
    Command::new(env!("CARGO_BIN_EXE_cakepass"))
        .arg("--version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")).and(contains("commit ")));
}
