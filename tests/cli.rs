//! Integration tests: run the real `kluis` program with input via stdin.
//!
//! All tests use a temporary directory and light Argon2 settings
//! (8 MiB, t=1) so they are fast. A clipboard is never used. The settings
//! directory is redirected to the temporary directory as well, so the tests
//! never touch your real `~/.config`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

/// Test passwords (for tests only; strong enough for zxcvbn).
const PW: &str = "tq8#vLp2!mZr9wXe";
const PW2: &str = "grape-lantern-oyster-bulky-scenic-dwarf";
const ITEM_PW: &str = "Item-Secret-7731!";
const FAST_KDF: [&str; 6] = ["--kdf-memory", "8", "--kdf-iterations", "1", "--kdf-parallelism", "1"];

struct Vaulty {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl Vaulty {
    fn new() -> Vaulty {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        Vaulty { _dir: dir, path }
    }

    fn dir(&self) -> &Path {
        self.path.parent().unwrap()
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_kluis"));
        c.env("KLUIS_VAULT", &self.path)
            .env("NO_COLOR", "1")
            .env("XDG_CONFIG_HOME", self.dir().join("config-home"))
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("DISPLAY")
            .timeout(Duration::from_secs(60));
        c
    }

    fn init(self) -> Vaulty {
        self.cmd()
            .arg("init")
            .args(FAST_KDF)
            .write_stdin(format!("{PW}\n{PW}\n"))
            .assert()
            .success()
            .stderr(contains("Vault created"));
        self
    }

    fn add(&self, name: &str, user: &str, password: &str) {
        self.cmd()
            .args(["add", name, "--username", user, "--url", "https://example.org", "--tags", "work,test"])
            .write_stdin(format!("{PW}\n{password}\n"))
            .assert()
            .success();
    }

    fn run(&self, args: &[&str], stdin: &str) -> assert_cmd::assert::Assert {
        self.cmd().args(args).write_stdin(stdin.to_string()).assert()
    }
}

#[test]
fn init_creates_vault_with_correct_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let k = Vaulty::new().init();
    let mode = std::fs::metadata(&k.path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    // A second init overwrites nothing.
    k.run(&["init"], &format!("{PW}\n{PW}\n")).failure().stderr(contains("will not overwrite"));
}

#[test]
fn weak_or_mismatched_master_password_is_rejected() {
    let k = Vaulty::new();
    k.run(&["init", FAST_KDF[0], FAST_KDF[1]], "password123\npassword123\n")
        .failure()
        .stderr(contains("too weak"));
    k.run(&["init", FAST_KDF[0], FAST_KDF[1]], &format!("{PW}\n{PW}x\n"))
        .failure()
        .stderr(contains("do not match"));
    assert!(!k.path.exists());
}

#[test]
fn add_get_and_show() {
    let k = Vaulty::new().init();
    k.add("GitHub", "john", ITEM_PW);

    // Without --show: the password never appears in the output; no clipboard → error.
    k.run(&["get", "github"], &format!("{PW}\n"))
        .failure()
        .stdout(contains("john").and(contains(ITEM_PW).not()))
        .stderr(contains("no clipboard tool found").and(contains(ITEM_PW).not()));
    k.run(&["get", "github", "--no-copy"], &format!("{PW}\n")).success().stdout(contains(ITEM_PW).not());

    // With --show: explicitly requested.
    k.run(&["get", "GITHUB", "--show"], &format!("{PW}\n")).success().stdout(contains(ITEM_PW));

    // list and search show no passwords.
    k.run(&["list"], &format!("{PW}\n")).success().stdout(contains("GitHub").and(contains(ITEM_PW).not()));
    k.run(&["search", "examp"], &format!("{PW}\n")).success().stdout(contains("GitHub"));
    k.run(&["search", ITEM_PW], &format!("{PW}\n")).success().stderr(contains("Nothing found"));
    k.run(&["list", "--tag", "WORK"], &format!("{PW}\n")).success().stdout(contains("GitHub"));
    k.run(&["list", "--tag", "private"], &format!("{PW}\n")).success().stderr(contains("No items match"));

    // A duplicate name is rejected.
    k.run(&["add", "github", "-u", "x", "--url", "", "-t", ""], &format!("{PW}\nx\n"))
        .failure()
        .stderr(contains("already exists"));
}

#[test]
fn interactive_add_with_generated_password() {
    let k = Vaulty::new().init();
    // username, url, tags, notes, password (empty = generate)
    k.run(&["add", "Mail"], &format!("{PW}\nme@mail.com\nhttps://mail.com\npriv\nsecret note\n\n"))
        .success()
        .stderr(contains("generated (24 characters"));
    let out = k.run(&["get", "mail", "--show"], &format!("{PW}\n")).success().get_output().stdout.clone();
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains("secret note"));
    let pw_line = out.lines().find(|l| l.starts_with("Password:")).unwrap();
    assert_eq!(pw_line.trim_start_matches("Password:").trim().chars().count(), 24);
}

#[test]
fn edit_and_remove() {
    let k = Vaulty::new().init();
    k.add("GitHub", "john", ITEM_PW);
    k.run(
        &["edit", "github", "--username", "pete", "--rename", "GitLab", "--password"],
        &format!("{PW}\nNew-PW-99\n"),
    )
    .success();
    k.run(&["get", "gitlab", "--show"], &format!("{PW}\n"))
        .success()
        .stdout(contains("pete").and(contains("New-PW-99")));
    k.run(&["get", "github", "--show"], &format!("{PW}\n")).failure().stderr(contains("no item found"));

    // Without confirmation nothing happens.
    k.run(&["rm", "gitlab"], &format!("{PW}\nn\n")).success().stderr(contains("Nothing removed"));
    k.run(&["rm", "gitlab"], &format!("{PW}\ny\n")).success();
    k.run(&["list"], &format!("{PW}\n")).success().stderr(contains("empty"));
    k.run(&["rm", "does-not-exist", "-y"], &format!("{PW}\n")).failure();
}

#[test]
fn wrong_master_password_always_fails() {
    let k = Vaulty::new().init();
    k.add("GitHub", "john", ITEM_PW);
    for wrong in ["", "wrong", &PW[..PW.len() - 1], &format!("{PW} "), &PW.to_uppercase()] {
        k.run(&["get", "github", "--show"], &format!("{wrong}\n"))
            .failure()
            .stdout(contains(ITEM_PW).not())
            .stderr(contains("wrong master password"));
    }
}

#[test]
fn tampered_or_broken_file_fails_cleanly() {
    let k = Vaulty::new().init();
    k.add("GitHub", "john", ITEM_PW);
    let good = std::fs::read(&k.path).unwrap();

    // Every bit flip (sampled over the whole file) is noticed.
    for i in (0..good.len()).step_by(7) {
        let mut bad = good.clone();
        bad[i] ^= 0x04;
        std::fs::write(&k.path, &bad).unwrap();
        k.run(&["get", "github", "--show"], &format!("{PW}\n")).failure().stdout(contains(ITEM_PW).not());
    }
    // Truncated, empty, junk.
    for bad in [&good[..good.len() - 1], &good[..40], &b""[..], &b"hello, this is not a vault"[..]] {
        std::fs::write(&k.path, bad).unwrap();
        k.run(&["list"], &format!("{PW}\n")).failure().stderr(contains("error:"));
    }
    // Restore and check that it works again.
    std::fs::write(&k.path, &good).unwrap();
    k.run(&["list"], &format!("{PW}\n")).success().stdout(contains("GitHub"));
}

#[test]
fn backup_holds_previous_version() {
    let k = Vaulty::new().init();
    k.add("One", "a", "pw-one-1234");
    k.add("Two", "b", "pw-two-1234");
    let bak = k.dir().join("vault.enc.bak");
    let out = Command::new(env!("CARGO_BIN_EXE_kluis"))
        .args(["--vault", bak.to_str().unwrap(), "list"])
        .env("NO_COLOR", "1")
        .write_stdin(format!("{PW}\n"))
        .assert()
        .success();
    out.stdout(contains("One").and(contains("Two").not()));
}

#[test]
fn change_master_password() {
    let k = Vaulty::new().init();
    k.add("GitHub", "john", ITEM_PW);
    k.run(&["passwd"], &format!("{PW}\n{PW2}\n{PW2}\n")).success().stderr(contains("changed"));
    k.run(&["list"], &format!("{PW}\n")).failure();
    k.run(&["get", "github", "--show"], &format!("{PW2}\n")).success().stdout(contains(ITEM_PW));
    // The backup no longer opens with the old password either.
    let bak = k.dir().join("vault.enc.bak");
    Command::new(env!("CARGO_BIN_EXE_kluis"))
        .args(["--vault", bak.to_str().unwrap(), "list"])
        .write_stdin(format!("{PW}\n"))
        .assert()
        .failure();
}

#[test]
fn export_and_import() {
    let a = Vaulty::new().init();
    a.add("GitHub", "john", ITEM_PW);
    let export = a.dir().join("export.kluis");
    let export_s = export.to_str().unwrap();
    a.run(&["export", export_s], &format!("{PW}\n{PW2}\n{PW2}\n")).success();
    // An existing file is not overwritten.
    a.run(&["export", export_s], &format!("{PW}\n")).failure().stderr(contains("will not overwrite"));
    let raw = std::fs::read(&export).unwrap();
    assert!(!raw.windows(ITEM_PW.len()).any(|w| w == ITEM_PW.as_bytes()), "the export is encrypted");

    let b = Vaulty::new().init();
    b.run(&["import", export_s], &format!("{PW}\n{PW}\n")).failure().stderr(contains("wrong"));
    b.run(&["import", export_s], &format!("{PW}\n{PW2}\n")).success().stderr(contains("1 item(s) added"));
    b.run(&["import", export_s], &format!("{PW}\n{PW2}\n")).success().stderr(contains("0 item(s) added"));
    b.run(&["get", "github", "--show"], &format!("{PW}\n")).success().stdout(contains(ITEM_PW));
}

#[test]
fn csv_import_with_warning_and_deletion() {
    let k = Vaulty::new().init();
    let csv = k.dir().join("bitwarden.csv");
    std::fs::write(
        &csv,
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
         Work,,login,GitHub,,,0,https://github.com,john,csv-pw-1,\n\
         ,,login,Mail,,,0,https://mail.nl,me,csv-pw-2,\n",
    )
    .unwrap();
    let csv_s = csv.to_str().unwrap();
    k.run(&["import-csv", csv_s], &format!("{PW}\nn\n"))
        .success()
        .stderr(contains("NOT encrypted").and(contains("2 item(s) imported")).and(contains("shred")));
    assert!(csv.exists());
    // Again: no duplicates, and this time have it deleted.
    k.run(&["import-csv", csv_s], &format!("{PW}\ny\n"))
        .success()
        .stderr(contains("0 item(s) imported").and(contains("deleted")));
    assert!(!csv.exists());
    k.run(&["get", "mail", "--show"], &format!("{PW}\n")).success().stdout(contains("csv-pw-2"));
}

#[test]
fn generator() {
    let k = Vaulty::new();
    let out = k.run(&["generate", "--show", "-l", "40"], "").success().get_output().stdout.clone();
    assert_eq!(String::from_utf8(out).unwrap().trim().chars().count(), 40);
    let out = k
        .run(&["generate", "--show", "-p", "-w", "5", "--separator", "_"], "")
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8(out).unwrap().trim().split('_').count(), 5);
    k.run(&["generate", "--show", "-l", "4"], "").failure().stderr(contains("length"));
    k.run(&["generate"], "").failure().stderr(contains("no clipboard tool found"));
}

#[test]
fn info_works_without_password() {
    let k = Vaulty::new();
    k.run(&["info"], "").success().stdout(contains("does not exist yet"));
    let k = k.init();
    k.run(&["info"], "").success().stdout(
        contains("Argon2id, 8 MiB")
            .and(contains("Permissions:      600"))
            .and(contains("Core dumps off:   yes"))
            .and(contains("Format version:   2"))
            .and(contains("all item content encrypted separately")),
    );
}

#[test]
fn missing_vault_gives_hint() {
    let k = Vaulty::new();
    k.run(&["list"], "").failure().stderr(contains("kluis setup"));
}

#[test]
fn completions_for_all_shells() {
    let k = Vaulty::new();
    for shell in ["bash", "zsh", "fish"] {
        k.run(&["completions", shell], "")
            .success()
            .stdout(contains("generate").and(contains("__clipboard-clear").not()));
    }
}

#[test]
fn shell_mode() {
    let k = Vaulty::new().init();
    k.add("GitHub", "john", ITEM_PW);
    k.run(&["shell"], &format!("{PW}\nlist\nget github --show\nnonsense\nadd\n\"unclosed\nexit\n"))
        .success()
        .stdout(contains("GitHub").and(contains(ITEM_PW)))
        .stderr(contains("unlocked").and(contains("locked")));
    // passwd in the shell asks for the current password again.
    k.run(&["shell"], &format!("{PW}\npasswd\nfout\nexit\n"))
        .success()
        .stderr(contains("wrong master password"));
    k.run(&["list"], &format!("{PW}\n")).success();
}

/// Start `kluis shell --timeout 1`, send `input` and leave stdin open.
/// Returns the stderr output as soon as the shell stops by itself.
fn shell_until_locked(k: &Vaulty, input: &str) -> String {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_kluis"))
        .args(["shell", "--timeout", "1"])
        .env("KLUIS_VAULT", &k.path)
        .env("NO_COLOR", "1")
        .env("XDG_CONFIG_HOME", k.dir().join("config-home"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input.as_bytes()).unwrap();
    // stdin stays open: there simply is no more input.
    let start = Instant::now();
    let out = loop {
        if let Some(_status) = child.try_wait().unwrap() {
            break child.wait_with_output().unwrap();
        }
        assert!(start.elapsed() < Duration::from_secs(30), "the shell did not lock");
        std::thread::sleep(Duration::from_millis(50));
    };
    drop(stdin);
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn shell_locks_automatically_when_idle() {
    let k = Vaulty::new().init();
    let err = shell_until_locked(&k, &format!("{PW}\n"));
    assert!(err.contains("Locked automatically"));
    assert!(err.contains("wiped from memory"));
}

#[test]
fn shell_also_locks_in_the_middle_of_a_question() {
    let k = Vaulty::new().init();
    // `add` asks for a username; there will never be an answer.
    let err = shell_until_locked(&k, &format!("{PW}\nadd Walker\n"));
    assert!(err.contains("Username"));
    assert!(err.contains("Locked automatically"));
    k.run(&["list"], &format!("{PW}\n")).success().stdout(contains("Walker").not());
}

#[test]
fn vault_file_contains_no_plain_text() {
    let k = Vaulty::new().init();
    k.add("VisibleName", "user123", ITEM_PW);
    let raw = std::fs::read(&k.path).unwrap();
    for needle in ["VisibleName", "user123", ITEM_PW, "example.org"] {
        assert!(
            !raw.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{needle} is readable in the file"
        );
    }
    assert_eq!(&raw[..8], b"KLUISVLT");
}

#[test]
fn store_and_get_api_keys() {
    let k = Vaulty::new().init();
    const KEY: &str = "sk-proj-Very-Secret-0042";
    k.run(
        &["add", "OpenAI", "--type", "api", "-u", "project-1", "--url", "https://api.openai.com", "-t", "ai"],
        &format!("{PW}\n{KEY}\n"),
    )
    .success()
    .stderr(contains("API key 'OpenAI' saved (encrypted)"));
    // Without --show: key hidden, and without a clipboard a clean error.
    k.run(&["get", "openai"], &format!("{PW}\n"))
        .failure()
        .stdout(contains("api key").and(contains("project-1")).and(contains(KEY).not()))
        .stderr(contains("no clipboard tool found"));
    k.run(&["get", "openai", "--show"], &format!("{PW}\n"))
        .success()
        .stdout(contains(format!("{:<16} {KEY}", "API key:")));
    // An empty key is rejected.
    k.run(&["add", "Empty", "--type", "api", "-u", "", "--url", "", "-t", ""], &format!("{PW}\n\n"))
        .failure()
        .stderr(contains("must not be empty"));
    // Replace the key.
    k.run(&["edit", "openai", "--password"], &format!("{PW}\nsk-new-1\n")).success();
    k.run(&["get", "openai", "--show"], &format!("{PW}\n"))
        .success()
        .stdout(contains("sk-new-1").and(contains(KEY).not()));
}

#[test]
fn secure_notes_with_multiple_lines() {
    let k = Vaulty::new().init();
    // tags, then the text (finished with a dot)
    k.run(
        &["add", "Recovery codes", "--type", "note"],
        &format!("{PW}\nprive\nCode 1: 7731\nCode 2: 9921\n.\n"),
    )
    .success()
    .stderr(contains("Note 'Recovery codes' saved (encrypted)"));
    k.run(&["get", "recovery codes", "--no-copy"], &format!("{PW}\n"))
        .success()
        .stdout(contains("note").and(contains("(hidden").and(contains("7731").not())));
    k.run(&["get", "recovery codes", "--show"], &format!("{PW}\n"))
        .success()
        .stdout(contains("Code 1: 7731").and(contains("Code 2: 9921")));
    // A note has no username or password.
    k.run(&["add", "X", "--type", "note", "-u", "john"], &format!("{PW}\n"))
        .failure()
        .stderr(contains("no username"));
    k.run(&["edit", "recovery codes", "--generate"], &format!("{PW}\n")).failure();
    // Change the contents.
    k.run(&["edit", "recovery codes", "--notes"], &format!("{PW}\nNew code 5555\n.\n")).success();
    k.run(&["get", "recovery codes", "--show"], &format!("{PW}\n"))
        .success()
        .stdout(contains("5555").and(contains("7731").not()));
}

#[test]
fn list_filters_by_type() {
    let k = Vaulty::new().init();
    k.add("GitHub", "john", ITEM_PW);
    k.run(
        &["add", "Stripe", "--type", "api", "-u", "", "--url", "", "-t", ""],
        &format!("{PW}\nsk_live_x\n"),
    )
    .success();
    k.run(&["add", "Diary", "--type", "note", "-t", ""], &format!("{PW}\ntext\n.\n")).success();
    k.run(&["list"], &format!("{PW}\n"))
        .success()
        .stdout(contains("GitHub").and(contains("Stripe")).and(contains("Diary")))
        .stderr(contains("3 items: 1 login · 1 API key · 1 note"));
    k.run(&["list", "--type", "api"], &format!("{PW}\n"))
        .success()
        .stdout(contains("Stripe").and(contains("GitHub").not()));
    k.run(&["list", "--type", "note"], &format!("{PW}\n"))
        .success()
        .stdout(contains("Diary").and(contains("Stripe").not()));
    k.run(&["list", "--type", "bicycle"], "").failure();
    k.run(&["search", "note"], &format!("{PW}\n")).success().stdout(contains("Diary"));
}

#[test]
fn shell_joins_loose_words_into_a_name() {
    let k = Vaulty::new().init();
    k.add("My Bank", "john", ITEM_PW);
    k.run(&["shell"], &format!("{PW}\nget my bank --show\nexit\n")).success().stdout(contains(ITEM_PW));
}

#[test]
fn without_a_command() {
    let k = Vaulty::new();
    // No vault yet: a hint to create one.
    k.run(&[], "").success().stderr(contains("kluis setup"));
    // With a vault: login screen + interactive mode.
    let k = k.init();
    k.run(&[], &format!("{PW}\nlist\nexit\n")).success().stderr(contains("Vault unlocked"));
}

#[test]
fn no_ansi_codes_outside_a_terminal() {
    let k = Vaulty::new().init();
    k.add("GitHub", "john", ITEM_PW);
    let out = k
        .cmd()
        .env_remove("NO_COLOR")
        .env("COLORTERM", "truecolor")
        .args(["shell"])
        .write_stdin(format!("{PW}\nlist\nexit\n"))
        .assert()
        .success();
    let o = out.get_output();
    assert!(!o.stdout.contains(&0x1b) && !o.stderr.contains(&0x1b), "no escape codes in pipes");
    k.cmd().args(["logo"]).assert().success().stderr(contains("color terminal"));
}

// ───────────────────────── setup wizard and settings ─────────────────────────

fn config_file(v: &Vaulty) -> std::path::PathBuf {
    v.dir().join("config-home").join("kluis").join("config")
}

#[test]
fn setup_saves_settings_and_creates_the_vault() {
    let v = Vaulty::new();
    // animation? n | lock minutes: 10 | master password, repeated
    v.run(&["setup"], &format!("n\n10\n{PW}\n{PW}\n")).success().stderr(
        contains("Step 1 of 3")
            .and(contains("Step 2 of 3"))
            .and(contains("Step 3 of 3"))
            .and(contains("Settings saved"))
            .and(contains("Vault created"))
            .and(contains("All set!")),
    );
    // (the real setup uses full-strength Argon2; --kdf-* flags are exercised in the next test)
    assert!(v.path.exists());
    let cfg = std::fs::read_to_string(config_file(&v)).unwrap();
    assert!(cfg.contains("animation=off") && cfg.contains("lock_timeout_minutes=10"), "{cfg}");
    // The vault works, and `info` shows the saved settings.
    v.run(&["list"], &format!("{PW}\n")).success();
    v.run(&["info"], "")
        .success()
        .stdout(contains("Animation:        off").and(contains("after 10 minute(s)")));
}

#[test]
fn setup_with_empty_answers_uses_the_defaults() {
    let v = Vaulty::new();
    v.run(
        &["setup", FAST_KDF[0], FAST_KDF[1], FAST_KDF[2], FAST_KDF[3], FAST_KDF[4], FAST_KDF[5]],
        &format!("\n\n{PW}\n{PW}\n"),
    )
    .success();
    let cfg = std::fs::read_to_string(config_file(&v)).unwrap();
    assert!(cfg.contains("animation=on") && cfg.contains("lock_timeout_minutes=5"), "{cfg}");
    assert!(v.path.exists());
}

#[test]
fn setup_keeps_an_existing_vault() {
    let v = Vaulty::new().init();
    v.add("GitHub", "john", ITEM_PW);
    let before = std::fs::read(&v.path).unwrap();
    // No password questions when a vault already exists.
    v.run(&["setup"], "y\n3\n")
        .success()
        .stderr(contains("keeping it as it is").and(contains("kluis passwd")));
    assert_eq!(std::fs::read(&v.path).unwrap(), before, "vault untouched");
    let cfg = std::fs::read_to_string(config_file(&v)).unwrap();
    assert!(cfg.contains("animation=on") && cfg.contains("lock_timeout_minutes=3"), "{cfg}");
}

#[test]
fn setup_rejects_bad_answers_and_weak_passwords() {
    let v = Vaulty::new();
    v.run(&["setup"], "y\nabc\n").failure().stderr(contains("whole number of minutes"));
    v.run(&["setup"], "y\n0\n").failure().stderr(contains("between 1 and 1440"));
    v.run(&["setup"], "y\n99999\n").failure().stderr(contains("between 1 and 1440"));
    assert!(!v.path.exists(), "no vault after bad answers");
    // A weak master password is refused; no vault is created.
    v.run(&["setup", FAST_KDF[0], FAST_KDF[1]], "y\n5\npassword123\npassword123\n")
        .failure()
        .stderr(contains("too weak"));
    assert!(!v.path.exists());
}

#[test]
fn setup_asks_for_a_password_twice() {
    let v = Vaulty::new();
    v.run(&["setup", FAST_KDF[0], FAST_KDF[1]], &format!("y\n5\n{PW}\n{PW}x\n"))
        .failure()
        .stderr(contains("do not match"));
    assert!(!v.path.exists());
}

#[test]
fn config_show_and_set() {
    let v = Vaulty::new();
    v.run(&["config"], "")
        .success()
        .stdout(contains("animation:     on").and(contains("lock-timeout:  5 minute(s)")));
    assert!(!config_file(&v).exists(), "showing settings writes nothing");

    v.run(&["config", "set", "animation", "off"], "").success().stderr(contains("Setting saved"));
    v.run(&["config", "set", "lock-timeout", "12"], "").success();
    v.run(&["config", "show"], "")
        .success()
        .stdout(contains("animation:     off").and(contains("lock-timeout:  12 minute(s)")));
    let cfg = std::fs::read_to_string(config_file(&v)).unwrap();
    assert_eq!(
        cfg.lines().filter(|l| !l.starts_with('#')).collect::<Vec<_>>(),
        ["animation=off", "lock_timeout_minutes=12"]
    );

    // On/off words are flexible; bad values and unknown keys are refused.
    v.run(&["config", "set", "animation", "YES"], "").success();
    v.run(&["config", "set", "animation", "maybe"], "").failure().stderr(contains("'on' or 'off'"));
    v.run(&["config", "set", "lock-timeout", "0"], "").failure().stderr(contains("between 1 and 1440"));
    v.run(&["config", "set", "lock-timeout", "soon"], "").failure();
    v.run(&["config", "set", "colour", "red"], "").failure();
    // Failed changes left the file alone.
    assert!(std::fs::read_to_string(config_file(&v)).unwrap().contains("animation=on"));
}

#[test]
fn a_damaged_config_file_never_stops_the_program() {
    let v = Vaulty::new().init();
    let cfg = config_file(&v);
    std::fs::create_dir_all(cfg.parent().unwrap()).unwrap();
    std::fs::write(&cfg, b"\xff\xfe not even text \x1b[2J\nanimation=banana\nlock_timeout_minutes=-1\n")
        .unwrap();
    v.run(&["list"], &format!("{PW}\n")).success();
    v.run(&["config"], "").success().stdout(contains("animation:     on"));
    // A bad file is replaced by a clean one the next time you change a setting.
    v.run(&["config", "set", "animation", "off"], "").success();
    assert!(std::fs::read_to_string(&cfg).unwrap().starts_with("# CakePass settings"));
}

#[test]
fn settings_and_flags_do_not_break_non_terminal_output() {
    let v = Vaulty::new().init();
    v.run(&["config", "set", "animation", "off"], "").success();
    v.add("GitHub", "john", ITEM_PW);
    // With the animation off, or the flag given, scripts still get clean output.
    v.run(&["--no-animation", "shell"], &format!("{PW}\nlist\nexit\n")).success().stdout(contains("GitHub"));
    v.run(&["shell"], &format!("{PW}\nlist\nexit\n")).success().stdout(contains("GitHub"));
}
