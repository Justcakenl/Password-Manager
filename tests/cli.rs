//! Integration tests: run the real `cakepass` program with input via stdin.
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
        let mut c = Command::new(env!("CARGO_BIN_EXE_cakepass"));
        c.env("CAKEPASS_VAULT", &self.path)
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
            .args([
                "add",
                name,
                "--username",
                user,
                "--email",
                "john@example.org",
                "--url",
                "https://example.org",
                "--tags",
                "work,test",
            ])
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
    k.run(&["add", "github", "-u", "x", "-e", "", "--url", "", "-t", ""], &format!("{PW}\nx\n"))
        .failure()
        .stderr(contains("already exists"));
}

#[test]
fn interactive_add_with_generated_password() {
    let k = Vaulty::new().init();
    // username, e-mail, url, tags, notes, password (empty = generate)
    k.run(&["add", "Mail"], &format!("{PW}\nmailuser\nme@mail.com\nhttps://mail.com\npriv\nsecret note\n\n"))
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
    let out = Command::new(env!("CARGO_BIN_EXE_cakepass"))
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
    Command::new(env!("CARGO_BIN_EXE_cakepass"))
        .args(["--vault", bak.to_str().unwrap(), "list"])
        .write_stdin(format!("{PW}\n"))
        .assert()
        .failure();
}

#[test]
fn export_and_import() {
    let a = Vaulty::new().init();
    a.add("GitHub", "john", ITEM_PW);
    let export = a.dir().join("export.cakepass");
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
            .and(contains("Format version:   3"))
            .and(contains("Security level:   custom"))
            .and(contains("Key file:         not used"))
            .and(contains("encrypted separately")),
    );
}

#[test]
fn missing_vault_gives_hint() {
    let k = Vaulty::new();
    k.run(&["list"], "").failure().stderr(contains("cakepass setup"));
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

/// Start `cakepass shell --timeout 1`, send `input` and leave stdin open.
/// Returns the stderr output as soon as the shell stops by itself.
fn shell_until_locked(k: &Vaulty, input: &str) -> String {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_cakepass"))
        .args(["shell", "--timeout", "1"])
        .env("CAKEPASS_VAULT", &k.path)
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
        &[
            "add",
            "OpenAI",
            "--type",
            "api",
            "-u",
            "project-1",
            "-e",
            "",
            "--url",
            "https://api.openai.com",
            "-t",
            "ai",
        ],
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
    k.run(
        &["add", "Empty", "--type", "api", "-u", "", "-e", "", "--url", "", "-t", ""],
        &format!("{PW}\n\n"),
    )
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
        &["add", "Stripe", "--type", "api", "-u", "", "-e", "", "--url", "", "-t", ""],
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
    k.run(&[], "").success().stderr(contains("cakepass setup"));
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
    v.dir().join("config-home").join("cakepass").join("config")
}

#[test]
fn setup_saves_settings_and_creates_the_vault() {
    let v = Vaulty::new();
    // animation? n | lock minutes: 10 | level: 1 (standard) | make a passphrase? n |
    // master password, repeated | key file? (Enter = no)
    v.run(&["setup"], &format!("n\n10\n1\nn\n{PW}\n{PW}\n\n")).success().stderr(
        contains("Step 1 of 5")
            .and(contains("Step 2 of 5"))
            .and(contains("Step 3 of 5 — Security level"))
            .and(contains("High (recommended)"))
            .and(contains("Standard: unlocking takes about"))
            .and(contains("Step 4 of 5 — Master password"))
            .and(contains("Make a strong passphrase for me? [Y/n]"))
            .and(contains("Step 5 of 5 — Extra protection: a key file"))
            .and(contains("No key file."))
            .and(contains("Settings saved"))
            .and(contains("Vault created"))
            .and(contains("All set!")),
    );
    // (the real setup uses full-strength Argon2; --kdf-* flags are exercised in the next test)
    assert!(v.path.exists());
    v.run(&["info"], "").success().stdout(contains("Security level:   standard"));
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
    // (the level comes from the flags; "n" = type my own password; Enter = no key file)
    v.run(
        &["setup", FAST_KDF[0], FAST_KDF[1], FAST_KDF[2], FAST_KDF[3], FAST_KDF[4], FAST_KDF[5]],
        &format!("\n\nn\n{PW}\n{PW}\n\n"),
    )
    .success()
    .stderr(contains("Using the settings from the command line").and(contains("Step 3 of 5")));
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
        .stderr(contains("keeping it as it is").and(contains("cakepass passwd")));
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
    v.run(&["setup", FAST_KDF[0], FAST_KDF[1]], "y\n5\nn\npassword123\npassword123\n")
        .failure()
        .stderr(contains("too weak"));
    // A level this program does not know.
    v.run(&["setup"], "y\n5\n9\n").failure().stderr(contains("choose 1, 2 or 3"));
    assert!(!v.path.exists());
}

#[test]
fn setup_asks_for_a_password_twice() {
    let v = Vaulty::new();
    v.run(&["setup", FAST_KDF[0], FAST_KDF[1]], &format!("y\n5\nn\n{PW}\n{PW}x\n"))
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

// ───────────────────────── e-mail addresses ─────────────────────────

#[test]
fn email_addresses_are_stored_shown_and_searchable() {
    let k = Vaulty::new().init();
    k.add("GitHub", "john", ITEM_PW); // helper adds --email john@example.org

    k.run(&["get", "github", "--no-copy"], &format!("{PW}\n"))
        .success()
        .stdout(contains(format!("{:<16} john@example.org", "E-mail:")));
    // Searchable, and copyable (no clipboard in the test → a clean error).
    k.run(&["search", "john@example"], &format!("{PW}\n")).success().stdout(contains("GitHub"));
    k.run(&["get", "github", "--copy-email"], &format!("{PW}\n"))
        .failure()
        .stderr(contains("no clipboard tool found"));
    // Change it, then clear it.
    k.run(&["edit", "github", "--email", "pete@example.net"], &format!("{PW}\n")).success();
    k.run(&["get", "github", "--no-copy"], &format!("{PW}\n"))
        .success()
        .stdout(contains("pete@example.net").and(contains("john@example.org").not()));
    k.run(&["edit", "github", "-e", ""], &format!("{PW}\n")).success();
    k.run(&["get", "github", "--copy-email"], &format!("{PW}\n"))
        .failure()
        .stderr(contains("has no e-mail address"));
    // A hint (not an error) when it does not look like an address.
    k.run(&["edit", "github", "-e", "not-an-address"], &format!("{PW}\n"))
        .success()
        .stderr(contains("does not look like an e-mail address"));
    // A note has no e-mail address.
    k.run(&["add", "N", "--type", "note", "-e", "a@b.nl"], &format!("{PW}\n")).failure();
}

#[test]
fn email_column_is_imported_from_csv() {
    let k = Vaulty::new().init();
    let csv = k.dir().join("export.csv");
    std::fs::write(&csv, "name,url,username,email,password\nSite,https://s.nl,sam,sam@s.nl,pw-1\n").unwrap();
    k.run(&["import-csv", csv.to_str().unwrap()], &format!("{PW}\nn\n")).success();
    k.run(&["get", "site", "--show"], &format!("{PW}\n"))
        .success()
        .stdout(contains("sam@s.nl").and(contains("sam")).and(contains("pw-1")));
}

// ───────────────────────── generate + edit + save ─────────────────────────

#[test]
fn generate_and_save_in_one_step() {
    let k = Vaulty::new().init();
    // Master password first, then the same questions as `add`: username,
    // e-mail, URL, tags, notes.
    k.run(&["generate", "--save", "Mail", "-l", "30"], &format!("{PW}\nmailuser\nme@mail.com\n\n\n\n"))
        .success()
        .stderr(contains("Login 'Mail' saved (encrypted)"));
    let out = k.run(&["get", "mail", "--show"], &format!("{PW}\n")).success().get_output().stdout.clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("me@mail.com") && text.contains("mailuser"));
    let pw_line = text.lines().find(|l| l.starts_with("Password:")).unwrap();
    assert_eq!(pw_line.trim_start_matches("Password:").trim().chars().count(), 30);
    // An existing name is refused before anything else happens.
    k.run(&["generate", "--save", "MAIL"], &format!("{PW}\n")).failure().stderr(contains("already exists"));
    // A wrong master password stops it before a password is even made.
    k.run(&["generate", "--save", "Other"], "wrong-password\n")
        .failure()
        .stderr(contains("decryption failed"));
}

#[test]
fn plain_generate_still_works_in_scripts() {
    // Without a terminal there is no menu: same behavior as before.
    let k = Vaulty::new();
    let out = k.run(&["generate", "--show", "-l", "20"], "").success().get_output().clone();
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim().chars().count(), 20);
    assert!(String::from_utf8_lossy(&out.stderr).contains("Strength:"));
}

// ───────────────────────── everything on disk is encrypted ─────────────────────────

fn all_files(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            all_files(&p, out);
        } else {
            out.push((p.clone(), std::fs::read(&p).unwrap()));
        }
    }
}

#[test]
fn nothing_readable_is_written_to_disk() {
    use std::os::unix::fs::PermissionsExt;
    let k = Vaulty::new().init();
    // Distinctive markers for every kind of data the program can write.
    let markers = [
        "zq-name-4711",
        "zq-user-4711",
        "zq-mail-4711@example.org",
        "zq-url-4711.example",
        "zq-tag-4711",
        "zq-pass-4711-Xv9",
        "zq-note-4711",
        "zq-api-name-4711",
        "zq-api-id-4711",
        "zq-api-mail-4711@example.org",
        "zq-api-key-4711",
        "zq-text-name-4711",
        "zq-text-tag-4711",
        "zq-text-body-4711",
    ];
    k.run(
        &[
            "add",
            "zq-name-4711",
            "-u",
            "zq-user-4711",
            "-e",
            "zq-mail-4711@example.org",
            "--url",
            "https://zq-url-4711.example",
            "-t",
            "zq-tag-4711",
        ],
        &format!("{PW}\nzq-pass-4711-Xv9\n"),
    )
    .success();
    k.run(&["edit", "zq-name-4711", "--notes"], &format!("{PW}\nzq-note-4711\n")).success();
    k.run(
        &[
            "add",
            "zq-api-name-4711",
            "--type",
            "api",
            "-u",
            "zq-api-id-4711",
            "-e",
            "zq-api-mail-4711@example.org",
            "--url",
            "",
            "-t",
            "",
        ],
        &format!("{PW}\nzq-api-key-4711\n"),
    )
    .success();
    k.run(
        &["add", "zq-text-name-4711", "--type", "note", "-t", "zq-text-tag-4711"],
        &format!("{PW}\nzq-text-body-4711\n.\n"),
    )
    .success();
    // A second save leaves an older version behind in the backup file too.
    k.run(&["edit", "zq-name-4711", "-e", "zq-mail-4711@example.org"], &format!("{PW}\n")).success();
    k.run(&["config", "set", "animation", "off"], "").success();
    k.run(&["config", "set", "lock-timeout", "7"], "").success();
    let export = k.dir().join("backup.cakepass");
    k.run(&["export", export.to_str().unwrap()], &format!("{PW}\n{PW2}\n{PW2}\n")).success();

    // Sanity check: the data really is there when you log in.
    let shown = k.run(&["get", "zq-name-4711", "--show"], &format!("{PW}\n")).success();
    let shown = String::from_utf8(shown.get_output().stdout.clone()).unwrap();
    for m in ["zq-user-4711", "zq-mail-4711@example.org", "zq-pass-4711-Xv9", "zq-note-4711"] {
        assert!(shown.contains(m), "{m} missing from `get --show`");
    }

    // Now read EVERY file the program wrote and look for any readable marker.
    let mut files = Vec::new();
    all_files(k.dir(), &mut files);
    assert!(files.len() >= 4, "vault, backup, settings and export expected, got {}", files.len());
    for (path, bytes) in &files {
        for m in markers {
            assert!(
                !bytes.windows(m.len()).any(|w| w == m.as_bytes()),
                "{m} is readable in {}",
                path.display()
            );
        }
        // Everything the program wrote is private to the user.
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0, "{} is not private ({mode:o})", path.display());
    }
    // The settings file holds only the two settings, no user data.
    let cfg = files.iter().find(|(p, _)| p.ends_with("cakepass/config")).expect("settings file");
    let cfg = String::from_utf8(cfg.1.clone()).unwrap();
    let data_lines: Vec<&str> = cfg.lines().filter(|l| !l.starts_with('#') && !l.is_empty()).collect();
    assert_eq!(data_lines, ["animation=off", "lock_timeout_minutes=7"]);
}

#[test]
fn old_kluis_folders_are_moved_to_cakepass() {
    let k = Vaulty::new();
    let cfg_home = k.dir().join("config-home");
    std::fs::create_dir_all(cfg_home.join("kluis")).unwrap();
    std::fs::write(cfg_home.join("kluis").join("config"), "animation=off\nlock_timeout_minutes=9\n").unwrap();
    k.run(&["config"], "").success().stdout(contains("9 minute"));
    assert!(cfg_home.join("cakepass").join("config").exists());
    assert!(!cfg_home.join("kluis").exists());
}

// ───────────────────────── security levels and key files (0.4) ─────────────────────────

/// The "error: …" line of a failed run.
fn error_line(a: &assert_cmd::assert::Assert) -> String {
    let err = String::from_utf8_lossy(&a.get_output().stderr).into_owned();
    err.lines().find(|l| l.starts_with("error:")).unwrap_or_default().to_string()
}

/// A folder that plays the USB stick.
fn usb(v: &Vaulty) -> PathBuf {
    let d = v.dir().join("usb");
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn make_key_file(v: &Vaulty, name: &str) -> PathBuf {
    let kf = usb(v).join(name);
    v.run(&["keyfile", "create", kf.to_str().unwrap()], "").success();
    kf
}

/// A vault (light Argon2 settings) that needs the key file `usb/cakepass.key`.
fn init_with_key_file(v: &Vaulty) -> PathBuf {
    let kf = make_key_file(v, "cakepass.key");
    v.cmd()
        .args(["--keyfile", kf.to_str().unwrap(), "init"])
        .args(FAST_KDF)
        .write_stdin(format!("{PW}\n{PW}\n"))
        .assert()
        .success()
        .stderr(
            contains("Vault created")
                .and(contains("needs the key file"))
                .and(contains("Saved in your settings")),
        );
    kf
}

#[test]
fn keyfile_create_never_overwrites_and_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let v = Vaulty::new();
    let kf = usb(&v).join("cakepass.key");
    let kf_s = kf.to_str().unwrap();
    v.run(&["keyfile", "create", kf_s], "")
        .success()
        .stderr(contains("Key file created").and(contains("no recovery")).and(contains("--new-keyfile")));
    let bytes = std::fs::read(&kf).unwrap();
    assert_eq!(bytes.len(), 64);
    assert_eq!(std::fs::metadata(&kf).unwrap().permissions().mode() & 0o777, 0o600);
    v.run(&["keyfile", "create", kf_s], "").failure().stderr(contains("will not overwrite"));
    assert_eq!(std::fs::read(&kf).unwrap(), bytes, "untouched");
    let other = usb(&v).join("second.key");
    v.run(&["keyfile", "create", other.to_str().unwrap()], "").success();
    assert_ne!(std::fs::read(&other).unwrap(), bytes, "random");
    let nowhere = v.dir().join("no-such-folder").join("k");
    v.run(&["keyfile", "create", nowhere.to_str().unwrap()], "").failure().stderr(contains("does not exist"));
}

#[test]
fn a_vault_with_a_key_file() {
    let v = Vaulty::new();
    let kf = init_with_key_file(&v);
    let kf_s = kf.to_str().unwrap();
    // Only the path is in the settings, never the contents.
    let cfg = std::fs::read(config_file(&v)).unwrap();
    let key = std::fs::read(&kf).unwrap();
    assert!(String::from_utf8_lossy(&cfg).contains(&format!("keyfile={kf_s}\n")));
    assert!(!cfg.windows(16).any(|w| key.windows(16).any(|k| k == w)), "no key bytes in the settings");
    // The settings point to it, so everything works as usual.
    v.add("GitHub", "john", ITEM_PW);
    v.run(&["get", "github", "--show"], &format!("{PW}\n")).success().stdout(contains(ITEM_PW));
    v.run(&["info"], "").success().stdout(
        contains("Format version:   3").and(contains("Key file:         required:")).and(contains("(found)")),
    );
    v.run(&["config"], "").success().stdout(contains(format!("keyfile:       {kf_s}")));

    // Without the key file: a clear error, before the password is even asked.
    v.run(&["config", "set", "keyfile", "none"], "").success();
    v.run(&["get", "github", "--show"], &format!("{PW}\n")).failure().stdout(contains(ITEM_PW).not()).stderr(
        contains("needs its key file")
            .and(contains("--keyfile PATH"))
            .and(contains("CAKEPASS_KEYFILE"))
            .and(contains("config set keyfile"))
            .and(contains("Master password").not()),
    );
    // Given with --keyfile (before or after the command) or in the environment.
    v.run(&["--keyfile", kf_s, "get", "github", "--show"], &format!("{PW}\n"))
        .success()
        .stdout(contains(ITEM_PW));
    v.run(&["get", "github", "--show", "--keyfile", kf_s], &format!("{PW}\n")).success();
    v.cmd()
        .env("CAKEPASS_KEYFILE", &kf)
        .args(["get", "github", "--show"])
        .write_stdin(format!("{PW}\n"))
        .assert()
        .success()
        .stdout(contains(ITEM_PW));

    // A wrong key file and a wrong password give exactly the same error.
    let other = make_key_file(&v, "other.key");
    let wrong_kf =
        v.cmd().env("CAKEPASS_KEYFILE", &other).arg("list").write_stdin(format!("{PW}\n")).assert().failure();
    let wrong_pw =
        v.cmd().env("CAKEPASS_KEYFILE", &kf).arg("list").write_stdin("not-it\n").assert().failure();
    assert_eq!(error_line(&wrong_kf), error_line(&wrong_pw));
    assert!(error_line(&wrong_kf).contains("decryption failed"));
    for a in [&wrong_kf, &wrong_pw] {
        assert!(String::from_utf8_lossy(&a.get_output().stderr).contains("the key file used was"));
    }

    // --keyfile beats the environment, the environment beats the settings.
    v.run(&["config", "set", "keyfile", other.to_str().unwrap()], "").success();
    v.cmd().env("CAKEPASS_KEYFILE", &kf).arg("list").write_stdin(format!("{PW}\n")).assert().success();
    v.cmd()
        .env("CAKEPASS_KEYFILE", &other)
        .args(["--keyfile", kf_s, "list"])
        .write_stdin(format!("{PW}\n"))
        .assert()
        .success();

    // The USB stick is not plugged in: say so plainly, with the path.
    let gone = v.dir().join("unplugged").join("cakepass.key");
    v.run(&["config", "set", "keyfile", gone.to_str().unwrap()], "").success().stderr(contains("no file at"));
    v.run(&["list"], &format!("{PW}\n"))
        .failure()
        .stderr(contains("cannot be read").and(contains(gone.to_str().unwrap())).and(contains("plugged in")));

    // The backup needs the same key file.
    let bak = v.dir().join("vault.enc.bak");
    v.cmd()
        .env("CAKEPASS_KEYFILE", &kf)
        .args(["--vault", bak.to_str().unwrap(), "list"])
        .write_stdin(format!("{PW}\n"))
        .assert()
        .success();
    v.cmd()
        .env("CAKEPASS_KEYFILE", &other)
        .args(["--vault", bak.to_str().unwrap(), "list"])
        .write_stdin(format!("{PW}\n"))
        .assert()
        .failure()
        .stderr(contains("decryption failed"));
}

#[test]
fn a_key_file_that_is_not_needed_is_mentioned() {
    let v = Vaulty::new().init();
    let kf = make_key_file(&v, "k.key");
    v.run(&["--keyfile", kf.to_str().unwrap(), "list"], &format!("{PW}\n"))
        .success()
        .stderr(contains("does not use a key file"));
}

#[test]
fn security_levels_and_key_files_can_be_changed_and_keep_everything() {
    let v = Vaulty::new().init();
    v.add("GitHub", "john", ITEM_PW);
    v.run(&["security"], "").success().stdout(
        contains("Security level:   custom")
            .and(contains("Key file:         not used"))
            .and(contains("Unlock time:      about"))
            .and(contains("maximum   1024 MiB")),
    );
    // Another level: same password, everything kept.
    v.run(&["security", "--level", "standard"], &format!("{PW}\n"))
        .success()
        .stderr(contains("Security level: Standard").and(contains("Unlocking takes about")));
    v.run(&["info"], "").success().stdout(contains("Security level:   standard"));
    v.run(&["get", "github", "--show"], &format!("{PW}\n")).success().stdout(contains(ITEM_PW));
    // Nothing to change: no password asked.
    v.run(&["security", "--level", "standard"], "")
        .success()
        .stderr(contains("already uses the standard level"));
    v.run(&["security", "--no-keyfile"], "").success().stderr(contains("does not use a key file"));

    // Turn the key file on.
    let kf = make_key_file(&v, "first.key");
    v.run(&["security", "--new-keyfile", kf.to_str().unwrap()], &format!("{PW}\n")).success().stderr(
        contains("now needs the key file")
            .and(contains("Saved in your settings"))
            .and(contains("no recovery"))
            .and(contains("Copies of the vault you made yourself earlier")),
    );
    v.run(&["get", "github", "--show"], &format!("{PW}\n")).success().stdout(contains(ITEM_PW));
    v.run(&["security"], "").success().stdout(contains("Key file:         required:"));
    let bak = v.dir().join("vault.enc.bak");
    v.cmd()
        .env("CAKEPASS_KEYFILE", v.dir().join("usb").join("missing"))
        .args(["--vault", bak.to_str().unwrap(), "list"])
        .write_stdin(format!("{PW}\n"))
        .assert()
        .failure()
        .stderr(contains("cannot be read"));

    // Rotate it: the old key file opens nothing any more; the settings follow.
    let kf2 = make_key_file(&v, "second.key");
    v.run(&["security", "--new-keyfile", kf2.to_str().unwrap()], &format!("{PW}\n")).success();
    v.run(&["config"], "").success().stdout(contains("second.key"));
    v.cmd().env("CAKEPASS_KEYFILE", &kf).arg("list").write_stdin(format!("{PW}\n")).assert().failure();
    v.run(&["list"], &format!("{PW}\n")).success().stdout(contains("GitHub"));

    // Remove it: the master password alone opens the vault again.
    v.run(&["security", "--no-keyfile"], &format!("{PW}\n"))
        .success()
        .stderr(contains("no longer needs a key file").and(contains("Removed the key file path")));
    v.run(&["config"], "").success().stdout(contains("keyfile:       none"));
    v.run(&["get", "github", "--show"], &format!("{PW}\n")).success().stdout(contains(ITEM_PW));
    v.run(&["info"], "").success().stdout(contains("Key file:         not used"));
    // A wrong password changes nothing.
    v.run(&["security", "--level", "high"], "wrong\n").failure().stderr(contains("decryption failed"));
    v.run(&["info"], "").success().stdout(contains("Security level:   standard"));
}

#[test]
fn security_refuses_bad_key_files_before_asking_anything() {
    let v = Vaulty::new().init();
    let missing = usb(&v).join("not-made-yet.key");
    v.run(&["security", "--new-keyfile", missing.to_str().unwrap()], &format!("{PW}\n"))
        .failure()
        .stderr(contains("cakepass keyfile create").and(contains("Master password").not()));
    v.run(&["security", "--new-keyfile", v.path.to_str().unwrap()], &format!("{PW}\n"))
        .failure()
        .stderr(contains("cannot be its own key file"));
    let empty = usb(&v).join("empty");
    std::fs::write(&empty, b"").unwrap();
    v.run(&["security", "--new-keyfile", empty.to_str().unwrap()], &format!("{PW}\n"))
        .failure()
        .stderr(contains("is empty"));
    let link = usb(&v).join("link.key");
    std::os::unix::fs::symlink(make_key_file(&v, "real.key"), &link).unwrap();
    v.run(&["security", "--new-keyfile", link.to_str().unwrap()], &format!("{PW}\n"))
        .failure()
        .stderr(contains("symbolic link"));
    // Next to the vault: allowed, with a warning.
    let beside = v.dir().join("beside.key");
    v.run(&["keyfile", "create", beside.to_str().unwrap()], "").success();
    v.run(&["security", "--new-keyfile", beside.to_str().unwrap()], &format!("{PW}\n"))
        .success()
        .stderr(contains("same folder as the vault"));
    v.run(&["passwd", "--kdf-memory", "9"], &format!("{PW}\n{PW2}\n{PW2}\n")).success();
    v.run(&["list"], &format!("{PW2}\n")).success();
    v.run(&["info"], "").success().stdout(contains("Argon2id, 9 MiB").and(contains("required:")));
}

#[test]
fn the_shell_reconfirms_with_the_key_file() {
    let v = Vaulty::new();
    init_with_key_file(&v);
    v.add("GitHub", "john", ITEM_PW);
    v.run(&["shell"], &format!("{PW}\nsecurity --level standard\n{PW}\nlist\nexit\n"))
        .success()
        .stdout(contains("GitHub"))
        .stderr(contains("Current master password (to confirm)").and(contains("Security level: Standard")));
    v.run(&["info"], "").success().stdout(contains("Security level:   standard").and(contains("required:")));
    // A wrong password in the shell changes nothing.
    v.run(&["shell"], &format!("{PW}\nsecurity --level high\nwrong\nexit\n"))
        .success()
        .stderr(contains("decryption failed"));
    v.run(&["info"], "").success().stdout(contains("Security level:   standard"));
}

#[test]
fn export_and_import_do_not_need_the_key_file() {
    let a = Vaulty::new();
    init_with_key_file(&a);
    a.add("GitHub", "john", ITEM_PW);
    let export = a.dir().join("export.cakepass");
    a.run(&["export", export.to_str().unwrap()], &format!("{PW}\n{PW2}\n{PW2}\n"))
        .success()
        .stderr(contains("export password ONLY"));
    let b = Vaulty::new().init();
    b.run(&["import", export.to_str().unwrap()], &format!("{PW}\n{PW2}\n"))
        .success()
        .stderr(contains("1 item(s) added"));
    b.run(&["get", "github", "--show"], &format!("{PW}\n")).success().stdout(contains(ITEM_PW));
}

#[test]
fn the_memory_guard_refuses_before_allocating() {
    let v = Vaulty::new();
    // Creating at a level that does not fit: refused, nothing created, no password asked.
    v.cmd()
        .env("CAKEPASS_TEST_MEM_AVAILABLE_KIB", "300000")
        .args(["init", "--level", "high"])
        .write_stdin(format!("{PW}\n{PW}\n"))
        .assert()
        .failure()
        .stderr(
            contains("needs about 342 MiB of free memory")
                .and(contains("lower level"))
                .and(contains("New master password").not()),
        );
    assert!(!v.path.exists());
    let v = v.init();
    // Opening a vault whose level this computer cannot run right now.
    v.cmd()
        .env("CAKEPASS_TEST_MEM_AVAILABLE_KIB", "4000")
        .arg("list")
        .write_stdin(format!("{PW}\n"))
        .assert()
        .failure()
        .stderr(
            contains("cannot run at the moment")
                .and(contains("more memory"))
                .and(contains("Master password").not()),
        );
    // Switching to a level that does not fit: refused before the password.
    v.cmd()
        .env("CAKEPASS_TEST_MEM_AVAILABLE_KIB", "1000000")
        .args(["security", "--level", "maximum"])
        .write_stdin(format!("{PW}\n"))
        .assert()
        .failure()
        .stderr(contains("needs about 1366 MiB").and(contains("Master password").not()));
    v.cmd()
        .env("CAKEPASS_TEST_MEM_AVAILABLE_KIB", "4000")
        .arg("security")
        .assert()
        .success()
        .stdout(contains("cannot run here right now"));
    v.run(&["list"], &format!("{PW}\n")).success();
}

#[test]
fn a_version_2_vault_becomes_version_3_on_its_next_save() {
    use cakepass::crypto::KdfParams;
    use cakepass::format::{self, Credentials, VaultKey};
    let v = Vaulty::new();
    let fast = KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 };
    let vk = VaultKey::create(Credentials::password(PW.as_bytes()), fast).unwrap();
    let json = cakepass::vault::Vault::new().to_json().unwrap();
    let v2 = format::seal_as_version_for_tests(&vk, 2, json.as_slice()).unwrap();
    std::fs::write(&v.path, &v2).unwrap();
    let version = |p: &Path| {
        let b = std::fs::read(p).unwrap();
        u16::from_le_bytes([b[8], b[9]])
    };
    // Reading does not rewrite it (an older cakepass can still open it).
    v.run(&["list"], &format!("{PW}\n")).success();
    assert_eq!(std::fs::read(&v.path).unwrap(), v2);
    v.run(&["info"], "").success().stdout(contains("Format version:   2"));
    // The next change saves it as version 3; the .bak is the version 2 file.
    v.add("GitHub", "john", ITEM_PW);
    assert_eq!(version(&v.path), 3);
    assert_eq!(std::fs::read(v.dir().join("vault.enc.bak")).unwrap(), v2);
    v.run(&["get", "github", "--show"], &format!("{PW}\n")).success().stdout(contains(ITEM_PW));
}

/// Run `cakepass setup` with pipes: answer, read the generated passphrase
/// from stdout, then type it back (and answer the key file question).
fn setup_with_passphrase(v: &Vaulty, after: impl FnOnce(&str) -> String) -> (std::process::Output, String) {
    use std::io::{BufRead, BufReader};
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_cakepass"))
        .arg("setup")
        .args(FAST_KDF)
        .env("CAKEPASS_VAULT", &v.path)
        .env("NO_COLOR", "1")
        .env("XDG_CONFIG_HOME", v.dir().join("config-home"))
        .env_remove("CAKEPASS_KEYFILE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // animation: n | lock: Enter | make a passphrase for me: Enter (yes)
    stdin.write_all(b"n\n\n\n").unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut phrase = String::new();
    let start = Instant::now();
    while phrase.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(30), "no passphrase shown");
        let mut line = String::new();
        assert!(out.read_line(&mut line).unwrap() > 0, "stdout closed before the passphrase");
        let t = line.trim();
        if t.contains('-') && t.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
            phrase = t.to_string();
        }
    }
    stdin.write_all(after(&phrase).as_bytes()).unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    (output, phrase)
}

#[test]
fn setup_offers_a_passphrase_and_a_key_file() {
    let v = Vaulty::new();
    let kf = usb(&v).join("cakepass.key");
    let kf_s = kf.to_str().unwrap().to_string();
    let (out, phrase) = setup_with_passphrase(&v, |p| format!("{p}\ny\n{kf_s}\n"));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    let words = cakepass::generator::wordlist();
    // 7 words from the EFF list (some EFF words contain a dash themselves).
    let mut rest = phrase.as_str();
    for i in 0..7 {
        let w = words
            .iter()
            .filter(|w| rest.starts_with(**w) && (rest.len() == w.len() || rest[w.len()..].starts_with('-')))
            .max_by_key(|w| w.len())
            .unwrap_or_else(|| panic!("word {i} of {phrase:?} is not in the list"));
        rest = rest[w.len()..].strip_prefix('-').unwrap_or("");
    }
    assert!(rest.is_empty(), "more than 7 words: {phrase}");
    for text in [
        "about 90 bits",
        "Write it down on paper NOW",
        "Passphrase confirmed",
        "Key file created",
        "Vault created",
        "no recovery",
        "Saved in your settings",
        "All set!",
    ] {
        assert!(err.contains(text), "{text} missing:\n{err}");
    }
    assert!(!err.contains(&phrase), "the passphrase goes to stdout only");
    assert_eq!(std::fs::read(&kf).unwrap().len(), 64);
    // The vault opens with the passphrase and the key file (from the settings) …
    v.run(&["list"], &format!("{phrase}\n")).success();
    v.run(&["info"], "").success().stdout(contains("required:"));
    // … and not without the key file.
    v.run(&["config", "set", "keyfile", "none"], "").success();
    v.run(&["list"], &format!("{phrase}\n")).failure().stderr(contains("needs its key file"));
}

#[test]
fn a_mistyped_passphrase_creates_nothing() {
    let v = Vaulty::new();
    let (out, _) = setup_with_passphrase(&v, |p| format!("{p}x\n"));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("does not match"));
    assert!(!v.path.exists());
}
