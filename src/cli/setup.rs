//! First-time setup (`cakepass setup`) and the `cakepass config` command.
//!
//! The setup wizard asks, in this order:
//!
//! 1. whether to play the 3D logo animation at startup,
//! 2. after how many minutes of inactivity CakePass locks,
//! 3. the security level (how much memory Argon2id uses; skipped when
//!    `--level` or `--kdf-*` was given), with the unlock time measured on
//!    this computer once a level is chosen,
//! 4. the master password: CakePass offers to make a 7-word passphrase
//!    (shown once, then typed back), or you type your own,
//! 5. optionally a key file (a second secret, e.g. on a USB stick).
//!
//! Steps 3–5 only happen when there is no vault yet. Everything is asked
//! first; the vault is created at the end (one Argon2 run).
//!
//! It also works without a terminal: the answers are then read from stdin,
//! one per line (handy for scripts and tests).

use std::fs;
use std::path::{Path, PathBuf};

use secrecy::SecretString;

use cakepass::crypto::{self, KdfParams, MemoryUse, SecurityLevel};
use cakepass::generator::{self, PassphraseOptions};
use cakepass::keyfile::{self, LoadedKeyFile};
use cakepass::storage::{UnlockedVault, VaultPaths};
use cakepass::{Error, Result};

use super::args::{ConfigAction, ConfigKey, KdfArgs};
use super::config::{self, Config, LOCK_MINUTES_RANGE};
use super::{commands, logo, prompt, ui};

const TAGLINE: &str = "welcome! let's set things up";
/// Words in the passphrase the wizard offers (7 × 12.9 ≈ 90 bits).
const PASSPHRASE_WORDS: usize = 7;

/// Ask for a number of minutes; empty input keeps `default`.
fn ask_minutes(default: u64) -> Result<u64> {
    let answer = prompt::line(&format!("  Lock after how many minutes of inactivity? [{default}] "))?;
    if answer.is_empty() {
        return Ok(default);
    }
    config::parse_lock_minutes(&answer).ok_or_else(|| {
        Error::InvalidInput(format!(
            "enter a whole number of minutes between {} and {}",
            LOCK_MINUTES_RANGE.start(),
            LOCK_MINUTES_RANGE.end()
        ))
    })
}

/// How many times to ask again after a bad answer: in a terminal a few
/// times, from a script once (a script cannot correct itself).
fn tries() -> usize {
    if prompt::stdin_is_tty() { 3 } else { 1 }
}

/// The first-time setup wizard (`cakepass setup`).
pub fn run(paths: &VaultPaths, kdf_args: &KdfArgs) -> Result<()> {
    wizard(paths, kdf_args).map(drop)
}

/// The wizard itself. Returns the new vault, still unlocked, when it created
/// one (so `cakepass` can open it right away without asking again).
pub fn wizard(paths: &VaultPaths, kdf_args: &KdfArgs) -> Result<Option<UnlockedVault>> {
    // Bad flags fail before any question.
    let kdf_from_flags = commands::kdf_from_args(kdf_args)?;
    let have_vault = fs::symlink_metadata(&paths.file).is_ok();
    let steps = if have_vault { 3 } else { 5 };
    let mut cfg = config::load();

    logo::show(true);
    logo::tagline(TAGLINE);

    ui::info(&ui::pink_bold(&format!("Step 1 of {steps} — Startup animation")));
    ui::info("  CakePass can play a short 3D logo animation when it starts (color terminals only).");
    cfg.animation = prompt::ask_yes_no("  Play the animation at startup?", cfg.animation)?;
    logo::set_animation(cfg.animation);

    ui::info(&ui::pink_bold(&format!("\nStep 2 of {steps} — Auto-lock")));
    ui::info(
        "  CakePass (`cakepass`, `cakepass shell`) locks itself and wipes your secrets from memory when idle.",
    );
    cfg.lock_timeout_minutes = ask_minutes(cfg.lock_timeout_minutes)?;

    config::save(&cfg)?;
    ui::success("Settings saved.");

    if have_vault {
        ui::info(&ui::pink_bold("\nStep 3 of 3 — Your vault"));
        ui::info(&format!(
            "  A vault already exists at {}; keeping it as it is.\n  \
             (Change its master password with `cakepass passwd`, its security level or key file\n  \
             with `cakepass security`.)",
            paths.file.display()
        ));
        finish(false);
        return Ok(None);
    }

    ui::info(&ui::pink_bold("\nStep 3 of 5 — Security level"));
    let kdf = if kdf_args.is_explicit() {
        ui::info(&format!("  Using the settings from the command line: {}.", kdf_from_flags.describe()));
        commands::warn_if_weak_kdf(&kdf_from_flags);
        crypto::ensure_memory(&kdf_from_flags, MemoryUse::Create)?;
        kdf_from_flags
    } else {
        ask_level()?
    };

    ui::info(&ui::pink_bold("\nStep 4 of 5 — Master password"));
    commands::print_new_vault_banner();
    let pw = ask_master_password()?;

    ui::info(&ui::pink_bold("\nStep 5 of 5 — Extra protection: a key file (optional)"));
    let key_file = key_file_step(paths)?;
    let (kf_path, kf): (Option<PathBuf>, Option<LoadedKeyFile>) = match key_file {
        Some((p, k)) => (Some(p), Some(k)),
        None => (None, None),
    };

    let uv = commands::create_vault(paths, kdf, &pw, &kf)?;
    drop(pw);
    drop(kf);
    if let Some(p) = &kf_path {
        commands::remember_key_file(p, None);
        commands::key_file_loss_warning();
    }
    finish(true);
    Ok(Some(uv))
}

fn finish(created: bool) {
    ui::success("All set!");
    ui::info("  Start CakePass:      cakepass   (arrow keys; `cakepass shell` for typed commands)");
    ui::info("  Add something:       cakepass add GitHub   (or --type api, --type note)");
    ui::info("  Change settings:     cakepass config");
    ui::info("  Security:            cakepass security   (level, key file, unlock time)");
    ui::info("  Update later:        cakepass --update");
    if created {
        ui::info("  Make regular copies of the vault file (see the README, \"Backups\").");
    }
}

/// A short, plain description of a level for the menu.
fn level_blurb(level: SecurityLevel) -> String {
    let need = level.min_available_mib();
    match level {
        SecurityLevel::Standard => {
            format!("works on any computer; unlocks fastest (64 MiB; needs ~{need} MiB free)")
        }
        SecurityLevel::High => format!("about 1 s to unlock; needs ~{need} MiB free memory (256 MiB)"),
        SecurityLevel::Maximum => format!("about 3-5 s to unlock; needs ~{need} MiB free memory (1 GiB)"),
    }
}

/// Step 3: choose a level; then measure it on this computer.
fn ask_level() -> Result<KdfParams> {
    ui::info("  How expensive should guessing your master password be for someone who steals the");
    ui::info("  vault file? More memory makes every guess cost more, and unlocking a bit slower.");
    for (i, l) in SecurityLevel::ALL.iter().enumerate() {
        ui::info(&format!("    {}  {:<19} {}", i + 1, l.title(), level_blurb(*l)));
    }
    let mut last = Error::InvalidInput("choose 1, 2 or 3".into());
    for _ in 0..tries() {
        let answer = prompt::line("  Choose 1, 2 or 3 [2]: ")?;
        let level = match answer.trim() {
            "" => SecurityLevel::DEFAULT,
            "1" => SecurityLevel::Standard,
            "2" => SecurityLevel::High,
            "3" => SecurityLevel::Maximum,
            other => match SecurityLevel::parse(other) {
                Some(l) => l,
                None => {
                    ui::warn("Type 1, 2 or 3 (or press Enter for 2).");
                    last = Error::InvalidInput("choose 1, 2 or 3".into());
                    continue;
                }
            },
        };
        // Never run what this computer cannot spare: say so and ask again.
        if let Err(e) = crypto::ensure_memory(&level.params(), MemoryUse::Create) {
            ui::warn(&e.to_string());
            last = e;
            continue;
        }
        ui::info("  Measuring on this computer…");
        match crypto::measure_unlock(&level.params()) {
            Ok(d) => ui::success(&format!(
                "{}: unlocking takes about {} on this computer.",
                level.title(),
                commands::seconds(d)
            )),
            Err(e) => ui::warn(&format!("Could not measure the unlock time: {e}")),
        }
        return Ok(level.params());
    }
    Err(last)
}

/// Step 4: a generated passphrase (offered first) or your own password.
fn ask_master_password() -> Result<SecretString> {
    ui::info("  A passphrase of random words is very strong and still easy to type.");
    if prompt::ask_yes_no("  Make a strong passphrase for me?", true)? {
        generated_passphrase()
    } else {
        prompt::new_strong_password("master password")
    }
}

/// Make a 7-word passphrase, show it once, and have it typed back.
fn generated_passphrase() -> Result<SecretString> {
    let opts = PassphraseOptions { words: PASSPHRASE_WORDS, separator: "-".into() };
    let phrase = generator::generate_passphrase(&opts)?;
    ui::info(&format!(
        "  Your master password ({PASSPHRASE_WORDS} random words, about {:.0} bits):",
        opts.entropy_bits()
    ));
    ui::print_secret_line("\n      ", &phrase)?;
    eprintln!();
    ui::warn(
        "Write it down on paper NOW, exactly as shown (with the dashes), and keep the paper somewhere \
         safe. It is shown only this once, and nobody can recover it for you.",
    );
    let tty = prompt::stdin_is_tty();
    for _ in 0..tries() {
        let again = prompt::secret("  Type it again to confirm: ")?;
        if prompt::secrets_equal(&again, &SecretString::from(phrase.to_string())) {
            if tty {
                // Take the passphrase off the screen (and out of the scrollback).
                ui::clear_screen();
                ui::success(
                    "Passphrase confirmed. It has been cleared from the screen; keep your paper safe.",
                );
            } else {
                ui::success("Passphrase confirmed.");
            }
            return Ok(SecretString::from(phrase.to_string()));
        }
        ui::warn("That does not match. Check what you wrote down (words joined by '-') and try again.");
    }
    Err(Error::InvalidInput("the passphrase was not typed back correctly; no vault was created".into()))
}

/// Step 5: optionally create a key file (or use the one given with --keyfile).
fn key_file_step(paths: &VaultPaths) -> Result<Option<(PathBuf, LoadedKeyFile)>> {
    if let Some(p) = commands::explicit_key_file() {
        ui::info(&format!(
            "  Using the key file {} (given with --keyfile or CAKEPASS_KEYFILE).",
            p.display()
        ));
        let loaded = commands::load_new_key_file(&p, paths)?;
        return Ok(Some((p, loaded)));
    }
    ui::info("  A key file is a small file with random data, for example on a USB stick. With one,");
    ui::info("  your vault opens only with the master password AND the key file: a stolen vault");
    ui::info("  file is useless without it, even if someone learns or guesses your password.");
    ui::info("  But if you lose the key file (and its copies), the vault is lost for good.");
    if !prompt::ask_yes_no("  Create a key file?", false)? {
        ui::info("  No key file. (Add one later with `cakepass security --new-keyfile PATH`.)");
        return Ok(None);
    }
    let mut last = Error::InvalidInput("no key file was created".into());
    for _ in 0..tries() {
        let answer = prompt::line("  Where should it go? (e.g. /run/media/you/USB/cakepass.key): ")?;
        if answer.is_empty() {
            ui::info("  No key file.");
            return Ok(None);
        }
        let path = commands::absolute_path(Path::new(&answer));
        match keyfile::create(&path) {
            Ok(warnings) => {
                ui::success(&format!("Key file created: {}", path.display()));
                for w in warnings {
                    ui::warn(&w);
                }
                let loaded = commands::load_new_key_file(&path, paths)?;
                return Ok(Some((path, loaded)));
            }
            Err(Error::AlreadyExists(p)) => {
                ui::warn(&format!(
                    "There is already a file at {}; CakePass never overwrites files. Choose another name.",
                    p.display()
                ));
                last = Error::AlreadyExists(p);
            }
            Err(e) => {
                ui::warn(&e.to_string());
                last = e;
            }
        }
    }
    Err(last)
}

/// `cakepass config` (show) and `cakepass config set <key> <value>`.
pub fn config_command(action: Option<ConfigAction>) -> Result<()> {
    match action {
        None | Some(ConfigAction::Show) => {
            show(&config::load());
            Ok(())
        }
        Some(ConfigAction::Set { key, value }) => {
            let mut cfg = config::load();
            match key {
                ConfigKey::Animation => {
                    cfg.animation = config::parse_on_off(&value)
                        .ok_or_else(|| Error::InvalidInput("animation must be 'on' or 'off'".into()))?;
                }
                ConfigKey::LockTimeout => {
                    cfg.lock_timeout_minutes = config::parse_lock_minutes(&value).ok_or_else(|| {
                        Error::InvalidInput(format!(
                            "lock-timeout must be a whole number of minutes between {} and {}",
                            LOCK_MINUTES_RANGE.start(),
                            LOCK_MINUTES_RANGE.end()
                        ))
                    })?;
                }
                ConfigKey::Keyfile => cfg.keyfile = keyfile_setting(&value)?,
            }
            config::save(&cfg)?;
            if key == ConfigKey::Keyfile {
                // Also for the rest of this process (`cakepass shell`).
                commands::set_configured_key_file(cfg.keyfile.clone());
            }
            ui::success("Setting saved.");
            show(&cfg);
            Ok(())
        }
    }
}

/// The value of `config set keyfile`: a path (made absolute) or `none`.
fn keyfile_setting(value: &str) -> Result<Option<PathBuf>> {
    let value = value.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    let path = commands::absolute_path(Path::new(value));
    let stored = path.to_str().and_then(config::parse_keyfile_path).ok_or_else(|| {
        Error::InvalidInput(
            "the key file path must be plain text without control characters or '..'; or use 'none'".into(),
        )
    })?;
    if fs::symlink_metadata(&stored).is_err() {
        ui::warn(&format!(
            "There is no file at {} right now. That is fine if it is on a USB stick that is not plugged in.",
            stored.display()
        ));
    }
    Ok(Some(stored))
}

fn show(cfg: &Config) {
    println!("{}", ui::bold("CakePass settings"));
    println!("  animation:     {}", if cfg.animation { "on" } else { "off" });
    println!("  lock-timeout:  {} minute(s)", cfg.lock_timeout_minutes);
    println!(
        "  keyfile:       {}",
        cfg.keyfile.as_ref().map_or("none".to_string(), |p| p.display().to_string())
    );
    println!("  file:          {}", config::path().map_or("-".to_string(), |p| p.display().to_string()));
    ui::info("Change with: cakepass config set animation off   |   cakepass config set lock-timeout 10");
    ui::info("             cakepass config set keyfile /path/to/cakepass.key   (or: none)");
}
