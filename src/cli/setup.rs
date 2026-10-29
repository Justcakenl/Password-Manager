//! First-time setup (`cakepass setup`) and the `cakepass config` command.
//!
//! The setup wizard asks three things, in this order:
//!
//! 1. whether to play the 3D logo animation at startup,
//! 2. after how many minutes of inactivity the interactive mode locks,
//! 3. the master password (only when there is no vault yet).
//!
//! It also works without a terminal: the answers are then read from stdin,
//! one per line (handy for scripts and tests).

use std::fs;

use cakepass::storage::{UnlockedVault, VaultPaths};
use cakepass::{Error, Result};

use super::args::{ConfigAction, ConfigKey, KdfArgs};
use super::config::{self, Config, LOCK_MINUTES_RANGE};
use super::{commands, logo, prompt, ui};

const TAGLINE: &str = "welcome! let's set things up";

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

/// The first-time setup wizard (`cakepass setup`).
pub fn run(paths: &VaultPaths, kdf_args: &KdfArgs) -> Result<()> {
    wizard(paths, kdf_args).map(drop)
}

/// The wizard itself. Returns the new vault, still unlocked, when it created
/// one (so the caller can use it right away without asking again).
pub fn wizard(paths: &VaultPaths, kdf_args: &KdfArgs) -> Result<Option<UnlockedVault>> {
    let kdf = commands::kdf_from_args(kdf_args)?;
    let have_vault = fs::symlink_metadata(&paths.file).is_ok();
    let mut cfg = config::load();

    logo::show(true);
    logo::tagline(TAGLINE);

    ui::info(&ui::pink_bold("Step 1 of 3 — Startup animation"));
    ui::info("  CakePass can play a short 3D logo animation when it starts (color terminals only).");
    cfg.animation = prompt::ask_yes_no("  Play the animation at startup?", cfg.animation)?;
    logo::set_animation(cfg.animation);

    ui::info(&ui::pink_bold("\nStep 2 of 3 — Auto-lock"));
    ui::info(
        "  The interactive mode (`cakepass`) locks itself and wipes your secrets from memory when idle.",
    );
    cfg.lock_timeout_minutes = ask_minutes(cfg.lock_timeout_minutes)?;

    config::save(&cfg)?;
    ui::success("Settings saved.");

    ui::info(&ui::pink_bold("\nStep 3 of 3 — Master password"));
    let created = if have_vault {
        ui::info(&format!(
            "  A vault already exists at {}; keeping it as it is.\n  \
             (Change its master password with `cakepass passwd`.)",
            paths.file.display()
        ));
        None
    } else {
        Some(commands::create_vault(paths, kdf)?)
    };

    ui::success("All set!");
    ui::info("  Start CakePass:      cakepass");
    ui::info("  Add something:       cakepass add GitHub   (or --type api, --type note)");
    ui::info("  Change settings:     cakepass config");
    ui::info("  Update later:        cakepass --update");
    if !have_vault {
        ui::info("  Make regular copies of the vault file (see the README, \"Backups\").");
    }
    Ok(created)
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
            }
            config::save(&cfg)?;
            ui::success("Setting saved.");
            show(&cfg);
            Ok(())
        }
    }
}

fn show(cfg: &Config) {
    println!("{}", ui::bold("CakePass settings"));
    println!("  animation:     {}", if cfg.animation { "on" } else { "off" });
    println!("  lock-timeout:  {} minute(s)", cfg.lock_timeout_minutes);
    println!("  file:          {}", config::path().map_or("-".to_string(), |p| p.display().to_string()));
    ui::info("Change with: cakepass config set animation off   |   cakepass config set lock-timeout 10");
}
