//! User settings, stored in `~/.config/cakepass/config` (XDG: `$XDG_CONFIG_HOME`).
//!
//! The file is a plain `key=value` list. It contains no secrets, only
//! preferences:
//!
//! ```text
//! # CakePass settings (change them with `cakepass config`)
//! animation=on
//! lock_timeout_minutes=5
//! ```
//!
//! Parsing is forgiving: unknown lines and invalid
//! values are ignored (the default is used), so a damaged config file can never
//! stop the program from starting.

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use cakepass::{Error, Result, storage};

/// Default idle time before the interactive mode locks, in minutes.
pub const DEFAULT_LOCK_MINUTES: u64 = 5;
/// Allowed range for the lock timeout, in minutes.
pub const LOCK_MINUTES_RANGE: std::ops::RangeInclusive<u64> = 1..=1440;

/// The user's preferences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Play the 3D logo animation on the login screen.
    pub animation: bool,
    /// Lock the interactive mode after this many minutes without input.
    pub lock_timeout_minutes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config { animation: true, lock_timeout_minutes: DEFAULT_LOCK_MINUTES }
    }
}

/// Parse an on/off value ("on", "off", "true", "false", "yes", "no", "1", "0").
pub fn parse_on_off(s: &str) -> Option<bool> {
    match s.trim().to_lowercase().as_str() {
        "on" | "true" | "yes" | "y" | "1" => Some(true),
        "off" | "false" | "no" | "n" | "0" => Some(false),
        _ => None,
    }
}

/// Parse a lock timeout in minutes (must be inside [`LOCK_MINUTES_RANGE`]).
pub fn parse_lock_minutes(s: &str) -> Option<u64> {
    s.trim().parse::<u64>().ok().filter(|m| LOCK_MINUTES_RANGE.contains(m))
}

impl Config {
    /// Parse the text of a config file; anything invalid keeps its default.
    pub fn parse(text: &str) -> Config {
        let mut cfg = Config::default();
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else { continue };
            match key.trim() {
                "animation" => {
                    if let Some(on) = parse_on_off(value) {
                        cfg.animation = on;
                    }
                }
                "lock_timeout_minutes" => {
                    if let Some(m) = parse_lock_minutes(value) {
                        cfg.lock_timeout_minutes = m;
                    }
                }
                _ => {}
            }
        }
        cfg
    }

    /// The text to write to a config file.
    pub fn to_text(&self) -> String {
        format!(
            "# CakePass settings (change them with `cakepass config`)\nanimation={}\nlock_timeout_minutes={}\n",
            if self.animation { "on" } else { "off" },
            self.lock_timeout_minutes
        )
    }

    /// The lock timeout in seconds.
    pub fn lock_timeout_secs(&self) -> u64 {
        self.lock_timeout_minutes * 60
    }
}

/// Where the config file lives (`None` if there is no home directory).
pub fn path() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
        Some(p) if p.is_absolute() => p,
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".config"),
    };
    Some(storage::app_dir(&base).join("config"))
}

/// Load the settings from `path` (defaults if missing or unreadable).
pub fn load_from(path: &Path) -> Config {
    fs::read_to_string(path).map(|t| Config::parse(&t)).unwrap_or_default()
}

/// Load the settings from the standard location.
pub fn load() -> Config {
    path().map(|p| load_from(&p)).unwrap_or_default()
}

/// Save the settings to `path` (atomically, permissions 0600).
pub fn save_to(path: &Path, cfg: &Config) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    storage::write_atomic(path, cfg.to_text().as_bytes())
}

/// Save the settings to the standard location.
pub fn save(cfg: &Config) -> Result<()> {
    let path = path().ok_or_else(|| Error::InvalidInput("HOME is not set; cannot save settings".into()))?;
    save_to(&path, cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn defaults() {
        let c = Config::default();
        assert!(c.animation);
        assert_eq!(c.lock_timeout_minutes, 5);
        assert_eq!(c.lock_timeout_secs(), 300);
        assert_eq!(Config::parse(""), c);
    }

    #[test]
    fn parses_valid_values() {
        let c = Config::parse("# comment\nanimation=off\nlock_timeout_minutes=15\n");
        assert!(!c.animation);
        assert_eq!(c.lock_timeout_minutes, 15);
        assert!(!Config::parse(" animation = off ").animation, "spaces around = are fine");
    }

    #[test]
    fn ignores_invalid_values_and_unknown_keys() {
        for text in [
            "animation=maybe",
            "lock_timeout_minutes=0",
            "lock_timeout_minutes=99999",
            "lock_timeout_minutes=abc",
            "lock_timeout_minutes=-5",
            "unknown=1\n\x1b[2J\nnonsense",
        ] {
            assert_eq!(Config::parse(text), Config::default(), "{text:?}");
        }
        // A bad value does not spoil the good ones around it.
        let c = Config::parse("animation=off\nlock_timeout_minutes=oops\n");
        assert!(!c.animation && c.lock_timeout_minutes == 5);
    }

    #[test]
    fn on_off_words() {
        for on in ["on", "ON", "true", "yes", "1"] {
            assert_eq!(parse_on_off(on), Some(true));
        }
        for off in ["off", "Off", "false", "no", "0"] {
            assert_eq!(parse_on_off(off), Some(false));
        }
        assert_eq!(parse_on_off("sometimes"), None);
        assert_eq!(parse_lock_minutes("10"), Some(10));
        assert_eq!(parse_lock_minutes("0"), None);
        assert_eq!(parse_lock_minutes("1441"), None);
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("config");
        assert_eq!(load_from(&path), Config::default(), "missing file gives defaults");
        let cfg = Config { animation: false, lock_timeout_minutes: 42 };
        save_to(&path, &cfg).unwrap();
        assert_eq!(load_from(&path), cfg);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777, 0o700);
        assert!(fs::read_to_string(&path).unwrap().starts_with("# CakePass settings"));
    }
}
