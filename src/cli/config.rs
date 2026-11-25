//! User settings, stored in `~/.config/cakepass/config` (XDG: `$XDG_CONFIG_HOME`).
//!
//! The file is a plain `key=value` list. It contains no secrets, only
//! preferences, and the *path* of your key file (never its contents):
//!
//! ```text
//! # CakePass settings (change them with `cakepass config`)
//! animation=on
//! lock_timeout_minutes=5
//! clip_time_seconds=20
//! hidden_tabs=api,ssh-key
//! keyfile=/run/media/you/USB/cakepass.key
//! ```
//!
//! Parsing is forgiving: unknown lines and invalid
//! values are ignored (the default is used), so a damaged config file can never
//! stop the program from starting.

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Component, Path, PathBuf};

use cakepass::clipboard::{DEFAULT_CLEAR_SECS, parse_clear_secs};
use cakepass::vault::Kind;
use cakepass::{Error, Result, storage};

/// Default idle time before the screen mode and the line mode lock, in minutes.
pub const DEFAULT_LOCK_MINUTES: u64 = 5;
/// Allowed range for the lock timeout, in minutes.
pub const LOCK_MINUTES_RANGE: std::ops::RangeInclusive<u64> = 1..=1440;

/// The user's preferences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Play the 3D logo animation on the login screen.
    pub animation: bool,
    /// Lock the screen mode and the line mode after this many minutes without input.
    pub lock_timeout_minutes: u64,
    /// Clear the clipboard this many seconds after copying a secret (inside
    /// `cakepass::clipboard::CLEAR_SECS_RANGE`).
    pub clip_time_secs: u64,
    /// The types whose tab the screen mode leaves out (in the order of
    /// [`Kind::ALL`], no repeats). Only navigation: the items stay under
    /// "All", and `list`, `search` and `get` never look at this.
    pub hidden_tabs: Vec<Kind>,
    /// Where the key file is, for a vault that needs one (only the path).
    pub keyfile: Option<PathBuf>,
    /// The accent color of the screen mode (pink unless chosen).
    pub colors: Colors,
    /// Own names for type tabs ("Notes" → "Clients"), in the order of
    /// [`Kind::ALL`], each name checked by [`parse_tab_name`].
    pub tab_names: Vec<(Kind, String)>,
    /// Own tabs: each lists the items with a tag of the same name (any
    /// case). At most [`MAX_OWN_TABS`], names checked by [`parse_tab_name`].
    pub own_tabs: Vec<String>,
    /// Whether the screen mode shows the 2FA tab.
    pub two_factor_tab: bool,
}

/// The most own tabs (the tab bar has to hold them).
pub const MAX_OWN_TABS: usize = 6;

/// Parse `own_tabs`: names separated by commas, each checked by
/// [`parse_tab_name`], no repeats (any case), at most [`MAX_OWN_TABS`].
pub fn parse_own_tabs(s: &str) -> Vec<String> {
    let mut tabs: Vec<String> = Vec::new();
    for name in s.split(',').filter_map(parse_tab_name) {
        if tabs.len() < MAX_OWN_TABS && !tabs.iter().any(|t| t.to_lowercase() == name.to_lowercase()) {
            tabs.push(name);
        }
    }
    tabs
}

/// The accent colors of the screen mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Colors {
    #[default]
    Pink,
    Blue,
    Green,
    Purple,
    Orange,
    Red,
    Teal,
}

impl Colors {
    pub const ALL: [Colors; 7] = [
        Colors::Pink,
        Colors::Blue,
        Colors::Green,
        Colors::Purple,
        Colors::Orange,
        Colors::Red,
        Colors::Teal,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Colors::Pink => "pink",
            Colors::Blue => "blue",
            Colors::Green => "green",
            Colors::Purple => "purple",
            Colors::Orange => "orange",
            Colors::Red => "red",
            Colors::Teal => "teal",
        }
    }

    pub fn parse(s: &str) -> Option<Colors> {
        let s = s.trim().to_lowercase();
        Colors::ALL.into_iter().find(|c| c.name() == s)
    }

    /// The next (`1`) or previous (`-1`) one, wrapping around.
    pub fn step(self, delta: isize) -> Colors {
        let n = Colors::ALL.len() as isize;
        let i = Colors::ALL.iter().position(|&c| c == self).unwrap_or(0) as isize;
        Colors::ALL[(i + delta).rem_euclid(n) as usize]
    }
}

/// The longest own tab name (it has to fit in the tab bar).
pub const MAX_TAB_NAME: usize = 16;

/// An own name for a tab: 1 to 16 characters, no control or invisible
/// characters, and none of `,` `:` `=` (the settings file uses them).
/// `None` otherwise.
pub fn parse_tab_name(s: &str) -> Option<String> {
    let s = s.trim();
    let ok = !s.is_empty()
        && s.chars().count() <= MAX_TAB_NAME
        && !s.chars().any(|c| {
            c.is_control()
                || matches!(c, ',' | ':' | '=')
                || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}')
        });
    ok.then(|| s.to_string())
}

/// Parse `tab_names`: `type:name` pairs separated by commas
/// ("note:Clients,api:Tokens"). A pair with an unknown type or a name
/// [`parse_tab_name`] refuses is left out.
pub fn parse_tab_names(s: &str) -> Vec<(Kind, String)> {
    let mut names: Vec<(Kind, String)> = Vec::new();
    for pair in s.split(',') {
        let Some((kind, name)) = pair.split_once(':') else { continue };
        if let (Some(kind), Some(name)) = (Kind::parse(kind.trim()), parse_tab_name(name))
            && !names.iter().any(|(k, _)| *k == kind)
        {
            names.push((kind, name));
        }
    }
    names.sort_by_key(|(k, _)| Kind::ALL.iter().position(|a| a == k));
    names
}

impl Default for Config {
    fn default() -> Self {
        Config {
            animation: true,
            lock_timeout_minutes: DEFAULT_LOCK_MINUTES,
            clip_time_secs: DEFAULT_CLEAR_SECS,
            hidden_tabs: Vec::new(),
            keyfile: None,
            colors: Colors::Pink,
            tab_names: Vec::new(),
            own_tabs: Vec::new(),
            two_factor_tab: true,
        }
    }
}

/// The name of a type in the settings file and on the command line: the
/// same names `--type` accepts.
pub fn type_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Login => "login",
        Kind::Api => "api",
        Kind::Card => "card",
        Kind::Identity => "identity",
        Kind::SshKey => "ssh-key",
        Kind::Note => "note",
    }
}

/// Parse a list of hidden tabs: type names separated by commas ("api,
/// ssh-key"; any name `--type` accepts), or nothing / "none" for none. The
/// result is in the order of the tabs, without repeats. `None` if a name is
/// not a type, which includes "all": the All tab cannot be hidden.
pub fn parse_hidden_tabs(s: &str) -> Option<Vec<Kind>> {
    let s = s.trim();
    let mut kinds = Vec::new();
    if !s.eq_ignore_ascii_case("none") {
        for name in s.split(',').map(str::trim).filter(|n| !n.is_empty()) {
            kinds.push(Kind::parse(name)?);
        }
    }
    Some(Kind::ALL.into_iter().filter(|k| kinds.contains(k)).collect())
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

/// A key-file path as stored in the settings: absolute, without `..`, and
/// without control characters (the file is line-based). `None` otherwise.
pub fn parse_keyfile_path(s: &str) -> Option<PathBuf> {
    let s = s.trim();
    let p = PathBuf::from(s);
    let ok = p.is_absolute()
        && !s.chars().any(char::is_control)
        && !p.components().any(|c| c == Component::ParentDir);
    ok.then_some(p)
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
                "clip_time_seconds" => {
                    if let Some(s) = parse_clear_secs(value) {
                        cfg.clip_time_secs = s;
                    }
                }
                "hidden_tabs" => {
                    if let Some(kinds) = parse_hidden_tabs(value) {
                        cfg.hidden_tabs = kinds;
                    }
                }
                "keyfile" => cfg.keyfile = parse_keyfile_path(value),
                "colors" => cfg.colors = Colors::parse(value).unwrap_or_default(),
                "tab_names" => cfg.tab_names = parse_tab_names(value),
                "own_tabs" => cfg.own_tabs = parse_own_tabs(value),
                "two_factor_tab" => cfg.two_factor_tab = parse_on_off(value).unwrap_or(true),
                _ => {}
            }
        }
        cfg
    }

    /// The text to write to a config file.
    pub fn to_text(&self) -> String {
        let mut text = format!(
            "# CakePass settings (change them with `cakepass config`)\nanimation={}\nlock_timeout_minutes={}\nclip_time_seconds={}\n",
            if self.animation { "on" } else { "off" },
            self.lock_timeout_minutes,
            self.clip_time_secs
        );
        // Like the key file: no line while nothing is hidden.
        if !self.hidden_tabs.is_empty() {
            text.push_str(&format!("hidden_tabs={}\n", self.hidden_tabs_text(",")));
        }
        if self.colors != Colors::Pink {
            text.push_str(&format!("colors={}\n", self.colors.name()));
        }
        // Only names that read back the same are written.
        let names: Vec<String> = self
            .tab_names
            .iter()
            .filter(|(_, n)| parse_tab_name(n).as_deref() == Some(n.as_str()))
            .map(|(k, n)| format!("{}:{n}", type_name(*k)))
            .collect();
        if !names.is_empty() {
            text.push_str(&format!("tab_names={}\n", names.join(",")));
        }
        let own: Vec<&str> = self
            .own_tabs
            .iter()
            .filter(|n| parse_tab_name(n).as_deref() == Some(n.as_str()))
            .map(String::as_str)
            .take(MAX_OWN_TABS)
            .collect();
        if !own.is_empty() {
            text.push_str(&format!("own_tabs={}\n", own.join(",")));
        }
        if !self.two_factor_tab {
            text.push_str("two_factor_tab=off\n");
        }
        // Only a path that reads back the same is written (see `parse_keyfile_path`).
        if let Some(p) =
            self.keyfile.as_ref().and_then(|p| p.to_str()).filter(|p| parse_keyfile_path(p).is_some())
        {
            text.push_str(&format!("keyfile={p}\n"));
        }
        text
    }

    /// The hidden tabs as type names joined by `sep` (empty if none).
    pub fn hidden_tabs_text(&self, sep: &str) -> String {
        self.hidden_tabs.iter().map(|&k| type_name(k)).collect::<Vec<_>>().join(sep)
    }

    /// The own name of a type's tab, if one was given.
    pub fn tab_name(&self, kind: Kind) -> Option<&str> {
        self.tab_names.iter().find(|(k, _)| *k == kind).map(|(_, n)| n.as_str())
    }

    /// Give a type's tab its own name, or its usual one back (`None`).
    pub fn set_tab_name(&mut self, kind: Kind, name: Option<String>) {
        self.tab_names.retain(|(k, _)| *k != kind);
        if let Some(name) = name {
            self.tab_names.push((kind, name));
            self.tab_names.sort_by_key(|(k, _)| Kind::ALL.iter().position(|a| a == k));
        }
    }

    /// Whether the screen mode shows the tab of this type.
    pub fn shows_tab(&self, kind: Kind) -> bool {
        !self.hidden_tabs.contains(&kind)
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
    fn colors_and_tab_names_read_back() {
        let mut c = Config { colors: Colors::Teal, ..Config::default() };
        c.set_tab_name(Kind::Note, Some("Clients".into()));
        c.set_tab_name(Kind::Login, Some("Websites".into()));
        let text = c.to_text();
        assert!(text.contains("colors=teal\ntab_names=login:Websites,note:Clients\n"), "{text}");
        assert_eq!(Config::parse(&text), c);
        c.set_tab_name(Kind::Note, None);
        assert_eq!(c.tab_name(Kind::Note), None);
        assert_eq!(c.tab_name(Kind::Login), Some("Websites"));
        // Pink and no names: no lines at all (files of older versions stay the same).
        assert!(
            !Config::default().to_text().contains("colors")
                && !Config::default().to_text().contains("tab_names")
        );
    }

    #[test]
    fn own_tabs_and_the_2fa_tab_read_back() {
        let c = Config::parse("own_tabs=Klanten, werk ,KLANTEN,a:b,,Thuis,5,6,7,8,9\ntwo_factor_tab=off\n");
        assert_eq!(c.own_tabs, ["Klanten", "werk", "Thuis", "5", "6", "7"], "no repeats, at most 6");
        assert!(!c.two_factor_tab);
        assert_eq!(Config::parse(&c.to_text()), c);
        let d = Config::default();
        assert!(d.two_factor_tab && !d.to_text().contains("own_tabs") && !d.to_text().contains("two_factor"));
        assert!(Config::parse("two_factor_tab=maybe").two_factor_tab, "unreadable: shown");
    }

    #[test]
    fn bad_colors_and_tab_names_are_ignored() {
        let c = Config::parse(
            "colors=rainbow\ntab_names=note:Clients,bogus:X,api:,card:a=b,login:\u{202E}evil,ssh-key:Way too long a tab name,note:Twice\n",
        );
        assert_eq!(c.colors, Colors::Pink);
        assert_eq!(c.tab_names, vec![(Kind::Note, "Clients".to_string())]);
        for bad in ["", "   ", "a,b", "a:b", "a=b", "tab\x1b[31m", "\u{200B}", "12345678901234567"] {
            assert_eq!(parse_tab_name(bad), None, "{bad:?}");
        }
        assert_eq!(parse_tab_name(" Klanten "), Some("Klanten".into()));
        assert_eq!(parse_tab_name("Café 2FA ✓").as_deref(), Some("Café 2FA ✓"));
        assert_eq!(Colors::Pink.step(-1), Colors::Teal);
        assert_eq!(Colors::Teal.step(1), Colors::Pink);
    }

    #[test]
    fn defaults() {
        let c = Config::default();
        assert!(c.animation);
        assert_eq!(c.lock_timeout_minutes, 5);
        assert_eq!(c.lock_timeout_secs(), 300);
        assert_eq!(c.clip_time_secs, 20);
        assert_eq!(Config::parse(""), c);
    }

    #[test]
    fn parses_valid_values() {
        let c = Config::parse("# comment\nanimation=off\nlock_timeout_minutes=15\nclip_time_seconds=45\n");
        assert!(!c.animation);
        assert_eq!(c.lock_timeout_minutes, 15);
        assert_eq!(c.clip_time_secs, 45);
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
            "clip_time_seconds=0",
            "clip_time_seconds=4",
            "clip_time_seconds=301",
            "clip_time_seconds=never",
            "hidden_tabs=all",
            "hidden_tabs=api,all",
            "hidden_tabs=api,nonsense",
            "hidden_tabs=none",
            "hidden_tabs=",
            "unknown=1\n\x1b[2J\nnonsense",
        ] {
            assert_eq!(Config::parse(text), Config::default(), "{text:?}");
        }
        // A bad value does not spoil the good ones around it.
        let c = Config::parse("animation=off\nlock_timeout_minutes=oops\n");
        assert!(!c.animation && c.lock_timeout_minutes == 5);
    }

    #[test]
    fn hidden_tab_lists() {
        use Kind::*;
        assert_eq!(parse_hidden_tabs("api,ssh-key"), Some(vec![Api, SshKey]));
        // Any name `--type` takes; spaces, case, order and repeats do not matter.
        assert_eq!(parse_hidden_tabs(" Note , SSH, api-key,note,"), Some(vec![Api, SshKey, Note]));
        assert_eq!(parse_hidden_tabs("passport,card"), Some(vec![Card, Identity]));
        for none in ["", "  ", "none", "NONE", ","] {
            assert_eq!(parse_hidden_tabs(none), Some(vec![]), "{none:?}");
        }
        // "All" is not a type, so it can never be hidden.
        for bad in ["all", "api,all", "api;card", "logins2"] {
            assert_eq!(parse_hidden_tabs(bad), None, "{bad:?}");
        }
        // Every type name reads back as itself.
        for k in Kind::ALL {
            assert_eq!(parse_hidden_tabs(type_name(k)), Some(vec![k]));
        }
        let c = Config::parse("hidden_tabs=note,api\n");
        assert_eq!(c.hidden_tabs, [Api, Note]);
        assert!(!c.shows_tab(Api) && c.shows_tab(Login));
        assert_eq!(c.hidden_tabs_text(", "), "api, note");
        // Nothing hidden: no line in the file.
        assert!(!Config::default().to_text().contains("hidden_tabs"));
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
        let cfg = Config {
            animation: false,
            lock_timeout_minutes: 42,
            clip_time_secs: 90,
            hidden_tabs: vec![Kind::Api, Kind::SshKey],
            keyfile: None,
            colors: Colors::Purple,
            tab_names: vec![(Kind::Note, "Clients".into())],
            own_tabs: vec!["Klanten".into(), "Werk".into()],
            two_factor_tab: false,
        };
        save_to(&path, &cfg).unwrap();
        assert_eq!(load_from(&path), cfg);
        assert!(fs::read_to_string(&path).unwrap().contains("\nhidden_tabs=api,ssh-key\n"));
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777, 0o700);
        assert!(fs::read_to_string(&path).unwrap().starts_with("# CakePass settings"));
    }

    #[test]
    fn keyfile_path_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        let cfg = Config {
            keyfile: Some(PathBuf::from("/run/media/me/USB stick/cakepass.key")),
            ..Config::default()
        };
        save_to(&path, &cfg).unwrap();
        assert_eq!(load_from(&path), cfg);
        assert!(
            fs::read_to_string(&path).unwrap().contains("keyfile=/run/media/me/USB stick/cakepass.key\n")
        );
        // Without a key file there is no line for it.
        assert!(!Config::default().to_text().contains("keyfile"));
    }

    #[test]
    fn bad_keyfile_paths_are_ignored() {
        for bad in ["keyfile=relative/path", "keyfile=", "keyfile=/a/../b", "keyfile=/x\u{1b}[2J"] {
            assert_eq!(Config::parse(bad).keyfile, None, "{bad:?}");
        }
        assert_eq!(Config::parse("keyfile= /k ").keyfile, Some(PathBuf::from("/k")));
        // A path that would not read back is never written.
        let odd = Config { keyfile: Some(PathBuf::from("/a\nanimation=off")), ..Config::default() };
        assert_eq!(Config::parse(&odd.to_text()), Config::default());
    }
}
