//! The settings screen: the startup animation, the auto-lock time, changing
//! the master password, the security level, and information about the vault
//! and this version (like `cakepass info`). Changes are saved right away
//! with `config`.
//!
//! SECURITY: changing the master password first asks for the current one
//! again (as `passwd` in `cakepass shell` does), then a new one that passes
//! the same strength check as everywhere else, typed twice. Switching the
//! security level (← → choose, Enter apply) asks for the current master
//! password too, and refuses a level this computer lacks the memory for.
//! The unlock time of a level is measured on this computer the first time
//! the level is shown (not when the program starts).

use std::time::{Duration, Instant};

use cakepass::Error;
use cakepass::crypto::{KdfParams, SecurityLevel};

use super::super::super::commands;
use super::super::super::config::{self, Config, LOCK_MINUTES_RANGE};
use super::super::super::update;
use super::super::app::{App, Modal, Screen, error_text, level_index};
use super::super::grid::{Grid, Rect, str_width};
use super::super::keys::{Event, Key};
use super::super::theme::Style;
use super::dialog::{Help, HelpPage, Prompt, PromptPurpose};
use super::{Hint, field_row, title_bar};

pub struct Settings {
    pub row: usize,
    /// The level chosen on the security row (applied only with Enter).
    pub level: SecurityLevel,
    /// Looked up once when the screen opens (no need to search PATH every frame).
    clipboard: Option<&'static str>,
    update: Option<String>,
}

const ROWS: usize = 4;
/// The row of the security level.
pub const LEVEL_ROW: usize = 3;

impl Settings {
    /// The screen as it opens (the cursor on the first setting). The level
    /// row starts at the vault's level (High for custom settings).
    pub fn load(current: KdfParams) -> Settings {
        Settings {
            row: 0,
            level: SecurityLevel::of(&current).unwrap_or(SecurityLevel::DEFAULT),
            clipboard: cakepass::clipboard::detect().map(|t| t.name()),
            update: update::pending_notice(),
        }
    }
}

impl App {
    pub fn handle_settings(&mut self, ev: Event) {
        let Event::Key(key) = ev else { return };
        let Screen::Settings(s) = &mut self.screen else { return };
        let row = s.row;
        match key {
            Key::Esc => self.screen = Screen::Main,
            Key::Up | Key::BackTab => s.row = row.saturating_sub(1),
            Key::Down | Key::Tab => s.row = (row + 1).min(ROWS - 1),
            Key::Char('?') | Key::F(1) => self.modals.push(Modal::Help(Help::new(HelpPage::Settings))),
            Key::Left | Key::Right | Key::Enter | Key::Char(' ') | Key::PageUp | Key::PageDown => {
                self.change_setting(row, key)
            }
            _ => {}
        }
        // The level on the security row is measured when it is first shown.
        if let Screen::Settings(s) = &self.screen
            && s.row == LEVEL_ROW
            && self.modals.is_empty()
        {
            let level = s.level;
            self.request_measure(level);
        }
    }

    fn change_setting(&mut self, row: usize, key: Key) {
        let mut cfg = self.cfg.clone();
        match row {
            0 => {
                cfg.animation = !cfg.animation;
                let state = if cfg.animation { "on" } else { "off" };
                if self.save_config(cfg) {
                    self.ok(format!("Startup animation {state} (from the next start)."));
                }
            }
            1 => {
                let delta: i64 = match key {
                    Key::Left => -1,
                    Key::Right => 1,
                    Key::PageUp => 10,
                    Key::PageDown => -10,
                    _ => return self.info("Use ← → to change the minutes."),
                };
                let (lo, hi) = (*LOCK_MINUTES_RANGE.start() as i64, *LOCK_MINUTES_RANGE.end() as i64);
                cfg.lock_timeout_minutes = (cfg.lock_timeout_minutes as i64 + delta).clamp(lo, hi) as u64;
                let minutes = cfg.lock_timeout_minutes;
                if self.save_config(cfg) {
                    self.lock_after = Duration::from_secs(minutes * 60);
                    self.ok(format!("CakePass now locks after {minutes} minute(s) without input."));
                }
            }
            LEVEL_ROW => {
                let Screen::Settings(s) = &mut self.screen else { return };
                match key {
                    Key::Left | Key::PageDown => s.level = s.level.step(-1),
                    Key::Right | Key::PageUp => s.level = s.level.step(1),
                    Key::Enter | Key::Char(' ') => {
                        let level = s.level;
                        self.confirm_level(level);
                    }
                    _ => {}
                }
            }
            _ => {
                if matches!(key, Key::Enter | Key::Char(' ') | Key::Right) {
                    self.modals.push(Modal::Prompt(Prompt::new(
                        "Change the master password",
                        vec!["First type your current master password, to confirm it is you.".into()],
                        "Current",
                        true,
                        PromptPurpose::Reconfirm,
                    )));
                }
            }
        }
    }

    /// The line under the settings for the security row: the measured
    /// unlock time, "Measuring…", or why the level cannot run here.
    fn level_line(&self, level: SecurityLevel) -> String {
        if self.measuring(level) {
            return "Measuring how long unlocking takes on this computer…".into();
        }
        match &self.level_times[level_index(level)] {
            Some(Ok(d)) => format!(
                "Unlock here ≈ {} · needs {} MiB free · Enter: switch",
                commands::seconds(*d),
                level.min_available_mib()
            ),
            Some(Err(why)) => why.clone(),
            None => "← →: choose a level · Enter: switch to it (asks your master password).".into(),
        }
    }

    /// Save the settings file; on success they take effect.
    fn save_config(&mut self, cfg: Config) -> bool {
        let saved = match &self.config_path {
            Some(path) => config::save_to(path, &cfg),
            None => Err(Error::InvalidInput("HOME is not set; cannot save settings".into())),
        };
        match saved {
            Ok(()) => {
                self.cfg = cfg;
                true
            }
            Err(e) => {
                self.fail(format!("The setting was not saved: {}", error_text(&e)));
                false
            }
        }
    }

    pub fn draw_settings(&self, g: &mut Grid, s: &Settings, now: Instant) -> Vec<Hint> {
        let (w, h) = (g.width(), g.height());
        title_bar(g, self, "Settings", now);
        g.print(1, 1, w - 2, "Changes are saved right away.", Style::DIM);
        let frame = Rect::new(0, 2, w, h - 4);
        g.frame(frame, "Settings", Style::BORDER, Style::ACCENT_BOLD);
        let inner = frame.inner();
        let r = Rect::new(inner.x + 2, inner.y, inner.w.saturating_sub(3), inner.h);
        const LW: u16 = 18;
        let (l, rt) = (g.g.left, g.g.right);
        let current = self.uv.security_level();
        let rows = [
            ("Startup animation", format!("{l} {} {rt}", if self.cfg.animation { "on" } else { "off" })),
            ("Auto-lock after", format!("{l} {} min {rt}", self.cfg.lock_timeout_minutes)),
            ("Master password", "[ Change… ]".to_string()),
            (
                "Security level",
                format!(
                    "{l} {} {rt}{}",
                    s.level.title(),
                    if current == Some(s.level) { "  (current)" } else { "" }
                ),
            ),
        ];
        for (i, (label, value)) in rows.iter().enumerate() {
            let y = r.y + i as u16;
            let focused = i == s.row;
            if focused {
                g.set(inner.x, y, g.g.marker, Style::ACCENT_BOLD);
            }
            g.print(r.x, y, LW, label, if focused { Style::ACCENT_BOLD } else { Style::BOLD });
            g.print(
                r.x + LW + 1,
                y,
                r.w.saturating_sub(LW + 1),
                value,
                if focused { Style::SELECTED } else { Style::PLAIN },
            );
        }
        // Information (read only).
        let kdf = self.uv.kdf();
        let mut kdf_text = format!("{} · {}", commands::level_name(&kdf), kdf.describe());
        if kdf.weaker_than_standard() {
            kdf_text.push_str(" (lighter than recommended)");
        }
        let key_file_text = if self.uv.uses_key_file() {
            let path = self.key_file.as_ref().map_or("-".into(), |p| p.display().to_string());
            format!("required: {}", fit_tail(&path, r.w.saturating_sub(LW + 11)))
        } else {
            "not used (cakepass security --new-keyfile)".into()
        };
        let settings_file = self.config_path.as_ref().map_or("-".to_string(), |p| p.display().to_string());
        let vault_file = fit_tail(&self.uv.paths().file.display().to_string(), r.w.saturating_sub(LW + 1));
        let settings_file = fit_tail(&settings_file, r.w.saturating_sub(LW + 1));
        let info: [(&str, Option<String>); 10] = [
            ("Vault", None),
            ("File", Some(vault_file)),
            ("Key derivation", Some(kdf_text)),
            ("Key file", Some(key_file_text)),
            ("Encryption", Some("XChaCha20-Poly1305; every field once more on its own".into())),
            ("Settings file", Some(settings_file)),
            ("CakePass", None),
            ("Version", Some(format!("{} (commit {})", env!("CARGO_PKG_VERSION"), update::INSTALLED_COMMIT))),
            (
                "Update",
                Some(
                    s.update
                        .clone()
                        .unwrap_or_else(|| "no new version known (cakepass --update --check)".into()),
                ),
            ),
            (
                "Clipboard",
                Some(
                    s.clipboard.map_or("not found (install wl-clipboard or xclip)".into(), |t| t.to_string()),
                ),
            ),
        ];
        for (y, (label, value)) in (r.y + ROWS as u16 + 1..r.bottom()).zip(info) {
            match value {
                None => {
                    g.print(r.x, y, r.w, label, Style::ACCENT_BOLD);
                }
                Some(v) => field_row(g, r, y, LW, label, &v, Style::PLAIN),
            }
        }
        let help = match s.row {
            0 => "← → or Enter: an animated or a still logo at startup.".to_string(),
            1 => "← → (PgUp PgDn: ±10): minutes until CakePass locks itself.".to_string(),
            LEVEL_ROW => self.level_line(s.level),
            _ => "Enter: change it (asks for the current one first).".to_string(),
        };
        g.print(1, h - 2, w - 2, &help, Style::DIM);
        vec![("↑↓", "choose"), ("←→", "change"), ("Enter", "select"), ("Esc", "back"), ("?", "help")]
    }
}

/// Keep the end of a long path visible: "…/share/cakepass/vault.enc".
fn fit_tail(s: &str, w: u16) -> String {
    let w = w as usize;
    if str_width(s) <= w || w < 2 {
        return s.to_string();
    }
    let tail: Vec<char> = s.chars().rev().take(w - 1).collect();
    std::iter::once('…').chain(tail.into_iter().rev()).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn long_paths_keep_their_end() {
        assert_eq!(super::fit_tail("/home/me/.local/share/cakepass/vault.enc", 12), "…s/vault.enc");
        assert_eq!(super::fit_tail("short", 12), "short");
    }
}
