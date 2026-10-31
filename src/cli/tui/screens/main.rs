//! The main screen: type tabs and the search on top, the list of items, and
//! the details of the selected item (to the right, or below on a narrow
//! terminal).
//!
//! SECURITY: list rows show the username like `cakepass list` does; it is
//! decrypted for the visible rows only, per frame, and wiped right after.
//! The details decrypt the selected item only. Password, API key and notes
//! are shown as dots until revealed (and see `app.rs` for the hiding).

use std::time::{Duration, Instant};

use cakepass::vault::Kind;

use super::super::super::{commands, ui};
use super::super::app::{App, CopyWhat, Exit, Modal, Screen, Tab};
use super::super::grid::{Grid, Rect, str_width, wrap};
use super::super::keys::{Event, Key};
use super::dialog::{Confirm, ConfirmAction, Help, HelpPage};
use super::generator::{GenTarget, Generator};
use super::settings::Settings;
use super::{Hint, field_row, title_bar};
use crate::cli::tui::app::REVEAL_SECS;
use crate::cli::tui::theme::Style;

/// Where the parts of the main screen go for a terminal of `w` × `h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MainLayout {
    pub frame: Rect,
    pub list: Rect,
    pub detail: Rect,
    /// Details below the list instead of next to it.
    pub stacked: bool,
}

impl MainLayout {
    pub fn new(w: u16, h: u16) -> MainLayout {
        let frame = Rect::new(0, 2, w, h.saturating_sub(4));
        let inner_h = frame.h.saturating_sub(2);
        let stacked = w < 80 && h >= 24;
        if stacked {
            let dh = (inner_h / 2).clamp(6, 11);
            let lh = inner_h.saturating_sub(dh + 1);
            MainLayout {
                frame,
                list: Rect::new(1, 3, w - 2, lh),
                detail: Rect::new(2, 4 + lh, w - 4, dh),
                stacked,
            }
        } else {
            let inner_w = w.saturating_sub(3);
            let dw = (inner_w * 45 / 100).max(33).min(inner_w.saturating_sub(20));
            let lw = inner_w - dw;
            MainLayout {
                frame,
                list: Rect::new(1, 3, lw, inner_h),
                detail: Rect::new(lw + 3, 3, dw.saturating_sub(2), inner_h),
                stacked,
            }
        }
    }
}

impl App {
    fn list_rows(&self) -> usize {
        MainLayout::new(self.size.0, self.size.1).list.h.max(1) as usize
    }

    fn move_sel(&mut self, delta: isize) {
        let last = self.view.len().saturating_sub(1) as isize;
        let new = (self.sel as isize + delta).clamp(0, last.max(0)) as usize;
        if new != self.sel {
            self.sel = new;
            self.reveal_until = None;
        }
    }

    fn set_tab(&mut self, tab: Tab) {
        self.tab = tab;
        self.reveal_until = None;
        self.refilter();
    }

    pub fn handle_main(&mut self, ev: Event) {
        let key = match ev {
            Event::Key(k) => k,
            // Pasting only means something in the search; never a shortcut.
            Event::Paste(text) => {
                if self.searching && self.search.insert_str(&text) {
                    self.refilter();
                }
                return;
            }
        };
        let page = self.list_rows() as isize;
        if self.searching {
            match key {
                Key::Esc => {
                    self.search.clear();
                    self.searching = false;
                    self.refilter();
                }
                Key::Enter => self.searching = false,
                Key::Up => self.move_sel(-1),
                Key::Down => self.move_sel(1),
                Key::PageUp => self.move_sel(-page),
                Key::PageDown => self.move_sel(page),
                Key::Tab => self.set_tab(self.tab.step(1)),
                Key::BackTab => self.set_tab(self.tab.step(-1)),
                Key::F(1) => self.modals.push(Modal::Help(Help::new(HelpPage::Main))),
                k => {
                    if self.search.edit(k) {
                        self.reveal_until = None;
                        self.refilter();
                    }
                }
            }
            return;
        }
        match key {
            Key::Up => self.move_sel(-1),
            Key::Down => self.move_sel(1),
            Key::PageUp => self.move_sel(-page),
            Key::PageDown => self.move_sel(page),
            Key::Home => self.move_sel(isize::MIN / 2),
            Key::End => self.move_sel(isize::MAX / 2),
            Key::Left | Key::BackTab => self.set_tab(self.tab.step(-1)),
            Key::Right | Key::Tab => self.set_tab(self.tab.step(1)),
            Key::Enter | Key::Char('v') => self.toggle_reveal(),
            Key::Char('c') => self.copy_field(CopyWhat::Secret),
            Key::Char('u') => self.copy_field(CopyWhat::Username),
            Key::Char('m') => self.copy_field(CopyWhat::Email),
            Key::Char('a' | 'n') => self.open_add(),
            Key::Char('e') => self.open_edit(),
            Key::Delete | Key::Char('d') => self.ask_delete(),
            Key::Char('g') => {
                let g = Generator::new(GenTarget::NewLogin, self.gen_prefs.clone());
                self.modals.push(Modal::Generator(Box::new(g)));
            }
            Key::Char('s') => {
                self.reveal_until = None;
                self.screen = Screen::Settings(Settings::load(self.uv.kdf()));
            }
            Key::Char('l') => self.exit = Some(Exit::Lock),
            Key::Char('q') => self.exit = Some(Exit::Quit),
            Key::Char('?') | Key::F(1) => self.modals.push(Modal::Help(Help::new(HelpPage::Main))),
            Key::Char('/') => self.searching = true,
            Key::Esc => {
                if !self.search.is_empty() {
                    self.search.clear();
                    self.refilter();
                }
            }
            // Any other character (not a space) starts the search with it.
            Key::Char(c) if c != ' ' => {
                self.searching = true;
                if self.search.insert(c) {
                    self.reveal_until = None;
                    self.refilter();
                }
            }
            _ => {}
        }
    }

    fn toggle_reveal(&mut self) {
        if self.reveal_until.take().is_some() {
            return;
        }
        match self.selected() {
            Some(e) if e.has_secret() || e.has_notes() => {
                self.reveal_until = Some(self.now + Duration::from_secs(REVEAL_SECS));
            }
            Some(_) => self.info("This item has no password, key or notes to show."),
            None => {}
        }
    }

    fn ask_delete(&mut self) {
        let Some(e) = self.selected() else { return };
        let (name, kind) = (e.name().to_string(), e.kind());
        self.reveal_until = None;
        self.modals.push(Modal::Confirm(Confirm::new(
            "Delete",
            vec![
                format!("Delete the {} '{name}'?", commands::kind_noun(kind).to_lowercase()),
                "The previous version stays in the .bak backup until the next change.".into(),
            ],
            "Delete",
            "Keep",
            false,
            ConfirmAction::Delete(name),
        )));
    }

    pub fn draw_main(&self, g: &mut Grid, now: Instant) -> Vec<Hint> {
        let (w, h) = (g.width(), g.height());
        let file =
            self.uv.paths().file.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
        title_bar(g, self, &file, now);
        self.draw_tabs(g);
        let lay = MainLayout::new(w, h);
        let (frame, border, gl) = (lay.frame, Style::BORDER, g.g);
        g.frame(frame, "Items", border, Style::ACCENT_BOLD);
        if lay.stacked {
            let y = lay.detail.y - 1;
            g.hline(1, y, w - 2, border);
            g.set(0, y, gl.tee_right, border);
            g.set(w - 1, y, gl.tee_left, border);
            g.print(2, y, 10, " Details ", Style::ACCENT_BOLD);
        } else {
            let x = lay.list.x + lay.list.w;
            g.set(x, frame.y, gl.tee_down, border);
            g.set(x, frame.bottom() - 1, gl.tee_up, border);
            for y in frame.y + 1..frame.bottom() - 1 {
                g.set(x, y, gl.v, border);
            }
            g.print(x + 2, frame.y, 10, " Details ", Style::ACCENT_BOLD);
        }
        self.draw_list(g, lay);
        self.draw_detail(g, lay.detail, now);
        // The status line (a message from `app.toast` is drawn over it).
        let total = self.entries().len();
        let status = if !self.search.is_empty() {
            format!(
                "{} of {total} items match \"{}\" · Esc clears the search",
                self.view.len(),
                self.search.as_str()
            )
        } else {
            commands::capitalize(&commands::vault_summary(&self.uv.vault))
        };
        g.print(1, h - 2, w - 2, &status, Style::DIM);
        if self.searching {
            vec![("type", "to search"), ("↑↓", "choose"), ("Enter", "done"), ("Esc", "clear"), ("F1", "help")]
        } else {
            // In order of importance: what does not fit is left out.
            vec![
                ("↑↓", "move"),
                ("Enter", "show"),
                ("c", "copy"),
                ("a", "add"),
                ("q", "quit"),
                ("e", "edit"),
                ("d", "delete"),
                ("/", "search"),
                ("g", "generate"),
                ("s", "settings"),
                ("←→", "type"),
                ("l", "lock"),
                ("?", "help"),
            ]
        }
    }

    fn draw_tabs(&self, g: &mut Grid) {
        let w = g.width();
        let count = |t: Tab| self.entries().iter().filter(|e| t.kind().is_none_or(|k| e.kind() == k)).count();
        let labels: Vec<String> = Tab::ALL.iter().map(|&t| format!("{} {}", t.label(), count(t))).collect();
        let full_w: usize = labels.iter().map(|l| str_width(l) + 3).sum();
        let with_counts = full_w + 18 <= w as usize;
        let mut x = 1;
        for (i, &t) in Tab::ALL.iter().enumerate() {
            let label = if with_counts { labels[i].as_str() } else { t.label() };
            let style = if t == self.tab { Style::ACTIVE_TAB } else { Style::DIM };
            x += g.print(x, 1, w.saturating_sub(x), label, style) + 3;
        }
        // The search field on the right.
        let sw = (w.saturating_sub(x + 1)).min(32);
        if sw < 8 {
            return;
        }
        let sx = w - sw - 1;
        if self.searching || !self.search.is_empty() {
            g.print(sx, 1, 2, "/", Style::ACCENT_BOLD);
            let cursor = self.search.draw(g, Rect::new(sx + 2, 1, sw - 2, 1), Style::BOLD, None);
            if self.searching {
                g.set_cursor(Some(cursor));
            }
        } else {
            let hint = "/ search";
            g.print(w - 1 - hint.len() as u16, 1, hint.len() as u16, hint, Style::DIM);
        }
    }

    fn draw_list(&self, g: &mut Grid, lay: MainLayout) {
        let r = lay.list;
        let rows = r.h.max(1) as usize;
        if self.view.is_empty() {
            let lines: [&str; 2] = if self.entries().is_empty() {
                ["Your vault is empty.", "Press a to add your first item, or g to generate a password."]
            } else if !self.search.is_empty() {
                ["No items match.", "Esc clears the search."]
            } else {
                ["Nothing of this type yet.", "Press a to add one, or ← → for the other types."]
            };
            let width = r.w.saturating_sub(3);
            let wrapped = lines.iter().flat_map(|l| wrap(l, width as usize));
            for (y, l) in (r.y + 1..r.bottom()).zip(wrapped) {
                g.print(r.x + 2, y, width, &l, Style::DIM);
            }
            return;
        }
        // Keep the selection visible.
        let mut top = self.top.get();
        if self.sel < top {
            top = self.sel;
        } else if self.sel >= top + rows {
            top = self.sel + 1 - rows;
        }
        top = top.min(self.view.len().saturating_sub(rows));
        self.top.set(top);
        let avail = r.w.saturating_sub(9);
        let (nw, uw) = if avail >= 46 {
            (avail * 2 / 5, avail * 3 / 10)
        } else if avail >= 26 {
            (avail * 3 / 5, avail - avail * 3 / 5 - 1)
        } else {
            (avail, 0)
        };
        let tw = avail.saturating_sub(nw + uw + 2);
        let key = self.key();
        for (row, &idx) in self.view.iter().enumerate().skip(top).take(rows) {
            let e = &self.entries()[idx];
            let y = r.y + (row - top) as u16;
            let selected = row == self.sel;
            let base = if selected { Style::SELECTED } else { Style::PLAIN };
            g.fill(Rect::new(r.x, y, r.w, 1), base);
            if selected {
                g.set(r.x, y, g.g.marker, base);
            }
            let kind_style = if selected { base } else { Style::kind(e.kind()) };
            g.print(r.x + 2, y, 6, kind_tag(e.kind()), kind_style);
            let mut x = r.x + 9;
            g.print(x, y, nw, e.name(), if selected { base } else { Style::BOLD });
            x += nw + 1;
            if uw > 0 && e.kind() != Kind::Note {
                // Decrypted for this row only; wiped when `user` goes out of scope.
                if let Ok(user) = e.username(key) {
                    g.print(x, y, uw, &user, if selected { base } else { Style::PLAIN });
                }
            }
            x += uw + 1;
            if tw > 0 {
                g.print(x, y, tw, &e.tags().join(", "), if selected { base } else { Style::DIM });
            }
        }
        if self.view.len() > rows {
            let pos = format!(" {}/{} ", self.sel + 1, self.view.len());
            let pw = pos.len() as u16;
            let y = if lay.stacked { lay.detail.y - 1 } else { lay.frame.bottom() - 1 };
            if r.w > pw + 2 {
                g.print(r.x + r.w - pw - 1, y, pw, &pos, Style::BORDER);
            }
        }
    }

    fn draw_detail(&self, g: &mut Grid, r: Rect, now: Instant) {
        let Some(e) = self.selected() else {
            g.print(r.x, r.y + 1, r.w, "No item selected.", Style::DIM);
            return;
        };
        let key = self.key();
        let kind = e.kind();
        const LW: u16 = 11;
        let mut y = r.y;
        let bottom = r.bottom();
        let row = |g: &mut Grid, y: &mut u16, label: &str, value: &str, style: Style| {
            if *y < bottom {
                field_row(g, r, *y, LW, label, value, style);
                *y += 1;
            }
        };
        row(g, &mut y, "Name", e.name(), Style::BOLD);
        row(g, &mut y, "Type", kind.label(), Style::kind(kind));
        if kind != Kind::Note {
            let (user_l, url_l) =
                if kind == Kind::Api { ("Account/ID", "Service") } else { ("Username", "URL") };
            for (label, value) in [(user_l, e.username(key)), ("E-mail", e.email(key)), (url_l, e.url(key))] {
                match value {
                    Ok(v) if v.is_empty() => row(g, &mut y, label, "-", Style::DIM),
                    Ok(v) => row(g, &mut y, label, &v, Style::PLAIN),
                    Err(_) => row(g, &mut y, label, "(cannot decrypt)", Style::ERROR),
                }
            }
        }
        let tags = e.tags().join(", ");
        row(g, &mut y, "Tags", if tags.is_empty() { "-" } else { &tags }, Style::PLAIN);
        row(g, &mut y, "Modified", &ui::format_time(e.modified()), Style::DIM);

        let revealed = self.reveal_until.is_some();
        let dots: String = std::iter::repeat_n(g.g.dot, 8).collect();
        let footer_rows = u16::from(bottom.saturating_sub(y) > 3);
        if kind != Kind::Note {
            let label = commands::capitalize(kind.secret_label());
            if !e.has_password() {
                row(g, &mut y, &label, "-", Style::DIM);
            } else if revealed {
                match e.password(key) {
                    Ok(pw) => row(g, &mut y, &label, &pw, Style::ACCENT_BOLD),
                    Err(_) => row(g, &mut y, &label, "(cannot decrypt)", Style::ERROR),
                }
            } else {
                row(g, &mut y, &label, &dots, Style::DIM);
            }
        }
        let notes_label = if kind == Kind::Note { "Content" } else { "Notes" };
        if !e.has_notes() {
            row(g, &mut y, notes_label, "-", Style::DIM);
        } else if !revealed {
            row(g, &mut y, notes_label, &dots, Style::DIM);
        } else {
            match e.notes(key) {
                Ok(text) => draw_block(g, r, &mut y, notes_label, &text, bottom - footer_rows),
                Err(_) => row(g, &mut y, notes_label, "(cannot decrypt)", Style::ERROR),
            }
        }
        if footer_rows > 0 && y < bottom {
            let hint = match self.reveal_until {
                Some(t) => {
                    let left = t.saturating_duration_since(now).as_secs_f32().ceil() as u64;
                    format!("Hides in {left} s · Enter hides")
                }
                None if e.has_secret() || e.has_notes() => "Enter shows · c copies · e edits".to_string(),
                None => "e edits · d deletes".to_string(),
            };
            g.print(r.x, bottom - 1, r.w, &hint, Style::DIM);
        }
    }
}

/// A revealed multi-line text (notes, the content of a note), up to `bottom`.
fn draw_block(g: &mut Grid, r: Rect, y: &mut u16, label: &str, text: &str, bottom: u16) {
    const LW: u16 = 11;
    g.print(r.x, *y, LW, label, Style::BOLD);
    let (x, w) = (r.x + LW + 1, r.w.saturating_sub(LW + 1));
    let lines: Vec<&str> = text.split('\n').collect();
    let room = bottom.saturating_sub(*y) as usize;
    for (i, line) in lines.iter().enumerate() {
        if i >= room {
            break;
        }
        if i + 1 == room && lines.len() > room {
            let more = format!("{} {} more lines (c copies all)", g.g.ellipsis, lines.len() - i);
            g.print(x, *y, w, &more, Style::DIM);
        } else {
            g.print(x, *y, w, line, Style::ACCENT_BOLD);
        }
        *y += 1;
    }
}

/// The short type label in the list.
fn kind_tag(kind: Kind) -> &'static str {
    match kind {
        Kind::Login => "login",
        Kind::Api => "api",
        Kind::Note => "note",
    }
}
