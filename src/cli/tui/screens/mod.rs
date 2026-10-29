//! The screens of the screen mode and the parts they share: the title bar
//! at the top, the status line and the key hints at the bottom.

pub mod dialog;
pub mod form;
pub mod generator;
pub mod main;
pub mod settings;

use std::time::Instant;

use super::app::App;
use super::grid::{Grid, Rect, str_width};
use super::theme::Style;

/// A key hint for the bottom line: (keys, what they do).
pub type Hint = (&'static str, &'static str);

/// The top line: "CakePass", what you are looking at, and the lock countdown.
pub fn title_bar(g: &mut Grid, app: &App, subtitle: &str, now: Instant) {
    let w = g.width();
    g.fill(Rect::new(0, 0, w, 1), Style::PLAIN);
    let n = g.print(0, 0, w, " CakePass ", Style::TITLE);
    let left = app.lock_left(now);
    let right = format!("locks in {}:{:02} ", left / 60, left % 60);
    let rw = str_width(&right) as u16;
    if w > n + rw + 2 {
        g.print(n + 1, 0, w - n - rw - 2, subtitle, Style::BOLD);
        g.print(w - rw, 0, rw, &right, Style::DIM);
    }
}

/// The second-to-last line: the latest message, or `fallback`.
pub fn status_line(g: &mut Grid, app: &App, now: Instant) {
    let y = g.height() - 2;
    let Some(t) = &app.toast else { return };
    let w = g.width();
    g.fill(Rect::new(0, y, w, 1), Style::PLAIN);
    let mark = match t.style {
        Style::SUCCESS => Some(g.g.check),
        Style::ERROR => Some(g.g.cross),
        _ => None,
    };
    let mut text = match mark {
        Some(m) => format!("{m} {}", t.text),
        None => t.text.clone(),
    };
    if let Some(at) = t.clears_at {
        let left = at.saturating_duration_since(now).as_secs_f32().ceil() as u64;
        text.push_str(&format!("; the clipboard is cleared in {left} s"));
    }
    g.print(1, y, w - 2, &text, t.style);
}

/// The last line: the keys that work right now. The help key always fits.
pub fn hint_bar(g: &mut Grid, hints: &[Hint]) {
    let (w, y) = (g.width(), g.height() - 1);
    g.fill(Rect::new(0, y, w, 1), Style::PLAIN);
    let glyphs = g.g;
    let arrows = |k: &'static str| match k {
        "↑↓" => glyphs.up_down,
        "←→" => glyphs.left_right,
        k => k,
    };
    let item_w = |&(k, l): &Hint| (str_width(arrows(k)) + 1 + str_width(l) + 2) as u16;
    let help = hints.iter().find(|h| h.1 == "help");
    let reserve = help.map_or(0, item_w);
    let mut x = 1;
    for h in hints.iter().filter(|h| h.1 != "help") {
        if x + item_w(h) + reserve > w {
            break;
        }
        x = draw_hint(g, x, y, arrows(h.0), h.1);
    }
    if let Some(h) = help {
        draw_hint(g, x, y, h.0, h.1);
    }
}

fn draw_hint(g: &mut Grid, x: u16, y: u16, keys: &str, label: &str) -> u16 {
    let w = g.width();
    let mut x = x + g.print(x, y, w.saturating_sub(x), keys, Style::ACCENT_BOLD);
    if !label.is_empty() {
        x += 1;
        x += g.print(x, y, w.saturating_sub(x), label, Style::DIM);
    }
    x + 2
}

/// A label + value row ("Username  john"), the value cut off with "…".
pub fn field_row(g: &mut Grid, r: Rect, y: u16, label_w: u16, label: &str, value: &str, style: Style) {
    g.print(r.x, y, label_w.min(r.w), label, Style::BOLD);
    if r.w > label_w + 1 {
        g.print(r.x + label_w + 1, y, r.w - label_w - 1, value, style);
    }
}
