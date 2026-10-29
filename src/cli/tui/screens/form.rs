//! The form to add or edit an item.
//!
//! What you see is what is saved. An edit form is filled in with the
//! decrypted item when it opens; the password is shown as dots with
//! "(unchanged)" until you change it (typing replaces it, Ctrl+R shows it
//! and lets you edit it in place). Validation is the library's: its error
//! appears in the status line and the form stays open.
//!
//! SECURITY: the fields are `Zeroizing` text inputs that exist only while the
//! form is open; they are wiped when it closes, saved or not.

use std::time::Instant;

use cakepass::crypto::ItemKey;
use cakepass::vault::{Entry, Kind, NewEntry};
use cakepass::{Error, Result};

use super::super::super::commands;
use super::super::app::{App, Modal, Screen};
use super::super::grid::{Grid, Rect};
use super::super::input::TextInput;
use super::super::keys::{Event, Key};
use super::super::theme::Style;
use super::dialog::{Confirm, ConfirmAction, Help, HelpPage};
use super::generator::{GenTarget, Generator};
use super::{Hint, title_bar};

pub enum Mode {
    Add,
    /// Editing the item with this name.
    Edit {
        original: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Name,
    Kind,
    User,
    Email,
    Url,
    Tags,
    Secret,
    Notes,
    Buttons,
}

impl Field {
    fn bit(self) -> u16 {
        1 << self as u16
    }
}

pub enum Action {
    None,
    Save,
    Cancel,
    Generate,
    Help,
}

pub struct Form {
    pub mode: Mode,
    pub kind: Kind,
    pub focus: Field,
    pub name: TextInput,
    pub user: TextInput,
    pub email: TextInput,
    pub url: TextInput,
    pub tags: TextInput,
    pub secret: TextInput,
    pub notes: TextInput,
    pub secret_shown: bool,
    /// Edit: the field holds the stored password, untouched so far.
    pub secret_unchanged: bool,
    changed: u16,
    pub error: Option<String>,
    /// 0 = Save, 1 = Cancel.
    pub button: u8,
}

const KINDS: [Kind; 3] = [Kind::Login, Kind::Api, Kind::Note];

impl Form {
    pub fn add(kind: Kind) -> Form {
        Form {
            mode: Mode::Add,
            kind,
            focus: Field::Name,
            name: TextInput::new(false),
            user: TextInput::new(false),
            email: TextInput::new(false),
            url: TextInput::new(false),
            tags: TextInput::new(false),
            secret: TextInput::new(false),
            notes: TextInput::new(true),
            secret_shown: false,
            secret_unchanged: false,
            changed: 0,
            error: None,
            button: 0,
        }
    }

    /// A form filled in with the item (decrypted now, wiped when the form closes).
    pub fn edit(e: &Entry, key: &ItemKey) -> Result<Form> {
        let mut f = Form::add(e.kind());
        f.mode = Mode::Edit { original: e.name().to_string() };
        f.name.set(e.name());
        f.user.set(&e.username(key)?);
        f.email.set(&e.email(key)?);
        f.url.set(&e.url(key)?);
        f.tags.set(&e.tags().join(", "));
        f.notes.set(&e.notes(key)?);
        f.secret.set(&e.password(key)?);
        f.secret_unchanged = true;
        Ok(f)
    }

    fn adding(&self) -> bool {
        matches!(self.mode, Mode::Add)
    }

    /// The fields of this type, top to bottom.
    pub fn fields(&self) -> Vec<Field> {
        let mut out = vec![Field::Name, Field::Kind];
        if self.kind != Kind::Note {
            out.extend([Field::User, Field::Email, Field::Url]);
        }
        out.push(Field::Tags);
        if self.kind != Kind::Note {
            out.push(Field::Secret);
        }
        out.extend([Field::Notes, Field::Buttons]);
        out
    }

    /// Move the focus to the next (`1`) or previous (`-1`) field.
    pub fn step(&mut self, delta: isize) {
        let fields: Vec<Field> =
            self.fields().into_iter().filter(|&f| f != Field::Kind || self.adding()).collect();
        let i = fields.iter().position(|&f| f == self.focus).unwrap_or(0) as isize;
        self.focus = fields[(i + delta).rem_euclid(fields.len() as isize) as usize];
    }

    pub fn is_changed(&self, f: Field) -> bool {
        self.changed & f.bit() != 0
    }

    /// Whether anything was changed (to ask before throwing it away).
    pub fn dirty(&self) -> bool {
        self.changed != 0
    }

    fn mark(&mut self, f: Field) {
        self.changed |= f.bit();
        self.error = None;
    }

    pub fn label(&self, f: Field) -> &'static str {
        match (f, self.kind) {
            (Field::Name, _) => "Name",
            (Field::Kind, _) => "Type",
            (Field::User, Kind::Api) => "Account/ID",
            (Field::User, _) => "Username",
            (Field::Email, _) => "E-mail",
            (Field::Url, Kind::Api) => "Service URL",
            (Field::Url, _) => "URL",
            (Field::Tags, _) => "Tags",
            (Field::Secret, Kind::Api) => "API key",
            (Field::Secret, _) => "Password",
            (Field::Notes, Kind::Note) => "Content",
            (Field::Notes, _) => "Notes",
            (Field::Buttons, _) => "",
        }
    }

    fn input(&mut self, f: Field) -> Option<&mut TextInput> {
        match f {
            Field::Name => Some(&mut self.name),
            Field::User => Some(&mut self.user),
            Field::Email => Some(&mut self.email),
            Field::Url => Some(&mut self.url),
            Field::Tags => Some(&mut self.tags),
            Field::Secret => Some(&mut self.secret),
            Field::Notes => Some(&mut self.notes),
            Field::Kind | Field::Buttons => None,
        }
    }

    /// Put a generated password in the password field.
    pub fn set_secret(&mut self, s: &str) {
        self.secret.set(s);
        self.secret_unchanged = false;
        self.mark(Field::Secret);
    }

    pub fn handle(&mut self, ev: Event) -> Action {
        let key = match ev {
            Event::Key(k) => k,
            Event::Paste(text) => {
                if self.focus == Field::Secret && self.secret_unchanged && !self.secret_shown {
                    self.secret.clear();
                    self.secret_unchanged = false;
                }
                let focus = self.focus;
                if self.input(focus).is_some_and(|i| i.insert_str(&text)) {
                    self.mark(focus);
                }
                return Action::None;
            }
        };
        let secret_keys = self.kind != Kind::Note;
        match key {
            Key::Ctrl('s') => return Action::Save,
            Key::Esc => return Action::Cancel,
            Key::F(1) => return Action::Help,
            Key::Ctrl('g') if secret_keys => return Action::Generate,
            Key::Ctrl('r') if secret_keys => {
                self.secret_shown = !self.secret_shown;
                return Action::None;
            }
            Key::Tab => self.step(1),
            Key::BackTab => self.step(-1),
            _ => return self.field_key(key),
        }
        Action::None
    }

    fn field_key(&mut self, key: Key) -> Action {
        match self.focus {
            Field::Kind => match key {
                Key::Left | Key::Right | Key::Char(' ') => {
                    let i = KINDS.iter().position(|&k| k == self.kind).unwrap_or(0) as isize;
                    let d = if key == Key::Left { -1 } else { 1 };
                    self.kind = KINDS[(i + d).rem_euclid(3) as usize];
                    self.mark(Field::Kind);
                }
                Key::Up => self.step(-1),
                Key::Down | Key::Enter => self.step(1),
                _ => {}
            },
            Field::Buttons => match key {
                Key::Left | Key::Right => self.button ^= 1,
                Key::Up => self.step(-1),
                Key::Down => self.step(1),
                Key::Enter | Key::Char(' ') => {
                    return if self.button == 0 { Action::Save } else { Action::Cancel };
                }
                _ => {}
            },
            Field::Notes => match key {
                Key::Up => {
                    if !self.notes.up() {
                        self.step(-1);
                    }
                }
                Key::Down => {
                    if !self.notes.down() {
                        self.step(1);
                    }
                }
                k => {
                    if self.notes.edit(k) {
                        self.mark(Field::Notes);
                    }
                }
            },
            field => match key {
                Key::Up => self.step(-1),
                Key::Down | Key::Enter => self.step(1),
                k => {
                    let editing = matches!(k, Key::Char(_) | Key::Backspace | Key::Delete | Key::Ctrl('u'));
                    if field == Field::Secret && editing && self.secret_unchanged && !self.secret_shown {
                        // Typing replaces a stored password you cannot see.
                        self.secret.clear();
                        self.secret_unchanged = false;
                        self.mark(Field::Secret);
                        if !matches!(k, Key::Char(_)) {
                            return Action::None;
                        }
                    }
                    if self.input(field).is_some_and(|i| i.edit(k)) {
                        if field == Field::Secret {
                            self.secret_unchanged = false;
                        }
                        self.mark(field);
                    }
                }
            },
        }
        Action::None
    }

    /// What the focused field is for (shown in the status line).
    fn help(&self) -> &'static str {
        match (self.focus, self.kind) {
            (Field::Name, _) => "The name you find it by, e.g. GitHub (each name once).",
            (Field::Kind, _) if !self.adding() => "The type cannot be changed.",
            (Field::Kind, _) => "← → choose: login, API key or note (a note is text only).",
            (Field::User, Kind::Api) => "Optional: the account or key ID.",
            (Field::User, _) => "Optional.",
            (Field::Email, _) => "Optional: the e-mail address that belongs to it.",
            (Field::Url, _) => "Optional: the web address.",
            (Field::Tags, _) => "Optional, separated by commas: work, mail",
            (Field::Secret, _) if self.secret_unchanged => "Unchanged; typing replaces it. Ctrl+R shows it.",
            (Field::Secret, Kind::Api) => "Hidden. Paste or type the key; Ctrl+R shows it.",
            (Field::Secret, _) => "Hidden while you type. Ctrl+R shows, Ctrl+G generates.",
            (Field::Notes, Kind::Note) => "The text of the note. Enter starts a new line.",
            (Field::Notes, _) => "Optional. Enter starts a new line.",
            (Field::Buttons, _) => "Enter: save or cancel. Ctrl+S saves from any field.",
        }
    }
}

impl App {
    pub fn open_add(&mut self) {
        let kind = self.tab.kind().unwrap_or(Kind::Login);
        self.reveal_until = None;
        self.screen = Screen::Form(Box::new(Form::add(kind)));
    }

    pub fn open_edit(&mut self) {
        let Some(e) = self.selected() else { return };
        match Form::edit(e, self.key()) {
            Ok(f) => {
                self.reveal_until = None;
                self.screen = Screen::Form(Box::new(f));
            }
            Err(e) => self.fail(super::super::app::error_text(&e)),
        }
    }

    pub fn handle_form(&mut self, ev: Event) {
        let Screen::Form(f) = &mut self.screen else { return };
        let action = f.handle(ev);
        let dirty = f.dirty();
        match action {
            Action::None => {}
            Action::Save => self.save_form(),
            Action::Cancel if dirty => self.modals.push(Modal::Confirm(Confirm::new(
                "Unsaved changes",
                vec!["Close the form without saving? What you typed is thrown away.".into()],
                "Discard",
                "Keep editing",
                false,
                ConfirmAction::Discard,
            ))),
            Action::Cancel => self.screen = Screen::Main,
            Action::Generate => {
                let g = Generator::new(GenTarget::Form, self.gen_prefs.clone());
                self.modals.push(Modal::Generator(Box::new(g)));
            }
            Action::Help => self.modals.push(Modal::Help(Help::new(HelpPage::Form))),
        }
    }

    fn save_form(&mut self) {
        let Screen::Form(mut f) = std::mem::replace(&mut self.screen, Screen::Main) else { return };
        match self.try_save(&mut f) {
            // The form is dropped here, which wipes what was typed.
            Ok((name, msg)) => {
                self.refilter();
                self.select_name(&name);
                self.ok(msg);
            }
            Err(e) => {
                f.error = e;
                self.screen = Screen::Form(f);
            }
        }
    }

    /// Save the form. Ok: (name, message). Err: the text for the status line,
    /// or `None` when a dialog took over.
    fn try_save(&mut self, f: &mut Form) -> std::result::Result<(String, String), Option<String>> {
        let kind = f.kind;
        let note = kind == Kind::Note;
        if f.name.as_str().trim().is_empty() {
            f.focus = Field::Name;
            return Err(Some("Give the item a name.".into()));
        }
        if !note && f.secret.is_empty() && (f.adding() || f.is_changed(Field::Secret)) {
            f.focus = Field::Secret;
            return Err(Some(match kind {
                Kind::Api => "The API key must not be empty.".into(),
                _ => "The password is empty: type one or press Ctrl+G.".into(),
            }));
        }
        let tags = commands::split_tags(f.tags.as_str());
        let odd_mail = !note && commands::email_looks_odd(f.email.as_str());
        let result: Result<(String, String)> = match &f.mode {
            Mode::Add => {
                let text = |i: &TextInput| if note { String::new() } else { i.as_str().to_string() };
                let fields = NewEntry {
                    name: f.name.as_str().to_string(),
                    kind,
                    username: text(&f.user),
                    email: text(&f.email),
                    password: text(&f.secret),
                    url: text(&f.url),
                    notes: f.notes.as_str().to_string(),
                    tags,
                };
                commands::add_entry(&mut self.uv, fields).map(|name| {
                    (name.clone(), format!("{} '{name}' saved (encrypted).", commands::kind_noun(kind)))
                })
            }
            Mode::Edit { original } if !f.dirty() => {
                return Ok((original.clone(), "Nothing changed.".into()));
            }
            Mode::Edit { original } => {
                let original = original.clone();
                let form: &Form = f;
                self.commit(|vault, key| {
                    vault.update(&original, |e| {
                        if form.is_changed(Field::User) {
                            e.set_username(key, form.user.as_str())?;
                        }
                        if form.is_changed(Field::Email) {
                            e.set_email(key, form.email.as_str())?;
                        }
                        if form.is_changed(Field::Url) {
                            e.set_url(key, form.url.as_str())?;
                        }
                        if form.is_changed(Field::Tags) {
                            e.set_tags(&tags)?;
                        }
                        if form.is_changed(Field::Notes) {
                            e.set_notes(key, form.notes.as_str())?;
                        }
                        if form.is_changed(Field::Secret) {
                            e.set_password(key, form.secret.as_str())?;
                        }
                        if form.is_changed(Field::Name) {
                            e.set_name(form.name.as_str())?;
                        }
                        Ok(())
                    })
                })
                .map(|()| {
                    let name = if form.is_changed(Field::Name) {
                        form.name.as_str().trim().to_string()
                    } else {
                        original
                    };
                    (name.clone(), format!("Item '{name}' updated."))
                })
            }
        };
        match result {
            Ok((name, mut msg)) => {
                if odd_mail {
                    msg.push_str(" Note: that e-mail address looks odd (saved anyway).");
                }
                Ok((name, msg))
            }
            Err(e) => {
                if matches!(e, Error::EntryExists(_)) {
                    f.focus = Field::Name;
                }
                Err(self.save_error(e))
            }
        }
    }

    pub fn draw_form(&self, g: &mut Grid, f: &Form, now: Instant) -> Vec<Hint> {
        let (w, h) = (g.width(), g.height());
        let subtitle = match &f.mode {
            Mode::Add => "Add an item".to_string(),
            Mode::Edit { original } => format!("Edit '{original}'"),
        };
        title_bar(g, self, &subtitle, now);
        g.print(1, 1, w - 2, "Fill in the fields. Ctrl+S saves, Esc cancels.", Style::DIM);
        let frame = Rect::new(0, 2, w, h - 4);
        let title = if f.adding() { "New item" } else { "Edit item" };
        g.frame(frame, title, Style::BORDER, Style::ACCENT_BOLD);
        let inner = frame.inner();
        const LW: u16 = 12;
        let vx = inner.x + 3 + LW;
        let vw = inner.w.saturating_sub(LW + 4);
        let last = inner.bottom() - 1;
        let mut y = inner.y;
        let mut cursor = None;
        for field in f.fields() {
            let focused = f.focus == field;
            if field == Field::Buttons {
                let mut x = vx;
                for (i, label) in ["[ Save ]", "[ Cancel ]"].iter().enumerate() {
                    let style = if focused && f.button as usize == i { Style::SELECTED } else { Style::BOLD };
                    x += g.print(x, last, 12, label, style) + 2;
                }
                continue;
            }
            if focused {
                g.set(inner.x + 1, y, g.g.marker, Style::ACCENT_BOLD);
            }
            let label_style = if focused { Style::ACCENT_BOLD } else { Style::BOLD };
            g.print(inner.x + 2, y, LW, f.label(field), label_style);
            match field {
                Field::Kind if f.adding() => {
                    let mut x = vx;
                    for k in KINDS {
                        let name = if k == Kind::Api { "API key" } else { k.label() };
                        let style = match (k == f.kind, focused) {
                            (true, true) => Style::SELECTED,
                            (true, false) => Style::ACCENT_BOLD,
                            _ => Style::DIM,
                        };
                        x += g.print(x, y, 10, &format!(" {name} "), style) + 1;
                    }
                }
                Field::Kind => {
                    g.print(vx, y, vw, f.kind.label(), Style::kind(f.kind));
                }
                Field::Secret if f.secret_unchanged && !f.secret_shown => {
                    let dots: String = std::iter::repeat_n(g.g.dot, 8).collect();
                    let n = g.print(vx, y, vw, &dots, Style::DIM);
                    g.print(vx + n + 2, y, vw.saturating_sub(n + 2), "(unchanged)", Style::DIM);
                    if focused {
                        cursor = Some((vx, y));
                    }
                }
                Field::Notes => {
                    let rows = last.saturating_sub(y).max(1);
                    let area = Rect::new(vx, y, vw, rows);
                    if f.notes.is_empty() && !focused {
                        g.print(vx, y, vw, "(empty)", Style::DIM);
                    }
                    let pos = f.notes.draw(g, area, Style::PLAIN, None);
                    if focused {
                        cursor = Some(pos);
                    }
                    y += rows;
                    continue;
                }
                field => {
                    let input = match field {
                        Field::Name => &f.name,
                        Field::User => &f.user,
                        Field::Email => &f.email,
                        Field::Url => &f.url,
                        Field::Tags => &f.tags,
                        _ => &f.secret,
                    };
                    let mask = (field == Field::Secret && !f.secret_shown).then_some(g.g.dot);
                    let area = Rect::new(vx, y, vw, 1);
                    // The field you type in is underlined, like a line on a paper form.
                    let style = if focused { Style::FIELD } else { Style::PLAIN };
                    if focused {
                        g.fill(area, style);
                    }
                    let pos = input.draw(g, area, style, mask);
                    if focused {
                        cursor = Some(pos);
                    }
                }
            }
            y += 1;
        }
        g.set_cursor(cursor);
        match &f.error {
            Some(e) => g.print(1, h - 2, w - 2, &format!("{} {e}", g.g.cross), Style::ERROR),
            None => g.print(1, h - 2, w - 2, f.help(), Style::DIM),
        };
        let mut hints: Vec<Hint> = vec![("↑↓", "move"), ("Ctrl+S", "save"), ("Esc", "cancel")];
        if f.focus == Field::Kind && f.adding() {
            hints.insert(1, ("←→", "type"));
        }
        if f.kind != Kind::Note {
            hints.extend([("Ctrl+G", "generate"), ("Ctrl+R", "show password")]);
        }
        hints.push(("F1", "help"));
        hints
    }
}
