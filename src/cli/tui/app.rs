//! The state of the screen mode and what every key does.
//!
//! This is pure logic: it receives key events and the current time, and
//! draws into a [`Grid`]. Nothing here touches the terminal, so the tests at
//! the bottom drive it with synthetic keys against a real (temporary) vault.
//!
//! SECURITY:
//! - Fields are decrypted only to be drawn or copied, into `Zeroizing`
//!   buffers that are wiped right after. A revealed password or note is not
//!   kept either: it is decrypted again for every frame while it is shown.
//! - A revealed secret hides itself after [`REVEAL_SECS`], when the selection
//!   changes, when a dialog or another screen opens, and on locking.
//! - Every change is saved at once with the library (`UnlockedVault::save`).
//!   If saving fails the vault in memory is put back as it was, so memory and
//!   file never differ.
//! - A vault with a key file: only the key file's *path* is kept here. The
//!   file is read again (and its pepper wiped right after) for each action
//!   that needs it: re-checking the master password, re-keying, reloading.
//! - Changing the security level re-checks the master password first, so a
//!   typo can never re-key the vault under a password nobody knows.

use std::cell::Cell;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use cakepass::clipboard::CLEAR_AFTER_SECS;
use cakepass::crypto::{self, ItemKey, KdfParams, SecurityLevel};
use cakepass::format::Credentials;
use cakepass::keyfile::{self, LoadedKeyFile};
use cakepass::storage::{self, UnlockedVault};
use cakepass::vault::{Entry, Kind, Vault};
use cakepass::{Error, Result};

use super::super::commands::{self, Notice};
use super::super::config::Config;
use super::super::prompt;
use super::grid::{Grid, Rect, wrap};
use super::input::TextInput;
use super::keys::{Event, Key};
use super::screens::dialog::{Confirm, ConfirmAction, Help, HelpPage, Message, Prompt, PromptPurpose};
use super::screens::form::Form;
use super::screens::generator::{GenPrefs, GenTarget, Generator};
use super::screens::settings::Settings;
use super::screens::{self, Hint};
use super::theme::Style;
use super::{MIN_HEIGHT, MIN_WIDTH};

/// A revealed secret hides itself after this many seconds.
pub const REVEAL_SECS: u64 = 10;
/// How long a message stays in the status line.
const TOAST_SECS: u64 = 5;

/// Why the screen mode ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// `q` or Ctrl+C.
    Quit,
    /// `l`.
    Lock,
    /// No input for the lock timeout.
    Idle,
    /// SIGINT, SIGTERM, SIGHUP or SIGQUIT.
    Signal,
    /// The terminal went away.
    Hangup,
}

/// The type filter above the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    All,
    Logins,
    Api,
    Notes,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::All, Tab::Logins, Tab::Api, Tab::Notes];

    pub fn kind(self) -> Option<Kind> {
        match self {
            Tab::All => None,
            Tab::Logins => Some(Kind::Login),
            Tab::Api => Some(Kind::Api),
            Tab::Notes => Some(Kind::Note),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Tab::All => "All",
            Tab::Logins => "Logins",
            Tab::Api => "API keys",
            Tab::Notes => "Notes",
        }
    }

    pub fn step(self, delta: isize) -> Tab {
        let i = Tab::ALL.iter().position(|&t| t == self).unwrap_or(0) as isize;
        Tab::ALL[(i + delta).rem_euclid(4) as usize]
    }
}

pub enum Screen {
    Main,
    Form(Box<Form>),
    Settings(Settings),
}

/// A dialog on top of the screen; the top one gets the keys.
pub enum Modal {
    Help(Help),
    Message(Message),
    Confirm(Confirm),
    Prompt(Prompt),
    Generator(Box<Generator>),
}

/// A message in the status line.
pub struct Toast {
    pub text: String,
    pub style: Style,
    pub until: Instant,
    /// For a copied secret: when the clipboard is cleared (shown as a countdown).
    pub clears_at: Option<Instant>,
}

/// Slow work (Argon2) that runs after the next frame, so "Checking…" is
/// on screen while it runs.
pub enum Task {
    Reconfirm(Zeroizing<String>),
    ChangePassword(Zeroizing<String>),
    Reload(Zeroizing<String>),
    /// Time one unlock at this level (settings screen; no dialog involved).
    Measure(SecurityLevel),
    /// Re-check the master password, then re-key at this level.
    ChangeLevel(Zeroizing<String>, SecurityLevel),
}

/// Copies a secret to the clipboard (with automatic clearing); returns the
/// name of the tool. Replaced by a fake in the tests.
pub type Copier = Box<dyn FnMut(&str) -> Result<&'static str>>;

/// Measures how long one unlock takes with these settings (Argon2 on this
/// computer). Replaced by a fake in the tests.
pub type Measurer = Box<dyn FnMut(&KdfParams) -> Result<Duration>>;

/// A measured unlock time, or why it could not be measured.
pub type Timing = std::result::Result<Duration, String>;

#[derive(Debug, Clone, Copy)]
pub enum CopyWhat {
    Secret,
    Username,
    Email,
}

pub struct App {
    pub uv: UnlockedVault,
    pub cfg: Config,
    pub config_path: Option<PathBuf>,
    pub lock_after: Duration,
    pub last_input: Instant,
    pub now: Instant,
    copier: Copier,
    pub size: (u16, u16),
    pub tab: Tab,
    pub search: TextInput,
    pub searching: bool,
    /// Positions (in `vault.entries()`) of the items shown in the list.
    pub view: Vec<usize>,
    /// The selected row of `view`.
    pub sel: usize,
    /// First visible row of the list (kept between frames).
    pub top: Cell<usize>,
    pub reveal_until: Option<Instant>,
    pub screen: Screen,
    pub modals: Vec<Modal>,
    pub toast: Option<Toast>,
    pub task: Option<Task>,
    pub exit: Option<Exit>,
    pub gen_prefs: GenPrefs,
    pub wrong_reconfirms: u8,
    /// Where the key file is, for a vault that needs one (only the path).
    pub key_file: Option<PathBuf>,
    pub measurer: Measurer,
    /// Unlock times per level (index into `SecurityLevel::ALL`), measured
    /// the first time a level is shown.
    pub level_times: [Option<Timing>; 3],
}

impl App {
    pub fn new(
        uv: UnlockedVault,
        cfg: Config,
        config_path: Option<PathBuf>,
        lock_after: Duration,
        copier: Copier,
        now: Instant,
    ) -> App {
        let mut app = App {
            uv,
            cfg,
            config_path,
            lock_after,
            last_input: now,
            now,
            copier,
            size: (80, 24),
            tab: Tab::All,
            search: TextInput::new(false),
            searching: false,
            view: Vec::new(),
            sel: 0,
            top: Cell::new(0),
            reveal_until: None,
            screen: Screen::Main,
            modals: Vec::new(),
            toast: None,
            task: None,
            exit: None,
            gen_prefs: GenPrefs::default(),
            wrong_reconfirms: 0,
            key_file: None,
            measurer: Box::new(crypto::measure_unlock),
            level_times: Default::default(),
        };
        app.refilter();
        app
    }

    // ───────────────────────── key file and levels ─────────────────────────

    /// Read the key file when `required` (it is wiped when dropped).
    fn key_file_for(&self, required: bool) -> Result<Option<LoadedKeyFile>> {
        if !required {
            return Ok(None);
        }
        let path = self.key_file.as_ref().ok_or(Error::KeyFileRequired)?;
        keyfile::load(path).map(Some)
    }

    fn wrong_password_text(&self) -> &'static str {
        if self.uv.uses_key_file() {
            "Wrong master password (or key file). Try again."
        } else {
            "Wrong master password. Try again."
        }
    }

    /// Measure `level` (once) after the next frame, which says "Measuring…".
    pub fn request_measure(&mut self, level: SecurityLevel) {
        if self.level_times[level_index(level)].is_none() && self.task.is_none() {
            self.task = Some(Task::Measure(level));
        }
    }

    /// Whether `level` is being measured right now.
    pub fn measuring(&self, level: SecurityLevel) -> bool {
        matches!(self.task, Some(Task::Measure(l)) if l == level)
    }

    /// Show the messages from unlocking (warnings, an update) in a dialog.
    pub fn show_notices(&mut self, notices: Vec<Notice>) {
        if notices.is_empty() {
            return;
        }
        let warning = notices.iter().any(|n| n.warning);
        let lines = notices.into_iter().map(|n| n.text).collect();
        let title = if warning { "Please note" } else { "News" };
        self.modals.push(Modal::Message(Message::new(title, lines, warning)));
    }

    pub fn exit(&self) -> Option<Exit> {
        self.exit
    }

    pub fn lock_secs(&self) -> u64 {
        self.lock_after.as_secs()
    }

    /// Lock now because nobody typed anything for the lock timeout.
    pub fn lock_idle(&mut self) {
        self.reveal_until = None;
        self.exit.get_or_insert(Exit::Idle);
    }

    pub fn resize(&mut self, size: (u16, u16)) {
        self.size = size;
    }

    pub fn too_small(&self) -> bool {
        self.size.0 < MIN_WIDTH || self.size.1 < MIN_HEIGHT
    }

    /// Time passes: hide a revealed secret, drop an old message, lock.
    pub fn tick(&mut self, now: Instant) {
        self.now = now;
        if self.reveal_until.is_some_and(|t| now >= t) {
            self.reveal_until = None;
        }
        if self.toast.as_ref().is_some_and(|t| now >= t.until) {
            self.toast = None;
        }
        if now.saturating_duration_since(self.last_input) >= self.lock_after {
            self.lock_idle();
        }
    }

    /// How long the main loop may wait for a key before something changes on
    /// screen (at most a second, for the lock countdown).
    pub fn wait_ms(&self, now: Instant) -> i32 {
        let lock_at = self.last_input + self.lock_after;
        let mut next = [Some(lock_at), self.reveal_until, self.toast.as_ref().map(|t| t.until)]
            .into_iter()
            .flatten()
            .map(|t| t.saturating_duration_since(now))
            .min()
            .unwrap_or(Duration::from_secs(1))
            .min(Duration::from_secs(1));
        next = next.max(Duration::from_millis(10));
        next.as_millis() as i32
    }

    /// Seconds until the automatic lock.
    pub fn lock_left(&self, now: Instant) -> u64 {
        (self.last_input + self.lock_after).saturating_duration_since(now).as_secs()
    }

    // ───────────────────────── vault helpers ─────────────────────────

    pub fn key(&self) -> &ItemKey {
        self.uv.item_key()
    }

    pub fn entries(&self) -> &[Entry] {
        self.uv.vault.entries()
    }

    pub fn selected(&self) -> Option<&Entry> {
        self.view.get(self.sel).and_then(|&i| self.entries().get(i))
    }

    /// Recompute the list after a change of tab, search or vault, keeping the
    /// selected item selected when it is still there.
    pub fn refilter(&mut self) {
        let keep = self.selected().map(|e| e.name().to_string());
        let kind = self.tab.kind();
        let query = self.search.as_str().trim();
        let entries = self.uv.vault.entries();
        self.view = if query.is_empty() {
            (0..entries.len()).collect()
        } else {
            // Vault::search decides; both lists are in the same (sorted) order.
            let hits = self.uv.vault.search(query, self.uv.item_key());
            let mut hits = hits.into_iter().peekable();
            let mut out = Vec::new();
            for (i, e) in entries.iter().enumerate() {
                if hits.peek().is_some_and(|h| std::ptr::eq(*h, e)) {
                    hits.next();
                    out.push(i);
                }
            }
            out
        };
        self.view.retain(|&i| kind.is_none_or(|k| entries[i].kind() == k));
        match keep.and_then(|n| self.view.iter().position(|&i| entries[i].name() == n)) {
            Some(pos) => self.sel = pos,
            None => self.sel = self.sel.min(self.view.len().saturating_sub(1)),
        }
    }

    /// Select an item by name (after saving it), switching to "All" and
    /// clearing the search when needed to show it.
    pub fn select_name(&mut self, name: &str) {
        let find = |app: &App| app.view.iter().position(|&i| app.entries()[i].name() == name);
        if find(self).is_none() {
            self.tab = Tab::All;
            self.search.clear();
            self.searching = false;
            self.refilter();
        }
        if let Some(pos) = find(self) {
            self.sel = pos;
        }
    }

    /// Change the vault and save it. On any error the vault in memory is
    /// restored, so it always matches the file.
    pub fn commit(&mut self, change: impl FnOnce(&mut Vault, &ItemKey) -> Result<()>) -> Result<()> {
        let before = self.uv.vault.clone();
        let result = {
            let (vault, key) = self.uv.parts_mut();
            change(vault, key)
        }
        .and_then(|()| self.uv.save());
        if result.is_err() {
            self.uv.vault = before;
        }
        result
    }

    /// Handle a failed save. Another CakePass changed the file: offer to
    /// reload (the form stays filled in). Otherwise: the text to show.
    pub fn save_error(&mut self, e: Error) -> Option<String> {
        match e {
            Error::ConcurrentModification => {
                self.modals.push(Modal::Confirm(Confirm::new(
                    "Not saved",
                    vec![
                        "The vault was changed by another CakePass window in the meantime, so this \
                         change was NOT saved (nothing was lost)."
                            .into(),
                        "Reload the vault now? You type your master password again; what you \
                         entered stays as it is, so you can save it again afterwards."
                            .into(),
                    ],
                    "Reload",
                    "Not now",
                    true,
                    ConfirmAction::Reload,
                )));
                None
            }
            Error::EntryExists(n) => {
                Some(format!("An item named '{n}' already exists; choose another name."))
            }
            e => Some(error_text(&e)),
        }
    }

    // ───────────────────────── messages ─────────────────────────

    pub fn say(&mut self, style: Style, text: impl Into<String>) {
        let secs = if style == Style::ERROR { TOAST_SECS * 2 } else { TOAST_SECS };
        self.toast = Some(Toast {
            text: text.into(),
            style,
            until: self.now + Duration::from_secs(secs),
            clears_at: None,
        });
    }

    pub fn ok(&mut self, text: impl Into<String>) {
        self.say(Style::SUCCESS, text);
    }

    pub fn fail(&mut self, text: impl Into<String>) {
        self.say(Style::ERROR, text);
    }

    pub fn info(&mut self, text: impl Into<String>) {
        self.say(Style::PLAIN, text);
    }

    /// Put a secret on the clipboard and say so.
    pub fn copy_value(&mut self, value: &str, what: &str) {
        match (self.copier)(value) {
            Ok(tool) => {
                let clears = self.now + Duration::from_secs(CLEAR_AFTER_SECS);
                self.toast = Some(Toast {
                    text: format!("{what} copied ({tool})"),
                    style: Style::SUCCESS,
                    until: clears,
                    clears_at: Some(clears),
                });
            }
            Err(Error::NoClipboard) => {
                self.fail("No clipboard tool found: install wl-clipboard (Wayland) or xclip (X11).")
            }
            Err(e) => self.fail(format!("Copying failed: {}", error_text(&e))),
        }
    }

    /// Copy a field of the selected item.
    pub fn copy_field(&mut self, what: CopyWhat) {
        let Some(e) = self.selected() else { return };
        let (kind, key) = (e.kind(), self.uv.item_key());
        let (value, noun, missing) = match what {
            CopyWhat::Secret => {
                (e.secret(key), commands::secret_noun(kind), format!("no {}", kind.secret_label()))
            }
            CopyWhat::Username if kind == Kind::Note => return self.info("A note has no username."),
            CopyWhat::Username => {
                let noun = if kind == Kind::Api { "The account ID" } else { "The username" };
                (e.username(key), noun, "no username".to_string())
            }
            CopyWhat::Email if kind == Kind::Note => return self.info("A note has no e-mail address."),
            CopyWhat::Email => (e.email(key), "The e-mail address", "no e-mail address".to_string()),
        };
        match value {
            Ok(v) if v.is_empty() => self.info(format!("This item has {missing}.")),
            Ok(v) => self.copy_value(&v, noun),
            Err(e) => self.fail(error_text(&e)),
        }
    }

    // ───────────────────────── keys ─────────────────────────

    /// Handle one key press or paste.
    pub fn handle(&mut self, ev: Event, now: Instant) {
        self.now = now;
        self.last_input = now;
        prompt::mark_activity();
        if ev == Event::Key(Key::Ctrl('c')) {
            self.exit = Some(Exit::Quit);
            return;
        }
        if self.too_small() {
            if matches!(ev, Event::Key(Key::Char('q'))) {
                self.exit = Some(Exit::Quit);
            }
            return;
        }
        if self.task.is_some() {
            return; // busy with Argon2; the frame says so
        }
        if !self.modals.is_empty() {
            self.handle_modal(ev);
        } else {
            match self.screen {
                Screen::Main => self.handle_main(ev),
                Screen::Form(_) => self.handle_form(ev),
                Screen::Settings(_) => self.handle_settings(ev),
            }
        }
        // A secret is only ever revealed on the bare main screen.
        if !self.modals.is_empty() || !matches!(self.screen, Screen::Main) {
            self.reveal_until = None;
        }
    }

    fn handle_modal(&mut self, ev: Event) {
        let Some(top) = self.modals.last_mut() else { return };
        match top {
            Modal::Help(help) => {
                if let Event::Key(key) = ev
                    && help.handle(key)
                {
                    self.modals.pop();
                }
            }
            Modal::Message(_) => {
                if matches!(ev, Event::Key(Key::Esc | Key::Enter | Key::Char('q' | ' '))) {
                    self.modals.pop();
                }
            }
            Modal::Confirm(c) => {
                let Event::Key(key) = ev else { return };
                if let Some(yes) = c.handle(key)
                    && let Some(Modal::Confirm(c)) = self.modals.pop()
                {
                    self.confirmed(c.action, yes);
                }
            }
            Modal::Prompt(p) => match p.handle(ev) {
                Some(true) => {
                    if let Some(Modal::Prompt(p)) = self.modals.pop() {
                        self.prompt_submitted(p);
                    }
                }
                Some(false) => {
                    self.modals.pop();
                }
                None => {}
            },
            Modal::Generator(g) => {
                let Event::Key(key) = ev else { return };
                match g.handle(key) {
                    screens::generator::Action::None => {}
                    screens::generator::Action::Cancel => {
                        self.modals.pop();
                    }
                    screens::generator::Action::Help => {
                        self.modals.push(Modal::Help(Help::new(HelpPage::Generator)))
                    }
                    screens::generator::Action::Copy => {
                        let value = Zeroizing::new(g.value.to_string());
                        self.copy_value(&value, "The password");
                    }
                    screens::generator::Action::TypeOwn => self.modals.push(Modal::Prompt(Prompt::new(
                        "Your own password",
                        vec!["Type the password you want. It stays hidden; you type it twice.".into()],
                        "Password",
                        true,
                        PromptPurpose::OwnPassword,
                    ))),
                    screens::generator::Action::Accept => self.generator_accepted(),
                }
            }
        }
    }

    fn confirmed(&mut self, action: ConfirmAction, yes: bool) {
        match (action, yes) {
            (ConfirmAction::Delete(name), true) => match self.commit(|v, _| v.remove(&name)) {
                Ok(()) => {
                    self.refilter();
                    self.ok(format!("'{name}' deleted. (The previous version is still in the .bak backup.)"));
                }
                Err(e) => {
                    if let Some(t) = self.save_error(e) {
                        self.fail(t);
                    }
                }
            },
            (ConfirmAction::Delete(_), false) => self.info("Nothing deleted."),
            (ConfirmAction::Discard, true) => {
                self.screen = Screen::Main; // the form (and what was typed) is wiped
                self.info("Not saved.");
            }
            (ConfirmAction::Discard, false) => {}
            (ConfirmAction::Reload, true) => self.modals.push(Modal::Prompt(Prompt::new(
                "Reload the vault",
                vec!["Type your master password to read the vault again.".into()],
                "Master password",
                true,
                PromptPurpose::Reload,
            ))),
            (ConfirmAction::Reload, false) => {
                self.info("Not saved. Lock (l) and open CakePass again to see the other changes.")
            }
        }
    }

    fn prompt_submitted(&mut self, mut p: Prompt) {
        let text = Zeroizing::new(p.input.as_str().to_string());
        match std::mem::replace(&mut p.purpose, PromptPurpose::Reload) {
            PromptPurpose::SaveGenerated => {
                let Some(Modal::Generator(g)) = self.modals.last() else { return };
                let fields = cakepass::vault::NewEntry {
                    name: text.to_string(),
                    kind: Kind::Login,
                    password: g.value.to_string(),
                    ..Default::default()
                };
                match commands::add_entry(&mut self.uv, fields) {
                    Ok(name) => {
                        self.modals.pop();
                        self.refilter();
                        self.select_name(&name);
                        self.ok(format!(
                            "Login '{name}' saved (encrypted). Press e to add a username or URL."
                        ));
                    }
                    Err(e) => {
                        if let Some(t) = self.save_error(e) {
                            p.purpose = PromptPurpose::SaveGenerated;
                            p.error = Some(t);
                            self.modals.push(Modal::Prompt(p));
                        }
                    }
                }
            }
            PromptPurpose::OwnPassword => {
                if text.is_empty() {
                    return;
                }
                self.modals.push(Modal::Prompt(Prompt::new(
                    "Your own password",
                    vec!["Type it once more, to be sure there is no typo.".into()],
                    "Repeat",
                    true,
                    PromptPurpose::OwnPasswordRepeat(text),
                )));
            }
            PromptPurpose::OwnPasswordRepeat(first) => {
                let same = same_secret(&first, &text);
                if let Some(Modal::Generator(g)) = self.modals.last_mut() {
                    if same {
                        g.set_own(&first);
                    } else {
                        g.note = Some((Style::ERROR, "The passwords do not match; nothing changed.".into()));
                    }
                }
            }
            PromptPurpose::Reconfirm => {
                p.purpose = PromptPurpose::Reconfirm;
                p.busy = Some("Checking the master password…");
                self.modals.push(Modal::Prompt(p));
                self.task = Some(Task::Reconfirm(text));
            }
            PromptPurpose::NewMaster => {
                let problem = if text.is_empty() {
                    Some("The password must not be empty.".to_string())
                } else if text.len() > 1024 {
                    Some("The password is too long (max. 1024 bytes).".to_string())
                } else {
                    let (score, advice) = prompt::strength(&text);
                    (score < prompt::MIN_SCORE).then(|| {
                        let mut t = format!(
                            "Too weak (strength {score}/4, at least {} needed). Tip: 5 or more random words.",
                            prompt::MIN_SCORE
                        );
                        if let Some(a) = advice {
                            t = format!("{a} {t}");
                        }
                        t
                    })
                };
                match problem {
                    Some(t) => {
                        p.purpose = PromptPurpose::NewMaster;
                        p.input.clear();
                        p.error = Some(t);
                        self.modals.push(Modal::Prompt(p));
                    }
                    None => self.modals.push(Modal::Prompt(Prompt::new(
                        "Change the master password",
                        vec!["Type the new master password once more.".into()],
                        "Repeat",
                        true,
                        PromptPurpose::RepeatMaster(text),
                    ))),
                }
            }
            PromptPurpose::RepeatMaster(first) => {
                if same_secret(&first, &text) {
                    p.purpose = PromptPurpose::RepeatMaster(Zeroizing::new(String::new()));
                    p.busy = Some("Changing the master password (this takes a moment)…");
                    self.modals.push(Modal::Prompt(p));
                    self.task = Some(Task::ChangePassword(first));
                } else {
                    let mut again = new_master_prompt();
                    again.error = Some("The passwords do not match. Choose the new password again.".into());
                    self.modals.push(Modal::Prompt(again));
                }
            }
            PromptPurpose::Reload => {
                p.purpose = PromptPurpose::Reload;
                p.busy = Some("Reading the vault…");
                self.modals.push(Modal::Prompt(p));
                self.task = Some(Task::Reload(text));
            }
            PromptPurpose::ConfirmLevel(level) => {
                p.purpose = PromptPurpose::ConfirmLevel(level);
                p.busy = Some("Re-encrypting the vault at the new level (this takes a moment)…");
                self.modals.push(Modal::Prompt(p));
                self.task = Some(Task::ChangeLevel(text, level));
            }
        }
    }

    fn generator_accepted(&mut self) {
        let Some(Modal::Generator(g)) = self.modals.last() else { return };
        self.gen_prefs = g.prefs.clone();
        match g.target {
            GenTarget::Form => {
                let Some(Modal::Generator(g)) = self.modals.pop() else { return };
                let text = commands::strength_text(&g.value, g.bits);
                if let Screen::Form(f) = &mut self.screen {
                    f.set_secret(&g.value);
                }
                self.ok(format!("Password filled in ({text}). Ctrl+R shows it."));
            }
            GenTarget::NewLogin => self.modals.push(Modal::Prompt(Prompt::new(
                "Save as a new login",
                vec!["Give the new login a name, e.g. GitHub. You can add the username later (e).".into()],
                "Name",
                false,
                PromptPurpose::SaveGenerated,
            ))),
        }
    }

    /// Run the slow work queued by a dialog. Returns whether there was any.
    pub fn run_task(&mut self) -> bool {
        let Some(task) = self.task.take() else { return false };
        if let Task::Measure(level) = task {
            let timing = (self.measurer)(&level.params()).map_err(|e| error_text(&e));
            self.level_times[level_index(level)] = Some(timing);
            return true;
        }
        // The prompt that queued the task is on top; it is replaced or updated.
        let mut top = match self.modals.pop() {
            Some(Modal::Prompt(p)) => p,
            Some(other) => {
                self.modals.push(other);
                return true;
            }
            None => return true,
        };
        top.busy = None;
        match task {
            Task::Measure(_) => unreachable!("handled above"),
            Task::Reconfirm(pw) => match self.check_password(&pw) {
                Ok(true) => {
                    self.wrong_reconfirms = 0;
                    self.modals.push(Modal::Prompt(new_master_prompt()));
                }
                Ok(false) => self.wrong_password(top, "the master password was not changed"),
                Err(e) => self.check_failed(top, &e),
            },
            Task::ChangeLevel(pw, level) => match self.check_password(&pw) {
                Ok(true) => {
                    self.wrong_reconfirms = 0;
                    self.change_level(&pw, level);
                }
                Ok(false) => self.wrong_password(top, "the security level was not changed"),
                Err(e) => self.check_failed(top, &e),
            },
            Task::ChangePassword(new) => {
                let kdf = self.uv.kdf();
                // The key file (if any) stays: it is part of the new key too.
                let changed = self.key_file_for(self.uv.uses_key_file()).and_then(|kf| {
                    self.uv.rekey(Credentials::new(new.as_bytes(), kf.as_ref().map(|k| &k.pepper)), kdf)
                });
                match changed {
                    Ok(()) => self.modals.push(Modal::Message(Message::new(
                        "Master password changed",
                        vec![
                            "All items and the .bak backup now use the new master password.".into(),
                            "Copies and exports you made yourself earlier still open with the OLD \
                             password. Delete them if you think the old password has leaked."
                                .into(),
                        ],
                        false,
                    ))),
                    Err(e) => {
                        let mut lines =
                            vec![format!("The master password was NOT changed: {}", error_text(&e))];
                        if matches!(e, Error::ConcurrentModification) {
                            lines.push("Lock (l), open CakePass again and try once more.".into());
                        }
                        self.modals.push(Modal::Message(Message::new("Not changed", lines, true)));
                    }
                }
            }
            Task::Reload(pw) => match self.reopen(&pw) {
                Ok(mut fresh) => {
                    fresh.take_warnings();
                    self.uv = fresh; // the old copy (and its key) is wiped
                    self.refilter();
                    let hint = if matches!(self.screen, Screen::Form(_)) {
                        " Your form is still filled in: press Ctrl+S to save it."
                    } else {
                        ""
                    };
                    self.ok(format!("Vault reloaded.{hint}"));
                }
                Err(Error::Decrypt) => {
                    top.input.clear();
                    top.error = Some(self.wrong_password_text().into());
                    self.modals.push(Modal::Prompt(top));
                }
                Err(e) => self.modals.push(Modal::Message(Message::new(
                    "Could not reload",
                    vec![error_text(&e)],
                    true,
                ))),
            },
        }
        true
    }

    /// Check the master password (with the key file, if the vault has one).
    fn check_password(&self, pw: &str) -> Result<bool> {
        let kf = self.key_file_for(self.uv.uses_key_file())?;
        self.uv.verify_password(Credentials::new(pw.as_bytes(), kf.as_ref().map(|k| &k.pepper)))
    }

    /// The re-check itself failed. A key file problem (USB stick not plugged
    /// in, ...) gets a dialog of its own: its text is too long for the field.
    fn check_failed(&mut self, mut top: Prompt, e: &Error) {
        if matches!(e, Error::KeyFileRequired | Error::KeyFileUnreadable { .. } | Error::KeyFileInvalid(_)) {
            self.modals.push(Modal::Message(Message::new(
                "Key file needed",
                vec![error_text(e), "Nothing was changed.".into()],
                true,
            )));
        } else {
            top.error = Some(error_text(e));
            self.modals.push(Modal::Prompt(top));
        }
    }

    /// A wrong password in a re-check: try again, at most three times.
    fn wrong_password(&mut self, mut top: Prompt, what: &str) {
        self.wrong_reconfirms += 1;
        if self.wrong_reconfirms >= 3 {
            self.wrong_reconfirms = 0;
            self.fail(format!("Wrong master password; {what}."));
        } else {
            top.input.clear();
            top.error = Some(self.wrong_password_text().into());
            self.modals.push(Modal::Prompt(top));
        }
    }

    /// Read the vault from disk again (its key file too, if it needs one now).
    fn reopen(&self, pw: &str) -> Result<UnlockedVault> {
        let header = storage::read_header(&self.uv.paths().file)?;
        let kf = self.key_file_for(header.key_file)?;
        UnlockedVault::open(
            self.uv.paths().clone(),
            Credentials::new(pw.as_bytes(), kf.as_ref().map(|k| &k.pepper)),
        )
    }

    /// Re-key at `level` with the same password and key file (already checked).
    fn change_level(&mut self, pw: &str, level: SecurityLevel) {
        let start = Instant::now();
        let changed = self.key_file_for(self.uv.uses_key_file()).and_then(|kf| {
            self.uv.rekey(Credentials::new(pw.as_bytes(), kf.as_ref().map(|k| &k.pepper)), level.params())
        });
        let message = match changed {
            Ok(()) => Message::new(
                "Security level changed",
                vec![
                    format!("The vault now uses the {} level: {}.", level.title(), level.params().describe()),
                    format!("Unlocking takes about {} on this computer.", commands::seconds(start.elapsed())),
                    "Your master password did not change. The .bak backup was re-encrypted as well.".into(),
                ],
                false,
            ),
            Err(e) => Message::new(
                "Not changed",
                vec![format!("The security level was NOT changed: {}", error_text(&e))],
                true,
            ),
        };
        self.modals.push(Modal::Message(message));
    }

    /// Enter on the security level row: ask for the master password first.
    pub fn confirm_level(&mut self, level: SecurityLevel) {
        if self.uv.security_level() == Some(level) {
            return self.info(format!("The vault already uses the {} level.", level.title()));
        }
        if let Err(e) = crypto::ensure_memory(&level.params(), crypto::MemoryUse::Create) {
            return self.fail(error_text(&e));
        }
        let time = match &self.level_times[level_index(level)] {
            Some(Ok(d)) => format!(" Unlocking will take about {} on this computer.", commands::seconds(*d)),
            _ => String::new(),
        };
        self.modals.push(Modal::Prompt(Prompt::new(
            "Change the security level",
            vec![
                format!("Switch to {}: {}.{time}", level.title(), level.params().describe()),
                "Type your current master password to confirm. The vault and its .bak backup are \
                 re-encrypted with a fresh salt; the password itself stays the same."
                    .into(),
            ],
            "Current",
            true,
            PromptPurpose::ConfirmLevel(level),
        )));
    }

    // ───────────────────────── drawing ─────────────────────────

    /// Draw the whole screen for this moment.
    pub fn draw(&self, g: &mut Grid, now: Instant) {
        if g.width() < MIN_WIDTH || g.height() < MIN_HEIGHT {
            draw_too_small(g);
            return;
        }
        let hints: Vec<Hint> = match &self.screen {
            Screen::Main => self.draw_main(g, now),
            Screen::Form(f) => self.draw_form(g, f, now),
            Screen::Settings(s) => self.draw_settings(g, s, now),
        };
        let mut hints = hints;
        let area = Rect::new(0, 1, g.width(), g.height().saturating_sub(3));
        for m in &self.modals {
            g.set_cursor(None);
            hints = match m {
                Modal::Help(help) => help.draw(g, area),
                Modal::Message(msg) => msg.draw(g, area),
                Modal::Confirm(c) => c.draw(g, area),
                Modal::Prompt(p) => p.draw(g, area),
                Modal::Generator(gn) => gn.draw(g, area),
            };
        }
        screens::status_line(g, self, now);
        screens::hint_bar(g, &hints);
    }
}

/// The position of `level` in `SecurityLevel::ALL` (and `App::level_times`).
pub fn level_index(level: SecurityLevel) -> usize {
    SecurityLevel::ALL.iter().position(|&l| l == level).unwrap_or(0)
}

/// The new-master-password question (after the current one was confirmed).
fn new_master_prompt() -> Prompt {
    Prompt::new(
        "Change the master password",
        vec![
            "Choose a new master password: strong (score 3 of 4 or more), for example 5 or more random \
             words. Forgotten = everything lost."
                .into(),
        ],
        "New password",
        true,
        PromptPurpose::NewMaster,
    )
}

fn draw_too_small(g: &mut Grid) {
    let (w, h) = (g.width(), g.height());
    let lines = [
        "Terminal too small".to_string(),
        format!("CakePass needs at least {MIN_WIDTH}×{MIN_HEIGHT}; this window is {w}×{h}."),
        "Make the window bigger, or press q to quit.".to_string(),
    ];
    let mut wrapped = Vec::new();
    for l in &lines {
        wrapped.extend(wrap(l, w.max(1) as usize));
    }
    let top = h.saturating_sub(wrapped.len() as u16) / 2;
    for (i, l) in wrapped.iter().enumerate() {
        let style = if i == 0 { Style::ACCENT_BOLD } else { Style::PLAIN };
        let x = w.saturating_sub(super::grid::str_width(l) as u16) / 2;
        g.print(x, top + i as u16, w - x, l, style);
    }
}

/// An error as a sentence for the screen (never contains a secret; see error.rs).
pub fn error_text(e: &Error) -> String {
    let text = match e {
        Error::InvalidInput(m) => commands::capitalize(m),
        e => commands::capitalize(&e.to_string()),
    };
    if text.ends_with(['.', '!', '?']) { text } else { text + "." }
}

/// Compare two typed passwords in constant time.
fn same_secret(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests;
