//! The screen mode driven with synthetic keys against a real temporary
//! vault; afterwards the vault on disk is checked with the library.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use cakepass::crypto::{KdfParams, KeyFilePepper, SecurityLevel};
use cakepass::format::Credentials;
use cakepass::storage::{UnlockedVault, VaultPaths};
use cakepass::vault::{Entry, Kind, NewEntry};

use super::super::grid::Grid;
use super::super::keys::{Event, Key};
use super::super::theme::{ASCII, UNICODE};
use super::*;

const PW: &str = "tq8#vLp2!mZr9wXe";
const PW2: &str = "grape-lantern-oyster-bulky-scenic-dwarf";
const FAST: KdfParams = KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 };

struct T {
    dir: tempfile::TempDir,
    app: App,
    clip: Rc<RefCell<Vec<String>>>,
    now: Instant,
}

fn paths(dir: &tempfile::TempDir) -> VaultPaths {
    VaultPaths::for_file(dir.path().join("vault.enc"))
}

fn add(uv: &mut UnlockedVault, name: &str, kind: Kind, user: &str, secret: &str, notes: &str) {
    let fields = NewEntry {
        name: name.into(),
        kind,
        username: user.into(),
        email: if kind == Kind::Note { String::new() } else { format!("{user}@example.org") },
        password: secret.into(),
        url: if kind == Kind::Note { String::new() } else { "https://example.org".into() },
        notes: notes.into(),
        tags: vec!["work".into()],
    };
    commands::add_entry(uv, fields).unwrap();
}

impl T {
    fn new() -> T {
        T::with(|_| {})
    }

    fn with(fill: impl FnOnce(&mut UnlockedVault)) -> T {
        let dir = tempfile::tempdir().unwrap();
        let mut uv = UnlockedVault::create(paths(&dir), Credentials::password(PW.as_bytes()), FAST).unwrap();
        fill(&mut uv);
        let clip = Rc::new(RefCell::new(Vec::new()));
        let log = clip.clone();
        let copier: Copier = Box::new(move |s: &str| {
            log.borrow_mut().push(s.to_string());
            Ok("test-clipboard")
        });
        let now = Instant::now();
        let cfg_path = dir.path().join("config");
        let mut app = App::new(uv, Config::default(), Some(cfg_path), Duration::from_secs(300), copier, now);
        app.resize((80, 24));
        // Never run Argon2 at a real level just to show a time: 1 ms per 256 KiB.
        app.measurer = Box::new(|p: &KdfParams| Ok(Duration::from_millis(u64::from(p.memory_kib) / 256)));
        T { dir, app, clip, now }
    }

    fn sample() -> T {
        T::with(|uv| {
            add(uv, "GitHub", Kind::Login, "john", "gh-Secret-1", "gh note");
            add(uv, "OpenAI", Kind::Api, "proj-1", "sk-test-42", "");
            add(uv, "Recovery codes", Kind::Note, "", "", "Code 1: 7731\nCode 2: 9921");
        })
    }

    fn later(&mut self, secs: u64) {
        self.now += Duration::from_secs(secs);
        self.app.tick(self.now);
    }

    fn key(&mut self, k: Key) {
        self.app.handle(Event::Key(k), self.now);
        while self.app.run_task() {}
        self.app.tick(self.now);
    }

    fn keys(&mut self, ks: &[Key]) {
        for &k in ks {
            self.key(k);
        }
    }

    fn typ(&mut self, text: &str) {
        for c in text.chars() {
            self.key(Key::Char(c));
        }
    }

    fn paste(&mut self, text: &str) {
        self.app.handle(Event::Paste(Zeroizing::new(text.into())), self.now);
    }

    fn screen_at(&self, w: u16, h: u16) -> String {
        let mut g = Grid::new(w, h, &UNICODE);
        self.app.draw(&mut g, self.now);
        g.text()
    }

    fn screen(&self) -> String {
        self.screen_at(80, 24)
    }

    /// The vault as it is on disk now.
    fn reopen(&self, pw: &str) -> UnlockedVault {
        UnlockedVault::open(paths(&self.dir), Credentials::password(pw.as_bytes())).unwrap()
    }

    fn toast(&self) -> String {
        self.app.toast.as_ref().map(|t| t.text.clone()).unwrap_or_default()
    }
}

fn get<'a>(uv: &'a UnlockedVault, name: &str) -> &'a Entry {
    uv.vault.get(name).unwrap_or_else(|| panic!("{name} not in the vault"))
}

#[test]
fn empty_vault_shows_how_to_start() {
    let t = T::new();
    let s = t.screen();
    assert!(s.contains("Your vault is empty."), "{s}");
    assert!(s.contains("Press a to add your first item"));
    assert!(s.contains("locks in 5:00"));
    assert!(s.lines().last().unwrap().contains("? help"), "the key hints are on the last line");
}

#[test]
fn list_details_and_secrets_masked() {
    let t = T::sample();
    let s = t.screen();
    for text in
        ["GitHub", "OpenAI", "Recovery codes", "john", "john@example.org", "https://example.org", "••••••••"]
    {
        assert!(s.contains(text), "{text} missing:\n{s}");
    }
    for secret in ["gh-Secret-1", "gh note", "sk-test-42", "7731"] {
        assert!(!s.contains(secret), "{secret} is visible without revealing:\n{s}");
    }
    assert!(s.contains("All 3") && s.contains("Logins 1") && s.contains("API keys 1"));
}

#[test]
fn add_a_login_with_the_form() {
    let mut t = T::new();
    t.key(Key::Char('a'));
    assert!(matches!(t.app.screen, Screen::Form(_)));
    t.typ("Bank");
    t.key(Key::Down); // Type
    t.key(Key::Down);
    t.typ("jane");
    t.key(Key::Tab);
    t.typ("jane@bank.example");
    t.key(Key::Down);
    t.typ("https://bank.example");
    t.key(Key::Down);
    t.typ("money, home");
    t.key(Key::Down);
    t.typ("P4ss-wörd!");
    let s = t.screen();
    assert!(s.contains("••••••••••") && !s.contains("P4ss"), "the password is masked while typing:\n{s}");
    t.key(Key::Ctrl('r'));
    assert!(t.screen().contains("P4ss-wörd!"), "Ctrl+R shows it");
    t.key(Key::Down);
    t.typ("line one");
    t.key(Key::Enter); // a new line inside the notes
    t.typ("line two");
    t.key(Key::Ctrl('s'));
    assert!(matches!(t.app.screen, Screen::Main));
    assert_eq!(t.toast(), "Login 'Bank' saved (encrypted).");
    assert_eq!(t.app.selected().unwrap().name(), "Bank");

    let uv = t.reopen(PW);
    let e = get(&uv, "bank");
    let k = uv.item_key();
    assert_eq!(e.kind(), Kind::Login);
    assert_eq!(e.username(k).unwrap().as_str(), "jane");
    assert_eq!(e.email(k).unwrap().as_str(), "jane@bank.example");
    assert_eq!(e.url(k).unwrap().as_str(), "https://bank.example");
    assert_eq!(e.password(k).unwrap().as_str(), "P4ss-wörd!");
    assert_eq!(e.notes(k).unwrap().as_str(), "line one\nline two");
    assert_eq!(e.tags(), ["money", "home"]);
}

#[test]
fn add_an_api_key_by_pasting_and_a_note() {
    let mut t = T::new();
    t.key(Key::Char('n'));
    t.typ("Stripe");
    t.key(Key::Down);
    t.key(Key::Right); // login → API key
    for _ in 0..5 {
        t.key(Key::Down); // account, e-mail, URL, tags, API key
    }
    // Shortcut letters and Enter inside a paste are just text.
    t.paste("sk_live_qd\n");
    t.key(Key::Ctrl('s'));
    assert_eq!(t.toast(), "API key 'Stripe' saved (encrypted).");
    // A note hides the login fields.
    t.key(Key::Char('a'));
    t.typ("Wifi");
    t.key(Key::Down);
    t.key(Key::Left); // login → note
    t.key(Key::Down); // tags
    t.key(Key::Down); // content
    assert!(!t.screen().contains("Username"));
    t.typ("ssid: home");
    t.key(Key::Enter);
    t.typ("pass: 1234");
    t.key(Key::Ctrl('s'));
    let uv = t.reopen(PW);
    assert_eq!(get(&uv, "stripe").kind(), Kind::Api);
    assert_eq!(get(&uv, "stripe").password(uv.item_key()).unwrap().as_str(), "sk_live_qd");
    assert_eq!(get(&uv, "wifi").kind(), Kind::Note);
    assert_eq!(get(&uv, "wifi").notes(uv.item_key()).unwrap().as_str(), "ssid: home\npass: 1234");
}

#[test]
fn form_errors_are_shown_and_the_form_stays() {
    let mut t = T::sample();
    t.key(Key::Char('a'));
    t.key(Key::Ctrl('s'));
    assert!(t.screen().contains("Give the item a name."));
    t.typ("github"); // exists already (names are case-insensitive)
    t.keys(&[Key::Down, Key::Down]);
    t.typ("x");
    t.keys(&[Key::Down, Key::Down, Key::Down, Key::Down]);
    t.key(Key::Ctrl('s'));
    assert!(t.screen().contains("The password is empty"), "{}", t.screen());
    t.typ("pw");
    t.key(Key::Ctrl('s'));
    assert!(t.screen().contains("already exists"), "{}", t.screen());
    let Screen::Form(f) = &t.app.screen else { panic!("the form closed") };
    assert_eq!(f.focus, super::super::screens::form::Field::Name, "the name field gets the focus");
    assert_eq!(f.user.as_str(), "x", "what was typed is kept");
    // A control character never gets in (the library would refuse it too).
    t.paste("bad\u{1b}[2Jname");
    let Screen::Form(f) = &t.app.screen else { panic!() };
    assert_eq!(f.name.as_str(), "githubbad[2Jname");
    assert_eq!(t.reopen(PW).vault.len(), 3, "nothing saved");
}

#[test]
fn edit_keeps_or_replaces_the_password() {
    let mut t = T::sample();
    t.key(Key::Char('e'));
    let s = t.screen();
    assert!(s.contains("(unchanged)") && !s.contains("gh-Secret-1"), "{s}");
    assert!(s.contains("john@example.org"), "the form is filled in");
    t.keys(&[Key::Down]); // name → username (type is skipped when editing)
    t.key(Key::Ctrl('u'));
    t.typ("pete");
    t.key(Key::Ctrl('s'));
    assert_eq!(t.toast(), "Item 'GitHub' updated.");
    let uv = t.reopen(PW);
    let k = uv.item_key();
    assert_eq!(get(&uv, "github").username(k).unwrap().as_str(), "pete");
    assert_eq!(get(&uv, "github").password(k).unwrap().as_str(), "gh-Secret-1", "unchanged");
    assert_eq!(get(&uv, "github").notes(k).unwrap().as_str(), "gh note");
    drop(uv);
    // Typing in the (hidden) password field replaces the old password.
    t.key(Key::Char('e'));
    t.keys(&[Key::Down, Key::Down, Key::Down, Key::Down, Key::Down]);
    t.typ("new-pass-9");
    t.key(Key::BackTab);
    t.key(Key::BackTab);
    t.key(Key::BackTab);
    t.key(Key::BackTab);
    t.key(Key::BackTab); // back to the name
    t.key(Key::End);
    t.typ(" Work");
    t.key(Key::Ctrl('s'));
    assert_eq!(t.toast(), "Item 'GitHub Work' updated.");
    let uv = t.reopen(PW);
    assert_eq!(get(&uv, "github work").password(uv.item_key()).unwrap().as_str(), "new-pass-9");
    assert!(uv.vault.get("github").is_none(), "renamed");
    // Saving without changes changes nothing.
    t.key(Key::Char('e'));
    t.key(Key::Ctrl('s'));
    assert_eq!(t.toast(), "Nothing changed.");
}

#[test]
fn cancelling_with_changes_asks_first() {
    let mut t = T::sample();
    t.key(Key::Char('a'));
    t.key(Key::Esc);
    assert!(matches!(t.app.screen, Screen::Main), "nothing typed: closes at once");
    t.key(Key::Char('a'));
    t.typ("Draft");
    t.key(Key::Esc);
    assert!(t.screen().contains("Close the form without saving?"));
    t.key(Key::Enter); // default: keep editing
    assert!(matches!(t.app.screen, Screen::Form(_)));
    t.key(Key::Esc);
    t.key(Key::Char('y'));
    assert!(matches!(t.app.screen, Screen::Main));
    assert!(t.reopen(PW).vault.get("draft").is_none());
}

#[test]
fn delete_asks_and_defaults_to_no() {
    let mut t = T::sample();
    t.key(Key::Char('d'));
    assert!(t.screen().contains("Delete the login 'GitHub'?"));
    t.key(Key::Enter);
    assert_eq!(t.toast(), "Nothing deleted.");
    t.key(Key::Delete);
    t.key(Key::Right);
    t.key(Key::Enter);
    assert!(t.toast().starts_with("'GitHub' deleted."), "{}", t.toast());
    assert_eq!(t.app.selected().unwrap().name(), "OpenAI", "the next item is selected");
    let uv = t.reopen(PW);
    assert!(uv.vault.get("github").is_none());
    assert_eq!(uv.vault.len(), 2);
}

#[test]
fn search_and_tabs_filter_the_list() {
    let mut t = T::sample();
    t.key(Key::Char('/'));
    t.typ("open");
    assert_eq!(t.app.view.len(), 1);
    assert_eq!(t.app.selected().unwrap().name(), "OpenAI");
    assert!(t.screen().contains("1 of 3 items match \"open\""));
    t.key(Key::Enter); // done typing; the filter stays, shortcuts work again
    t.key(Key::Esc);
    assert_eq!(t.app.view.len(), 3, "Esc clears the search");
    // Searching looks at usernames and e-mail addresses, never at secrets.
    t.typ("Jo");
    assert!(t.app.searching, "a capital (not a shortcut) starts the search");
    assert_eq!(t.app.view.len(), 1);
    assert_eq!(t.app.selected().unwrap().name(), "GitHub", "found by its username");
    t.key(Key::Ctrl('u'));
    t.typ("sk-test");
    assert!(t.app.view.is_empty() && t.screen().contains("No items match."));
    t.key(Key::Esc);
    // Tabs.
    t.key(Key::Right);
    assert_eq!(t.app.tab, Tab::Logins);
    assert_eq!(t.app.view.len(), 1);
    t.keys(&[Key::Right, Key::Right]);
    assert_eq!(t.app.tab, Tab::Notes);
    assert_eq!(t.app.selected().unwrap().name(), "Recovery codes");
    t.key(Key::Right);
    assert_eq!(t.app.tab, Tab::All);
    // Pasting outside the search does nothing at all.
    t.paste("dq");
    assert!(matches!(t.app.screen, Screen::Main) && t.app.modals.is_empty() && t.app.exit.is_none());
}

#[test]
fn reveal_hides_itself() {
    let mut t = T::sample();
    t.key(Key::Enter);
    let s = t.screen();
    assert!(s.contains("gh-Secret-1") && s.contains("gh note") && s.contains("Hides in 10 s"), "{s}");
    t.later(5);
    assert!(t.screen().contains("gh-Secret-1"));
    t.later(6);
    assert!(!t.screen().contains("gh-Secret-1"), "hidden after 10 s");
    // A new selection hides it too.
    t.key(Key::Char('v'));
    t.key(Key::Down);
    assert!(t.app.reveal_until.is_none());
    assert!(!t.screen().contains("gh-Secret-1") && !t.screen().contains("sk-test-42"));
    // And so does opening a dialog or another screen.
    t.key(Key::Char('v'));
    assert!(t.screen().contains("sk-test-42"));
    t.key(Key::Char('?'));
    assert!(t.app.reveal_until.is_none());
    t.key(Key::Esc);
    // A note shows its lines.
    t.key(Key::Down);
    t.key(Key::Enter);
    let s = t.screen();
    assert!(s.contains("Code 1: 7731") && s.contains("Code 2: 9921"), "{s}");
    t.key(Key::Enter);
    assert!(!t.screen().contains("7731"), "Enter hides it again");
}

#[test]
fn copying_fields() {
    let mut t = T::sample();
    t.key(Key::Char('c'));
    t.key(Key::Char('u'));
    t.key(Key::Char('m'));
    assert_eq!(*t.clip.borrow(), ["gh-Secret-1", "john", "john@example.org"]);
    assert_eq!(t.toast(), "The e-mail address copied (test-clipboard)");
    assert!(t.screen().contains("the clipboard is cleared in 20 s"));
    t.later(3);
    assert!(t.screen().contains("cleared in 17 s"));
    t.keys(&[Key::Down, Key::Down]);
    t.key(Key::Char('c'));
    assert_eq!(t.clip.borrow().last().unwrap(), "Code 1: 7731\nCode 2: 9921", "c copies a note");
    t.key(Key::Char('u'));
    assert_eq!(t.toast(), "A note has no username.");
}

#[test]
fn generator_saves_a_new_login() {
    let mut t = T::new();
    t.key(Key::Char('g'));
    assert!(t.screen().contains("Password generator"));
    assert!(t.screen().contains("24 characters"));
    t.keys(&[Key::Down, Key::Right, Key::Right]); // length 26
    let shown = {
        t.key(Key::Char('v'));
        let Some(Modal::Generator(g)) = t.app.modals.last() else { panic!() };
        g.value.to_string()
    };
    assert_eq!(shown.chars().count(), 26);
    assert!(t.screen().contains(&shown), "v shows it");
    t.key(Key::Char('c'));
    assert_eq!(t.clip.borrow().last().unwrap(), &shown);
    t.key(Key::Enter);
    assert!(t.screen().contains("Save as a new login"));
    t.key(Key::Esc); // back to the generator, the password is kept
    t.key(Key::Enter);
    t.typ("Router");
    t.key(Key::Enter);
    assert!(t.app.modals.is_empty());
    assert!(t.toast().starts_with("Login 'Router' saved"), "{}", t.toast());
    let uv = t.reopen(PW);
    assert_eq!(get(&uv, "router").password(uv.item_key()).unwrap().as_str(), shown);
    // The settings are remembered for the next time.
    assert_eq!(t.app.gen_prefs.password.length, 26);
}

#[test]
fn generator_inside_the_form_and_own_password() {
    let mut t = T::new();
    t.key(Key::Char('a'));
    t.typ("Mail");
    t.key(Key::Ctrl('g'));
    t.key(Key::Char('e'));
    t.typ("Own-Choice-77");
    t.key(Key::Enter);
    t.typ("Own-Choice-78");
    t.key(Key::Enter);
    assert!(t.screen().contains("do not match"), "{}", t.screen());
    t.key(Key::Char('e'));
    t.typ("Own-Choice-77");
    t.key(Key::Enter);
    t.typ("Own-Choice-77");
    t.key(Key::Enter);
    t.key(Key::Enter); // use it
    assert!(t.toast().starts_with("Password filled in (13 characters, strength"), "{}", t.toast());
    t.key(Key::Ctrl('s'));
    let uv = t.reopen(PW);
    assert_eq!(get(&uv, "mail").password(uv.item_key()).unwrap().as_str(), "Own-Choice-77");
}

#[test]
fn settings_are_saved() {
    let mut t = T::new();
    t.key(Key::Char('s'));
    assert!(t.screen().contains("Startup animation") && t.screen().contains("8 MiB, 1 iterations"));
    t.key(Key::Right);
    assert!(!t.app.cfg.animation);
    t.key(Key::Down);
    t.keys(&[Key::Right, Key::Right, Key::PageUp]);
    assert_eq!(t.app.cfg.lock_timeout_minutes, 17);
    assert_eq!(t.app.lock_secs(), 17 * 60, "the new time counts at once");
    for _ in 0..10 {
        t.key(Key::PageDown);
    }
    assert_eq!(t.app.cfg.lock_timeout_minutes, 1, "never below one minute");
    let saved = crate::cli::config::load_from(&t.dir.path().join("config"));
    assert_eq!(saved, Config { animation: false, lock_timeout_minutes: 1, keyfile: None });
    t.key(Key::Esc);
    assert!(matches!(t.app.screen, Screen::Main));
}

#[test]
fn change_the_master_password() {
    let mut t = T::sample();
    t.key(Key::Char('s'));
    t.keys(&[Key::Down, Key::Down, Key::Enter]);
    assert!(t.screen().contains("current master password"));
    t.typ("wrong");
    assert!(t.screen().contains("•••••") && !t.screen().contains("wrong"), "hidden input");
    t.key(Key::Enter);
    assert!(t.screen().contains("Wrong master password"), "{}", t.screen());
    t.typ(PW);
    t.key(Key::Enter);
    assert!(t.screen().contains("Choose a new master password"), "{}", t.screen());
    t.typ("password123");
    t.key(Key::Enter);
    assert!(t.screen().contains("Too weak"), "{}", t.screen());
    t.typ(PW2);
    t.key(Key::Enter);
    t.typ(PW2);
    t.key(Key::Enter);
    assert!(t.screen().contains("Master password changed"), "{}", t.screen());
    t.key(Key::Enter);
    assert!(UnlockedVault::open(paths(&t.dir), Credentials::password(PW.as_bytes())).is_err());
    let uv = t.reopen(PW2);
    assert_eq!(get(&uv, "github").password(uv.item_key()).unwrap().as_str(), "gh-Secret-1");
    // The open vault keeps working with the new key.
    t.key(Key::Esc);
    t.key(Key::Char('d'));
    t.key(Key::Char('y'));
    assert_eq!(t.reopen(PW2).vault.len(), 2);
}

#[test]
fn locks_after_the_idle_time() {
    let mut t = T::sample();
    t.later(200);
    assert!(t.app.exit().is_none());
    assert!(t.screen().contains("locks in 1:40"));
    t.key(Key::Down); // any key resets the timer
    t.later(299);
    assert!(t.app.exit().is_none());
    t.later(1);
    assert_eq!(t.app.exit(), Some(Exit::Idle));
    assert!(t.app.reveal_until.is_none());
}

#[test]
fn quit_and_lock_keys() {
    let mut t = T::sample();
    t.key(Key::Char('q'));
    assert_eq!(t.app.exit(), Some(Exit::Quit));
    let mut t = T::sample();
    t.key(Key::Char('l'));
    assert_eq!(t.app.exit(), Some(Exit::Lock));
    let mut t = T::sample();
    t.key(Key::Char('a'));
    t.typ("q");
    assert!(t.app.exit().is_none(), "q is just a letter in a form");
    t.key(Key::Ctrl('c'));
    assert_eq!(t.app.exit(), Some(Exit::Quit), "Ctrl+C quits from anywhere");
}

#[test]
fn another_window_changed_the_vault() {
    let mut t = T::sample();
    // Meanwhile, another CakePass adds an item.
    let mut other = t.reopen(PW);
    add(&mut other, "From elsewhere", Kind::Login, "x", "y", "");
    drop(other);
    t.key(Key::Char('a'));
    t.typ("Mine");
    t.keys(&[Key::Down, Key::Down, Key::Down, Key::Down, Key::Down, Key::Down]);
    t.typ("my-pass");
    t.key(Key::Ctrl('s'));
    assert!(t.screen().contains("was NOT saved"), "{}", t.screen());
    assert!(matches!(t.app.screen, Screen::Form(_)), "the form is kept");
    assert!(t.app.uv.vault.get("mine").is_none(), "memory matches the file");
    t.key(Key::Enter); // reload
    t.typ("not it");
    t.key(Key::Enter);
    assert!(t.screen().contains("Wrong master password"));
    t.typ(PW);
    t.key(Key::Enter);
    assert!(t.toast().starts_with("Vault reloaded."), "{}", t.toast());
    t.key(Key::Ctrl('s'));
    let uv = t.reopen(PW);
    assert!(uv.vault.get("mine").is_some() && uv.vault.get("from elsewhere").is_some(), "nothing lost");
}

#[test]
fn layout_at_several_sizes() {
    let mut t = T::sample();
    t.key(Key::Enter);
    for (w, h) in [(80, 24), (100, 30), (60, 16), (70, 30), (200, 60)] {
        let s = t.screen_at(w, h);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), h as usize, "{w}x{h}");
        assert!(lines.iter().all(|l| l.chars().count() <= w as usize), "{w}x{h}: a line is too long");
        assert!(s.contains("GitHub") && s.contains("Details"), "{w}x{h}:\n{s}");
        assert!(lines[0].contains("CakePass") && lines[0].contains("locks in"), "{w}x{h}: title bar");
        assert!(lines[h as usize - 1].contains("help"), "{w}x{h}: hint bar");
        assert!(s.contains("gh-Secret-1"), "{w}x{h}: the revealed password");
    }
    // Narrow but tall: the details go below the list.
    let s = t.screen_at(70, 30);
    let list_row = s.lines().position(|l| l.contains("OpenAI")).unwrap();
    let detail_row = s.lines().position(|l| l.contains("Username")).unwrap();
    assert!(detail_row > list_row, "stacked:\n{s}");
    // Too small: a notice instead of a garbled screen.
    t.app.resize((50, 12));
    let s = t.screen_at(50, 12);
    assert!(s.contains("Terminal too small") && s.contains("50×12") && !s.contains("gh-Secret"), "{s}");
    t.key(Key::Char('a'));
    assert!(matches!(t.app.screen, Screen::Main), "keys other than q do nothing then");
    t.key(Key::Char('q'));
    assert_eq!(t.app.exit(), Some(Exit::Quit));
}

#[test]
fn every_screen_renders_at_the_minimum_size() {
    let mut t = T::sample();
    let check = |t: &T, what: &str| {
        for (w, h) in [(60, 16), (80, 24)] {
            let s = t.screen_at(w, h);
            assert!(s.lines().count() == h as usize && s.lines().all(|l| l.chars().count() <= w as usize));
            assert!(
                s.lines().last().unwrap().contains("Esc") || s.lines().last().unwrap().contains("help"),
                "{what}"
            );
        }
    };
    t.key(Key::Char('?'));
    check(&t, "help");
    t.key(Key::Esc);
    t.key(Key::Char('g'));
    check(&t, "generator");
    let s = t.screen_at(60, 16);
    assert!(s.contains("No look-alikes") && s.contains("Esc cancel"), "the generator fits at 60x16:\n{s}");
    t.key(Key::Esc);
    t.key(Key::Char('a'));
    check(&t, "form");
    t.key(Key::Esc);
    t.key(Key::Char('s'));
    check(&t, "settings");
    t.key(Key::Esc);
    t.key(Key::Char('d'));
    check(&t, "confirm");
}

#[test]
fn ascii_screens_without_utf8() {
    let mut t = T::sample();
    t.key(Key::Char('g'));
    let mut g = Grid::new(80, 24, &ASCII);
    t.app.draw(&mut g, t.now);
    let s = g.text();
    assert!(s.is_ascii(), "{s}");
    assert!(s.contains("+- Password generator -") && s.contains("< password >"), "{s}");
}

#[test]
fn startup_notices_are_shown_once() {
    let mut t = T::new();
    t.app.show_notices(vec![
        Notice { warning: true, text: "This vault uses lighter Argon2 settings.".into() },
        Notice { warning: false, text: "A new version is available.".into() },
    ]);
    let s = t.screen();
    assert!(s.contains("Please note") && s.contains("lighter Argon2") && s.contains("new version"), "{s}");
    assert!(s.contains("─ Please note ─"), "the title sits cleanly in the border: {s}");
    t.key(Key::Enter);
    assert!(t.app.modals.is_empty());
}

#[test]
fn the_security_level_row_measures_lazily_and_switches_the_level() {
    let mut t = T::sample();
    let measured = Rc::new(RefCell::new(Vec::new()));
    let log = measured.clone();
    t.app.measurer = Box::new(move |p: &KdfParams| {
        log.borrow_mut().push(p.memory_kib);
        Ok(Duration::from_millis(u64::from(p.memory_kib) / 256))
    });
    t.key(Key::Char('s'));
    t.keys(&[Key::Down, Key::Down]);
    assert!(measured.borrow().is_empty(), "nothing is measured before the row is shown");
    t.key(Key::Down);
    let s = t.screen();
    assert!(s.contains("Security level") && s.contains("High (recommended)"), "{s}");
    assert_eq!(*measured.borrow(), [256 * 1024], "the shown level is measured once");
    assert!(s.contains("Unlock here ≈ 1.02 s") && s.contains("needs 342 MiB free"), "{s}");
    assert!(s.contains("custom · Argon2id, 8 MiB"), "the current (test) settings: {s}");
    t.key(Key::Left);
    assert!(t.screen().contains("Standard") && t.screen().contains("Unlock here ≈ 0.26 s"));
    t.key(Key::Left); // stays at Standard
    t.key(Key::Right);
    t.key(Key::Left);
    assert_eq!(*measured.borrow(), [256 * 1024, 64 * 1024], "each level is measured only once");
    // Enter: asks for the master password; a wrong one changes nothing.
    t.key(Key::Enter);
    let s = t.screen();
    assert!(s.contains("Change the security level") && s.contains("current master password"), "{s}");
    assert!(s.contains("Unlocking will take about 0.26 s"), "{s}");
    t.typ("wrong");
    t.key(Key::Enter);
    assert!(t.screen().contains("Wrong master password"), "{}", t.screen());
    t.typ(PW);
    t.key(Key::Enter);
    let s = t.screen();
    assert!(s.contains("Security level changed") && s.contains("Standard level"), "{s}");
    t.key(Key::Enter);
    assert!(t.screen().contains("(current)"));
    // On disk: Standard, same password, everything still there; the backup too.
    let uv = t.reopen(PW);
    assert_eq!(uv.kdf(), KdfParams::STANDARD);
    assert_eq!(uv.security_level(), Some(SecurityLevel::Standard));
    assert_eq!(get(&uv, "github").password(uv.item_key()).unwrap().as_str(), "gh-Secret-1");
    let bak = VaultPaths::for_file(t.dir.path().join("vault.enc")).backup;
    assert_eq!(cakepass::storage::read_header(&bak).unwrap().kdf, KdfParams::STANDARD);
    // Enter on the level the vault already has does nothing.
    t.key(Key::Enter);
    assert!(t.toast().contains("already uses the Standard"), "{}", t.toast());
}

#[test]
fn a_level_this_computer_cannot_run_is_explained() {
    let mut t = T::new();
    t.app.measurer = Box::new(|p: &KdfParams| {
        if p.memory_kib > 256 * 1024 {
            cakepass::crypto::check_memory_with(p, Some(900 * 1024), cakepass::crypto::MemoryUse::Create)?;
        }
        Ok(Duration::from_millis(5))
    });
    t.key(Key::Char('s'));
    t.keys(&[Key::Down, Key::Down, Key::Down, Key::Right]);
    let s = t.screen_at(120, 30);
    assert!(s.contains("Maximum") && s.contains("needs about 1366 MiB of free memory"), "{s}");
}

/// A vault with a key file, for the screen mode tests.
fn key_file_vault() -> (T, std::path::PathBuf) {
    let mut t = T::sample();
    let kf_path = t.dir.path().join("usb.key");
    cakepass::keyfile::create(&kf_path).unwrap();
    let kf = cakepass::keyfile::load(&kf_path).unwrap();
    t.app.uv.rekey(Credentials::new(PW.as_bytes(), Some(&kf.pepper)), FAST).unwrap();
    t.app.key_file = Some(kf_path.clone());
    (t, kf_path)
}

fn reopen_with(t: &T, pw: &str, kf: &std::path::Path) -> cakepass::Result<UnlockedVault> {
    let pepper: KeyFilePepper = cakepass::keyfile::load(kf).unwrap().pepper;
    UnlockedVault::open(paths(&t.dir), Credentials::new(pw.as_bytes(), Some(&pepper)))
}

#[test]
fn a_vault_with_a_key_file_in_the_screen_mode() {
    let (mut t, kf_path) = key_file_vault();
    let s = t.screen();
    assert!(s.contains("GitHub"));
    t.key(Key::Char('s'));
    assert!(t.screen_at(120, 30).contains("required:"), "{}", t.screen_at(120, 30));
    // Changing the master password re-reads the key file and keeps it.
    t.keys(&[Key::Down, Key::Down, Key::Enter]);
    t.typ("wrong");
    t.key(Key::Enter);
    assert!(t.screen().contains("Wrong master password (or key file)"), "{}", t.screen());
    t.typ(PW);
    t.key(Key::Enter);
    t.typ(PW2);
    t.key(Key::Enter);
    t.typ(PW2);
    t.key(Key::Enter);
    assert!(t.screen().contains("Master password changed"), "{}", t.screen());
    t.key(Key::Enter);
    let uv = reopen_with(&t, PW2, &kf_path).unwrap();
    assert!(uv.uses_key_file(), "the key file is still required");
    assert!(matches!(
        UnlockedVault::open(paths(&t.dir), Credentials::password(PW2.as_bytes())),
        Err(cakepass::Error::KeyFileRequired)
    ));
    drop(uv);
    // The USB stick is gone: a clear message, nothing changes.
    let moved = t.dir.path().join("moved.key");
    std::fs::rename(&kf_path, &moved).unwrap();
    t.key(Key::Enter); // change the master password again
    t.typ(PW2);
    t.key(Key::Enter);
    let s = t.screen();
    assert!(s.contains("cannot be read") && s.contains("plugged in"), "{s}");
    t.key(Key::Esc);
    std::fs::rename(&moved, &kf_path).unwrap();
    // Reloading after another window changed the vault reads the key file too.
    let mut other = reopen_with(&t, PW2, &kf_path).unwrap();
    add(&mut other, "From elsewhere", Kind::Login, "x", "y", "");
    drop(other);
    t.key(Key::Esc);
    t.key(Key::Char('d'));
    t.key(Key::Char('y'));
    assert!(t.screen().contains("was NOT saved"), "{}", t.screen());
    t.key(Key::Enter);
    t.typ(PW2);
    t.key(Key::Enter);
    assert!(t.toast().starts_with("Vault reloaded."), "{}", t.toast());
}
