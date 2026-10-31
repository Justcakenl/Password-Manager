//! Execution of the commands. All security logic lives in the library; this
//! file only contains the interaction with the user.
//!
//! SECURITY: everything that comes out of the vault (including usernames and
//! URLs, which are encrypted too) is displayed through
//! `ui::print_secret_line`: straight to the terminal, without a copy in
//! Rust's output buffer.
//!
//! SECURITY (key files): a key file is read only when the vault header says
//! it is required, always *before* the password prompt, and its pepper is
//! dropped (wiped) as soon as the vault is open. Operations that need it
//! again (re-checking the password, re-keying) read the file again. Only
//! its path is kept, here in memory and in the settings file.

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use cakepass::clipboard::{self, CLEAR_AFTER_SECS};
use cakepass::crypto::{self, ItemKey, KdfParams, MemoryUse, SecurityLevel};
use cakepass::format::{Credentials, Header};
use cakepass::generator::{self, PassphraseOptions, PasswordOptions};
use cakepass::keyfile::{self, LoadedKeyFile};
use cakepass::secure_mem::{self, Hardening};
use cakepass::storage::{self, UnlockedVault, VaultPaths};
use cakepass::vault::{Entry, Kind, NewEntry, Vault};
use cakepass::{Error, Result, import};

use super::args::{
    self, AddArgs, Cmd, EditArgs, GenArgs, GetArgs, KdfArgs, KdfChangeArgs, KeyfileAction, SecurityArgs,
};
use super::{config, logo, prompt, setup, shell, tui, ui, update};

static HARDENING: OnceLock<Hardening> = OnceLock::new();

/// Where the key file is: given now (`--keyfile` or `CAKEPASS_KEYFILE`),
/// or in the settings. Only paths, never contents.
struct KeyFileSetting {
    explicit: Option<PathBuf>,
    configured: Option<PathBuf>,
}

static KEY_FILE: Mutex<KeyFileSetting> = Mutex::new(KeyFileSetting { explicit: None, configured: None });

fn key_file_setting() -> std::sync::MutexGuard<'static, KeyFileSetting> {
    KEY_FILE.lock().unwrap_or_else(|e| e.into_inner())
}

/// The key file to use for a vault that needs one: `--keyfile` or
/// `CAKEPASS_KEYFILE` first, then the `keyfile` setting.
pub fn key_file_path() -> Option<PathBuf> {
    let s = key_file_setting();
    s.explicit.clone().or_else(|| s.configured.clone())
}

/// The key file given with `--keyfile` or `CAKEPASS_KEYFILE` (not the setting).
pub(super) fn explicit_key_file() -> Option<PathBuf> {
    key_file_setting().explicit.clone()
}

/// `~/x` → `$HOME/x`, and relative → absolute (for messages and settings).
pub(super) fn absolute_path(p: &Path) -> PathBuf {
    let expanded = match (p.strip_prefix("~"), std::env::var_os("HOME")) {
        (Ok(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => p.to_path_buf(),
    };
    std::path::absolute(&expanded).unwrap_or(expanded)
}
const LABEL_WIDTH: usize = 16;
const TAGLINE: &str = "offline · encrypted · yours alone";

/// Remember the result of the process hardening (for `cakepass info`).
pub fn set_hardening(h: Hardening) {
    let _ = HARDENING.set(h);
}

/// Main entry point: run the command.
pub fn run(cli: args::Cli) -> Result<()> {
    let paths = match cli.vault {
        Some(p) => VaultPaths::for_file(p),
        None => VaultPaths::default_location()?,
    };
    let cfg = config::load();
    *key_file_setting() = KeyFileSetting {
        explicit: cli.keyfile.as_deref().filter(|p| !p.as_os_str().is_empty()).map(absolute_path),
        configured: cfg.keyfile.clone(),
    };
    let Some(command) = cli.command else {
        // `cakepass` without a command: login screen + the screen mode (or the
        // line mode), or the first-time setup when there is no vault yet.
        if fs::symlink_metadata(&paths.file).is_err() {
            if prompt::stdin_is_tty() {
                let created = setup::wizard(&paths, &KdfArgs::default_values())?;
                return match created {
                    Some(mut uv) if !cli.no_tui && tui::check().is_ok() && offer_screen_mode() => {
                        let notices = unlock_notices(&mut uv);
                        tui::run_unlocked(uv, notices, &config::load())
                    }
                    _ => Ok(()),
                };
            }
            logo::show(true);
            logo::tagline(TAGLINE);
            ui::info("There is no vault yet. Set one up with:  cakepass setup");
            return Ok(());
        }
        return interactive(&paths, &cfg, cli.no_tui);
    };
    match command {
        Cmd::Setup { kdf } => setup::run(&paths, &kdf),
        Cmd::Init { kdf } => init(&paths, &kdf),
        Cmd::Generate { opts, show, save } => generate(&paths, None, &opts, show, save),
        Cmd::Info => info(&paths),
        Cmd::Security(s) if s.changes_something() => security_change(&paths, None, &s),
        Cmd::Security(_) => security_show(&paths),
        Cmd::Keyfile { action } => keyfile_command(action),
        Cmd::Config { action } => setup::config_command(action),
        Cmd::Logo => show_logo(),
        Cmd::Update(u) => update::run(
            &update::Options {
                check_only: u.check,
                yes: u.yes,
                notify: u.notify,
                source: u.source,
                auto: u.auto,
            },
            &paths,
        ),
        Cmd::Completions { shell } => completions(shell),
        Cmd::Shell { timeout } => shell::run(&paths, timeout.unwrap_or(cfg.lock_timeout_secs())),
        cmd => {
            let mut uv = unlock(&paths)?;
            execute(&mut uv, cmd, false)
        }
    }
}

/// `cakepass` on its own: the screen mode when the terminal can show it,
/// otherwise (pipes, `TERM=dumb`, a tiny window, `--no-tui`) the line mode.
fn interactive(paths: &VaultPaths, cfg: &config::Config, no_tui: bool) -> Result<()> {
    if !no_tui {
        match tui::check() {
            Ok(()) => return tui::run(paths, cfg),
            Err(tui::Unavailable::NotATerminal) => {}
            Err(why) => ui::info(&ui::dim_err(&format!("({why}; using the line mode instead.)"))),
        }
    }
    shell::run(paths, cfg.lock_timeout_secs())
}

/// After the first-time setup: open the vault right away?
fn offer_screen_mode() -> bool {
    prompt::ask_yes_no("\nOpen CakePass now?", true).unwrap_or(false)
}

/// Run a command on an unlocked vault (also from `cakepass shell`).
pub fn execute(uv: &mut UnlockedVault, cmd: Cmd, in_shell: bool) -> Result<()> {
    match cmd {
        Cmd::Add(a) => add(uv, a),
        Cmd::Get(g) => get(uv, &g),
        Cmd::Edit(e) => edit(uv, e),
        Cmd::Rm { name, yes } => rm(uv, &name, yes),
        Cmd::List { tag, kind } => list(&uv.vault, uv.item_key(), tag.as_deref(), kind),
        Cmd::Search { query } => search(&uv.vault, uv.item_key(), &query),
        Cmd::Passwd { kdf } => {
            if in_shell {
                reconfirm(uv)?;
            }
            passwd(uv, &kdf)
        }
        Cmd::Export { file } => {
            if in_shell {
                reconfirm(uv)?;
            }
            export(uv, &file)
        }
        Cmd::Import { file } => import_vault(uv, &file),
        Cmd::ImportCsv { file } => import_csv(uv, &file),
        Cmd::Generate { opts, show, save } => {
            let paths = uv.paths().clone();
            generate(&paths, Some(uv), &opts, show, save)
        }
        Cmd::Info => info(uv.paths()),
        Cmd::Security(s) if s.changes_something() => {
            let paths = uv.paths().clone();
            security_change(&paths, Some(uv), &s)
        }
        Cmd::Security(_) => security_show(uv.paths()),
        Cmd::Keyfile { action } => keyfile_command(action),
        Cmd::Config { action } => setup::config_command(action),
        Cmd::Logo => show_logo(),
        Cmd::Completions { shell } => completions(shell),
        Cmd::Update(_) => Err(Error::InvalidInput(
            "close the vault first (exit) and then type `cakepass --update`; the vault should be closed while updating"
                .into(),
        )),
        Cmd::Init { .. } | Cmd::Setup { .. } | Cmd::Shell { .. } => {
            Err(Error::InvalidInput("this command does not work inside the interactive mode".into()))
        }
    }
}

// ───────────────────────── helpers ─────────────────────────

/// The Argon2 settings from `--level` (default: high) and the `--kdf-*` flags.
pub(super) fn kdf_from_args(a: &KdfArgs) -> Result<KdfParams> {
    let base = a.level.unwrap_or(SecurityLevel::DEFAULT).params();
    let memory_kib = match a.kdf_memory {
        Some(m) => m.checked_mul(1024).ok_or(Error::InvalidKdfParams("too much memory"))?,
        None => base.memory_kib,
    };
    let p = KdfParams {
        memory_kib,
        iterations: a.kdf_iterations.unwrap_or(base.iterations),
        parallelism: a.kdf_parallelism.unwrap_or(base.parallelism),
    };
    p.validate()?;
    Ok(p)
}

pub(super) fn warn_if_weak_kdf(p: &KdfParams) {
    if p.weaker_than_standard() {
        ui::warn(
            "You are using lighter Argon2 settings than the Standard level (64 MiB, 3 iterations). \
             A stolen vault file is then easier to crack.",
        );
    }
}

/// "standard" / "high" / "maximum", or "custom".
pub(super) fn level_name(kdf: &KdfParams) -> &'static str {
    SecurityLevel::of(kdf).map_or("custom", SecurityLevel::name)
}

/// "0.84 s", "3.1 s", "12 s".
pub(super) fn seconds(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s < 10.0 { format!("{s:.2} s") } else { format!("{s:.0} s") }
}

/// Read the key file if the vault needs one. Call this before asking for
/// the password, so a missing key file is reported first.
pub(super) fn key_file_for(required: bool) -> Result<Option<LoadedKeyFile>> {
    if !required {
        return Ok(None);
    }
    let path = key_file_path().ok_or(Error::KeyFileRequired)?;
    keyfile::load(&path).map(Some)
}

/// [`key_file_for`], with its warnings shown (on the command line).
fn key_file_with_warnings(required: bool) -> Result<Option<LoadedKeyFile>> {
    let kf = key_file_for(required)?;
    for w in kf.iter().flat_map(|k| &k.warnings) {
        ui::warn(w);
    }
    Ok(kf)
}

/// Checks before the password prompt: a readable header, enough memory for
/// its security level, and a note when a key file was given that is not needed.
fn preflight(paths: &VaultPaths) -> Result<Header> {
    let header = storage::read_header(&paths.file)?;
    crypto::ensure_memory(&header.kdf, MemoryUse::Unlock)?;
    if !header.key_file && explicit_key_file().is_some() {
        ui::info(&ui::dim_err(
            "(This vault does not use a key file, so the one given with --keyfile or CAKEPASS_KEYFILE is not needed.)",
        ));
    }
    Ok(header)
}

/// After a failed unlock of a vault with a key file: say which key file
/// was used (a wrong one fails exactly like a wrong password).
fn explain_failure(e: &Error, uses_key_file: bool) {
    if uses_key_file && matches!(e, Error::Decrypt) {
        let used = key_file_path().map_or("-".into(), |p| p.display().to_string());
        ui::info(&format!(
            "This vault also needs its key file; the key file used was {used}. \
             A wrong key file gives the same message as a wrong password."
        ));
    }
}

fn credentials<'a>(pw: &'a SecretString, kf: &'a Option<LoadedKeyFile>) -> Credentials<'a> {
    Credentials::new(pw.expose_secret().as_bytes(), kf.as_ref().map(|k| &k.pepper))
}

/// Something to tell the user right after unlocking.
pub struct Notice {
    pub warning: bool,
    pub text: String,
}

/// Warnings from opening the vault, an update notice and the mlock state
/// (shown by the line mode as messages and by the screen mode in a dialog).
pub(super) fn unlock_notices(uv: &mut UnlockedVault) -> Vec<Notice> {
    let mut out: Vec<Notice> =
        uv.take_warnings().into_iter().map(|text| Notice { warning: true, text }).collect();
    if let Some(text) = update::pending_notice() {
        out.push(Notice { warning: false, text });
    }
    if secure_mem::mlock_failed() {
        out.push(Notice {
            warning: true,
            text: "Memory could not be locked (mlock). Secrets may end up in swap. See `cakepass info`."
                .into(),
        });
    }
    out
}

fn after_unlock(uv: &mut UnlockedVault) {
    for n in unlock_notices(uv) {
        if n.warning { ui::warn(&n.text) } else { ui::info(&n.text) }
    }
}

/// Ask for the master password and open the vault (for single commands).
pub fn unlock(paths: &VaultPaths) -> Result<UnlockedVault> {
    // Check the header (and memory, and the key file) first, so a broken or
    // unknown file gives a clear error right away, without first asking for
    // a password.
    let header = preflight(paths)?;
    let kf = key_file_with_warnings(header.key_file)?;
    let pw = prompt::secret("Master password: ")?;
    let opened = UnlockedVault::open(paths.clone(), credentials(&pw, &kf));
    drop(pw);
    drop(kf);
    let mut uv = opened.inspect_err(|e| explain_failure(e, header.key_file))?;
    after_unlock(&mut uv);
    Ok(uv)
}

/// The login screen: animated logo and at most three attempts.
pub fn login_screen(paths: &VaultPaths) -> Result<UnlockedVault> {
    let mut uv = login(paths)?;
    after_unlock(&mut uv);
    Ok(uv)
}

/// The login screen without the messages afterwards (see [`unlock_notices`]).
pub(super) fn login(paths: &VaultPaths) -> Result<UnlockedVault> {
    let header = preflight(paths)?;
    logo::show(true);
    logo::tagline(TAGLINE);
    // The key file is read once, before the first attempt, and wiped after the last.
    let kf = key_file_with_warnings(header.key_file)?;
    let wrong = if header.key_file { "Wrong master password or key file." } else { "Wrong master password." };
    const ATTEMPTS: usize = 3;
    for attempt in 1..=ATTEMPTS {
        let pw = prompt::secret(&format!("  {} ", ui::pink_bold("🔑 Master password ❯")))?;
        match UnlockedVault::open(paths.clone(), credentials(&pw, &kf)) {
            Ok(uv) => {
                drop(pw);
                return Ok(uv);
            }
            Err(Error::Decrypt) if attempt < ATTEMPTS && prompt::stdin_is_tty() => {
                let left = ATTEMPTS - attempt;
                ui::warn(&format!("{wrong} {left} attempt(s) left."));
            }
            Err(e) => {
                explain_failure(&e, header.key_file);
                return Err(e);
            }
        }
    }
    explain_failure(&Error::Decrypt, header.key_file);
    Err(Error::Decrypt)
}

/// Ask for the master password again (in the shell, before sensitive actions).
fn reconfirm(uv: &UnlockedVault) -> Result<()> {
    let kf = key_file_with_warnings(uv.uses_key_file())?;
    let pw = prompt::secret("Current master password (to confirm): ")?;
    if uv.verify_password(credentials(&pw, &kf))? { Ok(()) } else { Err(Error::Decrypt) }
}

pub(super) fn split_tags(s: &str) -> Vec<String> {
    s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect()
}

/// What to generate: a password or a passphrase. Shared by the command line
/// (`generate`, `add --generate`, ...) and the generator of the screen mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipe {
    Password(PasswordOptions),
    Passphrase(PassphraseOptions),
}

impl Recipe {
    pub(super) fn from_args(g: &GenArgs) -> Recipe {
        if g.passphrase {
            Recipe::Passphrase(PassphraseOptions { words: g.words, separator: g.separator.clone() })
        } else {
            Recipe::Password(PasswordOptions {
                length: g.length,
                uppercase: !g.no_uppercase,
                lowercase: !g.no_lowercase,
                digits: !g.no_digits,
                symbols: !g.no_symbols,
                exclude_lookalikes: g.no_lookalikes,
            })
        }
    }

    /// The secret and its strength in bits.
    pub(super) fn generate(&self) -> Result<(Zeroizing<String>, f64)> {
        match self {
            Recipe::Password(o) => Ok((generator::generate_password(o)?, o.entropy_bits())),
            Recipe::Passphrase(o) => Ok((generator::generate_passphrase(o)?, o.entropy_bits())),
        }
    }
}

/// Generate a password or passphrase according to the options.
fn generate_secret(g: &GenArgs) -> Result<(Zeroizing<String>, f64)> {
    Recipe::from_args(g).generate()
}

/// "The password" / "The API key" / "The note".
pub(super) fn secret_noun(kind: Kind) -> &'static str {
    match kind {
        Kind::Login => "The password",
        Kind::Api => "The API key",
        Kind::Note => "The note",
    }
}

/// "Login" / "API key" / "Note" (for messages).
pub(super) fn kind_noun(kind: Kind) -> &'static str {
    match kind {
        Kind::Login => "Login",
        Kind::Api => "API key",
        Kind::Note => "Note",
    }
}

/// Copy to the clipboard and start the helper that clears it after 20 s.
/// Returns the name of the clipboard tool that was used.
pub(super) fn copy_secret(secret: &str) -> Result<&'static str> {
    let tool = clipboard::detect().ok_or(Error::NoClipboard)?;
    clipboard::copy_with_auto_clear(tool, secret.as_bytes())?;
    Ok(tool.name())
}

/// Copy to the clipboard and have it cleared after 20 s.
fn copy_to_clipboard(secret: &str, what: &str) -> Result<()> {
    let tool = copy_secret(secret)?;
    ui::success(&format!(
        "{what} was copied to the clipboard (via {tool}); it will be cleared in {CLEAR_AFTER_SECS} seconds."
    ));
    Ok(())
}

/// Find an item; give suggestions if it does not exist.
fn find_entry<'a>(vault: &'a Vault, key: &ItemKey, name: &str) -> Result<&'a Entry> {
    if let Some(e) = vault.get(name) {
        return Ok(e);
    }
    let suggestions: Vec<&str> = vault.search(name, key).iter().take(5).map(|e| e.name()).collect();
    if !suggestions.is_empty() {
        ui::info(&format!("Did you mean: {}?", suggestions.join(", ")));
    }
    Err(Error::EntryNotFound(name.to_string()))
}

/// Ask for a new password for a login (with repetition in a terminal).
/// Empty = generate one, which you can then view, edit or redo.
/// Returns (password, entropy bits if it is a generated one).
fn ask_item_password(g: &GenArgs) -> Result<(Zeroizing<String>, Option<f64>)> {
    let first = prompt::secret("Password (leave empty to let cakepass generate one): ")?;
    if first.expose_secret().is_empty() {
        let (pw, bits) = generate_secret(g)?;
        return review_for_saving(g, pw, bits);
    }
    if prompt::stdin_is_tty() {
        let again = prompt::secret("Repeat password: ")?;
        if !prompt::secrets_equal(&first, &again) {
            return Err(Error::InvalidInput("the passwords do not match".into()));
        }
    }
    Ok((Zeroizing::new(first.expose_secret().to_string()), None))
}

/// Ask for an API key (hidden input; pasting is fine, no repetition needed).
fn ask_api_key() -> Result<Zeroizing<String>> {
    let k = prompt::secret("API key (hidden input; pasting is fine): ")?;
    let k = Zeroizing::new(k.expose_secret().trim().to_string());
    if k.is_empty() {
        return Err(Error::InvalidInput("the API key must not be empty".into()));
    }
    Ok(k)
}

fn ask_note_content() -> Result<Zeroizing<String>> {
    prompt::multiline("Type or paste the text of your note (it is stored encrypted):")
}

fn report_generated(name: &str, pw: &str, bits: f64) {
    ui::info(&format!("Password generated ({} characters, about {bits:.0} bits).", pw.chars().count()));
    match copy_to_clipboard(pw, "The password") {
        Ok(()) => {}
        Err(Error::NoClipboard) => {
            ui::info(&format!("No clipboard tool found; view it with `cakepass get \"{name}\" --show`."));
        }
        Err(e) => ui::warn(&format!("Copying failed: {e}")),
    }
}

/// What the user decided in the password review menu.
enum Review {
    /// Use / save the password.
    Save,
    /// Copy the password to the clipboard and finish (`generate` only).
    Copy,
    /// Throw the password away.
    Cancel,
}

/// "24 characters, about 150 bits" (generated) or "... strength 3/4" (typed).
pub(super) fn strength_text(secret: &str, bits: Option<f64>) -> String {
    let n = secret.chars().count();
    match bits {
        Some(b) => format!("{n} characters, about {b:.0} bits"),
        None => format!("{n} characters, strength {}/4", prompt::strength(secret).0),
    }
}

/// Let the user look at, change or redo a generated password before it is used.
///
/// In a terminal this shows a small menu: view it, type your own instead
/// (edit), generate a new one, copy it, or accept it. Without a terminal
/// (scripts, pipes) the password is accepted as it is.
///
/// `saving` is true when the password goes straight into an item (`add`,
/// `edit`, `generate --save`): Enter then means "save". For a plain
/// `generate` Enter means "copy" and `s` saves it to the vault.
fn review_password(
    g: &GenArgs,
    secret: &mut Zeroizing<String>,
    bits: &mut Option<f64>,
    saving: bool,
) -> Result<Review> {
    let default = if saving { Review::Save } else { Review::Copy };
    if !prompt::stdin_is_tty() {
        return Ok(default);
    }
    let menu = if saving {
        "[Enter] save  [v]iew  [e]dit  [r]egenerate  [c]opy  [q]uit without saving"
    } else {
        "[Enter] copy  [s]ave to vault  [v]iew  [e]dit  [r]egenerate  [q]uit"
    };
    let mut show_header = true;
    loop {
        if show_header {
            ui::info(&format!("🔑 Password: {}", strength_text(secret, *bits)));
            ui::info(&ui::dim_err(&format!("   {menu}")));
            show_header = false;
        }
        let answer = prompt::line(&format!("   {} ", ui::pink_bold("❯")))?.to_lowercase();
        match answer.as_str() {
            "" => return Ok(default),
            "s" | "save" if !saving => return Ok(Review::Save),
            "v" | "view" => ui::print_secret_line("   ", secret)?,
            "e" | "edit" => {
                let first = prompt::secret("   Type the password you want (hidden, empty = keep): ")?;
                if first.expose_secret().is_empty() {
                    continue;
                }
                let again = prompt::secret("   Repeat password: ")?;
                if !prompt::secrets_equal(&first, &again) {
                    ui::warn("The passwords do not match; the password is unchanged.");
                    continue;
                }
                *secret = Zeroizing::new(first.expose_secret().to_string());
                *bits = None;
                if prompt::strength(secret).0 < prompt::MIN_SCORE {
                    ui::warn(
                        "This password is on the weak side. You can still use it, or press r to generate one.",
                    );
                }
                show_header = true;
            }
            "r" | "regenerate" => {
                let (pw, b) = generate_secret(g)?;
                *secret = pw;
                *bits = Some(b);
                show_header = true;
            }
            "c" | "copy" => {
                if saving {
                    match copy_to_clipboard(secret, "The password") {
                        Ok(()) => {}
                        Err(Error::NoClipboard) => ui::info("No clipboard tool found; use v to view it."),
                        Err(e) => ui::warn(&format!("Copying failed: {e}")),
                    }
                } else {
                    return Ok(Review::Copy);
                }
            }
            "q" | "quit" | "cancel" => return Ok(Review::Cancel),
            _ => ui::warn("Choose one of the options shown above."),
        }
    }
}

/// Review a freshly generated password that is about to be saved in an item.
/// Returns the final password and the bits of entropy if it is still the
/// generated one (`None` once the user typed their own).
fn review_for_saving(
    g: &GenArgs,
    secret: Zeroizing<String>,
    bits: f64,
) -> Result<(Zeroizing<String>, Option<f64>)> {
    let (mut secret, mut bits) = (secret, Some(bits));
    match review_password(g, &mut secret, &mut bits, true)? {
        Review::Cancel => Err(Error::Cancelled),
        Review::Save | Review::Copy => Ok((secret, bits)),
    }
}

/// Show one field (label + value), without a copy in the output buffer.
fn field(label: &str, value: &str) -> Result<()> {
    let label = ui::bold(&ui::pad(&format!("{label}:"), LABEL_WIDTH));
    ui::print_secret_line(&format!("{label} "), value)?;
    Ok(())
}

/// Show a multi-line field, neatly indented.
fn field_block(label: &str, text: &str) -> Result<()> {
    let safe = Zeroizing::new(ui::safe(text, true));
    let mut lines = safe.lines();
    field(label, lines.next().unwrap_or(""))?;
    let indent = " ".repeat(LABEL_WIDTH + 1);
    for line in lines {
        ui::print_secret_line(&indent, line)?;
    }
    Ok(())
}

// ───────────────────────── commands ─────────────────────────

fn show_logo() -> Result<()> {
    if ui::color_on_stderr() {
        logo::show(true);
        logo::tagline(TAGLINE);
    } else {
        ui::info("CakePass – the logo only appears in a color terminal.");
    }
    Ok(())
}

pub(super) fn print_new_vault_banner() {
    ui::banner(&[
        "You are about to create a new vault.",
        "",
        "The master password is the ONLY key to your vault.",
        "If you forget it, your data is gone for good:",
        "there is no recovery and no back door.",
        "You may want to write it down on paper and keep that somewhere safe.",
    ]);
}

/// Create the vault with a master password that was already chosen (and
/// the key file, if one was chosen).
pub(super) fn create_vault(
    paths: &VaultPaths,
    kdf: KdfParams,
    pw: &SecretString,
    kf: &Option<LoadedKeyFile>,
) -> Result<UnlockedVault> {
    ui::info(&format!("Deriving the key with {}…", kdf.describe()));
    let uv = UnlockedVault::create(paths.clone(), credentials(pw, kf), kdf)?;
    ui::success(&format!(
        "Vault created: {} (security level: {})",
        uv.paths().file.display(),
        level_name(&kdf)
    ));
    if kf.is_some() {
        ui::info("  It needs the key file as well as the master password to open.");
    }
    Ok(uv)
}

fn init(paths: &VaultPaths, kdf_args: &KdfArgs) -> Result<()> {
    if fs::symlink_metadata(&paths.file).is_ok() {
        return Err(Error::AlreadyExists(paths.file.clone()));
    }
    let kdf = kdf_from_args(kdf_args)?;
    crypto::ensure_memory(&kdf, MemoryUse::Create)?;
    // Only a key file given now (--keyfile, CAKEPASS_KEYFILE) protects a new
    // vault; a key file in the settings may belong to another vault.
    let key_file = explicit_key_file();
    let kf = key_file.as_deref().map(|p| load_new_key_file(p, paths)).transpose()?;
    logo::show(true);
    logo::tagline("welcome! let's create your vault");
    print_new_vault_banner();
    warn_if_weak_kdf(&kdf);
    let pw = prompt::new_strong_password("master password")?;
    create_vault(paths, kdf, &pw, &kf)?;
    drop(pw);
    drop(kf);
    if let Some(p) = &key_file {
        remember_key_file(p, None);
        key_file_loss_warning();
    }
    ui::info(
        "Next: `cakepass add <name>` (login), `--type api` (API key) or `--type note`. \
         Make regular copies of the vault file (see the README).",
    );
    Ok(())
}

fn add(uv: &mut UnlockedVault, a: AddArgs) -> Result<()> {
    add_item(uv, a, None)
}

/// Add an item. `preset` is a password that was already chosen (by
/// `generate --save`); the question for the password is then skipped.
fn add_item(
    uv: &mut UnlockedVault,
    a: AddArgs,
    mut preset: Option<(Zeroizing<String>, Option<f64>)>,
) -> Result<()> {
    if uv.vault.contains(&a.name) {
        return Err(Error::EntryExists(a.name.trim().to_string()));
    }
    let kind = a.kind;
    if kind == Kind::Note && (a.username.is_some() || a.email.is_some() || a.url.is_some() || a.generate) {
        return Err(Error::InvalidInput(
            "a note has no username, e-mail address, URL or password; use only --tags".into(),
        ));
    }
    let interactive = a.username.is_none() && a.email.is_none() && a.url.is_none() && a.tags.is_none();
    let (user_q, url_q) = match kind {
        Kind::Api => ("Account or key ID (optional): ", "Service URL (optional): "),
        _ => ("Username (optional): ", "URL (optional): "),
    };
    let username = match (kind, a.username) {
        (Kind::Note, _) => String::new(),
        (_, Some(u)) => u,
        (_, None) => prompt::line(user_q)?,
    };
    let email = match (kind, a.email) {
        (Kind::Note, _) => String::new(),
        (_, Some(e)) => e,
        (_, None) => prompt::line("E-mail address (optional): ")?,
    };
    warn_if_not_email(&email);
    let url = match (kind, a.url) {
        (Kind::Note, _) => String::new(),
        (_, Some(u)) => u,
        (_, None) => prompt::line(url_q)?,
    };
    let tags = match a.tags {
        Some(t) => t,
        None => split_tags(&prompt::line("Tags, separated by commas (optional): ")?),
    };
    let notes: Zeroizing<String> = match kind {
        Kind::Note => ask_note_content()?,
        _ if interactive => Zeroizing::new(prompt::line("Notes (optional, one line): ")?),
        _ => Zeroizing::new(String::new()),
    };
    let (secret, generated_bits) = if kind != Kind::Note && preset.is_some() {
        preset.take().expect("checked above")
    } else {
        match kind {
            Kind::Note => (Zeroizing::new(String::new()), None),
            _ if a.generate => {
                let (pw, bits) = generate_secret(&a.gen_opts)?;
                review_for_saving(&a.gen_opts, pw, bits)?
            }
            Kind::Login => ask_item_password(&a.gen_opts)?,
            Kind::Api => (ask_api_key()?, None),
        }
    };
    let fields = NewEntry {
        name: a.name.clone(),
        kind,
        username,
        email,
        password: secret.to_string(),
        url,
        notes: notes.to_string(),
        tags,
    };
    let name = add_entry(uv, fields)?;
    ui::success(&format!("{} '{name}' saved (encrypted).", kind_noun(kind)));
    if let Some(bits) = generated_bits {
        report_generated(&name, &secret, bits);
    }
    Ok(())
}

/// Encrypt a new item, add it and save the vault. If saving fails the item
/// is taken out again, so memory never holds what the file does not.
/// Used by `add`, `generate --save` and the screen mode.
pub(super) fn add_entry(uv: &mut UnlockedVault, fields: NewEntry) -> Result<String> {
    let entry = Entry::new(fields, uv.item_key())?;
    let name = entry.name().to_string();
    uv.vault.add(entry)?;
    if let Err(e) = uv.save() {
        let _ = uv.vault.remove(&name);
        return Err(e);
    }
    Ok(name)
}

/// Whether a (non-empty) e-mail address looks wrong.
pub(super) fn email_looks_odd(email: &str) -> bool {
    let e = email.trim();
    !e.is_empty() && !(e.contains('@') && !e.starts_with('@') && !e.ends_with('@') && !e.contains(' '))
}

/// A gentle hint (not an error) when an e-mail address looks wrong.
fn warn_if_not_email(email: &str) {
    if email_looks_odd(email) {
        let e = email.trim();
        ui::warn(&format!("'{}' does not look like an e-mail address (saved anyway).", ui::safe(e, false)));
    }
}

fn get(uv: &UnlockedVault, g: &GetArgs) -> Result<()> {
    let key = uv.item_key();
    let e = find_entry(&uv.vault, key, &g.name)?;
    let kind = e.kind();
    let hidden = ui::dim("(hidden; use --show)");
    let empty = ui::dim("-");
    let value = |v: &str| -> Zeroizing<String> {
        Zeroizing::new(if v.is_empty() { empty.clone() } else { ui::safe(v, false) })
    };
    field("Name", e.name())?;
    field("Type", &ui::kind_label(kind))?;
    match kind {
        Kind::Login => {
            field("Username", &value(&e.username(key)?))?;
            field("E-mail", &value(&e.email(key)?))?;
            field("URL", &value(&e.url(key)?))?;
        }
        Kind::Api => {
            field("Account / ID", &value(&e.username(key)?))?;
            field("E-mail", &value(&e.email(key)?))?;
            field("Service", &value(&e.url(key)?))?;
        }
        Kind::Note => {}
    }
    field("Tags", &value(&e.tags().join(", ")))?;
    field("Modified", &ui::format_time(e.modified()))?;
    let secret_label = capitalize(kind.secret_label());

    if g.show {
        // Only here, at your explicit request, are the secrets decrypted.
        if kind == Kind::Note {
            let text = e.notes(key)?;
            if text.is_empty() { field("Content", &empty)? } else { field_block("Content", &text)? }
        } else {
            let notes = e.notes(key)?;
            if notes.is_empty() {
                field("Notes", &empty)?
            } else {
                field_block("Notes", &notes)?
            }
            field(&secret_label, &value(&e.password(key)?))?;
        }
        return Ok(());
    }
    if kind == Kind::Note {
        field("Content", if e.has_notes() { &hidden } else { &empty })?;
    } else {
        field("Notes", if e.has_notes() { &hidden } else { &empty })?;
        field(&secret_label, if e.has_password() { &hidden } else { &empty })?;
    }
    if g.no_copy {
        return Ok(());
    }
    if g.copy_username {
        let user = e.username(key)?;
        if user.is_empty() {
            return Err(Error::InvalidInput("this item has no username".into()));
        }
        copy_to_clipboard(&user, "The username")
    } else if g.copy_email {
        let mail = e.email(key)?;
        if mail.is_empty() {
            return Err(Error::InvalidInput("this item has no e-mail address".into()));
        }
        copy_to_clipboard(&mail, "The e-mail address")
    } else if !e.has_secret() {
        ui::info(&format!("This item has no {}.", kind.secret_label()));
        Ok(())
    } else {
        copy_to_clipboard(&e.secret(key)?, secret_noun(kind))
    }
}

pub(super) fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next().map_or_else(String::new, |f| f.to_uppercase().chain(c).collect())
}

/// "" = unchanged, "-" = clear, anything else = the new value.
fn keep_or(input: String) -> Option<String> {
    match input.as_str() {
        "" => None,
        "-" => Some(String::new()),
        _ => Some(input),
    }
}

fn edit(uv: &mut UnlockedVault, a: EditArgs) -> Result<()> {
    let (old_name, kind, cur_user, cur_email, cur_url, cur_tags) = {
        let key = uv.item_key();
        let e = find_entry(&uv.vault, key, &a.name)?;
        (e.name().to_string(), e.kind(), e.username(key)?, e.email(key)?, e.url(key)?, e.tags().join(", "))
    };
    if kind == Kind::Note
        && (a.username.is_some() || a.email.is_some() || a.url.is_some() || a.password || a.generate)
    {
        return Err(Error::InvalidInput(
            "a note has no username, e-mail address, URL or password; use --notes for the contents".into(),
        ));
    }
    let interactive = a.rename.is_none()
        && a.username.is_none()
        && a.email.is_none()
        && a.url.is_none()
        && a.tags.is_none()
        && !a.password
        && !a.generate
        && !a.notes;

    let mut rename = a.rename;
    let mut username = a.username;
    let mut email = a.email;
    let mut url = a.url;
    let mut tags = a.tags;
    let mut notes: Option<Zeroizing<String>> = None;
    let mut new_secret: Option<Zeroizing<String>> = None;
    let mut generated_bits = None;

    if interactive {
        ui::info("Press Enter to leave a field unchanged, or type '-' to clear it.");
        rename = keep_or(prompt::line(&format!("Name [{old_name}]: "))?).filter(|s| !s.is_empty());
        if kind != Kind::Note {
            let (uq, lq) =
                if kind == Kind::Api { ("Account / ID", "Service URL") } else { ("Username", "URL") };
            username = keep_or(prompt::line(&format!("{uq} [{}]: ", cur_user.as_str()))?);
            email = keep_or(prompt::line(&format!("E-mail address [{}]: ", cur_email.as_str()))?);
            url = keep_or(prompt::line(&format!("{lq} [{}]: ", cur_url.as_str()))?);
        }
        tags = keep_or(prompt::line(&format!("Tags [{cur_tags}]: "))?).map(|t| split_tags(&t));
        match kind {
            Kind::Note => {
                if prompt::confirm("Change the contents of the note?")? {
                    notes = Some(ask_note_content()?);
                }
            }
            _ => {
                if prompt::confirm("Change the notes?")? {
                    notes = Some(Zeroizing::new(prompt::line("New notes (one line, empty = clear): ")?));
                }
            }
        }
        match kind {
            Kind::Login => {
                let choice = prompt::line("Password: (k)eep, (t)ype or (g)enerate? [k] ")?.to_lowercase();
                match choice.as_str() {
                    "" | "k" | "keep" => {}
                    "t" | "type" => new_secret = Some(ask_item_password(&a.gen_opts)?.0),
                    "g" | "generate" => {
                        let (pw, bits) = generate_secret(&a.gen_opts)?;
                        let (pw, bits) = review_for_saving(&a.gen_opts, pw, bits)?;
                        new_secret = Some(pw);
                        generated_bits = bits;
                    }
                    _ => return Err(Error::InvalidInput("choose k, t or g".into())),
                }
            }
            Kind::Api => {
                if prompt::confirm("Replace the API key?")? {
                    new_secret = Some(ask_api_key()?);
                }
            }
            Kind::Note => {}
        }
    } else {
        if a.notes {
            notes = Some(match kind {
                Kind::Note => ask_note_content()?,
                _ => Zeroizing::new(prompt::line("New notes (one line, empty = clear): ")?),
            });
        }
        if a.generate {
            let (pw, bits) = generate_secret(&a.gen_opts)?;
            let (pw, bits) = review_for_saving(&a.gen_opts, pw, bits)?;
            new_secret = Some(pw);
            generated_bits = bits;
        } else if a.password {
            new_secret = Some(match kind {
                Kind::Api => ask_api_key()?,
                _ => {
                    let first = prompt::secret("New password: ")?;
                    if prompt::stdin_is_tty() {
                        let again = prompt::secret("Repeat password: ")?;
                        if !prompt::secrets_equal(&first, &again) {
                            return Err(Error::InvalidInput("the passwords do not match".into()));
                        }
                    }
                    Zeroizing::new(first.expose_secret().to_string())
                }
            });
        }
    }

    if let Some(e) = &email {
        warn_if_not_email(e);
    }

    // All or nothing: on an error (e.g. an existing name) the item stays unchanged.
    let (vault, key) = uv.parts_mut();
    vault.update(&old_name, |entry| {
        if let Some(u) = &username {
            entry.set_username(key, u)?;
        }
        if let Some(m) = &email {
            entry.set_email(key, m)?;
        }
        if let Some(u) = &url {
            entry.set_url(key, u)?;
        }
        if let Some(t) = &tags {
            entry.set_tags(t)?;
        }
        if let Some(n) = &notes {
            entry.set_notes(key, n)?;
        }
        if let Some(p) = &new_secret {
            entry.set_password(key, p)?;
        }
        if let Some(new_name) = &rename {
            entry.set_name(new_name)?;
        }
        Ok(())
    })?;
    let final_name = rename.as_deref().map_or(old_name, |n| n.trim().to_string());
    uv.save()?;
    ui::success(&format!("Item '{final_name}' updated."));
    if let (Some(p), Some(bits)) = (&new_secret, generated_bits) {
        report_generated(&final_name, p, bits);
    }
    Ok(())
}

fn rm(uv: &mut UnlockedVault, name: &str, yes: bool) -> Result<()> {
    let real = find_entry(&uv.vault, uv.item_key(), name)?.name().to_string();
    if !yes && !prompt::confirm(&format!("Are you sure you want to remove '{real}'?"))? {
        ui::info("Nothing removed.");
        return Ok(());
    }
    uv.vault.remove(&real)?;
    uv.save()?;
    ui::success(&format!("Item '{real}' removed. (The previous version is still in the backup.)"));
    Ok(())
}

/// Table of items. Username and URL are briefly decrypted per row and shown
/// straight away (without a buffer).
fn print_table(entries: &[&Entry], key: &ItemKey) -> Result<()> {
    struct Row {
        user: Zeroizing<String>,
        url: Zeroizing<String>,
    }
    let rows: Vec<Row> = entries
        .iter()
        .map(|e| Ok(Row { user: e.username(key)?, url: e.url(key)? }))
        .collect::<Result<_>>()?;
    let w_name = entries.iter().map(|e| e.name().chars().count()).max().unwrap_or(0).clamp(4, 32);
    let w_user = rows.iter().map(|r| r.user.chars().count()).max().unwrap_or(0).clamp(11, 28);
    let w_url = rows.iter().map(|r| r.url.chars().count()).max().unwrap_or(0).clamp(3, 36);
    const W_KIND: usize = 8;
    let header = format!(
        "{}  {}  {}  {}  TAGS",
        ui::pad("TYPE", W_KIND),
        ui::pad("NAME", w_name),
        ui::pad("USER/ID", w_user),
        ui::pad("URL", w_url)
    );
    println!("{}", ui::bold(&header));
    for (e, r) in entries.iter().zip(&rows) {
        let kind_cell =
            format!("{}{}", ui::kind_label(e.kind()), " ".repeat(W_KIND - e.kind().label().len()));
        let line = Zeroizing::new(format!(
            "{kind_cell}  {}  {}  {}  {}",
            ui::pad(&ui::truncate(e.name(), w_name), w_name),
            ui::pad(&ui::truncate(&r.user, w_user), w_user),
            ui::pad(&ui::truncate(&r.url, w_url), w_url),
            e.tags().join(", ")
        ));
        ui::print_secret_line("", &line)?;
    }
    Ok(())
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn summary(entries: &[&Entry]) -> String {
    let count = |k: Kind| entries.iter().filter(|e| e.kind() == k).count();
    let parts: Vec<String> =
        [(Kind::Login, "login", "logins"), (Kind::Api, "API key", "API keys"), (Kind::Note, "note", "notes")]
            .iter()
            .filter(|&&(k, _, _)| count(k) > 0)
            .map(|&(k, one, many)| plural(count(k), one, many))
            .collect();
    format!("{}: {}", plural(entries.len(), "item", "items"), parts.join(" · "))
}

fn list(vault: &Vault, key: &ItemKey, tag: Option<&str>, kind: Option<Kind>) -> Result<()> {
    let entries: Vec<&Entry> = vault
        .entries()
        .iter()
        .filter(|e| tag.is_none_or(|t| e.has_tag(t)) && kind.is_none_or(|k| e.kind() == k))
        .collect();
    if entries.is_empty() {
        if vault.is_empty() {
            ui::info("The vault is still empty. Add an item with `cakepass add <name>`.");
        } else {
            ui::info("No items match.");
        }
        return Ok(());
    }
    print_table(&entries, key)?;
    ui::info(&summary(&entries));
    Ok(())
}

fn search(vault: &Vault, key: &ItemKey, query: &str) -> Result<()> {
    let found = vault.search(query, key);
    if found.is_empty() {
        ui::info(&format!("Nothing found for '{query}'."));
    } else {
        print_table(&found, key)?;
        ui::info(&format!("found {}", summary(&found)));
    }
    Ok(())
}

/// Short summary after unlocking (for the interactive mode).
pub fn vault_summary(vault: &Vault) -> String {
    let all: Vec<&Entry> = vault.entries().iter().collect();
    if all.is_empty() { "the vault is still empty".into() } else { summary(&all) }
}

fn generate(
    paths: &VaultPaths,
    uv: Option<&mut UnlockedVault>,
    g: &GenArgs,
    show: bool,
    save: Option<String>,
) -> Result<()> {
    // With --save we know up front that the vault is needed: ask for the master
    // password first, so a typo does not cost you a carefully edited password.
    let mut unlocked: Option<UnlockedVault> = None;
    if save.is_some() && uv.is_none() {
        unlocked = Some(unlock(paths)?);
    }
    if let Some(name) = &save {
        let vault = uv.as_ref().map(|u| &u.vault).or_else(|| unlocked.as_ref().map(|u| &u.vault));
        if vault.is_some_and(|v| v.contains(name)) {
            return Err(Error::EntryExists(name.trim().to_string()));
        }
    }
    let (secret, bits) = generate_secret(g)?;
    let (mut secret, mut bits) = (secret, Some(bits));
    if show {
        ui::print_secret_line("", &secret)?;
    }
    let choice = review_password(g, &mut secret, &mut bits, save.is_some())?;
    let choice = match (choice, save.is_some()) {
        (Review::Copy, true) => Review::Save,
        (c, _) => c,
    };
    match choice {
        Review::Cancel => {
            ui::info("Nothing saved, nothing copied.");
            Ok(())
        }
        Review::Copy => {
            if !show {
                copy_to_clipboard(&secret, "The generated password")?;
            }
            ui::info(&format!("Strength: {}.", strength_text(&secret, bits)));
            Ok(())
        }
        Review::Save => {
            let name = match save {
                Some(n) => n,
                None => prompt::line("Name for this login (e.g. GitHub): ")?,
            };
            if uv.is_none() && unlocked.is_none() {
                unlocked = Some(unlock(paths)?);
            }
            let uv: &mut UnlockedVault = match uv {
                Some(u) => u,
                None => unlocked.as_mut().expect("unlocked above"),
            };
            let args = AddArgs {
                name,
                kind: Kind::Login,
                username: None,
                email: None,
                url: None,
                tags: None,
                generate: false,
                gen_opts: g.clone(),
            };
            add_item(uv, args, Some((secret, bits)))
        }
    }
}

fn passwd(uv: &mut UnlockedVault, a: &KdfChangeArgs) -> Result<()> {
    let cur = uv.kdf();
    // The key file (if any) stays; it is needed to make the new key.
    let kf = key_file_with_warnings(uv.uses_key_file())?;
    let kdf = KdfParams {
        memory_kib: match a.kdf_memory {
            Some(m) => m.checked_mul(1024).ok_or(Error::InvalidKdfParams("too much memory"))?,
            None => cur.memory_kib,
        },
        iterations: a.kdf_iterations.unwrap_or(cur.iterations),
        parallelism: a.kdf_parallelism.unwrap_or(cur.parallelism),
    };
    kdf.validate()?;
    crypto::ensure_memory(&kdf, MemoryUse::Create)?;
    warn_if_weak_kdf(&kdf);
    ui::info("Choose a new master password. The same warning applies: forgotten = everything lost.");
    let new_pw: SecretString = prompt::new_strong_password("master password")?;
    uv.rekey(credentials(&new_pw, &kf), kdf)?;
    drop(kf);
    ui::success("Master password changed. All items and the backup now use the new key.");
    ui::warn(
        "Copies and exports you made yourself earlier still open with the OLD password. \
         Delete them if you think the old password has leaked.",
    );
    Ok(())
}

fn export(uv: &UnlockedVault, file: &Path) -> Result<()> {
    if fs::symlink_metadata(file).is_ok() {
        return Err(Error::AlreadyExists(file.to_path_buf()));
    }
    ui::info("Choose a password for the export file (it may differ from your master password).");
    let pw = prompt::new_strong_password("export password")?;
    uv.export_to(file, pw.expose_secret().as_bytes(), uv.export_params())?;
    ui::success(&format!(
        "{} exported (encrypted) to {}",
        plural(uv.vault.len(), "item", "items"),
        file.display()
    ));
    ui::info("Without the export password this file is useless. Import it with `cakepass import <file>`.");
    if uv.uses_key_file() {
        ui::warn(
            "The export file is protected by the export password ONLY, not by your key file. \
             Keep it as safe as the vault, and delete it when you no longer need it.",
        );
    }
    Ok(())
}

fn import_vault(uv: &mut UnlockedVault, file: &Path) -> Result<()> {
    // An export file has only a password; a copy of a vault may need its key file.
    let header = storage::read_header(file)?;
    crypto::ensure_memory(&header.kdf, MemoryUse::Unlock)?;
    let kf = key_file_with_warnings(header.key_file)?;
    let pw = prompt::secret("Password of the import file: ")?;
    let read = storage::read_vault_file(file, credentials(&pw, &kf));
    drop(pw);
    drop(kf);
    let (other, other_key) = read.inspect_err(|e| explain_failure(e, header.key_file))?;
    let (vault, key) = uv.parts_mut();
    let (added, skipped) = vault.merge(&other, other_key.item_key(), key)?;
    if added > 0 {
        uv.save()?;
    }
    ui::success(&format!("{added} item(s) added, {skipped} already present (skipped)."));
    if added > 0 {
        ui::info("Items with an existing name got a sequence number, e.g. \"GitHub (2)\".");
    }
    Ok(())
}

fn import_csv(uv: &mut UnlockedVault, file: &Path) -> Result<()> {
    ui::banner(&[
        "NOTE: a CSV export is NOT encrypted.",
        "Anyone who can read this file can see all your passwords.",
        "Delete it right after importing (cakepass offers to do that)",
        "and also check your Downloads folder, the trash and your backups.",
    ]);
    let f =
        File::options().read(true).custom_flags(libc::O_NOFOLLOW).open(file).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => Error::InvalidInput(format!("file {} not found", file.display())),
            _ => Error::Io(e),
        })?;
    let parsed = import::parse_csv(f, uv.item_key())?;
    let (vault, key) = uv.parts_mut();
    let (added, duplicates) = vault.merge(&parsed.vault, key, key)?;
    if added > 0 {
        uv.save()?;
    }
    ui::success(&format!(
        "{added} item(s) imported; {duplicates} already present; {} empty or invalid row(s) skipped.",
        parsed.skipped
    ));
    drop(parsed);

    if prompt::confirm(&format!("Do you want to overwrite and delete {} now?", file.display()))? {
        import::overwrite_and_remove(file)?;
        ui::success("CSV file overwritten and deleted.");
        ui::warn(
            "On SSDs and on btrfs/ZFS (copy-on-write) the old contents may still be on the disk \
             despite the overwriting. Full-disk encryption (LUKS) is the real protection.",
        );
    } else {
        ui::warn(&format!(
            "Delete the CSV file yourself as soon as possible, e.g. with: shred -u \"{}\"",
            file.display()
        ));
    }
    Ok(())
}

fn info(paths: &VaultPaths) -> Result<()> {
    let yes_no = |b: bool| if b { "yes" } else { "no" };
    println!("{}", ui::bold("CakePass vault"));
    println!("  File:             {}", paths.file.display());
    match fs::symlink_metadata(&paths.file) {
        Err(_) => println!("  Status:           does not exist yet (create one with `cakepass setup`)"),
        Ok(meta) => {
            let mode = meta.mode() & 0o777;
            let mode_ok = mode & 0o077 == 0;
            println!("  Size:             {} bytes", meta.len());
            println!(
                "  Permissions:      {mode:o} {}",
                if mode_ok { "(good: only you)" } else { "(TOO BROAD: repaired when opened)" }
            );
            println!("  Modified:         {}", ui::format_time(meta.mtime().max(0) as u64));
            match storage::read_header(&paths.file) {
                Ok(h) => {
                    println!("  Format version:   {}", h.version);
                    println!("  Security level:   {}", level_name(&h.kdf));
                    println!(
                        "  Key derivation:   {}{}",
                        h.kdf.describe(),
                        if h.kdf.weaker_than_standard() { " (lighter than recommended)" } else { "" }
                    );
                    println!("  Key file:         {}", key_file_status(h.key_file));
                    println!("  Encryption:       XChaCha20-Poly1305");
                    if h.version >= 2 {
                        println!(
                            "  Second layer:     every item field (username, e-mail, URL, password/key, notes) \
                             encrypted separately (XChaCha20-Poly1305, own HKDF subkey)"
                        );
                    } else {
                        println!("  Second layer:     not yet (old format; upgraded when opened)");
                    }
                }
                Err(e) => println!("  Header:           unreadable ({e})"),
            }
        }
    }
    match fs::metadata(&paths.backup) {
        Ok(m) => println!(
            "  Backup:           {} ({})",
            paths.backup.display(),
            ui::format_time(m.mtime().max(0) as u64)
        ),
        Err(_) => println!("  Backup:           none yet"),
    }

    println!("{}", ui::bold("Version"));
    println!("  This program:     {} (commit {})", env!("CARGO_PKG_VERSION"), update::INSTALLED_COMMIT);
    match update::pending_notice() {
        Some(n) => println!("  Update:           {n}"),
        None => println!("  Update:           no new version known (check with `cakepass --update --check`)"),
    }

    let cfg = config::load();
    println!("{}", ui::bold("Settings"));
    println!("  Animation:        {}", if cfg.animation { "on" } else { "off" });
    println!("  Auto-lock:        after {} minute(s) of inactivity", cfg.lock_timeout_minutes);
    println!("  Key file path:    {}", cfg.keyfile.as_ref().map_or("-".into(), |p| p.display().to_string()));
    println!("  Settings file:    {}", config::path().map_or("-".to_string(), |p| p.display().to_string()));

    println!("{}", ui::bold("System"));
    let tool = clipboard::detect();
    println!(
        "  Clipboard:        {}",
        tool.map_or("not found (install wl-clipboard or xclip)", |t| t.name())
    );
    let mlock = secure_mem::mlock_works();
    let limit = match secure_mem::memlock_limit() {
        Some(l) => format!("{} KiB", l / 1024),
        None => "unlimited".into(),
    };
    println!("  mlock works:      {} (limit {limit})", yes_no(mlock));
    if let Some(h) = HARDENING.get() {
        println!("  Core dumps off:   {}", yes_no(h.core_dumps_disabled));
        println!("  Non-dumpable:     {}", yes_no(h.non_dumpable));
    }
    Ok(())
}

/// "required: /path (found)" / "not used".
fn key_file_status(required: bool) -> String {
    if !required {
        return "not used".into();
    }
    match key_file_path() {
        None => "required, but none is set (use --keyfile PATH or `cakepass config set keyfile PATH`)".into(),
        Some(p) => {
            // Only looks whether it is there; the contents are not read.
            let found = fs::symlink_metadata(&p).is_ok_and(|m| m.is_file());
            format!("required: {} ({})", p.display(), if found { "found" } else { "NOT FOUND right now" })
        }
    }
}

/// `cakepass security` without options: the level, the key file and the
/// unlock time measured on this computer. Needs no password.
fn security_show(paths: &VaultPaths) -> Result<()> {
    let h = storage::read_header(&paths.file)?;
    println!("{}", ui::bold("CakePass security"));
    println!("  Vault:            {} (format version {})", paths.file.display(), h.version);
    let level = SecurityLevel::of(&h.kdf);
    println!("  Security level:   {}", level.map_or("custom", SecurityLevel::title));
    println!(
        "  Key derivation:   {}{}",
        h.kdf.describe(),
        if h.kdf.weaker_than_standard() { " (lighter than recommended)" } else { "" }
    );
    println!("  Key file:         {}", key_file_status(h.key_file));
    ui::info("Measuring how long unlocking takes on this computer…");
    match crypto::measure_unlock(&h.kdf) {
        Ok(d) => println!("  Unlock time:      about {} on this computer (measured just now)", seconds(d)),
        Err(e) => println!("  Unlock time:      cannot run here right now: {e}"),
    }
    println!("{}", ui::bold("Levels"));
    for l in SecurityLevel::ALL {
        let mark = if level == Some(l) { "  ← this vault" } else { "" };
        println!(
            "  {:<9} {:>4} MiB  needs about {} MiB free{mark}",
            l.name(),
            l.params().memory_kib / 1024,
            l.min_available_mib()
        );
    }
    ui::info("Change it:  cakepass security --level standard|high|maximum");
    if h.key_file {
        ui::info(
            "Key file:   cakepass security --new-keyfile PATH (another one)   |   --no-keyfile (stop using one)",
        );
    } else {
        ui::info("Key file:   cakepass keyfile create PATH, then cakepass security --new-keyfile PATH");
    }
    Ok(())
}

/// Read a key file that is about to protect a vault, with the checks that
/// only make sense then (exists, is not the vault itself, not next to it).
pub(super) fn load_new_key_file(path: &Path, paths: &VaultPaths) -> Result<LoadedKeyFile> {
    let path = absolute_path(path);
    if fs::symlink_metadata(&path).is_err() {
        return Err(Error::InvalidInput(format!(
            "there is no file at {}. Make a new key file first with `cakepass keyfile create {}`",
            path.display(),
            path.display()
        )));
    }
    if keyfile::same_file(&path, &paths.file) || keyfile::same_file(&path, &paths.backup) {
        return Err(Error::InvalidInput(
            "the vault file cannot be its own key file (it changes every time it is saved)".into(),
        ));
    }
    let loaded = keyfile::load(&path)?;
    for w in &loaded.warnings {
        ui::warn(w);
    }
    let same_folder = match (path.parent().map(fs::canonicalize), fs::canonicalize(paths.dir())) {
        (Some(Ok(a)), Ok(b)) => a == b,
        _ => false,
    };
    if same_folder {
        ui::warn(
            "The key file is in the same folder as the vault. Anyone who copies that folder (or the \
             disk) gets both, and then the key file adds nothing. Keep it somewhere else, e.g. on a USB stick.",
        );
    }
    Ok(loaded)
}

/// Store the path of the key file in the settings, unless they already point
/// to a key file of another vault. `previous` is the key file this vault used
/// until now (when it is in the settings, it is replaced).
pub(super) fn remember_key_file(new: &Path, previous: Option<&Path>) {
    let mut cfg = config::load();
    match cfg.keyfile.as_deref() {
        Some(p) if p == new => return,
        Some(p) if Some(p) != previous => {
            ui::info(&format!(
                "Your settings point to another key file ({}), maybe for another vault; they were not \
                 changed. Open this vault with --keyfile {}, or set it with `cakepass config set keyfile {}`.",
                p.display(),
                new.display(),
                new.display()
            ));
            return;
        }
        _ => {}
    }
    let Some(text) = new.to_str().and_then(config::parse_keyfile_path) else {
        ui::info("The key file path cannot be stored in the settings; give it with --keyfile each time.");
        return;
    };
    cfg.keyfile = Some(text.clone());
    match config::save(&cfg) {
        Ok(()) => {
            set_configured_key_file(Some(text));
            ui::info(&format!(
                "Saved in your settings: keyfile={} (only the path), so you do not have to type it.",
                new.display()
            ));
        }
        Err(e) => ui::warn(&format!("The key file path was not saved in the settings: {e}")),
    }
}

/// Keep the key file of the settings that this process uses in step with the
/// settings file (e.g. the screen mode opened right after the setup wizard).
pub(super) fn set_configured_key_file(path: Option<PathBuf>) {
    key_file_setting().configured = path;
}

/// Remove the key file from the settings if it is the one this vault used.
fn forget_key_file(removed: Option<&Path>) {
    let mut cfg = config::load();
    if removed.is_some() && cfg.keyfile.as_deref() == removed {
        cfg.keyfile = None;
        match config::save(&cfg) {
            Ok(()) => {
                set_configured_key_file(None);
                ui::info("Removed the key file path from your settings.");
            }
            Err(e) => ui::warn(&format!("The settings were not changed: {e}")),
        }
    }
}

/// The plain warning about losing a key file.
pub(super) fn key_file_loss_warning() {
    ui::banner(&[
        "Keep a copy of your key file somewhere else (a second USB stick).",
        "If you lose the key file and every copy of it, your vault is lost",
        "for good: there is no recovery, not even with the right password.",
        "Back up the key file SEPARATELY from the vault: a vault backup is",
        "useless without the key file, and both together protect nothing.",
    ]);
}

/// `cakepass security --level/--new-keyfile/--no-keyfile`: re-key the vault
/// with the same master password (fresh salt), atomically, backup included.
/// `open` is the vault when it is already unlocked (in `cakepass shell`).
fn security_change(paths: &VaultPaths, open: Option<&mut UnlockedVault>, a: &SecurityArgs) -> Result<()> {
    let (cur_kdf, cur_kf) = match &open {
        Some(uv) => (uv.kdf(), uv.uses_key_file()),
        None => {
            let h = preflight(paths)?;
            (h.kdf, h.key_file)
        }
    };
    let target_kdf = a.level.map_or(cur_kdf, SecurityLevel::params);
    let target_kf = !a.no_keyfile && (cur_kf || a.new_keyfile.is_some());
    if target_kdf == cur_kdf && a.new_keyfile.is_none() && target_kf == cur_kf {
        match a.level {
            Some(l) => ui::info(&format!("The vault already uses the {} level; nothing changed.", l.name())),
            None => ui::info("This vault does not use a key file; nothing changed."),
        }
        return Ok(());
    }
    // Everything that can be checked is checked before the password is typed.
    crypto::ensure_memory(&target_kdf, MemoryUse::Create)?;
    let new_path = a.new_keyfile.as_deref().map(absolute_path);
    let new_kf = new_path.as_deref().map(|p| load_new_key_file(p, paths)).transpose()?;
    let cur_path = key_file_path().filter(|_| cur_kf);
    let kf = key_file_with_warnings(cur_kf)?;
    let in_shell = open.is_some();
    let pw = prompt::secret(if in_shell {
        "Current master password (to confirm): "
    } else {
        "Master password: "
    })?;
    let mut owned = None;
    let uv: &mut UnlockedVault = match open {
        Some(uv) => {
            if !uv.verify_password(credentials(&pw, &kf))? {
                explain_failure(&Error::Decrypt, cur_kf);
                return Err(Error::Decrypt);
            }
            uv
        }
        None => {
            let opened = UnlockedVault::open(paths.clone(), credentials(&pw, &kf));
            let mut uv = opened.inspect_err(|e| explain_failure(e, cur_kf))?;
            after_unlock(&mut uv);
            owned.insert(uv)
        }
    };
    let pepper = match (&new_kf, a.no_keyfile) {
        (Some(new), _) => Some(&new.pepper),
        (None, true) => None,
        (None, false) => kf.as_ref().map(|k| &k.pepper),
    };
    ui::info(&format!("Re-encrypting the vault ({}, a fresh salt)…", target_kdf.describe()));
    let start = Instant::now();
    uv.rekey(Credentials::new(pw.expose_secret().as_bytes(), pepper), target_kdf)?;
    let took = start.elapsed();
    drop(pw);
    drop(kf);
    drop(new_kf);

    if target_kdf != cur_kdf {
        ui::success(&format!(
            "Security level: {} ({}). Unlocking takes about {} on this computer.",
            SecurityLevel::of(&target_kdf).map_or("custom", SecurityLevel::title),
            target_kdf.describe(),
            seconds(took)
        ));
    }
    if let Some(p) = &new_path {
        ui::success(&format!(
            "The vault now needs the key file {} as well as the master password.",
            p.display()
        ));
        remember_key_file(p, cur_path.as_deref());
        // In `cakepass shell`, re-checks from now on use the new key file.
        key_file_setting().explicit = Some(p.clone());
        key_file_loss_warning();
    }
    if a.no_keyfile && cur_kf {
        ui::success("The vault no longer needs a key file: the master password alone opens it.");
        forget_key_file(cur_path.as_deref());
    }
    ui::info("All items and the .bak backup now use the new key.");
    if new_path.is_some() || (a.no_keyfile && cur_kf) {
        ui::warn(
            "Copies of the vault you made yourself earlier still open the old way (the old key file, \
             or without one). Make new copies, and delete the old ones if they could fall into the wrong hands.",
        );
    }
    Ok(())
}

/// `cakepass keyfile create PATH`.
fn keyfile_command(action: KeyfileAction) -> Result<()> {
    match action {
        KeyfileAction::Create { path } => {
            let path = absolute_path(&path);
            let warnings = keyfile::create(&path)?;
            ui::success(&format!(
                "Key file created: {} ({} random bytes, only you can read it).",
                path.display(),
                keyfile::NEW_KEY_FILE_LEN
            ));
            for w in warnings {
                ui::warn(&w);
            }
            key_file_loss_warning();
            ui::info(&format!("Use it for your vault:  cakepass security --new-keyfile {}", path.display()));
            Ok(())
        }
    }
}

fn completions(shell: clap_complete::Shell) -> Result<()> {
    clap_complete::generate(shell, &mut args::command(), "cakepass", &mut io::stdout());
    Ok(())
}
