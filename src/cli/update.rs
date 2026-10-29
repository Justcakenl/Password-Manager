//! `kluis --update`: CakePass bijwerken naar de nieuwste versie op GitHub.
//!
//! BEVEILIGINGSKRITIEK – hoe dit werkt en waarom het zo veilig mogelijk is:
//!
//! - Het programma zelf bevat GEEN netwerkcode. Alleen deze opdracht start
//!   het programma `git`, en `git` gebruikt jouw eigen GitHub-toegang
//!   (SSH-sleutel of inlog). `kluis` bewaart nooit een token of wachtwoord
//!   voor GitHub.
//! - De opdracht ontgrendelt je kluis NIET: tijdens het updaten staat er
//!   geen sleutel of wachtwoord in het geheugen.
//! - Je kluis (`~/.local/share/kluis/`) staat buiten de installatie en wordt
//!   nooit overschreven. Vooraf maken we een extra kopie (`.voor-update-…`).
//!   Nieuwere versies lezen oudere kluisformaten en zetten ze bij het openen
//!   automatisch om; een oudere versie weigert een nieuwer formaat netjes.
//! - We halen alleen nieuwe commits binnen met `git merge --ff-only`. Dat
//!   herschrijft nooit je geschiedenis. Heb je zelf wijzigingen in de map,
//!   dan stoppen we.
//! - Je ziet eerst wat er nieuw is (de commit-titels) en waarvandaan het
//!   komt, en moet bevestigen.
//! - Het bouwen gebeurt met `makepkg` (inclusief alle tests). Mislukt iets,
//!   dan zetten we de map terug zoals hij was; je huidige versie blijft
//!   gewoon werken.
//!
//! De dagelijkse controle (`--check`, via een systemd-timer) haalt alleen
//! binnen en meldt dat er een update is; installeren doe je zelf. Een
//! wachtwoordmanager die zichzelf zonder jouw oog vervangt, is een te groot
//! risico: wie bij je GitHub-account kan, zou dan code op je computer
//! kunnen uitvoeren die bij je kluis kan.

use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use clap::ValueEnum;
use kluis::storage::{self, VaultPaths};
use kluis::{Error, Result};

use super::{prompt, ui};

/// De commit waaruit dit programma gebouwd is (zie build.rs).
pub const INSTALLED_COMMIT: &str = env!("KLUIS_GIT_COMMIT");
/// Waar de PKGBUILD de bronmap van de installatie vastlegt.
const SOURCE_DIR_FILE: &str = "/usr/share/kluis/source-dir";
const FETCH_TIMEOUT: Duration = Duration::from_secs(120);
const TIMER: &str = "kluis-update.timer";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AutoMode {
    /// Elke dag automatisch controleren
    On,
    /// Niet meer automatisch controleren
    Off,
    /// Laat zien of het aan staat
    Status,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub check_only: bool,
    pub yes: bool,
    pub notify: bool,
    pub source: Option<PathBuf>,
    pub auto: Option<AutoMode>,
}

// ───────────────────────── git ─────────────────────────

/// Draai `git` in `dir`. `unattended` = nooit om een wachtwoord vragen.
fn git(dir: &Path, args: &[&str], unattended: bool) -> Result<String> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(dir).arg("--no-pager").args(args).env("LC_ALL", "C");
    if unattended {
        cmd.env("GIT_TERMINAL_PROMPT", "0").stdin(Stdio::null());
        if std::env::var_os("GIT_SSH_COMMAND").is_none() {
            cmd.env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes -o ConnectTimeout=20");
        }
    } else {
        cmd.stdin(Stdio::inherit());
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(if unattended { Stdio::piped() } else { Stdio::inherit() })
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                Error::InvalidInput("`git` is niet geïnstalleerd (sudo pacman -S git)".into())
            }
            _ => Error::Io(e),
        })?;
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take();
    // Uitvoer leegmaken in aparte threads, zodat een volle pijp niets blokkeert.
    let out_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stdout.read_to_string(&mut buf);
        buf
    });
    let err_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(e) = stderr.as_mut() {
            let _ = e.read_to_string(&mut buf);
        }
        buf
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if unattended && start.elapsed() > FETCH_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::InvalidInput("git deed er te lang over (netwerk of GitHub-toegang?)".into()));
        }
        std::thread::sleep(Duration::from_millis(40));
    };
    let out = out_thread.join().unwrap_or_default();
    let err = err_thread.join().unwrap_or_default();
    if status.success() {
        Ok(out.trim().to_string())
    } else {
        let why = err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("onbekende fout");
        Err(Error::InvalidInput(format!(
            "git {} mislukte: {}",
            args.first().unwrap_or(&""),
            ui::safe(why, false)
        )))
    }
}

fn git_ok(dir: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// ───────────────────────── bronmap en status ─────────────────────────

/// De map met de broncode waaruit CakePass is gebouwd.
fn source_dir(arg: Option<&Path>) -> Result<PathBuf> {
    let dir = match arg {
        Some(p) => p.to_path_buf(),
        None => {
            let text = fs::read_to_string(SOURCE_DIR_FILE).map_err(|_| {
                Error::InvalidInput(format!(
                    "ik weet niet waar de broncode staat (geen {SOURCE_DIR_FILE}). \
                     Geef de map op met --source <map>, of installeer opnieuw met makepkg."
                ))
            })?;
            PathBuf::from(text.lines().next().unwrap_or("").trim())
        }
    };
    if !dir.is_absolute() || !dir.join(".git").exists() || !dir.join("packaging/arch/PKGBUILD").is_file() {
        return Err(Error::InvalidInput(format!(
            "{} is geen CakePass-bronmap (git-checkout met packaging/arch/PKGBUILD). \
             Geef de juiste map op met --source <map>.",
            dir.display()
        )));
    }
    Ok(dir)
}

fn cache_file() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from) {
        Some(p) if p.is_absolute() => p,
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".cache"),
    };
    Some(base.join("kluis").join("update-status"))
}

/// Wat de laatste controle opleverde (staat in `~/.cache/kluis/update-status`).
#[derive(Debug, Default, PartialEq, Eq)]
struct CachedStatus {
    remote: String,
    notified: String,
}

impl CachedStatus {
    fn parse(text: &str) -> CachedStatus {
        let mut s = CachedStatus::default();
        for line in text.lines() {
            match line.split_once('=') {
                Some(("remote", v)) if is_hex(v) && v.len() <= 64 => s.remote = v.into(),
                Some(("notified", v)) if is_hex(v) && v.len() <= 64 => s.notified = v.into(),
                _ => {}
            }
        }
        s
    }

    fn read() -> CachedStatus {
        cache_file()
            .and_then(|p| fs::read_to_string(p).ok())
            .map(|t| CachedStatus::parse(&t))
            .unwrap_or_default()
    }

    fn write(&self) {
        let Some(path) = cache_file() else { return };
        let text = format!("remote={}\nnotified={}\n", self.remote, self.notified);
        let _ = (|| -> std::io::Result<()> {
            if let Some(dir) = path.parent() {
                fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
            }
            let tmp = path.with_extension("tmp");
            let _ = fs::remove_file(&tmp);
            let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
            std::io::Write::write_all(&mut f, text.as_bytes())?;
            fs::rename(tmp, path)
        })();
    }

    /// Is er volgens de laatste controle een nieuwere versie?
    fn update_available(&self) -> bool {
        !self.remote.is_empty() && !is_installed(&self.remote)
    }
}

/// Komt deze (volledige) commit overeen met het geïnstalleerde programma?
fn is_installed(commit: &str) -> bool {
    installed_commit().is_some_and(|i| commit.starts_with(i.as_str()))
}

/// De geïnstalleerde commit; in debug-builds te overschrijven voor tests.
fn installed_commit() -> Option<String> {
    #[cfg(debug_assertions)]
    if let Ok(c) = std::env::var("KLUIS_TEST_INSTALLED_COMMIT") {
        return is_hex(&c).then_some(c);
    }
    is_hex(INSTALLED_COMMIT).then(|| INSTALLED_COMMIT.to_string())
}

fn running_as_root() -> bool {
    #[cfg(debug_assertions)]
    if std::env::var_os("KLUIS_TEST_ALLOW_ROOT").is_some() {
        return false;
    }
    // SAFETY: geteuid is altijd veilig.
    unsafe { libc::geteuid() == 0 }
}

/// Korte melding voor in `kluis info` en het inlogscherm (zonder netwerk:
/// leest alleen het resultaat van de laatste controle).
pub fn pending_notice() -> Option<String> {
    CachedStatus::read().update_available().then(|| {
        "🍰 Er is een nieuwe versie van CakePass beschikbaar. Typ in je terminal: kluis --update".into()
    })
}

// ───────────────────────── de opdracht ─────────────────────────

struct Situation {
    dir: PathBuf,
    branch: String,
    local_head: String,
    remote_tip: String,
    origin: String,
}

/// Controleer GitHub: haal de laatste commits op en bepaal waar we staan.
fn inspect(dir: &Path, unattended: bool) -> Result<Situation> {
    let branch = git(dir, &["rev-parse", "--abbrev-ref", "HEAD"], true)?;
    if branch == "HEAD" || branch.is_empty() {
        return Err(Error::InvalidInput(
            "de bronmap staat niet op een branch (losse commit). Ga met `git checkout main` terug naar main."
                .into(),
        ));
    }
    let origin = git(dir, &["remote", "get-url", "origin"], true)
        .map_err(|_| Error::InvalidInput("de bronmap heeft geen GitHub-adres (remote 'origin')".into()))?;
    let spec = format!("refs/heads/{branch}:refs/remotes/origin/{branch}");
    git(dir, &["fetch", "--quiet", "origin", &spec], unattended)?;
    let remote_tip = git(dir, &["rev-parse", "--verify", &format!("refs/remotes/origin/{branch}")], true)?;
    let local_head = git(dir, &["rev-parse", "HEAD"], true)?;
    if !is_hex(&remote_tip) || !is_hex(&local_head) {
        return Err(Error::InvalidInput("onverwachte uitvoer van git".into()));
    }
    Ok(Situation { dir: dir.to_path_buf(), branch, local_head, remote_tip, origin })
}

/// De titels van de nieuwe commits (maximaal 12), veilig om te tonen.
fn changelog(s: &Situation) -> (usize, Vec<String>) {
    let base = installed_commit().filter(|c| git_ok(&s.dir, &["cat-file", "-e", &format!("{c}^{{commit}}")]));
    let range = match &base {
        Some(c) => format!("{c}..{}", s.remote_tip),
        None => s.remote_tip.clone(),
    };
    let count =
        git(&s.dir, &["rev-list", "--count", &range], true).ok().and_then(|c| c.parse().ok()).unwrap_or(0);
    let log = git(&s.dir, &["log", "--no-merges", "--pretty=format:%h %s", "-n", "12", &range], true)
        .unwrap_or_default();
    let lines = log.lines().map(|l| ui::safe(l, false)).collect();
    (count, lines)
}

pub fn run(opts: &Options, vault: &VaultPaths) -> Result<()> {
    if let Some(mode) = opts.auto {
        return auto(mode);
    }
    let dir = source_dir(opts.source.as_deref())?;
    let unattended = opts.check_only && !prompt::stdin_is_tty();
    if opts.check_only {
        ui::info("Controleren op een nieuwe versie…");
    } else {
        ui::info(&format!("Ik controleer GitHub via git ({}).", dir.display()));
        ui::info(&ui::dim_err(
            "  Er wordt niets van je kluis gelezen of verstuurd; alleen git praat met GitHub.",
        ));
    }
    let s = inspect(&dir, unattended)?;
    let up_to_date = is_installed(&s.remote_tip);
    CachedStatus { remote: s.remote_tip.clone(), ..CachedStatus::read() }
        .write_if(!up_to_date, &s.remote_tip);

    if up_to_date {
        ui::success(&format!(
            "Je hebt al de nieuwste versie van CakePass (commit {}).",
            &s.remote_tip[..12.min(s.remote_tip.len())]
        ));
        return Ok(());
    }
    let (count, lines) = changelog(&s);
    if opts.check_only {
        ui::info(&format!(
            "🍰 Update beschikbaar ({count} nieuwe wijziging(en)). Installeren: kluis --update"
        ));
        if opts.notify {
            notify(&s.remote_tip);
        }
        return Ok(());
    }
    apply(&s, count, &lines, opts, vault)
}

impl CachedStatus {
    /// Bewaar het resultaat; bij "up to date" wordt de melding gewist.
    fn write_if(self, available: bool, remote: &str) {
        let mut s = self;
        s.remote = if available { remote.to_string() } else { String::new() };
        s.write();
    }
}

/// Stuur één desktopmelding per nieuwe versie (als notify-send bestaat).
fn notify(remote: &str) {
    let mut st = CachedStatus::read();
    if st.notified == remote {
        return;
    }
    let sent = Command::new("notify-send")
        .args(["-a", "CakePass", "-i", "dialog-information", "CakePass-update beschikbaar"])
        .arg("Typ in een terminal: kluis --update")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if sent {
        st.notified = remote.to_string();
        st.remote = remote.to_string();
        st.write();
    }
}

fn apply(s: &Situation, count: usize, lines: &[String], opts: &Options, vault: &VaultPaths) -> Result<()> {
    // 1. Voorwaarden
    if running_as_root() {
        return Err(Error::InvalidInput(
            "draai dit als gewone gebruiker, niet als root (makepkg weigert root). \
             Je wordt zelf om je wachtwoord gevraagd voor de installatie."
                .into(),
        ));
    }
    if Command::new("makepkg").arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_err()
    {
        return Err(Error::InvalidInput("`makepkg` ontbreekt (sudo pacman -S base-devel)".into()));
    }
    let dirty = git(&s.dir, &["status", "--porcelain"], true)?;
    if !dirty.is_empty() {
        return Err(Error::InvalidInput(format!(
            "er staan lokale wijzigingen in {} die niet op GitHub staan. Ik werk niets bij om ze \
             niet kwijt te raken. Bekijk ze met `git -C {} status`.",
            s.dir.display(),
            s.dir.display()
        )));
    }
    let behind = s.local_head != s.remote_tip;
    if behind && !git_ok(&s.dir, &["merge-base", "--is-ancestor", &s.local_head, &s.remote_tip]) {
        return Err(Error::InvalidInput(
            "jouw kopie wijkt af van GitHub (je hebt zelf commits gemaakt). Ik werk niets bij; \
             los dat eerst zelf op met git."
                .into(),
        ));
    }

    // 2. Laat zien wat er gebeurt en vraag bevestiging
    let short = |c: &str| c[..12.min(c.len())].to_string();
    ui::banner(&[
        "Er is een nieuwe versie van CakePass.",
        "",
        &format!("Nieuw: {count} wijziging(en)  (branch {})", ui::safe(&s.branch, false)),
        &format!("Van:   {}", ui::safe(&s.origin, false)),
        &format!(
            "Nu:    {}  →  straks: {}",
            installed_commit().map_or("onbekend".into(), |c| short(&c)),
            short(&s.remote_tip)
        ),
    ]);
    for l in lines {
        eprintln!("  • {l}");
    }
    if count > lines.len() {
        eprintln!("  … en {} oudere", count - lines.len());
    }
    ui::info("\nJe kluis en je instellingen blijven onaangeroerd; er komt eerst een extra back-up.");
    ui::warn(
        "Je installeert code van GitHub op je computer. Doe dit alleen als jij (of iemand die je \
         vertrouwt) die wijzigingen heeft gepusht.",
    );
    if !opts.yes && !prompt::confirm("Nu bijwerken?")? {
        ui::info("Niets gewijzigd.");
        return Ok(());
    }

    // 3. Extra back-up van de kluis
    match storage::backup_before_update(vault)? {
        Some(path) => ui::success(&format!("Extra back-up van je kluis: {}", path.display())),
        None => ui::info("Er is nog geen kluis; geen back-up nodig."),
    }

    // 4. Nieuwe code binnenhalen (alleen vooruit, nooit herschrijven)
    if behind {
        git(&s.dir, &["merge", "--ff-only", "--quiet", &s.remote_tip], false)?;
        ui::success("Nieuwe code binnengehaald.");
    }

    // 5. Bouwen, testen en installeren
    ui::info(
        "Bouwen en testen (dit duurt een minuutje); je wordt zo gevraagd om je wachtwoord voor de installatie…",
    );
    let pkg_dir = s.dir.join("packaging/arch");
    remove_old_packages(&pkg_dir);
    let mut makepkg = Command::new("makepkg");
    makepkg.args(["-s", "-i", "-f"]).current_dir(&pkg_dir);
    if opts.yes {
        makepkg.arg("--noconfirm");
    }
    let built = makepkg.status().is_ok_and(|st| st.success());
    if !built {
        if behind {
            // De map was schoon en we deden alleen een fast-forward: terugzetten kan veilig.
            let back = git(&s.dir, &["reset", "--hard", "--quiet", &s.local_head], true);
            if back.is_err() {
                ui::warn(&format!(
                    "Terugzetten van de bronmap mislukte. Doe zelf: git -C {} reset --hard {}",
                    s.dir.display(),
                    short(&s.local_head)
                ));
            }
        }
        return Err(Error::InvalidInput(
            "het bijwerken is mislukt (bouwen, testen of installeren). Er is niets veranderd aan \
             je geïnstalleerde versie; je kluis is veilig."
                .into(),
        ));
    }

    // 6. Klaar
    CachedStatus::default().write_if(false, "");
    ui::success("CakePass is bijgewerkt. Start `kluis` opnieuw om de nieuwe versie te gebruiken.");
    ui::info(
        "Je kluis is niet aangeraakt. Is er een nieuw kluisformaat, dan wordt hij bij het eerstvolgende ontgrendelen automatisch omgezet.",
    );
    Ok(())
}

/// Verwijder eerder gebouwde pakketten, zodat makepkg zeker opnieuw bouwt.
fn remove_old_packages(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with("kluis-") && name.contains(".pkg.tar") {
            let _ = fs::remove_file(e.path());
        }
    }
}

// ───────────────────────── automatisch controleren ─────────────────────────

fn systemctl(args: &[&str]) -> Result<(bool, String)> {
    let out =
        Command::new("systemctl").arg("--user").args(args).stdin(Stdio::null()).output().map_err(|_| {
            Error::InvalidInput(
                "`systemctl` niet gevonden; systemd is nodig voor de automatische controle".into(),
            )
        })?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), text.trim().to_string()))
}

fn auto(mode: AutoMode) -> Result<()> {
    match mode {
        AutoMode::Status => {
            let (_, enabled) = systemctl(&["is-enabled", TIMER])?;
            let (_, next) = systemctl(&["list-timers", TIMER, "--no-pager", "--no-legend"])?;
            ui::info(&format!(
                "Automatische controle: {}",
                ui::safe(enabled.lines().next().unwrap_or("onbekend"), false)
            ));
            if !next.is_empty() {
                ui::info(&format!("  {}", ui::safe(next.lines().next().unwrap_or(""), false)));
            }
            Ok(())
        }
        AutoMode::On => {
            let (ok, why) = systemctl(&["enable", "--now", TIMER])?;
            if !ok {
                return Err(Error::InvalidInput(format!(
                    "aanzetten lukte niet: {}. Is CakePass met makepkg geïnstalleerd?",
                    ui::safe(why.lines().last().unwrap_or(""), false)
                )));
            }
            ui::success(
                "Elke dag wordt gecontroleerd of er een nieuwe versie is. Je krijgt een melding; installeren doe je zelf met `kluis --update`.",
            );
            ui::info(&ui::dim_err(
                "  Tip: de controle werkt alleen zonder wachtwoordvraag als je GitHub-toegang automatisch werkt \
                 (SSH-sleutel zonder wachtwoord, of `gh auth setup-git`).",
            ));
            Ok(())
        }
        AutoMode::Off => {
            let (_, _) = systemctl(&["disable", "--now", TIMER])?;
            ui::success(
                "De automatische controle staat uit. Handmatig updaten kan nog steeds met `kluis --update`.",
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_bestand_wordt_streng_gelezen() {
        let s = CachedStatus::parse("remote=abc123def456\nnotified=0123abcd\n");
        assert_eq!((s.remote.as_str(), s.notified.as_str()), ("abc123def456", "0123abcd"));
        // Rommel, escape-codes en te lange waarden worden genegeerd.
        let bad = CachedStatus::parse("remote=zzz\nnotified=\x1b[2J\nremote=\nonzin\nremote=ab cd\n");
        assert_eq!(bad, CachedStatus::default());
        let long = format!("remote={}", "a".repeat(65));
        assert_eq!(CachedStatus::parse(&long), CachedStatus::default());
    }

    #[test]
    fn hex_controle() {
        assert!(is_hex("0123abcdefABCDEF"));
        assert!(!is_hex("") && !is_hex("xyz") && !is_hex("ab;rm"));
    }

    #[test]
    fn installed_vergelijking() {
        // Het ingebouwde commit is hex (of "onbekend", dan nooit gelijk).
        let commit = installed_commit();
        if let Some(c) = commit {
            assert!(is_installed(&format!("{c}0000000000000000000000000000")[..40]));
            assert!(!is_installed("ffffffffffffffffffffffffffffffffffffffff") || c.chars().all(|x| x == 'f'));
        }
        assert!(!is_installed(""), "leeg komt nooit overeen");
    }
}
