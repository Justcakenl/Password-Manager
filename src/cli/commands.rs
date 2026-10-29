//! Uitvoering van de opdrachten. Alle beveiligingslogica zit in de
//! bibliotheek; hier zit alleen de interactie met de gebruiker.
//!
//! BEVEILIGING: alles wat uit de kluis komt (ook gebruikersnamen en URL's,
//! die nu ook versleuteld zijn) wordt via `ui::print_secret_line` getoond:
//! rechtstreeks naar de terminal, zonder kopie in de uitvoerbuffer van Rust.

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::OnceLock;

use clap::CommandFactory;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use kluis::clipboard::{self, CLEAR_AFTER_SECS};
use kluis::crypto::{ItemKey, KdfParams};
use kluis::generator::{self, PassphraseOptions, PasswordOptions};
use kluis::secure_mem::{self, Hardening};
use kluis::storage::{self, UnlockedVault, VaultPaths};
use kluis::vault::{Entry, Kind, NewEntry, Vault};
use kluis::{Error, Result, import};

use super::args::{AddArgs, Cli, Cmd, EditArgs, GenArgs, GetArgs, KdfArgs, KdfChangeArgs};
use super::{logo, prompt, shell, ui};

static HARDENING: OnceLock<Hardening> = OnceLock::new();
const DEFAULT_SHELL_TIMEOUT: u64 = 300;
const LABEL_WIDTH: usize = 16;

/// Onthoud het resultaat van de procesbeveiliging (voor `kluis info`).
pub fn set_hardening(h: Hardening) {
    let _ = HARDENING.set(h);
}

/// Hoofdingang: voer de opdracht uit.
pub fn run(cli: Cli) -> Result<()> {
    let paths = match cli.vault {
        Some(p) => VaultPaths::for_file(p),
        None => VaultPaths::default_location()?,
    };
    let Some(command) = cli.command else {
        // `kluis` zonder opdracht: inlogscherm + interactieve modus.
        if fs::symlink_metadata(&paths.file).is_err() {
            logo::show(true);
            logo::tagline("offline · versleuteld · alleen van jou");
            ui::info("Er is nog geen kluis. Maak er een met:  kluis init");
            return Ok(());
        }
        return shell::run(&paths, DEFAULT_SHELL_TIMEOUT);
    };
    match command {
        Cmd::Init { kdf } => init(&paths, &kdf),
        Cmd::Generate { opts, show } => generate(&opts, show),
        Cmd::Info => info(&paths),
        Cmd::Logo => show_logo(),
        Cmd::Completions { shell } => completions(shell),
        Cmd::Shell { timeout } => shell::run(&paths, timeout),
        cmd => {
            let mut uv = unlock(&paths)?;
            execute(&mut uv, cmd, false)
        }
    }
}

/// Voer een opdracht uit op een ontgrendelde kluis (ook vanuit `kluis shell`).
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
        Cmd::Generate { opts, show } => generate(&opts, show),
        Cmd::Info => info(uv.paths()),
        Cmd::Logo => show_logo(),
        Cmd::Completions { shell } => completions(shell),
        Cmd::Init { .. } | Cmd::Shell { .. } => {
            Err(Error::InvalidInput("deze opdracht werkt niet binnen de interactieve modus".into()))
        }
    }
}

// ───────────────────────── hulpfuncties ─────────────────────────

fn kdf_from_args(a: &KdfArgs) -> Result<KdfParams> {
    let memory_kib = a.kdf_memory.checked_mul(1024).ok_or(Error::InvalidKdfParams("te veel geheugen"))?;
    let p = KdfParams { memory_kib, iterations: a.kdf_iterations, parallelism: a.kdf_parallelism };
    p.validate()?;
    Ok(p)
}

fn warn_if_weak_kdf(p: &KdfParams) {
    if p.weaker_than_default() {
        ui::warn(
            "Je gebruikt lichtere Argon2-instellingen dan aanbevolen (64 MiB, 3 iteraties). \
             Een gestolen kluisbestand is dan makkelijker te kraken.",
        );
    }
}

fn after_unlock(uv: &mut UnlockedVault) {
    for w in uv.take_warnings() {
        ui::warn(&w);
    }
    if secure_mem::mlock_failed() {
        ui::warn(
            "Het geheugen kon niet worden vergrendeld (mlock). Geheimen kunnen dan in swap \
             terechtkomen. Zie `kluis info`.",
        );
    }
}

/// Vraag het hoofdwachtwoord en open de kluis (voor losse opdrachten).
pub fn unlock(paths: &VaultPaths) -> Result<UnlockedVault> {
    // Eerst de header controleren, zodat een kapot of onbekend bestand
    // meteen een duidelijke fout geeft, zonder eerst om een wachtwoord te vragen.
    storage::read_header(&paths.file)?;
    let pw = prompt::secret("Hoofdwachtwoord: ")?;
    let mut uv = UnlockedVault::open(paths.clone(), pw.expose_secret().as_bytes())?;
    drop(pw);
    after_unlock(&mut uv);
    Ok(uv)
}

/// Het inlogscherm: geanimeerd logo en maximaal drie pogingen.
pub fn login_screen(paths: &VaultPaths) -> Result<UnlockedVault> {
    storage::read_header(&paths.file)?;
    logo::show(true);
    logo::tagline("offline · versleuteld · alleen van jou");
    const ATTEMPTS: usize = 3;
    for attempt in 1..=ATTEMPTS {
        let pw = prompt::secret(&format!("  {} ", ui::pink_bold("🔑 Hoofdwachtwoord ❯")))?;
        match UnlockedVault::open(paths.clone(), pw.expose_secret().as_bytes()) {
            Ok(mut uv) => {
                drop(pw);
                after_unlock(&mut uv);
                return Ok(uv);
            }
            Err(Error::Decrypt) if attempt < ATTEMPTS && prompt::stdin_is_tty() => {
                let left = ATTEMPTS - attempt;
                ui::warn(&format!("Onjuist hoofdwachtwoord. Nog {left} poging(en)."));
            }
            Err(e) => return Err(e),
        }
    }
    Err(Error::Decrypt)
}

/// Vraag het hoofdwachtwoord opnieuw (in de shell, vóór gevoelige acties).
fn reconfirm(uv: &UnlockedVault) -> Result<()> {
    let pw = prompt::secret("Huidig hoofdwachtwoord (ter bevestiging): ")?;
    if uv.verify_password(pw.expose_secret().as_bytes())? { Ok(()) } else { Err(Error::Decrypt) }
}

fn split_tags(s: &str) -> Vec<String> {
    s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect()
}

/// Genereer een wachtwoord of passphrase volgens de opties.
fn generate_secret(g: &GenArgs) -> Result<(Zeroizing<String>, f64)> {
    if g.passphrase {
        let opts = PassphraseOptions { words: g.words, separator: g.separator.clone() };
        Ok((generator::generate_passphrase(&opts)?, opts.entropy_bits()))
    } else {
        let opts = PasswordOptions {
            length: g.length,
            uppercase: !g.no_uppercase,
            lowercase: !g.no_lowercase,
            digits: !g.no_digits,
            symbols: !g.no_symbols,
            exclude_lookalikes: g.no_lookalikes,
        };
        Ok((generator::generate_password(&opts)?, opts.entropy_bits()))
    }
}

/// "Het wachtwoord" / "De API-sleutel" / "De notitie".
fn secret_noun(kind: Kind) -> &'static str {
    match kind {
        Kind::Login => "Het wachtwoord",
        Kind::Api => "De API-sleutel",
        Kind::Note => "De notitie",
    }
}

/// Kopieer naar het klembord en laat het na 20 s wissen.
fn copy_to_clipboard(secret: &str, what: &str) -> Result<()> {
    let tool = clipboard::detect().ok_or(Error::NoClipboard)?;
    clipboard::copy_with_auto_clear(tool, secret.as_bytes())?;
    ui::success(&format!(
        "{what} is gekopieerd naar het klembord (via {}); het wordt over {CLEAR_AFTER_SECS} seconden gewist.",
        tool.name()
    ));
    Ok(())
}

/// Zoek een item; geef suggesties als het niet bestaat.
fn find_entry<'a>(vault: &'a Vault, key: &ItemKey, name: &str) -> Result<&'a Entry> {
    if let Some(e) = vault.get(name) {
        return Ok(e);
    }
    let suggestions: Vec<&str> = vault.search(name, key).iter().take(5).map(|e| e.name()).collect();
    if !suggestions.is_empty() {
        ui::info(&format!("Bedoelde je: {}?", suggestions.join(", ")));
    }
    Err(Error::EntryNotFound(name.to_string()))
}

/// Vraag een nieuw wachtwoord voor een login (met herhaling in een terminal).
/// Leeg = genereren. Geeft (wachtwoord, sterkte als het gegenereerd is) terug.
fn ask_item_password(g: &GenArgs) -> Result<(Zeroizing<String>, Option<f64>)> {
    let first = prompt::secret("Wachtwoord (leeg laten = laat kluis er een genereren): ")?;
    if first.expose_secret().is_empty() {
        let (pw, bits) = generate_secret(g)?;
        return Ok((pw, Some(bits)));
    }
    if prompt::stdin_is_tty() {
        let again = prompt::secret("Herhaal wachtwoord: ")?;
        if !prompt::secrets_equal(&first, &again) {
            return Err(Error::InvalidInput("de wachtwoorden komen niet overeen".into()));
        }
    }
    Ok((Zeroizing::new(first.expose_secret().to_string()), None))
}

/// Vraag een API-sleutel (verborgen invoer; plakken mag, geen herhaling nodig).
fn ask_api_key() -> Result<Zeroizing<String>> {
    let k = prompt::secret("API-sleutel (verborgen invoer; plakken mag): ")?;
    let k = Zeroizing::new(k.expose_secret().trim().to_string());
    if k.is_empty() {
        return Err(Error::InvalidInput("de API-sleutel mag niet leeg zijn".into()));
    }
    Ok(k)
}

fn ask_note_content() -> Result<Zeroizing<String>> {
    prompt::multiline("Typ of plak de tekst van je notitie (wordt versleuteld opgeslagen):")
}

fn report_generated(name: &str, pw: &str, bits: f64) {
    ui::info(&format!("Wachtwoord gegenereerd ({} tekens, ongeveer {bits:.0} bits).", pw.chars().count()));
    match copy_to_clipboard(pw, "Het wachtwoord") {
        Ok(()) => {}
        Err(Error::NoClipboard) => {
            ui::info(&format!("Geen klembord gevonden; bekijk het met `kluis get \"{name}\" --show`."));
        }
        Err(e) => ui::warn(&format!("Kopiëren mislukt: {e}")),
    }
}

/// Toon één veld (label + waarde), zonder kopie in de uitvoerbuffer.
fn field(label: &str, value: &str) -> Result<()> {
    let label = ui::bold(&ui::pad(&format!("{label}:"), LABEL_WIDTH));
    ui::print_secret_line(&format!("{label} "), value)?;
    Ok(())
}

/// Toon een veld met meerdere regels, netjes ingesprongen.
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

// ───────────────────────── opdrachten ─────────────────────────

fn show_logo() -> Result<()> {
    if ui::color_on_stderr() {
        logo::show(true);
        logo::tagline("offline · versleuteld · alleen van jou");
    } else {
        ui::info("CakePass – het logo verschijnt alleen in een kleurenterminal.");
    }
    Ok(())
}

fn init(paths: &VaultPaths, kdf_args: &KdfArgs) -> Result<()> {
    if fs::symlink_metadata(&paths.file).is_ok() {
        return Err(Error::AlreadyExists(paths.file.clone()));
    }
    let kdf = kdf_from_args(kdf_args)?;
    logo::show(true);
    logo::tagline("welkom! we maken je kluis");
    ui::banner(&[
        "Je gaat een nieuwe kluis maken.",
        "",
        "Het hoofdwachtwoord is de ENIGE sleutel tot je kluis.",
        "Vergeet je het, dan zijn je gegevens voorgoed weg:",
        "er bestaat geen herstel en geen achterdeur.",
        "Schrijf het eventueel op papier en bewaar dat op een veilige plek.",
    ]);
    warn_if_weak_kdf(&kdf);
    let pw = prompt::new_strong_password("hoofdwachtwoord")?;
    ui::info(&format!(
        "Sleutel afleiden met Argon2id ({} MiB, {} iteraties, {} lanes)…",
        kdf.memory_kib / 1024,
        kdf.iterations,
        kdf.parallelism
    ));
    let uv = UnlockedVault::create(paths.clone(), pw.expose_secret().as_bytes(), kdf)?;
    ui::success(&format!("Kluis gemaakt: {}", uv.paths().file.display()));
    ui::info(
        "Volgende stap: `kluis add <naam>` (login), `--type api` (API-sleutel) of `--type notitie`. \
         Maak regelmatig een kopie van het kluisbestand (zie README).",
    );
    Ok(())
}

fn add(uv: &mut UnlockedVault, a: AddArgs) -> Result<()> {
    if uv.vault.contains(&a.name) {
        return Err(Error::EntryExists(a.name.trim().to_string()));
    }
    let kind = a.kind;
    if kind == Kind::Note && (a.username.is_some() || a.url.is_some() || a.generate) {
        return Err(Error::InvalidInput(
            "een notitie heeft geen gebruikersnaam, URL of wachtwoord; gebruik alleen --tags".into(),
        ));
    }
    let interactive = a.username.is_none() && a.url.is_none() && a.tags.is_none();
    let (user_q, url_q) = match kind {
        Kind::Api => ("Account of sleutel-ID (optioneel): ", "Service-URL (optioneel): "),
        _ => ("Gebruikersnaam (optioneel): ", "URL (optioneel): "),
    };
    let username = match (kind, a.username) {
        (Kind::Note, _) => String::new(),
        (_, Some(u)) => u,
        (_, None) => prompt::line(user_q)?,
    };
    let url = match (kind, a.url) {
        (Kind::Note, _) => String::new(),
        (_, Some(u)) => u,
        (_, None) => prompt::line(url_q)?,
    };
    let tags = match a.tags {
        Some(t) => t,
        None => split_tags(&prompt::line("Tags, gescheiden door komma's (optioneel): ")?),
    };
    let notes: Zeroizing<String> = match kind {
        Kind::Note => ask_note_content()?,
        _ if interactive => Zeroizing::new(prompt::line("Notities (optioneel, één regel): ")?),
        _ => Zeroizing::new(String::new()),
    };
    let (secret, generated_bits) = match kind {
        Kind::Note => (Zeroizing::new(String::new()), None),
        _ if a.generate => {
            let (pw, bits) = generate_secret(&a.gen_opts)?;
            (pw, Some(bits))
        }
        Kind::Login => ask_item_password(&a.gen_opts)?,
        Kind::Api => (ask_api_key()?, None),
    };
    let entry = Entry::new(
        NewEntry {
            name: a.name.clone(),
            kind,
            username,
            password: secret.to_string(),
            url,
            notes: notes.to_string(),
            tags,
        },
        uv.item_key(),
    )?;
    let name = entry.name().to_string();
    uv.vault.add(entry)?;
    uv.save()?;
    ui::success(&format!("{} '{name}' versleuteld opgeslagen.", capitalize(kind.label())));
    if let Some(bits) = generated_bits {
        report_generated(&name, &secret, bits);
    }
    Ok(())
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next().map_or_else(String::new, |f| f.to_uppercase().chain(c).collect())
}

fn get(uv: &UnlockedVault, g: &GetArgs) -> Result<()> {
    let key = uv.item_key();
    let e = find_entry(&uv.vault, key, &g.name)?;
    let kind = e.kind();
    let hidden = ui::dim("(verborgen; gebruik --show)");
    let empty = ui::dim("-");
    let value = |v: &str| -> Zeroizing<String> {
        Zeroizing::new(if v.is_empty() { empty.clone() } else { ui::safe(v, false) })
    };
    field("Naam", e.name())?;
    field("Soort", &ui::kind_label(kind))?;
    match kind {
        Kind::Login => {
            field("Gebruikersnaam", &value(&e.username(key)?))?;
            field("URL", &value(&e.url(key)?))?;
        }
        Kind::Api => {
            field("Account / ID", &value(&e.username(key)?))?;
            field("Service", &value(&e.url(key)?))?;
        }
        Kind::Note => {}
    }
    field("Tags", &value(&e.tags().join(", ")))?;
    field("Gewijzigd", &ui::format_time(e.modified()))?;
    let secret_label = capitalize(kind.secret_label());

    if g.show {
        // Pas hier, op jouw uitdrukkelijke verzoek, worden de geheimen ontsleuteld.
        if kind == Kind::Note {
            let text = e.notes(key)?;
            if text.is_empty() { field("Inhoud", &empty)? } else { field_block("Inhoud", &text)? }
        } else {
            let notes = e.notes(key)?;
            if notes.is_empty() {
                field("Notities", &empty)?
            } else {
                field_block("Notities", &notes)?
            }
            field(&secret_label, &value(&e.password(key)?))?;
        }
        return Ok(());
    }
    if kind == Kind::Note {
        field("Inhoud", if e.has_notes() { &hidden } else { &empty })?;
    } else {
        field("Notities", if e.has_notes() { &hidden } else { &empty })?;
        field(&secret_label, if e.has_password() { &hidden } else { &empty })?;
    }
    if g.no_copy {
        return Ok(());
    }
    if g.copy_username {
        let user = e.username(key)?;
        if user.is_empty() {
            return Err(Error::InvalidInput("dit item heeft geen gebruikersnaam".into()));
        }
        copy_to_clipboard(&user, "De gebruikersnaam")
    } else if !e.has_secret() {
        ui::info(&format!("Dit item heeft geen {}.", kind.secret_label()));
        Ok(())
    } else {
        copy_to_clipboard(&e.secret(key)?, secret_noun(kind))
    }
}

/// "" = ongewijzigd, "-" = leegmaken, anders de nieuwe waarde.
fn keep_or(input: String) -> Option<String> {
    match input.as_str() {
        "" => None,
        "-" => Some(String::new()),
        _ => Some(input),
    }
}

fn edit(uv: &mut UnlockedVault, a: EditArgs) -> Result<()> {
    let (old_name, kind, cur_user, cur_url, cur_tags) = {
        let key = uv.item_key();
        let e = find_entry(&uv.vault, key, &a.name)?;
        (e.name().to_string(), e.kind(), e.username(key)?, e.url(key)?, e.tags().join(", "))
    };
    if kind == Kind::Note && (a.username.is_some() || a.url.is_some() || a.password || a.generate) {
        return Err(Error::InvalidInput(
            "een notitie heeft geen gebruikersnaam, URL of wachtwoord; gebruik --notes voor de inhoud".into(),
        ));
    }
    let interactive = a.rename.is_none()
        && a.username.is_none()
        && a.url.is_none()
        && a.tags.is_none()
        && !a.password
        && !a.generate
        && !a.notes;

    let mut rename = a.rename;
    let mut username = a.username;
    let mut url = a.url;
    let mut tags = a.tags;
    let mut notes: Option<Zeroizing<String>> = None;
    let mut new_secret: Option<Zeroizing<String>> = None;
    let mut generated_bits = None;

    if interactive {
        ui::info("Druk op Enter om een veld ongewijzigd te laten, of typ '-' om het leeg te maken.");
        rename = keep_or(prompt::line(&format!("Naam [{old_name}]: "))?).filter(|s| !s.is_empty());
        if kind != Kind::Note {
            let (uq, lq) =
                if kind == Kind::Api { ("Account / ID", "Service-URL") } else { ("Gebruikersnaam", "URL") };
            username = keep_or(prompt::line(&format!("{uq} [{}]: ", cur_user.as_str()))?);
            url = keep_or(prompt::line(&format!("{lq} [{}]: ", cur_url.as_str()))?);
        }
        tags = keep_or(prompt::line(&format!("Tags [{cur_tags}]: "))?).map(|t| split_tags(&t));
        match kind {
            Kind::Note => {
                if prompt::confirm("Inhoud van de notitie wijzigen?")? {
                    notes = Some(ask_note_content()?);
                }
            }
            _ => {
                if prompt::confirm("Notities wijzigen?")? {
                    notes =
                        Some(Zeroizing::new(prompt::line("Nieuwe notities (één regel, leeg = wissen): ")?));
                }
            }
        }
        match kind {
            Kind::Login => {
                let choice = prompt::line("Wachtwoord: (n)iet wijzigen, (i)ntypen of (g)enereren? [n] ")?
                    .to_lowercase();
                match choice.as_str() {
                    "" | "n" | "niet" => {}
                    "i" | "intypen" => new_secret = Some(ask_item_password(&a.gen_opts)?.0),
                    "g" | "genereren" => {
                        let (pw, bits) = generate_secret(&a.gen_opts)?;
                        new_secret = Some(pw);
                        generated_bits = Some(bits);
                    }
                    _ => return Err(Error::InvalidInput("kies n, i of g".into())),
                }
            }
            Kind::Api => {
                if prompt::confirm("API-sleutel vervangen?")? {
                    new_secret = Some(ask_api_key()?);
                }
            }
            Kind::Note => {}
        }
    } else {
        if a.notes {
            notes = Some(match kind {
                Kind::Note => ask_note_content()?,
                _ => Zeroizing::new(prompt::line("Nieuwe notities (één regel, leeg = wissen): ")?),
            });
        }
        if a.generate {
            let (pw, bits) = generate_secret(&a.gen_opts)?;
            new_secret = Some(pw);
            generated_bits = Some(bits);
        } else if a.password {
            new_secret = Some(match kind {
                Kind::Api => ask_api_key()?,
                _ => {
                    let first = prompt::secret("Nieuw wachtwoord: ")?;
                    if prompt::stdin_is_tty() {
                        let again = prompt::secret("Herhaal wachtwoord: ")?;
                        if !prompt::secrets_equal(&first, &again) {
                            return Err(Error::InvalidInput("de wachtwoorden komen niet overeen".into()));
                        }
                    }
                    Zeroizing::new(first.expose_secret().to_string())
                }
            });
        }
    }

    // Alles-of-niets: bij een fout (bijv. bestaande naam) blijft het item ongewijzigd.
    let (vault, key) = uv.parts_mut();
    vault.update(&old_name, |entry| {
        if let Some(u) = &username {
            entry.set_username(key, u)?;
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
    ui::success(&format!("Item '{final_name}' bijgewerkt."));
    if let (Some(p), Some(bits)) = (&new_secret, generated_bits) {
        report_generated(&final_name, p, bits);
    }
    Ok(())
}

fn rm(uv: &mut UnlockedVault, name: &str, yes: bool) -> Result<()> {
    let real = find_entry(&uv.vault, uv.item_key(), name)?.name().to_string();
    if !yes && !prompt::confirm(&format!("Weet je zeker dat je '{real}' wilt verwijderen?"))? {
        ui::info("Niets verwijderd.");
        return Ok(());
    }
    uv.vault.remove(&real)?;
    uv.save()?;
    ui::success(&format!("Item '{real}' verwijderd. (De vorige versie staat nog in de back-up.)"));
    Ok(())
}

/// Tabel met items. Gebruikersnaam en URL worden per regel even ontsleuteld
/// en direct (zonder buffer) getoond.
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
    let w_user = rows.iter().map(|r| r.user.chars().count()).max().unwrap_or(0).clamp(14, 28);
    let w_url = rows.iter().map(|r| r.url.chars().count()).max().unwrap_or(0).clamp(3, 36);
    const W_KIND: usize = 11;
    let header = format!(
        "{}  {}  {}  {}  TAGS",
        ui::pad("SOORT", W_KIND),
        ui::pad("NAAM", w_name),
        ui::pad("GEBRUIKER/ID", w_user),
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

fn summary(entries: &[&Entry]) -> String {
    let count = |k: Kind| entries.iter().filter(|e| e.kind() == k).count();
    let parts: Vec<String> =
        [(Kind::Login, "login(s)"), (Kind::Api, "API-sleutel(s)"), (Kind::Note, "notitie(s)")]
            .iter()
            .filter(|&&(k, _)| count(k) > 0)
            .map(|&(k, label)| format!("{} {label}", count(k)))
            .collect();
    format!("{} item(s): {}", entries.len(), parts.join(" · "))
}

fn list(vault: &Vault, key: &ItemKey, tag: Option<&str>, kind: Option<Kind>) -> Result<()> {
    let entries: Vec<&Entry> = vault
        .entries()
        .iter()
        .filter(|e| tag.is_none_or(|t| e.has_tag(t)) && kind.is_none_or(|k| e.kind() == k))
        .collect();
    if entries.is_empty() {
        if vault.is_empty() {
            ui::info("De kluis is nog leeg. Voeg een item toe met `kluis add <naam>`.");
        } else {
            ui::info("Geen items die hierbij passen.");
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
        ui::info(&format!("Niets gevonden voor '{query}'."));
    } else {
        print_table(&found, key)?;
        ui::info(&format!("{} gevonden", summary(&found)));
    }
    Ok(())
}

/// Korte samenvatting na het ontgrendelen (voor de interactieve modus).
pub fn vault_summary(vault: &Vault) -> String {
    let all: Vec<&Entry> = vault.entries().iter().collect();
    if all.is_empty() { "de kluis is nog leeg".into() } else { summary(&all) }
}

fn generate(g: &GenArgs, show: bool) -> Result<()> {
    let (secret, bits) = generate_secret(g)?;
    if show {
        ui::print_secret_line("", &secret)?;
    } else {
        copy_to_clipboard(&secret, "Het gegenereerde wachtwoord")?;
    }
    ui::info(&format!("Sterkte: ongeveer {bits:.0} bits."));
    Ok(())
}

fn passwd(uv: &mut UnlockedVault, a: &KdfChangeArgs) -> Result<()> {
    let cur = uv.kdf();
    let kdf = KdfParams {
        memory_kib: match a.kdf_memory {
            Some(m) => m.checked_mul(1024).ok_or(Error::InvalidKdfParams("te veel geheugen"))?,
            None => cur.memory_kib,
        },
        iterations: a.kdf_iterations.unwrap_or(cur.iterations),
        parallelism: a.kdf_parallelism.unwrap_or(cur.parallelism),
    };
    kdf.validate()?;
    warn_if_weak_kdf(&kdf);
    ui::info("Kies een nieuw hoofdwachtwoord. Ook nu geldt: vergeten = alles kwijt.");
    let new_pw: SecretString = prompt::new_strong_password("hoofdwachtwoord")?;
    uv.change_password(new_pw.expose_secret().as_bytes(), kdf)?;
    ui::success("Hoofdwachtwoord gewijzigd. Alle items en de back-up gebruiken nu de nieuwe sleutel.");
    ui::warn(
        "Kopieën en exports die je eerder zelf hebt gemaakt, openen nog steeds met het OUDE \
         wachtwoord. Verwijder die als je denkt dat het oude wachtwoord is uitgelekt.",
    );
    Ok(())
}

fn export(uv: &UnlockedVault, file: &Path) -> Result<()> {
    if fs::symlink_metadata(file).is_ok() {
        return Err(Error::AlreadyExists(file.to_path_buf()));
    }
    ui::info("Kies een wachtwoord voor het exportbestand (mag anders zijn dan je hoofdwachtwoord).");
    let pw = prompt::new_strong_password("exportwachtwoord")?;
    uv.export_to(file, pw.expose_secret().as_bytes(), KdfParams::DEFAULT)?;
    ui::success(&format!("{} item(s) versleuteld geëxporteerd naar {}", uv.vault.len(), file.display()));
    ui::info("Zonder het exportwachtwoord is dit bestand onbruikbaar. Importeren: `kluis import <bestand>`.");
    Ok(())
}

fn import_vault(uv: &mut UnlockedVault, file: &Path) -> Result<()> {
    let pw = prompt::secret("Wachtwoord van het importbestand: ")?;
    let (other, other_key) = storage::read_vault_file(file, pw.expose_secret().as_bytes())?;
    drop(pw);
    let (vault, key) = uv.parts_mut();
    let (added, skipped) = vault.merge(&other, other_key.item_key(), key)?;
    if added > 0 {
        uv.save()?;
    }
    ui::success(&format!("{added} item(s) toegevoegd, {skipped} al aanwezig (overgeslagen)."));
    if added > 0 {
        ui::info("Items met een bestaande naam hebben een volgnummer gekregen, bijv. \"GitHub (2)\".");
    }
    Ok(())
}

fn import_csv(uv: &mut UnlockedVault, file: &Path) -> Result<()> {
    ui::banner(&[
        "LET OP: een CSV-export is NIET versleuteld.",
        "Iedereen die dit bestand kan lezen, ziet al je wachtwoorden.",
        "Verwijder het direct na het importeren (kluis biedt dat zo aan)",
        "en kijk ook in je map Downloads, de prullenbak en je back-ups.",
    ]);
    let f =
        File::options().read(true).custom_flags(libc::O_NOFOLLOW).open(file).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => {
                Error::InvalidInput(format!("bestand {} niet gevonden", file.display()))
            }
            _ => Error::Io(e),
        })?;
    let parsed = import::parse_csv(f, uv.item_key())?;
    let (vault, key) = uv.parts_mut();
    let (added, duplicates) = vault.merge(&parsed.vault, key, key)?;
    if added > 0 {
        uv.save()?;
    }
    ui::success(&format!(
        "{added} item(s) geïmporteerd; {duplicates} al aanwezig; {} lege of ongeldige regel(s) overgeslagen.",
        parsed.skipped
    ));
    drop(parsed);

    if prompt::confirm(&format!("Wil je {} nu overschrijven en verwijderen?", file.display()))? {
        import::overwrite_and_remove(file)?;
        ui::success("CSV-bestand overschreven en verwijderd.");
        ui::warn(
            "Op SSD's en op btrfs/ZFS (copy-on-write) kan de oude inhoud ondanks het \
             overschrijven nog op de schijf staan. Volledige schijfversleuteling (LUKS) is \
             de echte bescherming.",
        );
    } else {
        ui::warn(&format!(
            "Verwijder het CSV-bestand zelf zo snel mogelijk, bijv. met: shred -u \"{}\"",
            file.display()
        ));
    }
    Ok(())
}

fn info(paths: &VaultPaths) -> Result<()> {
    let yes_no = |b: bool| if b { "ja" } else { "nee" };
    println!("{}", ui::bold("CakePass-kluis"));
    println!("  Bestand:          {}", paths.file.display());
    match fs::symlink_metadata(&paths.file) {
        Err(_) => println!("  Status:           bestaat nog niet (maak er een met `kluis init`)"),
        Ok(meta) => {
            let mode = meta.mode() & 0o777;
            let mode_ok = mode & 0o077 == 0;
            println!("  Grootte:          {} bytes", meta.len());
            println!(
                "  Rechten:          {mode:o} {}",
                if mode_ok { "(goed: alleen jij)" } else { "(TE RUIM: wordt bij openen hersteld)" }
            );
            println!("  Gewijzigd:        {}", ui::format_time(meta.mtime().max(0) as u64));
            match storage::read_header(&paths.file) {
                Ok(h) => {
                    println!("  Formaatversie:    {}", h.version);
                    println!(
                        "  Sleutelafleiding: Argon2id, {} MiB, {} iteraties, {} lanes{}",
                        h.kdf.memory_kib / 1024,
                        h.kdf.iterations,
                        h.kdf.parallelism,
                        if h.kdf.weaker_than_default() { " (lichter dan aanbevolen)" } else { "" }
                    );
                    println!("  Versleuteling:    XChaCha20-Poly1305");
                    if h.version >= 2 {
                        println!(
                            "  Tweede laag:      alle inhoud per item apart versleuteld \
                             (XChaCha20-Poly1305, eigen HKDF-subsleutel)"
                        );
                    } else {
                        println!("  Tweede laag:      nog niet (oud formaat; wordt bij openen bijgewerkt)");
                    }
                }
                Err(e) => println!("  Header:           onleesbaar ({e})"),
            }
        }
    }
    match fs::metadata(&paths.backup) {
        Ok(m) => println!(
            "  Back-up:          {} ({})",
            paths.backup.display(),
            ui::format_time(m.mtime().max(0) as u64)
        ),
        Err(_) => println!("  Back-up:          nog geen"),
    }

    println!("{}", ui::bold("Systeem"));
    let tool = clipboard::detect();
    println!(
        "  Klembord:         {}",
        tool.map_or("niet gevonden (installeer wl-clipboard of xclip)", |t| t.name())
    );
    let mlock = secure_mem::mlock_works();
    let limit = match secure_mem::memlock_limit() {
        Some(l) => format!("{} KiB", l / 1024),
        None => "onbeperkt".into(),
    };
    println!("  mlock werkt:      {} (limiet {limit})", yes_no(mlock));
    if let Some(h) = HARDENING.get() {
        println!("  Core dumps uit:   {}", yes_no(h.core_dumps_disabled));
        println!("  Niet-dumpbaar:    {}", yes_no(h.non_dumpable));
    }
    Ok(())
}

fn completions(shell: clap_complete::Shell) -> Result<()> {
    clap_complete::generate(shell, &mut super::args::localize(Cli::command()), "kluis", &mut io::stdout());
    Ok(())
}
