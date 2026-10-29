//! Uitvoering van de opdrachten. Alle beveiligingslogica zit in de
//! bibliotheek; hier zit alleen de interactie met de gebruiker.

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::OnceLock;

use clap::CommandFactory;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use kluis::clipboard::{self, CLEAR_AFTER_SECS};

use kluis::crypto::KdfParams;
use kluis::generator::{self, PassphraseOptions, PasswordOptions};
use kluis::secure_mem::{self, Hardening};
use kluis::storage::{self, UnlockedVault, VaultPaths};
use kluis::vault::{Entry, NewEntry, Vault};
use kluis::{Error, Result, import};

use super::args::{AddArgs, Cli, Cmd, EditArgs, GenArgs, GetArgs, KdfArgs, KdfChangeArgs};
use super::{prompt, shell, ui};

static HARDENING: OnceLock<Hardening> = OnceLock::new();

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
    match cli.command {
        Cmd::Init { kdf } => init(&paths, &kdf),
        Cmd::Generate { opts, show } => generate(&opts, show),
        Cmd::Info => info(&paths),
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
        Cmd::List { tag } => list(&uv.vault, tag.as_deref()),
        Cmd::Search { query } => search(&uv.vault, &query),
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
        Cmd::Completions { shell } => completions(shell),
        Cmd::Init { .. } | Cmd::Shell { .. } => {
            Err(Error::InvalidInput("deze opdracht werkt niet binnen `kluis shell`".into()))
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

/// Vraag het hoofdwachtwoord en open de kluis.
pub fn unlock(paths: &VaultPaths) -> Result<UnlockedVault> {
    // Eerst de header controleren, zodat een kapot of onbekend bestand
    // meteen een duidelijke fout geeft, zonder eerst om een wachtwoord te vragen.
    storage::read_header(&paths.file)?;
    let pw = prompt::secret("Hoofdwachtwoord: ")?;
    let mut uv = UnlockedVault::open(paths.clone(), pw.expose_secret().as_bytes())?;
    drop(pw);
    for w in uv.take_warnings() {
        ui::warn(&w);
    }
    if secure_mem::mlock_failed() {
        ui::warn(
            "Het geheugen kon niet worden vergrendeld (mlock). Geheimen kunnen dan in swap \
             terechtkomen. Zie `kluis info`.",
        );
    }
    Ok(uv)
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

/// Kopieer naar het klembord en laat het na 20 s wissen.
fn copy_to_clipboard(secret: &str, what: &str) -> Result<()> {
    let tool = clipboard::detect().ok_or(Error::NoClipboard)?;
    clipboard::copy_with_auto_clear(tool, secret.as_bytes())?;
    ui::success(&format!(
        "{what} gekopieerd naar het klembord (via {}); het wordt over {CLEAR_AFTER_SECS} seconden gewist.",
        tool.name()
    ));
    Ok(())
}

/// Zoek een item; geef suggesties als het niet bestaat.
fn find_entry<'a>(vault: &'a Vault, name: &str) -> Result<&'a Entry> {
    if let Some(e) = vault.get(name) {
        return Ok(e);
    }
    let suggestions: Vec<&str> = vault.search(name).iter().take(5).map(|e| e.name()).collect();
    if !suggestions.is_empty() {
        ui::info(&format!("Bedoelde je: {}?", suggestions.join(", ")));
    }
    Err(Error::EntryNotFound(name.to_string()))
}

/// Vraag een nieuw wachtwoord voor een item (met herhaling in een terminal).
/// Leeg = genereren. Geeft (wachtwoord, gegenereerd?) terug.
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

// ───────────────────────── opdrachten ─────────────────────────

fn init(paths: &VaultPaths, kdf_args: &KdfArgs) -> Result<()> {
    if fs::symlink_metadata(&paths.file).is_ok() {
        return Err(Error::AlreadyExists(paths.file.clone()));
    }
    let kdf = kdf_from_args(kdf_args)?;
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
        "Volgende stap: `kluis add <naam>`. Maak regelmatig een kopie van het kluisbestand (zie README).",
    );
    Ok(())
}

fn add(uv: &mut UnlockedVault, a: AddArgs) -> Result<()> {
    if uv.vault.contains(&a.name) {
        return Err(Error::EntryExists(a.name.trim().to_string()));
    }
    let interactive = a.username.is_none() && a.url.is_none() && a.tags.is_none();
    let username = match a.username {
        Some(u) => u,
        None => prompt::line("Gebruikersnaam (optioneel): ")?,
    };
    let url = match a.url {
        Some(u) => u,
        None => prompt::line("URL (optioneel): ")?,
    };
    let tags = match a.tags {
        Some(t) => t,
        None => split_tags(&prompt::line("Tags, gescheiden door komma's (optioneel): ")?),
    };
    let notes =
        if interactive { prompt::line("Notities (optioneel, één regel): ")? } else { String::new() };
    let (password, generated_bits) = if a.generate {
        let (pw, bits) = generate_secret(&a.gen_opts)?;
        (pw, Some(bits))
    } else {
        ask_item_password(&a.gen_opts)?
    };
    let entry = Entry::new(
        NewEntry { name: a.name.clone(), username, password: password.to_string(), url, notes, tags },
        uv.item_key(),
    )?;
    let name = entry.name().to_string();
    uv.vault.add(entry)?;
    uv.save()?;
    ui::success(&format!("Item '{name}' opgeslagen."));
    if let Some(bits) = generated_bits {
        report_generated(&name, &password, bits);
    }
    Ok(())
}

fn get(uv: &UnlockedVault, g: &GetArgs) -> Result<()> {
    let e = find_entry(&uv.vault, &g.name)?;
    let hidden = ui::dim("(verborgen; gebruik --show)");
    let empty = ui::dim("-");
    let or_dash = |s: &str| if s.is_empty() { empty.clone() } else { s.to_string() };
    println!("{}  {}", ui::bold("Naam:          "), e.name());
    println!("{}  {}", ui::bold("Gebruikersnaam:"), or_dash(e.username()));
    println!("{}  {}", ui::bold("URL:           "), or_dash(e.url()));
    println!("{}  {}", ui::bold("Tags:          "), or_dash(&e.tags().join(", ")));
    println!("{}  {}", ui::bold("Gewijzigd:     "), ui::format_time(e.modified()));
    if g.show {
        // Pas hier, op jouw uitdrukkelijke verzoek, worden ze ontsleuteld.
        let key = uv.item_key();
        let show = |label: &str, value: &str, keep_newlines: bool| -> Result<()> {
            let shown = if value.is_empty() {
                Zeroizing::new(empty.clone())
            } else {
                Zeroizing::new(ui::safe(value, keep_newlines))
            };
            ui::print_secret_line(&format!("{}  ", ui::bold(label)), &shown)?;
            Ok(())
        };
        show("Notities:      ", &e.notes(key)?, true)?;
        show("Wachtwoord:    ", &e.password(key)?, false)?;
        return Ok(());
    }
    println!(
        "{}  {}",
        ui::bold("Notities:      "),
        if e.has_notes() { hidden.clone() } else { empty.clone() }
    );
    println!("{}  {}", ui::bold("Wachtwoord:    "), if e.has_password() { hidden } else { empty });
    if g.no_copy {
        return Ok(());
    }
    if g.copy_username {
        if e.username().is_empty() {
            return Err(Error::InvalidInput("dit item heeft geen gebruikersnaam".into()));
        }
        copy_to_clipboard(e.username(), "De gebruikersnaam")
    } else if !e.has_password() {
        ui::info("Dit item heeft geen wachtwoord.");
        Ok(())
    } else {
        copy_to_clipboard(&e.password(uv.item_key())?, "Het wachtwoord")
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
    let current = find_entry(&uv.vault, &a.name)?;
    let old_name = current.name().to_string();
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
    let mut notes: Option<String> = None;
    let mut new_password: Option<Zeroizing<String>> = None;
    let mut generated_bits = None;

    if interactive {
        ui::info("Druk op Enter om een veld ongewijzigd te laten, of typ '-' om het leeg te maken.");
        rename = keep_or(prompt::line(&format!("Naam [{}]: ", current.name()))?).filter(|s| !s.is_empty());
        username = keep_or(prompt::line(&format!("Gebruikersnaam [{}]: ", current.username()))?);
        url = keep_or(prompt::line(&format!("URL [{}]: ", current.url()))?);
        tags = keep_or(prompt::line(&format!("Tags [{}]: ", current.tags().join(", ")))?)
            .map(|t| split_tags(&t));
        if prompt::confirm("Notities wijzigen?")? {
            notes = Some(prompt::line("Nieuwe notities (één regel, leeg = wissen): ")?);
        }
        let choice =
            prompt::line("Wachtwoord: (n)iet wijzigen, (i)ntypen of (g)enereren? [n] ")?.to_lowercase();
        match choice.as_str() {
            "" | "n" | "niet" => {}
            "i" | "intypen" => new_password = Some(ask_item_password(&a.gen_opts)?.0),
            "g" | "genereren" => {
                let (pw, bits) = generate_secret(&a.gen_opts)?;
                new_password = Some(pw);
                generated_bits = Some(bits);
            }
            _ => return Err(Error::InvalidInput("kies n, i of g".into())),
        }
    } else {
        if a.notes {
            notes = Some(prompt::line("Nieuwe notities (één regel, leeg = wissen): ")?);
        }
        if a.generate {
            let (pw, bits) = generate_secret(&a.gen_opts)?;
            new_password = Some(pw);
            generated_bits = Some(bits);
        } else if a.password {
            let first = prompt::secret("Nieuw wachtwoord: ")?;
            if prompt::stdin_is_tty() {
                let again = prompt::secret("Herhaal wachtwoord: ")?;
                if !prompt::secrets_equal(&first, &again) {
                    return Err(Error::InvalidInput("de wachtwoorden komen niet overeen".into()));
                }
            }
            new_password = Some(Zeroizing::new(first.expose_secret().to_string()));
        }
    }

    // Alles-of-niets: bij een fout (bijv. bestaande naam) blijft het item ongewijzigd.
    let (vault, key) = uv.parts_mut();
    vault.update(&old_name, |entry| {
        if let Some(u) = &username {
            entry.set_username(u)?;
        }
        if let Some(u) = &url {
            entry.set_url(u)?;
        }
        if let Some(t) = &tags {
            entry.set_tags(t)?;
        }
        if let Some(n) = &notes {
            entry.set_notes(key, n)?;
        }
        if let Some(p) = &new_password {
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
    if let (Some(p), Some(bits)) = (&new_password, generated_bits) {
        report_generated(&final_name, p, bits);
    }
    Ok(())
}

fn rm(uv: &mut UnlockedVault, name: &str, yes: bool) -> Result<()> {
    let real = find_entry(&uv.vault, name)?.name().to_string();
    if !yes && !prompt::confirm(&format!("Weet je zeker dat je '{real}' wilt verwijderen?"))? {
        ui::info("Niets verwijderd.");
        return Ok(());
    }
    uv.vault.remove(&real)?;
    uv.save()?;
    ui::success(&format!("Item '{real}' verwijderd. (De vorige versie staat nog in de back-up.)"));
    Ok(())
}

fn print_table(entries: &[&Entry]) {
    let w_name = entries.iter().map(|e| e.name().chars().count()).max().unwrap_or(0).clamp(4, 32);
    let w_user = entries.iter().map(|e| e.username().chars().count()).max().unwrap_or(0).clamp(14, 28);
    let w_url = entries.iter().map(|e| e.url().chars().count()).max().unwrap_or(0).clamp(3, 36);
    println!(
        "{}",
        ui::bold(&format!(
            "{}  {}  {}  TAGS",
            ui::pad("NAAM", w_name),
            ui::pad("GEBRUIKERSNAAM", w_user),
            ui::pad("URL", w_url)
        ))
    );
    for e in entries {
        println!(
            "{}  {}  {}  {}",
            ui::pad(&ui::truncate(e.name(), w_name), w_name),
            ui::pad(&ui::truncate(e.username(), w_user), w_user),
            ui::pad(&ui::truncate(e.url(), w_url), w_url),
            e.tags().join(", ")
        );
    }
}

fn list(vault: &Vault, tag: Option<&str>) -> Result<()> {
    let entries: Vec<&Entry> = vault.entries().iter().filter(|e| tag.is_none_or(|t| e.has_tag(t))).collect();
    if entries.is_empty() {
        if vault.is_empty() {
            ui::info("De kluis is nog leeg. Voeg een item toe met `kluis add <naam>`.");
        } else {
            ui::info("Geen items met deze tag.");
        }
        return Ok(());
    }
    print_table(&entries);
    ui::info(&format!("{} item(s)", entries.len()));
    Ok(())
}

fn search(vault: &Vault, query: &str) -> Result<()> {
    let found = vault.search(query);
    if found.is_empty() {
        ui::info(&format!("Niets gevonden voor '{query}'."));
    } else {
        print_table(&found);
        ui::info(&format!("{} item(s) gevonden", found.len()));
    }
    Ok(())
}

fn generate(g: &GenArgs, show: bool) -> Result<()> {
    let (secret, bits) = generate_secret(g)?;
    if show {
        ui::print_secret_line("", &secret)?;
        ui::info(&format!("Sterkte: ongeveer {bits:.0} bits."));
        Ok(())
    } else {
        copy_to_clipboard(&secret, "Het gegenereerde wachtwoord")?;
        ui::info(&format!("Sterkte: ongeveer {bits:.0} bits."));
        Ok(())
    }
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
    ui::success("Hoofdwachtwoord gewijzigd. Ook de back-up gebruikt nu het nieuwe wachtwoord.");
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
    println!("{}", ui::bold("Kluis"));
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
                            "  Tweede laag:      elk wachtwoord en elke notitie apart versleuteld \
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
