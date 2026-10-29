//! Het kluismodel: items en bewerkingen daarop. Puur in-memory; geen I/O.
//!
//! BEVEILIGINGSKRITIEK – tweede versleutelingslaag.
//! Alle inhoud van een item (gebruikersnaam, URL, wachtwoord/API-sleutel en
//! notities) wordt per veld apart versleuteld met de itemsleutel
//! ([`ItemKey`]), elk met een eigen willekeurige nonce. Ook als de kluis
//! geopend is, staat die inhoud dus alleen versleuteld in het geheugen. Lezen
//! kan alleen via de methoden die de sleutel vragen; de klare tekst bestaat
//! dan heel even in een `Zeroizing<String>` en wordt daarna gewist.
//!
//! Alleen naam, soort, tags en datums zijn niet apart versleuteld (wel door
//! de buitenste laag op schijf), zodat je items kunt vinden en sorteren.
//!
//! Soorten items ([`Kind`]):
//! - **login**: gebruikersnaam, URL, wachtwoord, notities
//! - **api**: account/sleutel-ID, service-URL, de API-sleutel, notities
//! - **notitie**: alleen tekst (meerdere regels), bijv. herstelcodes
//!
//! Alle velden worden bij opruimen gewist (`ZeroizeOnDrop`). `Debug` toont
//! nooit geheimen.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{self, ItemKey};
use crate::error::{Error, Result};
use crate::secure_mem::{CountingWriter, SecureBuf};

/// Huidige versie van de (versleutelde) JSON-inhoud.
/// 1 = alles als tekst binnen de kluis; 2 = wachtwoord en notities per veld
/// versleuteld; 3 = alle inhoud per veld versleuteld + soorten items.
pub const SCHEMA_VERSION: u32 = 3;
const MAX_NAME_LEN: usize = 200;
const MAX_FIELD_LEN: usize = 64 * 1024;
const FIELD_USERNAME: &str = "username";
const FIELD_URL: &str = "url";
const FIELD_PASSWORD: &str = "password";
const FIELD_NOTES: &str = "notes";

/// Huidige tijd in seconden sinds 1970.
pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Soort item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Inloggegevens voor een website of dienst.
    #[default]
    Login,
    /// Een API-sleutel of token.
    Api,
    /// Een beveiligde notitie.
    Note,
}

impl Kind {
    /// Korte Nederlandse naam.
    pub fn label(self) -> &'static str {
        match self {
            Kind::Login => "login",
            Kind::Api => "api-sleutel",
            Kind::Note => "notitie",
        }
    }

    /// Hoe het geheime veld heet bij deze soort.
    pub fn secret_label(self) -> &'static str {
        match self {
            Kind::Login => "wachtwoord",
            Kind::Api => "API-sleutel",
            Kind::Note => "notitie",
        }
    }

    /// Lees een soort uit tekst ("login", "api", "notitie", ...).
    pub fn parse(s: &str) -> Option<Kind> {
        match s.trim().to_lowercase().as_str() {
            "login" | "wachtwoord" | "password" => Some(Kind::Login),
            "api" | "api-sleutel" | "apikey" | "api-key" | "token" | "sleutel" => Some(Kind::Api),
            "notitie" | "note" | "notities" | "notes" => Some(Kind::Note),
            _ => None,
        }
    }
}

/// Eén item in de kluis.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Entry {
    name: String,
    #[serde(default)]
    #[zeroize(skip)]
    kind: Kind,
    /// Versleuteld: base64(nonce || ciphertext || tag).
    username_sealed: String,
    /// Versleuteld.
    url_sealed: String,
    /// Versleuteld: wachtwoord (login) of API-sleutel (api).
    password_sealed: String,
    /// Versleuteld: notities, of de inhoud van een notitie.
    notes_sealed: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    created: u64,
    #[serde(default)]
    modified: u64,
}

/// Velden voor een nieuw item (alles behalve de naam is optioneel).
///
/// Bevat tijdelijk geheimen in klare tekst; de wissende allocator in de
/// binary ruimt het geheugen op. Roep `zeroize()` aan om het eerder te wissen.
#[derive(Default, Zeroize)]
pub struct NewEntry {
    pub name: String,
    #[zeroize(skip)]
    pub kind: Kind,
    pub username: String,
    /// Wachtwoord (login) of API-sleutel (api); leeg bij een notitie.
    pub password: String,
    pub url: String,
    /// Notities, of de tekst van een notitie.
    pub notes: String,
    pub tags: Vec<String>,
}

impl Entry {
    /// Maak een gecontroleerd item; alle inhoud wordt direct versleuteld.
    pub fn new(fields: NewEntry, key: &ItemKey) -> Result<Entry> {
        let t = now();
        let mut e = Entry {
            name: String::new(),
            kind: fields.kind,
            username_sealed: String::new(),
            url_sealed: String::new(),
            password_sealed: String::new(),
            notes_sealed: String::new(),
            tags: Vec::new(),
            created: t,
            modified: t,
        };
        e.set_name(&fields.name)?;
        e.set_username(key, &fields.username)?;
        e.set_password(key, &fields.password)?;
        e.set_url(key, &fields.url)?;
        e.set_notes(key, &fields.notes)?;
        e.set_tags(&fields.tags)?;
        e.modified = t;
        Ok(e)
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn kind(&self) -> Kind {
        self.kind
    }
    /// Ontsleutel de gebruikersnaam (of account/sleutel-ID bij een API-sleutel).
    pub fn username(&self, key: &ItemKey) -> Result<Zeroizing<String>> {
        key.open(FIELD_USERNAME, &self.username_sealed)
    }
    /// Ontsleutel de URL.
    pub fn url(&self, key: &ItemKey) -> Result<Zeroizing<String>> {
        key.open(FIELD_URL, &self.url_sealed)
    }
    /// Ontsleutel het wachtwoord of de API-sleutel. Alleen gebruiken om naar
    /// het klembord te kopiëren of op uitdrukkelijk verzoek (`--show`) te tonen.
    pub fn password(&self, key: &ItemKey) -> Result<Zeroizing<String>> {
        key.open(FIELD_PASSWORD, &self.password_sealed)
    }
    /// Ontsleutel de notities (of de inhoud van een notitie).
    pub fn notes(&self, key: &ItemKey) -> Result<Zeroizing<String>> {
        key.open(FIELD_NOTES, &self.notes_sealed)
    }
    /// Ontsleutel het belangrijkste geheim van dit item: het wachtwoord, de
    /// API-sleutel of de tekst van de notitie.
    pub fn secret(&self, key: &ItemKey) -> Result<Zeroizing<String>> {
        match self.kind {
            Kind::Note => self.notes(key),
            Kind::Login | Kind::Api => self.password(key),
        }
    }
    /// Of er een wachtwoord/API-sleutel is (zonder te ontsleutelen).
    pub fn has_password(&self) -> bool {
        crypto::sealed_plaintext_len(&self.password_sealed) > 0
    }
    /// Of er notities zijn (zonder te ontsleutelen).
    pub fn has_notes(&self) -> bool {
        crypto::sealed_plaintext_len(&self.notes_sealed) > 0
    }
    /// Of het hoofdgeheim gevuld is (zonder te ontsleutelen).
    pub fn has_secret(&self) -> bool {
        match self.kind {
            Kind::Note => self.has_notes(),
            Kind::Login | Kind::Api => self.has_password(),
        }
    }
    pub fn tags(&self) -> &[String] {
        &self.tags
    }
    pub fn created(&self) -> u64 {
        self.created
    }
    pub fn modified(&self) -> u64 {
        self.modified
    }

    fn touch(&mut self) {
        self.modified = now();
    }

    pub fn set_name(&mut self, name: &str) -> Result<()> {
        let name = validate_name(name)?;
        replace_secret(&mut self.name, name);
        self.touch();
        Ok(())
    }
    pub fn set_username(&mut self, key: &ItemKey, v: &str) -> Result<()> {
        self.username_sealed = key.seal(FIELD_USERNAME, validate_line("gebruikersnaam", v)?)?;
        self.touch();
        Ok(())
    }
    pub fn set_password(&mut self, key: &ItemKey, v: &str) -> Result<()> {
        if v.len() > MAX_FIELD_LEN {
            return Err(Error::InvalidInput("wachtwoord of sleutel is te lang".into()));
        }
        self.password_sealed = key.seal(FIELD_PASSWORD, v)?;
        self.touch();
        Ok(())
    }
    pub fn set_url(&mut self, key: &ItemKey, v: &str) -> Result<()> {
        self.url_sealed = key.seal(FIELD_URL, validate_line("URL", v)?)?;
        self.touch();
        Ok(())
    }
    pub fn set_notes(&mut self, key: &ItemKey, v: &str) -> Result<()> {
        if v.len() > MAX_FIELD_LEN {
            return Err(Error::InvalidInput("notities zijn te lang".into()));
        }
        // Regeleinden en tabs mogen; andere stuurtekens (zoals ANSI-escapes
        // die je terminal kunnen manipuleren) niet.
        if v.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
            return Err(Error::InvalidInput("notities bevatten ongeldige tekens".into()));
        }
        self.notes_sealed = key.seal(FIELD_NOTES, v)?;
        self.touch();
        Ok(())
    }
    pub fn set_tags(&mut self, tags: &[String]) -> Result<()> {
        let mut clean: Vec<String> = Vec::new();
        for t in tags {
            let t = validate_line("tag", t)?;
            if !t.is_empty() && !clean.iter().any(|c| c.to_lowercase() == t.to_lowercase()) {
                clean.push(t.to_string());
            }
        }
        self.tags.zeroize();
        self.tags = clean;
        self.touch();
        Ok(())
    }

    /// Versleutel alle inhoud opnieuw met een andere sleutel (na `passwd`,
    /// bij export en import). De wijzigingsdatum blijft gelijk.
    fn reseal(&mut self, from: &ItemKey, to: &ItemKey) -> Result<()> {
        let username = self.username(from)?;
        let url = self.url(from)?;
        let pw = self.password(from)?;
        let notes = self.notes(from)?;
        self.username_sealed = to.seal(FIELD_USERNAME, &username)?;
        self.url_sealed = to.seal(FIELD_URL, &url)?;
        self.password_sealed = to.seal(FIELD_PASSWORD, &pw)?;
        self.notes_sealed = to.seal(FIELD_NOTES, &notes)?;
        Ok(())
    }

    /// Of het item past bij een zoekterm (hoofdletterongevoelig). Zoekt in
    /// naam, soort, tags, gebruikersnaam en URL (die laatste twee worden
    /// daarvoor even ontsleuteld); nooit in wachtwoorden, sleutels of notities.
    pub fn matches(&self, query: &str, key: &ItemKey) -> bool {
        let q = query.to_lowercase();
        let hit = |s: &str| s.to_lowercase().contains(&q);
        hit(&self.name)
            || hit(self.kind.label())
            || self.tags.iter().any(|t| hit(t))
            || self.username(key).is_ok_and(|u| hit(&u))
            || self.url(key).is_ok_and(|u| hit(&u))
    }

    pub fn has_tag(&self, tag: &str) -> bool {
        let tag = tag.to_lowercase();
        self.tags.iter().any(|t| t.to_lowercase() == tag)
    }
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("inhoud", &"[VERSLEUTELD]")
            .field("tags", &self.tags)
            .finish()
    }
}

/// Overschrijf een String veilig: wis eerst de oude inhoud.
fn replace_secret(target: &mut String, new: &str) {
    target.zeroize();
    target.push_str(new);
}

fn validate_name(name: &str) -> Result<&str> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::InvalidInput("de naam mag niet leeg zijn".into()));
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(Error::InvalidInput("de naam is te lang (max. 200 tekens)".into()));
    }
    if name.chars().any(char::is_control) {
        return Err(Error::InvalidInput("de naam bevat ongeldige tekens".into()));
    }
    Ok(name)
}

fn validate_line<'a>(what: &str, v: &'a str) -> Result<&'a str> {
    let v = v.trim();
    if v.len() > MAX_FIELD_LEN {
        return Err(Error::InvalidInput(format!("{what} is te lang")));
    }
    if v.chars().any(char::is_control) {
        return Err(Error::InvalidInput(format!("{what} bevat ongeldige tekens")));
    }
    Ok(v)
}

/// "GitHub (2)" → "GitHub"; andere namen blijven gelijk.
fn base_name(name: &str) -> &str {
    let name = name.trim();
    if let Some(open) = name.rfind(" (") {
        let inner = &name[open + 2..];
        if let Some(num) = inner.strip_suffix(')')
            && !num.is_empty()
            && num.chars().all(|c| c.is_ascii_digit())
        {
            return &name[..open];
        }
    }
    name
}

fn same_name(a: &str, b: &str) -> bool {
    a.trim().to_lowercase() == b.trim().to_lowercase()
}

// ───────────────────────── oudere schema's (migratie) ─────────────────────────

/// Alleen om het schemanummer te lezen vóór de echte verwerking.
#[derive(Deserialize)]
struct SchemaPeek {
    schema: u32,
}

/// Schema 1: alles als gewone tekst (binnen de buitenste versleuteling).
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct VaultV1 {
    entries: Vec<EntryV1>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct EntryV1 {
    name: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    created: u64,
    #[serde(default)]
    modified: u64,
}

/// Schema 2: wachtwoord en notities versleuteld, gebruikersnaam en URL niet.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct VaultV2 {
    entries: Vec<EntryV2>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct EntryV2 {
    name: String,
    #[serde(default)]
    username: String,
    password_sealed: String,
    #[serde(default)]
    url: String,
    notes_sealed: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    created: u64,
    #[serde(default)]
    modified: u64,
}

// ───────────────────────── de kluis ─────────────────────────

/// De volledige kluisinhoud (met per veld versleutelde inhoud).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Vault {
    schema: u32,
    entries: Vec<Entry>,
}

impl Default for Vault {
    fn default() -> Self {
        Vault { schema: SCHEMA_VERSION, entries: Vec::new() }
    }
}

impl Vault {
    pub fn new() -> Vault {
        Vault::default()
    }

    /// Lees de JSON-inhoud (na ontsleutelen van de buitenste laag).
    ///
    /// Geeft ook terug of de inhoud is omgezet vanuit een ouder schema; de
    /// aanroeper moet de kluis dan opnieuw opslaan.
    pub fn from_json(bytes: &[u8], key: &ItemKey) -> Result<(Vault, bool)> {
        let peek: SchemaPeek = serde_json::from_slice(bytes).map_err(|_| Error::CorruptPayload)?;
        let (mut v, migrated) = match peek.schema {
            1 => (Self::migrate_v1(bytes, key)?, true),
            2 => (Self::migrate_v2(bytes, key)?, true),
            SCHEMA_VERSION => {
                (serde_json::from_slice::<Vault>(bytes).map_err(|_| Error::CorruptPayload)?, false)
            }
            other => return Err(Error::UnsupportedVersion(u16::try_from(other).unwrap_or(u16::MAX))),
        };
        v.schema = SCHEMA_VERSION;
        v.validate()?;
        v.sort();
        Ok((v, migrated))
    }

    /// Schema 1 → 3: versleutel alle inhoud per veld.
    fn migrate_v1(bytes: &[u8], key: &ItemKey) -> Result<Vault> {
        let old: VaultV1 = serde_json::from_slice(bytes).map_err(|_| Error::CorruptPayload)?;
        let mut v = Vault::new();
        for e in &old.entries {
            let mut new = Entry::new(
                NewEntry {
                    name: e.name.clone(),
                    kind: Kind::Login,
                    username: e.username.clone(),
                    password: e.password.clone(),
                    url: e.url.clone(),
                    notes: e.notes.clone(),
                    tags: e.tags.clone(),
                },
                key,
            )
            .map_err(|_| Error::CorruptPayload)?;
            new.created = e.created;
            new.modified = e.modified;
            v.entries.push(new);
        }
        Ok(v)
    }

    /// Schema 2 → 3: versleutel ook gebruikersnaam en URL.
    fn migrate_v2(bytes: &[u8], key: &ItemKey) -> Result<Vault> {
        let old: VaultV2 = serde_json::from_slice(bytes).map_err(|_| Error::CorruptPayload)?;
        let mut v = Vault::new();
        for e in &old.entries {
            let username = validate_line("", &e.username).map_err(|_| Error::CorruptPayload)?;
            let url = validate_line("", &e.url).map_err(|_| Error::CorruptPayload)?;
            v.entries.push(Entry {
                name: e.name.clone(),
                kind: Kind::Login,
                username_sealed: key.seal(FIELD_USERNAME, username)?,
                url_sealed: key.seal(FIELD_URL, url)?,
                password_sealed: e.password_sealed.clone(),
                notes_sealed: e.notes_sealed.clone(),
                tags: e.tags.clone(),
                created: e.created,
                modified: e.modified,
            });
        }
        Ok(v)
    }

    /// Controleer elk item, ook uit (mogelijk kwaadaardige) importbestanden:
    /// geldige velden, geldig versleutelde inhoud en unieke namen.
    fn validate(&self) -> Result<()> {
        for (i, e) in self.entries.iter().enumerate() {
            let valid = validate_name(&e.name).is_ok_and(|n| n == e.name)
                && e.tags.iter().all(|t| validate_line("", t).is_ok_and(|v| !v.is_empty() && v == t))
                && [&e.username_sealed, &e.url_sealed, &e.password_sealed, &e.notes_sealed]
                    .iter()
                    .all(|s| crypto::decode_sealed(s).is_ok())
                && !self.entries[..i].iter().any(|other| same_name(&other.name, &e.name));
            if !valid {
                return Err(Error::CorruptPayload);
            }
        }
        Ok(())
    }

    /// Schrijf de inhoud als JSON rechtstreeks in beschermd geheugen.
    ///
    /// We meten eerst de exacte grootte, zodat de buffer nooit hoeft te
    /// groeien (groeien zou ongewiste kopieën kunnen achterlaten).
    pub fn to_json(&self) -> Result<SecureBuf> {
        let mut counter = CountingWriter::default();
        serde_json::to_writer(&mut counter, self).map_err(|_| Error::CorruptPayload)?;
        let mut buf = SecureBuf::with_capacity(counter.0);
        serde_json::to_writer(&mut buf, self).map_err(|_| Error::CorruptPayload)?;
        Ok(buf)
    }

    fn sort(&mut self) {
        self.entries.sort_by_key(|e| e.name.to_lowercase());
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Alle items, gesorteerd op naam.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Zoek een item op exacte naam (hoofdletterongevoelig).
    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| same_name(&e.name, name))
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn add(&mut self, entry: Entry) -> Result<()> {
        if self.contains(&entry.name) {
            return Err(Error::EntryExists(entry.name.clone()));
        }
        self.entries.push(entry);
        self.sort();
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Result<()> {
        let idx = self
            .entries
            .iter()
            .position(|e| same_name(&e.name, name))
            .ok_or_else(|| Error::EntryNotFound(name.to_string()))?;
        // `Entry` is ZeroizeOnDrop: het verwijderde item wordt gewist.
        self.entries.remove(idx);
        Ok(())
    }

    pub fn rename(&mut self, old: &str, new: &str) -> Result<()> {
        self.update(old, |e| e.set_name(new))
    }

    /// Wijzig een item "alles of niets": de wijzigingen worden op een kopie
    /// uitgevoerd en pas overgenomen als alles gelukt is en de (eventueel
    /// nieuwe) naam niet botst met een ander item.
    pub fn update(&mut self, name: &str, f: impl FnOnce(&mut Entry) -> Result<()>) -> Result<()> {
        let idx = self
            .entries
            .iter()
            .position(|e| same_name(&e.name, name))
            .ok_or_else(|| Error::EntryNotFound(name.to_string()))?;
        let mut copy = self.entries[idx].clone();
        f(&mut copy)?;
        if self.entries.iter().enumerate().any(|(i, e)| i != idx && same_name(&e.name, &copy.name)) {
            return Err(Error::EntryExists(copy.name.clone()));
        }
        self.entries[idx] = copy;
        self.sort();
        Ok(())
    }

    /// Items die bij de zoekterm passen.
    pub fn search(&self, query: &str, key: &ItemKey) -> Vec<&Entry> {
        self.entries.iter().filter(|e| e.matches(query, key)).collect()
    }

    /// Een vrije naam op basis van `base` ("naam", "naam (2)", "naam (3)", ...).
    pub fn unique_name(&self, base: &str) -> String {
        let base = base.trim();
        if !self.contains(base) {
            return base.to_string();
        }
        (2..)
            .map(|n| format!("{base} ({n})"))
            .find(|candidate| !self.contains(candidate))
            .expect("oneindige reeks")
    }

    /// Versleutel alle inhoud opnieuw met een andere itemsleutel (alles of niets).
    pub fn rekey(&mut self, from: &ItemKey, to: &ItemKey) -> Result<()> {
        let mut entries = self.entries.clone();
        for e in &mut entries {
            e.reseal(from, to)?;
        }
        self.entries = entries;
        Ok(())
    }

    /// Voeg items uit een andere kluis toe (die met `other_key` versleuteld is).
    /// Een gelijk item wordt overgeslagen; bij een naamconflict krijgt het
    /// nieuwe item een volgnummer. Geeft (toegevoegd, overgeslagen) terug.
    pub fn merge(&mut self, other: &Vault, other_key: &ItemKey, my_key: &ItemKey) -> Result<(usize, usize)> {
        let mut added = 0;
        let mut skipped = 0;
        for e in other.entries() {
            let theirs =
                (e.username(other_key)?, e.url(other_key)?, e.password(other_key)?, e.notes(other_key)?);
            // Duplicaat: zelfde naam (eventueel met volgnummer, zodat herhaald
            // importeren geen kopieën maakt), soort en inhoud.
            let mut duplicate = false;
            for existing in &self.entries {
                if existing.kind != e.kind || !same_name(base_name(&existing.name), base_name(&e.name)) {
                    continue;
                }
                let mine = (
                    existing.username(my_key)?,
                    existing.url(my_key)?,
                    existing.password(my_key)?,
                    existing.notes(my_key)?,
                );
                let eq = |a: &str, b: &str| bool::from(a.as_bytes().ct_eq(b.as_bytes()));
                if eq(&mine.0, &theirs.0)
                    && eq(&mine.1, &theirs.1)
                    && eq(&mine.2, &theirs.2)
                    && eq(&mine.3, &theirs.3)
                {
                    duplicate = true;
                    break;
                }
            }
            if duplicate {
                skipped += 1;
                continue;
            }
            let mut copy = e.clone();
            copy.reseal(other_key, my_key)?;
            copy.name = self.unique_name(&e.name);
            self.entries.push(copy);
            self.sort();
            added += 1;
        }
        Ok((added, skipped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_item_key;

    fn entry(name: &str, pw: &str) -> Entry {
        Entry::new(
            NewEntry {
                name: name.into(),
                username: "jan".into(),
                password: pw.into(),
                url: "https://example.org".into(),
                notes: "geheime notitie".into(),
                tags: vec!["Werk".into(), "werk".into(), " mail ".into(), String::new()],
                ..Default::default()
            },
            &test_item_key(1),
        )
        .unwrap()
    }

    fn json_of(e: &Entry) -> String {
        let mut v = Vault::new();
        v.add(e.clone()).unwrap();
        String::from_utf8(v.to_json().unwrap().as_slice().to_vec()).unwrap()
    }

    #[test]
    fn toevoegen_opzoeken_verwijderen() {
        let k = test_item_key(1);
        let mut v = Vault::new();
        v.add(entry("GitHub", "pw1")).unwrap();
        v.add(entry("abc", "pw2")).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v.entries()[0].name(), "abc", "gesorteerd op naam");
        assert_eq!(v.get("github").unwrap().password(&k).unwrap().as_str(), "pw1");
        assert!(matches!(v.add(entry("GITHUB", "x")), Err(Error::EntryExists(_))));
        v.remove("GitHub").unwrap();
        assert!(v.get("github").is_none());
        assert!(matches!(v.remove("bestaat-niet"), Err(Error::EntryNotFound(_))));
    }

    #[test]
    fn alle_inhoud_is_per_item_versleuteld() {
        let k = test_item_key(1);
        let e = entry("x", "supergeheim");
        // In het model (en dus in het geheugen en in de JSON) staat geen klare tekst.
        let json = json_of(&e);
        for plain in ["supergeheim", "geheime notitie", "jan", "example.org"] {
            assert!(!json.contains(plain), "{plain} staat leesbaar in de JSON");
        }
        assert!(json.contains("username_sealed") && json.contains("password_sealed"));
        // Alleen met de juiste sleutel te lezen.
        assert_eq!(e.password(&k).unwrap().as_str(), "supergeheim");
        assert_eq!(e.notes(&k).unwrap().as_str(), "geheime notitie");
        assert_eq!(e.username(&k).unwrap().as_str(), "jan");
        assert_eq!(e.url(&k).unwrap().as_str(), "https://example.org");
        for wrong in [e.password(&test_item_key(2)), e.username(&test_item_key(2))] {
            assert!(matches!(wrong, Err(Error::Decrypt)));
        }
        assert!(e.has_password() && e.has_notes());
        // Twee items met hetzelfde wachtwoord zijn versleuteld toch verschillend.
        assert_ne!(entry("a", "zelfde").password_sealed, entry("b", "zelfde").password_sealed);
        let empty = Entry::new(NewEntry { name: "leeg".into(), ..Default::default() }, &k).unwrap();
        assert!(!empty.has_password() && !empty.has_notes());
    }

    #[test]
    fn soorten_items() {
        let k = test_item_key(1);
        let api = Entry::new(
            NewEntry {
                name: "OpenAI".into(),
                kind: Kind::Api,
                username: "projectsleutel-1".into(),
                password: "sk-geheim-123".into(),
                url: "https://api.example.com".into(),
                ..Default::default()
            },
            &k,
        )
        .unwrap();
        let note = Entry::new(
            NewEntry {
                name: "Herstelcodes".into(),
                kind: Kind::Note,
                notes: "regel 1\nregel 2\n\ttab".into(),
                ..Default::default()
            },
            &k,
        )
        .unwrap();
        assert_eq!(api.kind(), Kind::Api);
        assert_eq!(api.secret(&k).unwrap().as_str(), "sk-geheim-123");
        assert_eq!(note.secret(&k).unwrap().as_str(), "regel 1\nregel 2\n\ttab");
        assert!(note.has_secret() && !note.has_password());
        for (e, plain) in [(&api, "sk-geheim"), (&note, "regel 1")] {
            assert!(!json_of(e).contains(plain));
        }
        assert!(json_of(&note).contains("\"kind\":\"note\""));
        assert_eq!(Kind::parse("API"), Some(Kind::Api));
        assert_eq!(Kind::parse("notitie"), Some(Kind::Note));
        assert_eq!(Kind::parse("note"), Some(Kind::Note));
        assert_eq!(Kind::parse("iets"), None);
        // Zoeken op soort werkt; zoeken in de geheime inhoud niet.
        let mut v = Vault::new();
        v.add(api).unwrap();
        v.add(note).unwrap();
        assert_eq!(v.search("api-sleutel", &k).len(), 1);
        assert_eq!(v.search("notitie", &k).len(), 1);
        assert_eq!(v.search("sk-geheim", &k).len(), 0);
        assert_eq!(v.search("regel", &k).len(), 0);
        assert_eq!(v.search("projectsleutel", &k).len(), 1);
    }

    #[test]
    fn tags_worden_opgeschoond() {
        let e = entry("x", "y");
        assert_eq!(e.tags(), &["Werk".to_string(), "mail".to_string()]);
        assert!(e.has_tag("WERK"));
    }

    #[test]
    fn ongeldige_namen() {
        let k = test_item_key(1);
        let bad = |n: &str| Entry::new(NewEntry { name: n.into(), ..Default::default() }, &k).is_err();
        assert!(bad(""));
        assert!(bad("   "));
        assert!(bad("met\nnieuwe regel"));
        assert!(bad(&"x".repeat(201)));
        assert!(!bad("Bank – privé 🏦"));
    }

    #[test]
    fn zoeken_niet_in_wachtwoord_of_notities() {
        let k = test_item_key(1);
        let mut v = Vault::new();
        v.add(entry("Mail", "supergeheim")).unwrap();
        assert_eq!(v.search("MAIL", &k).len(), 1);
        assert_eq!(v.search("example", &k).len(), 1);
        assert_eq!(v.search("JAN", &k).len(), 1);
        assert_eq!(v.search("supergeheim", &k).len(), 0);
        assert_eq!(v.search("notitie", &k).len(), 0);
        assert_eq!(v.search("example", &test_item_key(2)).len(), 0, "verkeerde sleutel vindt niets");
    }

    #[test]
    fn hernoemen() {
        let mut v = Vault::new();
        v.add(entry("a", "1")).unwrap();
        v.add(entry("b", "2")).unwrap();
        assert!(matches!(v.rename("a", "B"), Err(Error::EntryExists(_))));
        v.rename("a", "A").unwrap();
        v.rename("A", "c").unwrap();
        assert!(v.get("c").is_some());
    }

    #[test]
    fn update_is_alles_of_niets() {
        let k = test_item_key(1);
        let mut v = Vault::new();
        v.add(entry("a", "1")).unwrap();
        v.add(entry("b", "2")).unwrap();
        // Botsende naam: niets wordt gewijzigd.
        let r = v.update("a", |e| {
            e.set_username(&k, "nieuw")?;
            e.set_name("B")
        });
        assert!(matches!(r, Err(Error::EntryExists(_))));
        assert_eq!(v.get("a").unwrap().username(&k).unwrap().as_str(), "jan");
        // Fout halverwege: ook niets gewijzigd.
        let r = v.update("a", |e| {
            e.set_username(&k, "nieuw")?;
            e.set_url(&k, "met\nnieuwe regel")
        });
        assert!(r.is_err());
        assert_eq!(v.get("a").unwrap().username(&k).unwrap().as_str(), "jan");
        v.update("a", |e| e.set_username(&k, "nieuw")).unwrap();
        assert_eq!(v.get("a").unwrap().username(&k).unwrap().as_str(), "nieuw");
    }

    #[test]
    fn json_heen_en_terug() {
        let k = test_item_key(1);
        let mut v = Vault::new();
        v.add(entry("één \"quote\" \\ test", "p@ss\"wo\\rd")).unwrap();
        let json = v.to_json().unwrap();
        assert_eq!(json.len(), json.capacity(), "exacte grootte, geen herallocatie");
        let (back, migrated) = Vault::from_json(json.as_slice(), &k).unwrap();
        assert!(!migrated);
        assert_eq!(back.entries(), v.entries());
        assert_eq!(back.entries()[0].password(&k).unwrap().as_str(), "p@ss\"wo\\rd");
    }

    #[test]
    fn migratie_van_schema_1() {
        let k = test_item_key(1);
        let old = br#"{"schema":1,"entries":[{"name":"Oud","username":"u","password":"oud-pw","notes":"n","tags":["t"],"created":5,"modified":6}]}"#;
        let (v, migrated) = Vault::from_json(old, &k).unwrap();
        assert!(migrated);
        let e = v.get("oud").unwrap();
        assert_eq!(e.kind(), Kind::Login);
        assert_eq!(e.password(&k).unwrap().as_str(), "oud-pw");
        assert_eq!(e.notes(&k).unwrap().as_str(), "n");
        assert_eq!(e.username(&k).unwrap().as_str(), "u");
        assert_eq!((e.created(), e.modified()), (5, 6), "datums blijven behouden");
        let json = String::from_utf8(v.to_json().unwrap().as_slice().to_vec()).unwrap();
        assert!(!json.contains("oud-pw") && json.contains("\"schema\":3"));
    }

    #[test]
    fn migratie_van_schema_2() {
        let k = test_item_key(1);
        let pw = k.seal("password", "v2-pw").unwrap();
        let notes = k.seal("notes", "v2-notitie").unwrap();
        let old = format!(
            r#"{{"schema":2,"entries":[{{"name":"Twee","username":"gebruiker2","password_sealed":"{pw}","url":"https://twee.nl","notes_sealed":"{notes}","tags":[],"created":7,"modified":8}}]}}"#
        );
        let (v, migrated) = Vault::from_json(old.as_bytes(), &k).unwrap();
        assert!(migrated);
        let e = v.get("twee").unwrap();
        assert_eq!(e.username(&k).unwrap().as_str(), "gebruiker2");
        assert_eq!(e.url(&k).unwrap().as_str(), "https://twee.nl");
        assert_eq!(e.password(&k).unwrap().as_str(), "v2-pw");
        assert_eq!(e.notes(&k).unwrap().as_str(), "v2-notitie");
        assert_eq!((e.created(), e.modified()), (7, 8));
        let json = String::from_utf8(v.to_json().unwrap().as_slice().to_vec()).unwrap();
        assert!(!json.contains("gebruiker2") && !json.contains("twee.nl"));
    }

    #[test]
    fn kapotte_of_te_nieuwe_inhoud() {
        let k = test_item_key(1);
        let s = k.seal("x", "").unwrap();
        let item = |extra: &str| {
            format!(
                r#"{{"schema":3,"entries":[{{{extra},"username_sealed":"{s}","url_sealed":"{s}","password_sealed":"{s}","notes_sealed":"{s}"}}]}}"#
            )
        };
        assert!(matches!(Vault::from_json(b"{niet json", &k), Err(Error::CorruptPayload)));
        assert!(matches!(Vault::from_json(b"[]", &k), Err(Error::CorruptPayload)));
        assert!(matches!(
            Vault::from_json(br#"{"schema":99,"entries":[]}"#, &k),
            Err(Error::UnsupportedVersion(99))
        ));
        assert!(Vault::from_json(item(r#""name":"x""#).as_bytes(), &k).is_ok());
        assert!(Vault::from_json(item(r#""name":"x","kind":"api""#).as_bytes(), &k).is_ok());
        // Ongeldige items uit een (kwaadaardig) bestand worden geweigerd.
        for bad in [
            item(r#""name":"""#),
            item(r#""name":" x""#),
            item(r#""name":"x\u001b[31m""#),
            item(r#""name":"x","tags":["\u0007"]"#),
            item(r#""name":"x","kind":"onbekend""#),
            format!(
                r#"{{"schema":3,"entries":[{{"name":"x","username_sealed":"onzin","url_sealed":"{s}","password_sealed":"{s}","notes_sealed":"{s}"}}]}}"#
            ),
            r#"{"schema":3,"entries":[{"name":"x"}]}"#.to_string(),
            r#"{"schema":2,"entries":[{"name":"x","username":"\u0007","password_sealed":"a","notes_sealed":"b"}]}"#
                .to_string(),
            r#"{"schema":1,"entries":[{"name":"x","notes":"\u001b[2J"}]}"#.to_string(),
            r#"{"schema":1,"entries":[{"name":"x"},{"name":"X"}]}"#.to_string(),
        ] {
            assert!(matches!(Vault::from_json(bad.as_bytes(), &k), Err(Error::CorruptPayload)), "{bad}");
        }
    }

    #[test]
    fn debug_toont_geen_geheimen() {
        let s = format!("{:?}", entry("x", "supergeheim"));
        assert!(!s.contains("supergeheim"));
        assert!(!s.contains("geheime notitie"));
    }

    #[test]
    fn opnieuw_versleutelen() {
        let (k1, k2) = (test_item_key(1), test_item_key(2));
        let mut v = Vault::new();
        v.add(entry("x", "pw")).unwrap();
        let before = v.get("x").unwrap().modified();
        v.rekey(&k1, &k2).unwrap();
        let e = v.get("x").unwrap();
        assert_eq!(e.password(&k2).unwrap().as_str(), "pw");
        assert_eq!(e.username(&k2).unwrap().as_str(), "jan");
        assert!(e.password(&k1).is_err() && e.url(&k1).is_err());
        assert_eq!(e.modified(), before);
        // Verkeerde bronsleutel: niets gewijzigd.
        assert!(v.rekey(&k1, &k2).is_err());
        assert_eq!(v.get("x").unwrap().password(&k2).unwrap().as_str(), "pw");
    }

    #[test]
    fn samenvoegen() {
        let k = test_item_key(1);
        let mut a = Vault::new();
        a.add(entry("x", "1")).unwrap();
        let mut b = Vault::new();
        b.add(entry("x", "1")).unwrap(); // identiek → overslaan
        b.add(entry("X", "anders")).unwrap_err(); // zelfde naam in b kan niet
        let mut c = Vault::new();
        c.add(entry("x", "anders")).unwrap(); // conflict → hernoemen
        c.add(entry("y", "2")).unwrap();
        assert_eq!(a.merge(&b, &k, &k).unwrap(), (0, 1));
        assert_eq!(a.merge(&c, &k, &k).unwrap(), (2, 0));
        assert!(a.get("x (2)").is_some());
        assert_eq!(a.unique_name("x"), "x (3)");
        // Nogmaals importeren maakt geen nieuwe kopieën.
        assert_eq!(a.merge(&c, &k, &k).unwrap(), (0, 2));
        assert_eq!(base_name("GitHub (12)"), "GitHub");
        assert_eq!(base_name("GitHub (x)"), "GitHub (x)");
        assert_eq!(base_name("(2)"), "(2)");
    }

    #[test]
    fn samenvoegen_met_andere_sleutel() {
        let (mine, theirs) = (test_item_key(1), test_item_key(2));
        let mut other = Vault::new();
        other.add(entry("z", "pw")).unwrap();
        other.rekey(&mine, &theirs).unwrap();
        let mut a = Vault::new();
        assert_eq!(a.merge(&other, &theirs, &mine).unwrap(), (1, 0));
        assert_eq!(a.get("z").unwrap().password(&mine).unwrap().as_str(), "pw");
        assert_eq!(a.merge(&other, &theirs, &mine).unwrap(), (0, 1));
        assert!(a.merge(&other, &mine, &mine).is_err(), "verkeerde sleutel van de andere kluis");
    }
}
