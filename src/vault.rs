//! Het kluismodel: items en bewerkingen daarop. Puur in-memory; geen I/O.
//!
//! BEVEILIGINGSKRITIEK – tweede versleutelingslaag.
//! Wachtwoorden en notities worden per item apart versleuteld met de
//! itemsleutel ([`ItemKey`]), elk met een eigen willekeurige nonce. Ook als
//! de kluis geopend is, staan ze dus alleen versleuteld in het geheugen. Je
//! kunt ze alleen lezen via [`Entry::password`] / [`Entry::notes`], met de
//! sleutel die uit je hoofdwachtwoord is afgeleid. De klare tekst bestaat dan
//! heel even in een `Zeroizing<String>` en wordt daarna gewist.
//!
//! Naam, gebruikersnaam, URL en tags zijn niet apart versleuteld (wel door de
//! buitenste laag op schijf), zodat `list` en `search` werken zonder geheimen
//! te ontsleutelen.
//!
//! Alle velden worden bij opruimen gewist (`ZeroizeOnDrop`). `Debug` toont
//! nooit wachtwoorden of notities.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{self, ItemKey};
use crate::error::{Error, Result};
use crate::secure_mem::{CountingWriter, SecureBuf};

/// Huidige versie van de (versleutelde) JSON-inhoud.
/// 1 = wachtwoorden als gewone tekst binnen de kluis; 2 = per veld versleuteld.
pub const SCHEMA_VERSION: u32 = 2;
const MAX_NAME_LEN: usize = 200;
const MAX_FIELD_LEN: usize = 64 * 1024;
const FIELD_PASSWORD: &str = "password";
const FIELD_NOTES: &str = "notes";

/// Huidige tijd in seconden sinds 1970.
pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Eén item in de kluis.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Entry {
    name: String,
    #[serde(default)]
    username: String,
    /// Versleuteld: base64(nonce || ciphertext || tag).
    password_sealed: String,
    #[serde(default)]
    url: String,
    /// Versleuteld: base64(nonce || ciphertext || tag).
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
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
}

impl Entry {
    /// Maak een gecontroleerd item; wachtwoord en notities worden direct versleuteld.
    pub fn new(fields: NewEntry, key: &ItemKey) -> Result<Entry> {
        let t = now();
        let mut e = Entry {
            name: String::new(),
            username: String::new(),
            password_sealed: String::new(),
            url: String::new(),
            notes_sealed: String::new(),
            tags: Vec::new(),
            created: t,
            modified: t,
        };
        e.set_name(&fields.name)?;
        e.set_username(&fields.username)?;
        e.set_password(key, &fields.password)?;
        e.set_url(&fields.url)?;
        e.set_notes(key, &fields.notes)?;
        e.set_tags(&fields.tags)?;
        e.modified = t;
        Ok(e)
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn username(&self) -> &str {
        &self.username
    }
    /// Ontsleutel het wachtwoord. Alleen gebruiken om naar het klembord te
    /// kopiëren of op uitdrukkelijk verzoek (`--show`) te tonen.
    pub fn password(&self, key: &ItemKey) -> Result<Zeroizing<String>> {
        key.open(FIELD_PASSWORD, &self.password_sealed)
    }
    /// Ontsleutel de notities.
    pub fn notes(&self, key: &ItemKey) -> Result<Zeroizing<String>> {
        key.open(FIELD_NOTES, &self.notes_sealed)
    }
    /// Of er een wachtwoord is (zonder te ontsleutelen).
    pub fn has_password(&self) -> bool {
        crypto::sealed_plaintext_len(&self.password_sealed) > 0
    }
    /// Of er notities zijn (zonder te ontsleutelen).
    pub fn has_notes(&self) -> bool {
        crypto::sealed_plaintext_len(&self.notes_sealed) > 0
    }
    pub fn url(&self) -> &str {
        &self.url
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
    pub fn set_username(&mut self, v: &str) -> Result<()> {
        replace_secret(&mut self.username, validate_line("gebruikersnaam", v)?);
        self.touch();
        Ok(())
    }
    pub fn set_password(&mut self, key: &ItemKey, v: &str) -> Result<()> {
        if v.len() > MAX_FIELD_LEN {
            return Err(Error::InvalidInput("wachtwoord is te lang".into()));
        }
        self.password_sealed = key.seal(FIELD_PASSWORD, v)?;
        self.touch();
        Ok(())
    }
    pub fn set_url(&mut self, v: &str) -> Result<()> {
        replace_secret(&mut self.url, validate_line("URL", v)?);
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

    /// Versleutel wachtwoord en notities opnieuw met een andere sleutel
    /// (na `passwd`, bij export en import). De wijzigingsdatum blijft gelijk.
    fn reseal(&mut self, from: &ItemKey, to: &ItemKey) -> Result<()> {
        let pw = self.password(from)?;
        let notes = self.notes(from)?;
        self.password_sealed = to.seal(FIELD_PASSWORD, &pw)?;
        self.notes_sealed = to.seal(FIELD_NOTES, &notes)?;
        Ok(())
    }

    /// Of het item past bij een zoekterm (hoofdletterongevoelig).
    /// Zoekt in naam, gebruikersnaam, URL en tags; niet in wachtwoord of notities.
    pub fn matches(&self, query: &str) -> bool {
        let q = query.to_lowercase();
        self.name.to_lowercase().contains(&q)
            || self.username.to_lowercase().contains(&q)
            || self.url.to_lowercase().contains(&q)
            || self.tags.iter().any(|t| t.to_lowercase().contains(&q))
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
            .field("username", &self.username)
            .field("password", &"[VERSLEUTELD]")
            .field("url", &self.url)
            .field("notes", &"[VERSLEUTELD]")
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

/// Alleen om het schemanummer te lezen vóór de echte verwerking.
#[derive(Deserialize)]
struct SchemaPeek {
    schema: u32,
}

/// Schema 1: wachtwoorden en notities als gewone tekst (binnen de buitenste versleuteling).
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

/// De volledige kluisinhoud (met per veld versleutelde geheimen).
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

    /// Schema 1 → 2: versleutel alle wachtwoorden en notities per veld.
    fn migrate_v1(bytes: &[u8], key: &ItemKey) -> Result<Vault> {
        let old: VaultV1 = serde_json::from_slice(bytes).map_err(|_| Error::CorruptPayload)?;
        let mut v = Vault::new();
        for e in &old.entries {
            let mut new = Entry::new(
                NewEntry {
                    name: e.name.clone(),
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

    /// Controleer elk item, ook uit (mogelijk kwaadaardige) importbestanden:
    /// geldige velden, geldig versleutelde geheimen en unieke namen.
    fn validate(&self) -> Result<()> {
        for (i, e) in self.entries.iter().enumerate() {
            let valid = validate_name(&e.name).is_ok_and(|n| n == e.name)
                && validate_line("", &e.username).is_ok_and(|u| u == e.username)
                && validate_line("", &e.url).is_ok_and(|u| u == e.url)
                && e.tags.iter().all(|t| validate_line("", t).is_ok_and(|v| !v.is_empty() && v == t))
                && crypto::decode_sealed(&e.password_sealed).is_ok()
                && crypto::decode_sealed(&e.notes_sealed).is_ok()
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
    pub fn search(&self, query: &str) -> Vec<&Entry> {
        self.entries.iter().filter(|e| e.matches(query)).collect()
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

    /// Versleutel alle geheimen opnieuw met een andere itemsleutel
    /// (alles of niets).
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
            let theirs = e.password(other_key)?;
            // Duplicaat: zelfde naam (eventueel met volgnummer, zodat herhaald
            // importeren geen kopieën maakt), gebruiker, URL en wachtwoord.
            let mut duplicate = false;
            for existing in &self.entries {
                if same_name(base_name(&existing.name), base_name(&e.name))
                    && existing.username == e.username
                    && existing.url == e.url
                {
                    let mine = existing.password(my_key)?;
                    if bool::from(mine.as_bytes().ct_eq(theirs.as_bytes())) {
                        duplicate = true;
                        break;
                    }
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
            },
            &test_item_key(1),
        )
        .unwrap()
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
    fn geheimen_zijn_per_item_versleuteld() {
        let e = entry("x", "supergeheim");
        // In het model (en dus in het geheugen en in de JSON) staat geen klare tekst.
        let json = {
            let mut v = Vault::new();
            v.add(e.clone()).unwrap();
            String::from_utf8(v.to_json().unwrap().as_slice().to_vec()).unwrap()
        };
        assert!(!json.contains("supergeheim"));
        assert!(!json.contains("geheime notitie"));
        assert!(json.contains("password_sealed"));
        // Alleen met de juiste sleutel te lezen.
        assert_eq!(e.password(&test_item_key(1)).unwrap().as_str(), "supergeheim");
        assert_eq!(e.notes(&test_item_key(1)).unwrap().as_str(), "geheime notitie");
        assert!(matches!(e.password(&test_item_key(2)), Err(Error::Decrypt)));
        assert!(e.has_password() && e.has_notes());
        // Twee items met hetzelfde wachtwoord zijn versleuteld toch verschillend.
        assert_ne!(entry("a", "zelfde").password_sealed, entry("b", "zelfde").password_sealed);
        let empty =
            Entry::new(NewEntry { name: "leeg".into(), ..Default::default() }, &test_item_key(1)).unwrap();
        assert!(!empty.has_password() && !empty.has_notes());
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
        let mut v = Vault::new();
        v.add(entry("Mail", "supergeheim")).unwrap();
        assert_eq!(v.search("MAIL").len(), 1);
        assert_eq!(v.search("example").len(), 1);
        assert_eq!(v.search("supergeheim").len(), 0);
        assert_eq!(v.search("notitie").len(), 0);
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
        let mut v = Vault::new();
        v.add(entry("a", "1")).unwrap();
        v.add(entry("b", "2")).unwrap();
        // Botsende naam: niets wordt gewijzigd.
        let r = v.update("a", |e| {
            e.set_username("nieuw")?;
            e.set_name("B")
        });
        assert!(matches!(r, Err(Error::EntryExists(_))));
        assert_eq!(v.get("a").unwrap().username(), "jan");
        // Fout halverwege: ook niets gewijzigd.
        let r = v.update("a", |e| {
            e.set_username("nieuw")?;
            e.set_url("met\nnieuwe regel")
        });
        assert!(r.is_err());
        assert_eq!(v.get("a").unwrap().username(), "jan");
        v.update("a", |e| e.set_username("nieuw")).unwrap();
        assert_eq!(v.get("a").unwrap().username(), "nieuw");
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
        assert_eq!(e.password(&k).unwrap().as_str(), "oud-pw");
        assert_eq!(e.notes(&k).unwrap().as_str(), "n");
        assert_eq!((e.created(), e.modified()), (5, 6), "datums blijven behouden");
        let json = String::from_utf8(v.to_json().unwrap().as_slice().to_vec()).unwrap();
        assert!(!json.contains("oud-pw") && json.contains("\"schema\":2"));
    }

    #[test]
    fn kapotte_of_te_nieuwe_inhoud() {
        let k = test_item_key(1);
        let ok_sealed = k.seal("password", "").unwrap();
        let item = |extra: &str| {
            format!(
                r#"{{"schema":2,"entries":[{{{extra},"password_sealed":"{ok_sealed}","notes_sealed":"{ok_sealed}"}}]}}"#
            )
        };
        assert!(matches!(Vault::from_json(b"{niet json", &k), Err(Error::CorruptPayload)));
        assert!(matches!(Vault::from_json(b"[]", &k), Err(Error::CorruptPayload)));
        assert!(matches!(
            Vault::from_json(br#"{"schema":99,"entries":[]}"#, &k),
            Err(Error::UnsupportedVersion(99))
        ));
        assert!(Vault::from_json(item(r#""name":"x""#).as_bytes(), &k).is_ok());
        // Ongeldige items uit een (kwaadaardig) bestand worden geweigerd.
        for bad in [
            item(r#""name":"""#),
            item(r#""name":" x""#),
            item(r#""name":"x\u001b[31m""#),
            item(r#""name":"x","username":"\u0007""#),
            format!(
                r#"{{"schema":2,"entries":[{{"name":"x","password_sealed":"onzin","notes_sealed":"{ok_sealed}"}}]}}"#
            ),
            r#"{"schema":2,"entries":[{"name":"x"}]}"#.to_string(),
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
        assert!(e.password(&k1).is_err());
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
