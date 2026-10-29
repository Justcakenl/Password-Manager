//! Het kluismodel: items en bewerkingen daarop. Puur in-memory; geen I/O.
//!
//! Alle velden worden bij opruimen gewist (`ZeroizeOnDrop`). `Debug` toont
//! nooit wachtwoorden of notities.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::secure_mem::{CountingWriter, SecureBuf};

/// Huidige versie van de (versleutelde) JSON-inhoud.
pub const SCHEMA_VERSION: u32 = 1;
const MAX_NAME_LEN: usize = 200;
const MAX_FIELD_LEN: usize = 64 * 1024;

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

/// Velden voor een nieuw item (alles behalve de naam is optioneel).
///
/// Bevat tijdelijk geheimen; de wissende allocator in de binary ruimt het
/// geheugen op. Roep `zeroize()` aan als je het eerder wilt wissen.
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
    /// Maak een gecontroleerd item.
    pub fn new(fields: NewEntry) -> Result<Entry> {
        let t = now();
        let mut e = Entry {
            name: String::new(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            tags: Vec::new(),
            created: t,
            modified: t,
        };
        e.set_name(&fields.name)?;
        e.set_username(&fields.username)?;
        e.set_password(&fields.password)?;
        e.set_url(&fields.url)?;
        e.set_notes(&fields.notes)?;
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
    /// Het wachtwoord. Alleen gebruiken om naar het klembord te kopiëren of
    /// op uitdrukkelijk verzoek (`--show`) te tonen.
    pub fn password(&self) -> &str {
        &self.password
    }
    pub fn url(&self) -> &str {
        &self.url
    }
    pub fn notes(&self) -> &str {
        &self.notes
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

    fn set_name(&mut self, name: &str) -> Result<()> {
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
    pub fn set_password(&mut self, v: &str) -> Result<()> {
        if v.len() > MAX_FIELD_LEN {
            return Err(Error::InvalidInput("wachtwoord is te lang".into()));
        }
        replace_secret(&mut self.password, v);
        self.touch();
        Ok(())
    }
    pub fn set_url(&mut self, v: &str) -> Result<()> {
        replace_secret(&mut self.url, validate_line("URL", v)?);
        self.touch();
        Ok(())
    }
    pub fn set_notes(&mut self, v: &str) -> Result<()> {
        if v.len() > MAX_FIELD_LEN {
            return Err(Error::InvalidInput("notities zijn te lang".into()));
        }
        replace_secret(&mut self.notes, v);
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
            .field("password", &"[VERBORGEN]")
            .field("url", &self.url)
            .field("notes", &"[VERBORGEN]")
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

fn same_name(a: &str, b: &str) -> bool {
    a.trim().to_lowercase() == b.trim().to_lowercase()
}

/// De volledige (ontsleutelde) kluisinhoud.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
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

    /// Lees de JSON-inhoud (na ontsleutelen).
    pub fn from_json(bytes: &[u8]) -> Result<Vault> {
        let mut v: Vault = serde_json::from_slice(bytes).map_err(|_| Error::CorruptPayload)?;
        if v.schema == 0 || v.schema > SCHEMA_VERSION {
            return Err(Error::UnsupportedVersion(u16::try_from(v.schema).unwrap_or(u16::MAX)));
        }
        // Migraties van oudere schema's zouden hier komen.
        v.schema = SCHEMA_VERSION;
        v.sort();
        Ok(v)
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

    pub fn get_mut(&mut self, name: &str) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| same_name(&e.name, name))
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
        if !same_name(old, new) && self.contains(new) {
            return Err(Error::EntryExists(new.trim().to_string()));
        }
        let entry = self.get_mut(old).ok_or_else(|| Error::EntryNotFound(old.to_string()))?;
        entry.set_name(new)?;
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

    /// Voeg items uit een andere kluis toe. Een exact gelijk item wordt
    /// overgeslagen; bij een naamconflict krijgt het nieuwe item een volgnummer.
    /// Geeft (toegevoegd, overgeslagen) terug.
    pub fn merge(&mut self, other: &Vault) -> (usize, usize) {
        let mut added = 0;
        let mut skipped = 0;
        for e in other.entries() {
            let duplicate = self.get(&e.name).is_some_and(|existing| {
                existing.username == e.username && existing.password == e.password && existing.url == e.url
            });
            if duplicate {
                skipped += 1;
                continue;
            }
            let mut copy = e.clone();
            copy.name = self.unique_name(&e.name);
            self.entries.push(copy);
            self.sort();
            added += 1;
        }
        (added, skipped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, pw: &str) -> Entry {
        Entry::new(NewEntry {
            name: name.into(),
            username: "jan".into(),
            password: pw.into(),
            url: "https://example.org".into(),
            notes: "geheime notitie".into(),
            tags: vec!["Werk".into(), "werk".into(), " mail ".into(), String::new()],
        })
        .unwrap()
    }

    #[test]
    fn toevoegen_opzoeken_verwijderen() {
        let mut v = Vault::new();
        v.add(entry("GitHub", "pw1")).unwrap();
        v.add(entry("abc", "pw2")).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v.entries()[0].name(), "abc", "gesorteerd op naam");
        assert_eq!(v.get("github").unwrap().password(), "pw1");
        assert!(matches!(v.add(entry("GITHUB", "x")), Err(Error::EntryExists(_))));
        v.remove("GitHub").unwrap();
        assert!(v.get("github").is_none());
        assert!(matches!(v.remove("bestaat-niet"), Err(Error::EntryNotFound(_))));
    }

    #[test]
    fn tags_worden_opgeschoond() {
        let e = entry("x", "y");
        assert_eq!(e.tags(), &["Werk".to_string(), "mail".to_string()]);
        assert!(e.has_tag("WERK"));
    }

    #[test]
    fn ongeldige_namen() {
        let bad = |n: &str| Entry::new(NewEntry { name: n.into(), ..Default::default() }).is_err();
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
    fn json_heen_en_terug() {
        let mut v = Vault::new();
        v.add(entry("één \"quote\" \\ test", "p@ss\"wo\\rd")).unwrap();
        let json = v.to_json().unwrap();
        assert_eq!(json.len(), json.capacity(), "exacte grootte, geen herallocatie");
        let back = Vault::from_json(json.as_slice()).unwrap();
        assert_eq!(back.entries(), v.entries());
    }

    #[test]
    fn kapotte_of_te_nieuwe_inhoud() {
        assert!(matches!(Vault::from_json(b"{niet json"), Err(Error::CorruptPayload)));
        assert!(matches!(Vault::from_json(b"[]"), Err(Error::CorruptPayload)));
        assert!(matches!(
            Vault::from_json(br#"{"schema":99,"entries":[]}"#),
            Err(Error::UnsupportedVersion(99))
        ));
        assert!(Vault::from_json(br#"{"schema":1,"entries":[{"name":"x"}]}"#).is_ok());
    }

    #[test]
    fn debug_toont_geen_geheimen() {
        let s = format!("{:?}", entry("x", "supergeheim"));
        assert!(!s.contains("supergeheim"));
        assert!(!s.contains("geheime notitie"));
    }

    #[test]
    fn samenvoegen() {
        let mut a = Vault::new();
        a.add(entry("x", "1")).unwrap();
        let mut b = Vault::new();
        b.add(entry("x", "1")).unwrap(); // identiek → overslaan
        b.add(entry("X", "anders")).unwrap_err(); // zelfde naam in b kan niet
        let mut c = Vault::new();
        c.add(entry("x", "anders")).unwrap(); // conflict → hernoemen
        c.add(entry("y", "2")).unwrap();
        assert_eq!(a.merge(&b), (0, 1));
        assert_eq!(a.merge(&c), (2, 0));
        assert!(a.get("x (2)").is_some());
        assert_eq!(a.unique_name("x"), "x (3)");
    }
}
