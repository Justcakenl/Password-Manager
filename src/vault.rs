//! The vault model: items and operations on them. Purely in-memory; no I/O.
//!
//! SECURITY-CRITICAL – second encryption layer.
//! All content of an item (username, e-mail address, URL, password/API key and notes) is
//! encrypted per field with the item key ([`ItemKey`]), each with its own
//! random nonce. Even while the vault is open, that content therefore only
//! exists encrypted in memory. It can only be read through the methods that
//! require the key; the plaintext then briefly lives in a `Zeroizing<String>`
//! and is wiped afterwards.
//!
//! Only name, type, tags and dates are not encrypted separately (they are
//! protected by the outer layer on disk), so you can find and sort items.
//!
//! Item types ([`Kind`]):
//! - **login**: username, e-mail address, URL, password, notes
//! - **api**: account/key ID, e-mail address, service URL, the API key, notes
//! - **note**: text only (multiple lines), e.g. recovery codes
//!
//! All fields are wiped on drop (`ZeroizeOnDrop`). `Debug` never shows secrets.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{self, ItemKey};
use crate::error::{Error, Result};
use crate::secure_mem::{CountingWriter, SecureBuf};

/// Current version of the (encrypted) JSON contents.
/// 1 = everything as text inside the vault; 2 = password and notes encrypted
/// per field; 3 = all content encrypted per field + item types; 4 = adds the
/// encrypted e-mail address.
pub const SCHEMA_VERSION: u32 = 4;
const MAX_NAME_LEN: usize = 200;
const MAX_FIELD_LEN: usize = 64 * 1024;
const FIELD_USERNAME: &str = "username";
const FIELD_EMAIL: &str = "email";
const FIELD_URL: &str = "url";
const FIELD_PASSWORD: &str = "password";
const FIELD_NOTES: &str = "notes";

/// Current time in seconds since 1970.
pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Type of item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Credentials for a website or service.
    #[default]
    Login,
    /// An API key or token.
    Api,
    /// A secure note.
    Note,
}

impl Kind {
    /// Short display name.
    pub fn label(self) -> &'static str {
        match self {
            Kind::Login => "login",
            Kind::Api => "api key",
            Kind::Note => "note",
        }
    }

    /// What the secret field is called for this type.
    pub fn secret_label(self) -> &'static str {
        match self {
            Kind::Login => "password",
            Kind::Api => "API key",
            Kind::Note => "note",
        }
    }

    /// Read a type from text ("login", "api", "note", ...).
    pub fn parse(s: &str) -> Option<Kind> {
        match s.trim().to_lowercase().as_str() {
            "login" | "password" => Some(Kind::Login),
            "api" | "api key" | "api-key" | "apikey" | "key" | "token" => Some(Kind::Api),
            "note" | "notes" | "secure-note" | "securenote" => Some(Kind::Note),
            _ => None,
        }
    }
}

/// One item in the vault.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Entry {
    name: String,
    #[serde(default)]
    #[zeroize(skip)]
    kind: Kind,
    /// Encrypted: base64(nonce || ciphertext || tag).
    username_sealed: String,
    /// Encrypted: the e-mail address that belongs to this item. Missing in
    /// vaults of schema 3; filled in (empty) when such a vault is opened.
    #[serde(default)]
    email_sealed: String,
    /// Encrypted.
    url_sealed: String,
    /// Encrypted: password (login) or API key (api).
    password_sealed: String,
    /// Encrypted: notes, or the contents of a note.
    notes_sealed: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    created: u64,
    #[serde(default)]
    modified: u64,
}

/// Fields for a new item (everything except the name is optional).
///
/// Temporarily holds secrets in plain text; the wiping allocator in the
/// binary cleans up the memory. Call `zeroize()` to wipe it earlier.
#[derive(Default, Zeroize)]
pub struct NewEntry {
    pub name: String,
    #[zeroize(skip)]
    pub kind: Kind,
    pub username: String,
    /// E-mail address that belongs to the item.
    pub email: String,
    /// Password (login) or API key (api); empty for a note.
    pub password: String,
    pub url: String,
    /// Notes, or the text of a note.
    pub notes: String,
    pub tags: Vec<String>,
}

impl Entry {
    /// Create a validated item; all content is encrypted right away.
    pub fn new(fields: NewEntry, key: &ItemKey) -> Result<Entry> {
        let t = now();
        let mut e = Entry {
            name: String::new(),
            kind: fields.kind,
            username_sealed: String::new(),
            email_sealed: String::new(),
            url_sealed: String::new(),
            password_sealed: String::new(),
            notes_sealed: String::new(),
            tags: Vec::new(),
            created: t,
            modified: t,
        };
        e.set_name(&fields.name)?;
        e.set_username(key, &fields.username)?;
        e.set_email(key, &fields.email)?;
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
    /// Decrypt the username (or account/key ID for an API key).
    pub fn username(&self, key: &ItemKey) -> Result<Zeroizing<String>> {
        key.open(FIELD_USERNAME, &self.username_sealed)
    }
    /// Decrypt the e-mail address.
    pub fn email(&self, key: &ItemKey) -> Result<Zeroizing<String>> {
        key.open(FIELD_EMAIL, &self.email_sealed)
    }
    /// Decrypt the URL.
    pub fn url(&self, key: &ItemKey) -> Result<Zeroizing<String>> {
        key.open(FIELD_URL, &self.url_sealed)
    }
    /// Decrypt the password or API key. Only use this to copy it to the
    /// clipboard or to show it on explicit request (`--show`).
    pub fn password(&self, key: &ItemKey) -> Result<Zeroizing<String>> {
        key.open(FIELD_PASSWORD, &self.password_sealed)
    }
    /// Decrypt the notes (or the contents of a note).
    pub fn notes(&self, key: &ItemKey) -> Result<Zeroizing<String>> {
        key.open(FIELD_NOTES, &self.notes_sealed)
    }
    /// Decrypt the main secret of this item: the password, the API key or
    /// the text of the note.
    pub fn secret(&self, key: &ItemKey) -> Result<Zeroizing<String>> {
        match self.kind {
            Kind::Note => self.notes(key),
            Kind::Login | Kind::Api => self.password(key),
        }
    }
    /// Whether there is an e-mail address (without decrypting).
    pub fn has_email(&self) -> bool {
        crypto::sealed_plaintext_len(&self.email_sealed) > 0
    }
    /// Whether there is a password/API key (without decrypting).
    pub fn has_password(&self) -> bool {
        crypto::sealed_plaintext_len(&self.password_sealed) > 0
    }
    /// Whether there are notes (without decrypting).
    pub fn has_notes(&self) -> bool {
        crypto::sealed_plaintext_len(&self.notes_sealed) > 0
    }
    /// Whether the main secret is filled in (without decrypting).
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
        self.username_sealed = key.seal(FIELD_USERNAME, validate_line("username", v)?)?;
        self.touch();
        Ok(())
    }
    pub fn set_email(&mut self, key: &ItemKey, v: &str) -> Result<()> {
        self.email_sealed = key.seal(FIELD_EMAIL, validate_line("e-mail address", v)?)?;
        self.touch();
        Ok(())
    }
    pub fn set_password(&mut self, key: &ItemKey, v: &str) -> Result<()> {
        if v.len() > MAX_FIELD_LEN {
            return Err(Error::InvalidInput("password or key is too long".into()));
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
            return Err(Error::InvalidInput("notes are too long".into()));
        }
        // Newlines and tabs are fine; other control characters (such as ANSI
        // escapes that can manipulate your terminal) are not.
        if v.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
            return Err(Error::InvalidInput("notes contain invalid characters".into()));
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

    /// Re-encrypt all content with another key (after `passwd`, on export
    /// and import). The modification date stays the same.
    fn reseal(&mut self, from: &ItemKey, to: &ItemKey) -> Result<()> {
        let username = self.username(from)?;
        let email = self.email(from)?;
        let url = self.url(from)?;
        let pw = self.password(from)?;
        let notes = self.notes(from)?;
        self.username_sealed = to.seal(FIELD_USERNAME, &username)?;
        self.email_sealed = to.seal(FIELD_EMAIL, &email)?;
        self.url_sealed = to.seal(FIELD_URL, &url)?;
        self.password_sealed = to.seal(FIELD_PASSWORD, &pw)?;
        self.notes_sealed = to.seal(FIELD_NOTES, &notes)?;
        Ok(())
    }

    /// Whether the item matches a search term (case-insensitive). Searches
    /// name, type, tags, username, e-mail address and URL (the last three are
    /// briefly decrypted for that); never passwords, keys or notes.
    pub fn matches(&self, query: &str, key: &ItemKey) -> bool {
        let q = query.to_lowercase();
        let hit = |s: &str| s.to_lowercase().contains(&q);
        hit(&self.name)
            || hit(self.kind.label())
            || self.tags.iter().any(|t| hit(t))
            || self.username(key).is_ok_and(|u| hit(&u))
            || self.email(key).is_ok_and(|u| hit(&u))
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
            .field("content", &"[ENCRYPTED]")
            .field("tags", &self.tags)
            .finish()
    }
}

/// Overwrite a String safely: wipe the old contents first.
fn replace_secret(target: &mut String, new: &str) {
    target.zeroize();
    target.push_str(new);
}

fn validate_name(name: &str) -> Result<&str> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::InvalidInput("the name must not be empty".into()));
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(Error::InvalidInput("the name is too long (max. 200 characters)".into()));
    }
    if name.chars().any(char::is_control) {
        return Err(Error::InvalidInput("the name contains invalid characters".into()));
    }
    Ok(name)
}

fn validate_line<'a>(what: &str, v: &'a str) -> Result<&'a str> {
    let v = v.trim();
    if v.len() > MAX_FIELD_LEN {
        return Err(Error::InvalidInput(format!("{what} is too long")));
    }
    if v.chars().any(char::is_control) {
        return Err(Error::InvalidInput(format!("{what} contains invalid characters")));
    }
    Ok(v)
}

/// "GitHub (2)" → "GitHub"; other names stay the same.
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

// ───────────────────────── older schemas (migration) ─────────────────────────

/// Only to read the schema number before the real processing.
#[derive(Deserialize)]
struct SchemaPeek {
    schema: u32,
}

/// Schema 1: everything as plain text (inside the outer encryption).
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

/// Schema 2: password and notes encrypted, username and URL not.
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

// ───────────────────────── the vault ─────────────────────────

/// The complete vault contents (with content encrypted per field).
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

    /// Read the JSON contents (after decrypting the outer layer).
    ///
    /// Also returns whether the contents were converted from an older schema;
    /// the caller must then save the vault again.
    pub fn from_json(bytes: &[u8], key: &ItemKey) -> Result<(Vault, bool)> {
        let peek: SchemaPeek = serde_json::from_slice(bytes).map_err(|_| Error::CorruptPayload)?;
        let (mut v, migrated) = match peek.schema {
            1 => (Self::migrate_v1(bytes, key)?, true),
            2 => (Self::migrate_v2(bytes, key)?, true),
            3 => (Self::migrate_v3(bytes, key)?, true),
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

    /// Schema 1 → 4: encrypt all content per field.
    fn migrate_v1(bytes: &[u8], key: &ItemKey) -> Result<Vault> {
        let old: VaultV1 = serde_json::from_slice(bytes).map_err(|_| Error::CorruptPayload)?;
        let mut v = Vault::new();
        for e in &old.entries {
            let mut new = Entry::new(
                NewEntry {
                    name: e.name.clone(),
                    kind: Kind::Login,
                    username: e.username.clone(),
                    email: String::new(),
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

    /// Schema 2 → 4: also encrypt username and URL.
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
                email_sealed: key.seal(FIELD_EMAIL, "")?,
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

    /// Schema 3 → 4: add the (empty) encrypted e-mail address.
    fn migrate_v3(bytes: &[u8], key: &ItemKey) -> Result<Vault> {
        let mut v: Vault = serde_json::from_slice(bytes).map_err(|_| Error::CorruptPayload)?;
        for e in &mut v.entries {
            if e.email_sealed.is_empty() {
                e.email_sealed = key.seal(FIELD_EMAIL, "")?;
            }
        }
        Ok(v)
    }

    /// Validate every item, including those from (possibly malicious) import
    /// files: valid fields, validly encrypted content and unique names.
    fn validate(&self) -> Result<()> {
        for (i, e) in self.entries.iter().enumerate() {
            let valid = validate_name(&e.name).is_ok_and(|n| n == e.name)
                && e.tags.iter().all(|t| validate_line("", t).is_ok_and(|v| !v.is_empty() && v == t))
                && [&e.username_sealed, &e.email_sealed, &e.url_sealed, &e.password_sealed, &e.notes_sealed]
                    .iter()
                    .all(|s| crypto::decode_sealed(s).is_ok())
                && !self.entries[..i].iter().any(|other| same_name(&other.name, &e.name));
            if !valid {
                return Err(Error::CorruptPayload);
            }
        }
        Ok(())
    }

    /// Write the contents as JSON straight into protected memory.
    ///
    /// We first measure the exact size so the buffer never has to grow
    /// (growing could leave unwiped copies behind).
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

    /// All items, sorted by name.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Find an item by exact name (case-insensitive).
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
        // `Entry` is ZeroizeOnDrop: the removed item is wiped.
        self.entries.remove(idx);
        Ok(())
    }

    pub fn rename(&mut self, old: &str, new: &str) -> Result<()> {
        self.update(old, |e| e.set_name(new))
    }

    /// Change an item "all or nothing": the changes are made on a copy and
    /// only adopted if everything succeeded and the (possibly new) name does
    /// not clash with another item.
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

    /// Items that match the search term.
    pub fn search(&self, query: &str, key: &ItemKey) -> Vec<&Entry> {
        self.entries.iter().filter(|e| e.matches(query, key)).collect()
    }

    /// A free name based on `base` ("name", "name (2)", "name (3)", ...).
    pub fn unique_name(&self, base: &str) -> String {
        let base = base.trim();
        if !self.contains(base) {
            return base.to_string();
        }
        (2..)
            .map(|n| format!("{base} ({n})"))
            .find(|candidate| !self.contains(candidate))
            .expect("infinite sequence")
    }

    /// Re-encrypt all content with another item key (all or nothing).
    pub fn rekey(&mut self, from: &ItemKey, to: &ItemKey) -> Result<()> {
        let mut entries = self.entries.clone();
        for e in &mut entries {
            e.reseal(from, to)?;
        }
        self.entries = entries;
        Ok(())
    }

    /// Add items from another vault (encrypted with `other_key`).
    /// An identical item is skipped; on a name clash the new item gets a
    /// sequence number. Returns (added, skipped).
    pub fn merge(&mut self, other: &Vault, other_key: &ItemKey, my_key: &ItemKey) -> Result<(usize, usize)> {
        let mut added = 0;
        let mut skipped = 0;
        for e in other.entries() {
            let theirs = (
                e.username(other_key)?,
                e.email(other_key)?,
                e.url(other_key)?,
                e.password(other_key)?,
                e.notes(other_key)?,
            );
            // Duplicate: same name (optionally with a sequence number, so importing
            // repeatedly makes no copies), type and content.
            let mut duplicate = false;
            for existing in &self.entries {
                if existing.kind != e.kind || !same_name(base_name(&existing.name), base_name(&e.name)) {
                    continue;
                }
                let mine = (
                    existing.username(my_key)?,
                    existing.email(my_key)?,
                    existing.url(my_key)?,
                    existing.password(my_key)?,
                    existing.notes(my_key)?,
                );
                let eq = |a: &str, b: &str| bool::from(a.as_bytes().ct_eq(b.as_bytes()));
                if eq(&mine.0, &theirs.0)
                    && eq(&mine.1, &theirs.1)
                    && eq(&mine.2, &theirs.2)
                    && eq(&mine.3, &theirs.3)
                    && eq(&mine.4, &theirs.4)
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
                username: "john".into(),
                email: "john@example.org".into(),
                password: pw.into(),
                url: "https://example.org".into(),
                notes: "secret note".into(),
                tags: vec!["Work".into(), "work".into(), " mail ".into(), String::new()],
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
    fn add_find_remove() {
        let k = test_item_key(1);
        let mut v = Vault::new();
        v.add(entry("GitHub", "pw1")).unwrap();
        v.add(entry("abc", "pw2")).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v.entries()[0].name(), "abc", "sorted by name");
        assert_eq!(v.get("github").unwrap().password(&k).unwrap().as_str(), "pw1");
        assert!(matches!(v.add(entry("GITHUB", "x")), Err(Error::EntryExists(_))));
        v.remove("GitHub").unwrap();
        assert!(v.get("github").is_none());
        assert!(matches!(v.remove("does-not-exist"), Err(Error::EntryNotFound(_))));
    }

    #[test]
    fn all_content_is_encrypted_per_item() {
        let k = test_item_key(1);
        let e = entry("x", "supersecret");
        // The model (and so memory and the JSON) holds no plain text.
        let json = json_of(&e);
        for plain in ["supersecret", "secret note", "john", "john@example.org", "example.org"] {
            assert!(!json.contains(plain), "{plain} is readable in the JSON");
        }
        assert!(json.contains("username_sealed") && json.contains("password_sealed"));
        // Only readable with the right key.
        assert_eq!(e.password(&k).unwrap().as_str(), "supersecret");
        assert_eq!(e.notes(&k).unwrap().as_str(), "secret note");
        assert_eq!(e.username(&k).unwrap().as_str(), "john");
        assert_eq!(e.email(&k).unwrap().as_str(), "john@example.org");
        assert_eq!(e.url(&k).unwrap().as_str(), "https://example.org");
        for wrong in
            [e.password(&test_item_key(2)), e.username(&test_item_key(2)), e.email(&test_item_key(2))]
        {
            assert!(matches!(wrong, Err(Error::Decrypt)));
        }
        assert!(e.has_password() && e.has_notes() && e.has_email());
        // Two items with the same password still encrypt differently.
        assert_ne!(entry("a", "same").password_sealed, entry("b", "same").password_sealed);
        let empty = Entry::new(NewEntry { name: "empty".into(), ..Default::default() }, &k).unwrap();
        assert!(!empty.has_password() && !empty.has_notes() && !empty.has_email());
    }

    #[test]
    fn item_types() {
        let k = test_item_key(1);
        let api = Entry::new(
            NewEntry {
                name: "OpenAI".into(),
                kind: Kind::Api,
                username: "project-key-1".into(),
                password: "sk-secret-123".into(),
                url: "https://api.example.com".into(),
                ..Default::default()
            },
            &k,
        )
        .unwrap();
        let note = Entry::new(
            NewEntry {
                name: "Recovery codes".into(),
                kind: Kind::Note,
                notes: "line 1\nline 2\n\ttab".into(),
                ..Default::default()
            },
            &k,
        )
        .unwrap();
        assert_eq!(api.kind(), Kind::Api);
        assert_eq!(api.secret(&k).unwrap().as_str(), "sk-secret-123");
        assert_eq!(note.secret(&k).unwrap().as_str(), "line 1\nline 2\n\ttab");
        assert!(note.has_secret() && !note.has_password());
        for (e, plain) in [(&api, "sk-secret"), (&note, "line 1")] {
            assert!(!json_of(e).contains(plain));
        }
        assert!(json_of(&note).contains("\"kind\":\"note\""));
        assert_eq!(Kind::parse("API"), Some(Kind::Api));
        assert_eq!(Kind::parse("notes"), Some(Kind::Note));
        assert_eq!(Kind::parse("note"), Some(Kind::Note));
        assert_eq!(Kind::parse("something"), None);
        // Searching by type works; searching in the secret content does not.
        let mut v = Vault::new();
        v.add(api).unwrap();
        v.add(note).unwrap();
        assert_eq!(v.search("api key", &k).len(), 1);
        assert_eq!(v.search("note", &k).len(), 1);
        assert_eq!(v.search("sk-secret", &k).len(), 0);
        assert_eq!(v.search("line", &k).len(), 0);
        assert_eq!(v.search("project-key", &k).len(), 1);
    }

    #[test]
    fn tags_are_cleaned_up() {
        let e = entry("x", "y");
        assert_eq!(e.tags(), &["Work".to_string(), "mail".to_string()]);
        assert!(e.has_tag("WORK"));
    }

    #[test]
    fn invalid_names() {
        let k = test_item_key(1);
        let bad = |n: &str| Entry::new(NewEntry { name: n.into(), ..Default::default() }, &k).is_err();
        assert!(bad(""));
        assert!(bad("   "));
        assert!(bad("with\nnewline"));
        assert!(bad(&"x".repeat(201)));
        assert!(!bad("Bank – café 🏦"));
    }

    #[test]
    fn search_does_not_look_in_passwords_or_notes() {
        let k = test_item_key(1);
        let mut v = Vault::new();
        v.add(entry("Mail", "supersecret")).unwrap();
        assert_eq!(v.search("MAIL", &k).len(), 1);
        assert_eq!(v.search("example", &k).len(), 1);
        assert_eq!(v.search("JOHN", &k).len(), 1);
        assert_eq!(v.search("john@example", &k).len(), 1, "the e-mail address is searchable");
        assert_eq!(v.search("supersecret", &k).len(), 0);
        assert_eq!(v.search("secret note", &k).len(), 0);
        assert_eq!(v.search("example", &test_item_key(2)).len(), 0, "wrong key finds nothing");
    }

    #[test]
    fn renaming() {
        let mut v = Vault::new();
        v.add(entry("a", "1")).unwrap();
        v.add(entry("b", "2")).unwrap();
        assert!(matches!(v.rename("a", "B"), Err(Error::EntryExists(_))));
        v.rename("a", "A").unwrap();
        v.rename("A", "c").unwrap();
        assert!(v.get("c").is_some());
    }

    #[test]
    fn update_is_all_or_nothing() {
        let k = test_item_key(1);
        let mut v = Vault::new();
        v.add(entry("a", "1")).unwrap();
        v.add(entry("b", "2")).unwrap();
        // Clashing name: nothing is changed.
        let r = v.update("a", |e| {
            e.set_username(&k, "new")?;
            e.set_name("B")
        });
        assert!(matches!(r, Err(Error::EntryExists(_))));
        assert_eq!(v.get("a").unwrap().username(&k).unwrap().as_str(), "john");
        // Error halfway: nothing is changed either.
        let r = v.update("a", |e| {
            e.set_username(&k, "new")?;
            e.set_url(&k, "with\nnewline")
        });
        assert!(r.is_err());
        assert_eq!(v.get("a").unwrap().username(&k).unwrap().as_str(), "john");
        v.update("a", |e| e.set_username(&k, "new")).unwrap();
        assert_eq!(v.get("a").unwrap().username(&k).unwrap().as_str(), "new");
    }

    #[test]
    fn json_round_trip() {
        let k = test_item_key(1);
        let mut v = Vault::new();
        v.add(entry("one \"quote\" \\ test", "p@ss\"wo\\rd")).unwrap();
        let json = v.to_json().unwrap();
        assert_eq!(json.len(), json.capacity(), "exact size, no reallocation");
        let (back, migrated) = Vault::from_json(json.as_slice(), &k).unwrap();
        assert!(!migrated);
        assert_eq!(back.entries(), v.entries());
        assert_eq!(back.entries()[0].password(&k).unwrap().as_str(), "p@ss\"wo\\rd");
    }

    #[test]
    fn migration_from_schema_1() {
        let k = test_item_key(1);
        let old = br#"{"schema":1,"entries":[{"name":"Old","username":"u","password":"old-pw","notes":"n","tags":["t"],"created":5,"modified":6}]}"#;
        let (v, migrated) = Vault::from_json(old, &k).unwrap();
        assert!(migrated);
        let e = v.get("old").unwrap();
        assert_eq!(e.kind(), Kind::Login);
        assert_eq!(e.password(&k).unwrap().as_str(), "old-pw");
        assert_eq!(e.notes(&k).unwrap().as_str(), "n");
        assert_eq!(e.username(&k).unwrap().as_str(), "u");
        assert_eq!((e.created(), e.modified()), (5, 6), "dates are preserved");
        let json = String::from_utf8(v.to_json().unwrap().as_slice().to_vec()).unwrap();
        assert!(!json.contains("old-pw") && json.contains("\"schema\":4"));
    }

    #[test]
    fn migration_from_schema_2() {
        let k = test_item_key(1);
        let pw = k.seal("password", "v2-pw").unwrap();
        let notes = k.seal("notes", "v2-note").unwrap();
        let old = format!(
            r#"{{"schema":2,"entries":[{{"name":"Two","username":"user2","password_sealed":"{pw}","url":"https://two.nl","notes_sealed":"{notes}","tags":[],"created":7,"modified":8}}]}}"#
        );
        let (v, migrated) = Vault::from_json(old.as_bytes(), &k).unwrap();
        assert!(migrated);
        let e = v.get("two").unwrap();
        assert_eq!(e.username(&k).unwrap().as_str(), "user2");
        assert_eq!(e.url(&k).unwrap().as_str(), "https://two.nl");
        assert_eq!(e.password(&k).unwrap().as_str(), "v2-pw");
        assert_eq!(e.notes(&k).unwrap().as_str(), "v2-note");
        assert_eq!(e.email(&k).unwrap().as_str(), "");
        assert_eq!((e.created(), e.modified()), (7, 8));
        let json = String::from_utf8(v.to_json().unwrap().as_slice().to_vec()).unwrap();
        assert!(!json.contains("user2") && !json.contains("two.nl"));
    }

    #[test]
    fn migration_from_schema_3() {
        let k = test_item_key(1);
        let s = |f: &str, v: &str| k.seal(f, v).unwrap();
        let old = format!(
            r#"{{"schema":3,"entries":[{{"name":"Three","kind":"api","username_sealed":"{}","url_sealed":"{}","password_sealed":"{}","notes_sealed":"{}","tags":["t"],"created":9,"modified":10}}]}}"#,
            s("username", "key-id"),
            s("url", "https://three.example"),
            s("password", "sk-three"),
            s("notes", "n3"),
        );
        let (v, migrated) = Vault::from_json(old.as_bytes(), &k).unwrap();
        assert!(migrated, "an old vault is saved again in the new schema");
        let e = v.get("three").unwrap();
        assert_eq!(e.kind(), Kind::Api);
        assert_eq!(e.username(&k).unwrap().as_str(), "key-id");
        assert_eq!(e.email(&k).unwrap().as_str(), "", "no e-mail address yet");
        assert_eq!(e.password(&k).unwrap().as_str(), "sk-three");
        assert_eq!((e.created(), e.modified()), (9, 10));
        let json = String::from_utf8(v.to_json().unwrap().as_slice().to_vec()).unwrap();
        assert!(json.contains("\"schema\":4") && json.contains("email_sealed"));
        // Now an e-mail address can be set and is encrypted too.
        let mut e2 = e.clone();
        e2.set_email(&k, "me@three.example").unwrap();
        assert_eq!(e2.email(&k).unwrap().as_str(), "me@three.example");
        assert!(!json_of(&e2).contains("me@three.example"));
        assert!(e2.set_email(&k, "bad\nline").is_err());
    }

    #[test]
    fn broken_or_too_new_contents() {
        let k = test_item_key(1);
        let s = k.seal("x", "").unwrap();
        let item = |extra: &str| {
            format!(
                r#"{{"schema":4,"entries":[{{{extra},"username_sealed":"{s}","email_sealed":"{s}","url_sealed":"{s}","password_sealed":"{s}","notes_sealed":"{s}"}}]}}"#
            )
        };
        assert!(matches!(Vault::from_json(b"{not json", &k), Err(Error::CorruptPayload)));
        assert!(matches!(Vault::from_json(b"[]", &k), Err(Error::CorruptPayload)));
        assert!(matches!(
            Vault::from_json(br#"{"schema":99,"entries":[]}"#, &k),
            Err(Error::UnsupportedVersion(99))
        ));
        assert!(Vault::from_json(item(r#""name":"x""#).as_bytes(), &k).is_ok());
        assert!(Vault::from_json(item(r#""name":"x","kind":"api""#).as_bytes(), &k).is_ok());
        // Invalid items from a (malicious) file are rejected.
        for bad in [
            item(r#""name":"""#),
            item(r#""name":" x""#),
            item(r#""name":"x\u001b[31m""#),
            item(r#""name":"x","tags":["\u0007"]"#),
            item(r#""name":"x","kind":"unknown""#),
            format!(
                r#"{{"schema":4,"entries":[{{"name":"x","username_sealed":"nonsense","email_sealed":"{s}","url_sealed":"{s}","password_sealed":"{s}","notes_sealed":"{s}"}}]}}"#
            ),
            r#"{"schema":4,"entries":[{"name":"x"}]}"#.to_string(),
            r#"{"schema":2,"entries":[{"name":"x","username":"\u0007","password_sealed":"a","notes_sealed":"b"}]}"#
                .to_string(),
            r#"{"schema":1,"entries":[{"name":"x","notes":"\u001b[2J"}]}"#.to_string(),
            r#"{"schema":1,"entries":[{"name":"x"},{"name":"X"}]}"#.to_string(),
        ] {
            assert!(matches!(Vault::from_json(bad.as_bytes(), &k), Err(Error::CorruptPayload)), "{bad}");
        }
    }

    #[test]
    fn debug_shows_no_secrets() {
        let s = format!("{:?}", entry("x", "supersecret"));
        assert!(!s.contains("supersecret"));
        assert!(!s.contains("secret note"));
    }

    #[test]
    fn re_encrypting() {
        let (k1, k2) = (test_item_key(1), test_item_key(2));
        let mut v = Vault::new();
        v.add(entry("x", "pw")).unwrap();
        let before = v.get("x").unwrap().modified();
        v.rekey(&k1, &k2).unwrap();
        let e = v.get("x").unwrap();
        assert_eq!(e.password(&k2).unwrap().as_str(), "pw");
        assert_eq!(e.username(&k2).unwrap().as_str(), "john");
        assert_eq!(e.email(&k2).unwrap().as_str(), "john@example.org");
        assert!(e.password(&k1).is_err() && e.url(&k1).is_err() && e.email(&k1).is_err());
        assert_eq!(e.modified(), before);
        // Wrong source key: nothing changed.
        assert!(v.rekey(&k1, &k2).is_err());
        assert_eq!(v.get("x").unwrap().password(&k2).unwrap().as_str(), "pw");
    }

    #[test]
    fn merging() {
        let k = test_item_key(1);
        let mut a = Vault::new();
        a.add(entry("x", "1")).unwrap();
        let mut b = Vault::new();
        b.add(entry("x", "1")).unwrap(); // identical → skip
        b.add(entry("X", "different")).unwrap_err(); // same name in b is not possible
        let mut c = Vault::new();
        c.add(entry("x", "different")).unwrap(); // conflict → rename
        c.add(entry("y", "2")).unwrap();
        assert_eq!(a.merge(&b, &k, &k).unwrap(), (0, 1));
        assert_eq!(a.merge(&c, &k, &k).unwrap(), (2, 0));
        assert!(a.get("x (2)").is_some());
        assert_eq!(a.unique_name("x"), "x (3)");
        // Importing again makes no new copies.
        assert_eq!(a.merge(&c, &k, &k).unwrap(), (0, 2));
        assert_eq!(base_name("GitHub (12)"), "GitHub");
        assert_eq!(base_name("GitHub (x)"), "GitHub (x)");
        assert_eq!(base_name("(2)"), "(2)");
    }

    #[test]
    fn merging_with_another_key() {
        let (mine, theirs) = (test_item_key(1), test_item_key(2));
        let mut other = Vault::new();
        other.add(entry("z", "pw")).unwrap();
        other.rekey(&mine, &theirs).unwrap();
        let mut a = Vault::new();
        assert_eq!(a.merge(&other, &theirs, &mine).unwrap(), (1, 0));
        assert_eq!(a.get("z").unwrap().password(&mine).unwrap().as_str(), "pw");
        assert_eq!(a.merge(&other, &theirs, &mine).unwrap(), (0, 1));
        assert!(a.merge(&other, &mine, &mine).is_err(), "wrong key for the other vault");
    }
}
