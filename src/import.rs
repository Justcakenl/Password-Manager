//! Import from CSV exports of other password managers.
//!
//! Recognizes the column names of Bitwarden, KeePassXC, 1Password, Firefox
//! and Chrome/Chromium, among others. The column order does not matter.
//!
//! NOTE: a CSV export is UNENCRYPTED. The CLI warns about that and offers to
//! overwrite and delete the file afterwards.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::crypto::ItemKey;
use crate::error::{Error, Result};
use crate::vault::{Entry, Kind, NewEntry, Vault};

const NAME: &[&str] = &["name", "title", "account", "item name", "site"];
const URL: &[&str] = &["url", "login_uri", "uri", "website", "web site", "login url", "urls"];
const USERNAME: &[&str] = &["username", "login_username", "user", "login", "user name", "login name"];
const EMAIL: &[&str] = &["email", "e-mail", "email address", "e-mail address", "login_email", "mail"];
const PASSWORD: &[&str] = &["password", "login_password", "pass"];
const NOTES: &[&str] = &["notes", "note", "extra", "comments", "comment"];
const TAGS: &[&str] = &["tags", "folder", "group", "grouping", "category", "collection"];
const TYPE: &[&str] = &["type", "item type"];

#[derive(Default)]
struct Columns {
    name: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    email: Option<usize>,
    password: Option<usize>,
    notes: Option<usize>,
    tags: Option<usize>,
    kind: Option<usize>,
}

fn find(headers: &[String], names: &[&str]) -> Option<usize> {
    names.iter().find_map(|n| headers.iter().position(|h| h == n))
}

/// Result of reading a CSV file.
pub struct CsvImport {
    /// The items that were read, as a temporary vault (names already made unique).
    pub vault: Vault,
    /// Empty or unusable rows.
    pub skipped: usize,
}

/// Get a readable name from a URL ("https://www.github.com/login" → "github.com").
fn host_from_url(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let host = host.split(':').next()?;
    let host = host.strip_prefix("www.").unwrap_or(host);
    (!host.is_empty()).then(|| host.to_string())
}

/// Read a CSV export.
/// All fields are encrypted per field with `key` right away.
pub fn parse_csv(reader: impl Read, key: &ItemKey) -> Result<CsvImport> {
    let mut rdr = csv::ReaderBuilder::new().flexible(true).trim(csv::Trim::Headers).from_reader(reader);
    let headers: Vec<String> = rdr
        .headers()
        .map_err(|_| Error::InvalidInput("cannot read the CSV header".into()))?
        .iter()
        .map(|h| h.trim_start_matches('\u{feff}').trim().to_lowercase())
        .collect();
    let cols = Columns {
        name: find(&headers, NAME),
        url: find(&headers, URL),
        username: find(&headers, USERNAME),
        email: find(&headers, EMAIL),
        password: find(&headers, PASSWORD),
        notes: find(&headers, NOTES),
        tags: find(&headers, TAGS),
        kind: find(&headers, TYPE),
    };
    if cols.password.is_none() && cols.name.is_none() {
        return Err(Error::InvalidInput(
            "unknown CSV layout: no 'password' or 'name'/'title' column found".into(),
        ));
    }

    let mut vault = Vault::new();
    let mut skipped = 0;
    let mut record = csv::StringRecord::new();
    loop {
        match rdr.read_record(&mut record) {
            Ok(false) => break,
            Ok(true) => {}
            Err(_) => {
                skipped += 1;
                continue;
            }
        }
        let get = |c: Option<usize>| c.and_then(|i| record.get(i)).unwrap_or("").trim().to_string();
        // Bitwarden marks secure notes with type "note".
        let kind = match get(cols.kind).to_lowercase().as_str() {
            "note" | "securenote" | "secure note" => Kind::Note,
            _ => Kind::Login,
        };
        let mut fields = NewEntry {
            kind,
            name: get(cols.name),
            username: get(cols.username),
            email: get(cols.email),
            password: record.get(cols.password.unwrap_or(usize::MAX)).unwrap_or("").to_string(),
            url: get(cols.url),
            notes: get(cols.notes),
            tags: get(cols.tags)
                .split([',', ';'])
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect(),
        };
        if fields.name.is_empty()
            && fields.username.is_empty()
            && fields.email.is_empty()
            && fields.password.is_empty()
            && fields.url.is_empty()
        {
            skipped += 1;
            continue;
        }
        if fields.name.is_empty() {
            fields.name = host_from_url(&fields.url)
                .or_else(|| (!fields.username.is_empty()).then(|| fields.username.clone()))
                .or_else(|| (!fields.email.is_empty()).then(|| fields.email.clone()))
                .unwrap_or_else(|| "Imported".into());
        }
        // Multiple lines in a URL field (Bitwarden): take the first one.
        if let Some(first) = fields.url.lines().next() {
            fields.url = first.trim().to_string();
        }
        fields.name = vault.unique_name(&fields.name.replace(char::is_control, " "));
        fields.username = fields.username.replace(char::is_control, " ");
        fields.email = fields.email.replace(char::is_control, " ");
        fields.url = fields.url.replace(char::is_control, " ");
        fields.notes = fields.notes.replace(|c: char| c.is_control() && c != '\n' && c != '\t', " ");
        fields.tags = fields.tags.iter().map(|t| t.replace(char::is_control, " ")).collect();
        match Entry::new(fields, key) {
            Ok(e) => vault.add(e)?,
            Err(_) => skipped += 1,
        }
    }
    record.clear();
    Ok(CsvImport { vault, skipped })
}

/// Overwrite a file with zeros, fsync and delete it.
///
/// NOTE: on SSDs (wear levelling) and copy-on-write file systems such as
/// btrfs and ZFS, overwriting does NOT guarantee that the old data is really
/// gone. It is better than just deleting, but no guarantee.
pub fn overwrite_and_remove(path: &Path) -> Result<()> {
    let mut f = OpenOptions::new().write(true).custom_flags_nofollow().open(path)?;
    let len = f.metadata()?.len();
    f.seek(SeekFrom::Start(0))?;
    let zeros = [0u8; 8192];
    let mut left = len;
    while left > 0 {
        let n = left.min(zeros.len() as u64) as usize;
        f.write_all(&zeros[..n])?;
        left -= n as u64;
    }
    f.sync_all()?;
    drop(f);
    std::fs::remove_file(path)?;
    Ok(())
}

trait NoFollow {
    fn custom_flags_nofollow(&mut self) -> &mut Self;
}

impl NoFollow for OpenOptions {
    fn custom_flags_nofollow(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.custom_flags(libc::O_NOFOLLOW)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_item_key;

    fn parse(csv: &str) -> Result<CsvImport> {
        parse_csv(csv.as_bytes(), &test_item_key(1))
    }

    fn pw(e: &Entry) -> String {
        e.password(&test_item_key(1)).unwrap().to_string()
    }

    #[test]
    fn bitwarden() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   Work,,login,GitHub,my note,,0,https://github.com,john,\"p,w\"\"1\",\n\
                   ,,login,GitHub,,,0,https://github.com/2,pete,pw2,\n";
        let r = parse(csv).unwrap();
        assert_eq!(r.vault.len(), 2);
        let e = r.vault.get("GitHub").unwrap();
        assert_eq!(e.username(&test_item_key(1)).unwrap().as_str(), "john");
        assert_eq!(pw(e), "p,w\"1");
        assert_eq!(e.url(&test_item_key(1)).unwrap().as_str(), "https://github.com");
        assert_eq!(e.notes(&test_item_key(1)).unwrap().as_str(), "my note");
        assert_eq!(e.tags(), &["Work".to_string()]);
        assert_eq!(r.vault.get("GitHub (2)").unwrap().username(&test_item_key(1)).unwrap().as_str(), "pete");
    }

    #[test]
    fn bitwarden_note() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   ,,note,Recovery codes,\"code 1\ncode 2\",,0,,,,\n";
        let r = parse(csv).unwrap();
        let e = r.vault.get("Recovery codes").unwrap();
        assert_eq!(e.kind(), Kind::Note);
        assert_eq!(e.secret(&test_item_key(1)).unwrap().as_str(), "code 1\ncode 2");
    }

    #[test]
    fn keepassxc_and_bom() {
        let csv = "\u{feff}\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\"\n\
                   \"Root\",\"Mail\",\"john@x.nl\",\"secret\",\"https://mail.x.nl\",\"\"\n";
        let r = parse(csv).unwrap();
        assert_eq!(pw(r.vault.get("Mail").unwrap()), "secret");
    }

    #[test]
    fn firefox_without_name_column() {
        let csv = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\"\n\
                   \"https://www.example.org:443\",\"jan\",\"pw\",,\"\",\"{x}\"\n\
                   \"\",\"\",\"\",,\"\",\"{y}\"\n";
        let r = parse(csv).unwrap();
        assert_eq!(r.vault.len(), 1);
        assert!(r.vault.get("example.org").is_some());
        assert_eq!(r.skipped, 1);
    }

    #[test]
    fn chrome_and_password_with_spaces() {
        let csv = "name,url,username,password,note\nsite,https://a.b,u, spaced pw ,n\n";
        let r = parse(csv).unwrap();
        assert_eq!(pw(r.vault.get("site").unwrap()), " spaced pw ", "do not trim the password");
    }

    #[test]
    fn control_characters_are_neutralized() {
        let csv =
            "name,username,password,url,notes\nx,\"u\u{1b}[31m\",pw,\"https://a\u{7}\",\"r1\nr2\u{1b}[2J\"\n";
        let r = parse(csv).unwrap();
        let e = r.vault.get("x").unwrap();
        assert!(!e.username(&test_item_key(1)).unwrap().contains('\u{1b}'));
        assert!(!e.url(&test_item_key(1)).unwrap().contains('\u{7}'));
        assert_eq!(e.notes(&test_item_key(1)).unwrap().as_str(), "r1\nr2 [2J");
    }

    #[test]
    fn unknown_layout() {
        assert!(parse("a,b,c\n1,2,3\n").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn host_from_url_cases() {
        assert_eq!(host_from_url("https://www.github.com/login").as_deref(), Some("github.com"));
        assert_eq!(host_from_url("http://user@host.nl:8080/x").as_deref(), Some("host.nl"));
        assert_eq!(host_from_url("example.org").as_deref(), Some("example.org"));
        assert_eq!(host_from_url("").as_deref(), None);
    }

    #[test]
    fn overwrite_and_remove_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("export.csv");
        std::fs::write(&p, "secret").unwrap();
        overwrite_and_remove(&p).unwrap();
        assert!(!p.exists());
    }
}
