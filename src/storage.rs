//! Opslag op schijf: paden, atomisch schrijven, back-up en vergrendeling.
//!
//! BEVEILIGINGSKRITIEK.
//! - Map 0700, bestanden 0600 (alleen jij kunt lezen/schrijven).
//! - Schrijven gaat altijd via: tijdelijk bestand → fsync → rename → fsync
//!   van de map. Bij stroomuitval heb je dus óf de oude, óf de nieuwe kluis,
//!   nooit een half bestand.
//! - Vóór elke opslag wordt de vorige versie als `<kluis>.bak` bewaard.
//! - Een `flock`-slot plus een controle "is het bestand intussen veranderd?"
//!   voorkomt dat twee terminals elkaars wijzigingen overschrijven.
//! - Symlinks worden geweigerd (`O_NOFOLLOW`).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::crypto::{self, ItemKey, KdfParams};
use crate::error::{Error, Result};
use crate::format::{self, Header, MAX_FILE_SIZE, VaultKey};
use crate::vault::Vault;

const APP_DIR: &str = "kluis";
const VAULT_FILE: &str = "vault.enc";

/// Alle paden die bij één kluis horen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPaths {
    pub file: PathBuf,
    pub backup: PathBuf,
    pub lock: PathBuf,
}

impl VaultPaths {
    /// Paden voor een kluisbestand op een zelfgekozen plek.
    pub fn for_file(file: impl Into<PathBuf>) -> VaultPaths {
        let file = file.into();
        let with_suffix = |suffix: &str| {
            let mut s = file.clone().into_os_string();
            s.push(suffix);
            PathBuf::from(s)
        };
        VaultPaths { backup: with_suffix(".bak"), lock: with_suffix(".lock"), file }
    }

    /// Standaardlocatie volgens de XDG Base Directory-specificatie:
    /// `$XDG_DATA_HOME/kluis/vault.enc`, of `~/.local/share/kluis/vault.enc`.
    pub fn default_location() -> Result<VaultPaths> {
        Ok(Self::for_file(data_home()?.join(APP_DIR).join(VAULT_FILE)))
    }

    pub fn dir(&self) -> &Path {
        self.file.parent().unwrap_or(Path::new("."))
    }
}

fn data_home() -> Result<PathBuf> {
    // De specificatie zegt: alleen absolute paden tellen, anders negeren.
    if let Some(x) = std::env::var_os("XDG_DATA_HOME") {
        let p = PathBuf::from(x);
        if p.is_absolute() {
            return Ok(p);
        }
    }
    match std::env::var_os("HOME") {
        Some(h) if PathBuf::from(&h).is_absolute() => Ok(PathBuf::from(h).join(".local").join("share")),
        _ => Err(Error::InvalidInput("HOME is niet ingesteld; gebruik --vault <pad>".into())),
    }
}

/// Lees een bestand veilig: geen symlinks, maximale grootte.
fn read_file(path: &Path) -> Result<Vec<u8>> {
    let mut f = match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(Error::VaultNotFound(path.to_path_buf()));
        }
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(Error::InvalidInput(format!(
                "{} is een symbolische link; geef het echte pad op",
                path.display()
            )));
        }
        Err(e) => return Err(e.into()),
    };
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(Error::InvalidInput(format!("{} is geen gewoon bestand", path.display())));
    }
    if meta.len() > MAX_FILE_SIZE as u64 {
        return Err(Error::TooLarge);
    }
    let mut data = Vec::with_capacity(meta.len() as usize);
    Read::by_ref(&mut f).take(MAX_FILE_SIZE as u64 + 1).read_to_end(&mut data)?;
    if data.len() > MAX_FILE_SIZE {
        return Err(Error::TooLarge);
    }
    Ok(data)
}

/// Lees alleen de (onversleutelde) header, voor `kluis info`.
pub fn read_header(path: &Path) -> Result<Header> {
    Ok(Header::decode(&read_file(path)?)?.0)
}

/// Schrijf `data` atomisch naar `path` met rechten 0600.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().ok_or_else(|| Error::InvalidInput("ongeldig pad".into()))?;
    let rnd = crypto::random_array::<8>()?;
    let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".tmp-{suffix}"));
    let tmp = dir.join(tmp_name);

    let result = (|| -> io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        // fsync van de map, zodat de rename zelf ook duurzaam is.
        File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    Ok(result?)
}

/// Schrijf een NIEUW bestand (faalt als het al bestaat), rechten 0600.
/// Gebruikt voor exports, ook naar bijv. een USB-stick (FAT kent geen hardlinks).
pub fn write_new_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(Error::AlreadyExists(path.to_path_buf()));
        }
        Err(e) => return Err(e.into()),
    };
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// Exclusief schrijfslot; wordt vrijgegeven als het object verdwijnt.
struct WriteLock(#[allow(dead_code)] File);

impl WriteLock {
    fn acquire(path: &Path) -> Result<WriteLock> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        // SAFETY: geldige file descriptor die we zelf bezitten.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(WriteLock(f))
    }
}

fn ensure_dir(dir: &Path) -> Result<()> {
    if !dir.as_os_str().is_empty() && !dir.exists() {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    Ok(())
}

/// Een geopende (ontgrendelde) kluis.
///
/// Houdt de sleutel in vergrendeld geheugen, zodat opslaan geen nieuw
/// wachtwoord vraagt. Als dit object verdwijnt, worden sleutel en inhoud gewist.
pub struct UnlockedVault {
    pub vault: Vault,
    key: VaultKey,
    paths: VaultPaths,
    /// Het bestand zoals we het gelezen/geschreven hebben (versleuteld).
    on_disk: Vec<u8>,
    warnings: Vec<String>,
}

impl UnlockedVault {
    /// Maak een nieuwe, lege kluis. Faalt als er al een bestand staat.
    pub fn create(paths: VaultPaths, password: &[u8], kdf: KdfParams) -> Result<UnlockedVault> {
        kdf.validate()?;
        ensure_dir(paths.dir())?;
        let _lock = WriteLock::acquire(&paths.lock)?;
        if fs::symlink_metadata(&paths.file).is_ok() {
            return Err(Error::AlreadyExists(paths.file.clone()));
        }
        let key = VaultKey::create(password, kdf)?;
        let vault = Vault::new();
        let bytes = format::seal(&key, vault.to_json()?.as_slice())?;
        write_atomic(&paths.file, &bytes)?;
        Ok(UnlockedVault { vault, key, paths, on_disk: bytes, warnings: Vec::new() })
    }

    /// Open en ontsleutel een bestaande kluis.
    pub fn open(paths: VaultPaths, password: &[u8]) -> Result<UnlockedVault> {
        let bytes = read_file(&paths.file)?;
        let mut warnings = Vec::new();
        let meta = fs::metadata(&paths.file)?;
        if meta.mode() & 0o077 != 0 {
            // Herstel te ruime rechten (bijv. na kopiëren) en meld het.
            fs::set_permissions(&paths.file, fs::Permissions::from_mode(0o600))?;
            warnings.push(format!(
                "De rechten van {} waren te ruim en zijn hersteld naar 600.",
                paths.file.display()
            ));
        }
        let (plaintext, key, version) = format::open(&bytes, password)?;
        let (vault, migrated) = Vault::from_json(plaintext.as_slice(), key.item_key())?;
        drop(plaintext);
        if key.kdf().weaker_than_default() {
            warnings.push(
                "Deze kluis gebruikt lichtere Argon2-instellingen dan aanbevolen. \
                 Overweeg `kluis passwd` met de standaardinstellingen."
                    .into(),
            );
        }
        let mut uv = UnlockedVault { vault, key, paths, on_disk: bytes, warnings };
        if migrated || version < format::CURRENT_VERSION {
            // Oud formaat: meteen opslaan in het nieuwe formaat, zodat elk
            // wachtwoord en elke notitie ook op schijf apart versleuteld is.
            uv.save()?;
            uv.warnings.push(
                "Je kluis is bijgewerkt naar formaat 2: elk wachtwoord en elke notitie is nu \
                 ook nog eens apart versleuteld. (De back-up .bak is nog de oude versie.)"
                    .into(),
            );
        }
        Ok(uv)
    }

    pub fn paths(&self) -> &VaultPaths {
        &self.paths
    }

    pub fn kdf(&self) -> KdfParams {
        self.key.kdf()
    }

    /// De sleutel om wachtwoorden en notities van items te ontsleutelen.
    pub fn item_key(&self) -> &ItemKey {
        self.key.item_key()
    }

    /// De kluis (om te wijzigen) plus de itemsleutel, tegelijk te gebruiken.
    pub fn parts_mut(&mut self) -> (&mut Vault, &ItemKey) {
        (&mut self.vault, self.key.item_key())
    }

    /// Controleer het hoofdwachtwoord opnieuw (bijv. vóór `passwd` in de shell).
    pub fn verify_password(&self, password: &[u8]) -> Result<bool> {
        self.key.verify(password)
    }

    /// Waarschuwingen die bij het openen zijn ontstaan.
    pub fn take_warnings(&mut self) -> Vec<String> {
        std::mem::take(&mut self.warnings)
    }

    /// Sla de huidige inhoud op (nieuwe nonce, atomisch, met back-up).
    pub fn save(&mut self) -> Result<()> {
        let plaintext = self.vault.to_json()?;
        let new_bytes = format::seal(&self.key, plaintext.as_slice())?;
        drop(plaintext);
        self.replace_file(new_bytes, false)
    }

    /// Wijzig het hoofdwachtwoord (nieuwe salt, eventueel nieuwe parameters).
    ///
    /// Ook de back-up wordt daarna met het NIEUWE wachtwoord versleuteld, zodat
    /// een eventueel uitgelekt oud wachtwoord geen enkel bestand meer opent.
    pub fn change_password(&mut self, new_password: &[u8], kdf: KdfParams) -> Result<()> {
        kdf.validate()?;
        let new_key = VaultKey::create(new_password, kdf)?;
        // Alle losse geheimen opnieuw versleutelen met de nieuwe itemsleutel.
        let mut rekeyed = self.vault.clone();
        rekeyed.rekey(self.key.item_key(), new_key.item_key())?;
        let plaintext = rekeyed.to_json()?;
        let new_bytes = format::seal(&new_key, plaintext.as_slice())?;
        drop(plaintext);
        self.replace_file(new_bytes, true)?;
        self.vault = rekeyed;
        self.key = new_key;
        Ok(())
    }

    fn replace_file(&mut self, new_bytes: Vec<u8>, backup_is_new: bool) -> Result<()> {
        let _lock = WriteLock::acquire(&self.paths.lock)?;
        // Is het bestand intussen door een ander proces gewijzigd?
        let current = match read_file(&self.paths.file) {
            Ok(c) => c,
            Err(Error::VaultNotFound(_)) => return Err(Error::ConcurrentModification),
            Err(e) => return Err(e),
        };
        if current != self.on_disk {
            return Err(Error::ConcurrentModification);
        }
        // 1. Vorige versie als back-up bewaren.
        write_atomic(&self.paths.backup, &current)?;
        // 2. Nieuwe versie atomisch neerzetten.
        write_atomic(&self.paths.file, &new_bytes)?;
        if backup_is_new {
            write_atomic(&self.paths.backup, &new_bytes)?;
        }
        self.on_disk = new_bytes;
        Ok(())
    }

    /// Exporteer de kluis als nieuw versleuteld bestand met een eigen wachtwoord.
    pub fn export_to(&self, path: &Path, password: &[u8], kdf: KdfParams) -> Result<()> {
        let key = VaultKey::create(password, kdf)?;
        let mut copy = self.vault.clone();
        copy.rekey(self.key.item_key(), key.item_key())?;
        let plaintext = copy.to_json()?;
        let bytes = format::seal(&key, plaintext.as_slice())?;
        write_new_file(path, &bytes)
    }
}

/// Open een geëxporteerd (of ander) kluisbestand alleen om te lezen.
/// Geeft ook de sleutel terug, nodig om de items te ontsleutelen.
pub fn read_vault_file(path: &Path, password: &[u8]) -> Result<(Vault, VaultKey)> {
    let bytes = read_file(path)?;
    let (plaintext, key, _version) = format::open(&bytes, password)?;
    let (vault, _migrated) = Vault::from_json(plaintext.as_slice(), key.item_key())?;
    Ok((vault, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Entry, NewEntry};

    const P: KdfParams = KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 };
    const PW: &[u8] = b"correct paard batterij nietje";

    fn paths(dir: &tempfile::TempDir) -> VaultPaths {
        VaultPaths::for_file(dir.path().join("sub").join("vault.enc"))
    }

    fn add(uv: &mut UnlockedVault, name: &str) {
        let (vault, key) = uv.parts_mut();
        let e =
            Entry::new(NewEntry { name: name.into(), password: "geheim".into(), ..Default::default() }, key)
                .unwrap();
        vault.add(e).unwrap();
    }

    #[test]
    fn xdg_paden() {
        let p = VaultPaths::for_file("/x/y/vault.enc");
        assert_eq!(p.backup, PathBuf::from("/x/y/vault.enc.bak"));
        assert_eq!(p.lock, PathBuf::from("/x/y/vault.enc.lock"));
        assert_eq!(p.dir(), Path::new("/x/y"));
    }

    #[test]
    fn maken_openen_opslaan_en_rechten() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        let mut uv = UnlockedVault::create(p.clone(), PW, P).unwrap();
        assert_eq!(fs::metadata(&p.file).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(p.dir()).unwrap().mode() & 0o777, 0o700);
        add(&mut uv, "een");
        uv.save().unwrap();
        assert!(p.backup.exists(), "back-up van de vorige versie");
        assert_eq!(fs::metadata(&p.backup).unwrap().mode() & 0o777, 0o600);
        drop(uv);

        let uv = UnlockedVault::open(p.clone(), PW).unwrap();
        assert_eq!(uv.vault.get("een").unwrap().password(uv.item_key()).unwrap().as_str(), "geheim");
        assert_eq!(uv.kdf(), P);
        // De back-up is de lege vorige versie en opent met hetzelfde wachtwoord.
        assert!(read_vault_file(&p.backup, PW).unwrap().0.is_empty());
        // Geen tijdelijke bestanden achtergebleven.
        let leftovers: Vec<_> = fs::read_dir(p.dir())
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn bestaande_kluis_wordt_niet_overschreven() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        UnlockedVault::create(p.clone(), PW, P).unwrap();
        assert!(matches!(UnlockedVault::create(p, PW, P), Err(Error::AlreadyExists(_))));
    }

    #[test]
    fn verkeerd_wachtwoord_en_ontbrekend_bestand() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        assert!(matches!(UnlockedVault::open(p.clone(), PW), Err(Error::VaultNotFound(_))));
        UnlockedVault::create(p.clone(), PW, P).unwrap();
        assert!(matches!(UnlockedVault::open(p, b"fout"), Err(Error::Decrypt)));
    }

    #[test]
    fn gemanipuleerd_bestand_faalt() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        UnlockedVault::create(p.clone(), PW, P).unwrap();
        let mut bytes = fs::read(&p.file).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x80;
        fs::write(&p.file, &bytes).unwrap();
        assert!(matches!(UnlockedVault::open(p.clone(), PW), Err(Error::Decrypt)));
        fs::write(&p.file, b"").unwrap();
        assert!(matches!(UnlockedVault::open(p.clone(), PW), Err(Error::Truncated)));
        fs::write(&p.file, vec![0u8; 500]).unwrap();
        assert!(matches!(UnlockedVault::open(p, PW), Err(Error::NotAVault)));
    }

    #[test]
    fn te_ruime_rechten_worden_hersteld() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        UnlockedVault::create(p.clone(), PW, P).unwrap();
        fs::set_permissions(&p.file, fs::Permissions::from_mode(0o644)).unwrap();
        let mut uv = UnlockedVault::open(p.clone(), PW).unwrap();
        assert_eq!(uv.take_warnings().len(), 2, "rechten + lichte KDF");
        assert_eq!(fs::metadata(&p.file).unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn symlink_wordt_geweigerd() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        UnlockedVault::create(p.clone(), PW, P).unwrap();
        let link = dir.path().join("link.enc");
        std::os::unix::fs::symlink(&p.file, &link).unwrap();
        assert!(matches!(UnlockedVault::open(VaultPaths::for_file(link), PW), Err(Error::InvalidInput(_))));
    }

    #[test]
    fn gelijktijdige_wijziging_wordt_opgemerkt() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        UnlockedVault::create(p.clone(), PW, P).unwrap();
        let mut a = UnlockedVault::open(p.clone(), PW).unwrap();
        let mut b = UnlockedVault::open(p.clone(), PW).unwrap();
        add(&mut a, "van a");
        a.save().unwrap();
        add(&mut b, "van b");
        assert!(matches!(b.save(), Err(Error::ConcurrentModification)));
        // De wijziging van a is niet verloren gegaan.
        assert!(UnlockedVault::open(p, PW).unwrap().vault.get("van a").is_some());
    }

    #[test]
    fn wachtwoord_wijzigen_ook_voor_backup() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        let mut uv = UnlockedVault::create(p.clone(), PW, P).unwrap();
        add(&mut uv, "x");
        uv.save().unwrap();
        let new_p = KdfParams { memory_kib: 9 * 1024, iterations: 2, parallelism: 1 };
        uv.change_password(b"nieuw wachtwoord", new_p).unwrap();
        add(&mut uv, "y");
        uv.save().unwrap(); // werkt met de nieuwe sleutel
        drop(uv);
        assert!(matches!(UnlockedVault::open(p.clone(), PW), Err(Error::Decrypt)));
        assert!(matches!(read_vault_file(&p.backup, PW), Err(Error::Decrypt)), "oude ww opent back-up niet");
        let uv = UnlockedVault::open(p.clone(), b"nieuw wachtwoord").unwrap();
        assert_eq!(uv.kdf(), new_p);
        assert_eq!(uv.vault.len(), 2);
        // Ook de losse wachtwoorden zijn met de nieuwe sleutel versleuteld.
        assert_eq!(uv.vault.get("x").unwrap().password(uv.item_key()).unwrap().as_str(), "geheim");
        assert!(read_vault_file(&p.backup, b"nieuw wachtwoord").is_ok());
    }

    #[test]
    fn export_en_import() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        let mut uv = UnlockedVault::create(p, PW, P).unwrap();
        add(&mut uv, "x");
        let out = dir.path().join("export.kluis");
        uv.export_to(&out, b"exportwachtwoord", P).unwrap();
        assert_eq!(fs::metadata(&out).unwrap().mode() & 0o777, 0o600);
        assert!(matches!(uv.export_to(&out, b"x", P), Err(Error::AlreadyExists(_))));
        assert!(matches!(read_vault_file(&out, PW), Err(Error::Decrypt)));
        let (v, k) = read_vault_file(&out, b"exportwachtwoord").unwrap();
        assert_eq!(v.get("x").unwrap().password(k.item_key()).unwrap().as_str(), "geheim");
        // De export heeft een eigen itemsleutel: de sleutel van de kluis werkt niet.
        assert!(v.get("x").unwrap().password(uv.item_key()).is_err());
    }

    #[test]
    fn oud_formaat_wordt_automatisch_bijgewerkt() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        ensure_dir(p.dir()).unwrap();
        let old_json = br#"{"schema":1,"entries":[{"name":"Oud","password":"oud-geheim","notes":"n"}]}"#;
        let v1 = format::seal_v1_for_tests(PW, P, old_json).unwrap();
        write_atomic(&p.file, &v1).unwrap();
        assert_eq!(read_header(&p.file).unwrap().version, 1);

        let mut uv = UnlockedVault::open(p.clone(), PW).unwrap();
        assert!(uv.take_warnings().iter().any(|w| w.contains("formaat 2")));
        assert_eq!(uv.vault.get("oud").unwrap().password(uv.item_key()).unwrap().as_str(), "oud-geheim");
        drop(uv);
        assert_eq!(read_header(&p.file).unwrap().version, 2);
        let mut uv = UnlockedVault::open(p, PW).unwrap();
        assert!(!uv.take_warnings().iter().any(|w| w.contains("formaat 2")), "maar één keer migreren");
    }

    #[test]
    fn header_lezen_zonder_wachtwoord() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        UnlockedVault::create(p.clone(), PW, P).unwrap();
        let h = read_header(&p.file).unwrap();
        assert_eq!(h.version, 2);
        assert_eq!(h.kdf, P);
    }
}
