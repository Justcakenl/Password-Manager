//! Storage on disk: paths, atomic writes, backups and locking.
//!
//! SECURITY-CRITICAL.
//! - Directory 0700, files 0600 (only you can read/write).
//! - Writing always goes through: temporary file → fsync → rename → fsync of
//!   the directory. After a power failure you have either the old or the new
//!   vault, never a half-written file.
//! - Before every save the previous version is kept as `<vault>.bak`.
//! - A `flock` lock plus a check "has the file changed in the meantime?"
//!   stops two terminals from overwriting each other's changes.
//! - Symlinks are refused (`O_NOFOLLOW`).
//! - Re-keying (new master password, key file or security level) also
//!   re-encrypts the backup and the `pre-update` copies, so the old secrets
//!   open no file CakePass keeps (copies of a still older key are reported).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::crypto::{self, ItemKey, KdfParams, SecurityLevel};
use crate::error::{Error, Result};
use crate::format::{self, Credentials, Header, MAX_FILE_SIZE, VaultKey};
use crate::vault::Vault;

const APP_DIR: &str = "cakepass";
/// Name of the folder used by the first releases (when the command was still
/// called `kluis`). Moved to the new name automatically, see [`app_dir`].
const LEGACY_APP_DIR: &str = "kluis";
const VAULT_FILE: &str = "vault.enc";

/// All paths that belong to one vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPaths {
    pub file: PathBuf,
    pub backup: PathBuf,
    pub lock: PathBuf,
}

impl VaultPaths {
    /// Paths for a vault file at a location of your choice.
    pub fn for_file(file: impl Into<PathBuf>) -> VaultPaths {
        let file = file.into();
        let with_suffix = |suffix: &str| {
            let mut s = file.clone().into_os_string();
            s.push(suffix);
            PathBuf::from(s)
        };
        VaultPaths { backup: with_suffix(".bak"), lock: with_suffix(".lock"), file }
    }

    /// Default location according to the XDG Base Directory specification:
    /// `$XDG_DATA_HOME/cakepass/vault.enc`, of `~/.local/share/cakepass/vault.enc`.
    pub fn default_location() -> Result<VaultPaths> {
        Ok(Self::for_file(app_dir(&data_home()?).join(VAULT_FILE)))
    }

    pub fn dir(&self) -> &Path {
        self.file.parent().unwrap_or(Path::new("."))
    }
}

/// The CakePass folder inside an XDG base directory (data, config or cache).
///
/// If only the folder of the first releases (`kluis`) exists, it is renamed
/// to `cakepass` first, so an existing vault is never left behind. A plain
/// rename within the same directory is atomic and keeps the permissions.
pub fn app_dir(base: &Path) -> PathBuf {
    let new = base.join(APP_DIR);
    let old = base.join(LEGACY_APP_DIR);
    if fs::symlink_metadata(&new).is_err()
        && fs::symlink_metadata(&old).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
    {
        let _ = fs::rename(&old, &new);
    }
    new
}

fn data_home() -> Result<PathBuf> {
    // The specification says: only absolute paths count, ignore anything else.
    if let Some(x) = std::env::var_os("XDG_DATA_HOME") {
        let p = PathBuf::from(x);
        if p.is_absolute() {
            return Ok(p);
        }
    }
    match std::env::var_os("HOME") {
        Some(h) if PathBuf::from(&h).is_absolute() => Ok(PathBuf::from(h).join(".local").join("share")),
        _ => Err(Error::InvalidInput("HOME is not set; use --vault <path>".into())),
    }
}

/// Read a file safely: no symlinks, maximum size.
fn read_file(path: &Path) -> Result<Vec<u8>> {
    let mut f = match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(Error::VaultNotFound(path.to_path_buf()));
        }
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(Error::InvalidInput(format!(
                "{} is a symbolic link; give the real path",
                path.display()
            )));
        }
        Err(e) => return Err(e.into()),
    };
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(Error::InvalidInput(format!("{} is not a regular file", path.display())));
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

/// Read only the (unencrypted) header, for `cakepass info`.
pub fn read_header(path: &Path) -> Result<Header> {
    Ok(Header::decode(&read_file(path)?)?.0)
}

/// Write `data` atomically to `path` with permissions 0600.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().ok_or_else(|| Error::InvalidInput("invalid path".into()))?;
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
        // fsync of the directory, so the rename itself is durable too.
        File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    Ok(result?)
}

/// Write a NEW file (fails if it already exists), permissions 0600.
/// Used for exports, also to e.g. a USB stick (FAT has no hard links).
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

/// Exclusive write lock; released when the object is dropped.
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
        // SAFETY: a valid file descriptor that we own.
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

/// An opened (unlocked) vault.
///
/// Keeps the key in locked memory, so saving does not ask for the password
/// again. When this object is dropped, key and contents are wiped.
pub struct UnlockedVault {
    pub vault: Vault,
    key: VaultKey,
    paths: VaultPaths,
    /// The file as we last read/wrote it (encrypted).
    on_disk: Vec<u8>,
    warnings: Vec<String>,
}

impl UnlockedVault {
    /// Create a new, empty vault. Fails if a file already exists. With a
    /// key-file pepper in `creds`, the vault requires that key file.
    pub fn create(paths: VaultPaths, creds: Credentials<'_>, kdf: KdfParams) -> Result<UnlockedVault> {
        kdf.validate()?;
        crypto::ensure_memory(&kdf, crypto::MemoryUse::Create)?;
        ensure_dir(paths.dir())?;
        let _lock = WriteLock::acquire(&paths.lock)?;
        if fs::symlink_metadata(&paths.file).is_ok() {
            return Err(Error::AlreadyExists(paths.file.clone()));
        }
        let key = VaultKey::create(creds, kdf)?;
        let vault = Vault::new();
        let bytes = format::seal(&key, vault.to_json()?.as_slice())?;
        write_atomic(&paths.file, &bytes)?;
        Ok(UnlockedVault { vault, key, paths, on_disk: bytes, warnings: Vec::new() })
    }

    /// Open and decrypt an existing vault (with its key file, if it needs one).
    ///
    /// A vault in format version 2 is not rewritten just for opening it: it
    /// becomes version 3 on its next save. Version 1 (and an old content
    /// schema) is converted right away, because only then is every field
    /// encrypted separately on disk.
    pub fn open(paths: VaultPaths, creds: Credentials<'_>) -> Result<UnlockedVault> {
        let bytes = read_file(&paths.file)?;
        let mut warnings = Vec::new();
        let meta = fs::metadata(&paths.file)?;
        if meta.mode() & 0o077 != 0 {
            // Repair overly broad permissions (e.g. after copying) and report it.
            fs::set_permissions(&paths.file, fs::Permissions::from_mode(0o600))?;
            warnings.push(format!(
                "The permissions of {} were too broad and have been reset to 600.",
                paths.file.display()
            ));
        }
        let (plaintext, key, version) = format::open(&bytes, creds)?;
        let (vault, migrated) = Vault::from_json(plaintext.as_slice(), key.item_key())?;
        drop(plaintext);
        if key.kdf().weaker_than_standard() {
            warnings.push(
                "This vault uses lighter Argon2 settings than recommended (lighter than the Standard \
                 level). Consider `cakepass security --level high`."
                    .into(),
            );
        }
        let mut uv = UnlockedVault { vault, key, paths, on_disk: bytes, warnings };
        if migrated || version < 2 {
            // Old format: save right away in the new format, so every field of
            // every item is also encrypted separately on disk.
            uv.save()?;
            uv.warnings.push(
                "Your vault was upgraded to the newest format: every field of every item is now \
                 also encrypted separately. (The .bak backup is still the old version.)"
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

    /// The named level of the Argon2 settings (`None` = custom settings).
    pub fn security_level(&self) -> Option<SecurityLevel> {
        SecurityLevel::of(&self.key.kdf())
    }

    /// Whether this vault requires a key file.
    pub fn uses_key_file(&self) -> bool {
        self.key.uses_key_file()
    }

    /// Argon2 settings for an export file: those of this vault, but never
    /// lighter than the Standard level. (An export has only its own
    /// password, never a key file.)
    pub fn export_params(&self) -> KdfParams {
        let kdf = self.kdf();
        if kdf.weaker_than_standard() { KdfParams::STANDARD } else { kdf }
    }

    /// The key to decrypt the fields of items.
    pub fn item_key(&self) -> &ItemKey {
        self.key.item_key()
    }

    /// The vault (to modify) plus the item key, usable at the same time.
    pub fn parts_mut(&mut self) -> (&mut Vault, &ItemKey) {
        (&mut self.vault, self.key.item_key())
    }

    /// Check the master password again (e.g. before `passwd` in the shell).
    /// For a vault with a key file, `creds` must hold the key file too.
    pub fn verify_password(&self, creds: Credentials<'_>) -> Result<bool> {
        self.key.verify(creds)
    }

    /// Warnings that arose while opening.
    pub fn take_warnings(&mut self) -> Vec<String> {
        std::mem::take(&mut self.warnings)
    }

    /// Save the current contents (new nonce, atomic, with backup).
    pub fn save(&mut self) -> Result<()> {
        let plaintext = self.vault.to_json()?;
        let new_bytes = format::seal(&self.key, plaintext.as_slice())?;
        drop(plaintext);
        self.replace_file(new_bytes, false)
    }

    /// Re-key the vault: a new master password, a new (or no) key file
    /// and/or new Argon2 settings, always with a new random salt. Used by
    /// `passwd` (new password) and `security` (same password; another level
    /// or key file).
    ///
    /// Every item is re-encrypted with the new item key, and the backup is
    /// then encrypted with the NEW secrets as well. All or nothing: on an
    /// error the vault (memory and file) is unchanged.
    ///
    /// Then the `pre-update` copies are re-encrypted too (see
    /// [`rekey_update_copies`]), keeping their old contents: the report
    /// says which could not be (a copy of a still older key, or an error).
    /// That part comes after the vault is safely re-keyed and never undoes
    /// it. Exports and copies you made yourself keep their own password.
    pub fn rekey(&mut self, new: Credentials<'_>, kdf: KdfParams) -> Result<CopiesReport> {
        kdf.validate()?;
        let new_key = VaultKey::create(new, kdf)?;
        // Re-encrypt every individual secret with the new item key.
        let mut rekeyed = self.vault.clone();
        rekeyed.rekey(self.key.item_key(), new_key.item_key())?;
        let plaintext = rekeyed.to_json()?;
        let new_bytes = format::seal(&new_key, plaintext.as_slice())?;
        drop(plaintext);
        self.replace_file(new_bytes, true)?;
        self.vault = rekeyed;
        let old_key = std::mem::replace(&mut self.key, new_key);
        Ok(rekey_update_copies(&self.paths, &old_key, &self.key))
    }

    fn replace_file(&mut self, new_bytes: Vec<u8>, backup_is_new: bool) -> Result<()> {
        let _lock = WriteLock::acquire(&self.paths.lock)?;
        // Has the file been changed by another process in the meantime?
        let current = match read_file(&self.paths.file) {
            Ok(c) => c,
            Err(Error::VaultNotFound(_)) => return Err(Error::ConcurrentModification),
            Err(e) => return Err(e),
        };
        if current != self.on_disk {
            return Err(Error::ConcurrentModification);
        }
        // 1. Keep the previous version as a backup.
        write_atomic(&self.paths.backup, &current)?;
        // 2. Put the new version in place atomically.
        write_atomic(&self.paths.file, &new_bytes)?;
        if backup_is_new {
            write_atomic(&self.paths.backup, &new_bytes)?;
        }
        self.on_disk = new_bytes;
        Ok(())
    }

    /// Export the vault as a new encrypted file with its own password.
    pub fn export_to(&self, path: &Path, password: &[u8], kdf: KdfParams) -> Result<()> {
        write_with_password(self.vault.clone(), self.key.item_key(), path, password, kdf)
    }

    /// Share some items: a new encrypted file with only these items and a
    /// password of its own, in the export format, so the other person adds
    /// them with `cakepass import` (which checks every item first). The
    /// master password and key file never go into it; 2FA secrets only with
    /// `with_totp` (see [`Vault::share_subset`]). Argon2 runs at the Standard
    /// level whatever this vault uses: the password is a generated passphrase,
    /// and a smaller computer must be able to open the file. Returns how
    /// many items.
    pub fn share_to(&self, path: &Path, names: &[&str], password: &[u8], with_totp: bool) -> Result<usize> {
        let part = self.vault.share_subset(names, self.key.item_key(), with_totp)?;
        let n = part.len();
        write_with_password(part, self.key.item_key(), path, password, KdfParams::STANDARD)?;
        Ok(n)
    }
}

/// Re-encrypt `vault` (now under `from`) with a new key from `password`
/// alone and write it to a NEW file (0600; never overwrites).
fn write_with_password(
    mut vault: Vault,
    from: &ItemKey,
    path: &Path,
    password: &[u8],
    kdf: KdfParams,
) -> Result<()> {
    let key = VaultKey::create(Credentials::password(password), kdf)?;
    vault.rekey(from, key.item_key())?;
    let plaintext = vault.to_json()?;
    let bytes = format::seal(&key, plaintext.as_slice())?;
    write_new_file(path, &bytes)
}

/// How many "pre-update" copies we keep.
const KEEP_UPDATE_BACKUPS: usize = 3;

/// The `pre-update` copies of this vault, oldest first: regular files named
/// exactly `<vault>.pre-update-<digits>` (no temporary files, no other
/// endings, no symlinks or folders).
impl VaultPaths {
    /// Whether `file` is this vault's own file: the vault itself, its backup
    /// or a copy made before an update (same file on disk, so also through
    /// another name). Never offer to delete those after an import.
    pub fn owns(&self, file: &Path) -> bool {
        use crate::keyfile::same_file;
        same_file(file, &self.file)
            || same_file(file, &self.backup)
            || update_copies(self).is_ok_and(|c| c.iter().any(|(_, p)| same_file(file, p)))
    }
}

fn update_copies(paths: &VaultPaths) -> Result<Vec<(u64, PathBuf)>> {
    let base = paths.file.file_name().ok_or_else(|| Error::InvalidInput("invalid path".into()))?;
    let prefix = format!("{}.pre-update-", base.to_string_lossy());
    let mut found: Vec<(u64, PathBuf)> = fs::read_dir(paths.dir())?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let digits = name.strip_prefix(&prefix)?;
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some((digits.parse::<u64>().ok()?, e.path()))
        })
        .collect();
    found.sort();
    Ok(found)
}

/// What happened to the `pre-update` copies when the vault was re-keyed.
#[derive(Debug, Default)]
pub struct CopiesReport {
    /// Re-encrypted with the new key; their contents are unchanged.
    pub rekeyed: usize,
    /// Encrypted with a key from before the previous change (they open with
    /// an even older password or key file): left as they are.
    pub stale: Vec<PathBuf>,
    /// Could not be re-encrypted, with the reason (never a secret).
    pub failed: Vec<(PathBuf, String)>,
}

/// Re-encrypt the `pre-update` copies made under `old` with `new`, keeping
/// their contents (the old vault, for going back to an older CakePass), their
/// schema and their file layout where possible. Written with `write_atomic`
/// (0600; a crash leaves the old or the new file, never half of one).
///
/// Idempotent: a copy is only touched when its header carries exactly the
/// old key's salt, settings and key-file flag; once re-encrypted it has the
/// new salt, which no later old key can match again.
pub fn rekey_update_copies(paths: &VaultPaths, old: &VaultKey, new: &VaultKey) -> CopiesReport {
    let mut report = CopiesReport::default();
    let copies = match update_copies(paths) {
        Ok(c) => c,
        Err(e) => {
            report.failed.push((paths.dir().to_path_buf(), e.to_string()));
            return report;
        }
    };
    if copies.is_empty() {
        return report;
    }
    let _lock = match WriteLock::acquire(&paths.lock) {
        Ok(l) => l,
        Err(e) => {
            report.failed.extend(copies.into_iter().map(|(_, p)| (p, e.to_string())));
            return report;
        }
    };
    for (_, path) in copies {
        let result = read_file(&path).and_then(|data| {
            // Already under the new key (re-keying again after a failure
            // half-way): nothing to do, and not an "older" copy either.
            if format::written_with(&data, new)? {
                return Ok(None);
            }
            Ok(Some(data))
        });
        let result = result.and_then(|data| match data {
            None => Ok(None),
            Some(data) => match format::open_with_key(&data, old)? {
                Some((plaintext, version)) => {
                    let json =
                        crate::vault::reseal_json(plaintext.as_slice(), old.item_key(), new.item_key())?;
                    drop(plaintext);
                    let bytes = format::seal_like(new, version, json.as_slice())?;
                    write_atomic(&path, &bytes).map(|()| Some(true))
                }
                // Not this key's copy: from before an earlier change.
                None => Ok(Some(false)),
            },
        });
        match result {
            Ok(None) => {}
            Ok(Some(true)) => report.rekeyed += 1,
            Ok(Some(false)) => report.stale.push(path),
            Err(e) => report.failed.push((path, e.to_string())),
        }
    }
    report
}

/// Make an extra copy of the vault file before an update
/// (`vault.enc.pre-update-<time>`, permissions 600) and delete the oldest if
/// there are more than three. Returns `None` if there is no vault (yet).
///
/// The copy is an ordinary encrypted vault file and opens with your master
/// password: `cakepass --vault <copy> list`.
pub fn backup_before_update(paths: &VaultPaths) -> Result<Option<PathBuf>> {
    if !paths.file.exists() {
        return Ok(None);
    }
    // Not while a save or a re-key is busy: the copy must be a whole file,
    // and a re-key must see (and convert) every copy.
    let _lock = WriteLock::acquire(&paths.lock)?;
    let data = match read_file(&paths.file) {
        Ok(d) => d,
        Err(Error::VaultNotFound(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    let base = paths.file.file_name().ok_or_else(|| Error::InvalidInput("invalid path".into()))?;
    let prefix = format!("{}.pre-update-", base.to_string_lossy());
    // The number is the time, but always higher than that of existing copies,
    // so the order is right and a deleted name never comes back.
    let n = update_copies(paths)?.last().map_or(0, |(s, _)| s + 1).max(crate::vault::now());
    let target = paths.dir().join(format!("{prefix}{n}"));
    write_new_file(&target, &data)?;

    // Clean up old copies (only files with exactly this name pattern).
    let mut old = update_copies(paths)?;
    while old.len() > KEEP_UPDATE_BACKUPS {
        let (_, path) = old.remove(0);
        let _ = fs::remove_file(path);
    }
    Ok(Some(target))
}

/// Open an exported (or other) vault file read-only.
/// Also returns the key, needed to decrypt the items.
pub fn read_vault_file(path: &Path, creds: Credentials<'_>) -> Result<(Vault, VaultKey)> {
    let bytes = read_file(path)?;
    let (plaintext, key, _version) = format::open(&bytes, creds)?;
    let (vault, _migrated) = Vault::from_json(plaintext.as_slice(), key.item_key())?;
    Ok((vault, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyFilePepper;
    use crate::vault::{Entry, NewEntry};

    const P: KdfParams = KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 };
    const PW: &[u8] = b"correct horse battery staple";
    const PWC: Credentials<'static> = Credentials { password: PW, key_file: None };

    fn creds(pw: &[u8]) -> Credentials<'_> {
        Credentials::password(pw)
    }

    fn paths(dir: &tempfile::TempDir) -> VaultPaths {
        VaultPaths::for_file(dir.path().join("sub").join("vault.enc"))
    }

    fn add(uv: &mut UnlockedVault, name: &str) {
        let (vault, key) = uv.parts_mut();
        let e =
            Entry::new(NewEntry { name: name.into(), password: "secret".into(), ..Default::default() }, key)
                .unwrap();
        vault.add(e).unwrap();
    }

    #[test]
    fn xdg_paths() {
        let p = VaultPaths::for_file("/x/y/vault.enc");
        assert_eq!(p.backup, PathBuf::from("/x/y/vault.enc.bak"));
        assert_eq!(p.lock, PathBuf::from("/x/y/vault.enc.lock"));
        assert_eq!(p.dir(), Path::new("/x/y"));
    }

    #[test]
    fn create_open_save_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        let mut uv = UnlockedVault::create(p.clone(), PWC, P).unwrap();
        assert_eq!(fs::metadata(&p.file).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(p.dir()).unwrap().mode() & 0o777, 0o700);
        add(&mut uv, "one");
        uv.save().unwrap();
        assert!(p.backup.exists(), "backup of the previous version");
        assert_eq!(fs::metadata(&p.backup).unwrap().mode() & 0o777, 0o600);
        drop(uv);

        let uv = UnlockedVault::open(p.clone(), PWC).unwrap();
        assert_eq!(uv.vault.get("one").unwrap().password(uv.item_key()).unwrap().as_str(), "secret");
        assert_eq!(uv.kdf(), P);
        // The backup is the empty previous version and opens with the same password.
        assert!(read_vault_file(&p.backup, PWC).unwrap().0.is_empty());
        // No temporary files left behind.
        let leftovers: Vec<_> = fs::read_dir(p.dir())
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn existing_vault_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        UnlockedVault::create(p.clone(), PWC, P).unwrap();
        assert!(matches!(UnlockedVault::create(p, PWC, P), Err(Error::AlreadyExists(_))));
    }

    #[test]
    fn wrong_password_and_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        assert!(matches!(UnlockedVault::open(p.clone(), PWC), Err(Error::VaultNotFound(_))));
        UnlockedVault::create(p.clone(), PWC, P).unwrap();
        assert!(matches!(UnlockedVault::open(p, creds(b"wrong")), Err(Error::Decrypt)));
    }

    #[test]
    fn tampered_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        UnlockedVault::create(p.clone(), PWC, P).unwrap();
        let mut bytes = fs::read(&p.file).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x80;
        fs::write(&p.file, &bytes).unwrap();
        assert!(matches!(UnlockedVault::open(p.clone(), PWC), Err(Error::Decrypt)));
        fs::write(&p.file, b"").unwrap();
        assert!(matches!(UnlockedVault::open(p.clone(), PWC), Err(Error::Truncated)));
        fs::write(&p.file, vec![0u8; 500]).unwrap();
        assert!(matches!(UnlockedVault::open(p, PWC), Err(Error::NotAVault)));
    }

    #[test]
    fn overly_broad_permissions_are_repaired() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        UnlockedVault::create(p.clone(), PWC, P).unwrap();
        fs::set_permissions(&p.file, fs::Permissions::from_mode(0o644)).unwrap();
        let mut uv = UnlockedVault::open(p.clone(), PWC).unwrap();
        assert_eq!(uv.take_warnings().len(), 2, "permissions + light KDF");
        assert_eq!(fs::metadata(&p.file).unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn symlink_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        UnlockedVault::create(p.clone(), PWC, P).unwrap();
        let link = dir.path().join("link.enc");
        std::os::unix::fs::symlink(&p.file, &link).unwrap();
        assert!(matches!(UnlockedVault::open(VaultPaths::for_file(link), PWC), Err(Error::InvalidInput(_))));
    }

    #[test]
    fn concurrent_modification_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        UnlockedVault::create(p.clone(), PWC, P).unwrap();
        let mut a = UnlockedVault::open(p.clone(), PWC).unwrap();
        let mut b = UnlockedVault::open(p.clone(), PWC).unwrap();
        add(&mut a, "from a");
        a.save().unwrap();
        add(&mut b, "from b");
        assert!(matches!(b.save(), Err(Error::ConcurrentModification)));
        // The change from a was not lost.
        assert!(UnlockedVault::open(p, PWC).unwrap().vault.get("from a").is_some());
    }

    #[test]
    fn changing_password_also_covers_backup() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        let mut uv = UnlockedVault::create(p.clone(), PWC, P).unwrap();
        add(&mut uv, "x");
        uv.save().unwrap();
        let new_p = KdfParams { memory_kib: 9 * 1024, iterations: 2, parallelism: 1 };
        uv.rekey(creds(b"new password"), new_p).unwrap();
        add(&mut uv, "y");
        uv.save().unwrap(); // works with the new key
        drop(uv);
        assert!(matches!(UnlockedVault::open(p.clone(), PWC), Err(Error::Decrypt)));
        assert!(
            matches!(read_vault_file(&p.backup, PWC), Err(Error::Decrypt)),
            "the old password does not open the backup"
        );
        let uv = UnlockedVault::open(p.clone(), creds(b"new password")).unwrap();
        assert_eq!(uv.kdf(), new_p);
        assert_eq!(uv.vault.len(), 2);
        // The individual passwords are encrypted with the new key as well.
        assert_eq!(uv.vault.get("x").unwrap().password(uv.item_key()).unwrap().as_str(), "secret");
        assert!(read_vault_file(&p.backup, creds(b"new password")).is_ok());
    }

    #[test]
    fn export_and_import() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        let mut uv = UnlockedVault::create(p, PWC, P).unwrap();
        add(&mut uv, "x");
        let out = dir.path().join("export.cakepass");
        uv.export_to(&out, b"export password", P).unwrap();
        assert_eq!(fs::metadata(&out).unwrap().mode() & 0o777, 0o600);
        assert!(matches!(uv.export_to(&out, b"x", P), Err(Error::AlreadyExists(_))));
        assert!(matches!(read_vault_file(&out, PWC), Err(Error::Decrypt)));
        let (v, k) = read_vault_file(&out, creds(b"export password")).unwrap();
        assert_eq!(v.get("x").unwrap().password(k.item_key()).unwrap().as_str(), "secret");
        // The export has its own item key: the vault's key does not work.
        assert!(v.get("x").unwrap().password(uv.item_key()).is_err());
    }

    #[test]
    fn old_format_is_upgraded_automatically() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        ensure_dir(p.dir()).unwrap();
        let old_json = br#"{"schema":1,"entries":[{"name":"Old","password":"old-secret","notes":"n"}]}"#;
        let v1 = format::seal_v1_for_tests(PW, P, old_json).unwrap();
        write_atomic(&p.file, &v1).unwrap();
        assert_eq!(read_header(&p.file).unwrap().version, 1);

        let mut uv = UnlockedVault::open(p.clone(), PWC).unwrap();
        assert!(uv.take_warnings().iter().any(|w| w.contains("newest format")));
        assert_eq!(uv.vault.get("old").unwrap().password(uv.item_key()).unwrap().as_str(), "old-secret");
        drop(uv);
        assert_eq!(read_header(&p.file).unwrap().version, 3);
        let mut uv = UnlockedVault::open(p, PWC).unwrap();
        assert!(!uv.take_warnings().iter().any(|w| w.contains("newest format")), "migrate only once");
    }

    #[test]
    fn backup_before_update_keeps_three() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        assert!(backup_before_update(&p).unwrap().is_none(), "no vault, no copy");
        let mut uv = UnlockedVault::create(p.clone(), PWC, P).unwrap();
        add(&mut uv, "important");
        uv.save().unwrap();
        drop(uv);
        let original = fs::read(&p.file).unwrap();
        let mut made = Vec::new();
        for _ in 0..5 {
            made.push(backup_before_update(&p).unwrap().unwrap());
        }
        // The last copy is identical, has permissions 600 and opens normally.
        let last = made.last().unwrap();
        assert_eq!(fs::read(last).unwrap(), original);
        assert_eq!(fs::metadata(last).unwrap().mode() & 0o777, 0o600);
        assert!(read_vault_file(last, PWC).is_ok());
        // Only three are kept; the oldest are gone; the vault itself is untouched.
        let left: Vec<_> = made.iter().filter(|m| m.exists()).collect();
        assert_eq!(left.len(), 3);
        assert!(!made[0].exists() && !made[1].exists());
        assert_eq!(fs::read(&p.file).unwrap(), original);
    }

    /// The names of the items in a vault file.
    fn names_in(path: &Path, c: Credentials<'_>) -> Result<Vec<String>> {
        let (v, _) = read_vault_file(path, c)?;
        Ok(v.entries().iter().map(|e| e.name().to_string()).collect())
    }

    #[test]
    fn rekeying_also_rekeys_the_pre_update_copies_keeping_their_contents() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        let mut uv = UnlockedVault::create(p.clone(), PWC, P).unwrap();
        add(&mut uv, "before");
        uv.save().unwrap();
        let copy = backup_before_update(&p).unwrap().unwrap();
        add(&mut uv, "after");
        uv.save().unwrap();
        // Files that only look like copies are never touched.
        let base = p.file.file_name().unwrap().to_string_lossy().into_owned();
        let lookalikes: Vec<PathBuf> = ["pre-update-12.tmp", "pre-update-+5", "pre-update-", "pre-update-7x"]
            .iter()
            .map(|t| p.dir().join(format!("{base}.{t}")))
            .chain([p.dir().join(format!(".{base}.pre-update-3.tmp-ab"))])
            .collect();
        for l in &lookalikes {
            fs::copy(&copy, l).unwrap();
        }
        let copy_before = fs::read(&copy).unwrap();

        let r = uv.rekey(creds(b"a whole new passphrase"), P).unwrap();
        assert_eq!((r.rekeyed, r.stale.len(), r.failed.len()), (1, 0, 0), "{r:?}");
        // The old password opens no copy CakePass keeps; the new one opens it,
        // with its OLD contents (it is the vault from before the update).
        assert!(matches!(read_vault_file(&copy, PWC), Err(Error::Decrypt)));
        assert_eq!(names_in(&copy, creds(b"a whole new passphrase")).unwrap(), ["before"]);
        assert_eq!(fs::metadata(&copy).unwrap().mode() & 0o777, 0o600, "still 0600 after re-keying");
        for l in &lookalikes {
            assert_eq!(fs::read(l).unwrap(), copy_before, "{} was touched", l.display());
        }
        // Idempotent: once more with the new key as the target changes nothing
        // (and an already re-keyed copy is not called "older" either).
        let now = fs::read(&copy).unwrap();
        let other = VaultKey::create(PWC, P).unwrap();
        let r = rekey_update_copies(&p, &other, &uv.key);
        assert_eq!((r.rekeyed, r.stale.len(), r.failed.len()), (0, 0, 0), "{r:?}");
        assert_eq!(fs::read(&copy).unwrap(), now);
        // A copy of a still older key is reported and left alone; a damaged
        // copy of the current key is an error, not "older".
        let older = p.dir().join(format!("{base}.pre-update-5"));
        fs::copy(&lookalikes[0], &older).unwrap();
        let mut damaged = fs::read(&copy).unwrap();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        let broken = p.dir().join(format!("{base}.pre-update-6"));
        write_atomic(&broken, &damaged).unwrap();
        let r = uv.rekey(creds(b"and yet another passphrase"), P).unwrap();
        assert_eq!(r.rekeyed, 1, "{r:?}");
        assert_eq!(r.stale, std::slice::from_ref(&older));
        assert_eq!(r.failed.len(), 1, "{r:?}");
        assert_eq!(r.failed[0].0, broken);
        assert_eq!(fs::read(&older).unwrap(), copy_before, "an older copy is not changed");
        assert_eq!(names_in(&copy, creds(b"and yet another passphrase")).unwrap(), ["before"]);
    }

    #[test]
    fn a_new_key_file_also_locks_the_old_one_out_of_the_copies() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        let kf1 = KeyFilePepper::derive(b"key file one").unwrap();
        let kf2 = KeyFilePepper::derive(b"key file two").unwrap();
        let mut uv = UnlockedVault::create(p.clone(), Credentials::new(PW, Some(&kf1)), P).unwrap();
        add(&mut uv, "x");
        uv.save().unwrap();
        let copy = backup_before_update(&p).unwrap().unwrap();
        let r = uv.rekey(Credentials::new(PW, Some(&kf2)), P).unwrap();
        assert_eq!(r.rekeyed, 1, "{r:?}");
        assert!(matches!(read_vault_file(&copy, Credentials::new(PW, Some(&kf1))), Err(Error::Decrypt)));
        assert_eq!(names_in(&copy, Credentials::new(PW, Some(&kf2))).unwrap(), ["x"]);
        assert_eq!(fs::metadata(&copy).unwrap().mode() & 0o777, 0o600);
        // And without a key file at all: the copy no longer needs one either.
        uv.rekey(PWC, P).unwrap();
        assert_eq!(names_in(&copy, PWC).unwrap(), ["x"]);
        assert!(!read_header(&copy).unwrap().key_file);
    }

    #[test]
    fn a_copy_keeps_its_old_layout_and_schema_when_re_keyed() {
        // A version 2 copy (as cakepass 0.3 wrote it) stays version 2, so
        // that version can still open it to go back.
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        let mut uv = UnlockedVault::create(p.clone(), PWC, P).unwrap();
        add(&mut uv, "x");
        uv.save().unwrap();
        let (vault, vk) = read_vault_file(&p.file, PWC).unwrap();
        let mut json: serde_json::Value =
            serde_json::from_slice(vault.to_json().unwrap().as_slice()).unwrap();
        json["unknown_later_field"] = 7.into();
        let v2 = format::seal_as_version_for_tests(&vk, 2, json.to_string().as_bytes()).unwrap();
        let copy = p.dir().join("vault.enc.pre-update-1");
        write_atomic(&copy, &v2).unwrap();
        let r = uv.rekey(creds(b"a whole new passphrase"), P).unwrap();
        assert_eq!(r.rekeyed, 1, "{r:?}");
        assert_eq!(read_header(&copy).unwrap().version, 2);
        let (plain, key, _) =
            format::open(&fs::read(&copy).unwrap(), creds(b"a whole new passphrase")).unwrap();
        let after: serde_json::Value = serde_json::from_slice(plain.as_slice()).unwrap();
        assert_eq!(after["unknown_later_field"], 7, "nothing but the sealed fields changes");
        assert_eq!(after["schema"], json["schema"]);
        let (v, _) = Vault::from_json(plain.as_slice(), key.item_key()).unwrap();
        assert_eq!(v.get("x").unwrap().password(key.item_key()).unwrap().as_str(), "secret");
    }

    #[test]
    fn a_version_1_copy_is_re_keyed_into_the_current_layout() {
        // Version 1 used the master key itself for the file: never write it again.
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        let mut uv = UnlockedVault::create(p.clone(), PWC, P).unwrap();
        add(&mut uv, "x");
        uv.save().unwrap();
        let (vault, vk) = read_vault_file(&p.file, PWC).unwrap();
        let v1 = format::seal_as_version_for_tests(&vk, 1, vault.to_json().unwrap().as_slice()).unwrap();
        let copy = p.dir().join("vault.enc.pre-update-1");
        write_atomic(&copy, &v1).unwrap();
        assert_eq!(read_header(&copy).unwrap().version, 1);
        let r = uv.rekey(creds(b"a whole new passphrase"), P).unwrap();
        assert_eq!(r.rekeyed, 1, "{r:?}");
        assert_eq!(read_header(&copy).unwrap().version, format::CURRENT_VERSION);
        assert_eq!(names_in(&copy, creds(b"a whole new passphrase")).unwrap(), ["x"]);
    }

    #[test]
    fn a_version_2_copy_given_a_key_file_moves_to_the_current_layout() {
        // Version 2 cannot say "needs a key file": then the current layout.
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        let mut uv = UnlockedVault::create(p.clone(), PWC, P).unwrap();
        add(&mut uv, "x");
        uv.save().unwrap();
        let (vault, vk) = read_vault_file(&p.file, PWC).unwrap();
        let v2 = format::seal_as_version_for_tests(&vk, 2, vault.to_json().unwrap().as_slice()).unwrap();
        let copy = p.dir().join("vault.enc.pre-update-1");
        write_atomic(&copy, &v2).unwrap();
        let kf = KeyFilePepper::derive(b"a new key file").unwrap();
        let r = uv.rekey(Credentials::new(PW, Some(&kf)), P).unwrap();
        assert_eq!(r.rekeyed, 1, "{r:?}");
        let h = read_header(&copy).unwrap();
        assert_eq!((h.version, h.key_file), (format::CURRENT_VERSION, true));
        assert_eq!(names_in(&copy, Credentials::new(PW, Some(&kf))).unwrap(), ["x"]);
        assert!(read_vault_file(&copy, PWC).is_err(), "no longer without the key file");
    }

    #[test]
    fn read_header_without_password() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        UnlockedVault::create(p.clone(), PWC, P).unwrap();
        let h = read_header(&p.file).unwrap();
        assert_eq!(h.version, 3);
        assert_eq!(h.kdf, P);
        assert!(!h.key_file);
    }

    #[test]
    fn old_app_folder_is_moved_to_the_new_name() {
        let base = tempfile::tempdir().unwrap();
        // Nothing there yet: just the new path, nothing created.
        assert_eq!(app_dir(base.path()), base.path().join("cakepass"));
        assert!(!base.path().join("cakepass").exists());
        // Folder of the first releases: moved, contents kept.
        fs::create_dir(base.path().join("kluis")).unwrap();
        fs::write(base.path().join("kluis").join("vault.enc"), b"data").unwrap();
        let dir = app_dir(base.path());
        assert_eq!(fs::read(dir.join("vault.enc")).unwrap(), b"data");
        assert!(!base.path().join("kluis").exists());
        // A second call changes nothing; an existing new folder is never touched.
        fs::create_dir(base.path().join("kluis")).unwrap();
        assert_eq!(app_dir(base.path()), dir);
        assert!(base.path().join("kluis").exists(), "old folder left alone when the new one exists");
    }

    fn secret_of(uv: &UnlockedVault, name: &str) -> String {
        uv.vault.get(name).unwrap().password(uv.item_key()).unwrap().to_string()
    }

    #[test]
    fn a_vault_with_a_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        let kf = KeyFilePepper::derive(b"contents of the key file").unwrap();
        let other = KeyFilePepper::derive(b"another key file").unwrap();
        let both = Credentials::new(PW, Some(&kf));
        let mut uv = UnlockedVault::create(p.clone(), both, P).unwrap();
        assert!(uv.uses_key_file());
        assert!(read_header(&p.file).unwrap().key_file);
        add(&mut uv, "x");
        uv.save().unwrap();
        // The shell re-check needs the key file as well.
        assert!(matches!(uv.verify_password(PWC), Err(Error::KeyFileRequired)));
        assert!(uv.verify_password(both).unwrap());
        assert!(!uv.verify_password(Credentials::new(PW, Some(&other))).unwrap());
        drop(uv);
        assert!(matches!(UnlockedVault::open(p.clone(), PWC), Err(Error::KeyFileRequired)));
        let wrong_kf = UnlockedVault::open(p.clone(), Credentials::new(PW, Some(&other))).err().unwrap();
        let wrong_pw = UnlockedVault::open(p.clone(), Credentials::new(b"nope", Some(&kf))).err().unwrap();
        assert!(matches!((&wrong_kf, &wrong_pw), (Error::Decrypt, Error::Decrypt)));
        assert_eq!(wrong_kf.to_string(), wrong_pw.to_string(), "indistinguishable");
        let uv = UnlockedVault::open(p.clone(), both).unwrap();
        assert_eq!(secret_of(&uv, "x"), "secret");
        // The backup needs the same key file.
        assert!(matches!(read_vault_file(&p.backup, PWC), Err(Error::KeyFileRequired)));
        assert!(read_vault_file(&p.backup, both).is_ok());
    }

    #[test]
    fn rekeying_changes_level_and_key_file_but_keeps_everything_else() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        let mut uv = UnlockedVault::create(p.clone(), PWC, P).unwrap();
        add(&mut uv, "x");
        add(&mut uv, "y");
        uv.save().unwrap();
        let salt_before = read_header(&p.file).unwrap().salt;

        // 1. Another level (same password, fresh salt).
        let stronger = KdfParams { memory_kib: 16 * 1024, iterations: 2, parallelism: 2 };
        uv.rekey(PWC, stronger).unwrap();
        let h = read_header(&p.file).unwrap();
        assert_eq!(h.kdf, stronger);
        assert_ne!(h.salt, salt_before, "a fresh salt");
        assert_eq!(read_header(&p.backup).unwrap().kdf, stronger, "the backup is re-keyed too");
        drop(uv);

        // 2. Turn the key file on.
        let kf = KeyFilePepper::derive(b"usb stick key").unwrap();
        let with_kf = Credentials::new(PW, Some(&kf));
        let mut uv = UnlockedVault::open(p.clone(), PWC).unwrap();
        assert_eq!(uv.kdf(), stronger);
        uv.rekey(with_kf, stronger).unwrap();
        assert!(uv.uses_key_file());
        add(&mut uv, "z");
        uv.save().unwrap(); // the open vault keeps working with the new key
        drop(uv);
        assert!(matches!(UnlockedVault::open(p.clone(), PWC), Err(Error::KeyFileRequired)));
        let mut uv = UnlockedVault::open(p.clone(), with_kf).unwrap();
        assert_eq!(uv.vault.len(), 3);
        assert_eq!(secret_of(&uv, "x"), "secret");
        assert!(read_vault_file(&p.backup, with_kf).is_ok());

        // 3. Rotate to another key file: the old one opens nothing any more.
        let kf2 = KeyFilePepper::derive(b"second stick").unwrap();
        let with_kf2 = Credentials::new(PW, Some(&kf2));
        uv.rekey(with_kf2, stronger).unwrap();
        drop(uv);
        assert!(matches!(UnlockedVault::open(p.clone(), with_kf), Err(Error::Decrypt)));
        assert!(matches!(read_vault_file(&p.backup, with_kf), Err(Error::Decrypt)));

        // 4. Turn it off again and go back to a level.
        let mut uv = UnlockedVault::open(p.clone(), with_kf2).unwrap();
        uv.rekey(PWC, P).unwrap();
        assert!(!uv.uses_key_file());
        drop(uv);
        let uv = UnlockedVault::open(p.clone(), PWC).unwrap();
        assert_eq!((uv.vault.len(), uv.kdf()), (3, P));
        assert_eq!(secret_of(&uv, "z"), "secret");
        assert!(!read_header(&p.file).unwrap().key_file);
    }

    #[test]
    fn a_failed_rekey_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        let mut uv = UnlockedVault::create(p.clone(), PWC, P).unwrap();
        add(&mut uv, "x");
        uv.save().unwrap();
        let before = fs::read(&p.file).unwrap();
        let bad = KdfParams { memory_kib: 1024, ..P };
        assert!(matches!(uv.rekey(PWC, bad), Err(Error::InvalidKdfParams(_))));
        // Another process changed the file: refused, nothing written.
        let mut other = UnlockedVault::open(p.clone(), PWC).unwrap();
        add(&mut other, "elsewhere");
        other.save().unwrap();
        let changed = fs::read(&p.file).unwrap();
        assert_ne!(changed, before);
        assert!(matches!(uv.rekey(creds(b"new password"), P), Err(Error::ConcurrentModification)));
        assert_eq!(fs::read(&p.file).unwrap(), changed);
        assert!(UnlockedVault::open(p.clone(), PWC).is_ok(), "the old password still opens it");
        assert_eq!(secret_of(&uv, "x"), "secret", "the open vault still works with its key");
    }

    #[test]
    fn version_2_is_read_as_is_and_becomes_version_3_on_the_next_save() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        ensure_dir(p.dir()).unwrap();
        // A real version 2 vault with one item, as cakepass 0.3 wrote it.
        let vk = VaultKey::create(PWC, P).unwrap();
        let mut v = Vault::new();
        let e = Entry::new(
            NewEntry { name: "old".into(), password: "v2-secret".into(), ..Default::default() },
            vk.item_key(),
        )
        .unwrap();
        v.add(e).unwrap();
        let v2 = format::seal_as_version_for_tests(&vk, 2, v.to_json().unwrap().as_slice()).unwrap();
        write_atomic(&p.file, &v2).unwrap();

        // Opening (read-only use) does not rewrite the file.
        let mut uv = UnlockedVault::open(p.clone(), PWC).unwrap();
        assert!(uv.take_warnings().iter().all(|w| !w.contains("newest format")), "no forced rewrite");
        assert_eq!(fs::read(&p.file).unwrap(), v2);
        assert_eq!(secret_of(&uv, "old"), "v2-secret");
        // The next save writes version 3; the backup keeps the version 2 file.
        add(&mut uv, "new");
        uv.save().unwrap();
        drop(uv);
        assert_eq!(read_header(&p.file).unwrap().version, 3);
        assert_eq!(fs::read(&p.backup).unwrap(), v2);
        let uv = UnlockedVault::open(p.clone(), PWC).unwrap();
        assert_eq!(secret_of(&uv, "old"), "v2-secret", "the items were not touched");
        assert_eq!(secret_of(&uv, "new"), "secret");
        assert!(read_vault_file(&p.backup, PWC).is_ok());
    }

    #[test]
    fn a_schema_4_vault_of_cakepass_0_4_is_upgraded_to_schema_5() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        ensure_dir(p.dir()).unwrap();
        // Format 3 with content schema 4, exactly as cakepass 0.4.0 wrote it
        // (no card, TOTP or SSH key fields yet).
        let vk = VaultKey::create(PWC, P).unwrap();
        let s = |f: &str, v: &str| vk.item_key().seal(f, v).unwrap();
        let json = format!(
            r#"{{"schema":4,"entries":[{{"name":"Mail","kind":"login","username_sealed":"{}","email_sealed":"{}","url_sealed":"{}","password_sealed":"{}","notes_sealed":"{}","tags":["home"],"created":3,"modified":4}}]}}"#,
            s("username", "me"),
            s("email", "me@mail.example"),
            s("url", "https://mail.example"),
            s("password", "schema-4-secret"),
            s("notes", ""),
        );
        let old = format::seal_as_version_for_tests(&vk, 3, json.as_bytes()).unwrap();
        write_atomic(&p.file, &old).unwrap();

        // Opening converts the content and saves it right away; the .bak
        // keeps the schema 4 file.
        let mut uv = UnlockedVault::open(p.clone(), PWC).unwrap();
        assert!(uv.take_warnings().iter().any(|w| w.contains("newest format")));
        assert_eq!(secret_of(&uv, "mail"), "schema-4-secret");
        assert_ne!(fs::read(&p.file).unwrap(), old);
        assert_eq!(fs::read(&p.backup).unwrap(), old);
        // The new fields can be used and are saved.
        let (vault, key) = uv.parts_mut();
        vault.update("mail", |e| e.set_totp_secret(key, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")).unwrap();
        uv.save().unwrap();
        drop(uv);
        let mut uv = UnlockedVault::open(p, PWC).unwrap();
        assert!(!uv.take_warnings().iter().any(|w| w.contains("newest format")), "migrate only once");
        let e = uv.vault.get("mail").unwrap();
        let k = uv.item_key();
        assert_eq!(e.username(k).unwrap().as_str(), "me");
        assert_eq!(e.email(k).unwrap().as_str(), "me@mail.example");
        assert_eq!(e.url(k).unwrap().as_str(), "https://mail.example");
        assert_eq!((e.tags(), e.created(), e.modified() > 4), (&["home".to_string()][..], 3, true));
        assert_eq!(e.totp(k).unwrap().unwrap().code_at(59).as_str(), "287082");
        assert!(e.cvv(k).unwrap().is_empty() && e.public_key(k).unwrap().is_empty());
    }

    #[test]
    fn export_files_are_never_lighter_than_standard() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        let uv = UnlockedVault::create(p, PWC, P).unwrap();
        assert_eq!(uv.export_params(), KdfParams::STANDARD);
        assert_eq!(uv.security_level(), None);
        let strong = KdfParams { memory_kib: 96 * 1024, ..KdfParams::STANDARD };
        let dir2 = tempfile::tempdir().unwrap();
        let uv = UnlockedVault::create(paths(&dir2), PWC, strong).unwrap();
        assert_eq!(uv.export_params(), strong, "a stronger vault exports as strongly");
    }
}
