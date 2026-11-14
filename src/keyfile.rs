//! Key files: an optional second secret next to the master password
//! ("two-factor at rest").
//!
//! A vault can require a key file: any file (recommended: 64 random bytes
//! made by [`create`], kept on a USB stick). Its contents are condensed into
//! a 32-byte pepper ([`KeyFilePepper`]) that Argon2id mixes into the key. A
//! stolen vault file is then useless without the key file, even when the
//! master password is weak or known.
//!
//! SECURITY-CRITICAL.
//! - Only the *path* of a key file is ever stored (in the settings file).
//!   Its contents are read when they are needed, condensed into the pepper,
//!   and wiped; the pepper is wiped as soon as Argon2 has run. Nothing here
//!   ever copies the file or logs its contents.
//! - Reading refuses symbolic links (`O_NOFOLLOW`) and anything that is not
//!   a regular file; `O_NONBLOCK` makes sure a FIFO or a device at that path
//!   cannot hang the program. A key file has 1 byte to 1 MiB.
//! - A key file that other users may read or change gives a warning, not an
//!   error: on a FAT/exFAT USB stick the permissions cannot be changed.
//! - [`create`] never overwrites anything (`O_CREAT | O_EXCL`, also refusing
//!   a dangling symbolic link), writes with mode 0600 and syncs to disk.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use zeroize::Zeroizing;

use crate::crypto::{self, KeyFilePepper};
use crate::error::{Error, Result};
use crate::secure_mem::SecureBuf;

/// The largest key file we accept.
pub const MAX_KEY_FILE_SIZE: u64 = 1024 * 1024;
/// The size of a key file made by [`create`].
pub const NEW_KEY_FILE_LEN: usize = 64;
/// Below this size a key file adds little; it gets a warning.
pub const SMALL_KEY_FILE: u64 = 32;

/// A key file that was read: its pepper, plus warnings for the user.
#[derive(Debug)]
pub struct LoadedKeyFile {
    pub pepper: KeyFilePepper,
    pub warnings: Vec<String>,
}

/// The error for a key file that could not be opened.
fn open_error(path: &Path, e: io::Error) -> Error {
    let reason = match e.kind() {
        io::ErrorKind::NotFound => {
            "it does not exist. Is the USB stick (or disk) with the key file plugged in and mounted?".into()
        }
        io::ErrorKind::PermissionDenied => "permission denied".into(),
        io::ErrorKind::NotADirectory => "a part of the path is not a folder".into(),
        _ if e.raw_os_error() == Some(libc::ELOOP) => {
            return Error::KeyFileInvalid(format!(
                "{} is a symbolic link; give the real path of the key file",
                path.display()
            ));
        }
        _ => e.to_string(),
    };
    Error::KeyFileUnreadable { path: path.to_path_buf(), reason }
}

/// A warning when others can read or change the file (`mode` from stat).
fn permission_warning(path: &Path, mode: u32) -> Option<String> {
    (mode & 0o077 != 0).then(|| {
        format!(
            "The key file {} can be read or changed by other users of this computer (permissions {:o}). \
             Make it private with `chmod 600`; on a FAT/exFAT USB stick that is not possible, so keep \
             the stick itself safe.",
            path.display(),
            mode & 0o777
        )
    })
}

/// Read a key file and derive its pepper.
pub fn load(path: &Path) -> Result<LoadedKeyFile> {
    let unreadable =
        |e: io::Error| Error::KeyFileUnreadable { path: path.to_path_buf(), reason: e.to_string() };
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| open_error(path, e))?;
    let meta = f.metadata().map_err(unreadable)?;
    if !meta.is_file() {
        return Err(Error::KeyFileInvalid(format!("{} is not a regular file", path.display())));
    }
    if meta.len() > MAX_KEY_FILE_SIZE {
        return Err(Error::KeyFileInvalid(format!(
            "{} is larger than 1 MiB ({} bytes); a key file must be at most 1 MiB",
            path.display(),
            meta.len()
        )));
    }
    if meta.len() == 0 {
        return Err(Error::KeyFileInvalid(format!("{} is empty", path.display())));
    }
    // Read straight into locked memory that is wiped on drop (no copies).
    let mut contents = SecureBuf::zeroed(meta.len() as usize);
    f.read_exact(contents.as_mut_slice()).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => {
            Error::KeyFileInvalid(format!("{} changed while it was being read", path.display()))
        }
        _ => unreadable(e),
    })?;
    let mut more = [0u8; 1];
    if f.read(&mut more).map_err(unreadable)? != 0 {
        return Err(Error::KeyFileInvalid(format!("{} changed while it was being read", path.display())));
    }
    let pepper = KeyFilePepper::derive(contents.as_slice())?;
    drop(contents);

    let mut warnings = Vec::new();
    warnings.extend(permission_warning(path, meta.mode()));
    if meta.len() < SMALL_KEY_FILE {
        warnings.push(format!(
            "The key file {} has only {} bytes, which adds little protection. A key file made by \
             `cakepass keyfile create` has 64 random bytes.",
            path.display(),
            meta.len()
        ));
    }
    Ok(LoadedKeyFile { pepper, warnings })
}

/// Create a new key file with 64 random bytes (never overwrites anything).
/// Returns warnings (e.g. a drive that does not keep file permissions).
pub fn create(path: &Path) -> Result<Vec<String>> {
    let mut bytes = Zeroizing::new([0u8; NEW_KEY_FILE_LEN]);
    crypto::fill_random(bytes.as_mut_slice())?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => Error::AlreadyExists(path.to_path_buf()),
            io::ErrorKind::NotFound => Error::InvalidInput(format!(
                "the folder {} does not exist",
                path.parent().unwrap_or(Path::new(".")).display()
            )),
            _ => Error::Io(e),
        })?;
    let written = f.write_all(bytes.as_slice()).and_then(|()| f.sync_all());
    if let Err(e) = written {
        drop(f);
        let _ = fs::remove_file(path);
        return Err(e.into());
    }
    let mode = f.metadata()?.mode();
    drop(f);
    // Make the new directory entry durable too (best effort: e.g. FAT).
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        let _ = File::open(dir).and_then(|d| d.sync_all());
    }
    Ok(permission_warning(path, mode).into_iter().collect())
}

/// Whether two paths are the same file (same device and inode).
pub fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(x), Ok(y)) => x.dev() == y.dev() && x.ino() == y.ino(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_with_mode(path: &Path, data: &[u8], mode: u32) {
        fs::write(path, data).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn a_created_key_file_is_random_private_and_loads() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.key");
        let b = dir.path().join("b.key");
        assert!(create(&a).unwrap().is_empty(), "no warnings on a normal file system");
        create(&b).unwrap();
        let bytes = fs::read(&a).unwrap();
        assert_eq!(bytes.len(), NEW_KEY_FILE_LEN);
        assert_ne!(bytes, fs::read(&b).unwrap(), "random");
        assert_eq!(fs::metadata(&a).unwrap().mode() & 0o777, 0o600);
        let loaded = load(&a).unwrap();
        assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
        assert!(loaded.pepper.ct_eq(&KeyFilePepper::derive(&bytes).unwrap()));
        assert!(!loaded.pepper.ct_eq(&load(&b).unwrap().pepper));
    }

    #[test]
    fn create_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        fs::write(&p, b"precious").unwrap();
        assert!(matches!(create(&p), Err(Error::AlreadyExists(_))));
        assert_eq!(fs::read(&p).unwrap(), b"precious");
        // Not through a (dangling) symbolic link either.
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(create(&link).is_err());
        assert!(!target.exists(), "nothing was created through the link");
        // A folder that does not exist.
        let e = create(&dir.path().join("nope").join("k")).unwrap_err();
        assert!(e.to_string().contains("does not exist"), "{e}");
    }

    #[test]
    fn symlinks_folders_fifos_and_devices_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.key");
        write_with_mode(&real, &[9u8; 64], 0o600);
        let link = dir.path().join("link.key");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let e = load(&link).unwrap_err();
        assert!(matches!(&e, Error::KeyFileInvalid(m) if m.contains("symbolic link")), "{e}");
        let e = load(dir.path()).unwrap_err();
        assert!(matches!(&e, Error::KeyFileInvalid(m) if m.contains("not a regular file")), "{e}");
        // A FIFO must not hang the program (O_NONBLOCK) and is refused.
        let fifo = dir.path().join("fifo");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid, NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(matches!(load(&fifo), Err(Error::KeyFileInvalid(_))));
        assert!(matches!(load(Path::new("/dev/null")), Err(Error::KeyFileInvalid(_))));
    }

    #[test]
    fn size_limits() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        write_with_mode(&p, b"", 0o600);
        let e = load(&p).unwrap_err();
        assert!(matches!(&e, Error::KeyFileInvalid(m) if m.contains("empty")), "{e}");
        write_with_mode(&p, &vec![1u8; MAX_KEY_FILE_SIZE as usize + 1], 0o600);
        let e = load(&p).unwrap_err();
        assert!(matches!(&e, Error::KeyFileInvalid(m) if m.contains("larger than 1 MiB")), "{e}");
        write_with_mode(&p, &vec![1u8; MAX_KEY_FILE_SIZE as usize], 0o600);
        assert!(load(&p).unwrap().warnings.is_empty(), "exactly 1 MiB is fine");
        // Any content works, e.g. a photo; a tiny file gets a warning.
        write_with_mode(&p, b"tiny", 0o600);
        let w = load(&p).unwrap().warnings;
        assert!(w.len() == 1 && w[0].contains("only 4 bytes"), "{w:?}");
    }

    #[test]
    fn missing_file_names_the_path_and_the_likely_cause() {
        let e = load(Path::new("/run/media/nobody/USB/cakepass.key")).unwrap_err();
        let text = e.to_string();
        assert!(matches!(e, Error::KeyFileUnreadable { .. }));
        assert!(text.contains("/run/media/nobody/USB/cakepass.key") && text.contains("plugged in"), "{text}");
    }

    #[test]
    fn readable_by_others_gives_a_warning_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        write_with_mode(&p, &[5u8; 64], 0o644);
        let loaded = load(&p).unwrap();
        assert_eq!(loaded.warnings.len(), 1);
        assert!(loaded.warnings[0].contains("644") && loaded.warnings[0].contains("chmod 600"));
        fs::set_permissions(&p, fs::Permissions::from_mode(0o620)).unwrap();
        assert_eq!(load(&p).unwrap().warnings.len(), 1, "writable by the group: also a warning");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(load(&p).unwrap().warnings.is_empty());
    }

    #[test]
    fn same_file_compares_inodes() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        fs::write(&a, b"x").unwrap();
        fs::write(&b, b"x").unwrap();
        assert!(same_file(&a, &a));
        assert!(same_file(&a, &dir.path().join(".").join("a")));
        assert!(!same_file(&a, &b), "same content, different file");
        assert!(!same_file(&a, &dir.path().join("missing")));
    }
}
