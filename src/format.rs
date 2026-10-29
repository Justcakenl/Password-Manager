//! The encrypted file format (version 2; version 1 stays readable).
//!
//! SECURITY-CRITICAL. Layout (all numbers little-endian):
//!
//! ```text
//! offset  size     field
//! 0       8        magic "KLUISVLT"   (legacy name; "kluis" is Dutch for "vault")
//! 8       2        format version (u16) = 2
//! 10      1        KDF id: 1 = Argon2id v1.3
//! 11      4        Argon2 memory in KiB (u32)
//! 15      4        Argon2 iterations (u32)
//! 19      4        Argon2 parallelism (u32)
//! 23      1        salt length n (16..=64)
//! 24      n        salt
//! 24+n    1        AEAD id: 1 = XChaCha20-Poly1305
//! 25+n    24       nonce
//! 49+n    rest     ciphertext || 16-byte Poly1305 tag
//! ```
//!
//! The complete header (everything before the ciphertext) is the AEAD's
//! "associated data". Anyone who changes even a single bit in the header
//! (for example lowering the Argon2 parameters) makes authentication fail.
//!
//! Keys (from version 2):
//!
//! ```text
//! master password ──Argon2id(salt)──► master key
//!     master key ──HKDF-SHA256("…file…")──► file key   (the whole vault)
//!     master key ──HKDF-SHA256("…item…")──► item key   (every field of every
//!                                                       item, separately)
//! ```
//!
//! In version 1 the master key encrypted the file directly and passwords
//! were plain text inside that encryption. Such a file is converted to
//! version 2 automatically when it is opened.
//!
//! Migrations: a new version gets its own `decode_vN`; old versions stay
//! readable and are written in the newest version on the next save.

use crate::crypto::{self, ItemKey, KdfParams, MasterKey, NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::secure_mem::SecureBuf;

pub const MAGIC: [u8; 8] = *b"KLUISVLT";
pub const CURRENT_VERSION: u16 = 2;
// Fixed protocol labels (Dutch text from the first release). Never change
// them: existing vaults would no longer open.
const FILE_KEY_INFO: &[u8] = b"kluis v2: bestandssleutel";
const ITEM_KEY_INFO: &[u8] = b"kluis v2: itemsleutel";
const KDF_ARGON2ID_V13: u8 = 1;
const AEAD_XCHACHA20_POLY1305: u8 = 1;
const MIN_SALT_LEN: usize = 16;
const MAX_SALT_LEN: usize = 64;
/// We refuse larger files (protection against memory DoS).
pub const MAX_FILE_SIZE: usize = 64 * 1024 * 1024;

/// The unencrypted header of a vault file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u16,
    pub kdf: KdfParams,
    pub salt: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    /// Write the header in the current format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(49 + self.salt.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(KDF_ARGON2ID_V13);
        out.extend_from_slice(&self.kdf.memory_kib.to_le_bytes());
        out.extend_from_slice(&self.kdf.iterations.to_le_bytes());
        out.extend_from_slice(&self.kdf.parallelism.to_le_bytes());
        out.push(u8::try_from(self.salt.len()).expect("salt is short"));
        out.extend_from_slice(&self.salt);
        out.push(AEAD_XCHACHA20_POLY1305);
        out.extend_from_slice(&self.nonce);
        out
    }

    /// Read a header. Returns the header and the number of header bytes.
    ///
    /// All fields are checked before any expensive Argon2 computation
    /// happens, so a broken or malicious file fails cleanly.
    pub fn decode(data: &[u8]) -> Result<(Header, usize)> {
        if data.len() > MAX_FILE_SIZE {
            return Err(Error::TooLarge);
        }
        let mut r = Reader { data, pos: 0 };
        if r.take(MAGIC.len())? != MAGIC {
            return Err(Error::NotAVault);
        }
        let version = r.u16()?;
        match version {
            // Versions 1 and 2 share the same header layout; only the key
            // usage differs (see the documentation at the top).
            1 | 2 => decode_v1_v2(&mut r, version),
            other => Err(Error::UnsupportedVersion(other)),
        }
    }
}

fn decode_v1_v2(r: &mut Reader<'_>, version: u16) -> Result<(Header, usize)> {
    if r.u8()? != KDF_ARGON2ID_V13 {
        return Err(Error::UnsupportedAlgorithm);
    }
    let kdf = KdfParams { memory_kib: r.u32()?, iterations: r.u32()?, parallelism: r.u32()? };
    kdf.validate()?;
    let salt_len = usize::from(r.u8()?);
    if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt_len) {
        return Err(Error::NotAVault);
    }
    let salt = r.take(salt_len)?.to_vec();
    if r.u8()? != AEAD_XCHACHA20_POLY1305 {
        return Err(Error::UnsupportedAlgorithm);
    }
    let nonce: [u8; NONCE_LEN] = r.take(NONCE_LEN)?.try_into().expect("length matches");
    Ok((Header { version, kdf, salt, nonce }, r.pos))
}

/// Small, bounds-checking reader.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let slice = self.data.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("2 bytes")))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }
}

/// An unlocked key plus the parameters it was created with.
///
/// This lets the vault be saved again without asking for the master password
/// once more. All keys are wiped on `Drop`.
#[derive(Debug)]
pub struct VaultKey {
    master: MasterKey,
    file_key: MasterKey,
    item_key: ItemKey,
    kdf: KdfParams,
    salt: Vec<u8>,
}

impl VaultKey {
    fn from_master(master: MasterKey, kdf: KdfParams, salt: Vec<u8>) -> VaultKey {
        let file_key = master.derive_subkey(FILE_KEY_INFO);
        let item_key = ItemKey::new(master.derive_subkey(ITEM_KEY_INFO));
        VaultKey { master, file_key, item_key, kdf, salt }
    }

    /// Derive a new key with a new, random salt.
    pub fn create(password: &[u8], kdf: KdfParams) -> Result<VaultKey> {
        let salt = crypto::random_array::<SALT_LEN>()?.to_vec();
        let master = crypto::derive_key(password, &salt, &kdf)?;
        Ok(VaultKey::from_master(master, kdf, salt))
    }

    pub fn kdf(&self) -> KdfParams {
        self.kdf
    }

    /// The key for the separately encrypted passwords and notes.
    pub fn item_key(&self) -> &ItemKey {
        &self.item_key
    }

    /// Check whether `password` yields the same key (constant time).
    pub fn verify(&self, password: &[u8]) -> Result<bool> {
        let candidate = crypto::derive_key(password, &self.salt, &self.kdf)?;
        Ok(candidate.ct_eq(&self.master))
    }
}

/// Encrypt `plaintext` into a complete vault file (always the newest
/// version). Every call uses a new, random nonce.
pub fn seal(vk: &VaultKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let header = Header {
        version: CURRENT_VERSION,
        kdf: vk.kdf,
        salt: vk.salt.clone(),
        nonce: crypto::random_array::<NONCE_LEN>()?,
    };
    let mut out = header.encode();
    let ct = crypto::encrypt(&vk.file_key, &header.nonce, &out, plaintext)?;
    out.extend_from_slice(&ct);
    if out.len() > MAX_FILE_SIZE {
        return Err(Error::TooLarge);
    }
    Ok(out)
}

/// Decrypt a vault file with the master password.
/// Also returns the format version of the file (for migration).
pub fn open(data: &[u8], password: &[u8]) -> Result<(SecureBuf, VaultKey, u16)> {
    let (header, header_len) = Header::decode(data)?;
    let ciphertext = &data[header_len..];
    if ciphertext.len() < TAG_LEN {
        return Err(Error::Truncated);
    }
    let master = crypto::derive_key(password, &header.salt, &header.kdf)?;
    let vk = VaultKey::from_master(master, header.kdf, header.salt);
    let plaintext = {
        // Version 1 used the master key directly for the file.
        let v1_key;
        let file_key = if header.version == 1 {
            v1_key = vk.master.duplicate();
            &v1_key
        } else {
            &vk.file_key
        };
        crypto::decrypt(file_key, &header.nonce, &data[..header_len], ciphertext)?
    };
    Ok((plaintext, vk, header.version))
}

/// Create a file in the old format (version 1), for migration tests only.
#[doc(hidden)]
pub fn seal_v1_for_tests(password: &[u8], kdf: KdfParams, plaintext: &[u8]) -> Result<Vec<u8>> {
    let salt = crypto::random_array::<SALT_LEN>()?.to_vec();
    let master = crypto::derive_key(password, &salt, &kdf)?;
    let header = Header { version: 1, kdf, salt, nonce: crypto::random_array::<NONCE_LEN>()? };
    let mut out = header.encode();
    let ct = crypto::encrypt(&master, &header.nonce, &out, plaintext)?;
    out.extend_from_slice(&ct);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: KdfParams = KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 };

    fn sample() -> (Vec<u8>, &'static [u8]) {
        let vk = VaultKey::create(b"correct password", P).unwrap();
        (seal(&vk, b"{\"content\":1}").unwrap(), b"correct password")
    }

    #[test]
    fn header_round_trip() {
        let h = Header { version: 2, kdf: KdfParams::DEFAULT, salt: vec![9; 32], nonce: [5; 24] };
        let bytes = h.encode();
        assert_eq!(bytes.len(), 49 + 32);
        let (back, len) = Header::decode(&bytes).unwrap();
        assert_eq!(back, h);
        assert_eq!(len, bytes.len());
    }

    #[test]
    fn save_and_open() {
        let (file, pw) = sample();
        let (pt, vk, version) = open(&file, pw).unwrap();
        assert_eq!(version, CURRENT_VERSION);
        assert_eq!(pt.as_slice(), b"{\"content\":1}");
        assert_eq!(vk.kdf(), P);
        // Saving again with the same key uses a new nonce.
        let again = seal(&vk, pt.as_slice()).unwrap();
        assert_ne!(again, file);
        assert_eq!(open(&again, pw).unwrap().0.as_slice(), pt.as_slice());
    }

    #[test]
    fn wrong_password_always_fails() {
        let (file, _) = sample();
        for pw in [&b"wrong"[..], b"", b"correct password ", b"Correct password"] {
            assert!(matches!(open(&file, pw), Err(Error::Decrypt)));
        }
    }

    #[test]
    fn every_bit_flip_in_the_file_fails() {
        let (file, pw) = sample();
        for i in 0..file.len() {
            let mut bad = file.clone();
            bad[i] ^= 0x01;
            assert!(open(&bad, pw).is_err(), "bit flip at byte {i} went unnoticed");
        }
    }

    #[test]
    fn broken_files_give_clean_errors() {
        let (file, pw) = sample();
        assert!(matches!(open(b"", pw), Err(Error::Truncated)));
        assert!(matches!(open(b"KLUIS", pw), Err(Error::Truncated)));
        assert!(matches!(open(b"not a vault but text that is long enough", pw), Err(Error::NotAVault)));
        // Every truncated length fails.
        for len in 0..file.len() {
            assert!(open(&file[..len], pw).is_err(), "truncation at {len} was accepted");
        }
        // Extra bytes at the end fail too (the tag no longer matches).
        let mut longer = file.clone();
        longer.push(0);
        assert!(matches!(open(&longer, pw), Err(Error::Decrypt)));
    }

    #[test]
    fn unknown_version_and_algorithm() {
        let (file, pw) = sample();
        let mut v = file.clone();
        v[8] = 3;
        assert!(matches!(open(&v, pw), Err(Error::UnsupportedVersion(3))));
        let mut k = file.clone();
        k[10] = 9;
        assert!(matches!(open(&k, pw), Err(Error::UnsupportedAlgorithm)));
        let mut a = file.clone();
        a[24 + 32] = 9;
        assert!(matches!(open(&a, pw), Err(Error::UnsupportedAlgorithm)));
    }

    #[test]
    fn tampered_kdf_parameters_are_rejected_or_fail() {
        let (file, pw) = sample();
        // Lowering memory to 1 MiB: rejected before Argon2 runs.
        let mut low = file.clone();
        low[11..15].copy_from_slice(&1024u32.to_le_bytes());
        assert!(matches!(open(&low, pw), Err(Error::InvalidKdfParams(_))));
        // Absurd amounts of memory: rejected (no DoS).
        let mut huge = file.clone();
        huge[11..15].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(open(&huge, pw), Err(Error::InvalidKdfParams(_))));
        // A valid but different value: different key, so authentication fails.
        let mut other = file.clone();
        other[15..19].copy_from_slice(&2u32.to_le_bytes());
        assert!(matches!(open(&other, pw), Err(Error::Decrypt)));
    }

    #[test]
    fn file_too_large() {
        let big = vec![0u8; MAX_FILE_SIZE + 1];
        assert!(matches!(Header::decode(&big), Err(Error::TooLarge)));
    }

    #[test]
    fn old_format_version_1_stays_readable() {
        let old = seal_v1_for_tests(b"pw", P, b"old content").unwrap();
        assert_eq!(u16::from_le_bytes([old[8], old[9]]), 1);
        let (pt, vk, version) = open(&old, b"pw").unwrap();
        assert_eq!(version, 1);
        assert_eq!(pt.as_slice(), b"old content");
        assert!(matches!(open(&old, b"wrong"), Err(Error::Decrypt)));
        // Saving again happens in version 2, with the file subkey.
        let new = seal(&vk, pt.as_slice()).unwrap();
        assert_eq!(u16::from_le_bytes([new[8], new[9]]), 2);
        assert_eq!(open(&new, b"pw").unwrap().0.as_slice(), b"old content");
        // A v2 file presented as v1 fails (different key and header).
        let mut fake = new.clone();
        fake[8] = 1;
        assert!(matches!(open(&fake, b"pw"), Err(Error::Decrypt)));
    }

    #[test]
    fn password_check() {
        let vk = VaultKey::create(b"right", P).unwrap();
        assert!(vk.verify(b"right").unwrap());
        assert!(!vk.verify(b"wrong").unwrap());
    }

    #[test]
    fn different_vaults_get_different_salts() {
        let a = VaultKey::create(b"x", P).unwrap();
        let b = VaultKey::create(b"x", P).unwrap();
        assert_ne!(a.salt, b.salt);
    }
}
