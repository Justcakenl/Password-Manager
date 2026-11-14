//! The encrypted file format (version 3; versions 1 and 2 stay readable).
//!
//! SECURITY-CRITICAL. Layout of version 3 (all numbers little-endian):
//!
//! ```text
//! offset  size     field
//! 0       8        magic "KLUISVLT"   (legacy name; "kluis" is Dutch for "vault")
//! 8       2        format version (u16) = 3
//! 10      1        flags: bit 0 = a key file is required; bits 1-7 must be 0
//! 11      1        KDF id: 1 = Argon2id v1.3
//! 12      4        Argon2 memory in KiB (u32)
//! 16      4        Argon2 iterations (u32)
//! 20      4        Argon2 parallelism (u32)
//! 24      1        salt length n (16..=64)
//! 25      n        salt
//! 25+n    1        AEAD id: 1 = XChaCha20-Poly1305
//! 26+n    24       nonce
//! 50+n    rest     ciphertext || 16-byte Poly1305 tag
//! ```
//!
//! Versions 1 and 2 have the same layout without the flags byte (the KDF id
//! is at offset 10, the ciphertext starts at 49+n).
//!
//! The complete header (everything before the ciphertext, including the
//! flags) is the AEAD's "associated data". Anyone who changes even a single
//! bit in the header (for example lowering the Argon2 parameters, or
//! clearing the key-file flag) makes authentication fail. Unknown flag bits
//! are refused before any work is done, so a future feature can never be
//! silently ignored by this version.
//!
//! Keys (from version 2; version 3 adds the optional key file):
//!
//! ```text
//! master password ──Argon2id(salt, secret K = key-file pepper if flag bit 0)──► master key
//!     master key ──HKDF-SHA256("kluis v2: bestandssleutel")──► file key   (the whole vault)
//!     master key ──HKDF-SHA256("kluis v2: itemsleutel")──────► item key   (every field of
//!                                                                         every item, separately)
//! ```
//!
//! Version 3 keeps the HKDF labels of version 2 on purpose: the labels say
//! what a key is *for*, and that did not change. A version 2 vault therefore
//! becomes a version 3 vault on its next save without touching its items
//! (same password, same salt, no key file: same master key). Older versions
//! of cakepass cannot open version 3 files; they refuse them cleanly
//! ("file version 3 is not supported").
//!
//! In version 1 the master key encrypted the file directly and passwords
//! were plain text inside that encryption. Such a file is converted to the
//! newest version automatically when it is opened.
//!
//! Migrations: a new version gets its own decoding; old versions stay
//! readable and are written in the newest version on the next save.

use crate::crypto::{
    self, ItemKey, KdfParams, KeyFilePepper, MasterKey, MemoryUse, NONCE_LEN, SALT_LEN, TAG_LEN,
};
use crate::error::{Error, Result};
use crate::secure_mem::SecureBuf;

pub const MAGIC: [u8; 8] = *b"KLUISVLT";
pub const CURRENT_VERSION: u16 = 3;
// Fixed protocol labels (Dutch text from the first release). Never change
// them: existing vaults would no longer open.
const FILE_KEY_INFO: &[u8] = b"kluis v2: bestandssleutel";
const ITEM_KEY_INFO: &[u8] = b"kluis v2: itemsleutel";
const KDF_ARGON2ID_V13: u8 = 1;
const AEAD_XCHACHA20_POLY1305: u8 = 1;
/// Flag bit (version 3): the vault requires a key file.
const FLAG_KEY_FILE: u8 = 0x01;
/// All flag bits this version understands.
const KNOWN_FLAGS: u8 = FLAG_KEY_FILE;
const MIN_SALT_LEN: usize = 16;
const MAX_SALT_LEN: usize = 64;
/// We refuse larger files (protection against memory DoS).
pub const MAX_FILE_SIZE: usize = 64 * 1024 * 1024;

/// What unlocks a vault: the master password and, for a vault that
/// requires one, the pepper of its key file.
#[derive(Clone, Copy)]
pub struct Credentials<'a> {
    pub password: &'a [u8],
    pub key_file: Option<&'a KeyFilePepper>,
}

impl<'a> Credentials<'a> {
    pub fn new(password: &'a [u8], key_file: Option<&'a KeyFilePepper>) -> Credentials<'a> {
        Credentials { password, key_file }
    }

    /// Only a password (vaults without a key file, export files).
    pub fn password(password: &'a [u8]) -> Credentials<'a> {
        Credentials { password, key_file: None }
    }
}

impl std::fmt::Debug for Credentials<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials([HIDDEN])")
    }
}

/// The unencrypted header of a vault file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u16,
    /// The vault requires a key file (flag bit 0; always false before version 3).
    pub key_file: bool,
    pub kdf: KdfParams,
    pub salt: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    /// Write the header in the layout of its version.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(50 + self.salt.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        if self.version >= 3 {
            out.push(if self.key_file { FLAG_KEY_FILE } else { 0 });
        } else {
            assert!(!self.key_file, "versions 1 and 2 cannot record a key file");
        }
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
            1 | 2 => decode_body(&mut r, version, false),
            3 => {
                let flags = r.u8()?;
                if flags & !KNOWN_FLAGS != 0 {
                    return Err(Error::UnsupportedFeature);
                }
                decode_body(&mut r, version, flags & FLAG_KEY_FILE != 0)
            }
            other => Err(Error::UnsupportedVersion(other)),
        }
    }
}

/// Everything after the version (and flags): KDF, salt, AEAD, nonce.
fn decode_body(r: &mut Reader<'_>, version: u16, key_file: bool) -> Result<(Header, usize)> {
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
    Ok((Header { version, key_file, kdf, salt, nonce }, r.pos))
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

/// The pepper to give Argon2: required (and used) only when the vault says so.
fn secret_for<'a>(required: bool, creds: &Credentials<'a>) -> Result<Option<&'a KeyFilePepper>> {
    if required { creds.key_file.map(Some).ok_or(Error::KeyFileRequired) } else { Ok(None) }
}

/// An unlocked key plus the parameters it was created with.
///
/// This lets the vault be saved again without asking for the master password
/// once more. All keys are wiped on `Drop`. Neither the password nor the
/// key-file pepper is kept.
#[derive(Debug)]
pub struct VaultKey {
    master: MasterKey,
    file_key: MasterKey,
    item_key: ItemKey,
    kdf: KdfParams,
    salt: Vec<u8>,
    key_file: bool,
}

impl VaultKey {
    fn from_master(master: MasterKey, kdf: KdfParams, salt: Vec<u8>, key_file: bool) -> VaultKey {
        let file_key = master.derive_subkey(FILE_KEY_INFO);
        let item_key = ItemKey::new(master.derive_subkey(ITEM_KEY_INFO));
        VaultKey { master, file_key, item_key, kdf, salt, key_file }
    }

    /// Derive a new key with a new, random salt. With a key-file pepper in
    /// `creds`, the vault will require that key file.
    ///
    /// Refuses parameters this computer cannot spare the memory for.
    pub fn create(creds: Credentials<'_>, kdf: KdfParams) -> Result<VaultKey> {
        kdf.validate()?;
        crypto::ensure_memory(&kdf, MemoryUse::Create)?;
        let salt = crypto::random_array::<SALT_LEN>()?.to_vec();
        let master = crypto::derive_key(creds.password, &salt, &kdf, creds.key_file)?;
        Ok(VaultKey::from_master(master, kdf, salt, creds.key_file.is_some()))
    }

    pub fn kdf(&self) -> KdfParams {
        self.kdf
    }

    /// Whether this key needs a key file (as well as the password).
    pub fn uses_key_file(&self) -> bool {
        self.key_file
    }

    /// The key for the separately encrypted passwords and notes.
    pub fn item_key(&self) -> &ItemKey {
        &self.item_key
    }

    /// Check whether `creds` yield the same key (constant time). For a key
    /// that uses a key file, the key file is required.
    pub fn verify(&self, creds: Credentials<'_>) -> Result<bool> {
        let secret = secret_for(self.key_file, &creds)?;
        let candidate = crypto::derive_key(creds.password, &self.salt, &self.kdf, secret)?;
        Ok(candidate.ct_eq(&self.master))
    }
}

/// Encrypt `plaintext` into a complete vault file (always the newest
/// version). Every call uses a new, random nonce.
pub fn seal(vk: &VaultKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    seal_version(vk, CURRENT_VERSION, plaintext)
}

fn seal_version(vk: &VaultKey, version: u16, plaintext: &[u8]) -> Result<Vec<u8>> {
    let header = Header {
        version,
        key_file: vk.key_file,
        kdf: vk.kdf,
        salt: vk.salt.clone(),
        nonce: crypto::random_array::<NONCE_LEN>()?,
    };
    let mut out = header.encode();
    // Version 1 used the master key directly for the file.
    let key = if version == 1 { &vk.master } else { &vk.file_key };
    let ct = crypto::encrypt(key, &header.nonce, &out, plaintext)?;
    out.extend_from_slice(&ct);
    if out.len() > MAX_FILE_SIZE {
        return Err(Error::TooLarge);
    }
    Ok(out)
}

/// Decrypt a vault file with the master password (and the key file, if the
/// header says the vault requires one; a pepper given for a vault without
/// a key file is not used).
///
/// Also returns the format version of the file (for migration). Checks, in
/// this order, before Argon2 runs: the header, the key file being present,
/// and the memory Argon2 needs. A wrong password and a wrong key file give
/// the same [`Error::Decrypt`].
pub fn open(data: &[u8], creds: Credentials<'_>) -> Result<(SecureBuf, VaultKey, u16)> {
    let (header, header_len) = Header::decode(data)?;
    let ciphertext = &data[header_len..];
    if ciphertext.len() < TAG_LEN {
        return Err(Error::Truncated);
    }
    let secret = secret_for(header.key_file, &creds)?;
    crypto::ensure_memory(&header.kdf, MemoryUse::Unlock)?;
    let master = crypto::derive_key(creds.password, &header.salt, &header.kdf, secret)?;
    let vk = VaultKey::from_master(master, header.kdf, header.salt, header.key_file);
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

/// Encrypt with `vk` in an older layout (1 or 2) or the current one, for
/// migration tests only.
#[doc(hidden)]
pub fn seal_as_version_for_tests(vk: &VaultKey, version: u16, plaintext: &[u8]) -> Result<Vec<u8>> {
    assert!((1..=CURRENT_VERSION).contains(&version) && !(version < 3 && vk.key_file));
    seal_version(vk, version, plaintext)
}

/// Create a file in the old format (version 1), for migration tests only.
#[doc(hidden)]
pub fn seal_v1_for_tests(password: &[u8], kdf: KdfParams, plaintext: &[u8]) -> Result<Vec<u8>> {
    let vk = VaultKey::create(Credentials::password(password), kdf)?;
    seal_as_version_for_tests(&vk, 1, plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: KdfParams = KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 };
    const PW: &[u8] = b"correct password";

    fn pepper(s: &[u8]) -> KeyFilePepper {
        KeyFilePepper::derive(s).unwrap()
    }

    fn sample() -> (Vec<u8>, &'static [u8]) {
        let vk = VaultKey::create(Credentials::password(PW), P).unwrap();
        (seal(&vk, b"{\"content\":1}").unwrap(), PW)
    }

    /// A vault that requires the key file with contents `b"usb key"`.
    fn sample_with_key_file() -> Vec<u8> {
        let kf = pepper(b"usb key");
        let vk = VaultKey::create(Credentials::new(PW, Some(&kf)), P).unwrap();
        assert!(vk.uses_key_file());
        seal(&vk, b"{\"content\":2}").unwrap()
    }

    #[test]
    fn header_round_trip() {
        for key_file in [false, true] {
            let h = Header { version: 3, key_file, kdf: KdfParams::HIGH, salt: vec![9; 32], nonce: [5; 24] };
            let bytes = h.encode();
            assert_eq!(bytes.len(), 50 + 32);
            assert_eq!(bytes[10], u8::from(key_file), "the flags byte");
            let (back, len) = Header::decode(&bytes).unwrap();
            assert_eq!(back, h);
            assert_eq!(len, bytes.len());
        }
        // The legacy layout (version 2) has no flags byte.
        let h = Header {
            version: 2,
            key_file: false,
            kdf: KdfParams::STANDARD,
            salt: vec![9; 32],
            nonce: [5; 24],
        };
        let bytes = h.encode();
        assert_eq!(bytes.len(), 49 + 32);
        assert_eq!(Header::decode(&bytes).unwrap(), (h, 49 + 32));
    }

    #[test]
    fn save_and_open() {
        let (file, pw) = sample();
        assert_eq!(u16::from_le_bytes([file[8], file[9]]), 3);
        assert_eq!(file[10], 0, "no key file");
        let (pt, vk, version) = open(&file, Credentials::password(pw)).unwrap();
        assert_eq!(version, CURRENT_VERSION);
        assert_eq!(pt.as_slice(), b"{\"content\":1}");
        assert_eq!(vk.kdf(), P);
        assert!(!vk.uses_key_file());
        // Saving again with the same key uses a new nonce.
        let again = seal(&vk, pt.as_slice()).unwrap();
        assert_ne!(again, file);
        assert_eq!(open(&again, Credentials::password(pw)).unwrap().0.as_slice(), pt.as_slice());
    }

    #[test]
    fn wrong_password_always_fails() {
        let (file, _) = sample();
        for pw in [&b"wrong"[..], b"", b"correct password ", b"Correct password"] {
            assert!(matches!(open(&file, Credentials::password(pw)), Err(Error::Decrypt)));
        }
    }

    #[test]
    fn a_key_file_vault_needs_both_secrets() {
        let file = sample_with_key_file();
        assert_eq!(file[10], FLAG_KEY_FILE);
        let right = pepper(b"usb key");
        let wrong = pepper(b"usb kez");
        // Missing key file: a clear error before Argon2 runs.
        assert!(matches!(open(&file, Credentials::password(PW)), Err(Error::KeyFileRequired)));
        // Wrong key file and wrong password: exactly the same error.
        let e1 = open(&file, Credentials::new(PW, Some(&wrong))).unwrap_err();
        let e2 = open(&file, Credentials::new(b"wrong", Some(&right))).unwrap_err();
        let e3 = open(&file, Credentials::new(b"wrong", Some(&wrong))).unwrap_err();
        assert!(matches!((&e1, &e2, &e3), (Error::Decrypt, Error::Decrypt, Error::Decrypt)));
        assert!(e1.to_string() == e2.to_string() && e2.to_string() == e3.to_string());
        // Both right.
        let (pt, vk, _) = open(&file, Credentials::new(PW, Some(&right))).unwrap();
        assert_eq!(pt.as_slice(), b"{\"content\":2}");
        assert!(vk.uses_key_file());
        // Saving keeps the requirement.
        let again = seal(&vk, pt.as_slice()).unwrap();
        assert_eq!(again[10], FLAG_KEY_FILE);
        assert!(open(&again, Credentials::new(PW, Some(&right))).is_ok());
        // A pepper offered for a vault without a key file is not used.
        let (plain, _) = sample();
        assert!(open(&plain, Credentials::new(PW, Some(&right))).is_ok());
    }

    #[test]
    fn the_key_file_flag_is_authenticated() {
        let right = pepper(b"usb key");
        // Clearing the flag of a key-file vault: the key file is no longer
        // used, so the key differs (and the header too): authentication fails.
        let mut cleared = sample_with_key_file();
        cleared[10] = 0;
        assert!(matches!(open(&cleared, Credentials::new(PW, Some(&right))), Err(Error::Decrypt)));
        assert!(matches!(open(&cleared, Credentials::password(PW)), Err(Error::Decrypt)));
        // Setting it on a vault without a key file: it asks for a key file,
        // and no key file makes it open.
        let (mut set, _) = sample();
        set[10] = FLAG_KEY_FILE;
        assert!(matches!(open(&set, Credentials::password(PW)), Err(Error::KeyFileRequired)));
        assert!(matches!(open(&set, Credentials::new(PW, Some(&right))), Err(Error::Decrypt)));
        // Unknown flag bits: refused before any work.
        for bit in 1..8 {
            let mut unknown = sample_with_key_file();
            unknown[10] |= 1 << bit;
            assert!(matches!(
                open(&unknown, Credentials::new(PW, Some(&right))),
                Err(Error::UnsupportedFeature)
            ));
        }
    }

    #[test]
    fn every_bit_flip_in_the_file_fails() {
        let right = pepper(b"usb key");
        let (plain, _) = sample();
        for (file, creds) in
            [(plain, Credentials::password(PW)), (sample_with_key_file(), Credentials::new(PW, Some(&right)))]
        {
            assert!(open(&file, creds).is_ok());
            for i in 0..file.len() {
                let mut bad = file.clone();
                bad[i] ^= 0x01;
                assert!(open(&bad, creds).is_err(), "bit flip at byte {i} went unnoticed");
            }
            // Every bit of magic, version, flags, KDF id and salt length. (The
            // KDF numbers are tested separately: some flips there are valid
            // but huge parameters, which would make this test slow.)
            for i in (0..12).chain([24]) {
                for bit in 1..8 {
                    let mut bad = file.clone();
                    bad[i] ^= 1 << bit;
                    assert!(open(&bad, creds).is_err(), "bit {bit} of header byte {i} went unnoticed");
                }
            }
        }
    }

    #[test]
    fn broken_files_give_clean_errors() {
        let right = pepper(b"usb key");
        let (file, pw) = sample();
        let pw = Credentials::password(pw);
        assert!(matches!(open(b"", pw), Err(Error::Truncated)));
        assert!(matches!(open(b"KLUIS", pw), Err(Error::Truncated)));
        assert!(matches!(open(b"not a vault but text that is long enough", pw), Err(Error::NotAVault)));
        // Every truncated length fails, with and without a key file.
        let with_kf = sample_with_key_file();
        for (f, creds) in [(&file, pw), (&with_kf, Credentials::new(PW, Some(&right)))] {
            for len in 0..f.len() {
                assert!(open(&f[..len], creds).is_err(), "truncation at {len} was accepted");
            }
            // Extra bytes at the end fail too (the tag no longer matches).
            let mut longer = f.clone();
            longer.push(0);
            assert!(matches!(open(&longer, creds), Err(Error::Decrypt)));
        }
    }

    #[test]
    fn unknown_version_and_algorithm() {
        let (file, pw) = sample();
        let pw = Credentials::password(pw);
        let mut v = file.clone();
        v[8] = 4;
        assert!(matches!(open(&v, pw), Err(Error::UnsupportedVersion(4))));
        let mut k = file.clone();
        k[11] = 9;
        assert!(matches!(open(&k, pw), Err(Error::UnsupportedAlgorithm)));
        let mut a = file.clone();
        a[25 + 32] = 9;
        assert!(matches!(open(&a, pw), Err(Error::UnsupportedAlgorithm)));
        // A version 3 file that claims to be version 2 is misread and fails.
        let mut old = file.clone();
        old[8] = 2;
        assert!(open(&old, pw).is_err());
    }

    #[test]
    fn tampered_kdf_parameters_are_rejected_or_fail() {
        let (file, pw) = sample();
        let pw = Credentials::password(pw);
        // Lowering memory to 1 MiB: rejected before Argon2 runs.
        let mut low = file.clone();
        low[12..16].copy_from_slice(&1024u32.to_le_bytes());
        assert!(matches!(open(&low, pw), Err(Error::InvalidKdfParams(_))));
        // Absurd amounts of memory: rejected (no DoS).
        let mut huge = file.clone();
        huge[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(open(&huge, pw), Err(Error::InvalidKdfParams(_))));
        // A valid but different value: different key, so authentication fails.
        let mut other = file.clone();
        other[16..20].copy_from_slice(&2u32.to_le_bytes());
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
        let (pt, vk, version) = open(&old, Credentials::password(b"pw")).unwrap();
        assert_eq!(version, 1);
        assert_eq!(pt.as_slice(), b"old content");
        assert!(matches!(open(&old, Credentials::password(b"wrong")), Err(Error::Decrypt)));
        // Saving again happens in the newest version, with the file subkey.
        let new = seal(&vk, pt.as_slice()).unwrap();
        assert_eq!(u16::from_le_bytes([new[8], new[9]]), CURRENT_VERSION);
        assert_eq!(open(&new, Credentials::password(b"pw")).unwrap().0.as_slice(), b"old content");
        // A newer file presented as version 1 fails (different key and header).
        let mut fake = new.clone();
        fake[8] = 1;
        assert!(open(&fake, Credentials::password(b"pw")).is_err());
    }

    #[test]
    fn version_2_stays_readable_and_becomes_version_3_with_the_same_keys() {
        let vk = VaultKey::create(Credentials::password(PW), P).unwrap();
        let sealed_item = vk.item_key().seal("password", "item secret").unwrap();
        let v2 = seal_as_version_for_tests(&vk, 2, sealed_item.as_bytes()).unwrap();
        assert_eq!(u16::from_le_bytes([v2[8], v2[9]]), 2);
        assert_eq!(v2.len(), 49 + 32 + sealed_item.len() + TAG_LEN, "no flags byte");
        let (pt, vk2, version) = open(&v2, Credentials::password(PW)).unwrap();
        assert_eq!(version, 2);
        assert!(!vk2.uses_key_file());
        let v3 = seal(&vk2, pt.as_slice()).unwrap();
        assert_eq!((u16::from_le_bytes([v3[8], v3[9]]), v3[10]), (3, 0));
        let (pt3, vk3, _) = open(&v3, Credentials::password(PW)).unwrap();
        // The same item key: items sealed under version 2 open unchanged.
        let text = std::str::from_utf8(pt3.as_slice()).unwrap();
        assert_eq!(vk3.item_key().open("password", text).unwrap().as_str(), "item secret");
        // Every bit flip of the version 2 file still fails.
        for i in 0..v2.len() {
            let mut bad = v2.clone();
            bad[i] ^= 0x01;
            assert!(open(&bad, Credentials::password(PW)).is_err(), "byte {i}");
        }
    }

    #[test]
    fn password_check() {
        let vk = VaultKey::create(Credentials::password(b"right"), P).unwrap();
        assert!(vk.verify(Credentials::password(b"right")).unwrap());
        assert!(!vk.verify(Credentials::password(b"wrong")).unwrap());
        // With a key file: the key file is needed to check the password.
        let kf = pepper(b"usb key");
        let vk = VaultKey::create(Credentials::new(b"right", Some(&kf)), P).unwrap();
        assert!(matches!(vk.verify(Credentials::password(b"right")), Err(Error::KeyFileRequired)));
        assert!(vk.verify(Credentials::new(b"right", Some(&kf))).unwrap());
        assert!(!vk.verify(Credentials::new(b"right", Some(&pepper(b"other")))).unwrap());
        assert!(!vk.verify(Credentials::new(b"wrong", Some(&kf))).unwrap());
    }

    #[test]
    fn different_vaults_get_different_salts() {
        let a = VaultKey::create(Credentials::password(b"x"), P).unwrap();
        let b = VaultKey::create(Credentials::password(b"x"), P).unwrap();
        assert_ne!(a.salt, b.salt);
    }

    #[test]
    fn nothing_secret_in_debug_output() {
        let kf = pepper(b"usb key");
        let creds = Credentials::new(b"hunter2-secret", Some(&kf));
        assert_eq!(format!("{creds:?}"), "Credentials([HIDDEN])");
        let vk = VaultKey::create(creds, P).unwrap();
        let dbg = format!("{vk:?}");
        assert!(dbg.contains("[HIDDEN]") && !dbg.contains("hunter2"), "{dbg}");
    }
}
