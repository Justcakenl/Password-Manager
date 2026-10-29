//! Cryptography: key derivation and authenticated encryption.
//!
//! SECURITY-CRITICAL. We do NOT implement any primitives ourselves; we only
//! use the expert-written and audited RustCrypto crates:
//!
//! - **Argon2id** (`argon2`): turns the master password plus a random salt
//!   into a 256-bit key. Argon2id is deliberately slow and memory-hungry, so
//!   guessing with GPUs becomes expensive.
//! - **XChaCha20-Poly1305** (`chacha20poly1305`): encrypts and authenticates.
//!   Any change to the file (including the header, which is part of the
//!   "associated data") makes decryption impossible. The 24-byte nonce is
//!   large enough that a random nonce per write is safe.
//! - **HKDF-SHA256** (`hkdf`): derives separate subkeys from the Argon2 key
//!   for the vault file and for the individual passwords and notes ("key
//!   separation"), so one key never serves two purposes.
//! - Randomness only comes from the OS CSPRNG (`getrandom`, on Linux the
//!   `getrandom(2)` system call).
//!
//! The HKDF `info` labels and the AEAD associated-data strings are part of
//! the on-disk format. They are fixed protocol constants and must never be
//! changed (vaults would no longer open).

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secure_mem::SecureBuf;

/// Length of the derived key (256 bits).
pub const KEY_LEN: usize = 32;
/// Length of the salt we use for new vaults.
pub const SALT_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;

/// Configurable Argon2id parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory use in KiB.
    pub memory_kib: u32,
    /// Number of passes (t).
    pub iterations: u32,
    /// Number of parallel lanes (p).
    pub parallelism: u32,
}

impl KdfParams {
    /// Default: 64 MiB, t=3, p=4 (stronger than the OWASP minimum).
    pub const DEFAULT: KdfParams = KdfParams { memory_kib: 64 * 1024, iterations: 3, parallelism: 4 };
    /// Lower bound we accept (8 MiB). Anything lower is too weak.
    pub const MIN_MEMORY_KIB: u32 = 8 * 1024;
    /// Upper bound (4 GiB), so a tampered header cannot cause a memory DoS.
    pub const MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024;
    pub const MAX_ITERATIONS: u32 = 64;
    pub const MAX_PARALLELISM: u32 = 64;

    /// Check that the parameters are within safe limits.
    pub fn validate(&self) -> Result<()> {
        if self.memory_kib < Self::MIN_MEMORY_KIB {
            return Err(Error::InvalidKdfParams("memory must be at least 8 MiB"));
        }
        if self.memory_kib > Self::MAX_MEMORY_KIB {
            return Err(Error::InvalidKdfParams("memory must be at most 4096 MiB"));
        }
        if self.iterations == 0 || self.iterations > Self::MAX_ITERATIONS {
            return Err(Error::InvalidKdfParams("iterations must be between 1 and 64"));
        }
        if self.parallelism == 0 || self.parallelism > Self::MAX_PARALLELISM {
            return Err(Error::InvalidKdfParams("parallelism must be between 1 and 64"));
        }
        // Argon2 requires at least 8 KiB per lane.
        if self.memory_kib < 8 * self.parallelism {
            return Err(Error::InvalidKdfParams("not enough memory for this parallelism"));
        }
        Ok(())
    }

    /// Whether these parameters are weaker than the default (for a warning).
    pub fn weaker_than_default(&self) -> bool {
        self.memory_kib < Self::DEFAULT.memory_kib || self.iterations < Self::DEFAULT.iterations
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The 256-bit key, in locked memory that is wiped when dropped.
pub struct MasterKey(SecureBuf);

impl MasterKey {
    fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Compare two keys in constant time.
    pub fn ct_eq(&self, other: &MasterKey) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.as_bytes().ct_eq(other.as_bytes()))
    }

    /// Derive a subkey for one specific purpose (`info`) with HKDF-SHA256.
    pub fn derive_subkey(&self, info: &[u8]) -> MasterKey {
        let hk = Hkdf::<Sha256>::new(None, self.as_bytes());
        let mut out = SecureBuf::zeroed(KEY_LEN);
        hk.expand(info, out.as_mut_slice()).expect("32 bytes is a valid HKDF length");
        MasterKey(out)
    }

    /// A copy in newly locked memory.
    pub fn duplicate(&self) -> MasterKey {
        MasterKey(SecureBuf::from_slice(self.as_bytes()))
    }

    /// Create a key from raw bytes (tests only).
    #[cfg(test)]
    pub(crate) fn from_bytes_for_test(bytes: &[u8; KEY_LEN]) -> Self {
        MasterKey(SecureBuf::from_slice(bytes))
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey([HIDDEN])")
    }
}

/// Key for the second encryption layer: every field of every item is
/// encrypted separately (own random nonce per field).
///
/// Even while the vault is open, item contents therefore stay encrypted in
/// memory. They are only decrypted at the moment you ask for one
/// (`get --show`, clipboard, export), and wiped again right afterwards.
pub struct ItemKey(MasterKey);

/// Overhead per encrypted field: nonce + tag.
pub const SEALED_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

impl ItemKey {
    pub fn new(key: MasterKey) -> ItemKey {
        ItemKey(key)
    }

    fn aad(field: &str) -> Vec<u8> {
        // The field name takes part in the authentication, so an encrypted
        // password cannot be passed off as a note (or the other way around).
        format!("kluis/item/v1/{field}").into_bytes()
    }

    /// Encrypt a field. Result: base64(nonce || ciphertext || tag).
    pub fn seal(&self, field: &str, plaintext: &str) -> Result<String> {
        use base64ct::{Base64, Encoding};
        let nonce = random_array::<NONCE_LEN>()?;
        let ct = encrypt(&self.0, &nonce, &Self::aad(field), plaintext.as_bytes())?;
        let mut raw = Vec::with_capacity(NONCE_LEN + ct.len());
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&ct);
        Ok(Base64::encode_string(&raw))
    }

    /// Decrypt a field that was encrypted with [`ItemKey::seal`].
    pub fn open(&self, field: &str, sealed: &str) -> Result<Zeroizing<String>> {
        let raw = decode_sealed(sealed)?;
        let (nonce, ct) = raw.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("length was checked");
        let plain = decrypt(&self.0, &nonce, &Self::aad(field), ct)?;
        let text = std::str::from_utf8(plain.as_slice()).map_err(|_| Error::CorruptPayload)?;
        Ok(Zeroizing::new(text.to_string()))
    }
}

/// A fixed item key for tests.
#[cfg(test)]
pub(crate) fn test_item_key(n: u8) -> ItemKey {
    ItemKey::new(MasterKey::from_bytes_for_test(&[n; KEY_LEN]))
}

impl std::fmt::Debug for ItemKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemKey([HIDDEN])")
    }
}

/// Validate and decode an encrypted field (without decrypting it).
pub fn decode_sealed(sealed: &str) -> Result<Vec<u8>> {
    use base64ct::{Base64, Encoding};
    let raw = Base64::decode_vec(sealed).map_err(|_| Error::CorruptPayload)?;
    if raw.len() < SEALED_OVERHEAD {
        return Err(Error::CorruptPayload);
    }
    Ok(raw)
}

/// Length of the plaintext of an encrypted field (without decrypting it).
pub fn sealed_plaintext_len(sealed: &str) -> usize {
    decode_sealed(sealed).map_or(0, |raw| raw.len() - SEALED_OVERHEAD)
}

/// Fill a buffer with cryptographically secure random bytes from the OS.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Rng)
}

/// Return `N` random bytes.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill_random(&mut out)?;
    Ok(out)
}

/// Derive a key from a password and salt with Argon2id.
pub fn derive_key(password: &[u8], salt: &[u8], params: &KdfParams) -> Result<MasterKey> {
    params.validate()?;
    let argon_params = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(KEY_LEN))
        .map_err(|_| Error::InvalidKdfParams("rejected by Argon2"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = SecureBuf::zeroed(KEY_LEN);
    argon.hash_password_into(password, salt, key.as_mut_slice()).map_err(|_| Error::Kdf)?;
    Ok(MasterKey(key))
}

fn cipher(key: &MasterKey) -> XChaCha20Poly1305 {
    // The cipher struct holds a copy of the key and wipes it itself on Drop.
    XChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("key is 32 bytes")
}

/// Encrypt `plaintext`. Returns `ciphertext || tag`.
///
/// `aad` (associated data) is not encrypted but is authenticated.
pub fn encrypt(key: &MasterKey, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    // We encrypt "in place": the buffer briefly holds the plaintext and is
    // then immediately overwritten with the ciphertext.
    let mut buf = Vec::with_capacity(plaintext.len() + TAG_LEN);
    buf.extend_from_slice(plaintext);
    let nonce = XNonce::from(*nonce);
    let tag = cipher(key)
        .encrypt_inout_detached(&nonce, aad, buf.as_mut_slice().into())
        .map_err(|_| Error::Encrypt)?;
    buf.extend_from_slice(tag.as_slice());
    Ok(buf)
}

/// Decrypt and verify `ciphertext || tag`.
///
/// The plaintext ends up in a [`SecureBuf`]. With a wrong key, or any change
/// at all, this fails with [`Error::Decrypt`]; the tag check in the crate is
/// constant-time.
pub fn decrypt(key: &MasterKey, nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> Result<SecureBuf> {
    let Some(msg_len) = ciphertext.len().checked_sub(TAG_LEN) else {
        return Err(Error::Truncated);
    };
    let (msg, tag) = ciphertext.split_at(msg_len);
    let tag = chacha20poly1305::Tag::try_from(tag).map_err(|_| Error::Truncated)?;
    let mut buf = SecureBuf::from_slice(msg);
    let nonce = XNonce::from(*nonce);
    cipher(key)
        .decrypt_inout_detached(&nonce, aad, buf.as_mut_slice().into(), &tag)
        .map_err(|_| Error::Decrypt)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fast parameters for tests (strength is irrelevant here).
    pub(crate) const TEST_PARAMS: KdfParams =
        KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 };

    #[test]
    fn default_parameters_are_valid() {
        KdfParams::DEFAULT.validate().unwrap();
        assert_eq!(KdfParams::DEFAULT.memory_kib, 65536);
        assert_eq!(KdfParams::DEFAULT.iterations, 3);
        assert_eq!(KdfParams::DEFAULT.parallelism, 4);
        assert!(!KdfParams::DEFAULT.weaker_than_default());
        assert!(TEST_PARAMS.weaker_than_default());
    }

    #[test]
    fn invalid_parameters_are_rejected() {
        let p = |m, t, par| KdfParams { memory_kib: m, iterations: t, parallelism: par };
        assert!(p(1024, 3, 4).validate().is_err());
        assert!(p(u32::MAX, 3, 4).validate().is_err());
        assert!(p(65536, 0, 4).validate().is_err());
        assert!(p(65536, 1000, 4).validate().is_err());
        assert!(p(65536, 3, 0).validate().is_err());
        assert!(p(65536, 3, 1000).validate().is_err());
    }

    #[test]
    fn argon2id_official_test_vector_rfc9106() {
        // RFC 9106, section 5.3: checks that the crate really computes
        // Argon2id (version 0x13).
        use argon2::{AssociatedData, ParamsBuilder};
        let params = ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(AssociatedData::new(&[4u8; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let argon = Argon2::new_with_secret(&[3u8; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
        let mut out = [0u8; 32];
        argon.hash_password_into(&[1u8; 32], &[2u8; 16], &mut out).unwrap();
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
    }

    #[test]
    fn key_derivation_is_deterministic_and_salt_dependent() {
        let a = derive_key(b"password", &[1u8; 32], &TEST_PARAMS).unwrap();
        let b = derive_key(b"password", &[1u8; 32], &TEST_PARAMS).unwrap();
        let c = derive_key(b"password", &[2u8; 32], &TEST_PARAMS).unwrap();
        let d = derive_key(b"Password", &[1u8; 32], &TEST_PARAMS).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
        assert_ne!(a.as_bytes(), d.as_bytes());
        assert!(!format!("{a:?}").contains(&format!("{:?}", a.as_bytes())));
    }

    #[test]
    fn encrypt_and_decrypt() {
        let key = MasterKey::from_bytes_for_test(&[7u8; 32]);
        let nonce = random_array::<NONCE_LEN>().unwrap();
        let ct = encrypt(&key, &nonce, b"header", b"secret data").unwrap();
        assert_eq!(ct.len(), b"secret data".len() + TAG_LEN);
        assert!(!ct.windows(6).any(|w| w == b"secret"));
        let pt = decrypt(&key, &nonce, b"header", &ct).unwrap();
        assert_eq!(pt.as_slice(), b"secret data");
    }

    #[test]
    fn any_change_fails() {
        let key = MasterKey::from_bytes_for_test(&[7u8; 32]);
        let other = MasterKey::from_bytes_for_test(&[8u8; 32]);
        let nonce = [3u8; NONCE_LEN];
        let ct = encrypt(&key, &nonce, b"aad", b"content").unwrap();

        // Wrong key.
        assert!(matches!(decrypt(&other, &nonce, b"aad", &ct), Err(Error::Decrypt)));
        // Different associated data (= tampered header).
        assert!(matches!(decrypt(&key, &nonce, b"aaD", &ct), Err(Error::Decrypt)));
        // Different nonce.
        assert!(matches!(decrypt(&key, &[4u8; NONCE_LEN], b"aad", &ct), Err(Error::Decrypt)));
        // Every single bit flip in the ciphertext or tag.
        for i in 0..ct.len() {
            for bit in 0..8 {
                let mut bad = ct.clone();
                bad[i] ^= 1 << bit;
                assert!(matches!(decrypt(&key, &nonce, b"aad", &bad), Err(Error::Decrypt)));
            }
        }
        // Truncated.
        assert!(decrypt(&key, &nonce, b"aad", &ct[..ct.len() - 1]).is_err());
        assert!(matches!(decrypt(&key, &nonce, b"aad", &ct[..5]), Err(Error::Truncated)));
    }

    #[test]
    fn hkdf_official_test_vector_rfc5869() {
        // RFC 5869, test case 3 (no salt, no info): checks the HKDF crate.
        let hk = Hkdf::<Sha256>::new(None, &[0x0b; 22]);
        let mut okm = [0u8; 42];
        hk.expand(&[], &mut okm).unwrap();
        let hex: String = okm.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn subkeys_are_different() {
        let m = MasterKey::from_bytes_for_test(&[7u8; 32]);
        let a = m.derive_subkey(b"purpose a");
        let b = m.derive_subkey(b"purpose b");
        assert!(!a.ct_eq(&b));
        assert!(!a.ct_eq(&m));
        assert!(a.ct_eq(&m.derive_subkey(b"purpose a")));
    }

    #[test]
    fn field_encryption() {
        let k = ItemKey::new(MasterKey::from_bytes_for_test(&[1u8; 32]));
        let other = ItemKey::new(MasterKey::from_bytes_for_test(&[2u8; 32]));
        let a = k.seal("password", "secret").unwrap();
        let b = k.seal("password", "secret").unwrap();
        assert_ne!(a, b, "every encryption has its own nonce");
        assert!(!a.contains("secret"));
        assert_eq!(k.open("password", &a).unwrap().as_str(), "secret");
        assert_eq!(sealed_plaintext_len(&a), 6);
        assert_eq!(sealed_plaintext_len(&k.seal("password", "").unwrap()), 0);
        // Wrong key, wrong field type, tampered or nonsense: always an error.
        assert!(matches!(other.open("password", &a), Err(Error::Decrypt)));
        assert!(matches!(k.open("notes", &a), Err(Error::Decrypt)));
        let mut raw = decode_sealed(&a).unwrap();
        raw[30] ^= 1;
        use base64ct::{Base64, Encoding};
        assert!(matches!(k.open("password", &Base64::encode_string(&raw)), Err(Error::Decrypt)));
        assert!(matches!(k.open("password", "not base64!"), Err(Error::CorruptPayload)));
        assert!(matches!(k.open("password", "AAAA"), Err(Error::CorruptPayload)));
    }

    #[test]
    fn nonces_are_random() {
        let a = random_array::<NONCE_LEN>().unwrap();
        let b = random_array::<NONCE_LEN>().unwrap();
        assert_ne!(a, b);
    }
}
