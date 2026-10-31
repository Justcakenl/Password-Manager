//! Cryptography: key derivation and authenticated encryption.
//!
//! SECURITY-CRITICAL. We do NOT implement any primitives ourselves; we only
//! use the expert-written and audited RustCrypto crates:
//!
//! - **Argon2id** (`argon2`): turns the master password plus a random salt
//!   (and, optionally, the pepper of a key file as Argon2's own "secret"
//!   input) into a 256-bit key. Argon2id is deliberately slow and
//!   memory-hungry, so guessing with GPUs becomes expensive. How expensive is
//!   set by the [`SecurityLevel`].
//! - **XChaCha20-Poly1305** (`chacha20poly1305`): encrypts and authenticates.
//!   Any change to the file (including the header, which is part of the
//!   "associated data") makes decryption impossible. The 24-byte nonce is
//!   large enough that a random nonce per write is safe.
//! - **HKDF-SHA256** (`hkdf`): derives separate subkeys from the Argon2 key
//!   for the vault file and for the individual passwords and notes ("key
//!   separation"), so one key never serves two purposes.
//! - **BLAKE2b-256** (`blake2`): condenses a key file (any content up to
//!   1 MiB) into a 32-byte pepper, with a domain-separation label.
//! - Randomness only comes from the OS CSPRNG (`getrandom`, on Linux the
//!   `getrandom(2)` system call).
//!
//! The HKDF `info` labels, the AEAD associated-data strings and the key-file
//! label are part of the on-disk format. They are fixed protocol constants
//! and must never be changed (vaults would no longer open).

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secure_mem::{self, SecureBuf};

/// Length of the derived key (256 bits).
pub const KEY_LEN: usize = 32;
/// Length of the salt we use for new vaults.
pub const SALT_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Length of the pepper derived from a key file.
pub const KEY_FILE_PEPPER_LEN: usize = 32;
/// Domain-separation label for the key-file pepper (protocol constant).
const KEY_FILE_LABEL: &[u8] = b"cakepass keyfile v1";

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
    /// The Standard level: 64 MiB, t=3, p=4 (the second recommendation of
    /// RFC 9106, and the default of CakePass up to version 0.3). Lighter
    /// settings get a warning.
    pub const STANDARD: KdfParams = KdfParams { memory_kib: 64 * 1024, iterations: 3, parallelism: 4 };
    /// The High level (default for new vaults): 256 MiB, t=3, p=4.
    pub const HIGH: KdfParams = KdfParams { memory_kib: 256 * 1024, iterations: 3, parallelism: 4 };
    /// The Maximum level: 1 GiB, t=3, p=4.
    pub const MAXIMUM: KdfParams = KdfParams { memory_kib: 1024 * 1024, iterations: 3, parallelism: 4 };
    /// Lower bound we accept (8 MiB). Anything lower is too weak.
    pub const MIN_MEMORY_KIB: u32 = 8 * 1024;
    /// Upper bound (4 GiB), so a tampered header cannot cause a memory DoS.
    /// (A second, machine-dependent check is [`ensure_memory`].)
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

    /// Whether these parameters are weaker than the Standard level (for a warning).
    pub fn weaker_than_standard(&self) -> bool {
        self.memory_kib < Self::STANDARD.memory_kib || self.iterations < Self::STANDARD.iterations
    }

    /// "Argon2id, 256 MiB, 3 iterations, 4 lanes".
    pub fn describe(&self) -> String {
        format!(
            "Argon2id, {} MiB, {} iterations, {} lanes",
            self.memory_kib / 1024,
            self.iterations,
            self.parallelism
        )
    }
}

impl Default for KdfParams {
    /// The parameters for new vaults: [`SecurityLevel::DEFAULT`].
    fn default() -> Self {
        SecurityLevel::DEFAULT.params()
    }
}

/// Named Argon2id settings, so nobody has to pick numbers.
///
/// All three use t=3 and p=4; they differ in memory. Memory is what makes
/// guessing on GPUs and ASICs expensive: every guess must fill (and read
/// back) that much memory, and a graphics card has only so much memory and
/// memory bandwidth. Four times the memory is roughly four times the cost
/// per guess for an attacker, and four times the unlock time for you.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// 64 MiB: works on any computer, unlocks in a fraction of a second.
    Standard,
    /// 256 MiB: the recommended default for new vaults.
    High,
    /// 1 GiB: for computers with plenty of memory.
    Maximum,
}

impl SecurityLevel {
    pub const ALL: [SecurityLevel; 3] =
        [SecurityLevel::Standard, SecurityLevel::High, SecurityLevel::Maximum];
    /// The level of new vaults.
    pub const DEFAULT: SecurityLevel = SecurityLevel::High;

    pub const fn params(self) -> KdfParams {
        match self {
            SecurityLevel::Standard => KdfParams::STANDARD,
            SecurityLevel::High => KdfParams::HIGH,
            SecurityLevel::Maximum => KdfParams::MAXIMUM,
        }
    }

    /// The level these exact parameters belong to; `None` means "custom".
    pub fn of(params: &KdfParams) -> Option<SecurityLevel> {
        Self::ALL.into_iter().find(|l| l.params() == *params)
    }

    /// The name used in commands and messages: "standard", "high", "maximum".
    pub fn name(self) -> &'static str {
        match self {
            SecurityLevel::Standard => "standard",
            SecurityLevel::High => "high",
            SecurityLevel::Maximum => "maximum",
        }
    }

    /// "Standard", "High (recommended)", "Maximum".
    pub fn title(self) -> &'static str {
        match self {
            SecurityLevel::Standard => "Standard",
            SecurityLevel::High => "High (recommended)",
            SecurityLevel::Maximum => "Maximum",
        }
    }

    /// Parse a name (case-insensitive; also "s", "h", "m" and "max").
    pub fn parse(s: &str) -> Option<SecurityLevel> {
        match s.trim().to_lowercase().as_str() {
            "standard" | "s" => Some(SecurityLevel::Standard),
            "high" | "h" => Some(SecurityLevel::High),
            "maximum" | "max" | "m" => Some(SecurityLevel::Maximum),
            _ => None,
        }
    }

    /// The next stronger (`delta` > 0) or lighter level, stopping at the ends.
    pub fn step(self, delta: isize) -> SecurityLevel {
        let i = Self::ALL.iter().position(|&l| l == self).unwrap_or(1) as isize;
        Self::ALL[(i + delta).clamp(0, 2) as usize]
    }

    /// The free memory this level needs before CakePass runs it.
    pub fn min_available_mib(self) -> u64 {
        min_available_kib(&self.params()).div_ceil(1024)
    }
}

// ───────────────────────── memory guard ─────────────────────────

/// Argon2 may use at most this share (percent) of the memory the kernel
/// reports as available.
///
/// SECURITY/robustness: the memory size comes from the vault header. A vault
/// made on a big desktop at the Maximum level, opened on a small laptop,
/// would otherwise make Linux kill the process for lack of memory (the OOM
/// killer) halfway through. We refuse cleanly before allocating instead.
pub const MEMORY_SHARE_PERCENT: u64 = 75;

/// Why Argon2 is about to run (only changes the wording of the error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryUse {
    /// Opening an existing vault: its level is fixed in its header.
    Unlock,
    /// Creating a vault or switching to a level: another level can be chosen.
    Create,
}

/// The least free memory (KiB) needed to run Argon2 with `params`.
pub fn min_available_kib(params: &KdfParams) -> u64 {
    (u64::from(params.memory_kib) * 100).div_ceil(MEMORY_SHARE_PERCENT)
}

/// `MemAvailable` from the text of `/proc/meminfo`, in KiB.
pub fn parse_mem_available_kib(meminfo: &str) -> Option<u64> {
    meminfo.lines().find_map(|l| {
        let rest = l.strip_prefix("MemAvailable:")?;
        let mut words = rest.split_whitespace();
        let n = words.next()?.parse::<u64>().ok()?;
        match words.next() {
            Some("kB") | None => Some(n),
            _ => None,
        }
    })
}

/// How much memory the kernel says is available (KiB), if it says so.
///
/// Debug builds (the tests) may pretend with `CAKEPASS_TEST_MEM_AVAILABLE_KIB`;
/// release builds ignore that variable.
pub fn mem_available_kib() -> Option<u64> {
    #[cfg(any(debug_assertions, feature = "test-hooks"))]
    if let Some(v) = std::env::var("CAKEPASS_TEST_MEM_AVAILABLE_KIB").ok().and_then(|v| v.parse().ok()) {
        return Some(v);
    }
    parse_mem_available_kib(&std::fs::read_to_string("/proc/meminfo").ok()?)
}

/// Check `params` against `available_kib` (`None` = unknown: allowed, as
/// before this check existed).
pub fn check_memory_with(params: &KdfParams, available_kib: Option<u64>, purpose: MemoryUse) -> Result<()> {
    let Some(available) = available_kib else { return Ok(()) };
    let needed = min_available_kib(params);
    if needed > available {
        return Err(Error::NotEnoughMemory {
            argon_mib: u64::from(params.memory_kib) / 1024,
            needed_mib: needed.div_ceil(1024),
            available_mib: available / 1024,
            unlocking: purpose == MemoryUse::Unlock,
        });
    }
    Ok(())
}

/// Refuse (before allocating anything) when this computer cannot spare the
/// memory Argon2 needs for `params`.
pub fn ensure_memory(params: &KdfParams, purpose: MemoryUse) -> Result<()> {
    check_memory_with(params, mem_available_kib(), purpose)
}

// ───────────────────────── keys ─────────────────────────

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

/// The 32-byte pepper derived from a key file, in locked memory that is
/// wiped when dropped.
///
/// ```text
/// pepper = BLAKE2b-256( le64(19) ‖ "cakepass keyfile v1" ‖ le64(n) ‖ file[0..n] )
/// ```
///
/// (BLAKE2b with a 32-byte digest length in its parameter block, not a
/// truncated BLAKE2b-512.) The pepper is passed to Argon2id as its secret
/// input `K` (RFC 9106, section 3.2), which Argon2 mixes into its very first
/// hash `H0` together with the password and the salt. Without the key file
/// an attacker would have to guess these 256 bits as well as the password.
///
/// SECURITY: the length-prefixed label separates this use of BLAKE2b from
/// every other; the length prefix of the content keeps the encoding
/// unambiguous. Any content of 1 to 1 MiB bytes works; an empty file is
/// refused (it would add nothing). The pepper only exists while Argon2 runs:
/// the program re-reads the key file whenever it needs it again.
pub struct KeyFilePepper(SecureBuf);

impl KeyFilePepper {
    /// Derive the pepper from the complete contents of a key file.
    pub fn derive(contents: &[u8]) -> Result<KeyFilePepper> {
        use blake2::Digest;
        if contents.is_empty() {
            return Err(Error::KeyFileInvalid("the key file is empty".into()));
        }
        let mut out = SecureBuf::zeroed(KEY_FILE_PEPPER_LEN);
        {
            // The `zeroize` feature of `blake2` wipes the hasher's state and
            // buffer when it is dropped (finalize consumes it).
            let mut h = blake2::Blake2b256::new();
            h.update((KEY_FILE_LABEL.len() as u64).to_le_bytes());
            h.update(KEY_FILE_LABEL);
            h.update((contents.len() as u64).to_le_bytes());
            h.update(contents);
            // Straight into locked memory: no copy of the pepper elsewhere.
            let target: &mut blake2::digest::Output<blake2::Blake2b256> =
                out.as_mut_slice().try_into().expect("32 bytes");
            h.finalize_into(target);
        }
        secure_mem::scrub_stack();
        Ok(KeyFilePepper(out))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Compare in constant time (tests).
    #[cfg(test)]
    pub(crate) fn ct_eq(&self, other: &KeyFilePepper) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.as_bytes().ct_eq(other.as_bytes()))
    }

    #[cfg(test)]
    pub(crate) fn hex_for_test(&self) -> String {
        self.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl std::fmt::Debug for KeyFilePepper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyFilePepper([HIDDEN])")
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

/// Derive a key from a password and salt with Argon2id (version 0x13), with
/// the key-file pepper as Argon2's secret input when there is one.
///
/// This does not check the free memory; callers that run parameters from a
/// file or a user's choice call [`ensure_memory`] first.
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
    key_file: Option<&KeyFilePepper>,
) -> Result<MasterKey> {
    params.validate()?;
    let argon_params = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(KEY_LEN))
        .map_err(|_| Error::InvalidKdfParams("rejected by Argon2"))?;
    let argon = match key_file {
        Some(pepper) => {
            Argon2::new_with_secret(pepper.as_bytes(), Algorithm::Argon2id, Version::V0x13, argon_params)
                .map_err(|_| Error::Kdf)?
        }
        None => Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params),
    };
    let mut key = SecureBuf::zeroed(KEY_LEN);
    // Argon2's working memory (`memory_kib`) is a normal heap allocation; the
    // wiping allocator of the program overwrites it when Argon2 frees it.
    let result = argon.hash_password_into(password, salt, key.as_mut_slice());
    // SECURITY: Argon2's first hash (H0) is computed on the stack from the
    // password and the pepper. Overwrite what the computation left there.
    secure_mem::scrub_stack();
    result.map_err(|_| Error::Kdf)?;
    Ok(MasterKey(key))
}

/// Time one key derivation with `params` on this computer (with a
/// throw-away password and salt): about how long unlocking takes.
///
/// Refuses, like unlocking would, when the memory is not available.
pub fn measure_unlock(params: &KdfParams) -> Result<Duration> {
    params.validate()?;
    ensure_memory(params, MemoryUse::Create)?;
    let salt = random_array::<SALT_LEN>()?;
    let start = Instant::now();
    let key = derive_key(b"cakepass timing run", &salt, params, None)?;
    let elapsed = start.elapsed();
    drop(key);
    Ok(elapsed)
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

    fn hex(b: &[u8]) -> String {
        b.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn level_parameters_are_valid() {
        for level in SecurityLevel::ALL {
            let p = level.params();
            p.validate().unwrap();
            assert_eq!((p.iterations, p.parallelism), (3, 4), "{level:?}");
            assert!(!p.weaker_than_standard(), "{level:?}");
            assert_eq!(SecurityLevel::of(&p), Some(level));
            assert_eq!(SecurityLevel::parse(level.name()), Some(level));
        }
        assert_eq!(KdfParams::STANDARD.memory_kib, 64 * 1024);
        assert_eq!(KdfParams::HIGH.memory_kib, 256 * 1024);
        assert_eq!(KdfParams::MAXIMUM.memory_kib, 1024 * 1024);
        assert_eq!(SecurityLevel::DEFAULT, SecurityLevel::High);
        assert_eq!(KdfParams::default(), KdfParams::HIGH, "new vaults get the High level");
        assert!(TEST_PARAMS.weaker_than_standard());
        assert_eq!(SecurityLevel::of(&TEST_PARAMS), None, "custom");
        // One iteration less than Standard is weaker too.
        assert!(KdfParams { iterations: 2, ..KdfParams::MAXIMUM }.weaker_than_standard());
        assert_eq!(SecurityLevel::of(&KdfParams { parallelism: 1, ..KdfParams::HIGH }), None);
    }

    #[test]
    fn level_names_and_steps() {
        assert_eq!(SecurityLevel::parse(" MAX "), Some(SecurityLevel::Maximum));
        assert_eq!(SecurityLevel::parse("h"), Some(SecurityLevel::High));
        assert_eq!(SecurityLevel::parse("ultra"), None);
        assert_eq!(SecurityLevel::Standard.step(-1), SecurityLevel::Standard, "stops at the end");
        assert_eq!(SecurityLevel::Standard.step(1), SecurityLevel::High);
        assert_eq!(SecurityLevel::Maximum.step(5), SecurityLevel::Maximum);
        assert_eq!(SecurityLevel::High.title(), "High (recommended)");
        assert_eq!(KdfParams::HIGH.describe(), "Argon2id, 256 MiB, 3 iterations, 4 lanes");
    }

    #[test]
    fn invalid_parameters_are_rejected() {
        let p = |m, t, par| KdfParams { memory_kib: m, iterations: t, parallelism: par };
        assert!(p(1024, 3, 4).validate().is_err());
        assert!(p(u32::MAX, 3, 4).validate().is_err());
        assert!(p(4 * 1024 * 1024 + 1, 3, 4).validate().is_err());
        assert!(p(65536, 0, 4).validate().is_err());
        assert!(p(65536, 1000, 4).validate().is_err());
        assert!(p(65536, 3, 0).validate().is_err());
        assert!(p(65536, 3, 1000).validate().is_err());
    }

    #[test]
    fn meminfo_is_parsed() {
        let text = "MemTotal:       16477352 kB\nMemFree:        15928936 kB\nMemAvailable:   15970964 kB\n";
        assert_eq!(parse_mem_available_kib(text), Some(15_970_964));
        assert_eq!(parse_mem_available_kib("MemTotal: 5 kB\n"), None, "old kernels have no MemAvailable");
        assert_eq!(parse_mem_available_kib("MemAvailable: lots kB\n"), None);
        assert_eq!(parse_mem_available_kib("MemAvailable: 5 MB\n"), None, "unknown unit");
        assert_eq!(parse_mem_available_kib(""), None);
    }

    #[test]
    fn memory_guard_refuses_what_does_not_fit() {
        let high = KdfParams::HIGH; // 256 MiB → needs 342 MiB free (75 % rule)
        assert_eq!(min_available_kib(&high), 349_526);
        assert_eq!(SecurityLevel::High.min_available_mib(), 342);
        assert_eq!(SecurityLevel::Standard.min_available_mib(), 86);
        assert_eq!(SecurityLevel::Maximum.min_available_mib(), 1366);
        assert!(check_memory_with(&high, Some(349_526), MemoryUse::Unlock).is_ok(), "exactly enough");
        assert!(check_memory_with(&high, None, MemoryUse::Unlock).is_ok(), "unknown: allowed");
        assert!(check_memory_with(&high, Some(16 * 1024 * 1024), MemoryUse::Create).is_ok());
        match check_memory_with(&high, Some(300 * 1024), MemoryUse::Unlock) {
            Err(Error::NotEnoughMemory {
                argon_mib: 256,
                needed_mib: 342,
                available_mib: 300,
                unlocking: true,
            }) => {}
            other => panic!("{other:?}"),
        }
        let e = check_memory_with(&KdfParams::MAXIMUM, Some(1024 * 1024), MemoryUse::Create).unwrap_err();
        let text = e.to_string();
        assert!(text.contains("1024 MiB") && text.contains("lower level"), "{text}");
        let e = check_memory_with(&KdfParams::MAXIMUM, Some(1024 * 1024), MemoryUse::Unlock).unwrap_err();
        assert!(e.to_string().contains("more memory"), "{e}");
    }

    #[test]
    fn argon2id_official_test_vector_rfc9106() {
        // RFC 9106, section 5.3: checks that the crate really computes
        // Argon2id (version 0x13), including the secret input K.
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
        assert_eq!(hex(&out), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
    }

    /// Known answers for `derive_key` exactly as CakePass calls it, computed
    /// independently with the reference C implementation (libargon2, via
    /// argon2-cffi's `argon2_ctx`; the harness reproduces RFC 9106 first).
    #[test]
    fn derive_key_known_answers_from_the_reference_implementation() {
        let pw = b"correct horse battery staple";
        let salt = [1u8; 32];
        let pepper = KeyFilePepper(SecureBuf::from_slice(&[7u8; 32]));
        let k = |params: &KdfParams, kf| hex(derive_key(pw, &salt, params, kf).unwrap().as_bytes());
        assert_eq!(
            k(&TEST_PARAMS, Some(&pepper)),
            "c1e05057cdf708797898a69614e3aa5fbe8e8809679f9bb7b3c68669533748d2"
        );
        let four_lanes = KdfParams { memory_kib: 8 * 1024, iterations: 3, parallelism: 4 };
        assert_eq!(
            k(&four_lanes, Some(&pepper)),
            "c658c12d5de2e0fc88d217bedc8093fb9659bce951390f28af17f518b7fc1e93"
        );
        assert_eq!(k(&TEST_PARAMS, None), "b6b834c3d814088dcc07b04a691f100a20e2b11e30451e0af0eb208dd89c8f9a");
    }

    #[test]
    fn key_derivation_is_deterministic_and_salt_dependent() {
        let a = derive_key(b"password", &[1u8; 32], &TEST_PARAMS, None).unwrap();
        let b = derive_key(b"password", &[1u8; 32], &TEST_PARAMS, None).unwrap();
        let c = derive_key(b"password", &[2u8; 32], &TEST_PARAMS, None).unwrap();
        let d = derive_key(b"Password", &[1u8; 32], &TEST_PARAMS, None).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
        assert_ne!(a.as_bytes(), d.as_bytes());
        assert!(!format!("{a:?}").contains(&format!("{:?}", a.as_bytes())));
    }

    #[test]
    fn the_key_file_changes_the_key() {
        let one = KeyFilePepper::derive(b"key file one").unwrap();
        let two = KeyFilePepper::derive(b"key file two").unwrap();
        let k = |kf| derive_key(b"password", &[1u8; 32], &TEST_PARAMS, kf).unwrap();
        let (none, a, b) = (k(None), k(Some(&one)), k(Some(&two)));
        assert!(!none.ct_eq(&a) && !a.ct_eq(&b) && !none.ct_eq(&b));
        assert!(a.ct_eq(&k(Some(&KeyFilePepper::derive(b"key file one").unwrap()))), "deterministic");
    }

    #[test]
    fn key_file_pepper_known_answers_and_domain_separation() {
        // Computed independently with Python's hashlib.blake2b(digest_size=32).
        let p = KeyFilePepper::derive(b"cakepass test key file").unwrap();
        assert_eq!(p.hex_for_test(), "d632d9c2523c53df515b9c1508d774e932776c021b9469e5bcfb425e9ee10a4b");
        let bytes: Vec<u8> = (0..64).collect();
        let p = KeyFilePepper::derive(&bytes).unwrap();
        assert_eq!(p.hex_for_test(), "f3ba14597b3cd6320e31208df2fb444c71ee7c3bbcbd0389fab8e68a2d7eccf2");
        // Not the plain BLAKE2b-256 of the content: the label separates it.
        assert_ne!(p.hex_for_test(), "10d8e6d534b00939843fe9dcc4dae48cdf008f6b8b2b82b156f5404d874887f5");
        let one = KeyFilePepper::derive(b"\x00").unwrap();
        assert_eq!(one.hex_for_test(), "11a5df38f010873d897f33b637a7dce8e4108748628ceb15efd4c1b9fb6a86af");
        // Deterministic; every byte and the length count.
        assert!(p.ct_eq(&KeyFilePepper::derive(&bytes).unwrap()));
        let mut changed = bytes.clone();
        changed[63] ^= 1;
        assert!(!p.ct_eq(&KeyFilePepper::derive(&changed).unwrap()));
        assert!(!one.ct_eq(&KeyFilePepper::derive(b"\x00\x00").unwrap()));
        // Empty is refused; large content is fine; nothing leaks through Debug.
        assert!(matches!(KeyFilePepper::derive(b""), Err(Error::KeyFileInvalid(_))));
        assert!(KeyFilePepper::derive(&vec![0xAB; 1024 * 1024]).is_ok());
        assert_eq!(format!("{p:?}"), "KeyFilePepper([HIDDEN])");
    }

    #[test]
    fn measuring_takes_real_time() {
        let t = measure_unlock(&TEST_PARAMS).unwrap();
        assert!(t > Duration::ZERO && t < Duration::from_secs(30));
        assert!(measure_unlock(&KdfParams { memory_kib: 1, ..TEST_PARAMS }).is_err());
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
        assert_eq!(
            hex(&okm),
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
