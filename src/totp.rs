//! TOTP: the six-digit codes of two-factor authentication (2FA), as made by
//! Google Authenticator, Aegis and the like.
//!
//! SECURITY-CRITICAL. What is implemented here, and what is not:
//!
//! - **TOTP** (RFC 6238) on top of **HOTP** (RFC 4226): the code for a moment
//!   is `HOTP(secret, floor(unix_time / period))`, and HOTP is an HMAC of the
//!   8-byte big-endian counter, "dynamically truncated" to 31 bits and
//!   written as `digits` decimal digits.
//! - The HMAC itself (HMAC-SHA1, and HMAC-SHA256/-SHA512 when an
//!   `otpauth://` URI asks for them) comes from the RustCrypto crates `hmac`,
//!   `sha1` and `sha2`. As everywhere in CakePass, we do NOT implement
//!   cryptographic primitives ourselves; their `zeroize` features wipe the
//!   hash states (which hold the secret) when they are dropped.
//! - **Base32** (RFC 4648) is decoded here by hand. It is a plain encoding,
//!   not cryptography: about twenty lines, tested against the RFC's own
//!   examples, instead of one more dependency.
//!
//! What is stored in the vault is the *secret* as the site gave it (a base32
//! string, or a complete `otpauth://totp/…` URI), encrypted like every other
//! field. A computed code is never stored or cached: it is computed fresh
//! from the decrypted secret every time one is asked for, and the decrypted
//! secret, the HMAC output and the code all live in memory that is wiped
//! when dropped.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

/// Digits of a code when the site does not say (RFC 6238; every app uses 6).
pub const DEFAULT_DIGITS: u32 = 6;
/// Seconds a code is valid when the site does not say (RFC 6238).
pub const DEFAULT_PERIOD: u64 = 30;
/// Longest input we accept (a base32 secret or an `otpauth://` URI).
const MAX_INPUT_LEN: usize = 4096;
/// Allowed numbers of digits. RFC 4226 requires at least 6; the 31-bit
/// truncated value has 10 digits at most, and nobody uses more than 8.
const DIGITS_RANGE: std::ops::RangeInclusive<u32> = 6..=8;
/// Allowed periods in seconds (a sanity bound; sites use 30 or 60).
const PERIOD_RANGE: std::ops::RangeInclusive<u64> = 1..=3600;

/// The hash function behind the HMAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// HMAC-SHA1: the default of RFC 6238 and what nearly every site uses.
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    /// Read the `algorithm` parameter of an `otpauth://` URI.
    fn parse(s: &str) -> Option<Algorithm> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" | "SHA-1" => Some(Algorithm::Sha1),
            "SHA256" | "SHA-256" => Some(Algorithm::Sha256),
            "SHA512" | "SHA-512" => Some(Algorithm::Sha512),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }
}

/// A parsed TOTP secret with its settings. The secret bytes are wiped when
/// this is dropped; `Debug` never shows them.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Totp {
    secret: Vec<u8>,
    #[zeroize(skip)]
    algorithm: Algorithm,
    digits: u32,
    period: u64,
}

/// One computed code and how long it is still valid. Wiped when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TotpCode {
    code: String,
    seconds_left: u64,
}

impl TotpCode {
    /// The code, e.g. "287082".
    pub fn as_str(&self) -> &str {
        &self.code
    }

    /// Seconds until the next code (1 ..= period).
    pub fn seconds_left(&self) -> u64 {
        self.seconds_left
    }
}

impl std::fmt::Debug for TotpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpCode([HIDDEN])")
    }
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("secret", &"[HIDDEN]")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish()
    }
}

fn invalid(msg: &str) -> Error {
    Error::InvalidInput(msg.into())
}

impl Totp {
    /// A TOTP secret with explicit settings (validated).
    pub fn new(secret: &[u8], algorithm: Algorithm, digits: u32, period: u64) -> Result<Totp> {
        if secret.is_empty() {
            return Err(invalid("the TOTP secret is empty"));
        }
        if !DIGITS_RANGE.contains(&digits) {
            return Err(invalid("a TOTP code must have 6, 7 or 8 digits"));
        }
        if !PERIOD_RANGE.contains(&period) {
            return Err(invalid("the TOTP period must be between 1 and 3600 seconds"));
        }
        Ok(Totp { secret: secret.to_vec(), algorithm, digits, period })
    }

    /// Read what a site gives you: a base32 secret (spaces allowed, any
    /// case, padding optional), or an `otpauth://totp/…?secret=…` URI with
    /// optional `algorithm`, `digits` and `period` (default SHA1, 6, 30).
    ///
    /// Error messages never contain (a part of) the secret.
    pub fn parse(input: &str) -> Result<Totp> {
        let input = input.trim();
        if input.len() > MAX_INPUT_LEN {
            return Err(invalid("the TOTP secret is too long"));
        }
        if input.get(..10).is_some_and(|p| p.eq_ignore_ascii_case("otpauth://")) {
            return Self::parse_uri(&input[10..]);
        }
        let secret = decode_secret(input)?;
        Totp::new(&secret, Algorithm::Sha1, DEFAULT_DIGITS, DEFAULT_PERIOD)
    }

    /// The part of an `otpauth://` URI after the scheme.
    fn parse_uri(rest: &str) -> Result<Totp> {
        let otp_type = rest.split(['/', '?']).next().unwrap_or("");
        if !otp_type.eq_ignore_ascii_case("totp") {
            return Err(invalid(
                "only time-based codes (otpauth://totp/…) are supported, not counter-based (hotp) ones",
            ));
        }
        let query = rest.split_once('?').map_or("", |(_, q)| q);
        let query = query.split('#').next().unwrap_or("");
        let mut secret: Option<Zeroizing<Vec<u8>>> = None;
        let (mut algorithm, mut digits, mut period) = (Algorithm::Sha1, DEFAULT_DIGITS, DEFAULT_PERIOD);
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (name, raw) = pair.split_once('=').unwrap_or((pair, ""));
            let value = percent_decode(raw).ok_or_else(|| invalid("the otpauth:// URI is not valid"))?;
            match name.to_ascii_lowercase().as_str() {
                "secret" => {
                    if secret.is_some() {
                        return Err(invalid("the otpauth:// URI has more than one secret"));
                    }
                    secret = Some(decode_secret(&value)?);
                }
                "algorithm" => {
                    algorithm = Algorithm::parse(&value)
                        .ok_or_else(|| invalid("unknown TOTP algorithm; SHA1, SHA256 or SHA512 work"))?;
                }
                "digits" => {
                    digits = value.parse().map_err(|_| invalid("the TOTP digits must be a number"))?;
                }
                "period" => {
                    period = value.parse().map_err(|_| invalid("the TOTP period must be a number"))?;
                }
                // issuer, image, … say nothing about the code.
                _ => {}
            }
        }
        let secret = secret.ok_or_else(|| invalid("the otpauth:// URI has no secret"))?;
        Totp::new(&secret, algorithm, digits, period)
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    pub fn digits(&self) -> u32 {
        self.digits
    }
    pub fn period(&self) -> u64 {
        self.period
    }

    /// The code for `unix_time` (seconds since 1970, UTC), with T0 = 0.
    pub fn code_at(&self, unix_time: u64) -> TotpCode {
        let counter = unix_time / self.period;
        let code = hotp(&self.secret, counter, self.digits, self.algorithm);
        TotpCode { code: code.to_string(), seconds_left: self.period - unix_time % self.period }
    }

    /// The code for this moment.
    pub fn now(&self) -> TotpCode {
        let t = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        self.code_at(t)
    }
}

/// HMAC(`key`, `msg`) with the chosen hash, into memory that is wiped.
fn hmac(algorithm: Algorithm, key: &[u8], msg: &[u8]) -> Zeroizing<Vec<u8>> {
    fn run<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut mac = <M as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
        mac.update(msg);
        let mut out = mac.finalize().into_bytes();
        let copy = Zeroizing::new(out.to_vec());
        out.as_mut_slice().zeroize();
        copy
    }
    match algorithm {
        Algorithm::Sha1 => run::<Hmac<sha1::Sha1>>(key, msg),
        Algorithm::Sha256 => run::<Hmac<sha2::Sha256>>(key, msg),
        Algorithm::Sha512 => run::<Hmac<sha2::Sha512>>(key, msg),
    }
}

/// HOTP (RFC 4226, section 5.3): HMAC of the big-endian counter, dynamic
/// truncation to 31 bits, the last `digits` decimal digits (zero-padded).
pub fn hotp(secret: &[u8], counter: u64, digits: u32, algorithm: Algorithm) -> Zeroizing<String> {
    let mac = hmac(algorithm, secret, &counter.to_be_bytes());
    // The low 4 bits of the last byte choose where the 4 bytes are taken from.
    let offset = usize::from(mac[mac.len() - 1] & 0x0f);
    let mut binary =
        u32::from_be_bytes([mac[offset], mac[offset + 1], mac[offset + 2], mac[offset + 3]]) & 0x7fff_ffff;
    let mut code = binary % 10u32.pow(digits);
    let text = Zeroizing::new(format!("{code:0width$}", width = digits as usize));
    binary.zeroize();
    code.zeroize();
    text
}

/// A base32 secret as sites show it: spaces between the groups are left
/// out, case does not matter. Must decode to at least one byte.
fn decode_secret(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    let compact: Zeroizing<String> = Zeroizing::new(text.chars().filter(|c| *c != ' ').collect());
    let bytes = base32_decode(&compact)
        .ok_or_else(|| invalid("the TOTP secret is not valid base32 (the letters A–Z and the digits 2–7)"))?;
    if bytes.is_empty() {
        return Err(invalid("the TOTP secret is empty"));
    }
    Ok(bytes)
}

/// Decode base32 (RFC 4648, section 6: the alphabet A–Z, 2–7), in either
/// case, with or without the `=` padding. `None` for anything else: other
/// characters, a length no encoder can produce, or wrong padding.
pub fn base32_decode(input: &str) -> Option<Zeroizing<Vec<u8>>> {
    let body = input.trim_end_matches('=');
    let pad = input.len() - body.len();
    // Unpadded input ends in a group of 0, 2, 4, 5 or 7 characters; with
    // padding the group is filled up to 8 with exactly that many '='.
    const PAD_FOR: [Option<usize>; 8] = [Some(0), None, Some(6), None, Some(4), Some(3), None, Some(1)];
    let expected = PAD_FOR[body.len() % 8]?;
    if pad != 0 && pad != expected {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() * 5 / 8));
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    for c in body.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u64::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    buffer.zeroize();
    Some(out)
}

/// `%XX` escapes in a URI query value (`+` is left as it is: base32 and the
/// parameter values never contain one).
fn percent_decode(s: &str) -> Option<Zeroizing<String>> {
    let bytes = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let text = std::str::from_utf8(&out).ok()?;
    Some(Zeroizing::new(text.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_SHA1: &[u8] = b"12345678901234567890";
    const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn totp_official_test_vectors_rfc6238() {
        // RFC 6238, Appendix B: 8 digits, period 30, T0 = 0, with the
        // RFC's seeds (the ASCII digits "1234567890" repeated to the hash's
        // size). The time, then the expected code for SHA1, SHA256, SHA512.
        let vectors: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        let sha1 = Totp::new(SEED_SHA1, Algorithm::Sha1, 8, 30).unwrap();
        let sha256 = Totp::new(SEED_SHA256, Algorithm::Sha256, 8, 30).unwrap();
        let sha512 = Totp::new(SEED_SHA512, Algorithm::Sha512, 8, 30).unwrap();
        for (t, c1, c256, c512) in vectors {
            assert_eq!(sha1.code_at(t).as_str(), c1, "SHA1 at {t}");
            assert_eq!(sha256.code_at(t).as_str(), c256, "SHA256 at {t}");
            assert_eq!(sha512.code_at(t).as_str(), c512, "SHA512 at {t}");
        }
    }

    #[test]
    fn hotp_official_test_vectors_rfc4226() {
        // RFC 4226, Appendix D: 6 digits, HMAC-SHA1, counters 0 to 9.
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
            "520489",
        ];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(hotp(SEED_SHA1, counter as u64, 6, Algorithm::Sha1).as_str(), *code, "{counter}");
        }
    }

    #[test]
    fn base32_official_test_vectors_rfc4648() {
        // RFC 4648, section 10.
        let vectors = [
            ("", ""),
            ("MY======", "f"),
            ("MZXQ====", "fo"),
            ("MZXW6===", "foo"),
            ("MZXW6YQ=", "foob"),
            ("MZXW6YTB", "fooba"),
            ("MZXW6YTBOI======", "foobar"),
        ];
        for (encoded, plain) in vectors {
            assert_eq!(base32_decode(encoded).unwrap().as_slice(), plain.as_bytes(), "{encoded}");
            // Padding is optional and case does not matter.
            let bare = encoded.trim_end_matches('=');
            assert_eq!(base32_decode(bare).unwrap().as_slice(), plain.as_bytes(), "{bare}");
            assert_eq!(base32_decode(&bare.to_lowercase()).unwrap().as_slice(), plain.as_bytes());
        }
        // The RFC 6238 seed in base32, as an authenticator app would get it.
        assert_eq!(base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap().as_slice(), SEED_SHA1);
    }

    #[test]
    fn invalid_base32_is_refused() {
        for bad in [
            "MZXW6YT1", // 1 is not in the alphabet
            "MZXW6YT8", // nor 8, 0 or 9
            "MZXW0YTB",
            "MZ XW", // spaces are only taken out by `parse`
            "M",     // a length no encoder makes (1, 3 or 6 in the last group)
            "MZX",
            "MZXW6Y",
            "MY=", // wrong amount of padding
            "MY=======",
            "MZXW6YQ==",
            "MY==MY==", // padding in the middle
            "MZXW6YTB=",
        ] {
            assert!(base32_decode(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn parse_a_base32_secret_as_sites_show_it() {
        let t = Totp::parse("  gezd gnbv gy3t qojq gezd gnbv gy3t qojq ").unwrap();
        assert_eq!((t.algorithm(), t.digits(), t.period()), (Algorithm::Sha1, 6, 30), "RFC 6238 defaults");
        assert_eq!(t.code_at(59).as_str(), "287082", "RFC 6238 seed, 6 digits: counter 1 of RFC 4226");
        assert_eq!(t.code_at(59).seconds_left(), 1);
        assert_eq!(t.code_at(60).seconds_left(), 30);
        assert_eq!(t.code_at(0).as_str(), "755224");
        for bad in ["", "   ", "====", "not base32!", "GEZDGNBV1"] {
            let e = Totp::parse(bad).unwrap_err();
            assert!(matches!(e, Error::InvalidInput(_)), "{bad}");
        }
        assert!(Totp::parse(&"A".repeat(5000)).is_err(), "too long");
    }

    #[test]
    fn parse_otpauth_uris() {
        let seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let t =
            Totp::parse(&format!("otpauth://totp/Example:alice@example.org?secret={seed}&issuer=Example"))
                .unwrap();
        assert_eq!((t.algorithm(), t.digits(), t.period()), (Algorithm::Sha1, 6, 30));
        assert_eq!(t.code_at(59).as_str(), "287082");
        // Every parameter, in any case and order; the RFC 6238 SHA256 vector.
        let seed256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA%3D%3D%3D%3D";
        let t =
            Totp::parse(&format!("OTPAUTH://TOTP/x?Period=30&DIGITS=8&algorithm=sha256&secret={seed256}"))
                .unwrap();
        assert_eq!((t.algorithm(), t.digits(), t.period()), (Algorithm::Sha256, 8, 30));
        assert_eq!(t.code_at(1_234_567_890).as_str(), "91819424");
        let t = Totp::parse(&format!("otpauth://totp/?secret={seed}&period=60")).unwrap();
        assert_eq!(t.code_at(119).as_str(), "287082", "period 60: counter 1");
        assert_eq!(t.code_at(119).seconds_left(), 1);
        for bad in [
            format!("otpauth://hotp/x?secret={seed}&counter=1"),
            "otpauth://totp/x?issuer=nobody".to_string(),
            format!("otpauth://totp/x?secret={seed}&secret={seed}"),
            format!("otpauth://totp/x?secret={seed}&algorithm=MD5"),
            format!("otpauth://totp/x?secret={seed}&digits=5"),
            format!("otpauth://totp/x?secret={seed}&digits=9"),
            format!("otpauth://totp/x?secret={seed}&digits=six"),
            format!("otpauth://totp/x?secret={seed}&period=0"),
            format!("otpauth://totp/x?secret={seed}%"),
            "otpauth://totp/x?secret=".to_string(),
            "otpauth://totp/x?secret=111".to_string(),
        ] {
            assert!(matches!(Totp::parse(&bad), Err(Error::InvalidInput(_))), "{bad}");
        }
    }

    #[test]
    fn errors_and_debug_never_show_the_secret() {
        let secret = "JBSWY3DPEHPK3PXP";
        let t = Totp::parse(secret).unwrap();
        assert!(!format!("{t:?}").contains(secret));
        assert_eq!(format!("{:?}", t.now()), "TotpCode([HIDDEN])");
        let e = Totp::parse(&format!("{secret}1")).unwrap_err().to_string();
        assert!(!e.contains(secret), "{e}");
        let now = t.now();
        assert_eq!(now.as_str().len(), 6);
        assert!(now.as_str().chars().all(|c| c.is_ascii_digit()));
        assert!((1..=30).contains(&now.seconds_left()));
    }
}
