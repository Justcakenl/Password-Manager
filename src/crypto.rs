//! Cryptografie: sleutelafleiding en authenticated encryption.
//!
//! BEVEILIGINGSKRITIEK. We implementeren hier zelf GEEN primitieven; we
//! gebruiken alleen de door experts geschreven en geaudite RustCrypto-crates:
//!
//! - **Argon2id** (`argon2`): maakt van het hoofdwachtwoord + een willekeurige
//!   salt een sleutel van 256 bits. Argon2id is bewust traag en gebruikt veel
//!   geheugen, zodat raden met GPU's duur wordt.
//! - **XChaCha20-Poly1305** (`chacha20poly1305`): versleutelt én authenticeert.
//!   Elke wijziging aan het bestand (ook aan de header, die als "associated
//!   data" meedoet) maakt het ontsleutelen onmogelijk. De 24-byte nonce is zo
//!   groot dat een willekeurige nonce per schrijfactie veilig is.
//! - Willekeur komt alleen van de OS-CSPRNG (`getrandom`, op Linux de
//!   `getrandom(2)`-systeemaanroep).

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use crate::error::{Error, Result};
use crate::secure_mem::SecureBuf;

/// Lengte van de afgeleide sleutel (256 bits).
pub const KEY_LEN: usize = 32;
/// Lengte van de salt die we bij nieuwe kluizen gebruiken.
pub const SALT_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce-lengte.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag-lengte.
pub const TAG_LEN: usize = 16;

/// Instelbare Argon2id-parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Geheugengebruik in KiB.
    pub memory_kib: u32,
    /// Aantal passes (t).
    pub iterations: u32,
    /// Aantal parallelle lanes (p).
    pub parallelism: u32,
}

impl KdfParams {
    /// Standaard: 64 MiB, t=3, p=4 (zoals gevraagd; sterker dan het OWASP-minimum).
    pub const DEFAULT: KdfParams = KdfParams { memory_kib: 64 * 1024, iterations: 3, parallelism: 4 };
    /// Ondergrens die we accepteren (8 MiB). Lager is te zwak.
    pub const MIN_MEMORY_KIB: u32 = 8 * 1024;
    /// Bovengrens (4 GiB), zodat een gemanipuleerde header geen geheugen-DoS geeft.
    pub const MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024;
    pub const MAX_ITERATIONS: u32 = 64;
    pub const MAX_PARALLELISM: u32 = 64;

    /// Controleer of de parameters binnen veilige grenzen liggen.
    pub fn validate(&self) -> Result<()> {
        if self.memory_kib < Self::MIN_MEMORY_KIB {
            return Err(Error::InvalidKdfParams("geheugen moet minstens 8 MiB zijn"));
        }
        if self.memory_kib > Self::MAX_MEMORY_KIB {
            return Err(Error::InvalidKdfParams("geheugen mag hoogstens 4096 MiB zijn"));
        }
        if self.iterations == 0 || self.iterations > Self::MAX_ITERATIONS {
            return Err(Error::InvalidKdfParams("iteraties moeten tussen 1 en 64 liggen"));
        }
        if self.parallelism == 0 || self.parallelism > Self::MAX_PARALLELISM {
            return Err(Error::InvalidKdfParams("parallelisme moet tussen 1 en 64 liggen"));
        }
        // Argon2 eist minstens 8 KiB per lane.
        if self.memory_kib < 8 * self.parallelism {
            return Err(Error::InvalidKdfParams("te weinig geheugen voor dit parallelisme"));
        }
        Ok(())
    }

    /// Of deze parameters zwakker zijn dan de standaard (voor een waarschuwing).
    pub fn weaker_than_default(&self) -> bool {
        self.memory_kib < Self::DEFAULT.memory_kib || self.iterations < Self::DEFAULT.iterations
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// De 256-bit sleutel, in vergrendeld geheugen dat bij opruimen gewist wordt.
pub struct MasterKey(SecureBuf);

impl MasterKey {
    fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Maak een sleutel van ruwe bytes (alleen voor tests).
    #[cfg(test)]
    pub(crate) fn from_bytes_for_test(bytes: &[u8; KEY_LEN]) -> Self {
        MasterKey(SecureBuf::from_slice(bytes))
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey([VERBORGEN])")
    }
}

/// Vul een buffer met cryptografisch veilige willekeurige bytes van het OS.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Rng)
}

/// Geef `N` willekeurige bytes terug.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill_random(&mut out)?;
    Ok(out)
}

/// Leid met Argon2id een sleutel af uit wachtwoord en salt.
pub fn derive_key(password: &[u8], salt: &[u8], params: &KdfParams) -> Result<MasterKey> {
    params.validate()?;
    let argon_params = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(KEY_LEN))
        .map_err(|_| Error::InvalidKdfParams("geweigerd door Argon2"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = SecureBuf::zeroed(KEY_LEN);
    argon.hash_password_into(password, salt, key.as_mut_slice()).map_err(|_| Error::Kdf)?;
    Ok(MasterKey(key))
}

fn cipher(key: &MasterKey) -> XChaCha20Poly1305 {
    // De cipher-struct bevat een kopie van de sleutel en wist die zelf bij Drop.
    XChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("sleutel is 32 bytes")
}

/// Versleutel `plaintext`. Geeft `ciphertext || tag` terug.
///
/// `aad` (associated data) wordt niet versleuteld maar wel geauthenticeerd.
pub fn encrypt(key: &MasterKey, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    // We versleutelen "in place": de buffer bevat heel even de klare tekst en
    // wordt daarna direct overschreven met de ciphertext.
    let mut buf = Vec::with_capacity(plaintext.len() + TAG_LEN);
    buf.extend_from_slice(plaintext);
    let nonce = XNonce::from(*nonce);
    let tag = cipher(key)
        .encrypt_inout_detached(&nonce, aad, buf.as_mut_slice().into())
        .map_err(|_| Error::Encrypt)?;
    buf.extend_from_slice(tag.as_slice());
    Ok(buf)
}

/// Ontsleutel en controleer `ciphertext || tag`.
///
/// De klare tekst komt in een [`SecureBuf`]. Bij een verkeerde sleutel of
/// welke wijziging dan ook faalt dit met [`Error::Decrypt`]; de tag-controle
/// in de crate is constant-time.
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

    /// Snelle parameters voor tests (sterkte is hier niet relevant).
    pub(crate) const TEST_PARAMS: KdfParams =
        KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 };

    #[test]
    fn standaardparameters_zijn_geldig() {
        KdfParams::DEFAULT.validate().unwrap();
        assert_eq!(KdfParams::DEFAULT.memory_kib, 65536);
        assert_eq!(KdfParams::DEFAULT.iterations, 3);
        assert_eq!(KdfParams::DEFAULT.parallelism, 4);
        assert!(!KdfParams::DEFAULT.weaker_than_default());
        assert!(TEST_PARAMS.weaker_than_default());
    }

    #[test]
    fn ongeldige_parameters_worden_geweigerd() {
        let p = |m, t, par| KdfParams { memory_kib: m, iterations: t, parallelism: par };
        assert!(p(1024, 3, 4).validate().is_err());
        assert!(p(u32::MAX, 3, 4).validate().is_err());
        assert!(p(65536, 0, 4).validate().is_err());
        assert!(p(65536, 1000, 4).validate().is_err());
        assert!(p(65536, 3, 0).validate().is_err());
        assert!(p(65536, 3, 1000).validate().is_err());
    }

    #[test]
    fn argon2id_officiele_testvector_rfc9106() {
        // RFC 9106, paragraaf 5.3: controleert dat de crate echt Argon2id
        // (versie 0x13) berekent.
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
    fn sleutelafleiding_is_deterministisch_en_salt_afhankelijk() {
        let a = derive_key(b"wachtwoord", &[1u8; 32], &TEST_PARAMS).unwrap();
        let b = derive_key(b"wachtwoord", &[1u8; 32], &TEST_PARAMS).unwrap();
        let c = derive_key(b"wachtwoord", &[2u8; 32], &TEST_PARAMS).unwrap();
        let d = derive_key(b"Wachtwoord", &[1u8; 32], &TEST_PARAMS).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
        assert_ne!(a.as_bytes(), d.as_bytes());
        assert!(!format!("{a:?}").contains(&format!("{:?}", a.as_bytes())));
    }

    #[test]
    fn versleutelen_en_ontsleutelen() {
        let key = MasterKey::from_bytes_for_test(&[7u8; 32]);
        let nonce = random_array::<NONCE_LEN>().unwrap();
        let ct = encrypt(&key, &nonce, b"header", b"geheime data").unwrap();
        assert_eq!(ct.len(), b"geheime data".len() + TAG_LEN);
        assert!(!ct.windows(6).any(|w| w == b"geheim"));
        let pt = decrypt(&key, &nonce, b"header", &ct).unwrap();
        assert_eq!(pt.as_slice(), b"geheime data");
    }

    #[test]
    fn elke_wijziging_faalt() {
        let key = MasterKey::from_bytes_for_test(&[7u8; 32]);
        let other = MasterKey::from_bytes_for_test(&[8u8; 32]);
        let nonce = [3u8; NONCE_LEN];
        let ct = encrypt(&key, &nonce, b"aad", b"inhoud").unwrap();

        // Verkeerde sleutel.
        assert!(matches!(decrypt(&other, &nonce, b"aad", &ct), Err(Error::Decrypt)));
        // Andere associated data (= gemanipuleerde header).
        assert!(matches!(decrypt(&key, &nonce, b"aaD", &ct), Err(Error::Decrypt)));
        // Andere nonce.
        assert!(matches!(decrypt(&key, &[4u8; NONCE_LEN], b"aad", &ct), Err(Error::Decrypt)));
        // Elke afzonderlijke bitflip in ciphertext of tag.
        for i in 0..ct.len() {
            for bit in 0..8 {
                let mut bad = ct.clone();
                bad[i] ^= 1 << bit;
                assert!(matches!(decrypt(&key, &nonce, b"aad", &bad), Err(Error::Decrypt)));
            }
        }
        // Afgekapt.
        assert!(decrypt(&key, &nonce, b"aad", &ct[..ct.len() - 1]).is_err());
        assert!(matches!(decrypt(&key, &nonce, b"aad", &ct[..5]), Err(Error::Truncated)));
    }

    #[test]
    fn nonces_zijn_willekeurig() {
        let a = random_array::<NONCE_LEN>().unwrap();
        let b = random_array::<NONCE_LEN>().unwrap();
        assert_ne!(a, b);
    }
}
