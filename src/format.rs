//! Het versleutelde bestandsformaat (versie 1).
//!
//! BEVEILIGINGSKRITIEK. Indeling (alle getallen little-endian):
//!
//! ```text
//! offset  grootte  veld
//! 0       8        magic "KLUISVLT"
//! 8       2        formaatversie (u16) = 1
//! 10      1        KDF-id: 1 = Argon2id v1.3
//! 11      4        Argon2 geheugen in KiB (u32)
//! 15      4        Argon2 iteraties (u32)
//! 19      4        Argon2 parallelisme (u32)
//! 23      1        salt-lengte n (16..=64)
//! 24      n        salt
//! 24+n    1        AEAD-id: 1 = XChaCha20-Poly1305
//! 25+n    24       nonce
//! 49+n    rest     ciphertext || 16-byte Poly1305-tag
//! ```
//!
//! De volledige header (alles vóór de ciphertext) is de "associated data" van
//! de AEAD. Wie dus ook maar één bit in de header verandert (bijv. de
//! Argon2-parameters verlaagt), laat de authenticatie mislukken.
//!
//! Migraties: een nieuwe versie krijgt een eigen `decode_vN`; oude versies
//! blijven leesbaar en worden bij de volgende opslag in de nieuwste versie
//! geschreven.

use crate::crypto::{self, KdfParams, MasterKey, NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::secure_mem::SecureBuf;

pub const MAGIC: [u8; 8] = *b"KLUISVLT";
pub const CURRENT_VERSION: u16 = 1;
const KDF_ARGON2ID_V13: u8 = 1;
const AEAD_XCHACHA20_POLY1305: u8 = 1;
const MIN_SALT_LEN: usize = 16;
const MAX_SALT_LEN: usize = 64;
/// Grotere bestanden weigeren we (bescherming tegen geheugen-DoS).
pub const MAX_FILE_SIZE: usize = 64 * 1024 * 1024;

/// De onversleutelde header van een kluisbestand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u16,
    pub kdf: KdfParams,
    pub salt: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    /// Schrijf de header in het huidige formaat.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(49 + self.salt.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&CURRENT_VERSION.to_le_bytes());
        out.push(KDF_ARGON2ID_V13);
        out.extend_from_slice(&self.kdf.memory_kib.to_le_bytes());
        out.extend_from_slice(&self.kdf.iterations.to_le_bytes());
        out.extend_from_slice(&self.kdf.parallelism.to_le_bytes());
        out.push(u8::try_from(self.salt.len()).expect("salt is kort"));
        out.extend_from_slice(&self.salt);
        out.push(AEAD_XCHACHA20_POLY1305);
        out.extend_from_slice(&self.nonce);
        out
    }

    /// Lees een header. Geeft de header en het aantal header-bytes terug.
    ///
    /// Alle velden worden gecontroleerd vóórdat er dure Argon2-berekeningen
    /// gebeuren, zodat een kapot of kwaadaardig bestand netjes faalt.
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
            1 => decode_v1(&mut r),
            other => Err(Error::UnsupportedVersion(other)),
        }
    }
}

fn decode_v1(r: &mut Reader<'_>) -> Result<(Header, usize)> {
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
    let nonce: [u8; NONCE_LEN] = r.take(NONCE_LEN)?.try_into().expect("lengte klopt");
    Ok((Header { version: 1, kdf, salt, nonce }, r.pos))
}

/// Kleine, grenscontrolerende lezer.
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

/// Een ontgrendelde sleutel plus de parameters waarmee hij gemaakt is.
///
/// Hiermee kan de kluis opnieuw worden opgeslagen zonder het hoofdwachtwoord
/// nog eens te vragen. De sleutel wordt bij `Drop` gewist.
#[derive(Debug)]
pub struct VaultKey {
    key: MasterKey,
    kdf: KdfParams,
    salt: Vec<u8>,
}

impl VaultKey {
    /// Leid een nieuwe sleutel af met een nieuwe, willekeurige salt.
    pub fn create(password: &[u8], kdf: KdfParams) -> Result<VaultKey> {
        let salt = crypto::random_array::<SALT_LEN>()?.to_vec();
        let key = crypto::derive_key(password, &salt, &kdf)?;
        Ok(VaultKey { key, kdf, salt })
    }

    pub fn kdf(&self) -> KdfParams {
        self.kdf
    }
}

/// Versleutel `plaintext` tot een compleet kluisbestand.
/// Elke aanroep gebruikt een nieuwe, willekeurige nonce.
pub fn seal(vk: &VaultKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let header = Header {
        version: CURRENT_VERSION,
        kdf: vk.kdf,
        salt: vk.salt.clone(),
        nonce: crypto::random_array::<NONCE_LEN>()?,
    };
    let mut out = header.encode();
    let ct = crypto::encrypt(&vk.key, &header.nonce, &out, plaintext)?;
    out.extend_from_slice(&ct);
    if out.len() > MAX_FILE_SIZE {
        return Err(Error::TooLarge);
    }
    Ok(out)
}

/// Ontsleutel een kluisbestand met het hoofdwachtwoord.
pub fn open(data: &[u8], password: &[u8]) -> Result<(SecureBuf, VaultKey)> {
    let (header, header_len) = Header::decode(data)?;
    let ciphertext = &data[header_len..];
    if ciphertext.len() < TAG_LEN {
        return Err(Error::Truncated);
    }
    let key = crypto::derive_key(password, &header.salt, &header.kdf)?;
    let plaintext = crypto::decrypt(&key, &header.nonce, &data[..header_len], ciphertext)?;
    Ok((plaintext, VaultKey { key, kdf: header.kdf, salt: header.salt }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: KdfParams = KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 };

    fn sample() -> (Vec<u8>, &'static [u8]) {
        let vk = VaultKey::create(b"juist wachtwoord", P).unwrap();
        (seal(&vk, b"{\"inhoud\":1}").unwrap(), b"juist wachtwoord")
    }

    #[test]
    fn header_heen_en_terug() {
        let h = Header { version: 1, kdf: KdfParams::DEFAULT, salt: vec![9; 32], nonce: [5; 24] };
        let bytes = h.encode();
        assert_eq!(bytes.len(), 49 + 32);
        let (back, len) = Header::decode(&bytes).unwrap();
        assert_eq!(back, h);
        assert_eq!(len, bytes.len());
    }

    #[test]
    fn opslaan_en_openen() {
        let (file, pw) = sample();
        let (pt, vk) = open(&file, pw).unwrap();
        assert_eq!(pt.as_slice(), b"{\"inhoud\":1}");
        assert_eq!(vk.kdf(), P);
        // Opnieuw opslaan met dezelfde sleutel gebruikt een nieuwe nonce.
        let again = seal(&vk, pt.as_slice()).unwrap();
        assert_ne!(again, file);
        assert_eq!(open(&again, pw).unwrap().0.as_slice(), pt.as_slice());
    }

    #[test]
    fn verkeerd_wachtwoord_faalt_altijd() {
        let (file, _) = sample();
        for pw in [&b"fout"[..], b"", b"juist wachtwoord ", b"Juist wachtwoord"] {
            assert!(matches!(open(&file, pw), Err(Error::Decrypt)));
        }
    }

    #[test]
    fn elke_bitflip_in_het_bestand_faalt() {
        let (file, pw) = sample();
        for i in 0..file.len() {
            let mut bad = file.clone();
            bad[i] ^= 0x01;
            assert!(open(&bad, pw).is_err(), "bitflip op byte {i} werd niet opgemerkt");
        }
    }

    #[test]
    fn kapotte_bestanden_geven_nette_fouten() {
        let (file, pw) = sample();
        assert!(matches!(open(b"", pw), Err(Error::Truncated)));
        assert!(matches!(open(b"KLUIS", pw), Err(Error::Truncated)));
        assert!(matches!(open(b"geen kluis maar tekst die lang genoeg is", pw), Err(Error::NotAVault)));
        // Elke afgekapte lengte faalt.
        for len in 0..file.len() {
            assert!(open(&file[..len], pw).is_err(), "afgekapt op {len} werd geaccepteerd");
        }
        // Extra bytes achteraan faalt ook (de tag klopt dan niet meer).
        let mut longer = file.clone();
        longer.push(0);
        assert!(matches!(open(&longer, pw), Err(Error::Decrypt)));
    }

    #[test]
    fn onbekende_versie_en_algoritme() {
        let (file, pw) = sample();
        let mut v = file.clone();
        v[8] = 2;
        assert!(matches!(open(&v, pw), Err(Error::UnsupportedVersion(2))));
        let mut k = file.clone();
        k[10] = 9;
        assert!(matches!(open(&k, pw), Err(Error::UnsupportedAlgorithm)));
        let mut a = file.clone();
        a[24 + 32] = 9;
        assert!(matches!(open(&a, pw), Err(Error::UnsupportedAlgorithm)));
    }

    #[test]
    fn gemanipuleerde_kdf_parameters_worden_geweigerd_of_falen() {
        let (file, pw) = sample();
        // Geheugen verlagen naar 1 MiB: geweigerd vóór Argon2 draait.
        let mut low = file.clone();
        low[11..15].copy_from_slice(&1024u32.to_le_bytes());
        assert!(matches!(open(&low, pw), Err(Error::InvalidKdfParams(_))));
        // Absurd veel geheugen: geweigerd (geen DoS).
        let mut huge = file.clone();
        huge[11..15].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(open(&huge, pw), Err(Error::InvalidKdfParams(_))));
        // Geldige maar andere waarde: andere sleutel, dus authenticatie faalt.
        let mut other = file.clone();
        other[15..19].copy_from_slice(&2u32.to_le_bytes());
        assert!(matches!(open(&other, pw), Err(Error::Decrypt)));
    }

    #[test]
    fn te_groot_bestand() {
        let big = vec![0u8; MAX_FILE_SIZE + 1];
        assert!(matches!(Header::decode(&big), Err(Error::TooLarge)));
    }

    #[test]
    fn verschillende_kluizen_krijgen_verschillende_salt() {
        let a = VaultKey::create(b"x", P).unwrap();
        let b = VaultKey::create(b"x", P).unwrap();
        assert_ne!(a.salt, b.salt);
    }
}
