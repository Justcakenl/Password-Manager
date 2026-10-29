//! Eén fouttype voor de hele bibliotheek.
//!
//! BEVEILIGING: foutmeldingen bevatten nooit wachtwoorden, sleutels of
//! ontsleutelde inhoud. Een verkeerd wachtwoord en een gemanipuleerd bestand
//! geven bewust exact dezelfde melding, zodat een aanvaller er niets uit leert.

use std::path::PathBuf;

/// Resultaat-type voor de hele bibliotheek.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("dit is geen kluisbestand (onbekende bestandskop)")]
    NotAVault,

    #[error("het kluisbestand is te kort of afgekapt")]
    Truncated,

    #[error("bestandsversie {0} wordt niet ondersteund; gebruik een nieuwere versie van kluis")]
    UnsupportedVersion(u16),

    #[error("het kluisbestand gebruikt een onbekend algoritme")]
    UnsupportedAlgorithm,

    #[error("ongeldige parameters voor sleutelafleiding: {0}")]
    InvalidKdfParams(&'static str),

    #[error("ontsleutelen mislukt: verkeerd hoofdwachtwoord, of het bestand is beschadigd of gemanipuleerd")]
    Decrypt,

    #[error("het bestand is te groot om een kluis te zijn")]
    TooLarge,

    #[error("de inhoud van de kluis is ongeldig")]
    CorruptPayload,

    #[error("sleutelafleiding (Argon2id) mislukt")]
    Kdf,

    #[error("versleutelen mislukt")]
    Encrypt,

    #[error("het besturingssysteem kon geen willekeurige getallen leveren")]
    Rng,

    #[error("er bestaat nog geen kluis op {0}. Maak er een met `kluis init`.")]
    VaultNotFound(PathBuf),

    #[error("er bestaat al een bestand op {0}; ik overschrijf het niet")]
    AlreadyExists(PathBuf),

    #[error("de kluis is intussen door een ander kluis-proces gewijzigd; probeer het opnieuw")]
    ConcurrentModification,

    #[error("geen item gevonden met de naam '{0}'")]
    EntryNotFound(String),

    #[error("er bestaat al een item met de naam '{0}'")]
    EntryExists(String),

    #[error("ongeldige invoer: {0}")]
    InvalidInput(String),

    #[error("bestandsfout: {0}")]
    Io(#[from] std::io::Error),
}
