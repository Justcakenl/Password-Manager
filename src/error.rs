//! A single error type for the whole library.
//!
//! SECURITY: error messages never contain passwords, keys or decrypted
//! content. A wrong password and a tampered file deliberately produce exactly
//! the same message, so an attacker learns nothing from it.

use std::path::PathBuf;

/// Result type used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("this is not a vault file (unknown file header)")]
    NotAVault,

    #[error("the vault file is too short or truncated")]
    Truncated,

    #[error("file version {0} is not supported; use a newer version of kluis")]
    UnsupportedVersion(u16),

    #[error("the vault file uses an unknown algorithm")]
    UnsupportedAlgorithm,

    #[error("invalid key derivation parameters: {0}")]
    InvalidKdfParams(&'static str),

    #[error("decryption failed: wrong master password, or the file is damaged or has been tampered with")]
    Decrypt,

    #[error("the file is too large to be a vault")]
    TooLarge,

    #[error("the contents of the vault are invalid")]
    CorruptPayload,

    #[error("key derivation (Argon2id) failed")]
    Kdf,

    #[error("encryption failed")]
    Encrypt,

    #[error("the operating system could not provide random numbers")]
    Rng,

    #[error("there is no vault at {0} yet. Create one with `kluis setup`.")]
    VaultNotFound(PathBuf),

    #[error("a file already exists at {0}; I will not overwrite it")]
    AlreadyExists(PathBuf),

    #[error("the vault was changed by another kluis process in the meantime; try again")]
    ConcurrentModification,

    #[error("no item found with the name '{0}'")]
    EntryNotFound(String),

    #[error("an item named '{0}' already exists")]
    EntryExists(String),

    #[error(
        "no clipboard tool found. Install wl-clipboard (Wayland) or xclip (X11), \
         or use --show to print it on screen"
    )]
    NoClipboard,

    #[error("cancelled")]
    Cancelled,

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("file error: {0}")]
    Io(#[from] std::io::Error),
}
