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

    #[error("file version {0} is not supported; use a newer version of cakepass")]
    UnsupportedVersion(u16),

    #[error("the vault file uses an unknown algorithm")]
    UnsupportedAlgorithm,

    #[error(
        "the vault file uses a feature this version of cakepass does not know; use a newer version of cakepass"
    )]
    UnsupportedFeature,

    #[error("invalid key derivation parameters: {0}")]
    InvalidKdfParams(&'static str),

    #[error("{}", not_enough_memory(*.argon_mib, *.needed_mib, *.available_mib, *.unlocking))]
    NotEnoughMemory {
        /// What Argon2 itself allocates.
        argon_mib: u64,
        /// The free memory needed for that (Argon2 may use at most 75 % of it).
        needed_mib: u64,
        /// What the kernel reports as available right now.
        available_mib: u64,
        /// Opening an existing vault (true) or choosing a level (false).
        unlocking: bool,
    },

    #[error("decryption failed: wrong master password, or the file is damaged or has been tampered with")]
    Decrypt,

    #[error(
        "this vault needs its key file as well as the master password, but no key file was given. \
         Supply it with --keyfile PATH, with the environment variable CAKEPASS_KEYFILE, or once with \
         `cakepass config set keyfile PATH`"
    )]
    KeyFileRequired,

    #[error("the key file {} cannot be read: {reason}", .path.display())]
    KeyFileUnreadable { path: PathBuf, reason: String },

    #[error("unusable key file: {0}")]
    KeyFileInvalid(String),

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

    #[error("there is no vault at {0} yet. Create one with `cakepass setup`.")]
    VaultNotFound(PathBuf),

    #[error("a file already exists at {0}; I will not overwrite it")]
    AlreadyExists(PathBuf),

    #[error("the vault was changed by another cakepass process in the meantime; try again")]
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

/// The text of [`Error::NotEnoughMemory`].
fn not_enough_memory(argon_mib: u64, needed_mib: u64, available_mib: u64, unlocking: bool) -> String {
    let why = format!(
        "needs about {needed_mib} MiB of free memory (Argon2id uses {argon_mib} MiB, and CakePass never \
         takes more than 75 % of what is free, so the system is not forced to kill it), but only about \
         {available_mib} MiB is free on this computer right now"
    );
    if unlocking {
        format!(
            "this vault was made with a security level that this computer cannot run at the moment: it {why}. \
             Close other programs and try again, or open the vault on a computer with more memory"
        )
    } else {
        format!(
            "this security level {why}. Choose a lower level (for example `--level standard`), \
             or close other programs first"
        )
    }
}
