//! # kluis
//!
//! Kernbibliotheek van de offline wachtwoordmanager `kluis`.
//!
//! De bibliotheek bevat alles behalve de gebruikersinterface, zodat er later
//! een TUI of GUI bovenop gebouwd kan worden zonder de kern te herschrijven:
//!
//! - [`secure_mem`]: wissen en vergrendelen van geheugen, procesbeveiliging.
//! - [`crypto`]: Argon2id en XChaCha20-Poly1305 (via RustCrypto-crates).
//! - [`format`]: het versioneerde, versleutelde bestandsformaat.
//! - [`vault`]: het kluismodel (items), zonder I/O.
//! - [`storage`]: paden (XDG), atomisch schrijven, back-ups, vergrendeling.
//! - [`generator`]: wachtwoorden en diceware-passphrases.
//! - [`import`]: CSV-import uit andere wachtwoordmanagers.
//! - [`clipboard`]: klembord met automatisch wissen.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod clipboard;
pub mod crypto;
pub mod error;
pub mod format;
pub mod generator;
pub mod import;
pub mod secure_mem;
pub mod storage;
pub mod vault;

pub use error::{Error, Result};
