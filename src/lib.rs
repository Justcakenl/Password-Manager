//! # cakepass
//!
//! Core library of the offline password manager `cakepass` (CakePass).
//!
//! The library contains everything except the user interface, so a TUI or
//! GUI can be built on top of it later without rewriting the core:
//!
//! - [`secure_mem`]: wiping and locking memory, process hardening.
//! - [`crypto`]: Argon2id and XChaCha20-Poly1305 (via RustCrypto crates),
//!   security levels and the memory guard.
//! - [`format`]: the versioned, encrypted file format.
//! - [`keyfile`]: the optional key file (second secret).
//! - [`vault`]: the vault model (items), without I/O.
//! - [`storage`]: paths (XDG), atomic writes, backups, locking.
//! - [`generator`]: passwords and diceware passphrases.
//! - [`totp`]: two-factor codes (TOTP, RFC 6238) from a stored secret.
//! - [`audit`]: the password health check (weak, reused, old, empty).
//! - [`import`]: CSV import from other password managers.
//! - [`clipboard`]: clipboard with automatic clearing.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod audit;
pub mod clipboard;
pub mod crypto;
pub mod error;
pub mod format;
pub mod generator;
pub mod import;
pub mod keyfile;
pub mod secure_mem;
pub mod storage;
pub mod totp;
pub mod vault;

pub use error::{Error, Result};
