//! hekate-core: shared crypto, sync state machine, and wire types.
//!
//! Stubs for M0. Real implementations land in M1+.

pub mod attachment;
pub mod cipher_id;
pub mod encstring;
// Import-format parsers are CLI-only — gated out of the wasm build
// because their transitive deps (zip, csv, keepass → getrandom 0.3)
// don't compile on wasm32-unknown-unknown, and the browser extension
// never runs imports anyway.
pub mod error;
#[cfg(not(target_arch = "wasm32"))]
pub mod import_1password;
#[cfg(not(target_arch = "wasm32"))]
pub mod import_bitwarden;
#[cfg(not(target_arch = "wasm32"))]
pub mod import_keepass;
#[cfg(not(target_arch = "wasm32"))]
pub mod import_lastpass;
pub mod kdf;
pub mod keypair;
pub mod manifest;
pub mod org_cipher_manifest;
pub mod org_roster;
pub mod passkey;
pub mod send;
pub mod signcrypt;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use error::{Error, Result};
