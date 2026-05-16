//! hekate-core: shared crypto, sync state machine, and wire types.
//!
//! Stubs for M0. Real implementations land in M1+.

pub mod attachment;
pub mod cipher_id;
pub mod encstring;
// Import-format parsers. `import_bitwarden` is pure-Rust (serde_json
// only) and compiles cleanly on wasm32 — exposed so the web vault
// can surface a graphical Bitwarden-JSON import flow. The other
// three depend on transitive crates (zip, csv, keepass →
// getrandom 0.3) that don't yet have a working WASM build; they
// stay gated to non-wasm and ship via the CLI for now.
pub mod error;
#[cfg(not(target_arch = "wasm32"))]
pub mod import_1password;
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
