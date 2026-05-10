//! Local daemon that holds the unwrapped account key in memory between
//! CLI invocations, so subsequent commands skip the ~500 ms Argon2id
//! derivation. Talks to the CLI over a per-uid Unix domain socket.
//!
//! Wire protocol: 4-byte big-endian length, then a JSON Request /
//! Response. The socket is mode 0600; access control relies on the
//! kernel's filesystem-level permission check.
//!
//! Unix-only for this iteration. Windows DPAPI-backed cache is a future
//! milestone.

use std::path::PathBuf;

#[allow(unused_imports)]
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

pub mod client;
pub mod server;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Returns both the unwrapped account key and the Ed25519 signing
    /// seed derived from the master key. New in M2.15b — both are
    /// needed to sign the per-user vault manifest after every write.
    GetUnlocked,
    Status,
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Unlocked {
        /// 32 bytes, URL-safe-no-pad base64.
        account_key_b64: String,
        /// 32 bytes, URL-safe-no-pad base64. Ed25519 seed.
        signing_seed_b64: String,
    },
    Status(StatusInfo),
    Ok,
    Err {
        message: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusInfo {
    pub email: String,
    pub expires_at: String,
    pub remaining_secs: i64,
    pub pid: u32,
}

/// Resolve the per-uid socket path. `$XDG_RUNTIME_DIR/hekate-<uid>.sock` if
/// available; falls back to `/tmp/hekate-<uid>.sock`.
#[cfg(unix)]
pub fn socket_path() -> Result<PathBuf> {
    let dir = match std::env::var("XDG_RUNTIME_DIR") {
        Ok(d) => PathBuf::from(d),
        Err(_) => PathBuf::from("/tmp"),
    };
    let uid = nix::unistd::getuid().as_raw();
    Ok(dir.join(format!("hekate-{uid}.sock")))
}

#[cfg(not(unix))]
pub fn socket_path() -> Result<PathBuf> {
    Err(anyhow!("daemon mode is unix-only in this build"))
}
