//! Server-side defense-in-depth hashing of the master password hash.
//!
//! The client sends a 32-byte master password hash (HKDF-Expand of the
//! Argon2id-derived master key). The server hashes it AGAIN with Argon2id
//! and stores the PHC string. If the DB is dumped, an attacker still has
//! to brute-force a memory-hard hash per account.
//!
//! Server-side params are deliberately lighter than client-side because the
//! server hashes on every login; client-side runs once per device unlock.

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use rand::rngs::OsRng;

use crate::AppState;

fn argon() -> Argon2<'static> {
    // Server-side: m=64MiB, t=3, p=4. ~80 ms on a 2024 laptop.
    let params = Params::new(64 * 1024, 3, 4, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash the client-supplied master password hash for at-rest storage.
/// Returns a PHC string (`$argon2id$v=19$m=...$<salt>$<hash>`).
pub fn hash(master_password_hash: &[u8]) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let phc = argon()
        .hash_password(master_password_hash, &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?
        .to_string();
    Ok(phc)
}

/// Constant-time verify of `master_password_hash` against a stored PHC string.
pub fn verify(master_password_hash: &[u8], phc: &str) -> bool {
    let parsed = match PasswordHash::new(phc) {
        Ok(p) => p,
        Err(_) => return false,
    };
    argon()
        .verify_password(master_password_hash, &parsed)
        .is_ok()
}

/// Marker so `AppState` can be referenced from doc-tests / future helpers.
#[allow(dead_code)]
fn _state_marker(_: &AppState) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_verifies() {
        let mph = b"\x01\x02\x03\x04";
        let phc = hash(mph).unwrap();
        assert!(verify(mph, &phc));
    }

    #[test]
    fn wrong_input_does_not_verify() {
        let phc = hash(b"\x01\x02\x03").unwrap();
        assert!(!verify(b"\x01\x02\x04", &phc));
    }

    #[test]
    fn malformed_phc_returns_false() {
        assert!(!verify(b"x", "not-a-phc-string"));
    }
}
