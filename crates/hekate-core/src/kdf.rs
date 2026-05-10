//! Master-password KDF.
//!
//! Pipeline (per design §5):
//!   master password ─Argon2id(salt)─► Master Key (32B)
//!                                     ├─HKDF("auth")─► master password hash (32B → server)
//!                                     ├─HKDF("wrap")─► Stretched Master Key (32B)
//!                                     └─HKDF("kdf-bind")─► KDF-params bind key (32B)
//!
//! The "wrap" subkey is what encrypts the Account Key and per-cipher keys.
//! The "auth" subkey is the proof-of-knowledge sent to the server.
//! The "kdf-bind" subkey is used to MAC the (params, salt) tuple so a malicious
//! server cannot downgrade the KDF parameters between registration and login
//! — see `compute_kdf_bind_mac` and the §5 mitigation in
//! `docs/threat-model-gaps.md` (BW07/LP04 in Scarlata et al. 2026).
//!
//! The server re-Argon2id-hashes the auth subkey for storage; that's not in
//! this module.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "alg", rename_all = "lowercase")]
pub enum KdfParams {
    Argon2id {
        /// Memory cost in KiB.
        m_kib: u32,
        /// Iteration count.
        t: u32,
        /// Parallelism degree.
        p: u32,
    },
}

impl KdfParams {
    /// Defaults targeted by hekate (2026): m=128 MiB, t=3, p=4.
    pub fn default_argon2id() -> Self {
        KdfParams::Argon2id {
            m_kib: 128 * 1024,
            t: 3,
            p: 4,
        }
    }

    /// Hard floor for KDF strength enforced client-side. A malicious server
    /// can only ever propose params at or above this floor — anything weaker
    /// is rejected before the master key is derived, so the brute-force-able
    /// `master_password_hash` is never produced under server-chosen weak
    /// params (BW07/LP04 in Scarlata et al. 2026).
    ///
    /// The floor sits at the Argon2id RFC 9106 "memory-constrained" profile
    /// (m=64 MiB, t=3) but we accept t=2 to leave one notch of headroom for
    /// older devices. Upper bounds are sanity caps to prevent a server from
    /// driving clients into OOM or multi-minute KDF stalls.
    ///
    /// Audit M-1 (2026-05-07): the upper m_kib was 2 GiB, which is high
    /// enough to crash WASM on memory-constrained mobile browsers even
    /// when the BW07/LP04 bind-MAC verifies. 512 MiB is the new cap —
    /// comfortably above OWASP 2026 strong-mode (m=64 MiB) and 1Password's
    /// 256 MiB while staying within the WASM heap ceilings of every shipping
    /// browser including iOS Safari.
    pub fn is_safe(&self) -> bool {
        match *self {
            KdfParams::Argon2id { m_kib, t, p } => {
                (64 * 1024..=512 * 1024).contains(&m_kib)
                    && (2..=100).contains(&t)
                    && (1..=16).contains(&p)
            }
        }
    }
}

/// 32-byte master key. Wrapped in Zeroizing so it's wiped on drop.
pub type MasterKey = Zeroizing<[u8; 32]>;

/// 32-byte stretched master key (used to wrap the Account Key).
pub type StretchedMasterKey = Zeroizing<[u8; 32]>;

/// 32-byte master password hash (proof of knowledge sent to server).
pub type MasterPasswordHash = [u8; 32];

/// 32-byte HMAC-SHA256 tag binding the KDF parameters (and salt) to the
/// master key.
pub type KdfBindMac = [u8; 32];

const HKDF_INFO_AUTH: &[u8] = b"pmgr-auth-v1";
const HKDF_INFO_WRAP: &[u8] = b"pmgr-wrap-v1";
const HKDF_INFO_KDF_BIND: &[u8] = b"pmgr-kdf-bind-v1";

/// Domain-separation tag prepended to the canonical (params || salt) message
/// before HMAC. Versioned independently of the HKDF info so we can rotate
/// just the binding format without rotating subkeys.
const KDF_BIND_DST: &[u8] = b"pmgr-kdf-bind-msg-v1\x00";

/// Run Argon2id over `password` with the given params and salt to produce
/// the 32-byte Master Key. Salt should be ≥ 8 bytes (we use 16 by default).
pub fn derive_master_key(password: &[u8], params: KdfParams, salt: &[u8]) -> Result<MasterKey> {
    let KdfParams::Argon2id { m_kib, t, p } = params;
    let argon_params = Params::new(m_kib, t, p, Some(32)).map_err(|e| Error::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(out)
}

/// Derive the master password hash sent to the server.
pub fn derive_master_password_hash(master_key: &MasterKey) -> MasterPasswordHash {
    hkdf_expand_32(master_key.as_ref(), HKDF_INFO_AUTH)
}

/// Derive the stretched master key used for wrapping account material.
pub fn derive_stretched_master_key(master_key: &MasterKey) -> StretchedMasterKey {
    let bytes = hkdf_expand_32(master_key.as_ref(), HKDF_INFO_WRAP);
    Zeroizing::new(bytes)
}

/// Derive the 32-byte key used to MAC the KDF parameters + salt. Wrapped in
/// `Zeroizing` because possession of this key is equivalent to possession of
/// the password (it can be used to forge a valid MAC for any params).
pub fn derive_kdf_bind_key(master_key: &MasterKey) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(hkdf_expand_32(master_key.as_ref(), HKDF_INFO_KDF_BIND))
}

/// Build the canonical bytes that get MACed: `DST || alg-tag || params || 0x00 || salt`.
/// Stable across JSON whitespace / key-order / future fields. New algorithm
/// variants must extend the match arm here AND bump `KDF_BIND_DST` (see
/// `compute_kdf_bind_mac`).
fn kdf_bind_message(params: KdfParams, salt: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(KDF_BIND_DST.len() + 32 + salt.len());
    buf.extend_from_slice(KDF_BIND_DST);
    match params {
        KdfParams::Argon2id { m_kib, t, p } => {
            buf.extend_from_slice(b"argon2id\x00");
            buf.extend_from_slice(&m_kib.to_be_bytes());
            buf.extend_from_slice(&t.to_be_bytes());
            buf.extend_from_slice(&p.to_be_bytes());
        }
    }
    buf.push(0x00);
    buf.extend_from_slice(salt);
    buf
}

/// Compute `HMAC-SHA256(bind_key, canonical(params, salt))`. The client
/// computes this at registration and sends it to the server alongside the
/// (plaintext) params and salt; the server stores it verbatim and returns
/// it on every prelogin. The client MUST verify on login *before* sending
/// the master_password_hash, otherwise a malicious server can extract a
/// brute-forceable hash under attacker-chosen params (BW07/LP04).
pub fn compute_kdf_bind_mac(bind_key: &[u8; 32], params: KdfParams, salt: &[u8]) -> KdfBindMac {
    let mut mac = HmacSha256::new_from_slice(bind_key).expect("HMAC-SHA256 accepts any key length");
    mac.update(&kdf_bind_message(params, salt));
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    tag
}

/// Constant-time verification of a KDF-params bind MAC. Returns `true` if
/// `tag == HMAC-SHA256(bind_key, canonical(params, salt))`.
pub fn verify_kdf_bind_mac(
    bind_key: &[u8; 32],
    params: KdfParams,
    salt: &[u8],
    tag: &[u8],
) -> bool {
    if tag.len() != 32 {
        return false;
    }
    let expected = compute_kdf_bind_mac(bind_key, params, salt);
    expected.ct_eq(tag).into()
}

fn hkdf_expand_32(prk: &[u8], info: &[u8]) -> [u8; 32] {
    // Use HKDF in Expand-only mode: the master key is already a high-entropy
    // 32-byte uniformly-random secret from Argon2id, so the Extract step
    // would only re-hash it.
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("32-byte PRK is sufficient for SHA-256");
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("OKM length 32 is valid");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_argon2id_128mib() {
        let p = KdfParams::default_argon2id();
        match p {
            KdfParams::Argon2id { m_kib, t, p } => {
                assert_eq!(m_kib, 128 * 1024);
                assert_eq!(t, 3);
                assert_eq!(p, 4);
            }
        }
    }

    #[test]
    fn serde_roundtrip() {
        let p = KdfParams::default_argon2id();
        let s = serde_json::to_string(&p).unwrap();
        let r: KdfParams = serde_json::from_str(&s).unwrap();
        assert_eq!(p, r);
    }

    /// Use a deliberately weak param set so the test suite stays under a
    /// second on commodity hardware. The production defaults take ~500 ms.
    fn fast_params() -> KdfParams {
        KdfParams::Argon2id {
            m_kib: 64,
            t: 1,
            p: 1,
        }
    }

    #[test]
    fn derive_master_key_is_deterministic() {
        let pw = b"correct horse battery staple";
        let salt = [0x42u8; 16];
        let k1 = derive_master_key(pw, fast_params(), &salt).unwrap();
        let k2 = derive_master_key(pw, fast_params(), &salt).unwrap();
        assert_eq!(k1.as_ref(), k2.as_ref());
    }

    #[test]
    fn different_salt_yields_different_key() {
        let pw = b"hunter2";
        let k1 = derive_master_key(pw, fast_params(), &[0u8; 16]).unwrap();
        let k2 = derive_master_key(pw, fast_params(), &[1u8; 16]).unwrap();
        assert_ne!(k1.as_ref(), k2.as_ref());
    }

    #[test]
    fn auth_and_wrap_subkeys_differ() {
        let mk = derive_master_key(b"pw", fast_params(), &[0u8; 16]).unwrap();
        let auth = derive_master_password_hash(&mk);
        let wrap = derive_stretched_master_key(&mk);
        assert_ne!(auth, *wrap.as_ref());
    }

    #[test]
    fn subkey_length_is_32() {
        let mk = derive_master_key(b"pw", fast_params(), &[0u8; 16]).unwrap();
        assert_eq!(derive_master_password_hash(&mk).len(), 32);
        assert_eq!(derive_stretched_master_key(&mk).len(), 32);
    }

    #[test]
    fn safe_params_accepts_defaults() {
        assert!(KdfParams::default_argon2id().is_safe());
    }

    #[test]
    fn safe_params_rejects_attacker_downgrade() {
        // The exact combinations a malicious server would supply to make
        // brute-force trivial. None of these should pass the floor.
        assert!(!KdfParams::Argon2id {
            m_kib: 8,
            t: 1,
            p: 1
        }
        .is_safe());
        assert!(!KdfParams::Argon2id {
            m_kib: 64,
            t: 1,
            p: 1
        }
        .is_safe()); // BW07-style
        assert!(!KdfParams::Argon2id {
            m_kib: 1024,
            t: 3,
            p: 4
        }
        .is_safe()); // 1 MiB
        assert!(!KdfParams::Argon2id {
            m_kib: 32 * 1024,
            t: 3,
            p: 4
        }
        .is_safe()); // 32 MiB
        assert!(!KdfParams::Argon2id {
            m_kib: 64 * 1024,
            t: 1,
            p: 4
        }
        .is_safe()); // t=1
    }

    #[test]
    fn safe_params_rejects_dos_inflation() {
        // Server can't push us into OOM either.
        assert!(!KdfParams::Argon2id {
            m_kib: 8 * 1024 * 1024,
            t: 3,
            p: 4
        }
        .is_safe());
        assert!(!KdfParams::Argon2id {
            m_kib: 128 * 1024,
            t: 3,
            p: 128
        }
        .is_safe());
    }

    #[test]
    fn safe_params_accepts_minimum_floor() {
        assert!(KdfParams::Argon2id {
            m_kib: 64 * 1024,
            t: 2,
            p: 1
        }
        .is_safe());
    }

    #[test]
    fn bind_mac_round_trips() {
        let mk = derive_master_key(b"pw", fast_params(), &[0u8; 16]).unwrap();
        let bk = derive_kdf_bind_key(&mk);
        let p = fast_params();
        let salt = [0xa5u8; 16];
        let tag = compute_kdf_bind_mac(&bk, p, &salt);
        assert!(verify_kdf_bind_mac(&bk, p, &salt, &tag));
    }

    #[test]
    fn bind_mac_rejects_param_tampering() {
        let mk = derive_master_key(b"pw", fast_params(), &[0u8; 16]).unwrap();
        let bk = derive_kdf_bind_key(&mk);
        let salt = [0xa5u8; 16];
        let tag = compute_kdf_bind_mac(
            &bk,
            KdfParams::Argon2id {
                m_kib: 128 * 1024,
                t: 3,
                p: 4,
            },
            &salt,
        );
        // Server-flipped params produce a different MAC.
        assert!(!verify_kdf_bind_mac(
            &bk,
            KdfParams::Argon2id {
                m_kib: 64,
                t: 1,
                p: 1
            },
            &salt,
            &tag
        ));
    }

    #[test]
    fn bind_mac_rejects_salt_tampering() {
        let mk = derive_master_key(b"pw", fast_params(), &[0u8; 16]).unwrap();
        let bk = derive_kdf_bind_key(&mk);
        let p = fast_params();
        let tag = compute_kdf_bind_mac(&bk, p, &[0u8; 16]);
        assert!(!verify_kdf_bind_mac(&bk, p, &[1u8; 16], &tag));
    }

    #[test]
    fn bind_mac_rejects_wrong_length_tag() {
        let mk = derive_master_key(b"pw", fast_params(), &[0u8; 16]).unwrap();
        let bk = derive_kdf_bind_key(&mk);
        assert!(!verify_kdf_bind_mac(&bk, fast_params(), &[0u8; 16], &[]));
        assert!(!verify_kdf_bind_mac(
            &bk,
            fast_params(),
            &[0u8; 16],
            &[0u8; 31]
        ));
        assert!(!verify_kdf_bind_mac(
            &bk,
            fast_params(),
            &[0u8; 16],
            &[0u8; 33]
        ));
    }

    #[test]
    fn bind_mac_subkey_differs_from_auth_and_wrap() {
        let mk = derive_master_key(b"pw", fast_params(), &[0u8; 16]).unwrap();
        let auth = derive_master_password_hash(&mk);
        let wrap = derive_stretched_master_key(&mk);
        let bind = derive_kdf_bind_key(&mk);
        assert_ne!(auth, *bind.as_ref());
        assert_ne!(*wrap.as_ref(), *bind.as_ref());
    }
}
