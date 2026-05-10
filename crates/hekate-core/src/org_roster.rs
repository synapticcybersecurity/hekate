//! Signed organization roster — BW08 mitigation.
//!
//! Mirror of the M2.15c vault-manifest pattern at the org level: each
//! org has an Ed25519 signing key (held by the owner under the single-
//! signer model in `docs/m4-organizations.md`); the roster is a signed
//! list of `(user_id, role)` for every accepted member. Members verify
//! the roster on every fetch under their locally-pinned org signing
//! pubkey, confirm the parent-hash chain forward, and refuse to act on
//! membership claims the server makes outside the signed roster.
//!
//! ## Canonical bytes (signed)
//!
//! ```text
//! DST            := "pmgr-org-roster-v1\x00"
//! canonical      := DST
//!                || u64(version)
//!                || [32 bytes parent_canonical_sha256]    // zeros for genesis
//!                || u32(org_id.len)         || org_id_bytes
//!                || u32(timestamp.len)      || timestamp_bytes
//!                || u32(entries.len)
//!                || entry × N
//!                || u32(org_sym_key_id.len) || org_sym_key_id_bytes
//! entry          := u32(user_id.len) || user_id
//!                || u32(role.len)    || role
//! ```
//!
//! Entries are sorted by `user_id` lex-ascending before signing for
//! canonicality.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

const DST: &[u8] = b"pmgr-org-roster-v1\x00";

/// All-zeros parent hash, used by the genesis roster (version 1).
pub const NO_PARENT_HASH: [u8; 32] = [0u8; 32];

pub fn hash_canonical(canonical: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(canonical);
    h.finalize().into()
}

/// One row in the roster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgRosterEntry {
    pub user_id: String,
    /// "owner" | "admin" | "user". Validated at the wire layer; this
    /// type itself accepts any string so future role additions don't
    /// have to ship through hekate-core.
    pub role: String,
}

/// Plaintext roster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgRoster {
    pub org_id: String,
    pub version: u64,
    pub parent_canonical_sha256: [u8; 32],
    pub timestamp: String,
    pub entries: Vec<OrgRosterEntry>,
    /// Bumps each time the org symmetric key rotates. Bound into the
    /// signature so a server can't claim "the current key_id is X" for
    /// a roster that was signed expecting Y.
    pub org_sym_key_id: String,
}

impl OrgRoster {
    pub fn sort_entries(&mut self) {
        self.entries.sort_by(|a, b| a.user_id.cmp(&b.user_id));
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let org = self.org_id.as_bytes();
        let ts = self.timestamp.as_bytes();
        let key_id = self.org_sym_key_id.as_bytes();
        let mut out = Vec::with_capacity(DST.len() + 64 + org.len() + ts.len() + 64);
        out.extend_from_slice(DST);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.parent_canonical_sha256);
        out.extend_from_slice(&(org.len() as u32).to_le_bytes());
        out.extend_from_slice(org);
        out.extend_from_slice(&(ts.len() as u32).to_le_bytes());
        out.extend_from_slice(ts);
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for e in &self.entries {
            let id = e.user_id.as_bytes();
            let role = e.role.as_bytes();
            out.extend_from_slice(&(id.len() as u32).to_le_bytes());
            out.extend_from_slice(id);
            out.extend_from_slice(&(role.len() as u32).to_le_bytes());
            out.extend_from_slice(role);
        }
        out.extend_from_slice(&(key_id.len() as u32).to_le_bytes());
        out.extend_from_slice(key_id);
        out
    }

    /// Sort entries deterministically and sign with the org's Ed25519
    /// key. Returns the wire form.
    pub fn sign(mut self, signing_key: &SigningKey) -> SignedOrgRoster {
        self.sort_entries();
        let canonical = self.canonical_bytes();
        let sig = signing_key.sign(&canonical);
        SignedOrgRoster {
            canonical_b64: STANDARD_NO_PAD.encode(&canonical),
            signature_b64: STANDARD_NO_PAD.encode(sig.to_bytes()),
        }
    }
}

/// Wire form: two base64-no-pad strings carried in JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOrgRoster {
    pub canonical_b64: String,
    pub signature_b64: String,
}

impl SignedOrgRoster {
    /// Verify under an *expected* signing pubkey (looked up out-of-band
    /// — local TOFU pin or invite envelope) and parse the canonical
    /// bytes back to a roster.
    pub fn verify(&self, expected_pubkey: &VerifyingKey) -> Result<OrgRoster> {
        let canonical = STANDARD_NO_PAD
            .decode(&self.canonical_b64)
            .map_err(|_| Error::InvalidEncoding("canonical_b64 not base64-no-pad".into()))?;
        let sig_bytes = STANDARD_NO_PAD
            .decode(&self.signature_b64)
            .map_err(|_| Error::InvalidEncoding("signature_b64 not base64-no-pad".into()))?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|_| Error::InvalidEncoding("signature has wrong length".into()))?;
        // Audit H-2 (2026-05-07): verify_strict rejects non-canonical
        // sig scalars + small-order R points. Non-strict verify would
        // accept a second byte-different signature that also passes,
        // breaking signature uniqueness assumptions a caching layer
        // (or BW09/LP07-style attribution gap) would mis-assume away.
        expected_pubkey
            .verify_strict(&canonical, &sig)
            .map_err(|_| Error::InvalidEncoding("org roster signature did not verify".into()))?;
        decode_canonical(&canonical)
    }
}

pub fn decode_canonical(canonical: &[u8]) -> Result<OrgRoster> {
    let mut p = canonical;
    expect_prefix(&mut p, DST)?;
    let version = read_u64_le(&mut p)?;
    let parent = read_fixed::<32>(&mut p)?;
    let org_id = read_lp_string(&mut p)?;
    let timestamp = read_lp_string(&mut p)?;
    let n_entries = read_u32_le(&mut p)? as usize;
    // Audit H-3 (2026-05-07): bound pre-allocation by remaining buffer
    // length so a signed-but-attacker-chosen `n_entries = u32::MAX`
    // can't OOM the client. Each entry is at minimum 4(user_id len) +
    // 4(role len) = 8 bytes; the cap keeps us from allocating more
    // than we could conceivably read.
    const MIN_ENTRY_SIZE: usize = 8;
    let cap = n_entries.min(p.len() / MIN_ENTRY_SIZE + 1);
    let mut entries = Vec::with_capacity(cap);
    for _ in 0..n_entries {
        let user_id = read_lp_string(&mut p)?;
        let role = read_lp_string(&mut p)?;
        entries.push(OrgRosterEntry { user_id, role });
    }
    let org_sym_key_id = read_lp_string(&mut p)?;
    if !p.is_empty() {
        return Err(Error::InvalidEncoding(
            "trailing bytes after org roster".into(),
        ));
    }
    Ok(OrgRoster {
        org_id,
        version,
        parent_canonical_sha256: parent,
        timestamp,
        entries,
        org_sym_key_id,
    })
}

// --- canonical-bytes parser helpers (mirror of manifest.rs) ----------------

fn expect_prefix(p: &mut &[u8], prefix: &[u8]) -> Result<()> {
    if p.len() < prefix.len() || &p[..prefix.len()] != prefix {
        return Err(Error::InvalidEncoding("bad org roster prefix".into()));
    }
    *p = &p[prefix.len()..];
    Ok(())
}
fn read_u64_le(p: &mut &[u8]) -> Result<u64> {
    if p.len() < 8 {
        return Err(Error::InvalidEncoding("short org roster u64".into()));
    }
    let v = u64::from_le_bytes(p[..8].try_into().unwrap());
    *p = &p[8..];
    Ok(v)
}
fn read_u32_le(p: &mut &[u8]) -> Result<u32> {
    if p.len() < 4 {
        return Err(Error::InvalidEncoding("short org roster u32".into()));
    }
    let v = u32::from_le_bytes(p[..4].try_into().unwrap());
    *p = &p[4..];
    Ok(v)
}
fn read_fixed<const N: usize>(p: &mut &[u8]) -> Result<[u8; N]> {
    if p.len() < N {
        return Err(Error::InvalidEncoding(format!(
            "short org roster fixed-{N}"
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&p[..N]);
    *p = &p[N..];
    Ok(out)
}
fn read_lp_string(p: &mut &[u8]) -> Result<String> {
    let len = read_u32_le(p)? as usize;
    if p.len() < len {
        return Err(Error::InvalidEncoding("short org roster string".into()));
    }
    let s = std::str::from_utf8(&p[..len])
        .map_err(|_| Error::InvalidEncoding("org roster string not utf-8".into()))?
        .to_string();
    *p = &p[len..];
    Ok(s)
}

// ============================================================================
// Org bundle (BW07) — owner's signed binding of (org_id, name, signing_pubkey,
// owner_user_id). Inviter signs this with their *user* Ed25519 key, and
// invitees verify under the inviter's pinned signing pubkey to prove the
// inviter created (or is authoritative for) this org's signing key. Same
// canonical-bytes layout the server uses in `routes/orgs.rs`.
// ============================================================================

const ORG_BUNDLE_DST: &[u8] = b"pmgr-org-bundle-v1\x00";

/// Build the canonical bytes for an org bundle. Mirrors the server's
/// `build_bundle_canonical` and the CLI's local helper — single source
/// of truth so popup/CLI/server can never drift.
pub fn org_bundle_canonical_bytes(
    org_id: &str,
    name: &str,
    signing_pubkey: &[u8; 32],
    owner_user_id: &str,
) -> Vec<u8> {
    let id = org_id.as_bytes();
    let n = name.as_bytes();
    let owner = owner_user_id.as_bytes();
    let mut out =
        Vec::with_capacity(ORG_BUNDLE_DST.len() + 12 + id.len() + n.len() + 32 + owner.len());
    out.extend_from_slice(ORG_BUNDLE_DST);
    out.extend_from_slice(&(id.len() as u32).to_le_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(&(n.len() as u32).to_le_bytes());
    out.extend_from_slice(n);
    out.extend_from_slice(signing_pubkey);
    out.extend_from_slice(&(owner.len() as u32).to_le_bytes());
    out.extend_from_slice(owner);
    out
}

/// Sign an org bundle with the owner's Ed25519 signing key. Returns
/// the 64-byte signature.
pub fn sign_org_bundle(
    owner_signing_key: &SigningKey,
    org_id: &str,
    name: &str,
    org_signing_pubkey: &[u8; 32],
    owner_user_id: &str,
) -> [u8; 64] {
    let canonical = org_bundle_canonical_bytes(org_id, name, org_signing_pubkey, owner_user_id);
    owner_signing_key.sign(&canonical).to_bytes()
}

/// AAD for an org-collection's encrypted `name` field. Binds the
/// ciphertext to (collection_id, org_id) so the server can't move
/// a name across collections or orgs. Consumed by both the CLI
/// (`commands/org.rs`) and the popup via the WASM
/// `collectionNameAad` binding.
pub fn collection_name_aad(collection_id: &str, org_id: &str) -> Vec<u8> {
    let mut v =
        Vec::with_capacity(b"pmgr-collection-name|".len() + collection_id.len() + 1 + org_id.len());
    v.extend_from_slice(b"pmgr-collection-name|");
    v.extend_from_slice(collection_id.as_bytes());
    v.push(b'|');
    v.extend_from_slice(org_id.as_bytes());
    v
}

/// Verify an org bundle signature under the *inviter's* (claimed
/// owner's) signing pubkey. Used by invitees during accept-invite.
pub fn verify_org_bundle(
    inviter_signing_pubkey: &VerifyingKey,
    org_id: &str,
    name: &str,
    org_signing_pubkey: &[u8; 32],
    owner_user_id: &str,
    signature: &[u8; 64],
) -> Result<()> {
    let canonical = org_bundle_canonical_bytes(org_id, name, org_signing_pubkey, owner_user_id);
    let sig = Signature::from_slice(signature)
        .map_err(|_| Error::InvalidEncoding("org bundle sig wrong length".into()))?;
    inviter_signing_pubkey
        .verify_strict(&canonical, &sig)
        .map_err(|_| Error::InvalidEncoding("org bundle sig did not verify".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn sample(version: u64, parent: [u8; 32]) -> OrgRoster {
        OrgRoster {
            org_id: "0192e0a0-0000-7000-8000-000000000001".into(),
            version,
            parent_canonical_sha256: parent,
            timestamp: "2026-05-03T00:00:00+00:00".into(),
            entries: vec![
                OrgRosterEntry {
                    user_id: "0192e0a0-0000-7000-8000-aaaaaaaaaaaa".into(),
                    role: "owner".into(),
                },
                OrgRosterEntry {
                    user_id: "0192e0a0-0000-7000-8000-bbbbbbbbbbbb".into(),
                    role: "user".into(),
                },
            ],
            org_sym_key_id: "0192e0a0-0000-7000-8000-key0000000001".into(),
        }
    }

    #[test]
    fn round_trips_under_correct_signing_key() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key();
        let signed = sample(1, NO_PARENT_HASH).sign(&sk);
        let parsed = signed.verify(&pk).expect("valid roster must verify");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.entries.len(), 2);
    }

    #[test]
    fn rejects_signature_under_wrong_key() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let attacker = SigningKey::from_bytes(&[8u8; 32]);
        let signed = sample(1, NO_PARENT_HASH).sign(&sk);
        assert!(signed.verify(&attacker.verifying_key()).is_err());
    }

    #[test]
    fn rejects_canonical_tampering() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut signed = sample(1, NO_PARENT_HASH).sign(&sk);
        let mut bytes = STANDARD_NO_PAD.decode(&signed.canonical_b64).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        signed.canonical_b64 = STANDARD_NO_PAD.encode(&bytes);
        assert!(signed.verify(&sk.verifying_key()).is_err());
    }

    #[test]
    fn decode_canonical_round_trips() {
        let mut r = sample(3, [0xa5u8; 32]);
        r.sort_entries();
        let bytes = r.canonical_bytes();
        let parsed = decode_canonical(&bytes).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn sort_is_canonical() {
        let mut a = sample(1, NO_PARENT_HASH);
        let mut b = sample(1, NO_PARENT_HASH);
        b.entries.reverse();
        a.sort_entries();
        b.sort_entries();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn parent_hash_chain_links_correctly() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key();
        let v1 = sample(1, NO_PARENT_HASH);
        let signed1 = v1.sign(&sk);
        let canonical1 = STANDARD_NO_PAD.decode(&signed1.canonical_b64).unwrap();
        let parent = hash_canonical(&canonical1);

        let v2 = sample(2, parent);
        let signed2 = v2.sign(&sk);
        let parsed2 = signed2.verify(&pk).unwrap();
        assert_eq!(parsed2.parent_canonical_sha256, parent);
    }

    /// Server-side substitution attempt: same canonical layout but
    /// different `org_sym_key_id` must not validate under the same sig.
    #[test]
    fn rejects_org_sym_key_id_substitution() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut r = sample(1, NO_PARENT_HASH);
        let original = r.clone().sign(&sk);
        // Build a doppelgänger with a different key_id but reuse the
        // original signature — must fail since the canonical bytes
        // differ.
        r.org_sym_key_id = "0192e0a0-0000-7000-8000-keyEVILEVIL01".into();
        let forged_canonical = {
            r.sort_entries();
            r.canonical_bytes()
        };
        let forged = SignedOrgRoster {
            canonical_b64: STANDARD_NO_PAD.encode(&forged_canonical),
            signature_b64: original.signature_b64,
        };
        assert!(forged.verify(&sk.verifying_key()).is_err());
    }

    #[test]
    fn rejects_role_swap() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let r = sample(1, NO_PARENT_HASH);
        let original = r.clone().sign(&sk);
        // Server tries to elevate the second member to owner.
        let mut tampered = r;
        tampered.entries[1].role = "owner".into();
        tampered.sort_entries();
        let forged_canonical = tampered.canonical_bytes();
        let forged = SignedOrgRoster {
            canonical_b64: STANDARD_NO_PAD.encode(&forged_canonical),
            signature_b64: original.signature_b64,
        };
        assert!(forged.verify(&sk.verifying_key()).is_err());
    }
}
