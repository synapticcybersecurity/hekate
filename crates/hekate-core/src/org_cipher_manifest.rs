//! Per-org signed cipher manifest — BW04 set-level integrity at org scope.
//!
//! Mirror of the M2.15c per-user vault manifest (`hekate-core::manifest`)
//! at the org level. The per-user manifest covers ciphers a user
//! personally owns (`user_id IS NOT NULL`); org-owned ciphers
//! (`org_id IS NOT NULL`) sit in a different ownership scope and were
//! deliberately excluded from that primitive.
//!
//! This module signs the *set* of org-owned cipher rows: a malicious
//! server can otherwise drop, replay an old `revision_date`, or hide a
//! soft-delete on an org-owned cipher between syncs without any client
//! tripping a warning. The signed manifest is the BW04 closure for org
//! scope — see `docs/threat-model-gaps.md` "Open: Org-cipher set-level
//! integrity".
//!
//! ## Trust model in M4 v1
//!
//! Single-signer: only the org owner holds the org's Ed25519 signing
//! seed (wrapped under the owner's account_key in
//! `organization_owner_keys`). So only the owner can produce a valid
//! signed manifest. Other admins / managers can write org ciphers, but
//! the manifest goes stale until the owner next refreshes it. This is
//! the same constraint as the M4 signed roster.
//!
//! ## Canonical bytes (signed)
//!
//! ```text
//! DST            := "pmgr-org-cipher-manifest-v1\x00"
//! canonical      := DST
//!                || u64(version)
//!                || [32 bytes parent_canonical_sha256]    // zeros for genesis
//!                || u32(org_id.len)        || org_id_bytes
//!                || u32(timestamp.len)     || timestamp_bytes
//!                || u32(entries.len)
//!                || entry × N
//! entry          := u32(cipher_id.len) || cipher_id
//!                || u32(rev.len)       || rev_bytes
//!                || u8(deleted)        // 0 = active, 1 = trashed
//! ```
//!
//! Entries are sorted by `cipher_id` lex-ascending before signing for
//! canonicality. `parent_canonical_sha256` chains forward across
//! versions exactly as in M2.15c.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

const DST: &[u8] = b"pmgr-org-cipher-manifest-v1\x00";

/// All-zeros parent hash, used by the genesis manifest (version 1).
pub const NO_PARENT_HASH: [u8; 32] = [0u8; 32];

pub fn hash_canonical(canonical: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(canonical);
    h.finalize().into()
}

/// One row in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgCipherEntry {
    pub cipher_id: String,
    /// RFC3339 `revision_date` from the cipher's last write.
    pub revision_date: String,
    /// True if the server's `deleted_date` column is non-NULL (cipher
    /// is in the trash).
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgCipherManifest {
    pub org_id: String,
    pub version: u64,
    pub parent_canonical_sha256: [u8; 32],
    pub timestamp: String,
    pub entries: Vec<OrgCipherEntry>,
}

impl OrgCipherManifest {
    pub fn sort_entries(&mut self) {
        self.entries.sort_by(|a, b| a.cipher_id.cmp(&b.cipher_id));
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let org = self.org_id.as_bytes();
        let ts = self.timestamp.as_bytes();
        let mut out =
            Vec::with_capacity(DST.len() + 64 + org.len() + ts.len() + self.entries.len() * 96);
        out.extend_from_slice(DST);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.parent_canonical_sha256);
        out.extend_from_slice(&(org.len() as u32).to_le_bytes());
        out.extend_from_slice(org);
        out.extend_from_slice(&(ts.len() as u32).to_le_bytes());
        out.extend_from_slice(ts);
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for e in &self.entries {
            let id = e.cipher_id.as_bytes();
            let rev = e.revision_date.as_bytes();
            out.extend_from_slice(&(id.len() as u32).to_le_bytes());
            out.extend_from_slice(id);
            out.extend_from_slice(&(rev.len() as u32).to_le_bytes());
            out.extend_from_slice(rev);
            out.push(if e.deleted { 1 } else { 0 });
        }
        out
    }

    /// Sort entries deterministically and sign with the org's Ed25519
    /// key. Returns the wire form.
    pub fn sign(mut self, signing_key: &SigningKey) -> SignedOrgCipherManifest {
        self.sort_entries();
        let canonical = self.canonical_bytes();
        let sig = signing_key.sign(&canonical);
        SignedOrgCipherManifest {
            canonical_b64: STANDARD_NO_PAD.encode(&canonical),
            signature_b64: STANDARD_NO_PAD.encode(sig.to_bytes()),
        }
    }
}

/// Wire form: two base64-no-pad strings carried in JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOrgCipherManifest {
    pub canonical_b64: String,
    pub signature_b64: String,
}

impl SignedOrgCipherManifest {
    /// Verify under an *expected* org signing pubkey (looked up
    /// out-of-band via the local TOFU pin from `hekate peer fetch` /
    /// `hekate org accept`) and parse the canonical bytes back.
    pub fn verify(&self, expected_pubkey: &VerifyingKey) -> Result<OrgCipherManifest> {
        let canonical = STANDARD_NO_PAD
            .decode(&self.canonical_b64)
            .map_err(|_| Error::InvalidEncoding("canonical_b64 not base64-no-pad".into()))?;
        let sig_bytes = STANDARD_NO_PAD
            .decode(&self.signature_b64)
            .map_err(|_| Error::InvalidEncoding("signature_b64 not base64-no-pad".into()))?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|_| Error::InvalidEncoding("signature has wrong length".into()))?;
        // Audit H-2 (2026-05-07): verify_strict rejects non-canonical
        // sig scalars + small-order R points (signature-uniqueness
        // gap; ed25519-dalek explicitly recommends verify_strict for
        // verification across a trust boundary).
        expected_pubkey
            .verify_strict(&canonical, &sig)
            .map_err(|_| {
                Error::InvalidEncoding("org cipher manifest signature did not verify".into())
            })?;
        decode_canonical(&canonical)
    }
}

pub fn decode_canonical(canonical: &[u8]) -> Result<OrgCipherManifest> {
    let mut p = canonical;
    expect_prefix(&mut p, DST)?;
    let version = read_u64_le(&mut p)?;
    let parent = read_fixed::<32>(&mut p)?;
    let org_id = read_lp_string(&mut p)?;
    let timestamp = read_lp_string(&mut p)?;
    let n_entries = read_u32_le(&mut p)? as usize;
    // Audit H-3 (2026-05-07): cap pre-allocation by remaining buffer
    // length to prevent a signed-but-attacker-chosen huge n_entries
    // from OOMing the client. Each entry minimum: 4 + 4 + 1 = 9 bytes;
    // we floor at 8 for safety margin.
    const MIN_ENTRY_SIZE: usize = 8;
    let cap = n_entries.min(p.len() / MIN_ENTRY_SIZE + 1);
    let mut entries = Vec::with_capacity(cap);
    for _ in 0..n_entries {
        let cipher_id = read_lp_string(&mut p)?;
        let revision_date = read_lp_string(&mut p)?;
        let deleted = read_u8(&mut p)? != 0;
        entries.push(OrgCipherEntry {
            cipher_id,
            revision_date,
            deleted,
        });
    }
    if !p.is_empty() {
        return Err(Error::InvalidEncoding(
            "trailing bytes after org cipher manifest".into(),
        ));
    }
    Ok(OrgCipherManifest {
        org_id,
        version,
        parent_canonical_sha256: parent,
        timestamp,
        entries,
    })
}

// --- canonical-bytes parser helpers (mirror of org_roster.rs) -------------

fn expect_prefix(p: &mut &[u8], prefix: &[u8]) -> Result<()> {
    if p.len() < prefix.len() || &p[..prefix.len()] != prefix {
        return Err(Error::InvalidEncoding(
            "bad org cipher manifest prefix".into(),
        ));
    }
    *p = &p[prefix.len()..];
    Ok(())
}
fn read_u64_le(p: &mut &[u8]) -> Result<u64> {
    if p.len() < 8 {
        return Err(Error::InvalidEncoding("short manifest u64".into()));
    }
    let v = u64::from_le_bytes(p[..8].try_into().unwrap());
    *p = &p[8..];
    Ok(v)
}
fn read_u32_le(p: &mut &[u8]) -> Result<u32> {
    if p.len() < 4 {
        return Err(Error::InvalidEncoding("short manifest u32".into()));
    }
    let v = u32::from_le_bytes(p[..4].try_into().unwrap());
    *p = &p[4..];
    Ok(v)
}
fn read_u8(p: &mut &[u8]) -> Result<u8> {
    if p.is_empty() {
        return Err(Error::InvalidEncoding("short manifest u8".into()));
    }
    let v = p[0];
    *p = &p[1..];
    Ok(v)
}
fn read_fixed<const N: usize>(p: &mut &[u8]) -> Result<[u8; N]> {
    if p.len() < N {
        return Err(Error::InvalidEncoding(format!("short manifest fixed-{N}")));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&p[..N]);
    *p = &p[N..];
    Ok(out)
}
fn read_lp_string(p: &mut &[u8]) -> Result<String> {
    let len = read_u32_le(p)? as usize;
    if p.len() < len {
        return Err(Error::InvalidEncoding("short manifest string".into()));
    }
    let s = std::str::from_utf8(&p[..len])
        .map_err(|_| Error::InvalidEncoding("manifest string not utf-8".into()))?
        .to_string();
    *p = &p[len..];
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(version: u64, parent: [u8; 32]) -> OrgCipherManifest {
        OrgCipherManifest {
            org_id: "0192e0a0-0000-7000-8000-aaaaaaaaaaaa".into(),
            version,
            parent_canonical_sha256: parent,
            timestamp: "2026-05-03T00:00:00+00:00".into(),
            entries: vec![
                OrgCipherEntry {
                    cipher_id: "0192e0a0-0000-7000-8000-000000000002".into(),
                    revision_date: "2026-05-03T00:01:00+00:00".into(),
                    deleted: false,
                },
                OrgCipherEntry {
                    cipher_id: "0192e0a0-0000-7000-8000-000000000001".into(),
                    revision_date: "2026-05-03T00:00:30+00:00".into(),
                    deleted: true,
                },
            ],
        }
    }

    #[test]
    fn round_trips_under_correct_signing_key() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let signed = sample(1, NO_PARENT_HASH).sign(&sk);
        let parsed = signed.verify(&sk.verifying_key()).expect("valid sig");
        // sign() sorts entries.
        assert_eq!(
            parsed.entries[0].cipher_id,
            "0192e0a0-0000-7000-8000-000000000001"
        );
        assert_eq!(
            parsed.entries[1].cipher_id,
            "0192e0a0-0000-7000-8000-000000000002"
        );
        assert_eq!(parsed.version, 1);
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
        bytes[last] ^= 0x01; // flips the last entry's `deleted` flag
        signed.canonical_b64 = STANDARD_NO_PAD.encode(&bytes);
        assert!(signed.verify(&sk.verifying_key()).is_err());
    }

    #[test]
    fn decode_canonical_round_trips() {
        let mut m = sample(3, [0xa5u8; 32]);
        m.sort_entries();
        let bytes = m.canonical_bytes();
        let parsed = decode_canonical(&bytes).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn parent_hash_chains_forward() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let v1 = OrgCipherManifest {
            org_id: "org1".into(),
            version: 1,
            parent_canonical_sha256: NO_PARENT_HASH,
            timestamp: "t1".into(),
            entries: vec![],
        };
        let signed1 = v1.clone().sign(&sk);
        let canonical1 = STANDARD_NO_PAD.decode(&signed1.canonical_b64).unwrap();
        let parent_hash = hash_canonical(&canonical1);

        let v2 = OrgCipherManifest {
            org_id: "org1".into(),
            version: 2,
            parent_canonical_sha256: parent_hash,
            timestamp: "t2".into(),
            entries: vec![OrgCipherEntry {
                cipher_id: "abc".into(),
                revision_date: "t1.5".into(),
                deleted: false,
            }],
        };
        let signed2 = v2.sign(&sk);
        let parsed = signed2.verify(&sk.verifying_key()).unwrap();
        assert_eq!(parsed.parent_canonical_sha256, parent_hash);
        assert_eq!(parsed.org_id, "org1");
    }

    #[test]
    fn empty_manifest_signs_and_verifies() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let m = OrgCipherManifest {
            org_id: "org1".into(),
            version: 1,
            parent_canonical_sha256: NO_PARENT_HASH,
            timestamp: "t".into(),
            entries: vec![],
        };
        let signed = m.sign(&sk);
        let parsed = signed.verify(&sk.verifying_key()).unwrap();
        assert!(parsed.entries.is_empty());
    }

    #[test]
    fn canonical_bytes_stable_under_entry_reorder() {
        let mut a = sample(1, NO_PARENT_HASH);
        let mut b = sample(1, NO_PARENT_HASH);
        b.entries.reverse();
        a.sort_entries();
        b.sort_entries();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn decode_rejects_short_input() {
        assert!(decode_canonical(&[]).is_err());
        assert!(decode_canonical(DST).is_err());
        let mut m = sample(1, NO_PARENT_HASH);
        m.sort_entries();
        let bytes = m.canonical_bytes();
        assert!(decode_canonical(&bytes[..bytes.len() - 1]).is_err());
    }
}
