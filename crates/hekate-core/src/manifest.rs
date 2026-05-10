//! Per-user signed vault manifest — defense against malicious-server vault
//! drop / replay / soft-delete-resurrection (BW04 set-level integrity).
//!
//! The per-cipher AAD-binding from `hekate-cli/src/crypto.rs::aad_*` covers
//! *row*-level substitution: a server flipping a cipher's id, type, or
//! field role breaks decryption. But it says nothing about the **set** of
//! ciphers the user owns. A malicious server can still:
//!
//! - drop a cipher silently → client sees one fewer item, no tombstone
//! - resurrect a soft-deleted cipher by NULL-ing its `deleted_date`
//! - replay an old `revision_date` to hide a recent edit
//!
//! The manifest is a per-user signed list of `(cipher_id, revision_date,
//! deleted)` for every cipher the user owns, plus a monotonic `version`
//! and an absolute `timestamp`. The client signs it under an Ed25519
//! account-signing key derived from the master key, the server stores the
//! latest signed blob, and every other client verifies the signature on
//! sync and refuses to display state that doesn't match.
//!
//! ## Canonical bytes (signed)
//!
//! Length-prefixed binary so the serialization is unambiguous across
//! implementations (Rust CLI + JS WASM popup) and unaffected by JSON
//! whitespace / key-order quirks. All multi-byte integers are little-
//! endian. Entries are sorted by `cipher_id` (lexicographic, byte-wise).
//!
//! ```text
//! DST           := "pmgr-vault-manifest-v3\x00"
//! canonical     := DST
//!                || u64(version)
//!                || [32 bytes parent_canonical_sha256]   // zeros for genesis
//!                || u32(timestamp.len()) || timestamp_bytes
//!                || u32(entries.len())
//!                || entry × N
//! entry         := u32(id.len())  || id_bytes
//!                || u32(rev.len()) || rev_bytes
//!                || u8(deleted)                          // 0 = active, 1 = trashed
//!                || [32 bytes attachments_root]          // SHA-256 of sorted attachment tuples; zeros if none
//! ```
//!
//! The `attachments_root` (M2.24) extends BW04 set-level integrity to
//! cover the cipher's attachments. It is the SHA-256 of a length-prefixed
//! binary encoding of the sorted `(att_id, revision_date, deleted)`
//! tuples for that cipher's attachments — see [`compute_attachments_root`].
//! A malicious server that drops, replays, or resurrects an attachment
//! is detected because the signed root no longer matches what the client
//! reconstructs from the `/sync` attachment list.
//!
//! ## Hash chain
//!
//! Each manifest commits to its parent's *canonical bytes* via
//! `parent_canonical_sha256`. Server enforces uploaded manifest's
//! `parent_canonical_sha256` equals SHA-256 of the currently-stored
//! manifest's canonical bytes (or all-zeros if no manifest is stored).
//! A malicious server that replays an old manifest can't construct a
//! valid forward chain without the user's signing seed.
//!
//! ## Wire format (`SignedManifest`)
//!
//! Three base64-no-pad strings, all transmitted as plaintext JSON:
//! - `canonical_b64`: the canonical bytes above.
//! - `signature_b64`: 64-byte Ed25519 signature over the canonical bytes.
//! - `public_key_b64`: 32-byte Ed25519 verifying key. Echoed for sanity;
//!   the authoritative copy lives on the server's `users` row alongside
//!   the X25519 account public key, set at register time and immutable
//!   without re-derivation.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{kdf::MasterKey, Error, Result};

/// 32-byte Ed25519 seed; expanded by `ed25519-dalek` into the full
/// `SigningKey` on demand. Wrapped in `Zeroizing` because possession of
/// the seed is equivalent to the user's master password from the
/// signing-perspective.
pub type AccountSigningSeed = Zeroizing<[u8; 32]>;

/// Domain separation prefix for the canonical bytes that Ed25519 signs.
/// Bumped to `-v3` (M2.24) for the `attachments_root` field on every
/// entry. Pre-alpha, no migration path; old manifests are wiped
/// server-side (`0020_manifest_v3.sql`). Predecessors:
/// - v1: bare `(cipher_id, revision_date, deleted)` (M2.15b / M3.5)
/// - v2: + `parent_canonical_sha256` chain field (M2.15c)
/// - v3: + per-entry `attachments_root` (M2.24)
const MANIFEST_DST: &[u8] = b"pmgr-vault-manifest-v3\x00";

/// Length of `attachments_root` and `parent_canonical_sha256`. Both
/// are SHA-256 outputs.
pub const ATTACHMENTS_ROOT_LEN: usize = 32;

/// "No attachments" sentinel. Distinguishes "the cipher has zero
/// attachments" from "this entry was written by an older client that
/// didn't know about attachments" — both produce the same bytes, which
/// is correct: an absent attachments_root is logically the same as no
/// attachments, and the v3 wire bump means *every* entry now carries a
/// 32-byte field.
pub const NO_ATTACHMENTS_ROOT: [u8; ATTACHMENTS_ROOT_LEN] = [0u8; ATTACHMENTS_ROOT_LEN];

/// All-zeroes parent hash, used by the genesis manifest (version 1).
pub const NO_PARENT_HASH: [u8; 32] = [0u8; 32];

/// SHA-256 of arbitrary canonical bytes — what the next manifest's
/// `parent_canonical_sha256` must equal.
pub fn hash_canonical(canonical_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(canonical_bytes);
    h.finalize().into()
}

/// HKDF info tag — independent of the wrap/auth subkeys so a future
/// signing-format change can rotate this without rotating those.
const HKDF_INFO_SIGN: &[u8] = b"pmgr-sign-v1";

/// Derive the 32-byte Ed25519 seed from the master key.
pub fn derive_account_signing_seed(master_key: &MasterKey) -> AccountSigningSeed {
    let hk = Hkdf::<Sha256>::new(None, master_key.as_ref());
    let mut out = [0u8; SECRET_KEY_LENGTH];
    hk.expand(HKDF_INFO_SIGN, &mut out)
        .expect("HKDF length within bounds");
    Zeroizing::new(out)
}

/// Reconstruct the `SigningKey` from a previously-derived seed. Cheap.
pub fn signing_key_from_seed(seed: &AccountSigningSeed) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// Public verifying key derived from the seed — what the server stores
/// and other clients check signatures against.
pub fn verifying_key_from_seed(seed: &AccountSigningSeed) -> VerifyingKey {
    signing_key_from_seed(seed).verifying_key()
}

/// One row in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub cipher_id: String,
    /// RFC3339 `revision_date` from the cipher's last write. Replay defense.
    pub revision_date: String,
    /// True if `deleted_date` is set on the server row. Server resurrection
    /// of a soft-deleted cipher is detected by the boolean flipping
    /// without a manifest update.
    pub deleted: bool,
    /// SHA-256 of the cipher's sorted attachment tuples (M2.24). All-zero
    /// when the cipher has no attachments. Build via
    /// [`compute_attachments_root`] passing the same `(att_id,
    /// revision_date, deleted)` tuples the server returned in /sync.
    /// Serialized as base64-no-pad on the JS side via the `attachmentsRoot`
    /// JSON field.
    #[serde(default = "default_attachments_root", with = "att_root_b64")]
    pub attachments_root: [u8; ATTACHMENTS_ROOT_LEN],
}

fn default_attachments_root() -> [u8; ATTACHMENTS_ROOT_LEN] {
    NO_ATTACHMENTS_ROOT
}

mod att_root_b64 {
    use super::ATTACHMENTS_ROOT_LEN;
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        v: &[u8; ATTACHMENTS_ROOT_LEN],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD_NO_PAD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<[u8; ATTACHMENTS_ROOT_LEN], D::Error> {
        let s = String::deserialize(d)?;
        if s.is_empty() {
            return Ok([0u8; ATTACHMENTS_ROOT_LEN]);
        }
        let bytes = STANDARD_NO_PAD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != ATTACHMENTS_ROOT_LEN {
            return Err(serde::de::Error::custom(
                "attachments_root must be 32 bytes",
            ));
        }
        let mut out = [0u8; ATTACHMENTS_ROOT_LEN];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

/// One row of the input to [`compute_attachments_root`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentTuple {
    pub attachment_id: String,
    pub revision_date: String,
    pub deleted: bool,
}

/// Hash a cipher's attachment list into the 32-byte root that goes into
/// its [`ManifestEntry`]. Tuples are sorted by `attachment_id`
/// (byte-wise) before hashing so the result is deterministic regardless
/// of the order the server returned them.
///
/// Empty input → [`NO_ATTACHMENTS_ROOT`] (all-zero bytes). This is also
/// what `default_attachments_root` returns for backward-compat decoders.
///
/// Encoding (length-prefixed binary, all u32 little-endian):
///
/// ```text
/// DST          := "pmgr-attachments-root-v1\x00"
/// canonical    := DST
///              || u32(count)
///              || tuple × N
/// tuple        := u32(att_id.len())  || att_id_bytes
///              || u32(rev.len())     || rev_bytes
///              || u8(deleted)
/// ```
pub fn compute_attachments_root(tuples: &[AttachmentTuple]) -> [u8; ATTACHMENTS_ROOT_LEN] {
    if tuples.is_empty() {
        return NO_ATTACHMENTS_ROOT;
    }
    const ATT_DST: &[u8] = b"pmgr-attachments-root-v1\x00";
    let mut sorted: Vec<&AttachmentTuple> = tuples.iter().collect();
    sorted.sort_by(|a, b| a.attachment_id.cmp(&b.attachment_id));
    let mut buf = Vec::with_capacity(ATT_DST.len() + 4 + sorted.len() * 64);
    buf.extend_from_slice(ATT_DST);
    buf.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
    for t in &sorted {
        let id = t.attachment_id.as_bytes();
        let rev = t.revision_date.as_bytes();
        buf.extend_from_slice(&(id.len() as u32).to_le_bytes());
        buf.extend_from_slice(id);
        buf.extend_from_slice(&(rev.len() as u32).to_le_bytes());
        buf.extend_from_slice(rev);
        buf.push(if t.deleted { 1 } else { 0 });
    }
    let mut h = Sha256::new();
    h.update(&buf);
    h.finalize().into()
}

/// Plaintext form. Verifiers should not display this — they should call
/// `SignedManifest::verify` and only use the returned `VaultManifest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultManifest {
    /// Monotonic counter. Server enforces strictly-greater on upload.
    pub version: u64,
    /// RFC3339 of when the manifest was generated. Defense-in-depth
    /// against replay even if version somehow regresses.
    pub timestamp: String,
    /// SHA-256 of the previous manifest's canonical bytes, or
    /// `NO_PARENT_HASH` (32 zero bytes) for the genesis (version 1)
    /// upload. Forms a hash chain so a malicious server can't
    /// silently roll the user back to an older manifest.
    pub parent_canonical_sha256: [u8; 32],
    pub entries: Vec<ManifestEntry>,
}

impl VaultManifest {
    /// Sort entries deterministically. Call before signing.
    pub fn sort_entries(&mut self) {
        self.entries.sort_by(|a, b| a.cipher_id.cmp(&b.cipher_id));
    }

    /// Canonical bytes — see module docs.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MANIFEST_DST.len() + 64 + 32 + self.entries.len() * 128);
        out.extend_from_slice(MANIFEST_DST);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.parent_canonical_sha256);
        let ts = self.timestamp.as_bytes();
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
            out.extend_from_slice(&e.attachments_root);
        }
        out
    }

    /// Sign in place: sorts entries, encodes canonical bytes, signs.
    pub fn sign(mut self, seed: &AccountSigningSeed) -> SignedManifest {
        self.sort_entries();
        let canonical = self.canonical_bytes();
        let sk = signing_key_from_seed(seed);
        let sig = sk.sign(&canonical);
        SignedManifest {
            canonical_b64: STANDARD_NO_PAD.encode(&canonical),
            signature_b64: STANDARD_NO_PAD.encode(sig.to_bytes()),
            public_key_b64: STANDARD_NO_PAD.encode(sk.verifying_key().as_bytes()),
        }
    }
}

/// Wire form: three base64-no-pad strings carried as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedManifest {
    pub canonical_b64: String,
    pub signature_b64: String,
    pub public_key_b64: String,
}

impl SignedManifest {
    /// Verify the signature with the *expected* verifying key (from the
    /// server's `users` row, not the embedded `public_key_b64`), then
    /// parse the canonical bytes back to a `VaultManifest`.
    ///
    /// Callers should always pass the authoritative pubkey — the
    /// embedded `public_key_b64` is for diagnostics only. (If the server
    /// is malicious, it could swap both the signature and the embedded
    /// pubkey to a key it controls; only the out-of-band-pinned pubkey
    /// catches that.)
    pub fn verify(&self, expected_pubkey: &VerifyingKey) -> Result<VaultManifest> {
        let canonical = STANDARD_NO_PAD
            .decode(&self.canonical_b64)
            .map_err(|_| Error::InvalidEncoding("canonical_b64 not base64-no-pad".into()))?;
        let sig_bytes = STANDARD_NO_PAD
            .decode(&self.signature_b64)
            .map_err(|_| Error::InvalidEncoding("signature_b64 not base64-no-pad".into()))?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|_| Error::InvalidEncoding("signature has wrong length".into()))?;
        // Audit H-2 (2026-05-07): use verify_strict to reject
        // non-canonical signature scalars (s ≥ ℓ) and small-order R
        // points. The lax `verify()` permits both, which would let a
        // server (or anyone holding a valid manifest) produce a
        // second byte-different signature that also verifies — a
        // signature-uniqueness gap any caching/dedup layer would mis-
        // assume away. ed25519-dalek explicitly recommends
        // verify_strict for verification-across-trust-boundary use.
        expected_pubkey
            .verify_strict(&canonical, &sig)
            .map_err(|_| Error::InvalidEncoding("manifest signature verify failed".into()))?;
        decode_canonical(&canonical)
    }
}

/// Parse canonical bytes back to a `VaultManifest`. Pure parser — does
/// not validate the signature; callers should go through
/// `SignedManifest::verify` instead.
pub fn decode_canonical(canonical: &[u8]) -> Result<VaultManifest> {
    let mut p = canonical;
    expect_prefix(&mut p, MANIFEST_DST)?;
    let version = read_u64_le(&mut p)?;
    let parent = read_fixed::<32>(&mut p)?;
    let ts = read_lp_string(&mut p)?;
    let n_entries = read_u32_le(&mut p)? as usize;
    // Audit H-3 (2026-05-07): cap the pre-allocation against the
    // remaining buffer length so a malicious-but-validly-signed blob
    // can't OOM the client by claiming `n_entries = u32::MAX`. Each
    // entry is at minimum 4(cipher_id len) + 4(rev len) + 1(deleted)
    // + 32(attachments_root) = 41 bytes; we use a slightly looser
    // floor (8) to stay safe against future schema tweaks while still
    // bounding the worst case at ~p.len()/8 entries. The signed
    // wrapper can still trip OOM via huge `canonical_b64`, but the
    // base64 decode and the signature pubkey gate make that visible
    // upstream.
    const MIN_ENTRY_SIZE: usize = 8;
    let cap = n_entries.min(p.len() / MIN_ENTRY_SIZE + 1);
    let mut entries = Vec::with_capacity(cap);
    for _ in 0..n_entries {
        let cipher_id = read_lp_string(&mut p)?;
        let revision_date = read_lp_string(&mut p)?;
        let deleted = read_u8(&mut p)? != 0;
        let attachments_root = read_fixed::<ATTACHMENTS_ROOT_LEN>(&mut p)?;
        entries.push(ManifestEntry {
            cipher_id,
            revision_date,
            deleted,
            attachments_root,
        });
    }
    if !p.is_empty() {
        return Err(Error::InvalidEncoding(
            "trailing bytes after manifest".into(),
        ));
    }
    Ok(VaultManifest {
        version,
        timestamp: ts,
        parent_canonical_sha256: parent,
        entries,
    })
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

// --- canonical-bytes parser helpers ---------------------------------------

fn expect_prefix(p: &mut &[u8], prefix: &[u8]) -> Result<()> {
    if p.len() < prefix.len() || &p[..prefix.len()] != prefix {
        return Err(Error::InvalidEncoding("bad manifest prefix".into()));
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
    use crate::kdf::{derive_master_key, KdfParams};

    fn fast_master_key() -> MasterKey {
        derive_master_key(
            b"hunter2",
            KdfParams::Argon2id {
                m_kib: 64,
                t: 1,
                p: 1,
            },
            &[0u8; 16],
        )
        .unwrap()
    }

    fn sample_manifest() -> VaultManifest {
        VaultManifest {
            version: 1,
            timestamp: "2026-05-02T12:00:00+00:00".into(),
            parent_canonical_sha256: NO_PARENT_HASH,
            entries: vec![
                ManifestEntry {
                    cipher_id: "0192e0a0-0000-7000-8000-000000000002".into(),
                    revision_date: "2026-05-02T11:59:00+00:00".into(),
                    deleted: false,
                    attachments_root: NO_ATTACHMENTS_ROOT,
                },
                ManifestEntry {
                    cipher_id: "0192e0a0-0000-7000-8000-000000000001".into(),
                    revision_date: "2026-05-02T11:58:00+00:00".into(),
                    deleted: true,
                    attachments_root: NO_ATTACHMENTS_ROOT,
                },
            ],
        }
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let mk = fast_master_key();
        let seed = derive_account_signing_seed(&mk);
        let pubkey = verifying_key_from_seed(&seed);

        let signed = sample_manifest().sign(&seed);
        let parsed = signed.verify(&pubkey).expect("valid signature");
        // sign() sorts entries; verify what we got back.
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
    fn decode_caps_huge_n_entries_against_remaining_buffer() {
        // Audit H-3 (2026-05-07) regression: an attacker who can sign
        // a manifest (or anyone holding a leaked signing key) could
        // emit a header claiming `n_entries = u32::MAX` followed by a
        // tiny body. Pre-fix, `Vec::with_capacity(u32::MAX as usize)`
        // would attempt a ~96 GiB allocation and abort the client.
        // Post-fix, we cap the pre-allocation against the remaining
        // buffer and let the per-entry parse fail naturally.
        let mut canonical = Vec::new();
        canonical.extend_from_slice(MANIFEST_DST);
        canonical.extend_from_slice(&1u64.to_le_bytes()); // version
        canonical.extend_from_slice(&NO_PARENT_HASH); // parent
                                                      // timestamp (lp string)
        let ts = b"2026-05-07T00:00:00+00:00";
        canonical.extend_from_slice(&(ts.len() as u32).to_le_bytes());
        canonical.extend_from_slice(ts);
        // Claim u32::MAX entries — body has none.
        canonical.extend_from_slice(&u32::MAX.to_le_bytes());
        // Decoder should return Err quickly, NOT allocate ~96 GiB.
        let r = decode_canonical(&canonical);
        assert!(
            r.is_err(),
            "decoder must reject truncated body for huge n_entries"
        );
    }

    #[test]
    fn verify_rejects_signature_under_wrong_key() {
        let seed_a = derive_account_signing_seed(&fast_master_key());
        let mk_b = derive_master_key(
            b"different",
            KdfParams::Argon2id {
                m_kib: 64,
                t: 1,
                p: 1,
            },
            &[0u8; 16],
        )
        .unwrap();
        let pubkey_b = verifying_key_from_seed(&derive_account_signing_seed(&mk_b));

        let signed = sample_manifest().sign(&seed_a);
        assert!(signed.verify(&pubkey_b).is_err());
    }

    #[test]
    fn verify_rejects_tampered_canonical() {
        let seed = derive_account_signing_seed(&fast_master_key());
        let pubkey = verifying_key_from_seed(&seed);

        let mut signed = sample_manifest().sign(&seed);
        // Flip a byte in the canonical payload — invalidates signature.
        let mut bytes = STANDARD_NO_PAD.decode(&signed.canonical_b64).unwrap();
        let tail = bytes.len() - 1;
        bytes[tail] ^= 0x01; // flip the last byte of the trailing attachments_root
        signed.canonical_b64 = STANDARD_NO_PAD.encode(&bytes);
        assert!(signed.verify(&pubkey).is_err());
    }

    #[test]
    fn canonical_bytes_are_stable_under_entry_reorder() {
        // Same logical manifest, different in-memory order → identical
        // canonical bytes after sort.
        let mut a = sample_manifest();
        let mut b = sample_manifest();
        b.entries.reverse();
        a.sort_entries();
        b.sort_entries();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn decode_canonical_round_trips() {
        let mut m = sample_manifest();
        m.sort_entries();
        let bytes = m.canonical_bytes();
        let parsed = decode_canonical(&bytes).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn decode_canonical_rejects_short_input() {
        assert!(decode_canonical(&[]).is_err());
        assert!(decode_canonical(MANIFEST_DST).is_err());
        // truncated entry
        let mut m = sample_manifest();
        m.sort_entries();
        let bytes = m.canonical_bytes();
        assert!(decode_canonical(&bytes[..bytes.len() - 1]).is_err());
    }

    /// JS-shape (camelCase) JSON should deserialize to a struct that
    /// converts losslessly to VaultManifest. This guards the wire format
    /// the popup uses through `hekate-core::wasm::JsManifest`. We test it
    /// here via serde_json since the WASM runtime is absent in cargo test.
    /// The popup may omit `attachmentsRoot` for ciphers with no
    /// attachments — the deserializer should default it to all-zeros.
    #[test]
    fn js_camelcase_shape_round_trips_through_serde() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize)]
        struct JsManifest {
            version: u64,
            timestamp: String,
            entries: Vec<JsEntry>,
        }
        #[derive(Serialize, Deserialize)]
        struct JsEntry {
            #[serde(rename = "cipherId")]
            cipher_id: String,
            #[serde(rename = "revisionDate")]
            revision_date: String,
            deleted: bool,
            /// base64-no-pad of 32-byte attachments_root, or absent
            /// for ciphers with no attachments.
            #[serde(rename = "attachmentsRoot", default)]
            attachments_root_b64: Option<String>,
        }

        // Exactly the JSON the popup builds via `JSON.stringify(manifestObj)`.
        let popup_json = r#"{
            "version": 7,
            "timestamp": "2026-05-02T12:00:00+00:00",
            "entries": [
                {
                    "cipherId": "0192e0a0-0000-7000-8000-000000000001",
                    "revisionDate": "2026-05-02T11:58:00+00:00",
                    "deleted": false
                }
            ]
        }"#;
        let js: JsManifest = serde_json::from_str(popup_json).unwrap();
        let m = VaultManifest {
            version: js.version,
            timestamp: js.timestamp,
            parent_canonical_sha256: NO_PARENT_HASH,
            entries: js
                .entries
                .into_iter()
                .map(|e| {
                    let attachments_root = match e.attachments_root_b64 {
                        Some(s) if !s.is_empty() => {
                            let bytes = STANDARD_NO_PAD.decode(&s).unwrap();
                            let mut a = [0u8; ATTACHMENTS_ROOT_LEN];
                            a.copy_from_slice(&bytes);
                            a
                        }
                        _ => NO_ATTACHMENTS_ROOT,
                    };
                    ManifestEntry {
                        cipher_id: e.cipher_id,
                        revision_date: e.revision_date,
                        deleted: e.deleted,
                        attachments_root,
                    }
                })
                .collect(),
        };
        assert_eq!(m.version, 7);
        assert_eq!(m.entries.len(), 1);
        assert_eq!(
            m.entries[0].cipher_id,
            "0192e0a0-0000-7000-8000-000000000001"
        );
        assert_eq!(m.entries[0].attachments_root, NO_ATTACHMENTS_ROOT);

        // Signs successfully under a real key.
        let seed = derive_account_signing_seed(&fast_master_key());
        let pubkey = verifying_key_from_seed(&seed);
        let signed = m.sign(&seed);
        signed
            .verify(&pubkey)
            .expect("popup-shape JSON signs and verifies");
    }

    #[test]
    fn compute_attachments_root_is_deterministic_under_reorder() {
        let a = AttachmentTuple {
            attachment_id: "att-1".into(),
            revision_date: "2026-05-01T00:00:00Z".into(),
            deleted: false,
        };
        let b = AttachmentTuple {
            attachment_id: "att-2".into(),
            revision_date: "2026-05-02T00:00:00Z".into(),
            deleted: true,
        };
        let r1 = compute_attachments_root(&[a.clone(), b.clone()]);
        let r2 = compute_attachments_root(&[b, a]);
        assert_eq!(r1, r2);
        assert_ne!(r1, NO_ATTACHMENTS_ROOT);
    }

    #[test]
    fn compute_attachments_root_empty_is_zero() {
        assert_eq!(compute_attachments_root(&[]), NO_ATTACHMENTS_ROOT);
    }

    #[test]
    fn compute_attachments_root_changes_on_revision_bump() {
        let mk = |rev: &str, deleted: bool| AttachmentTuple {
            attachment_id: "att-1".into(),
            revision_date: rev.into(),
            deleted,
        };
        let r1 = compute_attachments_root(&[mk("2026-01-01T00:00:00Z", false)]);
        let r2 = compute_attachments_root(&[mk("2026-01-02T00:00:00Z", false)]);
        let r3 = compute_attachments_root(&[mk("2026-01-01T00:00:00Z", true)]);
        assert_ne!(r1, r2);
        assert_ne!(r1, r3);
    }

    #[test]
    fn manifest_entry_with_attachments_root_round_trips() {
        let seed = derive_account_signing_seed(&fast_master_key());
        let pubkey = verifying_key_from_seed(&seed);
        let root = compute_attachments_root(&[AttachmentTuple {
            attachment_id: "att-x".into(),
            revision_date: "2026-05-02T11:58:00+00:00".into(),
            deleted: false,
        }]);
        let m = VaultManifest {
            version: 1,
            timestamp: "2026-05-02T12:00:00+00:00".into(),
            parent_canonical_sha256: NO_PARENT_HASH,
            entries: vec![ManifestEntry {
                cipher_id: "cipher-with-att".into(),
                revision_date: "2026-05-02T11:58:00+00:00".into(),
                deleted: false,
                attachments_root: root,
            }],
        };
        let signed = m.sign(&seed);
        let parsed = signed.verify(&pubkey).unwrap();
        assert_eq!(parsed.entries[0].attachments_root, root);
    }

    #[test]
    fn empty_manifest_signs_and_verifies() {
        let seed = derive_account_signing_seed(&fast_master_key());
        let pubkey = verifying_key_from_seed(&seed);
        let m = VaultManifest {
            version: 1,
            timestamp: "2026-05-02T12:00:00+00:00".into(),
            parent_canonical_sha256: NO_PARENT_HASH,
            entries: vec![],
        };
        let signed = m.sign(&seed);
        let parsed = signed.verify(&pubkey).unwrap();
        assert!(parsed.entries.is_empty());
    }

    #[test]
    fn parent_hash_chains_correctly() {
        let seed = derive_account_signing_seed(&fast_master_key());
        let pubkey = verifying_key_from_seed(&seed);

        // Genesis manifest (no parent).
        let v1 = VaultManifest {
            version: 1,
            timestamp: "2026-05-02T12:00:00+00:00".into(),
            parent_canonical_sha256: NO_PARENT_HASH,
            entries: vec![],
        };
        let signed1 = v1.clone().sign(&seed);
        let canonical1 = STANDARD_NO_PAD.decode(&signed1.canonical_b64).unwrap();
        let parent_hash = hash_canonical(&canonical1);

        // Forward link.
        let v2 = VaultManifest {
            version: 2,
            timestamp: "2026-05-02T12:01:00+00:00".into(),
            parent_canonical_sha256: parent_hash,
            entries: vec![ManifestEntry {
                cipher_id: "abc".into(),
                revision_date: "2026-05-02T12:00:30+00:00".into(),
                deleted: false,
                attachments_root: NO_ATTACHMENTS_ROOT,
            }],
        };
        let signed2 = v2.sign(&seed);
        let parsed2 = signed2.verify(&pubkey).unwrap();
        assert_eq!(parsed2.parent_canonical_sha256, parent_hash);
        // The genesis manifest's parent is all-zero — that's how
        // server distinguishes "first-ever upload" from "I don't know
        // what your prior was".
        assert_eq!(
            signed1.verify(&pubkey).unwrap().parent_canonical_sha256,
            NO_PARENT_HASH
        );
    }
}
