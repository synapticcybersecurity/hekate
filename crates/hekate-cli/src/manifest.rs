//! CLI-side helpers for the per-user signed vault manifest (BW04).
//!
//! Two responsibilities:
//!   1. After every successful cipher write, recompute + sign + upload
//!      the manifest so the server-stored set-state is always in sync
//!      with the actual rows. Other clients verify on their next sync.
//!   2. On every sync, verify the signature of the returned manifest
//!      (under the in-state account_signing_pubkey) and check that
//!      every cipher in `changes.ciphers` corresponds to a manifest
//!      entry with the same `revision_date`. Mismatch → warn loudly.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::VerifyingKey;
use hekate_core::manifest::{
    compute_attachments_root, hash_canonical, AttachmentTuple, ManifestEntry, SignedManifest,
    VaultManifest, NO_PARENT_HASH,
};

use crate::{
    api::{Api, ManifestUpload, ManifestView, SyncResponse},
    crypto::Unlocked,
};

/// Pull the latest cipher list from the server, build the manifest entries
/// from those rows, sign with the user's Ed25519 seed, and upload.
///
/// On a fresh account or after a write, this gets called from the
/// command's `run` after a successful create/update/delete/restore/purge.
/// The server enforces strictly-greater version, so we use
/// `current_version + 1` (or 1 for the first upload).
pub fn sync_and_upload(api: &Api, unlocked: &Unlocked) -> Result<()> {
    let sync = api.sync(None)?;
    let entries = entries_from_sync(&sync);

    let (next_version, parent_hash) = match &sync.manifest {
        Some(m) => {
            let prior_canonical = STANDARD_NO_PAD
                .decode(&m.canonical_b64)
                .map_err(|e| anyhow!("server's prior manifest canonical_b64 not base64: {e}"))?;
            ((m.version as u64) + 1, hash_canonical(&prior_canonical))
        }
        None => (1, NO_PARENT_HASH),
    };

    let manifest = VaultManifest {
        version: next_version,
        timestamp: chrono::Utc::now().to_rfc3339(),
        parent_canonical_sha256: parent_hash,
        entries,
    };
    let signed = manifest.sign(&unlocked.signing_seed);

    api.upload_manifest(&ManifestUpload {
        version: next_version as i64,
        canonical_b64: signed.canonical_b64,
        signature_b64: signed.signature_b64,
    })?;
    Ok(())
}

/// Verify the signed manifest from a `/sync` response and cross-check
/// every cipher against it. Returns a list of warnings — empty if the
/// manifest matches the cipher list exactly.
///
/// `expected_pubkey_b64` should come from the user's local state, NOT
/// the embedded `public_key_b64` on the wire (a malicious server could
/// swap that together with the signature).
pub fn verify_against_sync(sync: &SyncResponse, expected_pubkey_b64: &str) -> Result<Vec<String>> {
    let Some(manifest_view) = sync.manifest.as_ref() else {
        // No manifest yet — nothing to verify, but warn. Once the user
        // makes their first write under M2.15b+ the manifest exists.
        return Ok(vec!["server has no signed manifest yet".into()]);
    };
    if expected_pubkey_b64.is_empty() {
        return Ok(vec![
            "local state has no signing pubkey — re-register on a fresh DB \
             to enable BW04 set-level integrity"
                .into(),
        ]);
    }

    let pubkey = parse_pubkey(expected_pubkey_b64)?;
    let signed = manifest_view_to_signed(manifest_view);
    let parsed = signed
        .verify(&pubkey)
        .map_err(|e| anyhow!("manifest signature did not verify: {e}"))?;

    let mut warnings = Vec::new();
    let entries: std::collections::HashMap<&str, &ManifestEntry> = parsed
        .entries
        .iter()
        .map(|e| (e.cipher_id.as_str(), e))
        .collect();

    for c in &sync.changes.ciphers {
        // M4.3: org-owned ciphers live in a separate trust scope —
        // the BW04 per-user manifest only covers personal ciphers.
        // Org ciphers will get their own signed-set primitive in
        // M4.5 alongside org key rotation.
        if c.org_id.is_some() {
            continue;
        }
        let Some(entry) = entries.get(c.id.as_str()) else {
            warnings.push(format!(
                "cipher {} returned by server is NOT in the signed manifest \
                 — possible server-injected row",
                c.id
            ));
            continue;
        };
        if entry.revision_date != c.revision_date {
            warnings.push(format!(
                "cipher {}: server returned revision_date {} but the signed \
                 manifest says {} — possible server replay or rollback",
                c.id, c.revision_date, entry.revision_date
            ));
        }
        let server_deleted = c.deleted_date.is_some();
        if entry.deleted != server_deleted {
            warnings.push(format!(
                "cipher {}: server says deleted={} but the signed manifest \
                 says deleted={} — possible server resurrection or hidden trash",
                c.id, server_deleted, entry.deleted
            ));
        }
    }

    let server_ids: std::collections::HashSet<&str> = sync
        .changes
        .ciphers
        .iter()
        .filter(|c| c.org_id.is_none())
        .map(|c| c.id.as_str())
        .collect();
    for entry in &parsed.entries {
        if !server_ids.contains(entry.cipher_id.as_str()) {
            warnings.push(format!(
                "manifest lists cipher {} but the server's /sync did NOT \
                 return it — possible server drop",
                entry.cipher_id
            ));
        }
    }

    Ok(warnings)
}

fn entries_from_sync(sync: &SyncResponse) -> Vec<ManifestEntry> {
    // The per-user signed manifest covers ONLY personal ciphers
    // (M4.3). Org-owned ciphers belong to a different trust set and
    // get their own primitive in M4.5.
    //
    // (M2.24) Each entry also commits to its cipher's attachment list
    // via `attachments_root`. Group sync's flat `attachments` list by
    // cipher_id and SHA-256 the sorted (att_id, revision_date,
    // deleted) tuples; an empty list yields the all-zero sentinel.
    let mut by_cipher: std::collections::HashMap<&str, Vec<AttachmentTuple>> =
        std::collections::HashMap::new();
    for a in &sync.changes.attachments {
        by_cipher
            .entry(a.cipher_id.as_str())
            .or_default()
            .push(AttachmentTuple {
                attachment_id: a.id.clone(),
                revision_date: a.revision_date.clone(),
                deleted: a.deleted_date.is_some(),
            });
    }
    sync.changes
        .ciphers
        .iter()
        .filter(|c| c.org_id.is_none())
        .map(|c| {
            let attachments_root = by_cipher
                .get(c.id.as_str())
                .map(|t| compute_attachments_root(t))
                .unwrap_or([0u8; 32]);
            ManifestEntry {
                cipher_id: c.id.clone(),
                revision_date: c.revision_date.clone(),
                deleted: c.deleted_date.is_some(),
                attachments_root,
            }
        })
        .collect()
}

fn manifest_view_to_signed(v: &ManifestView) -> SignedManifest {
    // The server doesn't return the embedded public_key_b64 separately —
    // it's not stored on the manifest row. Verify uses an out-of-band
    // pubkey anyway, so the embedded value is unused here.
    SignedManifest {
        canonical_b64: v.canonical_b64.clone(),
        signature_b64: v.signature_b64.clone(),
        public_key_b64: String::new(),
    }
}

fn parse_pubkey(b64: &str) -> Result<VerifyingKey> {
    let bytes = STANDARD_NO_PAD
        .decode(b64)
        .map_err(|_| anyhow!("account_signing_pubkey_b64 not base64-no-pad"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("account_signing_pubkey has wrong length"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(|_| anyhow!("invalid Ed25519 pubkey on user state"))
}
