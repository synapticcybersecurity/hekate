//! CLI-side helpers for the per-org signed cipher manifest (BW04 at
//! org scope; M2.21 / M4.5 follow-up).
//!
//! Two responsibilities:
//!   1. After every org-cipher write the *owner* performs, rebuild +
//!      sign + upload the manifest so the server-stored set-state is
//!      always up to date. Non-owner writes leave the manifest stale
//!      until the owner runs `hekate org cipher-manifest refresh`
//!      (single-signer M4 v1 model).
//!   2. On every /sync, verify the signature under the locally-pinned
//!      org signing pubkey and cross-check every org-owned cipher
//!      against the manifest entries. Mismatches surface as ⚠.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hekate_core::org_cipher_manifest::{
    hash_canonical, OrgCipherEntry, OrgCipherManifest, SignedOrgCipherManifest, NO_PARENT_HASH,
};

use crate::{
    api::{Api, OrgCipherManifestUpload, OrgSyncView, SyncResponse},
    crypto::{Unlocked, AAD_PROTECTED_ACCOUNT_KEY},
};

/// Refresh the signed org cipher manifest if (and only if) the caller
/// is the org owner. Non-owners cannot sign — they leave the manifest
/// stale until the owner next refreshes.
///
/// Best-effort: returns `Ok(())` for all expected non-fatal cases
/// (caller isn't owner, signing seed isn't available, /sync fails).
/// Cipher writes already committed; refusing to rebuild here would
/// strand the manifest without buying any safety.
pub fn maybe_refresh_owner(api: &Api, unlocked: &Unlocked, org_id: &str) -> Result<()> {
    // Fetch the org metadata to check ownership and pull the wrapped
    // signing seed (only the owner gets a populated `owner_protected_signing_seed`).
    let org = match api.get_org(org_id) {
        Ok(o) => o,
        Err(_) => return Ok(()),
    };
    let Some(seed_wire) = org.owner_protected_signing_seed.as_deref() else {
        // Caller isn't the owner; nothing to sign.
        return Ok(());
    };
    let signing_seed = unwrap_signing_seed(&unlocked.account_key, seed_wire)?;
    let signing_key = SigningKey::from_bytes(&signing_seed);
    do_refresh(api, &signing_key, org_id)
}

/// Explicit owner-driven refresh. Same machinery as `maybe_refresh_owner`
/// but errors out loudly if the caller isn't the owner — surfaced by
/// `hekate org cipher-manifest refresh`.
pub fn refresh_explicit(api: &Api, unlocked: &Unlocked, org_id: &str) -> Result<()> {
    let org = api.get_org(org_id).context("fetch org")?;
    let seed_wire = org.owner_protected_signing_seed.as_deref().ok_or_else(|| {
        anyhow!("only the org owner can refresh the cipher manifest (single-signer M4 v1)")
    })?;
    let signing_seed = unwrap_signing_seed(&unlocked.account_key, seed_wire)?;
    let signing_key = SigningKey::from_bytes(&signing_seed);
    do_refresh(api, &signing_key, org_id)
}

fn do_refresh(api: &Api, signing_key: &SigningKey, org_id: &str) -> Result<()> {
    let sync = api.sync(None).context("sync to enumerate org ciphers")?;
    let entries = entries_from_sync(&sync, org_id);
    let entry = sync
        .orgs
        .iter()
        .find(|o| o.org_id == org_id)
        .ok_or_else(|| anyhow!("/sync returned no org entry for {org_id}"))?;

    let (next_version, parent_hash) = match &entry.cipher_manifest {
        Some(m) => {
            let prior_canonical = STANDARD_NO_PAD.decode(&m.canonical_b64).map_err(|e| {
                anyhow!("server's prior org cipher manifest canonical_b64 not base64: {e}")
            })?;
            ((m.version as u64) + 1, hash_canonical(&prior_canonical))
        }
        None => (1, NO_PARENT_HASH),
    };

    let manifest = OrgCipherManifest {
        org_id: org_id.to_string(),
        version: next_version,
        timestamp: chrono::Utc::now().to_rfc3339(),
        parent_canonical_sha256: parent_hash,
        entries,
    };
    let signed = manifest.sign(signing_key);
    api.upload_org_cipher_manifest(
        org_id,
        &OrgCipherManifestUpload {
            version: next_version as i64,
            canonical_b64: signed.canonical_b64,
            signature_b64: signed.signature_b64,
        },
    )?;
    Ok(())
}

/// Verify every org's cipher_manifest from a /sync response and
/// cross-check ciphers against it. Returns warnings keyed by org_id.
///
/// `expected_pubkey_for` resolves an org's expected signing pubkey
/// from the local TOFU pin store; missing or non-matching pin =
/// warning rather than hard error (the BW08 roster check is the
/// authoritative gate against fabricated org membership).
pub fn verify_against_sync<F>(sync: &SyncResponse, mut expected_pubkey_for: F) -> Vec<String>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut warnings: Vec<String> = Vec::new();
    for org in &sync.orgs {
        warnings.extend(verify_org_entry(org, sync, &mut expected_pubkey_for));
    }
    warnings
}

fn verify_org_entry<F>(
    org: &OrgSyncView,
    sync: &SyncResponse,
    expected_pubkey_for: &mut F,
) -> Vec<String>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut warnings: Vec<String> = Vec::new();

    // Ciphers actually returned for this org (after server-side
    // permission filter).
    let server_ciphers: Vec<&crate::api::CipherView> = sync
        .changes
        .ciphers
        .iter()
        .filter(|c| c.org_id.as_deref() == Some(org.org_id.as_str()))
        .collect();

    let Some(manifest_view) = org.cipher_manifest.as_ref() else {
        if !server_ciphers.is_empty() {
            warnings.push(format!(
                "org {} has {} cipher(s) but no signed cipher manifest yet — \
                 owner has not run `hekate org cipher-manifest refresh`",
                org.org_id,
                server_ciphers.len(),
            ));
        }
        return warnings;
    };
    let Some(pubkey_b64) = expected_pubkey_for(&org.org_id) else {
        warnings.push(format!(
            "org {}: cipher manifest present but no local pin — accept the \
             org via `hekate org accept` first",
            org.org_id,
        ));
        return warnings;
    };
    let pubkey = match parse_pubkey(&pubkey_b64) {
        Ok(p) => p,
        Err(e) => {
            warnings.push(format!(
                "org {}: malformed pinned signing pubkey: {e}",
                org.org_id
            ));
            return warnings;
        }
    };

    let signed = SignedOrgCipherManifest {
        canonical_b64: manifest_view.canonical_b64.clone(),
        signature_b64: manifest_view.signature_b64.clone(),
    };
    let parsed = match signed.verify(&pubkey) {
        Ok(m) => m,
        Err(e) => {
            warnings.push(format!(
                "org {}: cipher manifest signature did not verify: {e} — \
                 possible server substitution",
                org.org_id,
            ));
            return warnings;
        }
    };
    if parsed.org_id != org.org_id {
        warnings.push(format!(
            "org {}: manifest org_id {} does not match — refusing",
            org.org_id, parsed.org_id,
        ));
        return warnings;
    }
    if parsed.version as i64 != manifest_view.version {
        warnings.push(format!(
            "org {}: manifest wrapper version {} disagrees with canonical {}",
            org.org_id, manifest_view.version, parsed.version,
        ));
        return warnings;
    }

    // Cross-check ciphers vs manifest entries.
    let entries: std::collections::HashMap<&str, &OrgCipherEntry> = parsed
        .entries
        .iter()
        .map(|e| (e.cipher_id.as_str(), e))
        .collect();
    for c in &server_ciphers {
        let Some(entry) = entries.get(c.id.as_str()) else {
            warnings.push(format!(
                "org {}: cipher {} returned by server is NOT in the signed \
                 manifest — possible server-injected row, or owner has not \
                 yet refreshed after a non-owner write",
                org.org_id, c.id,
            ));
            continue;
        };
        if entry.revision_date != c.revision_date {
            warnings.push(format!(
                "org {}: cipher {}: server revision_date {} != manifest {} \
                 — possible replay or stale manifest",
                org.org_id, c.id, c.revision_date, entry.revision_date,
            ));
        }
        let server_deleted = c.deleted_date.is_some();
        if entry.deleted != server_deleted {
            warnings.push(format!(
                "org {}: cipher {}: server deleted={} but manifest deleted={} \
                 — possible resurrection or hidden trash",
                org.org_id, c.id, server_deleted, entry.deleted,
            ));
        }
    }
    let server_ids: std::collections::HashSet<&str> =
        server_ciphers.iter().map(|c| c.id.as_str()).collect();
    for entry in &parsed.entries {
        // Skip entries the manifest covers but the caller couldn't see:
        // that's the M4.4 permission filter, not a server drop.
        // Distinguishing the two needs a per-org full-listing endpoint;
        // for v1 we accept the false-negative on drop-detection for
        // members without `manage` everywhere. The owner (who DOES see
        // every cipher) catches drops on their next sync.
        if !server_ids.contains(entry.cipher_id.as_str()) && org.role.as_str() == "owner" {
            warnings.push(format!(
                "org {}: manifest lists cipher {} but /sync did NOT return it \
                 — possible server drop (you are the owner; this should not \
                 happen due to permissions)",
                org.org_id, entry.cipher_id,
            ));
        }
    }

    warnings
}

fn entries_from_sync(sync: &SyncResponse, org_id: &str) -> Vec<OrgCipherEntry> {
    sync.changes
        .ciphers
        .iter()
        .filter(|c| c.org_id.as_deref() == Some(org_id))
        .map(|c| OrgCipherEntry {
            cipher_id: c.id.clone(),
            revision_date: c.revision_date.clone(),
            deleted: c.deleted_date.is_some(),
        })
        .collect()
}

fn unwrap_signing_seed(account_key: &[u8; 32], wire: &str) -> Result<[u8; 32]> {
    let s = hekate_core::encstring::EncString::parse(wire)
        .context("parse owner_protected_signing_seed")?;
    let bytes = s
        .decrypt_xc20p(account_key, Some(b"pmgr-org-signing-seed"))
        .map_err(|e| anyhow!("decrypt org signing seed: {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("decrypted org signing seed has wrong length"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_pubkey(b64: &str) -> Result<VerifyingKey> {
    let bytes = STANDARD_NO_PAD
        .decode(b64)
        .map_err(|_| anyhow!("org signing pubkey not base64-no-pad"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("org signing pubkey has wrong length"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(|_| anyhow!("invalid Ed25519 org pubkey"))
}

// Suppress the unused-import warning in environments where every
// import isn't reachable through the public API yet.
#[allow(dead_code)]
fn _ensure_aad_used() {
    let _ = AAD_PROTECTED_ACCOUNT_KEY;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_filter_by_org_id() {
        // Stub a SyncResponse with a personal cipher and an org cipher;
        // entries_from_sync returns only the org cipher.
        // Build manually because constructing SyncResponse needs many fields.
        // Use serde_json to deserialize a minimal payload:
        let v = serde_json::json!({
            "changes": {
                "ciphers": [
                    {
                        "id": "personal",
                        "type": 1,
                        "folder_id": null,
                        "protected_cipher_key": "x",
                        "name": "n",
                        "notes": null,
                        "data": "d",
                        "favorite": false,
                        "revision_date": "r1",
                        "creation_date": "c1",
                        "deleted_date": null,
                        "org_id": null,
                        "collection_ids": [],
                    },
                    {
                        "id": "org-cipher",
                        "type": 1,
                        "folder_id": null,
                        "protected_cipher_key": "x",
                        "name": "n",
                        "notes": null,
                        "data": "d",
                        "favorite": false,
                        "revision_date": "r2",
                        "creation_date": "c2",
                        "deleted_date": null,
                        "org_id": "org1",
                        "collection_ids": [],
                    }
                ],
                "folders": [],
                "tombstones": []
            },
            "high_water": "hw",
            "server_time": "st",
            "complete": true,
            "manifest": null,
            "orgs": []
        });
        let sync: SyncResponse = serde_json::from_value(v).unwrap();
        let entries = entries_from_sync(&sync, "org1");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cipher_id, "org-cipher");
    }
}
