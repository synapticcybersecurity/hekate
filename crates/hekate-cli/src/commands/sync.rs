//! `hekate sync` — fetch deltas and report what changed since the last
//! call. Doesn't (yet) cache; just shows server-side state.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use hekate_core::{
    encstring::EncString,
    org_roster::decode_canonical as decode_roster_canonical,
    signcrypt::{self, SealedEnvelope},
};

use crate::{
    api::{Api, RotateConfirmRequest},
    commands::{persist_refreshed_tokens, unlock_session},
    crypto::{Unlocked, AAD_PROTECTED_ACCOUNT_KEY},
    state::State,
};

#[derive(Debug, Parser)]
pub struct Args {
    /// RFC3339 watermark; omit to receive everything.
    #[arg(long)]
    pub since: Option<String>,
}

pub fn run(args: Args) -> Result<()> {
    let (mut state, api, unlocked) = unlock_session()?;
    // `since` makes the cipher list a *delta*, which can't be fully
    // verified against an *absolute* manifest — only a full sync
    // (no `since`) gets verified. With `since`, we still print what
    // the server returned, but skip the BW04 cross-check.
    let full_sync = args.since.is_none();
    let mut resp = api.sync(args.since.as_deref())?;

    // M4.5b — consume any pending org-key rotation envelopes BEFORE
    // running the BW08 roster verification, so verification reports
    // the post-consume state (which is the actual user-visible
    // outcome). Each successful consume re-syncs locally at the next
    // run; for now we just refetch /sync once if any envelopes were
    // processed so the rest of this command sees the cleared state.
    let mut consume_warnings: Vec<String> = Vec::new();
    let mut consumed_any = false;
    for entry in resp.orgs.clone() {
        if entry.pending_envelope.is_none() {
            continue;
        }
        match consume_pending_envelope(&api, &state, &unlocked, &entry) {
            Ok(()) => {
                println!(
                    "↻ Consumed pending org-key rotation for {} (new key_id {})",
                    entry.org_id, entry.org_sym_key_id
                );
                consumed_any = true;
            }
            Err(e) => consume_warnings.push(format!("org {}: {e:#}", entry.org_id)),
        }
    }
    if consumed_any {
        // Refetch so the rest of the command (manifest verify, roster
        // verify, summary counts) sees the cleared pending fields and
        // any cipher rows that arrived as part of the rotation.
        resp = api.sync(args.since.as_deref())?;
    }
    persist_refreshed_tokens(&api, state.clone())?;
    println!("Server time: {}", resp.server_time);
    println!("High water:  {}", resp.high_water);
    println!("Ciphers:     {}", resp.changes.ciphers.len());
    println!("Folders:     {}", resp.changes.folders.len());
    println!("Tombstones:  {}", resp.changes.tombstones.len());
    if !resp.changes.tombstones.is_empty() {
        for t in &resp.changes.tombstones {
            println!("  removed {} {} at {}", t.kind, t.id, t.deleted_at);
        }
    }

    let mut strict_failure: Option<usize> = None;
    if full_sync {
        let warnings =
            crate::manifest::verify_against_sync(&resp, &state.user.account_signing_pubkey_b64)?;
        if warnings.is_empty() {
            println!(
                "Manifest:    ✓ verified ({} entries)",
                resp.changes.ciphers.len()
            );
        } else if state.prefs.strict_manifest {
            // Strict mode: surface warnings the same way, then fail
            // the command at the bottom so downstream automation
            // (CI, scripts) sees a non-zero exit. Other sections
            // (orgs, org ciphers) still print so the user gets the
            // full picture before the error fires.
            println!(
                "Manifest:    ✗ {} warning(s) — STRICT MODE, refusing",
                warnings.len()
            );
            for w in &warnings {
                println!("  ✗ {w}");
            }
            strict_failure = Some(warnings.len());
        } else {
            println!("Manifest:    ⚠ {} warning(s)", warnings.len());
            for w in &warnings {
                println!("  ⚠ {w}");
            }
        }
    }

    // M4.2 BW08 — verify each org's signed roster under the pinned
    // org signing key, regardless of whether this is a full or delta
    // sync. The roster is absolute (latest-only), so the delta-vs-full
    // distinction doesn't apply.
    if !resp.orgs.is_empty() {
        let (org_warnings, advances) =
            crate::org_sync::verify_against_sync(&resp, &state, &state.user.user_id)?;
        if org_warnings.is_empty() {
            println!("Orgs:        ✓ verified ({} org(s))", resp.orgs.len());
        } else {
            println!(
                "Orgs:        ⚠ {} warning(s) across {} org(s)",
                org_warnings.len(),
                resp.orgs.len()
            );
            for w in &org_warnings {
                println!("  ⚠ {w}");
            }
        }
        // Advance pins for orgs that verified cleanly. We persist
        // even if other orgs warned — the warnings don't poison
        // unrelated orgs.
        if !advances.is_empty() {
            for adv in advances {
                state.org_pins.insert(adv.org_id.clone(), adv);
            }
            crate::state::save(&state)?;
        }

        // M2.21 / M4.5 follow-up — per-org signed cipher manifest.
        // Verify each org's manifest under the pinned signing pubkey
        // and cross-check against the ciphers /sync returned.
        let cipher_warnings = crate::org_cipher_manifest::verify_against_sync(&resp, |org_id| {
            state
                .org_pins
                .get(org_id)
                .map(|p| p.signing_pubkey_b64.clone())
        });
        if cipher_warnings.is_empty() {
            // Only print when there's something to verify (an org with
            // a cipher manifest or org-owned ciphers). Empty case is
            // silent to avoid noise on first-touch orgs.
            let any_signed = resp.orgs.iter().any(|o| o.cipher_manifest.is_some());
            if any_signed {
                println!("Org ciphers: ✓ verified");
            }
        } else {
            println!("Org ciphers: ⚠ {} warning(s)", cipher_warnings.len());
            for w in &cipher_warnings {
                println!("  ⚠ {w}");
            }
        }
    }
    if !consume_warnings.is_empty() {
        println!(
            "Rotations: ⚠ {} pending envelope(s) could not be consumed",
            consume_warnings.len(),
        );
        for w in &consume_warnings {
            println!("  ⚠ {w}");
        }
    }

    // Strict-manifest mode: turn the personal-manifest warnings into
    // a hard non-zero exit AFTER printing every section, so the user
    // still sees orgs / org-ciphers / rotations context. Org-side
    // warnings stay warnings (per `Prefs::strict_manifest` doc).
    if let Some(n) = strict_failure {
        return Err(anyhow!(
            "strict-manifest mode is on and the personal vault manifest \
             reported {n} integrity warning(s). Run `hekate config strict-manifest off` \
             to switch back to warn-mode if this is expected (e.g. recovery)."
        ));
    }
    Ok(())
}

/// Decrypt a pending signcryption envelope (the new org sym key
/// rotated by the owner), re-wrap under our own account_key, and POST
/// /rotate-confirm to clear it server-side.
///
/// Verification chain:
///
///   1. The org owner is the only trust root for an org-key rotation
///      (single-signer model in M4 v1). They MUST be in our peer
///      pins; we refuse to decrypt envelopes from an unpinned sender
///      so a malicious server can't substitute its own envelope.
///   2. The signcryption envelope is verified under the owner's
///      pinned Ed25519 signing key (commits to sender + recipient +
///      ephemeral pubkey + ciphertext).
///   3. The decrypted payload's `org_id` and `org_sym_key_id` MUST
///      match the values from /sync (which were verified against the
///      pinned org signing key in `org_sync::verify_against_sync`).
///      Cross-checking these two trust paths is what closes the gap
///      where one is somehow being lied about.
fn consume_pending_envelope(
    api: &Api,
    state: &State,
    unlocked: &Unlocked,
    entry: &crate::api::OrgSyncView,
) -> Result<()> {
    let envelope_value = entry
        .pending_envelope
        .as_ref()
        .ok_or_else(|| anyhow!("no pending envelope"))?;
    let envelope: SealedEnvelope =
        serde_json::from_value(envelope_value.clone()).context("envelope shape")?;

    // The envelope's sender_id must be our pinned org owner. We don't
    // trust the server-supplied OrgView.owner_user_id in isolation —
    // we cross-check by looking up the pinned bundle.
    let owner_user_id = api
        .get_org(&entry.org_id)
        .context("fetch org to identify rotation initiator")?
        .owner_user_id;
    if envelope.sender_id != owner_user_id {
        return Err(anyhow!(
            "envelope sender {} does not match the org owner {} — \
             possible rotation injection",
            envelope.sender_id,
            owner_user_id,
        ));
    }
    let owner_pin = state.peer_pins.get(&owner_user_id).ok_or_else(|| {
        anyhow!(
            "org owner {owner_user_id} is not in peer pins — run \
             `hekate peer fetch {owner_user_id}` and verify the fingerprint \
             out of band before consuming the rotation."
        )
    })?;
    let owner_signing_pk = decode_pubkey_b64(&owner_pin.account_signing_pubkey_b64)?;
    let owner_vk = VerifyingKey::from_bytes(&owner_signing_pk)
        .map_err(|_| anyhow!("owner pinned signing key is not Ed25519"))?;

    // Our own X25519 secret (decrypts the envelope content key).
    let my_x25519_priv = decrypt_x25519_priv(
        &unlocked.account_key,
        &state.account_material.protected_account_private_key,
    )?;

    let plaintext =
        signcrypt::verify_decrypt(&envelope, &owner_vk, &state.user.user_id, &my_x25519_priv)
            .map_err(|e| {
                anyhow!(
                    "envelope did not verify under owner's pinned signing key: {e} — \
             possible server substitution"
                )
            })?;
    let payload: serde_json::Value =
        serde_json::from_slice(&plaintext).context("envelope payload not JSON")?;

    if payload["kind"].as_str() != Some("pmgr-org-key-rotation-v1") {
        return Err(anyhow!(
            "envelope payload kind is not pmgr-org-key-rotation-v1"
        ));
    }
    if payload["org_id"].as_str() != Some(entry.org_id.as_str()) {
        return Err(anyhow!(
            "envelope org_id does not match the org being rotated — \
             refusing to consume"
        ));
    }
    let claimed_key_id = payload["org_sym_key_id"]
        .as_str()
        .ok_or_else(|| anyhow!("envelope payload missing org_sym_key_id"))?;

    // The OrgSyncView.org_sym_key_id is from the *member row*, which
    // still references the OLD key until we POST /rotate-confirm. The
    // authoritative current key is whatever the signed roster says —
    // and the roster is BW08-verified upstream of this consume call.
    // Decode the canonical bytes to extract roster.org_sym_key_id and
    // compare the envelope against that.
    let roster_canonical = STANDARD_NO_PAD
        .decode(&entry.roster.canonical_b64)
        .context("decode roster canonical for key_id cross-check")?;
    let roster = decode_roster_canonical(&roster_canonical)
        .map_err(|e| anyhow!("decode roster canonical: {e}"))?;
    if claimed_key_id != roster.org_sym_key_id {
        return Err(anyhow!(
            "envelope org_sym_key_id ({claimed_key_id}) does not match the \
             current org_sym_key_id ({}) bound into the verified roster — \
             refusing to consume",
            roster.org_sym_key_id,
        ));
    }
    let new_sym_key_b64 = payload["org_sym_key_b64"]
        .as_str()
        .ok_or_else(|| anyhow!("envelope payload missing org_sym_key_b64"))?;
    let new_sym_key_bytes = STANDARD_NO_PAD
        .decode(new_sym_key_b64)
        .context("decode new org_sym_key_b64")?;
    if new_sym_key_bytes.len() != 32 {
        return Err(anyhow!("new org sym key has wrong length"));
    }

    // Re-wrap under our account_key for cheap unwrap on every sync.
    let protected_org_key = EncString::encrypt_xc20p(
        "ak:1",
        &unlocked.account_key,
        &new_sym_key_bytes,
        AAD_PROTECTED_ACCOUNT_KEY,
    )
    .map_err(|e| anyhow!("wrap new org sym key: {e}"))?
    .to_wire();

    api.rotate_confirm(
        &entry.org_id,
        &RotateConfirmRequest {
            protected_org_key,
            org_sym_key_id: claimed_key_id.to_string(),
        },
    )?;
    Ok(())
}

fn decode_pubkey_b64(b64: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD_NO_PAD
        .decode(b64)
        .context("pubkey not base64-no-pad")?;
    if bytes.len() != 32 {
        return Err(anyhow!("pubkey has wrong length"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn decrypt_x25519_priv(account_key: &[u8; 32], wire: &str) -> Result<[u8; 32]> {
    let s = EncString::parse(wire).context("malformed protected_account_private_key")?;
    let bytes = s
        .decrypt_xc20p(account_key, Some(b"pmgr-account-x25519-priv"))
        .map_err(|e| anyhow!("decrypt account x25519 priv: {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("account x25519 priv has wrong length"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
