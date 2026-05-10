//! M4.5a — `hekate move-to-org` / `hekate move-to-personal`.
//!
//! Re-keys the cipher client-side on the way over: a fresh per-cipher
//! key is generated and wrapped under the destination key (the org
//! sym key for move-to-org, the user's account_key for
//! move-to-personal). Every encrypted field is re-encrypted under the
//! new cipher key so the wrap chain matches.
//!
//! The cipher's id is preserved (it's bound into AAD), so other clients
//! see the same row with a bumped `revision_date` and a new
//! `org_id` / `collection_ids` / `protected_cipher_key`.

use anyhow::{anyhow, Context, Result};
use clap::Parser;

use crate::{
    api::{MoveToOrgRequest, MoveToPersonalRequest},
    commands::{persist_refreshed_tokens, unlock_session},
    crypto::{
        aad_cipher_data, aad_cipher_name, aad_cipher_notes, decrypt_field, encrypt_field,
        new_cipher_key, new_cipher_key_under, unwrap_cipher_key, unwrap_cipher_key_under,
    },
};

#[derive(Debug, Parser)]
pub struct MoveToOrgArgs {
    /// Cipher id (UUID) to move.
    pub id: String,
    /// Target org UUID. Caller must be a member.
    #[arg(long)]
    pub org: String,
    /// One or more collection UUIDs in the target org. Repeat the
    /// flag to attach to multiple. Required for non-owners.
    #[arg(long = "collection")]
    pub collections: Vec<String>,
}

#[derive(Debug, Parser)]
pub struct MoveToPersonalArgs {
    /// Cipher id (UUID) to move.
    pub id: String,
}

pub fn run_to_org(args: MoveToOrgArgs) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;
    let current = api.get_cipher(&args.id)?;
    if current.org_id.is_some() {
        return Err(anyhow!(
            "cipher is already org-owned; use `hekate move-to-personal` first"
        ));
    }

    // Decrypt under the OLD wrap (account_key, since this is currently
    // a personal cipher).
    let old_key = unwrap_cipher_key(&unlocked, &current.protected_cipher_key, &current.id)?;
    let aad_n = aad_cipher_name(&current.id, current.cipher_type);
    let aad_o = aad_cipher_notes(&current.id, current.cipher_type);
    let aad_d = aad_cipher_data(&current.id, current.cipher_type);
    let plain_name =
        decrypt_field(&old_key, &current.name, &aad_n).context("decrypt name under old key")?;
    let plain_data =
        decrypt_field(&old_key, &current.data, &aad_d).context("decrypt data under old key")?;
    let plain_notes = match &current.notes {
        Some(w) => Some(decrypt_field(&old_key, w, &aad_o).context("decrypt notes")?),
        None => None,
    };

    // Generate a fresh per-cipher key wrapped under the org sym key.
    let (_org, org_sym_key) =
        crate::commands::org::fetch_org_and_unwrap(&api, &unlocked, &args.org)?;
    let (new_key, new_protected) = new_cipher_key_under(&org_sym_key, "ok:1", &current.id)?;

    let body = MoveToOrgRequest {
        org_id: args.org.clone(),
        collection_ids: args.collections.clone(),
        protected_cipher_key: new_protected,
        name: encrypt_field(&new_key, &plain_name, &aad_n)?,
        notes: plain_notes
            .as_deref()
            .map(|n| encrypt_field(&new_key, n, &aad_o))
            .transpose()?,
        data: encrypt_field(&new_key, &plain_data, &aad_d)?,
        favorite: current.favorite,
    };

    let view = api
        .move_cipher_to_org(&current.id, &current.revision_date, &body)
        .context("move-to-org")?;
    println!(
        "✓ Moved {} into org {} ({} collection(s))",
        view.id,
        args.org,
        args.collections.len()
    );
    // Cipher just left the BW04 personal-manifest set: refresh so the
    // user-side manifest stops claiming this cipher exists in personal
    // scope. Then refresh the per-org cipher manifest if we own the
    // target org (M2.21 / M4.5 follow-up).
    if let Err(e) = crate::manifest::sync_and_upload(&api, &unlocked) {
        eprintln!("warning: signed manifest upload failed after move: {e}");
    }
    if let Err(e) = crate::org_cipher_manifest::maybe_refresh_owner(&api, &unlocked, &args.org) {
        eprintln!("warning: org cipher manifest refresh failed: {e}");
    }
    persist_refreshed_tokens(&api, state)?;
    Ok(())
}

pub fn run_to_personal(args: MoveToPersonalArgs) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;
    let current = api.get_cipher(&args.id)?;
    let Some(org_id) = current.org_id.as_deref() else {
        return Err(anyhow!("cipher is already personal; nothing to do"));
    };

    // Decrypt under the OLD wrap (org sym key).
    let (_org, org_sym_key) = crate::commands::org::fetch_org_and_unwrap(&api, &unlocked, org_id)?;
    let old_key =
        unwrap_cipher_key_under(&org_sym_key, &current.protected_cipher_key, &current.id)?;
    let aad_n = aad_cipher_name(&current.id, current.cipher_type);
    let aad_o = aad_cipher_notes(&current.id, current.cipher_type);
    let aad_d = aad_cipher_data(&current.id, current.cipher_type);
    let plain_name =
        decrypt_field(&old_key, &current.name, &aad_n).context("decrypt name under old key")?;
    let plain_data =
        decrypt_field(&old_key, &current.data, &aad_d).context("decrypt data under old key")?;
    let plain_notes = match &current.notes {
        Some(w) => Some(decrypt_field(&old_key, w, &aad_o).context("decrypt notes")?),
        None => None,
    };

    let (new_key, new_protected) = new_cipher_key(&unlocked, &current.id)?;

    let body = MoveToPersonalRequest {
        protected_cipher_key: new_protected,
        name: encrypt_field(&new_key, &plain_name, &aad_n)?,
        notes: plain_notes
            .as_deref()
            .map(|n| encrypt_field(&new_key, n, &aad_o))
            .transpose()?,
        data: encrypt_field(&new_key, &plain_data, &aad_d)?,
        favorite: current.favorite,
    };

    let view = api
        .move_cipher_to_personal(&current.id, &current.revision_date, &body)
        .context("move-to-personal")?;
    println!("✓ Moved {} into your personal vault", view.id);
    // Personal ciphers participate in the BW04 manifest; refresh now
    // so other clients see the new ownership immediately.
    if let Err(e) = crate::manifest::sync_and_upload(&api, &unlocked) {
        eprintln!("warning: signed manifest upload failed after move: {e}");
    }
    // The cipher left the org set — refresh that org's cipher manifest
    // too so the org's set-state stops claiming it.
    if let Err(e) = crate::org_cipher_manifest::maybe_refresh_owner(&api, &unlocked, org_id) {
        eprintln!("warning: org cipher manifest refresh failed: {e}");
    }
    persist_refreshed_tokens(&api, state)?;
    Ok(())
}
