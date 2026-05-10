//! `hekate delete <id>` — soft delete (move to trash).

use anyhow::Result;
use clap::Parser;

use crate::commands::{persist_refreshed_tokens, unlock_session};

#[derive(Debug, Parser)]
pub struct Args {
    pub id: String,
}

pub fn run(args: Args) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;
    // Pre-fetch so we know whether to refresh the personal or per-org
    // signed manifest after the delete. Best-effort: if the lookup
    // fails, fall through and hit only the personal-manifest path.
    let pre_org_id = api.get_cipher(&args.id).ok().and_then(|c| c.org_id);
    api.soft_delete_cipher(&args.id)?;
    println!("✓ Moved {} to trash", args.id);
    match pre_org_id.as_deref() {
        None => {
            if let Err(e) = crate::manifest::sync_and_upload(&api, &unlocked) {
                eprintln!("warning: signed manifest upload failed: {e}");
            }
        }
        Some(oid) => {
            if let Err(e) = crate::org_cipher_manifest::maybe_refresh_owner(&api, &unlocked, oid) {
                eprintln!("warning: org cipher manifest refresh failed: {e}");
            }
        }
    }
    persist_refreshed_tokens(&api, state)?;
    Ok(())
}
