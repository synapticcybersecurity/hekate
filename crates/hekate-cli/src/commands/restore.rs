//! `hekate restore <id>` — un-trash a soft-deleted cipher.

use anyhow::Result;
use clap::Parser;

use crate::commands::{persist_refreshed_tokens, unlock_session};

#[derive(Debug, Parser)]
pub struct Args {
    pub id: String,
}

pub fn run(args: Args) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;
    let view = api.restore_cipher(&args.id)?;
    println!("✓ Restored {} (revision {})", view.id, view.revision_date);
    match view.org_id.as_deref() {
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
