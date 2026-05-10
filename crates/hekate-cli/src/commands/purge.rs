//! `hekate purge <id>` — hard delete (creates a tombstone).

use anyhow::{anyhow, Result};
use clap::Parser;

use crate::commands::{persist_refreshed_tokens, unlock_session};

#[derive(Debug, Parser)]
pub struct Args {
    pub id: String,
    /// Skip the y/N confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

pub fn run(args: Args) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;
    if !args.yes {
        eprint!("Permanently delete {}? [y/N] ", args.id);
        std::io::Write::flush(&mut std::io::stderr())?;
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)?;
        let answer = line.trim().to_lowercase();
        if answer != "y" && answer != "yes" {
            return Err(anyhow!("aborted"));
        }
    }
    // Pre-fetch so we know whether the purge will affect a per-org
    // manifest. After the purge the cipher row is gone, so capture
    // org_id first.
    let pre_org_id = api.get_cipher(&args.id).ok().and_then(|c| c.org_id);
    api.purge_cipher(&args.id)?;
    println!("✓ Purged {}", args.id);
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
