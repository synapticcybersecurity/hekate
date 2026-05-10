//! `hekate config` — local CLI preferences. Today's only knob is
//! `strict-manifest`, which decides whether `hekate sync` exits non-zero
//! on a personal-manifest BW04 mismatch (strict) or just prints the
//! warnings and exits 0 (the historical, conservative default).
//!
//! The setting lives on the per-account state file (same file the
//! login tokens are stored in); see `crate::state::Prefs`.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

use crate::state;

#[derive(Debug, Parser)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Debug, Subcommand)]
pub enum Action {
    /// Toggle whether BW04 personal-manifest mismatches on `hekate sync`
    /// are hard errors (`on`) or warnings (`off`). `status` prints the
    /// current setting without changing it.
    #[command(name = "strict-manifest")]
    StrictManifest(StrictManifestArgs),
}

#[derive(Debug, Parser)]
pub struct StrictManifestArgs {
    #[command(subcommand)]
    pub op: StrictManifestOp,
}

#[derive(Debug, Subcommand)]
pub enum StrictManifestOp {
    /// Enable strict mode. Personal-manifest mismatches on `sync` will
    /// exit non-zero with a load-bearing error. Other warnings (orgs,
    /// org cipher manifest) stay non-fatal — they have legitimate
    /// transient states under M4 v1's single-signer model.
    On,
    /// Switch back to warn-mode. Mismatches print but the command
    /// exits 0. This is the default for fresh installs.
    Off,
    /// Print the current setting.
    Status,
}

pub fn run(args: Args) -> Result<()> {
    match args.action {
        Action::StrictManifest(s) => strict_manifest(s),
    }
}

fn strict_manifest(args: StrictManifestArgs) -> Result<()> {
    let mut st =
        state::load()?.ok_or_else(|| anyhow!("not logged in. Run `hekate login` first."))?;
    match args.op {
        StrictManifestOp::Status => {
            println!(
                "strict-manifest: {}",
                if st.prefs.strict_manifest {
                    "on"
                } else {
                    "off"
                }
            );
        }
        StrictManifestOp::On => {
            st.prefs.strict_manifest = true;
            state::save(&st)?;
            println!("✓ strict-manifest: on");
            println!(
                "  `hekate sync` will now exit non-zero on a BW04 personal-manifest \
                 mismatch. Run `hekate config strict-manifest off` to revert."
            );
        }
        StrictManifestOp::Off => {
            st.prefs.strict_manifest = false;
            state::save(&st)?;
            println!("✓ strict-manifest: off");
            println!("  `hekate sync` will surface mismatches as warnings only.");
        }
    }
    Ok(())
}
