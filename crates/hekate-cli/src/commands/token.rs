//! `hekate token create / list / revoke` — Personal Access Token
//! management. Doesn't need to decrypt the vault, but does need to
//! authenticate; we use the same JWT session for now.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{
    api::{Api, CreatePatRequest},
    commands::persist_refreshed_tokens,
    state,
};

#[derive(Debug, Parser)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Debug, Subcommand)]
pub enum Action {
    /// Create a new Personal Access Token. The secret is printed once;
    /// store it now — there's no way to retrieve it later.
    Create(CreateArgs),
    /// List all PATs (metadata only).
    List,
    /// Revoke a PAT by id.
    Revoke(RevokeArgs),
}

#[derive(Debug, Parser)]
pub struct CreateArgs {
    /// Human-readable label for the token.
    #[arg(long)]
    pub name: String,
    /// Comma-separated scopes. Available: vault:read, vault:write,
    /// account:admin.
    #[arg(long, default_value = "vault:read")]
    pub scopes: String,
    /// Optional days until expiry. Omit for never-expires.
    #[arg(long)]
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Parser)]
pub struct RevokeArgs {
    pub id: String,
}

pub fn run(args: Args) -> Result<()> {
    let st = state::load()?
        .ok_or_else(|| anyhow::anyhow!("not logged in. Run `hekate login` first."))?;
    let api = Api::new(&st.server_url)?
        .with_bearer(st.tokens.access_token.clone())
        .with_refresh(st.tokens.refresh_token.clone());

    match args.action {
        Action::Create(c) => {
            let resp = api.create_pat(&CreatePatRequest {
                name: c.name,
                scopes: c.scopes,
                expires_in_days: c.expires_in_days,
            })?;
            println!("✓ Created token id {}", resp.id);
            println!("  name:    {}", resp.name);
            println!("  scopes:  {}", resp.scopes);
            if let Some(exp) = resp.expires_at {
                println!("  expires: {exp}");
            }
            println!();
            println!("PAT (store this — it won't be shown again):");
            println!();
            println!("  {}", resp.token);
        }
        Action::List => {
            let items = api.list_pats()?;
            if items.is_empty() {
                println!("(no tokens)");
            } else {
                println!(
                    "{:<36}  {:<24}  {:<28}  {:<22}  {:<22}  STATUS",
                    "ID", "NAME", "SCOPES", "CREATED", "LAST USED"
                );
                for it in items {
                    let status = if it.revoked_at.is_some() {
                        "revoked"
                    } else {
                        match &it.expires_at {
                            Some(_) => "active (expires)",
                            None => "active",
                        }
                    };
                    println!(
                        "{:<36}  {:<24}  {:<28}  {:<22}  {:<22}  {}",
                        truncate(&it.id, 36),
                        truncate(&it.name, 24),
                        truncate(&it.scopes, 28),
                        truncate(&it.created_at, 22),
                        truncate(it.last_used_at.as_deref().unwrap_or("never"), 22),
                        status
                    );
                }
            }
        }
        Action::Revoke(r) => {
            api.revoke_pat(&r.id)?;
            println!("✓ Revoked {}", r.id);
        }
    }

    persist_refreshed_tokens(&api, st)?;
    Ok(())
}

fn truncate(s: &str, w: usize) -> String {
    if s.len() > w {
        format!("{}…", &s[..w.saturating_sub(1)])
    } else {
        s.to_string()
    }
}
