//! `hekate webhook create / list / delete` — manage outbound webhook
//! subscriptions. The HMAC secret is printed once on creation.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{
    api::{Api, CreateWebhookRequest},
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
    /// Subscribe a URL to receive signed webhook events. The HMAC
    /// secret is printed once — store it now.
    Create(CreateArgs),
    /// List webhook subscriptions.
    List,
    /// Delete a webhook subscription.
    Delete(DeleteArgs),
    /// Show recent delivery attempts for a webhook (last 50).
    Deliveries(DeliveriesArgs),
}

#[derive(Debug, Parser)]
pub struct CreateArgs {
    #[arg(long)]
    pub name: String,
    /// Destination URL (http or https).
    #[arg(long)]
    pub url: String,
    /// Comma-separated event filter. Omit or `*` for all. Known kinds:
    /// cipher.changed, cipher.deleted, cipher.tombstoned, folder.changed,
    /// folder.tombstoned.
    #[arg(long)]
    pub events: Option<String>,
}

#[derive(Debug, Parser)]
pub struct DeleteArgs {
    pub id: String,
}

#[derive(Debug, Parser)]
pub struct DeliveriesArgs {
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
            let resp = api.create_webhook(&CreateWebhookRequest {
                name: c.name,
                url: c.url,
                events: c.events,
            })?;
            println!("✓ Created webhook id {}", resp.id);
            println!("  name:   {}", resp.name);
            println!("  url:    {}", resp.url);
            println!("  events: {}", resp.events);
            println!();
            println!("HMAC secret (store this — it won't be shown again):");
            println!();
            println!("  {}", resp.secret);
            println!();
            println!("Verify incoming requests by recomputing");
            println!("  HMAC-SHA-256(secret, \"<unix_secs>.\" + body)");
            println!("and comparing to the v1 component of the X-Hekate-Signature header.");
        }
        Action::List => {
            let items = api.list_webhooks()?;
            if items.is_empty() {
                println!("(no webhooks)");
            } else {
                println!(
                    "{:<36}  {:<20}  {:<32}  {:<22}  STATUS",
                    "ID", "NAME", "EVENTS", "CREATED"
                );
                for it in items {
                    let status = if it.disabled_at.is_some() {
                        "disabled"
                    } else {
                        "active"
                    };
                    println!(
                        "{:<36}  {:<20}  {:<32}  {:<22}  {}",
                        truncate(&it.id, 36),
                        truncate(&it.name, 20),
                        truncate(&it.events, 32),
                        truncate(&it.created_at, 22),
                        status
                    );
                    println!("  → {}", it.url);
                }
            }
        }
        Action::Delete(d) => {
            api.delete_webhook(&d.id)?;
            println!("✓ Deleted {}", d.id);
        }
        Action::Deliveries(d) => {
            let items = api.list_deliveries(&d.id)?;
            if items.is_empty() {
                println!("(no deliveries yet)");
            } else {
                println!(
                    "{:<24}  {:<22}  {:>3}  {:>6}  STATUS",
                    "EVENT_TYPE", "CREATED", "TRY", "HTTP"
                );
                for it in items {
                    let status = if it.delivered_at.is_some() {
                        "delivered".to_string()
                    } else if it.failed_permanently_at.is_some() {
                        "failed_permanently".to_string()
                    } else {
                        format!("retry_at:{}", truncate(&it.next_attempt_at, 22))
                    };
                    println!(
                        "{:<24}  {:<22}  {:>3}  {:>6}  {}",
                        truncate(&it.event_type, 24),
                        truncate(&it.created_at, 22),
                        it.attempts,
                        it.last_status
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| "—".to_string()),
                        status
                    );
                    if let Some(err) = &it.last_error {
                        println!("    last_error: {err}");
                    }
                }
            }
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
