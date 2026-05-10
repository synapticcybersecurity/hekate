//! `hekate watch` — connect to /push/v1/stream and print events as they
//! arrive. Best-effort: reconnects on disconnect with exponential backoff.
//!
//! No vault decryption needed — push events carry only `{id, revision}`.
//! We still call `unlock_session` to load the access token; passing the
//! master password also lets us fail fast if the user mistypes.

use std::io::{BufRead, BufReader};
use std::time::Duration;

use anyhow::{anyhow, Result};
use clap::Parser;
// Note: relying on the server-side SSE heartbeat (every 15 s) to keep the
// TCP connection from going silent. reqwest's blocking ClientBuilder
// doesn't expose a per-read timeout, so we set the overall timeout to None.

use crate::commands::unlock_session;

#[derive(Debug, Parser)]
pub struct Args {
    /// Maximum reconnect attempts. 0 = retry forever.
    #[arg(long, default_value_t = 0)]
    pub max_reconnects: u32,
    /// Skip the master-password unlock step (just need the access token).
    #[arg(long)]
    pub skip_unlock: bool,
}

pub fn run(args: Args) -> Result<()> {
    let (state, _api, _unlocked) = if args.skip_unlock {
        let st = crate::state::load()?
            .ok_or_else(|| anyhow!("not logged in. Run `hekate login` first."))?;
        let api = crate::api::Api::new(&st.server_url)?
            .with_bearer(st.tokens.access_token.clone())
            .with_refresh(st.tokens.refresh_token.clone());
        (st, api, None)
    } else {
        let (s, a, u) = unlock_session()?;
        (s, a, Some(u))
    };

    let url = format!("{}/push/v1/stream", state.server_url);
    let access = state.tokens.access_token.clone();

    eprintln!(
        "Watching {}/push/v1/stream — Ctrl-C to exit.",
        state.server_url
    );

    let mut backoff = Duration::from_secs(1);
    let mut attempts: u32 = 0;
    loop {
        match stream_once(&url, &access) {
            Ok(()) => {
                eprintln!("→ stream ended cleanly; reconnecting");
            }
            Err(e) => {
                eprintln!("→ stream error: {e}");
            }
        }
        if args.max_reconnects > 0 && attempts >= args.max_reconnects {
            return Err(anyhow!("exhausted reconnect attempts"));
        }
        attempts += 1;
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

fn stream_once(url: &str, access: &str) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!("hekate-cli/", env!("CARGO_PKG_VERSION")))
        // Long-lived stream; no overall request timeout.
        .timeout(None)
        .build()?;

    let resp = client.get(url).bearer_auth(access).send()?;
    if !resp.status().is_success() {
        return Err(anyhow!("server returned {}", resp.status()));
    }

    let reader = BufReader::new(resp);
    let mut event = String::new();
    let mut id = String::new();
    let mut data = String::new();

    for line in reader.lines() {
        let line = line?;
        if line.is_empty() {
            if !data.is_empty() {
                let kind = if event.is_empty() {
                    "message"
                } else {
                    event.as_str()
                };
                println!(
                    "[{}] {} {} → {}",
                    chrono::Utc::now().to_rfc3339(),
                    kind,
                    if id.is_empty() { "-" } else { id.as_str() },
                    data
                );
            }
            event.clear();
            id.clear();
            data.clear();
        } else if let Some(v) = line.strip_prefix("event:") {
            event = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("id:") {
            id = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(v.trim());
        }
        // Ignore comments (":..."), retry hints, and unknown fields.
    }
    Ok(())
}
