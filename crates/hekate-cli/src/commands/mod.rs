pub mod account;
pub mod add;
pub mod attach;
pub mod config;
pub mod delete;
pub mod edit;
pub mod generate;
pub mod import;
pub mod list;
pub mod lock;
pub mod login;
pub mod logout;
pub mod move_cipher;
pub mod org;
pub mod peer;
pub mod purge;
pub mod register;
pub mod restore;
pub mod send;
pub mod show;
pub mod ssh_agent;
pub mod status;
pub mod sync;
pub mod token;
pub mod ttl;
pub mod two_factor;
pub mod unlock;
pub mod watch;
pub mod webhook;

use anyhow::{anyhow, Result};
#[cfg(unix)]
use zeroize::Zeroizing;

#[cfg(unix)]
use crate::daemon;
use crate::{api::Api, crypto, prompt, state};

/// Load the on-disk state (or err out), get the unwrapped account key
/// (from a running daemon if available, else by prompting for the master
/// password and deriving), build an authed API client, and return all
/// three. Used by every command that touches encrypted vault material.
pub fn unlock_session() -> Result<(state::State, Api, crypto::Unlocked)> {
    let st = state::load()?
        .ok_or_else(|| anyhow!("not logged in. Run `hekate login` or `hekate register` first."))?;

    let unlocked = match try_daemon_unlock() {
        Some(u) => u,
        None => {
            let pw = prompt::password("Master password: ")?;
            crypto::unlock(&st, &pw)?
        }
    };

    let api = Api::new(&st.server_url)?
        .with_bearer(st.tokens.access_token.clone())
        .with_refresh(st.tokens.refresh_token.clone());
    Ok((st, api, unlocked))
}

#[cfg(unix)]
fn try_daemon_unlock() -> Option<crypto::Unlocked> {
    if !daemon::client::is_running() {
        return None;
    }
    match daemon::client::get_unlocked() {
        Ok((key_bytes, seed_bytes)) => Some(crypto::Unlocked {
            account_key: Zeroizing::new(key_bytes),
            signing_seed: Zeroizing::new(seed_bytes),
        }),
        Err(_) => None,
    }
}

#[cfg(not(unix))]
fn try_daemon_unlock() -> Option<crypto::Unlocked> {
    None
}

/// After API operations complete, persist any tokens that were refreshed
/// during the session. Call this at the end of every command that
/// authenticated.
pub fn persist_refreshed_tokens(api: &Api, mut st: state::State) -> Result<()> {
    if let Some(new_tokens) = api.take_refreshed() {
        st.tokens.access_token = new_tokens.access_token;
        st.tokens.refresh_token = new_tokens.refresh_token;
        st.tokens.expires_at = new_tokens.expires_at;
        state::save(&st)?;
    }
    Ok(())
}
