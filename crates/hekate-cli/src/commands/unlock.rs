//! `hekate unlock [--ttl 15m]` — derive the account key client-side, fork
//! into a daemon process holding it in memory for the TTL, and detach.
//! Unix-only.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use nix::unistd::{fork, setsid, ForkResult};

use crate::{api::Api, commands::ttl::parse_ttl, crypto, daemon, prompt, state};

#[derive(Debug, Parser)]
pub struct Args {
    /// Time-to-live for the cached account key. Examples: "15m", "1h", "300s".
    #[arg(long, default_value = "15m")]
    pub ttl: String,
}

pub fn run(args: Args) -> Result<()> {
    if !cfg!(unix) {
        return Err(anyhow!("daemon mode is unix-only in this build"));
    }

    let ttl_dur = parse_ttl(&args.ttl)?;
    if ttl_dur < Duration::from_secs(1) {
        return Err(anyhow!("--ttl must be at least 1s"));
    }
    let mut ttl_secs = ttl_dur.as_secs();

    let st = state::load()?
        .ok_or_else(|| anyhow!("not logged in. Run `hekate login` or `hekate register` first."))?;

    // M4.6 vault_timeout: cap the in-memory cache TTL at the smallest
    // max_seconds across orgs the user belongs to. Best-effort — if
    // /sync fails (offline, expired token), fall through with the
    // user-supplied TTL rather than blocking unlock entirely.
    let api = Api::new(&st.server_url)?
        .with_bearer(st.tokens.access_token.clone())
        .with_refresh(st.tokens.refresh_token.clone());
    if let Ok(Some(agg)) = crate::policies::fetch_aggregate(&api) {
        if agg.vault_timeout.max_seconds > 0 && ttl_secs > agg.vault_timeout.max_seconds {
            println!(
                "↓ Capping --ttl from {}s to {}s per org vault_timeout policy.",
                ttl_secs, agg.vault_timeout.max_seconds
            );
            ttl_secs = agg.vault_timeout.max_seconds;
        }
    }

    if daemon::client::is_running() && daemon::client::status().is_ok() {
        return Err(anyhow!(
            "a hekate daemon is already running. Run `hekate lock` first."
        ));
    }

    let pw = prompt::password("Master password: ")?;
    println!("Deriving master key...");
    let unlocked = crypto::unlock(&st, &pw)?;
    let key_bytes: [u8; 32] = *unlocked.account_key;
    let seed_bytes: [u8; 32] = *unlocked.signing_seed;
    let email = st.user.email.clone();

    let socket_path = daemon::socket_path()?;

    // Fork. The parent reports + exits; the child becomes a session
    // leader, detaches stdio, then runs the tokio server.
    //
    // SAFETY: we have not yet started a tokio runtime in the parent, so
    // forking is safe. We also haven't spawned any threads yet, which is
    // the other constraint.
    match unsafe { fork() }.context("fork failed")? {
        ForkResult::Parent { child } => {
            // Wait briefly for the daemon to bind the socket so subsequent
            // commands in this terminal can find it immediately.
            for _ in 0..50 {
                if daemon::client::is_running() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            println!(
                "✓ Unlocked. Daemon pid {}, socket {}, ttl {ttl_secs}s.",
                child,
                socket_path.display()
            );
            Ok(())
        }
        ForkResult::Child => {
            // Become session leader so we don't carry the controlling tty.
            let _ = setsid();
            // Redirect stdin/stdout/stderr to /dev/null.
            let null = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null")?;
            use std::os::fd::AsRawFd;
            let null_fd = null.as_raw_fd();
            for fd in [0, 1, 2] {
                let _ = nix::unistd::dup2(null_fd, fd);
            }
            // Now run the daemon. tokio runtime starts here.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let res = rt.block_on(daemon::server::run(
                key_bytes,
                seed_bytes,
                email,
                ttl_secs,
                &socket_path,
            ));
            // On clean exit, remove the socket (best-effort).
            let _ = std::fs::remove_file(&socket_path);
            match res {
                Ok(()) => std::process::exit(0),
                Err(_) => std::process::exit(1),
            }
        }
    }
}
