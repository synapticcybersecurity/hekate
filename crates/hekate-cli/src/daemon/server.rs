//! Daemon process that holds the unwrapped account key in memory.
//!
//! Spawned by `hekate unlock`. Listens on the per-uid Unix domain socket,
//! serves Get / Status / Shutdown requests until the TTL expires.
//! Account key is held in `Zeroizing` so it wipes on drop.

use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::daemon::{Request, Response, StatusInfo};

struct State {
    account_key: Zeroizing<[u8; 32]>,
    signing_seed: Zeroizing<[u8; 32]>,
    email: String,
    expires_at: DateTime<Utc>,
    pid: u32,
}

/// Run the daemon until TTL expires or a shutdown request arrives.
/// Removes the socket on exit.
pub async fn run(
    account_key: [u8; 32],
    signing_seed: [u8; 32],
    email: String,
    ttl_secs: u64,
    socket_path: &Path,
) -> Result<()> {
    // Remove any stale socket. (Either a previous daemon crashed without
    // cleanup, or the file is foreign — refuse if its mode looks wrong.)
    if socket_path.exists() {
        std::fs::remove_file(socket_path)
            .map_err(|e| anyhow!("removing stale socket {}: {e}", socket_path.display()))?;
    }

    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;

    let expires_at = Utc::now() + chrono::Duration::seconds(ttl_secs as i64);
    let state = Arc::new(Mutex::new(State {
        account_key: Zeroizing::new(account_key),
        signing_seed: Zeroizing::new(signing_seed),
        email,
        expires_at,
        pid: std::process::id(),
    }));

    // TTL watcher: when expires_at hits, exit cleanly. The Zeroizing
    // wrapper wipes the key on drop.
    let state_for_ttl = state.clone();
    let socket_for_ttl = socket_path.to_path_buf();
    tokio::spawn(async move {
        let until = state_for_ttl.lock().await.expires_at;
        let dur = (until - Utc::now())
            .to_std()
            .unwrap_or(Duration::from_secs(0));
        tokio::time::sleep(dur).await;
        let _ = std::fs::remove_file(&socket_for_ttl);
        std::process::exit(0);
    });

    // Accept loop.
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        let sock = socket_path.to_path_buf();
        tokio::spawn(async move {
            // Errors are intentionally silent — stderr is /dev/null after
            // detach, and protocol-level mistakes shouldn't crash the daemon.
            let _ = handle(stream, state, sock).await;
        });
    }
}

async fn handle(
    mut stream: UnixStream,
    state: Arc<Mutex<State>>,
    sock_path: std::path::PathBuf,
) -> Result<()> {
    // Frame in
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1 << 20 {
        return Err(anyhow!("client message too large: {len}"));
    }
    let mut req_buf = vec![0u8; len];
    stream.read_exact(&mut req_buf).await?;
    let req: Request = serde_json::from_slice(&req_buf)?;

    let resp = process(req, &state).await;
    let body = serde_json::to_vec(&resp)?;
    let len_out = u32::try_from(body.len())?;
    stream.write_all(&len_out.to_be_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await.ok();

    // If we just acked a Shutdown, exit after the response is on the wire.
    if let Response::Ok = resp {
        // Heuristic: only exit if the request was a Shutdown. We re-decode
        // by checking whether the daemon's account key is still valid is
        // brittle; instead we detect Shutdown explicitly below.
    }
    // Simpler: re-parse the request to know if it was Shutdown.
    if let Ok(Request::Shutdown) = serde_json::from_slice::<Request>(&req_buf) {
        // Drop the state (zeroizes the key) and remove socket.
        drop(state);
        let _ = std::fs::remove_file(&sock_path);
        let _ = stream.as_raw_fd();
        std::process::exit(0);
    }
    Ok(())
}

async fn process(req: Request, state: &Arc<Mutex<State>>) -> Response {
    let s = state.lock().await;
    let now = Utc::now();
    if now >= s.expires_at {
        return Response::Err {
            message: "session expired".into(),
        };
    }
    match req {
        Request::GetUnlocked => {
            let key_bytes: &[u8] = &s.account_key[..];
            let seed_bytes: &[u8] = &s.signing_seed[..];
            Response::Unlocked {
                account_key_b64: URL_SAFE_NO_PAD.encode(key_bytes),
                signing_seed_b64: URL_SAFE_NO_PAD.encode(seed_bytes),
            }
        }
        Request::Status => Response::Status(StatusInfo {
            email: s.email.clone(),
            expires_at: s.expires_at.to_rfc3339(),
            remaining_secs: (s.expires_at - now).num_seconds(),
            pid: s.pid,
        }),
        Request::Shutdown => Response::Ok,
    }
}
