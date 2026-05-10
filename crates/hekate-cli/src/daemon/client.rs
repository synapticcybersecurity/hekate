//! Synchronous Unix-socket client that the CLI uses to talk to a running
//! daemon. Returns Err quickly when no daemon is reachable so callers can
//! fall back to the prompt-and-derive flow.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{anyhow, Result};

use crate::daemon::{socket_path, Request, Response, StatusInfo};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(200);
const READ_TIMEOUT: Duration = Duration::from_secs(5);

fn connect() -> Result<UnixStream> {
    let path = socket_path()?;
    if !path.exists() {
        return Err(anyhow!("daemon socket not present"));
    }
    // std::os::unix doesn't take a connect timeout, so we trust that local
    // socket connects are essentially instant. The daemon's accept side
    // handles the request quickly.
    let stream = UnixStream::connect(&path)?;
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;
    Ok(stream)
}

fn send(req: Request) -> Result<Response> {
    let mut stream = connect()?;
    let body = serde_json::to_vec(&req)?;
    let len = u32::try_from(body.len())?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&body)?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1 << 20 {
        return Err(anyhow!("daemon response too large: {len} bytes"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(serde_json::from_slice(&buf)?)
}

pub fn get_unlocked() -> Result<([u8; 32], [u8; 32])> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    match send(Request::GetUnlocked)? {
        Response::Unlocked {
            account_key_b64,
            signing_seed_b64,
        } => {
            let key = URL_SAFE_NO_PAD.decode(&account_key_b64)?;
            let seed = URL_SAFE_NO_PAD.decode(&signing_seed_b64)?;
            if key.len() != 32 {
                return Err(anyhow!("daemon returned account key of wrong length"));
            }
            if seed.len() != 32 {
                return Err(anyhow!("daemon returned signing seed of wrong length"));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&key);
            let mut s = [0u8; 32];
            s.copy_from_slice(&seed);
            Ok((k, s))
        }
        Response::Err { message } => Err(anyhow!("daemon: {message}")),
        other => Err(anyhow!("unexpected daemon response: {other:?}")),
    }
}

pub fn status() -> Result<StatusInfo> {
    match send(Request::Status)? {
        Response::Status(s) => Ok(s),
        Response::Err { message } => Err(anyhow!("daemon: {message}")),
        other => Err(anyhow!("unexpected daemon response: {other:?}")),
    }
}

pub fn shutdown() -> Result<()> {
    match send(Request::Shutdown)? {
        Response::Ok => Ok(()),
        Response::Err { message } => Err(anyhow!("daemon: {message}")),
        other => Err(anyhow!("unexpected daemon response: {other:?}")),
    }
}

pub fn is_running() -> bool {
    socket_path().map(|p| p.exists()).unwrap_or(false)
}
