//! `hekate ssh-agent {start|stop|status}` — local SSH agent backed by
//! the user's stored ssh-key ciphers.
//!
//! Listens on `$XDG_RUNTIME_DIR/hekate-ssh-<uid>.sock` (default; override
//! with `--socket`). Set `SSH_AUTH_SOCK=<that path>` and `ssh` /
//! `git push` will use this agent instead of the system one.
//!
//! Implements the two essential agent-protocol messages from
//! draft-miller-ssh-agent-04:
//!   * SSH_AGENTC_REQUEST_IDENTITIES (11) → SSH_AGENT_IDENTITIES_ANSWER (12)
//!   * SSH_AGENTC_SIGN_REQUEST (13)         → SSH_AGENT_SIGN_RESPONSE (14)
//!
//! Pre-alpha scope:
//!   * Ed25519 only — RSA / ECDSA tracked as follow-ups.
//!   * NO per-use approval. Any caller with socket access can sign;
//!     same trust model as the existing `hekate unlock` daemon (kernel
//!     filesystem permission on the 0600 socket is the only barrier).
//!     Adding desktop-notification approval is tracked separately.
//!   * Identity list snapshots at start time. Adding a cipher later
//!     requires `stop && start` (a follow-up will hot-reload via SSE).

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use nix::sys::signal::{kill, Signal};
use nix::unistd::{fork, setsid, ForkResult, Pid};
use ssh_key::{private::KeypairData, HashAlg, PrivateKey};

use crate::commands::{persist_refreshed_tokens, unlock_session};
use crate::crypto::{aad_cipher_data, decrypt_field_string, unwrap_cipher_key, Unlocked};

#[derive(Debug, Parser)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Debug, Subcommand)]
pub enum Action {
    /// Start the agent in the background.
    Start {
        /// Override the default socket path.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Per-use approval command. The agent runs this for every
        /// SIGN_REQUEST with `HEKATE_SSH_KEY_COMMENT` and `HEKATE_SSH_KEY_FP`
        /// in the environment; non-zero exit denies the sign.
        ///
        /// Examples:
        ///   macOS: --approve-cmd "osascript -e 'display dialog
        ///          \"hekate: sign with $HEKATE_SSH_KEY_COMMENT?\" buttons
        ///          {\"No\",\"Yes\"} default button \"Yes\"
        ///          giving up after 30'"
        ///   Linux: --approve-cmd "zenity --question --text=\"hekate: sign
        ///          with $HEKATE_SSH_KEY_COMMENT?\" --timeout=30"
        ///
        /// Without this flag, the agent signs without prompting (same
        /// behavior as M2.17 baseline).
        #[arg(long)]
        approve_cmd: Option<String>,
    },
    /// Stop a running agent (sends SIGTERM to its recorded PID).
    Stop,
    /// Show whether an agent is running.
    Status,
}

// SSH agent protocol message types (draft-miller-ssh-agent-04 §6).
const MSG_FAILURE: u8 = 5;
const MSG_REQUEST_IDENTITIES: u8 = 11;
const MSG_IDENTITIES_ANSWER: u8 = 12;
const MSG_SIGN_REQUEST: u8 = 13;
const MSG_SIGN_RESPONSE: u8 = 14;

const SSH_ED25519: &str = "ssh-ed25519";

pub fn run(args: Args) -> Result<()> {
    match args.action {
        Action::Start {
            socket,
            approve_cmd,
        } => start(socket, approve_cmd),
        Action::Stop => stop(),
        Action::Status => status(),
    }
}

// ---------------- entry points ----------------------------------------------

fn start(socket_override: Option<PathBuf>, approve_cmd: Option<String>) -> Result<()> {
    let socket_path = socket_override.unwrap_or_else(|| default_socket().expect("uid"));
    let pid_path = pid_path_for(&socket_path);

    // Refuse to clobber a running agent. If the PID file exists and the
    // process is alive, error out; if dead, clean up.
    if let Some(pid) = read_pid(&pid_path) {
        if process_alive(pid) {
            return Err(anyhow!(
                "an ssh-agent is already running (pid {pid}). Run `hekate ssh-agent stop` first."
            ));
        }
        let _ = std::fs::remove_file(&pid_path);
    }
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)
            .with_context(|| format!("removing stale socket {}", socket_path.display()))?;
    }

    // Load identities BEFORE forking so the user's password prompt + the
    // server `/sync` call stay attached to the foreground tty.
    let (mut state, api, unlocked) = unlock_session()?;
    let sync = api.sync(None)?;
    persist_refreshed_tokens(&api, state.clone())?;
    if let Some(t) = api.take_refreshed() {
        state.tokens.access_token = t.access_token;
        state.tokens.refresh_token = t.refresh_token;
        state.tokens.expires_at = t.expires_at;
    }
    let identities = load_ed25519_identities(&sync.changes.ciphers, &unlocked)?;
    if identities.is_empty() {
        return Err(anyhow!(
            "no Ed25519 ssh-key ciphers in the vault — add one with \
             `hekate add ssh-key --name … --public-key=… --private-key=…`. \
             RSA / ECDSA support is tracked as a follow-up."
        ));
    }
    let n = identities.len();
    let approve_cmd = approve_cmd.map(std::sync::Arc::new);

    // For hot-reload (M2.17b): keep the account_key + tokens + server URL
    // so the SSE listener thread can re-fetch /sync and re-decrypt new
    // ssh-key ciphers without prompting again. Trust trade-off: the agent
    // now holds the unwrapped account key for its full lifetime; without
    // hot reload it would be dropped after this initial load. Documented
    // in docs/ssh-agent.md.
    let reload_ctx = ReloadCtx {
        server_url: state.server_url.clone(),
        access_token: std::sync::Mutex::new(state.tokens.access_token.clone()),
        refresh_token: std::sync::Mutex::new(state.tokens.refresh_token.clone()),
        account_key: zeroize::Zeroizing::new(*unlocked.account_key),
    };

    // SAFETY: no tokio runtime started in the parent yet, no other threads.
    match unsafe { fork() }.context("fork failed")? {
        ForkResult::Parent { child } => {
            // Wait briefly for the daemon to bind so subsequent commands
            // in this terminal can find it immediately.
            for _ in 0..50 {
                if socket_path.exists() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            println!(
                "✓ hekate ssh-agent started (pid {}, {n} ident{}).",
                child,
                if n == 1 { "ity" } else { "ities" }
            );
            println!("  socket: {}", socket_path.display());
            println!("  Use it from this shell with:");
            println!("    export SSH_AUTH_SOCK={}", socket_path.display());
            Ok(())
        }
        ForkResult::Child => {
            let _ = setsid();
            let null = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null")?;
            let null_fd = null.as_raw_fd();
            for fd in [0, 1, 2] {
                let _ = nix::unistd::dup2(null_fd, fd);
            }
            // Persist PID so `hekate ssh-agent stop` can find us.
            std::fs::write(&pid_path, std::process::id().to_string())
                .context("writing pid file")?;
            let res = serve(&socket_path, identities, approve_cmd, reload_ctx);
            let _ = std::fs::remove_file(&socket_path);
            let _ = std::fs::remove_file(&pid_path);
            match res {
                Ok(()) => std::process::exit(0),
                Err(_) => std::process::exit(1),
            }
        }
    }
}

fn stop() -> Result<()> {
    let socket_path = default_socket()?;
    let pid_path = pid_path_for(&socket_path);
    let pid = read_pid(&pid_path).ok_or_else(|| anyhow!("no hekate ssh-agent is running"))?;
    if !process_alive(pid) {
        let _ = std::fs::remove_file(&pid_path);
        let _ = std::fs::remove_file(&socket_path);
        return Err(anyhow!(
            "pid file referenced pid {pid} but that process is gone — cleaned up stale files"
        ));
    }
    kill(Pid::from_raw(pid as i32), Signal::SIGTERM).map_err(|e| anyhow!("kill {pid}: {e}"))?;
    println!("✓ Sent SIGTERM to ssh-agent pid {pid}.");
    Ok(())
}

fn status() -> Result<()> {
    let socket_path = default_socket()?;
    let pid_path = pid_path_for(&socket_path);
    match read_pid(&pid_path) {
        Some(pid) if process_alive(pid) => {
            println!("running (pid {pid})");
            println!("  socket: {}", socket_path.display());
        }
        Some(pid) => {
            println!("stale pid file (recorded pid {pid} no longer exists)");
        }
        None => println!("not running"),
    }
    Ok(())
}

// ---------------- daemon loop -----------------------------------------------

fn serve(
    socket_path: &Path,
    initial_identities: Vec<Identity>,
    approve_cmd: Option<std::sync::Arc<String>>,
    reload_ctx: ReloadCtx,
) -> Result<()> {
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;

    let identities = std::sync::Arc::new(std::sync::Mutex::new(initial_identities));
    let reload_ctx = std::sync::Arc::new(reload_ctx);

    // Hot-reload thread: subscribe to /push/v1/stream, on cipher.changed
    // re-fetch /sync and replace the identity list. Errors stay silent
    // (stderr is /dev/null after detach); the agent keeps serving with
    // the most recent successful snapshot.
    let ids_for_sse = identities.clone();
    let ctx_for_sse = reload_ctx.clone();
    std::thread::spawn(move || {
        let _ = sse_reload_loop(ids_for_sse, ctx_for_sse);
    });

    loop {
        let (stream, _) = match listener.accept() {
            Ok(x) => x,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        let snapshot = match identities.lock() {
            Ok(g) => g.clone(),
            Err(_) => continue, // poisoned mutex; skip this connection
        };
        let approve = approve_cmd.clone();
        std::thread::spawn(move || {
            let _ = handle_connection(stream, &snapshot, approve.as_deref().map(String::as_str));
        });
    }
}

/// Holds the bits the SSE reload thread needs to re-fetch /sync and
/// re-decrypt cipher data: server URL, mutable tokens (rotated on 401),
/// and the account key for cipher-key unwrapping.
struct ReloadCtx {
    server_url: String,
    access_token: std::sync::Mutex<String>,
    refresh_token: std::sync::Mutex<String>,
    account_key: zeroize::Zeroizing<[u8; 32]>,
}

fn handle_connection(
    mut stream: UnixStream,
    identities: &[Identity],
    approve_cmd: Option<&str>,
) -> Result<()> {
    loop {
        // SSH agent framing: u32 length, body. Body[0] is msg type.
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(()) => {}
            // Clean EOF on the client side ends this thread.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 1 << 20 {
            return Err(anyhow!("oversized ssh-agent frame: {len}"));
        }
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body)?;

        let resp = match body[0] {
            MSG_REQUEST_IDENTITIES => identities_answer(identities),
            MSG_SIGN_REQUEST => match sign_request(&body[1..], identities, approve_cmd) {
                Ok(sig) => sig,
                Err(_) => vec![MSG_FAILURE],
            },
            _ => vec![MSG_FAILURE],
        };
        let len = u32::try_from(resp.len()).map_err(|e| anyhow!("response too large: {e}"))?;
        stream.write_all(&len.to_be_bytes())?;
        stream.write_all(&resp)?;
    }
}

// ---------------- protocol messages -----------------------------------------

fn identities_answer(identities: &[Identity]) -> Vec<u8> {
    let mut buf = vec![MSG_IDENTITIES_ANSWER];
    buf.extend_from_slice(&(identities.len() as u32).to_be_bytes());
    for id in identities {
        write_string(&mut buf, &id.public_blob);
        write_string(&mut buf, id.comment.as_bytes());
    }
    buf
}

fn sign_request(
    body: &[u8],
    identities: &[Identity],
    approve_cmd: Option<&str>,
) -> Result<Vec<u8>> {
    let mut p = body;
    let key_blob = read_string(&mut p)?;
    let data = read_string(&mut p)?;
    let _flags = read_u32(&mut p)?;

    let id = identities
        .iter()
        .find(|i| i.public_blob == key_blob)
        .ok_or_else(|| anyhow!("no matching identity"))?;

    if let Some(cmd) = approve_cmd {
        if !approval_granted(cmd, &id.comment, &id.fingerprint) {
            return Err(anyhow!("user denied sign for {}", id.comment));
        }
    }

    let signature = id.signing_key.sign(data);

    // Wire format for an ssh-ed25519 signature blob:
    //   string "ssh-ed25519" || string 64-byte raw signature
    let mut sig_blob = Vec::with_capacity(4 + SSH_ED25519.len() + 4 + 64);
    write_string(&mut sig_blob, SSH_ED25519.as_bytes());
    write_string(&mut sig_blob, &signature.to_bytes());

    let mut out = vec![MSG_SIGN_RESPONSE];
    write_string(&mut out, &sig_blob);
    Ok(out)
}

/// Run the user-supplied approval command for a sign request. Returns
/// `true` iff the command exits 0 within ~60 s. The command runs through
/// `sh -c` so users can plug in osascript, zenity, notify-send, custom
/// scripts, etc. The selected key's comment + fingerprint are exposed
/// via env vars so the approval UI can display them.
fn approval_granted(cmd: &str, comment: &str, fingerprint: &str) -> bool {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let mut child = match Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .env("HEKATE_SSH_KEY_COMMENT", comment)
        .env("HEKATE_SSH_KEY_FP", fingerprint)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Hard 60 s ceiling — we don't want a stuck approval UI to hang an
    // ssh session forever.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    return false;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => {
                let _ = child.kill();
                return false;
            }
        }
    }
}

// ---------------- hot reload via SSE ----------------------------------------

/// Long-lived SSE consumer: opens a blocking GET on /push/v1/stream and,
/// on every non-heartbeat event, re-fetches /sync and replaces the
/// shared identity list. Designed to fail-quiet: every error path is
/// either a backoff-and-retry or a silent give-up so we never crash
/// the agent itself.
fn sse_reload_loop(
    identities: std::sync::Arc<std::sync::Mutex<Vec<Identity>>>,
    ctx: std::sync::Arc<ReloadCtx>,
) -> Result<()> {
    use std::io::{BufRead, BufReader};

    let client = reqwest::blocking::Client::builder()
        .timeout(None)
        .build()
        .map_err(|e| anyhow!("reqwest client: {e}"))?;
    let mut backoff = std::time::Duration::from_secs(1);
    let cap = std::time::Duration::from_secs(30);

    loop {
        let token = ctx
            .access_token
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let resp = client
            .get(format!("{}/push/v1/stream", ctx.server_url))
            .header("authorization", format!("Bearer {token}"))
            .header("accept", "text/event-stream")
            .send();
        let resp = match resp {
            Ok(r) => r,
            Err(_) => {
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(cap);
                continue;
            }
        };
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            if !try_refresh_tokens(&client, &ctx) {
                return Ok(()); // refresh failed → give up; user can stop && start
            }
            continue;
        }
        if !resp.status().is_success() {
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(cap);
            continue;
        }
        backoff = std::time::Duration::from_secs(1);

        // Parse the SSE wire format inline. Each event is "field: value\n…\n\n".
        let mut reader = BufReader::new(resp);
        let mut chunk = String::new();
        let mut line = String::new();
        loop {
            line.clear();
            let n = match reader.read_line(&mut line) {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                break; // EOF
            }
            if line == "\n" || line == "\r\n" {
                if let Some(ev) = parse_sse_chunk(&chunk) {
                    if ev.event.as_deref() != Some("heartbeat") {
                        // Burst-coalesce by sleeping briefly then reloading once.
                        std::thread::sleep(std::time::Duration::from_millis(250));
                        let _ = drain_extra_events(&mut reader);
                        let _ = reload_identities(&client, &ctx, &identities);
                    }
                }
                chunk.clear();
                continue;
            }
            chunk.push_str(&line);
        }
        // Stream ended; reconnect after a short pause.
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// Read whatever bytes are immediately available without blocking long.
/// Used after we've decided to reload, to coalesce event bursts before
/// the actual /sync round trip.
fn drain_extra_events<R: std::io::BufRead>(_reader: &mut R) -> std::io::Result<()> {
    // Best-effort no-op: BufReader doesn't expose nonblocking reads
    // portably and the reload itself takes ~50–200 ms which already
    // coalesces most bursts.
    Ok(())
}

struct SseEvent {
    event: Option<String>,
    #[allow(dead_code)]
    data: Option<String>,
}

fn parse_sse_chunk(chunk: &str) -> Option<SseEvent> {
    let mut event = None;
    let mut data: Option<String> = None;
    for line in chunk.lines() {
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };
        match field {
            "event" => event = Some(value.to_string()),
            "data" => {
                data = Some(match data {
                    Some(d) => d + "\n" + value,
                    None => value.to_string(),
                });
            }
            _ => {}
        }
    }
    if event.is_some() || data.is_some() {
        Some(SseEvent { event, data })
    } else {
        None
    }
}

fn reload_identities(
    client: &reqwest::blocking::Client,
    ctx: &ReloadCtx,
    identities: &std::sync::Mutex<Vec<Identity>>,
) -> Result<()> {
    let token = ctx
        .access_token
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    let resp = client
        .get(format!("{}/api/v1/sync", ctx.server_url))
        .header("authorization", format!("Bearer {token}"))
        .send()?;
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        if !try_refresh_tokens(client, ctx) {
            return Err(anyhow!("/sync 401 and refresh failed"));
        }
        return reload_identities(client, ctx, identities);
    }
    if !resp.status().is_success() {
        return Err(anyhow!("/sync returned {}", resp.status()));
    }

    #[derive(serde::Deserialize)]
    struct SyncResp {
        changes: Changes,
    }
    #[derive(serde::Deserialize)]
    struct Changes {
        ciphers: Vec<crate::api::CipherView>,
    }
    let sync: SyncResp = resp.json()?;

    // Build a fresh Unlocked from the in-memory account_key — the
    // existing decrypt helpers only need account_key + cipher AAD.
    let unlocked = Unlocked {
        account_key: zeroize::Zeroizing::new(*ctx.account_key),
        signing_seed: zeroize::Zeroizing::new([0u8; 32]),
    };
    let new_ids = load_ed25519_identities(&sync.changes.ciphers, &unlocked)?;
    if let Ok(mut g) = identities.lock() {
        *g = new_ids;
    }
    Ok(())
}

fn try_refresh_tokens(client: &reqwest::blocking::Client, ctx: &ReloadCtx) -> bool {
    let rt = match ctx.refresh_token.lock() {
        Ok(g) => g.clone(),
        Err(_) => return false,
    };
    let resp = client
        .post(format!("{}/identity/connect/token", ctx.server_url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt.as_str()),
        ])
        .send();
    let Ok(resp) = resp else { return false };
    if !resp.status().is_success() {
        return false;
    }
    #[derive(serde::Deserialize)]
    struct Tok {
        access_token: String,
        refresh_token: String,
    }
    let Ok(tok) = resp.json::<Tok>() else {
        return false;
    };
    if let Ok(mut g) = ctx.access_token.lock() {
        *g = tok.access_token;
    }
    if let Ok(mut g) = ctx.refresh_token.lock() {
        *g = tok.refresh_token;
    }
    true
}

// ---------------- identity loading ------------------------------------------

#[derive(Clone)]
struct Identity {
    public_blob: Vec<u8>,
    comment: String,
    fingerprint: String,
    signing_key: SigningKey,
}

fn load_ed25519_identities(
    ciphers: &[crate::api::CipherView],
    unlocked: &Unlocked,
) -> Result<Vec<Identity>> {
    let mut out = Vec::new();
    for c in ciphers {
        if c.cipher_type != 5 || c.deleted_date.is_some() {
            continue;
        }
        let cipher_key = match unwrap_cipher_key(unlocked, &c.protected_cipher_key, &c.id) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let aad = aad_cipher_data(&c.id, c.cipher_type);
        let pt = match decrypt_field_string(&cipher_key, &c.data, &aad) {
            Ok(s) => s,
            Err(_) => continue,
        };
        #[derive(serde::Deserialize)]
        struct Data {
            #[serde(rename = "privateKey")]
            private_key: Option<String>,
        }
        let data: Data = serde_json::from_str(&pt).unwrap_or(Data { private_key: None });
        let Some(priv_text) = data.private_key else {
            continue;
        };
        let pk = match PrivateKey::from_openssh(&priv_text) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let KeypairData::Ed25519(kp) = pk.key_data() else {
            continue; // skip RSA/ECDSA for MVP
        };
        let seed: [u8; 32] = kp.private.to_bytes();
        let signing_key = SigningKey::from_bytes(&seed);
        let pub_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();

        // ssh-ed25519 wire-format public key blob:
        //   string "ssh-ed25519" || string 32-byte raw pubkey
        let mut public_blob = Vec::with_capacity(4 + SSH_ED25519.len() + 4 + pub_bytes.len());
        write_string(&mut public_blob, SSH_ED25519.as_bytes());
        write_string(&mut public_blob, &pub_bytes);

        let comment = if pk.comment().is_empty() {
            format!("hekate:{}", c.id)
        } else {
            pk.comment().to_string()
        };
        let fingerprint = pk.fingerprint(HashAlg::Sha256).to_string();
        out.push(Identity {
            public_blob,
            comment,
            fingerprint,
            signing_key,
        });
    }
    Ok(out)
}

// ---------------- ssh wire helpers ------------------------------------------

fn write_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s);
}

fn read_u32(p: &mut &[u8]) -> Result<u32> {
    if p.len() < 4 {
        return Err(anyhow!("short ssh u32"));
    }
    let v = u32::from_be_bytes(p[..4].try_into().unwrap());
    *p = &p[4..];
    Ok(v)
}

fn read_string<'a>(p: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = read_u32(p)? as usize;
    if p.len() < len {
        return Err(anyhow!("short ssh string"));
    }
    let s = &p[..len];
    *p = &p[len..];
    Ok(s)
}

// ---------------- paths + pid helpers ---------------------------------------

fn default_socket() -> Result<PathBuf> {
    let dir = match std::env::var("XDG_RUNTIME_DIR") {
        Ok(d) => PathBuf::from(d),
        Err(_) => PathBuf::from("/tmp"),
    };
    let uid = nix::unistd::getuid().as_raw();
    Ok(dir.join(format!("hekate-ssh-{uid}.sock")))
}

fn pid_path_for(socket: &Path) -> PathBuf {
    socket.with_extension("pid")
}

fn read_pid(path: &Path) -> Option<u32> {
    let f = std::fs::File::open(path).ok()?;
    let mut br = BufReader::new(f);
    let mut line = String::new();
    br.read_line(&mut line).ok()?;
    line.trim().parse::<u32>().ok()
}

fn process_alive(pid: u32) -> bool {
    // signal 0 is the "is this process there" probe.
    kill(Pid::from_raw(pid as i32), None).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_string_round_trips() {
        let mut buf = Vec::new();
        write_string(&mut buf, b"hello");
        let mut p: &[u8] = &buf;
        assert_eq!(read_string(&mut p).unwrap(), b"hello");
        assert!(p.is_empty());
    }

    #[test]
    fn identities_answer_frames_correctly() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let mut public_blob = Vec::new();
        write_string(&mut public_blob, SSH_ED25519.as_bytes());
        write_string(&mut public_blob, &pub_bytes);
        let id = Identity {
            public_blob: public_blob.clone(),
            comment: "test".into(),
            fingerprint: "SHA256:test".into(),
            signing_key,
        };
        let answer = identities_answer(&[id]);
        assert_eq!(answer[0], MSG_IDENTITIES_ANSWER);
        let mut p = &answer[1..];
        assert_eq!(read_u32(&mut p).unwrap(), 1);
        assert_eq!(read_string(&mut p).unwrap(), public_blob.as_slice());
        assert_eq!(read_string(&mut p).unwrap(), b"test");
    }

    #[test]
    fn sign_request_produces_verifiable_signature() {
        use ed25519_dalek::Verifier;
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        let mut public_blob = Vec::new();
        write_string(&mut public_blob, SSH_ED25519.as_bytes());
        write_string(&mut public_blob, &pub_bytes);

        let id = Identity {
            public_blob: public_blob.clone(),
            comment: "t".into(),
            fingerprint: "SHA256:t".into(),
            signing_key,
        };

        let to_sign = b"some session-bound bytes from sshd";
        let mut req = Vec::new();
        write_string(&mut req, &public_blob);
        write_string(&mut req, to_sign);
        req.extend_from_slice(&0u32.to_be_bytes()); // flags

        let resp = sign_request(&req, &[id], None).unwrap();
        assert_eq!(resp[0], MSG_SIGN_RESPONSE);
        let mut p = &resp[1..];
        let sig_blob = read_string(&mut p).unwrap();

        // Unwrap the inner string-string pair.
        let mut sb = sig_blob;
        assert_eq!(read_string(&mut sb).unwrap(), b"ssh-ed25519");
        let raw_sig = read_string(&mut sb).unwrap();
        assert_eq!(raw_sig.len(), 64);
        let sig = ed25519_dalek::Signature::from_slice(raw_sig).unwrap();
        verifying_key
            .verify(to_sign, &sig)
            .expect("server-issued signature must verify");
    }

    fn one_id() -> (Identity, Vec<u8>) {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pub_bytes = sk.verifying_key().to_bytes();
        let mut public_blob = Vec::new();
        write_string(&mut public_blob, SSH_ED25519.as_bytes());
        write_string(&mut public_blob, &pub_bytes);
        (
            Identity {
                public_blob: public_blob.clone(),
                comment: "test-key".into(),
                fingerprint: "SHA256:abc".into(),
                signing_key: sk,
            },
            public_blob,
        )
    }

    fn make_sign_req(public_blob: &[u8]) -> Vec<u8> {
        let mut req = Vec::new();
        write_string(&mut req, public_blob);
        write_string(&mut req, b"data");
        req.extend_from_slice(&0u32.to_be_bytes());
        req
    }

    #[test]
    fn approve_cmd_exit_zero_signs() {
        let (id, blob) = one_id();
        let req = make_sign_req(&blob);
        // `true` always exits 0.
        let r = sign_request(&req, &[id], Some("true")).unwrap();
        assert_eq!(r[0], MSG_SIGN_RESPONSE);
    }

    #[test]
    fn approve_cmd_exit_nonzero_denies() {
        let (id, blob) = one_id();
        let req = make_sign_req(&blob);
        let err = sign_request(&req, &[id], Some("false")).unwrap_err();
        assert!(err.to_string().contains("denied sign"));
    }

    #[test]
    fn approve_cmd_receives_env_vars() {
        let (id, blob) = one_id();
        let req = make_sign_req(&blob);
        // Exit 0 only if both env vars match what we set on the Identity.
        let cmd =
            "[ \"$HEKATE_SSH_KEY_COMMENT\" = test-key ] && [ \"$HEKATE_SSH_KEY_FP\" = SHA256:abc ]";
        let r = sign_request(&req, &[id], Some(cmd)).unwrap();
        assert_eq!(r[0], MSG_SIGN_RESPONSE);
    }
}
