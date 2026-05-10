//! `hekate send {create-text, list, delete, disable, enable, open}` —
//! M2.25 Send.
//!
//! Sender flow (`create-text`):
//!   1. Generate a 32-byte send_key.
//!   2. Encrypt the plaintext with HKDF-derived content_key (AAD bound
//!      to send_id + send_type).
//!   3. Wrap send_key under the account key with AAD `pmgr-send-key-v1:<id>`.
//!      Lets the sender list/edit from any device.
//!   4. POST /api/v1/sends; print the recipient URL.
//!
//! Recipient flow (`open`): parse `https://<host>/send/#/<id>/<key>`,
//! POST /api/v1/public/sends/{id}/access (with password if needed),
//! HKDF + decrypt the returned `data` EncString.

use std::time::Duration as StdDuration;

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use chrono::{Duration, Utc};
use clap::{Args as ClapArgs, Subcommand};
use hekate_core::{
    encstring::EncString,
    send::{
        decode_send_key, decrypt_text, encode_send_key, encrypt_text, generate_send_key,
        key_wrap_aad,
    },
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    api::Api,
    commands::{persist_refreshed_tokens, ttl, unlock_session},
};

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[command(subcommand)]
    pub cmd: Sub,
}

#[derive(Debug, Subcommand)]
pub enum Sub {
    /// Create a new text Send and print the share URL.
    CreateText(CreateTextArgs),
    /// Create a new file Send (encrypts + uploads body via tus) and
    /// print the share URL. (M2.25a)
    CreateFile(CreateFileArgs),
    /// List your sender-owned Sends (decrypted names + access stats).
    List,
    /// Permanently remove a Send.
    Delete(DeleteArgs),
    /// Disable a Send (returns 410 Gone on public access until re-enabled).
    Disable(IdArgs),
    /// Re-enable a previously disabled Send.
    Enable(IdArgs),
    /// Fetch + decrypt a Send via its public URL (recipient-side).
    /// Auto-detects text vs. file from the server response.
    Open(OpenArgs),
}

#[derive(Debug, ClapArgs)]
pub struct CreateTextArgs {
    /// Plaintext text body. Use `-` to read from stdin.
    pub text: String,
    /// Sender-side display name (decryptable by you, never sent to
    /// recipients). Defaults to the first 32 chars of the text.
    #[arg(long)]
    pub name: Option<String>,
    /// Optional access password. Server-side Argon2id-PHC'd; never
    /// fed into encryption (server can revoke but not decrypt).
    #[arg(long)]
    pub password: Option<String>,
    /// Maximum recipient accesses. Omit for unlimited.
    #[arg(long)]
    pub max_access: Option<i64>,
    /// Time-to-live before the Send is auto-deleted by the GC worker.
    /// Accepts `30s`, `15m`, `2h`, `7d`. Default `7d`.
    #[arg(long, default_value = "7d")]
    pub ttl: String,
    /// Optional tighter expiration_date applied alongside the TTL —
    /// the public-access endpoint enforces both.
    #[arg(long)]
    pub expires_at: Option<String>,
    /// Hostname the recipient URL should point at. Defaults to the
    /// server URL the CLI is logged into.
    #[arg(long)]
    pub url_base: Option<String>,
}

#[derive(Debug, ClapArgs)]
pub struct CreateFileArgs {
    /// Path to the file to share.
    pub file: std::path::PathBuf,
    /// Sender-side display name. Defaults to the file's basename.
    #[arg(long)]
    pub name: Option<String>,
    /// Optional access password (server-side Argon2id-PHC'd).
    #[arg(long)]
    pub password: Option<String>,
    /// Maximum recipient accesses. Omit for unlimited.
    #[arg(long)]
    pub max_access: Option<i64>,
    /// TTL before the Send is auto-deleted. Default `7d`.
    #[arg(long, default_value = "7d")]
    pub ttl: String,
    /// Optional tighter expiration_date alongside the TTL.
    #[arg(long)]
    pub expires_at: Option<String>,
    /// Hostname for the share URL. Defaults to the API host.
    #[arg(long)]
    pub url_base: Option<String>,
}

#[derive(Debug, ClapArgs)]
pub struct OpenFileArgs {
    /// Output path. `-` writes to stdout. Defaults to the original
    /// filename embedded in the encrypted metadata.
    #[arg(short, long)]
    pub out: Option<String>,
}

#[derive(Debug, ClapArgs)]
pub struct DeleteArgs {
    pub id: String,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, ClapArgs)]
pub struct IdArgs {
    pub id: String,
}

#[derive(Debug, ClapArgs)]
pub struct OpenArgs {
    /// Full share URL, e.g. `https://hekate.example/send/#/<id>/<key>`.
    pub url: String,
    /// Access password if the Send is gated.
    #[arg(long)]
    pub password: Option<String>,
    /// Output path for file Sends. `-` writes plaintext to stdout.
    /// Defaults to the original filename. Ignored for text Sends.
    #[arg(short, long)]
    pub out: Option<String>,
}

pub fn run(args: Args) -> Result<()> {
    match args.cmd {
        Sub::CreateText(a) => run_create_text(a),
        Sub::CreateFile(a) => run_create_file(a),
        Sub::List => run_list(),
        Sub::Delete(a) => run_delete(a),
        Sub::Disable(a) => run_set_disabled(a, true),
        Sub::Enable(a) => run_set_disabled(a, false),
        Sub::Open(a) => run_open(a),
    }
}

// =====================================================================
// create-text
// =====================================================================

fn run_create_text(args: CreateTextArgs) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;

    // Read body — either inline arg or stdin.
    let plaintext = if args.text == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("read stdin")?;
        buf
    } else {
        args.text
    };
    if plaintext.is_empty() {
        return Err(anyhow!("refusing to create an empty text Send"));
    }

    let id = Uuid::now_v7().to_string();
    let send_key = generate_send_key();

    // Encrypt the payload with the HKDF-derived content key. send_id
    // is the HKDF salt and AAD; send_type=1 (text) is in the AAD.
    let data_wire = encrypt_text(&send_key, &id, plaintext.as_bytes())
        .map_err(|e| anyhow!("encrypt send: {e}"))?;

    // Wrap the send_key under the user's account key so the sender
    // can list/edit from any device. AAD binds the wrap to the send
    // id so the server can't move a wrapped key to a different row.
    let key_aad = key_wrap_aad(&id);
    let protected_send_key =
        EncString::encrypt_xc20p("ak:1", &unlocked.account_key, send_key.as_ref(), &key_aad)
            .map_err(|e| anyhow!("wrap send_key: {e}"))?
            .to_wire();

    // Sender-side display name: encrypt under account key with a
    // fixed AAD bound to the send id. Reuse the EncString shape;
    // server validates structure but never decrypts.
    let name_pt = args
        .name
        .clone()
        .unwrap_or_else(|| plaintext.chars().take(32).collect());
    let name_aad = name_aad(&id);
    let name_wire =
        EncString::encrypt_xc20p("ak:1", &unlocked.account_key, name_pt.as_bytes(), &name_aad)
            .map_err(|e| anyhow!("encrypt name: {e}"))?
            .to_wire();

    // Compute deletion_date from TTL.
    let ttl: StdDuration = ttl::parse_ttl(&args.ttl)?;
    let ttl_secs: i64 = ttl
        .as_secs()
        .try_into()
        .map_err(|_| anyhow!("ttl too large"))?;
    let deletion_date = (Utc::now() + Duration::seconds(ttl_secs)).to_rfc3339();

    let mut body = serde_json::json!({
        "id": id,
        "send_type": 1,
        "name": name_wire,
        "protected_send_key": protected_send_key,
        "data": data_wire,
        "deletion_date": deletion_date,
        "disabled": false,
    });
    if let Some(p) = &args.password {
        body["password"] = serde_json::json!(p);
    }
    if let Some(m) = args.max_access {
        body["max_access_count"] = serde_json::json!(m);
    }
    if let Some(e) = &args.expires_at {
        body["expiration_date"] = serde_json::json!(e);
    }

    // Snapshot the server URL before `persist_refreshed_tokens` consumes
    // `state`. Override via --url-base when the share host differs from
    // the API host (e.g. CDN or split host).
    let url_base = args
        .url_base
        .clone()
        .unwrap_or_else(|| state.server_url.clone())
        .trim_end_matches('/')
        .to_string();

    let view = api.create_send(&body).context("server rejected send")?;
    persist_refreshed_tokens(&api, state)?;
    let share_url = format!(
        "{url_base}/send/#/{}/{}",
        view.id,
        encode_send_key(&send_key)
    );
    println!("{share_url}");
    eprintln!("send_id:        {}", view.id);
    eprintln!("expires (TTL):  {deletion_date}");
    if let Some(m) = view.max_access_count {
        eprintln!("max_access:     {m}");
    }
    if view.has_password {
        eprintln!("password gate:  yes");
    }
    Ok(())
}

// =====================================================================
// create-file (M2.25a)
// =====================================================================

/// 4 MiB tus PATCH chunk size — same as `attach upload`. Independent
/// of the AEAD chunk size (1 MiB).
const TUS_PATCH_CHUNK: usize = 4 * 1024 * 1024;

fn run_create_file(args: CreateFileArgs) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;

    let plaintext =
        std::fs::read(&args.file).with_context(|| format!("read {}", args.file.display()))?;
    if plaintext.is_empty() {
        return Err(anyhow!("refusing to create an empty file Send"));
    }
    let filename = args
        .file
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("send-body")
        .to_string();

    let id = uuid::Uuid::now_v7().to_string();
    let send_key = generate_send_key();

    // Per-file AEAD key. Stored as part of the encrypted metadata so
    // only a recipient with the URL-fragment send_key can extract it.
    let mut file_aead_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut file_aead_key);

    // Encrypt the body with chunked-AEAD. Reuses the M2.24 PMGRA1
    // format unchanged; AAD `location_bytes` is the send id.
    let ciphertext = hekate_core::attachment::encrypt(&file_aead_key, id.as_bytes(), &plaintext)
        .map_err(|e| anyhow!("attachment encrypt: {e}"))?;
    let hash_b64 = hekate_core::attachment::content_hash_b3(&ciphertext);

    // Encrypted metadata payload — JSON of `{filename, size_pt,
    // file_aead_key_b64}` under content_key. The recipient HKDFs the
    // send_key, decrypts this, then uses `file_aead_key` to decrypt
    // the body bytes from /blob.
    let metadata_json = serde_json::json!({
        "filename": filename,
        "size_pt": plaintext.len(),
        "file_aead_key_b64": base64::engine::general_purpose::STANDARD_NO_PAD.encode(file_aead_key),
    })
    .to_string();
    let data_wire = encrypt_text(&send_key, &id, metadata_json.as_bytes())
        .map_err(|e| anyhow!("encrypt send metadata: {e}"))?;

    // Wrap send_key under the account key so the sender can list/edit.
    let key_aad = key_wrap_aad(&id);
    let protected_send_key =
        EncString::encrypt_xc20p("ak:1", &unlocked.account_key, send_key.as_ref(), &key_aad)
            .map_err(|e| anyhow!("wrap send_key: {e}"))?
            .to_wire();

    // Sender-side display name.
    let display_name = args.name.clone().unwrap_or_else(|| filename.clone());
    let name_aad_v = name_aad(&id);
    let name_wire = EncString::encrypt_xc20p(
        "ak:1",
        &unlocked.account_key,
        display_name.as_bytes(),
        &name_aad_v,
    )
    .map_err(|e| anyhow!("encrypt name: {e}"))?
    .to_wire();

    // Compute deletion_date from TTL.
    let ttl = ttl::parse_ttl(&args.ttl)?;
    let ttl_secs: i64 = ttl
        .as_secs()
        .try_into()
        .map_err(|_| anyhow!("ttl too large"))?;
    let deletion_date = (Utc::now() + Duration::seconds(ttl_secs)).to_rfc3339();

    // POST the metadata row first, then upload the body.
    let mut create_body = serde_json::json!({
        "id": id,
        "send_type": 2,
        "name": name_wire,
        "protected_send_key": protected_send_key,
        "data": data_wire,
        "deletion_date": deletion_date,
        "disabled": false,
    });
    if let Some(p) = &args.password {
        create_body["password"] = serde_json::json!(p);
    }
    if let Some(m) = args.max_access {
        create_body["max_access_count"] = serde_json::json!(m);
    }
    if let Some(e) = &args.expires_at {
        create_body["expiration_date"] = serde_json::json!(e);
    }
    let view = api
        .create_send(&create_body)
        .context("server rejected send")?;

    // Snapshot URL base before tokens are persisted.
    let url_base = args
        .url_base
        .clone()
        .unwrap_or_else(|| state.server_url.clone())
        .trim_end_matches('/')
        .to_string();

    // tus upload via creation-with-upload + 4 MiB transport chunks.
    let upload_metadata = build_tus_metadata(&[
        ("content_hash_b3", &hash_b64),
        ("size_pt", &plaintext.len().to_string()),
    ]);
    let first = std::cmp::min(TUS_PATCH_CHUNK, ciphertext.len());
    let location = api.send_upload_create(
        &view.id,
        ciphertext.len() as u64,
        &upload_metadata,
        Some(&ciphertext[..first]),
    )?;
    let mut offset = first as u64;
    while (offset as usize) < ciphertext.len() {
        let take = std::cmp::min(TUS_PATCH_CHUNK, ciphertext.len() - offset as usize);
        let chunk = ciphertext[offset as usize..offset as usize + take].to_vec();
        match api.send_tus_patch(&location, offset, chunk) {
            Ok(new_off) => offset = new_off,
            Err(e) => {
                if let Ok(server_off) = api.send_tus_head(&location) {
                    eprintln!("patch failed ({e}); resuming from server offset {server_off}");
                    offset = server_off;
                    continue;
                }
                return Err(anyhow!("upload aborted at offset {offset}: {e}"));
            }
        }
    }

    persist_refreshed_tokens(&api, state)?;

    let share_url = format!(
        "{url_base}/send/#/{}/{}",
        view.id,
        encode_send_key(&send_key)
    );
    println!("{share_url}");
    eprintln!("send_id:        {}", view.id);
    eprintln!("filename:       {filename}");
    eprintln!("size:           {} bytes (plaintext)", plaintext.len());
    eprintln!("expires (TTL):  {deletion_date}");
    if let Some(m) = view.max_access_count {
        eprintln!("max_access:     {m}");
    }
    if view.has_password {
        eprintln!("password gate:  yes");
    }
    Ok(())
}

// =====================================================================
// list
// =====================================================================

fn run_list() -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;
    let sends = api.list_sends()?;
    if sends.is_empty() {
        println!("(no sends)");
    } else {
        for s in &sends {
            // Decrypt the sender-side name. Failure here means the row
            // was tampered or a different account_key was used.
            let aad = name_aad(&s.id);
            let name = match EncString::parse(&s.name) {
                Ok(es) => es
                    .decrypt_xc20p(&unlocked.account_key, Some(&aad))
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_else(|| "<undecryptable>".into()),
                Err(_) => "<malformed>".into(),
            };
            let access = match s.max_access_count {
                Some(m) => format!("{}/{}", s.access_count, m),
                None => format!("{}/∞", s.access_count),
            };
            let flags = match (s.disabled, s.has_password) {
                (true, true) => " [disabled, password]",
                (true, false) => " [disabled]",
                (false, true) => " [password]",
                (false, false) => "",
            };
            println!(
                "{}  exp:{}  access:{}  {}{}",
                s.id, s.deletion_date, access, name, flags
            );
        }
    }
    persist_refreshed_tokens(&api, state)?;
    Ok(())
}

// =====================================================================
// delete / disable / enable
// =====================================================================

fn run_delete(args: DeleteArgs) -> Result<()> {
    let (state, api, _unlocked) = unlock_session()?;
    Uuid::parse_str(&args.id).context("send id must be a UUID")?;
    if !args.yes {
        eprintln!(
            "About to permanently delete send {}. Re-run with --yes to confirm.",
            args.id
        );
        return Ok(());
    }
    api.delete_send(&args.id)?;
    persist_refreshed_tokens(&api, state)?;
    println!("deleted");
    Ok(())
}

fn run_set_disabled(args: IdArgs, disabled: bool) -> Result<()> {
    let (state, api, _unlocked) = unlock_session()?;
    Uuid::parse_str(&args.id).context("send id must be a UUID")?;
    let view = api.set_send_disabled(&args.id, disabled)?;
    persist_refreshed_tokens(&api, state)?;
    println!(
        "{} {}",
        if view.disabled { "disabled" } else { "enabled" },
        view.id
    );
    Ok(())
}

// =====================================================================
// open (recipient)
// =====================================================================

/// Parse a Send share URL into `(server_base, send_id, send_key)`.
/// Accepts both the canonical format `<base>/send/#/<id>/<key>` and a
/// shorter `<base>/#/<id>/<key>` for self-hosters who didn't mount the
/// `/send` path.
fn parse_share_url(url: &str) -> Result<(String, String, Zeroizing<[u8; 32]>)> {
    let (before_frag, frag) = url.split_once('#').ok_or_else(|| {
        anyhow!("URL missing the `#fragment` — recipient key must be in the fragment")
    })?;
    // Strip optional `/send` path so the base is just the host.
    let base = before_frag
        .trim_end_matches('/')
        .trim_end_matches("/send")
        .trim_end_matches('/')
        .to_string();
    if base.is_empty() {
        return Err(anyhow!("URL missing scheme + host"));
    }
    // Fragment shape: `/<id>/<key>` or just `<id>/<key>`.
    let frag = frag.trim_start_matches('/');
    let mut it = frag.splitn(2, '/');
    let id = it
        .next()
        .ok_or_else(|| anyhow!("fragment missing send_id"))?
        .to_string();
    let key_b64 = it
        .next()
        .ok_or_else(|| anyhow!("fragment missing send_key"))?;
    Uuid::parse_str(&id).context("send_id in URL fragment is not a UUID")?;
    let send_key =
        decode_send_key(key_b64).map_err(|e| anyhow!("send_key in URL fragment: {e}"))?;
    Ok((base, id, send_key))
}

fn run_open(args: OpenArgs) -> Result<()> {
    let (server_base, id, send_key) = parse_share_url(&args.url)?;
    let api = Api::new(&server_base)?;
    let resp = api.public_access_send(&server_base, &id, args.password.as_deref())?;

    // Always decrypt the metadata blob first — for text Sends it's
    // the message; for file Sends it's the {filename, size_pt,
    // file_aead_key_b64} JSON.
    let pt_meta = decrypt_text(&send_key, &id, &resp.data)
        .map_err(|e| anyhow!("decrypt send payload: {e}"))?;

    eprintln!("# send_id:        {}", resp.id);
    eprintln!(
        "# access_count:   {} / {}",
        resp.access_count,
        resp.max_access_count
            .map(|m| m.to_string())
            .unwrap_or_else(|| "∞".into())
    );
    if let Some(exp) = &resp.expiration_date {
        eprintln!("# expires:        {exp}");
    }

    match resp.send_type {
        1 => {
            let s =
                String::from_utf8(pt_meta).map_err(|_| anyhow!("decrypted payload not UTF-8"))?;
            println!("{s}");
        }
        2 => {
            let dl_token = resp
                .download_token
                .clone()
                .ok_or_else(|| anyhow!("server response missing download_token for file Send"))?;
            #[derive(serde::Deserialize)]
            struct FileMeta {
                filename: String,
                size_pt: u64,
                file_aead_key_b64: String,
            }
            let meta: FileMeta = serde_json::from_slice(&pt_meta)
                .context("decrypted file metadata is not valid JSON")?;
            let key_bytes = base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(&meta.file_aead_key_b64)
                .context("file_aead_key not base64-no-pad")?;
            if key_bytes.len() != 32 {
                return Err(anyhow!("file_aead_key has wrong length"));
            }
            let mut file_key = [0u8; 32];
            file_key.copy_from_slice(&key_bytes);

            // Server reports ciphertext size; compare against what we
            // actually downloaded as a sanity check.
            let ciphertext = api.public_send_blob_download(&server_base, &id, &dl_token)?;
            if let Some(expected) = resp.size_ct {
                if (expected as usize) != ciphertext.len() {
                    return Err(anyhow!(
                        "downloaded {} ciphertext bytes; server claimed {}",
                        ciphertext.len(),
                        expected
                    ));
                }
            }
            let plaintext = hekate_core::attachment::decrypt(&file_key, id.as_bytes(), &ciphertext)
                .map_err(|e| anyhow!("attachment decrypt: {e}"))?;
            if plaintext.len() as u64 != meta.size_pt {
                eprintln!(
                    "# warning: plaintext is {} bytes but metadata claimed {}",
                    plaintext.len(),
                    meta.size_pt
                );
            }
            let out_path = args.out.clone().unwrap_or(meta.filename.clone());
            if out_path == "-" {
                use std::io::Write;
                let stdout = std::io::stdout();
                let mut h = stdout.lock();
                h.write_all(&plaintext).context("write stdout")?;
            } else {
                std::fs::write(&out_path, &plaintext)
                    .with_context(|| format!("write {out_path}"))?;
                eprintln!(
                    "# wrote {out_path} ({} bytes; original filename: {})",
                    plaintext.len(),
                    meta.filename
                );
            }
        }
        other => {
            return Err(anyhow!("unknown send_type {other}"));
        }
    }
    Ok(())
}

// =====================================================================
// helpers
// =====================================================================

/// Build a tus `Upload-Metadata` header value. Comma-separated
/// `key value` pairs where each value is base64-encoded (server
/// accepts both padded and unpadded; we emit padded for fidelity to
/// the spec). Mirrors the helper in `attach.rs` so `hekate send
/// create-file` doesn't depend on a pub-crate export from there.
fn build_tus_metadata(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(k);
        out.push(' ');
        out.push_str(&base64::engine::general_purpose::STANDARD.encode(v));
    }
    out
}

/// Thin alias over the canonical `hekate-core::send::name_aad` so older
/// call-sites in this file keep their short name.
fn name_aad(send_id: &str) -> Vec<u8> {
    hekate_core::send::name_aad(send_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_share_url_canonical() {
        let id = "0192e0a0-0000-7000-8000-000000000001";
        let key_b64 = encode_send_key(&generate_send_key());
        let url = format!("https://hekate.example/send/#/{id}/{key_b64}");
        let (base, parsed_id, _key) = parse_share_url(&url).unwrap();
        assert_eq!(base, "https://hekate.example");
        assert_eq!(parsed_id, id);
    }

    #[test]
    fn parse_share_url_without_send_path() {
        let id = "0192e0a0-0000-7000-8000-000000000001";
        let key_b64 = encode_send_key(&generate_send_key());
        let url = format!("https://hekate.example/#/{id}/{key_b64}");
        let (base, parsed_id, _key) = parse_share_url(&url).unwrap();
        assert_eq!(base, "https://hekate.example");
        assert_eq!(parsed_id, id);
    }

    #[test]
    fn parse_share_url_rejects_missing_fragment() {
        assert!(parse_share_url("https://hekate.example/send/").is_err());
    }

    #[test]
    fn parse_share_url_rejects_short_fragment() {
        let url = "https://hekate.example/send/#/just-an-id";
        assert!(parse_share_url(url).is_err());
    }
}
