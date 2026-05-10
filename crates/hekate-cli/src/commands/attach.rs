//! `hekate attach {upload, download, list, delete}` — M2.24 attachments.
//!
//! Upload flow:
//!   1. Generate a per-attachment 32-byte AEAD key.
//!   2. Stream-encrypt the file into the chunked PMGRA1 ciphertext, in
//!      RAM (M2.24 caps at 100 MiB; future work streams from disk).
//!   3. Wrap att_key under the cipher key with AAD = att_key_wrap_aad().
//!   4. POST /api/v1/attachments with creation-with-upload to start tus
//!      and submit the first ciphertext chunk in one round trip.
//!   5. PATCH the rest in 4 MiB tus-transport chunks, with HEAD-based
//!      resume on transient network errors.
//!   6. Sign + upload a fresh manifest so the new attachment_root is
//!      committed for BW04 verification on other devices.
//!
//! Download flow is the inverse: GET metadata + blob, unwrap att_key,
//! stream-decrypt, write plaintext.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Args as ClapArgs, Subcommand};
use hekate_core::{
    attachment::{
        att_key_wrap_aad, ciphertext_size_for, content_hash_b3, decrypt as att_decrypt,
        encrypt as att_encrypt, generate_attachment_key,
    },
    encstring::EncString,
};
use uuid::Uuid;

use crate::{
    api::{Api, CipherView},
    commands::{persist_refreshed_tokens, unlock_session},
    crypto::{
        aad_cipher_name, decrypt_field_string, encrypt_field, unwrap_cipher_key,
        unwrap_cipher_key_under, Unlocked,
    },
};
use zeroize::Zeroizing;

/// Resolve the per-cipher key for either a personal or org-owned cipher.
/// Mirrors the dispatch in `hekate show`: org ciphers wrap their per-cipher
/// key under the org symmetric key; personal ciphers wrap under the
/// account key. Centralized here so all four `attach` subcommands stay
/// in lockstep.
fn cipher_key_for(
    api: &Api,
    unlocked: &Unlocked,
    cipher: &CipherView,
) -> Result<Zeroizing<[u8; 32]>> {
    match &cipher.org_id {
        None => unwrap_cipher_key(unlocked, &cipher.protected_cipher_key, &cipher.id),
        Some(oid) => {
            let (_org, org_sym_key) =
                crate::commands::org::fetch_org_and_unwrap(api, unlocked, oid)?;
            unwrap_cipher_key_under(&org_sym_key, &cipher.protected_cipher_key, &cipher.id)
        }
    }
}

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[command(subcommand)]
    pub cmd: Sub,
}

#[derive(Debug, Subcommand)]
pub enum Sub {
    /// Encrypt a file and upload it as a new attachment on a cipher.
    Upload(UploadArgs),
    /// Download and decrypt an attachment to a local file (or stdout
    /// via `-o -`).
    Download(DownloadArgs),
    /// List attachments on a cipher (decrypted filenames).
    List(ListArgs),
    /// Permanently remove an attachment.
    Delete(DeleteArgs),
}

#[derive(Debug, ClapArgs)]
pub struct UploadArgs {
    /// Cipher id (UUID) to attach to.
    pub cipher_id: String,
    /// Local file path to upload.
    pub file: PathBuf,
}

#[derive(Debug, ClapArgs)]
pub struct DownloadArgs {
    /// Attachment id (UUID).
    pub id: String,
    /// Output path. `-` writes to stdout.
    #[arg(short, long)]
    pub out: Option<String>,
}

#[derive(Debug, ClapArgs)]
pub struct ListArgs {
    /// Cipher id (UUID).
    pub cipher_id: String,
}

#[derive(Debug, ClapArgs)]
pub struct DeleteArgs {
    /// Attachment id (UUID).
    pub id: String,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

pub fn run(args: Args) -> Result<()> {
    match args.cmd {
        Sub::Upload(a) => run_upload(a),
        Sub::Download(a) => run_download(a),
        Sub::List(a) => run_list(a),
        Sub::Delete(a) => run_delete(a),
    }
}

// =====================================================================
// Upload
// =====================================================================

/// 4 MiB tus PATCH transport chunk size. Independent of the AEAD
/// chunk size (1 MiB) — tus is purely transport. We keep PATCH chunks
/// big enough that small files fit in one POST body via
/// creation-with-upload.
const TUS_PATCH_CHUNK: usize = 4 * 1024 * 1024;

fn run_upload(args: UploadArgs) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;

    // Validate cipher id shape; generate the new attachment id.
    Uuid::parse_str(&args.cipher_id).context("cipher_id must be a UUID")?;
    let attachment_id = Uuid::now_v7().to_string();

    // Read the file. M2.24 caps individual attachments at 100 MiB by
    // default; the server enforces — we let the server reject oversize
    // rather than re-implement quota math here.
    let plaintext =
        std::fs::read(&args.file).with_context(|| format!("read {}", args.file.display()))?;
    if plaintext.is_empty() {
        return Err(anyhow!("refusing to upload an empty file"));
    }

    // Fetch the parent cipher and unwrap its per-cipher key (account
    // key for personal, org sym key for org-owned).
    let cipher = api.get_cipher(&args.cipher_id)?;
    let cipher_key = cipher_key_for(&api, &unlocked, &cipher)?;

    // Encrypt + hash. att_encrypt buffers the whole plaintext for now.
    let att_key = generate_attachment_key();
    let ciphertext = att_encrypt(&att_key, attachment_id.as_bytes(), &plaintext)
        .map_err(|e| anyhow!("attachment encrypt: {e}"))?;
    let hash_b64 = content_hash_b3(&ciphertext);

    // Wrap att_key under the cipher key with AAD bound to the
    // (attachment_id, cipher_id) location.
    let wrap_aad = att_key_wrap_aad(&attachment_id, &args.cipher_id);
    let content_key_wire = encrypt_field(&cipher_key, &att_key, &wrap_aad)?;

    // Encrypt the filename under the cipher key. We bind the AAD to the
    // attachment_id (not to the cipher's name AAD) so a server can't
    // splice a filename from one attachment onto another. Reusing the
    // cipher's `name` AAD would also work but conflates two roles.
    let filename_pt = args
        .file
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("attachment")
        .to_string();
    let filename_aad = filename_aad(&attachment_id, &args.cipher_id);
    let filename_wire = encrypt_field(&cipher_key, filename_pt.as_bytes(), &filename_aad)?;

    let upload_length = ciphertext.len() as u64;
    let expected = ciphertext_size_for(plaintext.len() as u64);
    if upload_length != expected {
        return Err(anyhow!(
            "internal: ciphertext length {upload_length} != ciphertext_size_for({})={expected}",
            plaintext.len()
        ));
    }

    // tus Upload-Metadata: `key value, key value, ...` with values
    // base64-encoded.
    let meta = build_upload_metadata(&[
        ("attachment_id", &attachment_id),
        ("cipher_id", &args.cipher_id),
        ("filename", &filename_wire),
        ("content_key", &content_key_wire),
        ("content_hash_b3", &hash_b64),
        ("size_pt", &plaintext.len().to_string()),
    ]);

    // creation-with-upload: ship the first transport chunk inline. If
    // the entire file fits, finalize happens in this single round trip.
    let first = std::cmp::min(TUS_PATCH_CHUNK, ciphertext.len());
    let location = api.tus_create(upload_length, &meta, Some(&ciphertext[..first]))?;

    // PATCH the remainder in chunks. Resume on transient errors via
    // tus HEAD.
    let mut offset = first as u64;
    while (offset as usize) < ciphertext.len() {
        let take = std::cmp::min(TUS_PATCH_CHUNK, ciphertext.len() - offset as usize);
        let chunk = ciphertext[offset as usize..offset as usize + take].to_vec();
        match api.tus_patch(&location, offset, chunk) {
            Ok(new_off) => offset = new_off,
            Err(e) => {
                // Network blip: try one HEAD-based resume before bailing.
                if let Ok(server_off) = api.tus_head(&location) {
                    eprintln!("patch failed ({e}); resuming from server offset {server_off}");
                    offset = server_off;
                    continue;
                }
                return Err(anyhow!("upload aborted at offset {offset}: {e}"));
            }
        }
    }

    // After the server finalizes (when the last byte lands), the
    // attachment is visible via /sync. Refresh and re-upload the BW04
    // manifest so the new attachments_root is committed.
    crate::manifest::sync_and_upload(&api, &unlocked)?;
    persist_refreshed_tokens(&api, state)?;

    println!(
        "uploaded {attachment_id}  ({} bytes plaintext)",
        plaintext.len()
    );
    Ok(())
}

// =====================================================================
// Download
// =====================================================================

fn run_download(args: DownloadArgs) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;
    Uuid::parse_str(&args.id).context("attachment id must be a UUID")?;

    let view = api.get_attachment(&args.id)?;
    let cipher = api.get_cipher(&view.cipher_id)?;
    let cipher_key = cipher_key_for(&api, &unlocked, &cipher)?;

    // Unwrap the per-attachment key.
    let wrap_aad = att_key_wrap_aad(&view.id, &view.cipher_id);
    let parsed = EncString::parse(&view.content_key)
        .context("malformed content_key on server-returned attachment view")?;
    let att_key_bytes = parsed
        .decrypt_xc20p(&cipher_key, Some(&wrap_aad))
        .map_err(|_| {
            anyhow!("could not unwrap attachment key — wrong cipher key or tampered AAD")
        })?;
    if att_key_bytes.len() != 32 {
        return Err(anyhow!("unwrapped attachment key has wrong length"));
    }
    let mut att_key = [0u8; 32];
    att_key.copy_from_slice(&att_key_bytes);

    // Pull the ciphertext, verify content_hash_b3 (matches what the
    // manifest binds), decrypt.
    let ciphertext = api.download_attachment_blob(&view.id)?;
    let observed_hash = content_hash_b3(&ciphertext);
    if observed_hash != view.content_hash_b3 {
        return Err(anyhow!(
            "BLAKE3 of downloaded ciphertext does not match server-reported \
             content_hash_b3 — possible tamper-in-transit or backend bit-rot"
        ));
    }
    let plaintext = att_decrypt(&att_key, view.id.as_bytes(), &ciphertext)
        .map_err(|e| anyhow!("attachment decrypt: {e}"))?;

    let filename_aad = filename_aad(&view.id, &view.cipher_id);
    let filename_pt = decrypt_field_string(&cipher_key, &view.filename, &filename_aad)?;

    let out_path = args.out.unwrap_or_else(|| filename_pt.clone());
    if out_path == "-" {
        use std::io::Write;
        let stdout = std::io::stdout();
        let mut h = stdout.lock();
        h.write_all(&plaintext).context("write stdout")?;
    } else {
        std::fs::write(&out_path, &plaintext).with_context(|| format!("write {out_path}"))?;
        println!(
            "wrote {out_path}  ({} bytes, original filename: {filename_pt})",
            plaintext.len()
        );
    }

    persist_refreshed_tokens(&api, state)?;
    Ok(())
}

// =====================================================================
// List
// =====================================================================

fn run_list(args: ListArgs) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;
    Uuid::parse_str(&args.cipher_id).context("cipher_id must be a UUID")?;

    let cipher = api.get_cipher(&args.cipher_id)?;
    let cipher_key = cipher_key_for(&api, &unlocked, &cipher)?;

    // Pull /sync, filter to this cipher's attachments. /sync gives us
    // the full attachment list (status=1 only).
    let sync = api.sync(None)?;
    let mut found = false;
    for a in sync.changes.attachments {
        if a.cipher_id != args.cipher_id {
            continue;
        }
        let aad = filename_aad(&a.id, &a.cipher_id);
        let name = decrypt_field_string(&cipher_key, &a.filename, &aad)
            .unwrap_or_else(|_| "<undecryptable>".into());
        println!("{}  {:>10} bytes  {}", a.id, a.size_pt, name);
        found = true;
    }
    if !found {
        // Suppress the unused-binding warning when there are no rows.
        let _ = aad_cipher_name(&cipher.id, cipher.cipher_type);
        println!("(no attachments)");
    }

    persist_refreshed_tokens(&api, state)?;
    Ok(())
}

// =====================================================================
// Delete
// =====================================================================

fn run_delete(args: DeleteArgs) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;
    Uuid::parse_str(&args.id).context("attachment id must be a UUID")?;
    if !args.yes {
        eprintln!(
            "About to permanently delete attachment {}. Re-run with --yes to confirm.",
            args.id
        );
        return Ok(());
    }
    api.delete_attachment(&args.id)?;
    crate::manifest::sync_and_upload(&api, &unlocked)?;
    persist_refreshed_tokens(&api, state)?;
    println!("deleted");
    Ok(())
}

// =====================================================================
// Helpers
// =====================================================================

/// AAD for the encrypted `filename` field. Bound to (attachment_id,
/// cipher_id) so a server cannot splice a filename across attachments.
fn filename_aad(attachment_id: &str, cipher_id: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(64 + attachment_id.len() + cipher_id.len());
    v.extend_from_slice(b"pmgr-attachment-filename-v1:");
    v.extend_from_slice(attachment_id.as_bytes());
    v.push(b':');
    v.extend_from_slice(cipher_id.as_bytes());
    v
}

fn build_upload_metadata(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(k);
        out.push(' ');
        out.push_str(&STANDARD.encode(v));
    }
    out
}
