//! M2.24 — Attachment endpoints.
//!
//! Implements the tus 1.0 subset (Creation, Termination, Checksum
//! discovery) plus auth-gated download. Wire layout:
//!
//! ```text
//! OPTIONS /api/v1/attachments              -> tus discovery
//! POST    /api/v1/attachments              -> tus create + bind to cipher
//! HEAD    /api/v1/tus/{token}              -> resume probe
//! PATCH   /api/v1/tus/{token}              -> append bytes
//! DELETE  /api/v1/tus/{token}              -> abort upload
//! GET     /api/v1/attachments/{id}         -> metadata only (JSON)
//! GET     /api/v1/attachments/{id}/blob    -> auth-gated stream of ciphertext
//! DELETE  /api/v1/attachments/{id}         -> hard-delete (writes tombstone)
//! ```
//!
//! ## Auth + permission model
//!
//! - All endpoints require a JWT-or-PAT bearer with `vault:write`
//!   (creation/PATCH/DELETE) or `vault:read` (HEAD/GET).
//! - Creation binds the upload to a specific `cipher_id`. The cipher
//!   must be writeable by the caller — personal ciphers are owned, org
//!   ciphers gate on `effective_permission == Manage`.
//! - The `upload_token` returned from creation is an unguessable 32-byte
//!   capability used for HEAD/PATCH/DELETE. We re-check ownership on
//!   every PATCH (the caller must still match `attachments.user_id`)
//!   so a leaked token can't be used by another user.
//!
//! ## Quotas
//!
//! Three limits, all on ciphertext bytes — enforced at creation time:
//! - per-file (`max_attachment_bytes`)
//! - per-cipher (`max_cipher_attachment_bytes`)
//! - per-account (`max_account_attachment_bytes`)
//!
//! Reserved bytes from in-progress uploads count against the quota
//! until the upload row expires (24h).
//!
//! ## Integrity
//!
//! Client computes BLAKE3 of the entire ciphertext and includes it in
//! the tus `Upload-Metadata` (`content_hash_b3`). On finalize, server
//! re-hashes from disk and rejects on mismatch. Per-AEAD-chunk integrity
//! is provided by the chunked-AEAD format itself (see
//! `hekate-core::attachment`); the server never decrypts.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, options, patch},
    Json, Router,
};
use base64::Engine as _;
use chrono::{Duration, Utc};
use hekate_core::{
    attachment::{ciphertext_size_for, content_hash_b3, HEADER_LEN},
    encstring::EncString,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    auth::{scope, AuthUser},
    perms::{effective_permission, Permission},
    push::{PushEvent, PushKind},
    routes::accounts::ApiError,
    AppState,
};

const TUS_VERSION: &str = "1.0.0";
const TUS_SUPPORTED: &str = "1.0.0";
/// Extensions we implement. `creation-with-upload` lets clients send
/// the first body chunk in the same request as the create — saves a
/// round trip on small files.
const TUS_EXTENSIONS: &str = "creation,creation-with-upload,termination,checksum";
const TUS_CHECKSUM_ALGORITHMS: &str = "sha-256";

pub fn router() -> Router<AppState> {
    // Audit S-M2 (2026-05-07): explicit body cap on the attachment
    // upload routes (POST + PATCH). axum's implicit default is 2 MiB
    // which is fine for JSON endpoints but actively wrong for tus
    // chunks; set a 128 MiB ceiling on the attachment router so a
    // misbehaving client can't request multi-GiB allocations. The
    // per-handler `upload_length > max_attachment_bytes` check (in
    // tus_create) is the policy gate; this is the resource gate.
    const ATTACHMENT_BODY_LIMIT: usize = 128 * 1024 * 1024;
    Router::new()
        .route(
            "/api/v1/attachments",
            options(tus_discover).post(tus_create),
        )
        .route(
            "/api/v1/tus/{token}",
            patch(tus_patch).delete(tus_terminate).head(tus_head),
        )
        .layer(axum::extract::DefaultBodyLimit::max(ATTACHMENT_BODY_LIMIT))
        .route(
            "/api/v1/attachments/{id}",
            get(get_metadata).delete(delete_attachment),
        )
        .route("/api/v1/attachments/{id}/blob", get(get_blob))
}

// =====================================================================
// Wire types
// =====================================================================

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct AttachmentView {
    pub id: String,
    pub cipher_id: String,
    /// EncString v3 envelope of the plaintext filename, under the
    /// cipher key.
    pub filename: String,
    /// EncString v3 envelope of the per-attachment AEAD key, under
    /// the cipher key with AAD `attachment_id || "|key|" || cipher_id`.
    pub content_key: String,
    /// Plaintext bytes, client-asserted at create time.
    pub size_pt: i64,
    /// Ciphertext bytes on disk.
    pub size_ct: i64,
    /// BLAKE3(ciphertext), base64-no-pad.
    pub content_hash_b3: String,
    pub revision_date: String,
    pub creation_date: String,
    /// Reserved for future trash semantics (always `None` in M2.24 —
    /// attachments hard-delete to a tombstone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_date: Option<String>,
}

// =====================================================================
// tus discovery (OPTIONS)
// =====================================================================

/// `OPTIONS /api/v1/attachments` — tus 1.0 capability discovery.
async fn tus_discover(State(state): State<AppState>) -> Response {
    let mut h = HeaderMap::new();
    h.insert("Tus-Resumable", HeaderValue::from_static(TUS_VERSION));
    h.insert("Tus-Version", HeaderValue::from_static(TUS_SUPPORTED));
    h.insert("Tus-Extension", HeaderValue::from_static(TUS_EXTENSIONS));
    h.insert(
        "Tus-Checksum-Algorithm",
        HeaderValue::from_static(TUS_CHECKSUM_ALGORITHMS),
    );
    h.insert(
        "Tus-Max-Size",
        HeaderValue::from_str(&state.config.max_attachment_bytes.to_string()).expect("u64 fits"),
    );
    (StatusCode::NO_CONTENT, h).into_response()
}

// =====================================================================
// tus create (POST)
// =====================================================================

/// Parse the tus `Upload-Metadata` header (RFC: comma-separated
/// `key value` pairs where value is base64-encoded). We accept both
/// padded and unpadded base64 since clients vary; we always emit
/// no-pad on our side.
fn parse_upload_metadata(raw: &str) -> Result<HashMap<String, String>, ApiError> {
    use base64::{
        engine::general_purpose::{STANDARD, STANDARD_NO_PAD as NOPAD},
        Engine,
    };
    let mut out = HashMap::new();
    for pair in raw.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, ' ');
        let key = it
            .next()
            .ok_or_else(|| ApiError::bad_request("malformed Upload-Metadata"))?
            .trim()
            .to_string();
        let val_b64 = it.next().unwrap_or("").trim();
        // tus spec says base64-encoded; in practice padding may or may
        // not be present. Try both.
        let bytes = STANDARD
            .decode(val_b64)
            .or_else(|_| NOPAD.decode(val_b64))
            .map_err(|_| {
                ApiError::bad_request(format!("bad base64 in Upload-Metadata key {key}"))
            })?;
        let val = String::from_utf8(bytes).map_err(|_| {
            ApiError::bad_request(format!("non-utf8 Upload-Metadata value for {key}"))
        })?;
        out.insert(key, val);
    }
    Ok(out)
}

fn require_meta<'a>(meta: &'a HashMap<String, String>, key: &str) -> Result<&'a str, ApiError> {
    meta.get(key).map(|s| s.as_str()).ok_or_else(|| {
        ApiError::bad_request(format!("Upload-Metadata missing required key '{key}'"))
    })
}

async fn tus_create(
    user: AuthUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    let upload_length = headers
        .get("upload-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| ApiError::bad_request("Upload-Length header required"))?;
    if upload_length < HEADER_LEN as u64 + 16 + 1 {
        return Err(ApiError::bad_request(
            "Upload-Length too small to be a valid PMGRA1 attachment",
        ));
    }
    if upload_length > state.config.max_attachment_bytes {
        return Err(ApiError::bad_request(format!(
            "attachment exceeds per-file limit ({} bytes)",
            state.config.max_attachment_bytes
        )));
    }

    let raw_meta = headers
        .get("upload-metadata")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::bad_request("Upload-Metadata header required"))?;
    let meta = parse_upload_metadata(raw_meta)?;
    let cipher_id = require_meta(&meta, "cipher_id")?.to_string();
    let filename = require_meta(&meta, "filename")?.to_string();
    let content_key = require_meta(&meta, "content_key")?.to_string();
    let content_hash_b3 = require_meta(&meta, "content_hash_b3")?.to_string();
    let attachment_id = require_meta(&meta, "attachment_id")?.to_string();
    let size_pt: i64 = require_meta(&meta, "size_pt")?.parse().map_err(|_| {
        ApiError::bad_request("Upload-Metadata size_pt must be a non-negative integer")
    })?;
    if size_pt < 0 {
        return Err(ApiError::bad_request("size_pt must be >= 0"));
    }

    // Validate UUIDv7 shape on both ids (defense vs path-traversal-via-id).
    Uuid::parse_str(&cipher_id)
        .map_err(|_| ApiError::bad_request("cipher_id must be a UUID string"))?;
    Uuid::parse_str(&attachment_id)
        .map_err(|_| ApiError::bad_request("attachment_id must be a UUID string"))?;
    EncString::parse(&filename).map_err(|e| ApiError::bad_request(format!("filename: {e}")))?;
    EncString::parse(&content_key)
        .map_err(|e| ApiError::bad_request(format!("content_key: {e}")))?;
    // Sanity: claimed plaintext size matches the chunked-AEAD wire size.
    let expected_ct = ciphertext_size_for(size_pt as u64);
    if expected_ct != upload_length {
        return Err(ApiError::bad_request(format!(
            "Upload-Length {upload_length} does not match ciphertext_size_for(size_pt={size_pt})={expected_ct}"
        )));
    }

    // Cipher must exist + be writeable by caller.
    let cipher_row: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT user_id, org_id FROM ciphers WHERE id = $1")
            .bind(&cipher_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let (cipher_user_id, cipher_org_id) =
        cipher_row.ok_or_else(|| ApiError::not_found("cipher not found"))?;
    let is_personal_owner = cipher_user_id.as_deref() == Some(user.user_id.as_str());
    if !is_personal_owner && cipher_org_id.is_some() {
        let perm = effective_permission(&state, &user.user_id, &cipher_id).await?;
        if !matches!(perm, Some(Permission::Manage)) {
            return Err(ApiError::forbidden("need `manage` on the cipher to attach"));
        }
    } else if !is_personal_owner {
        return Err(ApiError::forbidden("cipher not writeable by caller"));
    }

    // Per-cipher and per-account quotas: completed bytes + reserved
    // bytes from in-progress uploads.
    // CAST AS BIGINT keeps both Postgres + SQLite happy. Postgres'
    // SUM(BIGINT) returns NUMERIC by default, which sqlx's `Any`
    // driver can't decode; SQLite's SUM is INTEGER so it doesn't
    // notice. Same fix on every SUM(size_ct) / SUM(expected_size)
    // call in this module.
    let (cipher_used,): (i64,) = sqlx::query_as(
        "SELECT CAST(COALESCE(SUM(size_ct),0) AS BIGINT) FROM attachments
         WHERE cipher_id = $1 AND status = 1",
    )
    .bind(&cipher_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let (cipher_reserved,): (i64,) = sqlx::query_as(
        "SELECT CAST(COALESCE(SUM(u.expected_size),0) AS BIGINT)
         FROM attachment_uploads u
         JOIN attachments a ON a.id = u.id
         WHERE a.cipher_id = $1",
    )
    .bind(&cipher_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    if (cipher_used as u64 + cipher_reserved as u64 + upload_length)
        > state.config.max_cipher_attachment_bytes
    {
        return Err(ApiError::bad_request(format!(
            "attachment would exceed per-cipher limit ({} bytes)",
            state.config.max_cipher_attachment_bytes
        )));
    }

    let (account_used,): (i64,) = sqlx::query_as(
        "SELECT CAST(COALESCE(SUM(size_ct),0) AS BIGINT) FROM attachments
         WHERE user_id = $1 AND status = 1",
    )
    .bind(&user.user_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let (account_reserved,): (i64,) = sqlx::query_as(
        "SELECT CAST(COALESCE(SUM(u.expected_size),0) AS BIGINT)
         FROM attachment_uploads u
         JOIN attachments a ON a.id = u.id
         WHERE a.user_id = $1",
    )
    .bind(&user.user_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    if (account_used as u64 + account_reserved as u64 + upload_length)
        > state.config.max_account_attachment_bytes
    {
        return Err(ApiError::bad_request(format!(
            "attachment would exceed per-account limit ({} bytes)",
            state.config.max_account_attachment_bytes
        )));
    }

    // Allocate row + tus state.
    let now = Utc::now().to_rfc3339();
    let expires_at = (Utc::now() + Duration::hours(24)).to_rfc3339();
    let storage_key = format!("{}/{}", user.user_id, attachment_id);
    let mut token_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut token_bytes);
    let upload_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);

    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let attachments_insert = sqlx::query(
        "INSERT INTO attachments
            (id, cipher_id, user_id, org_id, filename, content_key,
             size_ct, size_pt, storage_key, content_hash_b3, status,
             revision_date, creation_date)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,0,$11,$12)",
    )
    .bind(&attachment_id)
    .bind(&cipher_id)
    .bind(&user.user_id)
    .bind(cipher_org_id.as_deref())
    .bind(&filename)
    .bind(&content_key)
    .bind(upload_length as i64)
    .bind(size_pt)
    .bind(&storage_key)
    .bind(&content_hash_b3)
    .bind(&now)
    .bind(&now)
    .execute(&mut *tx)
    .await;
    match attachments_insert {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(ApiError::conflict("attachment id already exists"));
        }
        Err(e) => return Err(ApiError::internal(e.to_string())),
    }

    sqlx::query(
        "INSERT INTO attachment_uploads
            (id, upload_token, bytes_received, expected_size, expires_at, upload_metadata)
         VALUES ($1,$2,0,$3,$4,$5)",
    )
    .bind(&attachment_id)
    .bind(&upload_token)
    .bind(upload_length as i64)
    .bind(&expires_at)
    .bind(raw_meta)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // creation-with-upload: if the body is non-empty, route through the
    // PATCH path immediately. We've committed the row first so a flaky
    // network on the body still leaves a resumable upload.
    let mut bytes_received: u64 = 0;
    if !body.is_empty() {
        write_chunk(&state, &user.user_id, &upload_token, 0, &body).await?;
        bytes_received = body.len() as u64;
    }
    if bytes_received == upload_length {
        finalize_upload(&state, &user.user_id, &upload_token).await?;
    }

    let location = format!("/api/v1/tus/{}", upload_token);
    let mut h = HeaderMap::new();
    h.insert("Tus-Resumable", HeaderValue::from_static(TUS_VERSION));
    h.insert(
        header::LOCATION,
        HeaderValue::from_str(&location).expect("safe ASCII"),
    );
    h.insert(
        "Upload-Offset",
        HeaderValue::from_str(&bytes_received.to_string()).expect("u64 fits"),
    );
    Ok((StatusCode::CREATED, h).into_response())
}

// =====================================================================
// tus HEAD (resume probe)
// =====================================================================

async fn tus_head(
    user: AuthUser,
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Response, ApiError> {
    user.require(scope::VAULT_READ)?;
    let row = lookup_upload(&state, &user.user_id, &token).await?;
    let mut h = HeaderMap::new();
    h.insert("Tus-Resumable", HeaderValue::from_static(TUS_VERSION));
    h.insert(
        "Upload-Offset",
        HeaderValue::from_str(&row.bytes_received.to_string()).expect("u64 fits"),
    );
    h.insert(
        "Upload-Length",
        HeaderValue::from_str(&row.expected_size.to_string()).expect("u64 fits"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((StatusCode::OK, h).into_response())
}

// =====================================================================
// tus PATCH (append bytes)
// =====================================================================

async fn tus_patch(
    user: AuthUser,
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    let upload = lookup_upload(&state, &user.user_id, &token).await?;
    let claimed_offset = headers
        .get("upload-offset")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| ApiError::bad_request("Upload-Offset header required"))?;
    if claimed_offset != upload.bytes_received {
        // tus spec: 409 Conflict when offsets disagree.
        return Err(ApiError::conflict(format!(
            "Upload-Offset {claimed_offset} does not match server's {}",
            upload.bytes_received
        )));
    }
    let new_total = upload.bytes_received + body.len() as u64;
    if new_total > upload.expected_size {
        return Err(ApiError::bad_request(format!(
            "PATCH would write {new_total} bytes; expected_size is {}",
            upload.expected_size
        )));
    }

    write_chunk(&state, &user.user_id, &token, upload.bytes_received, &body).await?;

    let bytes_received = new_total;
    let mut h = HeaderMap::new();
    h.insert("Tus-Resumable", HeaderValue::from_static(TUS_VERSION));
    h.insert(
        "Upload-Offset",
        HeaderValue::from_str(&bytes_received.to_string()).expect("u64 fits"),
    );

    if bytes_received == upload.expected_size {
        finalize_upload(&state, &user.user_id, &token).await?;
    }
    Ok((StatusCode::NO_CONTENT, h).into_response())
}

/// Persist a PATCH body. The DB row is updated within a single SQL
/// statement that asserts the previous `bytes_received`, which serves
/// as the optimistic lock against concurrent PATCHes against the same
/// upload — second writer's update affects 0 rows and we abort.
async fn write_chunk(
    state: &AppState,
    user_id: &str,
    token: &str,
    expected_offset: u64,
    bytes: &[u8],
) -> Result<(), ApiError> {
    if bytes.is_empty() {
        return Ok(());
    }
    // Look up storage_key from attachments via the upload token.
    let row: Option<(String, i64)> = sqlx::query_as(
        "SELECT a.storage_key, u.bytes_received
         FROM attachment_uploads u
         JOIN attachments a ON a.id = u.id
         WHERE u.upload_token = $1 AND a.user_id = $2",
    )
    .bind(token)
    .bind(user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let (storage_key, current_bytes) =
        row.ok_or_else(|| ApiError::not_found("upload not found"))?;
    if current_bytes as u64 != expected_offset {
        return Err(ApiError::conflict("upload offset moved under us"));
    }

    state
        .blob
        .append(&storage_key, bytes)
        .await
        .map_err(|e| ApiError::internal(format!("blob append: {e}")))?;

    let new_offset = current_bytes + bytes.len() as i64;
    let res = sqlx::query(
        "UPDATE attachment_uploads
         SET bytes_received = $1
         WHERE upload_token = $2 AND bytes_received = $3",
    )
    .bind(new_offset)
    .bind(token)
    .bind(current_bytes)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    if res.rows_affected() == 0 {
        return Err(ApiError::conflict("concurrent PATCH detected"));
    }
    Ok(())
}

/// Verify hash, promote the attachment row to status=1, drop the
/// upload row, fire push events.
async fn finalize_upload(state: &AppState, user_id: &str, token: &str) -> Result<(), ApiError> {
    let row: Option<(String, String, String, String)> = sqlx::query_as(
        "SELECT a.id, a.cipher_id, a.storage_key, a.content_hash_b3
         FROM attachment_uploads u
         JOIN attachments a ON a.id = u.id
         WHERE u.upload_token = $1 AND a.user_id = $2",
    )
    .bind(token)
    .bind(user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let (att_id, cipher_id, storage_key, expected_hash) =
        row.ok_or_else(|| ApiError::not_found("upload not found"))?;

    // Read back from disk for the server-side BLAKE3 verify. For the
    // ~100 MiB cap this is well under a second; future work uses
    // streaming-hash on PATCH to avoid the extra read.
    let bytes = state
        .blob
        .read_full(&storage_key)
        .await
        .map_err(|e| ApiError::internal(format!("blob read on finalize: {e}")))?;
    let actual_hash = content_hash_b3(&bytes);
    if actual_hash != expected_hash {
        // Hash mismatch: tear down state. The caller has to retry the
        // upload from scratch. Mark the attachment row deleted (it's in
        // status=uploading anyway, never visible) and remove the blob.
        let _ = state.blob.delete(&storage_key).await;
        sqlx::query("DELETE FROM attachment_uploads WHERE upload_token = $1")
            .bind(token)
            .execute(state.db.pool())
            .await
            .ok();
        sqlx::query("DELETE FROM attachments WHERE id = $1")
            .bind(&att_id)
            .execute(state.db.pool())
            .await
            .ok();
        return Err(ApiError::bad_request(
            "ciphertext BLAKE3 hash does not match Upload-Metadata content_hash_b3",
        ));
    }

    let now = Utc::now().to_rfc3339();
    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    sqlx::query("UPDATE attachments SET status = 1, revision_date = $1 WHERE id = $2")
        .bind(&now)
        .bind(&att_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    sqlx::query("DELETE FROM attachment_uploads WHERE upload_token = $1")
        .bind(token)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    // Bump the parent cipher's revision_date so /sync surfaces the
    // change without a separate cipher write.
    sqlx::query("UPDATE ciphers SET revision_date = $1 WHERE id = $2")
        .bind(&now)
        .bind(&cipher_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    state.push.publish(PushEvent {
        user_id: user_id.into(),
        kind: PushKind::AttachmentChanged,
        id: att_id,
        revision: now.clone(),
    });
    state.push.publish(PushEvent {
        user_id: user_id.into(),
        kind: PushKind::CipherChanged,
        id: cipher_id,
        revision: now,
    });
    Ok(())
}

// =====================================================================
// tus DELETE (terminate)
// =====================================================================

async fn tus_terminate(
    user: AuthUser,
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Response, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT a.id, a.storage_key
         FROM attachment_uploads u
         JOIN attachments a ON a.id = u.id
         WHERE u.upload_token = $1 AND a.user_id = $2",
    )
    .bind(&token)
    .bind(&user.user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some((att_id, storage_key)) = row else {
        return Err(ApiError::not_found("upload not found"));
    };
    // Order: delete the blob first, then the rows. If the blob delete
    // fails we leak bytes but never lose the row pointing at them.
    let _ = state.blob.delete(&storage_key).await;
    sqlx::query("DELETE FROM attachments WHERE id = $1 AND status = 0")
        .bind(&att_id)
        .execute(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let mut h = HeaderMap::new();
    h.insert("Tus-Resumable", HeaderValue::from_static(TUS_VERSION));
    Ok((StatusCode::NO_CONTENT, h).into_response())
}

// =====================================================================
// Metadata + blob download + delete
// =====================================================================

async fn get_metadata(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<AttachmentView>, ApiError> {
    user.require(scope::VAULT_READ)?;
    let view = load_visible(&state, &user.user_id, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("attachment not found"))?;
    Ok(Json(view))
}

async fn get_blob(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    user.require(scope::VAULT_READ)?;
    let row: Option<(String, String, i64, i32)> = sqlx::query_as(
        "SELECT a.cipher_id, a.storage_key, a.size_ct, a.status
         FROM attachments a
         WHERE a.id = $1",
    )
    .bind(&id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let (cipher_id, storage_key, _size_ct, status) =
        row.ok_or_else(|| ApiError::not_found("attachment not found"))?;
    if status != 1 {
        return Err(ApiError::not_found("attachment not finalized"));
    }
    require_read_permission(&state, &user.user_id, &cipher_id).await?;

    let bytes = state
        .blob
        .read_full(&storage_key)
        .await
        .map_err(|e| ApiError::internal(format!("blob read: {e}")))?;
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&bytes.len().to_string()).expect("usize fits"),
    );
    Ok((StatusCode::OK, h, bytes).into_response())
}

async fn delete_attachment(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    let row: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT a.cipher_id, a.storage_key, a.user_id FROM attachments a WHERE a.id = $1",
    )
    .bind(&id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let (cipher_id, storage_key, _row_user) =
        row.ok_or_else(|| ApiError::not_found("attachment not found"))?;
    require_write_permission(&state, &user.user_id, &cipher_id).await?;

    let now = Utc::now().to_rfc3339();
    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    sqlx::query("DELETE FROM attachments WHERE id = $1")
        .bind(&id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    // Tombstone (per-user, same shape as cipher tombstones).
    sqlx::query(
        "INSERT INTO tombstones (kind, id, user_id, deleted_at)
         VALUES ('attachment', $1, $2, $3)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(&now)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    // Cleanup queue: blob delete is best-effort and async to PATCH/GET
    // hot path. Background worker drains this table.
    sqlx::query(
        "INSERT INTO attachment_blob_tombstones (storage_key, enqueued_at) VALUES ($1, $2)",
    )
    .bind(&storage_key)
    .bind(&now)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    // Bump cipher revision so /sync surfaces the change.
    sqlx::query("UPDATE ciphers SET revision_date = $1 WHERE id = $2")
        .bind(&now)
        .bind(&cipher_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // Best-effort blob delete inline; if it fails the worker retries.
    let _ = state.blob.delete(&storage_key).await;

    state.push.publish(PushEvent {
        user_id: user.user_id.clone(),
        kind: PushKind::AttachmentTombstoned,
        id: id.clone(),
        revision: now.clone(),
    });
    state.push.publish(PushEvent {
        user_id: user.user_id.clone(),
        kind: PushKind::CipherChanged,
        id: cipher_id,
        revision: now,
    });
    Ok(StatusCode::NO_CONTENT.into_response())
}

// =====================================================================
// Helpers
// =====================================================================

struct UploadRow {
    bytes_received: u64,
    expected_size: u64,
}

async fn lookup_upload(
    state: &AppState,
    user_id: &str,
    token: &str,
) -> Result<UploadRow, ApiError> {
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT u.bytes_received, u.expected_size
         FROM attachment_uploads u
         JOIN attachments a ON a.id = u.id
         WHERE u.upload_token = $1 AND a.user_id = $2",
    )
    .bind(token)
    .bind(user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let (br, es) = row.ok_or_else(|| ApiError::not_found("upload not found"))?;
    Ok(UploadRow {
        bytes_received: br as u64,
        expected_size: es as u64,
    })
}

async fn require_read_permission(
    state: &AppState,
    user_id: &str,
    cipher_id: &str,
) -> Result<(), ApiError> {
    let row: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT user_id, org_id FROM ciphers WHERE id = $1")
            .bind(cipher_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let (cu, co) = row.ok_or_else(|| ApiError::not_found("cipher not found"))?;
    if cu.as_deref() == Some(user_id) {
        return Ok(());
    }
    if co.is_some() {
        let perm = effective_permission(state, user_id, cipher_id).await?;
        if perm.is_some() {
            return Ok(());
        }
    }
    Err(ApiError::not_found("attachment not found"))
}

async fn require_write_permission(
    state: &AppState,
    user_id: &str,
    cipher_id: &str,
) -> Result<(), ApiError> {
    let row: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT user_id, org_id FROM ciphers WHERE id = $1")
            .bind(cipher_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let (cu, co) = row.ok_or_else(|| ApiError::not_found("cipher not found"))?;
    if cu.as_deref() == Some(user_id) {
        return Ok(());
    }
    if co.is_some() {
        let perm = effective_permission(state, user_id, cipher_id).await?;
        if matches!(perm, Some(Permission::Manage)) {
            return Ok(());
        }
    }
    Err(ApiError::forbidden(
        "permission denied: this cipher requires `manage` to modify attachments",
    ))
}

async fn load_visible(
    state: &AppState,
    user_id: &str,
    id: &str,
) -> Result<Option<AttachmentView>, ApiError> {
    let row: Option<AttachmentRow> = sqlx::query_as(
        "SELECT a.id, a.cipher_id, a.filename, a.content_key,
                a.size_pt, a.size_ct, a.content_hash_b3,
                a.revision_date, a.creation_date, a.status
         FROM attachments a
         WHERE a.id = $1",
    )
    .bind(id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some(r) = row else { return Ok(None) };
    if r.status != 1 {
        return Ok(None);
    }
    require_read_permission(state, user_id, &r.cipher_id).await?;
    Ok(Some(AttachmentView {
        id: r.id,
        cipher_id: r.cipher_id,
        filename: r.filename,
        content_key: r.content_key,
        size_pt: r.size_pt,
        size_ct: r.size_ct,
        content_hash_b3: r.content_hash_b3,
        revision_date: r.revision_date,
        creation_date: r.creation_date,
        deleted_date: None,
    }))
}

#[derive(sqlx::FromRow)]
pub(crate) struct AttachmentRow {
    pub id: String,
    pub cipher_id: String,
    pub filename: String,
    pub content_key: String,
    pub size_pt: i64,
    pub size_ct: i64,
    pub content_hash_b3: String,
    pub revision_date: String,
    pub creation_date: String,
    pub status: i32,
}

impl AttachmentRow {
    pub(crate) fn into_view(self) -> AttachmentView {
        AttachmentView {
            id: self.id,
            cipher_id: self.cipher_id,
            filename: self.filename,
            content_key: self.content_key,
            size_pt: self.size_pt,
            size_ct: self.size_ct,
            content_hash_b3: self.content_hash_b3,
            revision_date: self.revision_date,
            creation_date: self.creation_date,
            deleted_date: None,
        }
    }
}
