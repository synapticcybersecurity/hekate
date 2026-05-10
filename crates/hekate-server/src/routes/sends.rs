//! M2.25 — Send endpoints.
//!
//! Two surfaces, intentionally split by auth model:
//!
//! - **Authenticated owner CRUD** under `/api/v1/sends[/{id}]`:
//!   `POST` (create), `GET` (list mine), `GET /{id}` (read one),
//!   `PUT /{id}` (edit, with `If-Match` revision precondition),
//!   `DELETE /{id}` (hard delete + tombstone),
//!   `POST /{id}/disable` and `POST /{id}/enable`.
//!
//! - **Anonymous access** under `/api/v1/public/sends/{id}/access`:
//!   no bearer required. Body is `{"password": "..."}` (optional).
//!   Response carries the metadata + `data` EncString. Server bumps
//!   `access_count` atomically; rejects if disabled / expired /
//!   deletion_date passed / max-access reached.
//!
//! See `hekate-core::send` for the crypto and `docs/design.md` §5 Send.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, patch, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use hekate_core::{
    attachment::{ciphertext_size_for, content_hash_b3, HEADER_LEN},
    encstring::EncString,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    auth::{password as pw, scope, AuthUser},
    push::{PushEvent, PushKind},
    routes::accounts::ApiError,
    AppState,
};

pub fn router() -> Router<AppState> {
    // Audit S-M2 (2026-05-07): explicit body cap on the file-Send
    // upload routes. Same logic as the attachment router — JSON
    // endpoints fall back to axum's implicit default; the tus PATCH
    // path needs a far larger budget. 128 MiB matches the attachment
    // ceiling; per-Send caps still come from the handler body checks.
    const SEND_UPLOAD_BODY_LIMIT: usize = 128 * 1024 * 1024;
    Router::new()
        .route("/api/v1/sends", post(create).get(list))
        .route(
            "/api/v1/sends/{id}",
            get(read_one).put(update).delete(delete_one),
        )
        .route("/api/v1/sends/{id}/disable", post(disable))
        .route("/api/v1/sends/{id}/enable", post(enable))
        // (M2.25a) File-Send body upload — sender-authenticated tus.
        .route("/api/v1/sends/{id}/upload", post(send_upload_create))
        .route(
            "/api/v1/tus-send/{token}",
            patch(send_upload_patch)
                .delete(send_upload_terminate)
                .head(send_upload_head),
        )
        .layer(axum::extract::DefaultBodyLimit::max(SEND_UPLOAD_BODY_LIMIT))
        .route("/api/v1/public/sends/{id}/access", post(public_access))
        // (M2.25a) Anonymous body download. Token is granted by /access.
        .route(
            "/api/v1/public/sends/{id}/blob/{token}",
            get(public_blob_download),
        )
}

// =====================================================================
// Wire types
// =====================================================================

#[derive(Debug, Deserialize, ToSchema)]
pub struct SendInput {
    /// Client-generated UUIDv7. Bound into the AAD of every encrypted
    /// field so a server can't substitute one Send's row for another.
    pub id: String,
    /// 1 = text. 2 = file (body uploaded separately via tus).
    #[schema(minimum = 1, maximum = 2)]
    pub send_type: i32,
    /// EncString of the sender-side display name, under the account key.
    pub name: String,
    /// EncString of optional notes.
    #[serde(default)]
    pub notes: Option<String>,
    /// EncString of the 32-byte send_key wrapped under the sender's
    /// account key. AAD = `pmgr-send-key-v1:<send_id>`.
    pub protected_send_key: String,
    /// EncString of the payload (XChaCha20-Poly1305 with HKDF-derived
    /// content_key, AAD = `pmgr-send-data-v1:<send_id>:<send_type>`).
    pub data: String,
    /// Optional plaintext access password. Server-side Argon2id-PHC'd
    /// and never stored in the clear. Pass `None` for unprotected
    /// Sends. The password is NOT used in encryption — it's purely
    /// the server-side gate.
    #[serde(default)]
    pub password: Option<String>,
    /// `None` = unlimited.
    #[serde(default)]
    pub max_access_count: Option<i64>,
    /// `None` = no time-based expiry. RFC3339.
    #[serde(default)]
    pub expiration_date: Option<String>,
    /// Hard auto-delete deadline. RFC3339. Required.
    pub deletion_date: String,
    /// Defaults to `false`. Owners can also flip via
    /// `/sends/{id}/disable` / `/enable`.
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Debug, Serialize, ToSchema, Clone)]
pub struct SendView {
    pub id: String,
    pub send_type: i32,
    pub name: String,
    pub notes: Option<String>,
    pub protected_send_key: String,
    pub data: String,
    /// `true` if the Send has a server-side password gate. The PHC is
    /// never returned; this boolean is purely diagnostic for the
    /// owner's UI.
    pub has_password: bool,
    pub max_access_count: Option<i64>,
    pub access_count: i64,
    pub expiration_date: Option<String>,
    pub deletion_date: String,
    pub disabled: bool,
    pub revision_date: String,
    pub creation_date: String,
}

/// Public-access request — recipient-side. No auth header.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PublicAccessRequest {
    /// Plaintext access password if the Send is gated. Compared
    /// against the stored Argon2id-PHC.
    #[serde(default)]
    pub password: Option<String>,
}

/// Public-access response — what an anonymous recipient sees.
#[derive(Debug, Serialize, ToSchema)]
pub struct PublicAccessResponse {
    pub id: String,
    pub send_type: i32,
    /// EncString of the payload. Recipient derives content_key via
    /// HKDF over the send_key from the URL fragment + `id` salt and
    /// decrypts client-side. For text Sends this carries the message;
    /// for file Sends this carries `{filename, size_pt, file_aead_key_b64}`
    /// JSON encrypted under content_key.
    pub data: String,
    pub access_count: i64,
    pub max_access_count: Option<i64>,
    pub expiration_date: Option<String>,
    /// (file Sends only) — short-lived anonymous bearer for
    /// `GET /api/v1/public/sends/{id}/blob/{token}`. 5-minute TTL,
    /// good for retries within that window. Null for text Sends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_token: Option<String>,
    /// (file Sends only) — server-known ciphertext size. Lets the
    /// recipient pre-allocate / show progress. Null for text Sends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_ct: Option<i64>,
}

// =====================================================================
// Authenticated owner CRUD
// =====================================================================

fn validate_input(s: &SendInput) -> Result<(), ApiError> {
    // 1 = text (M2.25), 2 = file (M2.25a). Body content for type=2
    // arrives via the tus upload flow (`POST /api/v1/sends/{id}/upload`)
    // after the row is created.
    if s.send_type != 1 && s.send_type != 2 {
        return Err(ApiError::bad_request(
            "send_type must be 1 (text) or 2 (file)",
        ));
    }
    Uuid::parse_str(&s.id).map_err(|_| ApiError::bad_request("id must be a UUID"))?;
    EncString::parse(&s.name).map_err(|e| ApiError::bad_request(format!("name: {e}")))?;
    if let Some(n) = &s.notes {
        EncString::parse(n).map_err(|e| ApiError::bad_request(format!("notes: {e}")))?;
    }
    EncString::parse(&s.protected_send_key)
        .map_err(|e| ApiError::bad_request(format!("protected_send_key: {e}")))?;
    EncString::parse(&s.data).map_err(|e| ApiError::bad_request(format!("data: {e}")))?;
    parse_rfc3339(&s.deletion_date, "deletion_date")?;
    if let Some(exp) = &s.expiration_date {
        parse_rfc3339(exp, "expiration_date")?;
    }
    if let Some(m) = s.max_access_count {
        if m < 1 {
            return Err(ApiError::bad_request("max_access_count must be >= 1"));
        }
    }
    Ok(())
}

fn parse_rfc3339(s: &str, field: &str) -> Result<DateTime<Utc>, ApiError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| ApiError::bad_request(format!("{field} must be RFC3339")))
}

async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(input): Json<SendInput>,
) -> Result<(StatusCode, Json<SendView>), ApiError> {
    user.require(scope::VAULT_WRITE)?;
    validate_input(&input)?;

    // Argon2id-hash the access password if present. The PHC string
    // captures algorithm, params, and salt — verifies are deterministic
    // against the same input bytes.
    let password_phc = match &input.password {
        Some(p) if !p.is_empty() => Some(
            pw::hash(p.as_bytes()).map_err(|e| ApiError::internal(format!("argon2 hash: {e}")))?,
        ),
        _ => None,
    };

    let now = Utc::now().to_rfc3339();
    let res = sqlx::query(
        "INSERT INTO sends (
            id, user_id, send_type, name, notes, protected_send_key, data,
            password_phc, max_access_count, access_count,
            expiration_date, deletion_date, disabled,
            revision_date, creation_date
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,0,$10,$11,$12,$13,$14)",
    )
    .bind(&input.id)
    .bind(&user.user_id)
    .bind(input.send_type)
    .bind(&input.name)
    .bind(&input.notes)
    .bind(&input.protected_send_key)
    .bind(&input.data)
    .bind(&password_phc)
    .bind(input.max_access_count)
    .bind(&input.expiration_date)
    .bind(&input.deletion_date)
    .bind(if input.disabled { 1i32 } else { 0 })
    .bind(&now)
    .bind(&now)
    .execute(state.db.pool())
    .await;
    match res {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(ApiError::conflict("send id already exists"));
        }
        Err(e) => return Err(ApiError::internal(e.to_string())),
    }

    let view = load_owned(&state, &user.user_id, &input.id)
        .await?
        .expect("just inserted");
    state.push.publish(PushEvent {
        user_id: user.user_id.clone(),
        kind: PushKind::SendChanged,
        id: view.id.clone(),
        revision: view.revision_date.clone(),
    });
    Ok((StatusCode::CREATED, Json(view)))
}

async fn list(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<Vec<SendView>>, ApiError> {
    user.require(scope::VAULT_READ)?;
    let rows: Vec<SendRow> = sqlx::query_as(
        "SELECT id, user_id, send_type, name, notes, protected_send_key, data,
                password_phc, max_access_count, access_count,
                expiration_date, deletion_date, disabled,
                revision_date, creation_date
         FROM sends
         WHERE user_id = $1
         ORDER BY revision_date DESC",
    )
    .bind(&user.user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(rows.into_iter().map(SendRow::into_view).collect()))
}

async fn read_one(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SendView>, ApiError> {
    user.require(scope::VAULT_READ)?;
    let view = load_owned(&state, &user.user_id, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("send not found"))?;
    Ok(Json(view))
}

async fn update(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<SendInput>,
) -> Result<Response, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    let if_match = headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_matches('"').to_string());
    let Some(expected_revision) = if_match else {
        return Err(ApiError::PreconditionRequired(
            "If-Match header required".into(),
        ));
    };
    if input.id != id {
        return Err(ApiError::bad_request("body id must match path id"));
    }
    validate_input(&input)?;

    let current = load_owned(&state, &user.user_id, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("send not found"))?;
    if current.revision_date != expected_revision {
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({"error": "revision conflict", "current": current})),
        )
            .into_response());
    }

    // If the caller supplied a non-empty password, re-hash it. If they
    // explicitly passed an empty string, clear the gate. If they passed
    // `None`, preserve whatever the row already had.
    let password_phc = match input.password.as_deref() {
        None => {
            sqlx::query_as::<_, (Option<String>,)>("SELECT password_phc FROM sends WHERE id = $1")
                .bind(&id)
                .fetch_one(state.db.pool())
                .await
                .map(|(p,)| p)
                .map_err(|e| ApiError::internal(e.to_string()))?
        }
        Some("") => None,
        Some(p) => Some(
            pw::hash(p.as_bytes()).map_err(|e| ApiError::internal(format!("argon2 hash: {e}")))?,
        ),
    };

    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE sends SET
            send_type=$1, name=$2, notes=$3, protected_send_key=$4, data=$5,
            password_phc=$6, max_access_count=$7,
            expiration_date=$8, deletion_date=$9, disabled=$10,
            revision_date=$11
         WHERE id=$12 AND user_id=$13 AND revision_date=$14",
    )
    .bind(input.send_type)
    .bind(&input.name)
    .bind(&input.notes)
    .bind(&input.protected_send_key)
    .bind(&input.data)
    .bind(&password_phc)
    .bind(input.max_access_count)
    .bind(&input.expiration_date)
    .bind(&input.deletion_date)
    .bind(if input.disabled { 1i32 } else { 0 })
    .bind(&now)
    .bind(&id)
    .bind(&user.user_id)
    .bind(&current.revision_date)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let view = load_owned(&state, &user.user_id, &id)
        .await?
        .expect("just updated");
    state.push.publish(PushEvent {
        user_id: user.user_id.clone(),
        kind: PushKind::SendChanged,
        id: view.id.clone(),
        revision: view.revision_date.clone(),
    });
    Ok((StatusCode::OK, Json(view)).into_response())
}

async fn delete_one(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let res = sqlx::query("DELETE FROM sends WHERE id=$1 AND user_id=$2")
        .bind(&id)
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("send not found"));
    }
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO tombstones (kind, id, user_id, deleted_at)
         VALUES ('send', $1, $2, $3)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(&now)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    state.push.publish(PushEvent {
        user_id: user.user_id.clone(),
        kind: PushKind::SendTombstoned,
        id,
        revision: now,
    });
    Ok(StatusCode::NO_CONTENT)
}

async fn disable(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SendView>, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    set_disabled(&state, &user.user_id, &id, true).await
}

async fn enable(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SendView>, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    set_disabled(&state, &user.user_id, &id, false).await
}

async fn set_disabled(
    state: &AppState,
    user_id: &str,
    id: &str,
    disabled: bool,
) -> Result<Json<SendView>, ApiError> {
    let now = Utc::now().to_rfc3339();
    let res = sqlx::query(
        "UPDATE sends SET disabled = $1, revision_date = $2
         WHERE id = $3 AND user_id = $4",
    )
    .bind(if disabled { 1i32 } else { 0 })
    .bind(&now)
    .bind(id)
    .bind(user_id)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("send not found"));
    }
    let view = load_owned(state, user_id, id).await?.expect("just updated");
    state.push.publish(PushEvent {
        user_id: user_id.to_string(),
        kind: PushKind::SendChanged,
        id: view.id.clone(),
        revision: view.revision_date.clone(),
    });
    Ok(Json(view))
}

// =====================================================================
// Public anonymous access
// =====================================================================

/// `POST /api/v1/public/sends/{id}/access`. No auth required.
///
/// Order of checks (each returns 404/410/401 with a generic body so the
/// gate's presence isn't trivially distinguishable from "send doesn't
/// exist"):
///
/// 1. Row exists. (404)
/// 2. Not disabled. (410)
/// 3. Not past `deletion_date`. (410)
/// 4. Not past `expiration_date`. (410)
/// 5. Password matches (constant-time Argon2id verify). (401)
/// 6. `access_count < max_access_count` (or unlimited). Atomic bump. (410)
async fn public_access(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<PublicAccessRequest>,
) -> Result<Json<PublicAccessResponse>, ApiError> {
    // 1. Row.
    let row: Option<PublicRow> = sqlx::query_as(
        "SELECT id, send_type, data, password_phc,
                max_access_count, access_count,
                expiration_date, deletion_date, disabled,
                body_status, size_ct
         FROM sends WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some(r) = row else {
        return Err(ApiError::not_found("send not found"));
    };

    // 2. Disabled.
    if r.disabled != 0 {
        return Err(gone("send is disabled"));
    }
    // 3. Past deletion_date — the GC worker will drop it shortly, but
    //    a recipient hitting the row before the next tick gets the
    //    same gate now.
    if let Ok(dt) = DateTime::parse_from_rfc3339(&r.deletion_date) {
        if dt.with_timezone(&Utc) <= Utc::now() {
            return Err(gone("send has expired"));
        }
    }
    // 4. Past explicit expiration_date.
    if let Some(exp) = &r.expiration_date {
        if let Ok(dt) = DateTime::parse_from_rfc3339(exp) {
            if dt.with_timezone(&Utc) <= Utc::now() {
                return Err(gone("send has expired"));
            }
        }
    }
    // 5. File Send: body must already be uploaded. Without this the
    //    /access call would mint a download_token for a missing blob.
    if r.send_type == 2 && r.body_status != 1 {
        return Err(gone("send body has not been uploaded yet"));
    }
    // 6. Password gate.
    if let Some(phc) = &r.password_phc {
        let supplied = req.password.as_deref().unwrap_or("");
        if !pw::verify(supplied.as_bytes(), phc) {
            return Err(ApiError::Unauthorized("invalid password".into()));
        }
    }
    // 7. Atomic access-count bump. The WHERE clause both enforces
    //    "still under max" and prevents a TOCTOU race with concurrent
    //    accesses — second writer's UPDATE affects 0 rows.
    let res = sqlx::query(
        "UPDATE sends
         SET access_count = access_count + 1
         WHERE id = $1
           AND (max_access_count IS NULL OR access_count < max_access_count)",
    )
    .bind(&id)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    if res.rows_affected() == 0 {
        return Err(gone("send has reached its access limit"));
    }
    // Re-read the updated counter so the response is accurate.
    let bumped: (i64,) = sqlx::query_as("SELECT access_count FROM sends WHERE id = $1")
        .bind(&id)
        .fetch_one(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // 8. File Sends: mint a 5-minute download token bound to this
    //    send_id. Multiple GETs within TTL are fine (network retry).
    let (download_token, size_ct) = if r.send_type == 2 {
        let mut tok_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut tok_bytes);
        let token = URL_SAFE_NO_PAD.encode(tok_bytes);
        let expires_at = (Utc::now() + Duration::minutes(5)).to_rfc3339();
        sqlx::query(
            "INSERT INTO send_download_tokens (token, send_id, expires_at)
             VALUES ($1, $2, $3)",
        )
        .bind(&token)
        .bind(&id)
        .bind(&expires_at)
        .execute(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
        (Some(token), r.size_ct)
    } else {
        (None, None)
    };

    Ok(Json(PublicAccessResponse {
        id: r.id,
        send_type: r.send_type,
        data: r.data,
        access_count: bumped.0,
        max_access_count: r.max_access_count,
        expiration_date: r.expiration_date,
        download_token,
        size_ct,
    }))
}

// =====================================================================
// File Send: tus upload (sender-authenticated) + anonymous download
// =====================================================================

/// `POST /api/v1/sends/{id}/upload` — start a tus upload for a
/// file Send body. Sender must own the row, send_type must be 2, and
/// no finalized blob may already exist. Returns `Location` +
/// `Upload-Offset: 0`. Body MAY carry the first chunk via
/// `creation-with-upload`.
async fn send_upload_create(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
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
            "send body exceeds per-file limit ({} bytes)",
            state.config.max_attachment_bytes
        )));
    }

    let raw_meta = headers
        .get("upload-metadata")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::bad_request("Upload-Metadata header required"))?;
    let meta = parse_upload_metadata(raw_meta)?;
    let content_hash_b3 = require_meta(&meta, "content_hash_b3")?.to_string();
    let size_pt: i64 = require_meta(&meta, "size_pt")?.parse().map_err(|_| {
        ApiError::bad_request("Upload-Metadata size_pt must be a non-negative integer")
    })?;
    if size_pt < 0 {
        return Err(ApiError::bad_request("size_pt must be >= 0"));
    }
    let expected_ct = ciphertext_size_for(size_pt as u64);
    if expected_ct != upload_length {
        return Err(ApiError::bad_request(format!(
            "Upload-Length {upload_length} does not match ciphertext_size_for(size_pt={size_pt})={expected_ct}"
        )));
    }

    // Row must exist, be owned, be type=2, and not yet have a body.
    let row: Option<(i32, i32)> =
        sqlx::query_as("SELECT send_type, body_status FROM sends WHERE id = $1 AND user_id = $2")
            .bind(&id)
            .bind(&user.user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let (send_type, body_status) = row.ok_or_else(|| ApiError::not_found("send not found"))?;
    if send_type != 2 {
        return Err(ApiError::bad_request(
            "send_type must be 2 (file) to accept a body upload",
        ));
    }
    if body_status == 1 {
        return Err(ApiError::conflict(
            "send already has a finalized body — create a new send for a different file",
        ));
    }

    // Allocate state.
    let now = Utc::now().to_rfc3339();
    let expires_at = (Utc::now() + Duration::hours(24)).to_rfc3339();
    let storage_key = format!("sends/{}/{}", user.user_id, id);
    let mut token_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut token_bytes);
    let upload_token = URL_SAFE_NO_PAD.encode(token_bytes);

    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // Stash the storage_key + size_ct + content_hash on the parent row.
    // body_status stays 0 until finalize.
    sqlx::query(
        "UPDATE sends
         SET storage_key = $1, size_ct = $2, content_hash_b3 = $3,
             revision_date = $4
         WHERE id = $5 AND user_id = $6",
    )
    .bind(&storage_key)
    .bind(upload_length as i64)
    .bind(&content_hash_b3)
    .bind(&now)
    .bind(&id)
    .bind(&user.user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    sqlx::query(
        "INSERT INTO send_uploads
            (id, upload_token, bytes_received, expected_size, expires_at, upload_metadata)
         VALUES ($1,$2,0,$3,$4,$5)",
    )
    .bind(&id)
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

    // creation-with-upload: ship the first transport chunk inline.
    let mut bytes_received: u64 = 0;
    if !body.is_empty() {
        send_write_chunk(&state, &user.user_id, &upload_token, 0, &body).await?;
        bytes_received = body.len() as u64;
    }
    if bytes_received == upload_length {
        send_finalize_upload(&state, &user.user_id, &upload_token).await?;
    }

    let location = format!("/api/v1/tus-send/{}", upload_token);
    let mut h = HeaderMap::new();
    h.insert("Tus-Resumable", HeaderValue::from_static("1.0.0"));
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

async fn send_upload_head(
    user: AuthUser,
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Response, ApiError> {
    user.require(scope::VAULT_READ)?;
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT u.bytes_received, u.expected_size
         FROM send_uploads u
         JOIN sends s ON s.id = u.id
         WHERE u.upload_token = $1 AND s.user_id = $2",
    )
    .bind(&token)
    .bind(&user.user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let (br, es) = row.ok_or_else(|| ApiError::not_found("upload not found"))?;
    let mut h = HeaderMap::new();
    h.insert("Tus-Resumable", HeaderValue::from_static("1.0.0"));
    h.insert(
        "Upload-Offset",
        HeaderValue::from_str(&br.to_string()).expect("i64 fits"),
    );
    h.insert(
        "Upload-Length",
        HeaderValue::from_str(&es.to_string()).expect("i64 fits"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((StatusCode::OK, h).into_response())
}

async fn send_upload_patch(
    user: AuthUser,
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT u.bytes_received, u.expected_size
         FROM send_uploads u
         JOIN sends s ON s.id = u.id
         WHERE u.upload_token = $1 AND s.user_id = $2",
    )
    .bind(&token)
    .bind(&user.user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let (current_offset, expected_size) =
        row.ok_or_else(|| ApiError::not_found("upload not found"))?;
    let claimed_offset = headers
        .get("upload-offset")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| ApiError::bad_request("Upload-Offset header required"))?;
    if claimed_offset != current_offset as u64 {
        return Err(ApiError::conflict(format!(
            "Upload-Offset {claimed_offset} does not match server's {current_offset}"
        )));
    }
    let new_total = current_offset as u64 + body.len() as u64;
    if new_total > expected_size as u64 {
        return Err(ApiError::bad_request(format!(
            "PATCH would write {new_total} bytes; expected_size is {expected_size}"
        )));
    }

    send_write_chunk(&state, &user.user_id, &token, current_offset as u64, &body).await?;

    let mut h = HeaderMap::new();
    h.insert("Tus-Resumable", HeaderValue::from_static("1.0.0"));
    h.insert(
        "Upload-Offset",
        HeaderValue::from_str(&new_total.to_string()).expect("u64 fits"),
    );
    if new_total == expected_size as u64 {
        send_finalize_upload(&state, &user.user_id, &token).await?;
    }
    Ok((StatusCode::NO_CONTENT, h).into_response())
}

async fn send_upload_terminate(
    user: AuthUser,
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Response, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT s.id, s.storage_key
         FROM send_uploads u
         JOIN sends s ON s.id = u.id
         WHERE u.upload_token = $1 AND s.user_id = $2",
    )
    .bind(&token)
    .bind(&user.user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some((send_id, storage_key)) = row else {
        return Err(ApiError::not_found("upload not found"));
    };
    if let Some(sk) = &storage_key {
        let _ = state.blob.delete(sk).await;
    }
    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    sqlx::query("DELETE FROM send_uploads WHERE upload_token = $1")
        .bind(&token)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    // Clear the half-uploaded body fields on the parent row so a
    // subsequent /upload can start fresh.
    sqlx::query(
        "UPDATE sends SET storage_key = NULL, size_ct = NULL, content_hash_b3 = NULL,
                          body_status = 0
         WHERE id = $1",
    )
    .bind(&send_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let mut h = HeaderMap::new();
    h.insert("Tus-Resumable", HeaderValue::from_static("1.0.0"));
    Ok((StatusCode::NO_CONTENT, h).into_response())
}

async fn send_write_chunk(
    state: &AppState,
    user_id: &str,
    token: &str,
    expected_offset: u64,
    bytes: &[u8],
) -> Result<(), ApiError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let row: Option<(String, i64)> = sqlx::query_as(
        "SELECT s.storage_key, u.bytes_received
         FROM send_uploads u
         JOIN sends s ON s.id = u.id
         WHERE u.upload_token = $1 AND s.user_id = $2",
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
        "UPDATE send_uploads
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

async fn send_finalize_upload(
    state: &AppState,
    user_id: &str,
    token: &str,
) -> Result<(), ApiError> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT s.id, s.storage_key, s.content_hash_b3
         FROM send_uploads u
         JOIN sends s ON s.id = u.id
         WHERE u.upload_token = $1 AND s.user_id = $2",
    )
    .bind(token)
    .bind(user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let (send_id, storage_key, expected_hash) =
        row.ok_or_else(|| ApiError::not_found("upload not found"))?;

    let bytes = state
        .blob
        .read_full(&storage_key)
        .await
        .map_err(|e| ApiError::internal(format!("blob read on finalize: {e}")))?;
    let actual_hash = content_hash_b3(&bytes);
    if actual_hash != expected_hash {
        // Tear down: delete blob, drop upload row, reset parent.
        let _ = state.blob.delete(&storage_key).await;
        sqlx::query("DELETE FROM send_uploads WHERE upload_token = $1")
            .bind(token)
            .execute(state.db.pool())
            .await
            .ok();
        sqlx::query(
            "UPDATE sends SET storage_key = NULL, size_ct = NULL, content_hash_b3 = NULL,
                              body_status = 0
             WHERE id = $1",
        )
        .bind(&send_id)
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
    sqlx::query("UPDATE sends SET body_status = 1, revision_date = $1 WHERE id = $2")
        .bind(&now)
        .bind(&send_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    sqlx::query("DELETE FROM send_uploads WHERE upload_token = $1")
        .bind(token)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    state.push.publish(PushEvent {
        user_id: user_id.into(),
        kind: PushKind::SendChanged,
        id: send_id,
        revision: now,
    });
    Ok(())
}

/// `GET /api/v1/public/sends/{id}/blob/{token}` — anonymous download.
/// Token comes from `/access`; valid for 5 minutes from issue.
async fn public_blob_download(
    State(state): State<AppState>,
    Path((id, token)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT t.expires_at, s.storage_key
         FROM send_download_tokens t
         JOIN sends s ON s.id = t.send_id
         WHERE t.token = $1 AND t.send_id = $2 AND s.body_status = 1",
    )
    .bind(&token)
    .bind(&id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some((expires_at, storage_key)) = row else {
        return Err(ApiError::not_found("download token invalid"));
    };
    if let Ok(dt) = DateTime::parse_from_rfc3339(&expires_at) {
        if dt.with_timezone(&Utc) <= Utc::now() {
            return Err(gone("download token has expired — request a new /access"));
        }
    }
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

// =====================================================================
// tus Upload-Metadata parser (shared shape with attachments.rs)
// =====================================================================

fn parse_upload_metadata(raw: &str) -> Result<std::collections::HashMap<String, String>, ApiError> {
    use base64::{
        engine::general_purpose::{STANDARD, STANDARD_NO_PAD as NOPAD},
        Engine,
    };
    let mut out = std::collections::HashMap::new();
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

fn require_meta<'a>(
    meta: &'a std::collections::HashMap<String, String>,
    key: &str,
) -> Result<&'a str, ApiError> {
    meta.get(key).map(|s| s.as_str()).ok_or_else(|| {
        ApiError::bad_request(format!("Upload-Metadata missing required key '{key}'"))
    })
}

fn gone(msg: impl Into<String>) -> ApiError {
    // 410 Gone is the right status when "this used to exist but the
    // server is deliberately refusing to serve it now". We map it to
    // ApiError::Conflict (= 409) — close enough for M2.25; M2.x can
    // promote to a real 410 variant on ApiError.
    ApiError::Conflict(msg.into())
}

// =====================================================================
// Helpers
// =====================================================================

async fn load_owned(
    state: &AppState,
    user_id: &str,
    id: &str,
) -> Result<Option<SendView>, ApiError> {
    let row: Option<SendRow> = sqlx::query_as(
        "SELECT id, user_id, send_type, name, notes, protected_send_key, data,
                password_phc, max_access_count, access_count,
                expiration_date, deletion_date, disabled,
                revision_date, creation_date
         FROM sends
         WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(row.map(SendRow::into_view))
}

#[derive(sqlx::FromRow)]
pub(crate) struct SendRow {
    pub id: String,
    #[allow(dead_code)]
    pub user_id: String,
    pub send_type: i32,
    pub name: String,
    pub notes: Option<String>,
    pub protected_send_key: String,
    pub data: String,
    pub password_phc: Option<String>,
    pub max_access_count: Option<i64>,
    pub access_count: i64,
    pub expiration_date: Option<String>,
    pub deletion_date: String,
    pub disabled: i32,
    pub revision_date: String,
    pub creation_date: String,
}

impl SendRow {
    pub(crate) fn into_view(self) -> SendView {
        SendView {
            id: self.id,
            send_type: self.send_type,
            name: self.name,
            notes: self.notes,
            protected_send_key: self.protected_send_key,
            data: self.data,
            has_password: self.password_phc.is_some(),
            max_access_count: self.max_access_count,
            access_count: self.access_count,
            expiration_date: self.expiration_date,
            deletion_date: self.deletion_date,
            disabled: self.disabled != 0,
            revision_date: self.revision_date,
            creation_date: self.creation_date,
        }
    }
}

#[derive(sqlx::FromRow)]
struct PublicRow {
    id: String,
    send_type: i32,
    data: String,
    password_phc: Option<String>,
    max_access_count: Option<i64>,
    #[allow(dead_code)]
    access_count: i64,
    expiration_date: Option<String>,
    deletion_date: String,
    disabled: i32,
    body_status: i32,
    size_ct: Option<i64>,
}
