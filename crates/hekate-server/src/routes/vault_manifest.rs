//! Per-user signed vault manifest — BW04 set-level integrity.
//!
//! The client uploads a signed list of `(cipher_id, revision_date,
//! deleted)` for every cipher it owns; the server stores it; other
//! clients verify on sync. See `hekate-core::manifest`.
//!
//! The server itself verifies the signature on upload — a benign
//! double-check that catches client bugs early. The authoritative
//! verification happens client-side under each device's own copy of
//! the user's signing pubkey, since a malicious server could otherwise
//! upload its own manifest under its own pubkey and serve that.

use axum::{extract::State, response::Json, routing::post, Router};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hekate_core::manifest::{decode_canonical, hash_canonical, NO_PARENT_HASH};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    auth::{scope, AuthUser},
    routes::accounts::ApiError,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new().route("/api/v1/vault/manifest", post(upload).get(get_manifest))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ManifestUpload {
    /// Monotonic counter; server enforces strictly-greater than the stored
    /// version so an old manifest can't be replayed.
    pub version: i64,
    /// Length-prefixed canonical bytes (see `hekate-core::manifest`), base64-no-pad.
    pub canonical_b64: String,
    /// 64-byte Ed25519 signature, base64-no-pad.
    pub signature_b64: String,
}

#[derive(Debug, Serialize, ToSchema, Clone)]
pub struct ManifestView {
    pub version: i64,
    pub canonical_b64: String,
    pub signature_b64: String,
    pub updated_at: String,
}

/// Upload the latest signed vault manifest. Requires `vault:write`.
#[utoipa::path(
    post,
    path = "/api/v1/vault/manifest",
    tag = "vault",
    request_body = ManifestUpload,
    responses(
        (status = 200, description = "Stored", body = ManifestView),
        (status = 400, description = "Validation failed", body = crate::routes::accounts::ErrorResponse),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Insufficient scope"),
        (status = 409, description = "Stale version", body = crate::routes::accounts::ErrorResponse),
    ),
    security(("bearerAuth" = [])),
)]
pub async fn upload(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<ManifestUpload>,
) -> Result<Json<ManifestView>, ApiError> {
    user.require(scope::VAULT_WRITE)?;

    if req.version < 1 {
        return Err(ApiError::bad_request("version must be >= 1"));
    }

    let canonical = STANDARD_NO_PAD
        .decode(&req.canonical_b64)
        .map_err(|_| ApiError::bad_request("canonical_b64 not base64-no-pad"))?;
    let sig_bytes = STANDARD_NO_PAD
        .decode(&req.signature_b64)
        .map_err(|_| ApiError::bad_request("signature_b64 not base64-no-pad"))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| ApiError::bad_request("signature has wrong length"))?;

    let pubkey = load_user_pubkey(&state, &user.user_id).await?;
    pubkey
        .verify(&canonical, &signature)
        .map_err(|_| ApiError::bad_request("manifest signature invalid"))?;

    // Defense against the wrapper-version disagreeing with the signed-canonical-version:
    // the wrapper is what we monotonicity-check; the canonical is what's actually signed.
    // They MUST agree, otherwise an attacker could submit `{version: 999, canonical: <v=1>}`
    // and bypass replay defenses while keeping a valid signature.
    let parsed = decode_canonical(&canonical)
        .map_err(|e| ApiError::bad_request(format!("canonical bytes parse: {e}")))?;
    if parsed.version != req.version as u64 {
        return Err(ApiError::bad_request(
            "wrapper version does not match canonical version",
        ));
    }

    // Monotonicity + hash chain. Both checks come from the same row read.
    let current: Option<(i64, String)> =
        sqlx::query_as("SELECT version, canonical_b64 FROM vault_manifests WHERE user_id = $1")
            .bind(&user.user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    match &current {
        Some((cur_version, cur_canonical_b64)) => {
            if req.version <= *cur_version {
                return Err(ApiError::conflict(format!(
                    "manifest version {} not greater than current {cur_version}",
                    req.version,
                )));
            }
            // Hash chain: the uploaded manifest must commit to the
            // currently-stored canonical bytes. Otherwise an attacker
            // (or a buggy client) could fork the chain at an earlier
            // version and silently roll the user back.
            let cur_canonical = STANDARD_NO_PAD
                .decode(cur_canonical_b64)
                .map_err(|_| ApiError::internal("malformed stored canonical_b64"))?;
            let expected_parent = hash_canonical(&cur_canonical);
            if parsed.parent_canonical_sha256 != expected_parent {
                return Err(ApiError::conflict(
                    "manifest parent_canonical_sha256 does not match stored manifest \
                     — chain broken; pull /sync, rebuild from the server's current \
                     manifest, and retry",
                ));
            }
        }
        None => {
            // Genesis upload: parent must be all-zeros so a malicious
            // client can't sneak in a forked chain on a fresh row.
            if parsed.parent_canonical_sha256 != NO_PARENT_HASH {
                return Err(ApiError::bad_request(
                    "first manifest upload must use parent_canonical_sha256 = zeros",
                ));
            }
        }
    }

    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO vault_manifests
            (user_id, version, canonical_b64, signature_b64, updated_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (user_id) DO UPDATE SET
            version = excluded.version,
            canonical_b64 = excluded.canonical_b64,
            signature_b64 = excluded.signature_b64,
            updated_at = excluded.updated_at",
    )
    .bind(&user.user_id)
    .bind(req.version)
    .bind(&req.canonical_b64)
    .bind(&req.signature_b64)
    .bind(&now)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(ManifestView {
        version: req.version,
        canonical_b64: req.canonical_b64,
        signature_b64: req.signature_b64,
        updated_at: now,
    }))
}

/// Fetch the latest signed vault manifest. Requires `vault:read`.
/// Returns `null` if the user has never uploaded one.
#[utoipa::path(
    get,
    path = "/api/v1/vault/manifest",
    tag = "vault",
    responses(
        (status = 200, description = "OK", body = Option<ManifestView>),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Insufficient scope"),
    ),
    security(("bearerAuth" = [])),
)]
pub async fn get_manifest(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<Option<ManifestView>>, ApiError> {
    user.require(scope::VAULT_READ)?;
    Ok(Json(latest_manifest(&state, &user.user_id).await?))
}

/// Helper: load the latest stored manifest for a user. Used both by
/// the standalone GET endpoint and embedded in `/sync` responses.
pub async fn latest_manifest(
    state: &AppState,
    user_id: &str,
) -> Result<Option<ManifestView>, ApiError> {
    let row: Option<(i64, String, String, String)> = sqlx::query_as(
        "SELECT version, canonical_b64, signature_b64, updated_at
           FROM vault_manifests
          WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(row.map(
        |(version, canonical_b64, signature_b64, updated_at)| ManifestView {
            version,
            canonical_b64,
            signature_b64,
            updated_at,
        },
    ))
}

async fn load_user_pubkey(state: &AppState, user_id: &str) -> Result<VerifyingKey, ApiError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT account_signing_pubkey_b64 FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let pubkey_b64 = row
        .map(|(s,)| s)
        .ok_or_else(|| ApiError::internal("user row missing"))?;
    if pubkey_b64.is_empty() {
        return Err(ApiError::bad_request(
            "account has no signing pubkey — re-register on a fresh DB",
        ));
    }
    let pubkey_bytes = STANDARD_NO_PAD
        .decode(&pubkey_b64)
        .map_err(|_| ApiError::internal("malformed pubkey on user row"))?;
    if pubkey_bytes.len() != 32 {
        return Err(ApiError::internal("pubkey on user row has wrong length"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pubkey_bytes);
    VerifyingKey::from_bytes(&arr).map_err(|_| ApiError::internal("malformed pubkey on user row"))
}
