//! Per-org signed cipher manifest — M2.21 / M4.5 follow-up.
//!
//! Owner uploads a signed list of `(cipher_id, revision_date, deleted)`
//! for every org-owned cipher; the server stores the latest blob;
//! members verify on `/sync` under the TOFU-pinned org signing pubkey.
//!
//! Server-side validation:
//!   * caller is the org owner (single-signer M4 v1 model)
//!   * Ed25519 signature verifies under the org's stored signing pubkey
//!   * canonical bytes parse + wrapper version matches canonical version
//!   * canonical org_id matches path org_id
//!   * version is strictly greater than the stored version (or 1 for
//!     genesis), and `parent_canonical_sha256` chains forward
//!     (genesis = all-zeros)
//!
//! See `crates/hekate-core/src/org_cipher_manifest.rs` for the canonical-
//! bytes layout and `docs/threat-model-gaps.md` "Open: Org-cipher
//! set-level integrity" for the threat this closes.

use axum::{
    extract::{Path, State},
    response::Json,
    routing::post,
    Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hekate_core::org_cipher_manifest::{decode_canonical, hash_canonical, NO_PARENT_HASH};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    auth::{scope, AuthUser},
    routes::accounts::ApiError,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/api/v1/orgs/{org_id}/cipher-manifest",
        post(upload).get(get_manifest),
    )
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct OrgCipherManifestUpload {
    /// Monotonic counter; server enforces strictly-greater than the
    /// stored version so an old manifest can't be replayed.
    pub version: i64,
    /// Length-prefixed canonical bytes (see
    /// `hekate-core::org_cipher_manifest`), base64-no-pad.
    pub canonical_b64: String,
    /// 64-byte Ed25519 signature under the org's signing key,
    /// base64-no-pad.
    pub signature_b64: String,
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct OrgCipherManifestView {
    pub version: i64,
    pub canonical_b64: String,
    pub signature_b64: String,
    pub updated_at: String,
}

/// Owner-only. Upload the latest signed org cipher manifest.
#[utoipa::path(
    post,
    path = "/api/v1/orgs/{org_id}/cipher-manifest",
    tag = "orgs",
    params(("org_id" = String, Path)),
    request_body = OrgCipherManifestUpload,
    responses(
        (status = 200, description = "Stored", body = OrgCipherManifestView),
        (status = 400, description = "Validation failed", body = crate::routes::accounts::ErrorResponse),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Insufficient scope"),
        (status = 404, description = "Org not found / not owner"),
        (status = 409, description = "Stale version or chain broken", body = crate::routes::accounts::ErrorResponse),
    ),
    security(("bearerAuth" = [])),
)]
pub async fn upload(
    user: AuthUser,
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Json(req): Json<OrgCipherManifestUpload>,
) -> Result<Json<OrgCipherManifestView>, ApiError> {
    user.require(scope::VAULT_WRITE)?;

    if req.version < 1 {
        return Err(ApiError::bad_request("version must be >= 1"));
    }

    // Owner gate (404 cloak per the M4 convention).
    let pubkey = load_org_signing_pubkey_for_owner(&state, &org_id, &user.user_id).await?;

    let canonical = STANDARD_NO_PAD
        .decode(&req.canonical_b64)
        .map_err(|_| ApiError::bad_request("canonical_b64 not base64-no-pad"))?;
    let sig_bytes = STANDARD_NO_PAD
        .decode(&req.signature_b64)
        .map_err(|_| ApiError::bad_request("signature_b64 not base64-no-pad"))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| ApiError::bad_request("signature has wrong length"))?;
    pubkey
        .verify(&canonical, &signature)
        .map_err(|_| ApiError::bad_request("manifest signature did not verify"))?;

    // Wrapper-version-vs-canonical-version match. Same defense as the
    // per-user vault manifest: signing one version while wrapping
    // another would let a server replay an old canonical at a new
    // version number.
    let parsed = decode_canonical(&canonical)
        .map_err(|e| ApiError::bad_request(format!("canonical bytes parse: {e}")))?;
    if parsed.version != req.version as u64 {
        return Err(ApiError::bad_request(
            "wrapper version does not match canonical version",
        ));
    }
    if parsed.org_id != org_id {
        return Err(ApiError::bad_request(
            "canonical org_id does not match path org_id",
        ));
    }

    // Monotonic version + parent-hash chain.
    let current: Option<(i64, String)> =
        sqlx::query_as("SELECT version, canonical_b64 FROM org_cipher_manifests WHERE org_id = $1")
            .bind(&org_id)
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
            let cur_canonical = STANDARD_NO_PAD
                .decode(cur_canonical_b64)
                .map_err(|_| ApiError::internal("malformed stored canonical_b64"))?;
            let expected_parent = hash_canonical(&cur_canonical);
            if parsed.parent_canonical_sha256 != expected_parent {
                return Err(ApiError::conflict(
                    "manifest parent_canonical_sha256 does not match stored manifest \
                     — chain broken; refresh and retry",
                ));
            }
        }
        None => {
            if parsed.parent_canonical_sha256 != NO_PARENT_HASH {
                return Err(ApiError::bad_request(
                    "first manifest upload must use parent_canonical_sha256 = zeros",
                ));
            }
        }
    }

    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO org_cipher_manifests
            (org_id, version, canonical_b64, signature_b64, updated_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (org_id) DO UPDATE SET
            version = excluded.version,
            canonical_b64 = excluded.canonical_b64,
            signature_b64 = excluded.signature_b64,
            updated_at = excluded.updated_at",
    )
    .bind(&org_id)
    .bind(req.version)
    .bind(&req.canonical_b64)
    .bind(&req.signature_b64)
    .bind(&now)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(OrgCipherManifestView {
        version: req.version,
        canonical_b64: req.canonical_b64,
        signature_b64: req.signature_b64,
        updated_at: now,
    }))
}

/// Member-only. Fetch the latest signed org cipher manifest. Returns
/// `null` if no manifest has been uploaded yet.
#[utoipa::path(
    get,
    path = "/api/v1/orgs/{org_id}/cipher-manifest",
    tag = "orgs",
    params(("org_id" = String, Path)),
    responses(
        (status = 200, description = "OK", body = Option<OrgCipherManifestView>),
        (status = 401, description = "Unauthenticated"),
        (status = 404, description = "Org not found / not a member"),
    ),
    security(("bearerAuth" = [])),
)]
pub async fn get_manifest(
    user: AuthUser,
    State(state): State<AppState>,
    Path(org_id): Path<String>,
) -> Result<Json<Option<OrgCipherManifestView>>, ApiError> {
    user.require(scope::VAULT_READ)?;
    require_org_member(&state, &org_id, &user.user_id).await?;
    Ok(Json(latest_manifest(&state, &org_id).await?))
}

/// Helper: load the latest stored org cipher manifest for an org.
/// Used by the standalone GET endpoint and embedded in /sync responses.
pub async fn latest_manifest(
    state: &AppState,
    org_id: &str,
) -> Result<Option<OrgCipherManifestView>, ApiError> {
    let row: Option<(i64, String, String, String)> = sqlx::query_as(
        "SELECT version, canonical_b64, signature_b64, updated_at
           FROM org_cipher_manifests WHERE org_id = $1",
    )
    .bind(org_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(row.map(
        |(version, canonical_b64, signature_b64, updated_at)| OrgCipherManifestView {
            version,
            canonical_b64,
            signature_b64,
            updated_at,
        },
    ))
}

async fn load_org_signing_pubkey_for_owner(
    state: &AppState,
    org_id: &str,
    user_id: &str,
) -> Result<VerifyingKey, ApiError> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT owner_user_id, signing_pubkey_b64 FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let (owner, pubkey_b64) = row.ok_or_else(|| ApiError::not_found("org"))?;
    if owner != user_id {
        return Err(ApiError::not_found("org"));
    }
    let bytes = STANDARD_NO_PAD
        .decode(&pubkey_b64)
        .map_err(|_| ApiError::internal("malformed org signing pubkey"))?;
    if bytes.len() != 32 {
        return Err(ApiError::internal("org signing pubkey has wrong length"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(|_| ApiError::internal("malformed org signing pubkey"))
}

async fn require_org_member(state: &AppState, org_id: &str, user_id: &str) -> Result<(), ApiError> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT 1 FROM organization_members WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    if row.is_some() {
        Ok(())
    } else {
        Err(ApiError::not_found("org"))
    }
}
