//! Public key directory — `GET /api/v1/users/{id}/pubkeys`.
//!
//! Returns the self-signed pubkey bundle a user uploaded at register
//! time. Consumers verify the signature with
//! `hekate-core::signcrypt::verify_pubkey_bundle` before using either
//! pubkey for sharing wraps or signcryption envelopes.
//!
//! No authentication is required — public keys are, by definition,
//! public. We do return 404 when the user has no bundle (legacy
//! pre-M2.19 row), so a malicious server can't silently degrade a
//! consumer to "I guess they don't have one yet" and persuade it to
//! skip the bundle verification step.
//!
//! BW09 / LP07 / DL02: this endpoint plus the M2.18 signcryption
//! primitive give us the *cryptographic* substitution defense. The
//! remaining piece — TOFU pinning / org CA / verified-directory
//! authentication of the bundle itself — sits on top of this.

use axum::{
    extract::{Path, Query, State},
    response::Json,
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::{
    auth::{scope, AuthUser},
    routes::accounts::ApiError,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/users/{user_id}/pubkeys", get(get_pubkeys))
        .route("/api/v1/users/lookup", get(lookup_by_email))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PubkeyBundle {
    pub user_id: String,
    /// 32 bytes, base64-no-pad.
    pub account_signing_pubkey: String,
    /// 32 bytes, base64-no-pad.
    pub account_public_key: String,
    /// 64 bytes, base64-no-pad. Ed25519 sig over canonical
    /// `(user_id || signing_pk || x25519_pk)` per
    /// `hekate-core::signcrypt::pubkey_bundle_canonical_bytes`.
    pub account_pubkey_bundle_sig: String,
}

/// Fetch the self-signed pubkey bundle for a user.
#[utoipa::path(
    get,
    path = "/api/v1/users/{user_id}/pubkeys",
    tag = "accounts",
    params(("user_id" = String, Path, description = "Target user UUID")),
    responses(
        (status = 200, description = "OK", body = PubkeyBundle),
        (status = 404, description = "User not found, or has not yet uploaded a self-signed bundle"),
    ),
)]
pub async fn get_pubkeys(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<PubkeyBundle>, ApiError> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT account_signing_pubkey_b64, account_public_key,
                account_pubkey_bundle_sig_b64
           FROM users
          WHERE id = $1",
    )
    .bind(&user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let (signing_pk, x25519_pk, sig) = match row {
        Some(r) => r,
        None => return Err(ApiError::not_found("user")),
    };
    if signing_pk.is_empty() || x25519_pk.is_empty() || sig.is_empty() {
        // Defensive: every register flow populates these. Refuse to
        // serve an unverifiable bundle if a row is somehow incomplete.
        return Err(ApiError::not_found(
            "user has no self-signed pubkey bundle; re-register",
        ));
    }
    Ok(Json(PubkeyBundle {
        user_id,
        account_signing_pubkey: signing_pk,
        account_public_key: x25519_pk,
        account_pubkey_bundle_sig: sig,
    }))
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct EmailLookupQuery {
    /// Email address to resolve to a `PubkeyBundle`.
    pub email: String,
}

/// Resolve an email address to a user's `PubkeyBundle`. Useful for
/// invite flows where the inviter knows the peer's email but not
/// their UUID. Authentication required so anonymous callers can't
/// turn this into an enumeration oracle (the unauthenticated
/// `/users/{id}/pubkeys` is keyed by random-looking UUID, which
/// isn't enumeration-friendly; email is). 404 for unknown emails
/// matches the user-id route's behavior.
///
/// Email is case-insensitive on lookup — the column stores it
/// lowercased at registration time.
#[utoipa::path(
    get,
    path = "/api/v1/users/lookup",
    tag = "accounts",
    params(EmailLookupQuery),
    responses(
        (status = 200, description = "OK", body = PubkeyBundle),
        (status = 401, description = "Unauthenticated"),
        (status = 404, description = "No user with that email"),
    ),
    security(("bearerAuth" = [])),
)]
pub async fn lookup_by_email(
    user: AuthUser,
    State(state): State<AppState>,
    Query(q): Query<EmailLookupQuery>,
) -> Result<Json<PubkeyBundle>, ApiError> {
    user.require(scope::VAULT_READ)?;

    let email = q.email.trim().to_lowercase();
    if email.is_empty() {
        return Err(ApiError::bad_request("email is required"));
    }
    let row: Option<(String, String, String, String)> = sqlx::query_as(
        "SELECT id, account_signing_pubkey_b64, account_public_key,
                account_pubkey_bundle_sig_b64
           FROM users
          WHERE LOWER(email) = $1",
    )
    .bind(&email)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let (user_id, signing_pk, x25519_pk, sig) = match row {
        Some(r) => r,
        None => return Err(ApiError::not_found("no user with that email")),
    };
    if signing_pk.is_empty() || x25519_pk.is_empty() || sig.is_empty() {
        return Err(ApiError::not_found(
            "user has no self-signed pubkey bundle (pre-M2.19 row); re-register",
        ));
    }
    Ok(Json(PubkeyBundle {
        user_id,
        account_signing_pubkey: signing_pk,
        account_public_key: x25519_pk,
        account_pubkey_bundle_sig: sig,
    }))
}
