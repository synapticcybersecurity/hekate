//! WebAuthn / FIDO2 second factor (M2.23a). Phishing-resistant
//! companion to the TOTP path from M2.22.
//!
//! Flow: two-leg ceremonies, mid-state stashed in
//! `two_factor_webauthn_pending` (keyed by `(user_id, ceremony)`) so
//! the server stays stateless across requests and across server
//! processes. Recovery codes from M2.22 also rescue WebAuthn-only
//! users — same `two_factor_recovery_codes` rows are honored at the
//! `provider="recovery"` path of the identity grant.
//!
//! Endpoints (all require an active access token, plus master-password
//! re-auth on register/start to match the TOTP enrollment shape):
//! - `POST /api/v1/account/2fa/webauthn/register/start`
//! - `POST /api/v1/account/2fa/webauthn/register/finish`
//! - `GET  /api/v1/account/2fa/webauthn/credentials`
//! - `DELETE /api/v1/account/2fa/webauthn/credentials/{id}`
//! - `PATCH  /api/v1/account/2fa/webauthn/credentials/{id}` (rename)

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, patch, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use webauthn_rs::prelude::{
    Passkey, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};
use webauthn_rs::Webauthn;

use crate::{
    auth::{password, AuthUser},
    routes::accounts::ApiError,
    AppState,
};

/// Mid-ceremony pending rows are dropped after this. Long enough for
/// the user to tap the security key; short enough that abandoned
/// ceremonies don't pile up.
pub(crate) const CEREMONY_TTL_SECS: i64 = 300;

const CEREMONY_REGISTER: &str = "register";
pub(crate) const CEREMONY_LOGIN: &str = "login";

const NAME_MAX: usize = 64;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/account/2fa/webauthn/register/start",
            post(register_start),
        )
        .route(
            "/api/v1/account/2fa/webauthn/register/finish",
            post(register_finish),
        )
        .route(
            "/api/v1/account/2fa/webauthn/credentials",
            get(list_credentials),
        )
        .route(
            "/api/v1/account/2fa/webauthn/credentials/{id}",
            delete(delete_credential),
        )
        .route(
            "/api/v1/account/2fa/webauthn/credentials/{id}",
            patch(rename_credential),
        )
}

// ---- shared helpers ------------------------------------------------------

async fn require_master_password(
    state: &AppState,
    user_id: &str,
    master_password_hash_b64: &str,
) -> Result<(), ApiError> {
    let mph = STANDARD_NO_PAD
        .decode(master_password_hash_b64)
        .map_err(|_| ApiError::bad_request("master_password_hash is not base64-no-pad"))?;
    if mph.len() != 32 {
        return Err(ApiError::bad_request(
            "master_password_hash must be 32 bytes",
        ));
    }
    let row: Option<(String,)> =
        sqlx::query_as("SELECT master_password_hash FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some((stored_phc,)) = row else {
        return Err(ApiError::unauthorized("user no longer exists"));
    };
    if !password::verify(&mph, &stored_phc) {
        return Err(ApiError::unauthorized("master password is wrong"));
    }
    Ok(())
}

/// Look up the caller's user_id from their email, since WebAuthn
/// requires a stable per-user handle. We use the UUIDv7 (already
/// stable, already in-DB) — passed to webauthn-rs as the user's
/// `unique_id` claim.
async fn user_handle(state: &AppState, user_id: &str) -> Result<(Uuid, String), ApiError> {
    let row: Option<(String,)> = sqlx::query_as("SELECT email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some((email,)) = row else {
        return Err(ApiError::unauthorized("user no longer exists"));
    };
    let uuid = Uuid::parse_str(user_id)
        .map_err(|e| ApiError::internal(format!("user_id is not a UUID: {e}")))?;
    Ok((uuid, email))
}

/// Load every passkey enrolled for `user_id`. Used both during
/// register (to populate `exclude_credentials`) and during login (to
/// build the authentication challenge).
pub(crate) async fn load_passkeys(
    state: &AppState,
    user_id: &str,
) -> Result<Vec<Passkey>, ApiError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT passkey_json FROM two_factor_webauthn_credentials WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    rows.into_iter()
        .map(|(j,)| {
            serde_json::from_str::<Passkey>(&j)
                .map_err(|e| ApiError::internal(format!("stored passkey row failed to parse: {e}")))
        })
        .collect()
}

/// True iff the caller has at least one WebAuthn credential. Used by
/// the identity grant to decide whether to advertise `"webauthn"` in
/// `two_factor_providers`.
pub(crate) async fn has_credentials(state: &AppState, user_id: &str) -> Result<bool, ApiError> {
    let row: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM two_factor_webauthn_credentials WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(row.0 > 0)
}

async fn upsert_pending(
    state: &AppState,
    user_id: &str,
    ceremony: &str,
    state_json: &str,
    name: Option<&str>,
) -> Result<(), ApiError> {
    let now = chrono::Utc::now();
    let expires_at = (now + chrono::Duration::seconds(CEREMONY_TTL_SECS)).to_rfc3339();
    let now_str = now.to_rfc3339();
    sqlx::query(
        "INSERT INTO two_factor_webauthn_pending
            (user_id, ceremony, state_json, name, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (user_id, ceremony) DO UPDATE SET
            state_json = EXCLUDED.state_json,
            name       = EXCLUDED.name,
            created_at = EXCLUDED.created_at,
            expires_at = EXCLUDED.expires_at",
    )
    .bind(user_id)
    .bind(ceremony)
    .bind(state_json)
    .bind(name)
    .bind(&now_str)
    .bind(&expires_at)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(())
}

async fn take_pending(
    state: &AppState,
    user_id: &str,
    ceremony: &str,
) -> Result<Option<(String, Option<String>)>, ApiError> {
    let row: Option<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT state_json, name, expires_at
         FROM two_factor_webauthn_pending
         WHERE user_id = $1 AND ceremony = $2",
    )
    .bind(user_id)
    .bind(ceremony)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some((state_json, name, expires_at)) = row else {
        return Ok(None);
    };
    let _ =
        sqlx::query("DELETE FROM two_factor_webauthn_pending WHERE user_id = $1 AND ceremony = $2")
            .bind(user_id)
            .bind(ceremony)
            .execute(state.db.pool())
            .await;
    let expires = chrono::DateTime::parse_from_rfc3339(&expires_at)
        .map_err(|e| ApiError::internal(format!("bad expires_at: {e}")))?;
    if chrono::Utc::now() > expires {
        return Ok(None);
    }
    Ok(Some((state_json, name)))
}

fn webauthn(state: &AppState) -> &Webauthn {
    state.webauthn.as_ref()
}

// ---- register/start ------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterStartRequest {
    /// Master password hash, base64-no-pad of 32 bytes. Re-auth so a
    /// stolen access token can't enroll someone else's authenticator.
    pub master_password_hash: String,
    /// Human-readable name for this credential — `"YubiKey 5C"`,
    /// `"MacBook TouchID"`. Surfaces in `2fa list`.
    pub name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterStartResponse {
    /// `PublicKeyCredentialCreationOptions` JSON, ready to feed into
    /// `navigator.credentials.create({ publicKey: ... })` from a
    /// browser context.
    #[schema(value_type = Object)]
    pub creation_options: serde_json::Value,
}

#[utoipa::path(
    post,
    path = "/api/v1/account/2fa/webauthn/register/start",
    tag = "two-factor",
    request_body = RegisterStartRequest,
    responses(
        (status = 200, description = "Creation options issued", body = RegisterStartResponse),
        (status = 400, description = "Bad name or already-pending ceremony hijacked"),
        (status = 401, description = "Master password is wrong"),
    ),
    security(("bearerAuth" = [])),
)]
async fn register_start(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<RegisterStartRequest>,
) -> Result<Json<RegisterStartResponse>, ApiError> {
    require_master_password(&state, &user.user_id, &req.master_password_hash).await?;

    let name = req.name.trim();
    if name.is_empty() || name.len() > NAME_MAX {
        return Err(ApiError::bad_request(format!(
            "name must be 1..={NAME_MAX} characters"
        )));
    }

    let (uuid, email) = user_handle(&state, &user.user_id).await?;
    let existing = load_passkeys(&state, &user.user_id).await?;
    let exclude: Vec<_> = existing.iter().map(|p| p.cred_id().clone()).collect();

    let (ccr, reg_state) = webauthn(&state)
        .start_passkey_registration(uuid, &email, &email, Some(exclude))
        .map_err(|e| ApiError::internal(format!("WebAuthn start failed: {e}")))?;

    let state_json =
        serde_json::to_string(&reg_state).map_err(|e| ApiError::internal(e.to_string()))?;
    upsert_pending(
        &state,
        &user.user_id,
        CEREMONY_REGISTER,
        &state_json,
        Some(name),
    )
    .await?;

    Ok(Json(RegisterStartResponse {
        creation_options: serde_json::to_value(ccr)
            .map_err(|e| ApiError::internal(e.to_string()))?,
    }))
}

// ---- register/finish -----------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterFinishRequest {
    /// `RegisterPublicKeyCredential` JSON exactly as
    /// `navigator.credentials.create()` produced it.
    #[schema(value_type = Object)]
    pub credential: serde_json::Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterFinishResponse {
    pub credential_id: String,
    pub name: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/account/2fa/webauthn/register/finish",
    tag = "two-factor",
    request_body = RegisterFinishRequest,
    responses(
        (status = 200, description = "Credential enrolled", body = RegisterFinishResponse),
        (status = 400, description = "No pending ceremony, expired, or attestation failed"),
    ),
    security(("bearerAuth" = [])),
)]
async fn register_finish(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<Json<RegisterFinishResponse>, ApiError> {
    let pending = take_pending(&state, &user.user_id, CEREMONY_REGISTER)
        .await?
        .ok_or_else(|| {
            ApiError::bad_request("no pending WebAuthn registration — call /register/start first")
        })?;
    let (state_json, name_opt) = pending;
    let name = name_opt.unwrap_or_else(|| "WebAuthn credential".to_string());

    let reg_state: PasskeyRegistration = serde_json::from_str(&state_json)
        .map_err(|e| ApiError::internal(format!("pending state corrupt: {e}")))?;
    let credential: RegisterPublicKeyCredential =
        serde_json::from_value(req.credential).map_err(|e| {
            ApiError::bad_request(format!(
                "credential is not a valid PublicKeyCredential: {e}"
            ))
        })?;

    let passkey = webauthn(&state)
        .finish_passkey_registration(&credential, &reg_state)
        .map_err(|e| ApiError::bad_request(format!("WebAuthn registration failed: {e}")))?;

    let credential_id_b64 = STANDARD_NO_PAD.encode(passkey.cred_id().as_ref());
    let id = Uuid::now_v7().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let passkey_json =
        serde_json::to_string(&passkey).map_err(|e| ApiError::internal(e.to_string()))?;

    let result = sqlx::query(
        "INSERT INTO two_factor_webauthn_credentials
            (id, user_id, credential_id, passkey_json, name, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(&credential_id_b64)
    .bind(&passkey_json)
    .bind(&name)
    .bind(&now)
    .execute(state.db.pool())
    .await;
    if let Err(sqlx::Error::Database(db_err)) = &result {
        if db_err.is_unique_violation() {
            return Err(ApiError::conflict("this authenticator is already enrolled"));
        }
    }
    result.map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(RegisterFinishResponse {
        credential_id: id,
        name,
    }))
}

// ---- list / delete / rename ---------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct CredentialListItem {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/account/2fa/webauthn/credentials",
    tag = "two-factor",
    responses((status = 200, description = "Enrolled credentials", body = Vec<CredentialListItem>)),
    security(("bearerAuth" = [])),
)]
async fn list_credentials(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<Vec<CredentialListItem>>, ApiError> {
    let rows: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, name, created_at, last_used_at
         FROM two_factor_webauthn_credentials
         WHERE user_id = $1
         ORDER BY created_at",
    )
    .bind(&user.user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, name, created_at, last_used_at)| CredentialListItem {
                id,
                name,
                created_at,
                last_used_at,
            })
            .collect(),
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/account/2fa/webauthn/credentials/{id}",
    tag = "two-factor",
    params(("id" = String, Path, description = "Credential row id (UUIDv7)")),
    responses(
        (status = 204, description = "Credential removed"),
        (status = 404, description = "No such credential for this user"),
    ),
    security(("bearerAuth" = [])),
)]
async fn delete_credential(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let res =
        sqlx::query("DELETE FROM two_factor_webauthn_credentials WHERE id = $1 AND user_id = $2")
            .bind(&id)
            .bind(&user.user_id)
            .execute(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("credential not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RenameRequest {
    pub name: String,
}

#[utoipa::path(
    patch,
    path = "/api/v1/account/2fa/webauthn/credentials/{id}",
    tag = "two-factor",
    params(("id" = String, Path, description = "Credential row id (UUIDv7)")),
    request_body = RenameRequest,
    responses(
        (status = 204, description = "Credential renamed"),
        (status = 400, description = "Bad name"),
        (status = 404, description = "No such credential for this user"),
    ),
    security(("bearerAuth" = [])),
)]
async fn rename_credential(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<RenameRequest>,
) -> Result<StatusCode, ApiError> {
    let name = req.name.trim();
    if name.is_empty() || name.len() > NAME_MAX {
        return Err(ApiError::bad_request(format!(
            "name must be 1..={NAME_MAX} characters"
        )));
    }
    let res = sqlx::query(
        "UPDATE two_factor_webauthn_credentials SET name = $1
         WHERE id = $2 AND user_id = $3",
    )
    .bind(name)
    .bind(&id)
    .bind(&user.user_id)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("credential not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---- login-leg helpers (used by identity.rs) ----------------------------

/// Build an authentication challenge for `user_id` and stash the
/// PasskeyAuthentication state in the pending table. Returns the
/// `RequestChallengeResponse` JSON to be embedded in the
/// `two_factor_required` body.
pub(crate) async fn start_login_challenge(
    state: &AppState,
    user_id: &str,
) -> Result<RequestChallengeResponse, ApiError> {
    let passkeys = load_passkeys(state, user_id).await?;
    if passkeys.is_empty() {
        return Err(ApiError::internal(
            "start_login_challenge called without any enrolled credentials",
        ));
    }
    let (rcr, auth_state) = webauthn(state)
        .start_passkey_authentication(&passkeys)
        .map_err(|e| ApiError::internal(format!("WebAuthn login start failed: {e}")))?;
    let state_json =
        serde_json::to_string(&auth_state).map_err(|e| ApiError::internal(e.to_string()))?;
    upsert_pending(state, user_id, CEREMONY_LOGIN, &state_json, None).await?;
    Ok(rcr)
}

/// Consume the login pending state, verify the supplied assertion,
/// and bump the credential's stored sign_counter on success.
pub(crate) async fn finish_login_assertion(
    state: &AppState,
    user_id: &str,
    credential_json: serde_json::Value,
) -> Result<(), ApiError> {
    use webauthn_rs::prelude::PasskeyAuthentication;

    let pending = take_pending(state, user_id, CEREMONY_LOGIN)
        .await?
        .ok_or_else(|| {
            ApiError::unauthorized("no pending WebAuthn login — challenge expired or never issued")
        })?;
    let auth_state: PasskeyAuthentication = serde_json::from_str(&pending.0)
        .map_err(|e| ApiError::internal(format!("pending state corrupt: {e}")))?;
    let credential: PublicKeyCredential = serde_json::from_value(credential_json).map_err(|e| {
        ApiError::bad_request(format!("assertion is not a valid PublicKeyCredential: {e}"))
    })?;

    let auth_result = webauthn(state)
        .finish_passkey_authentication(&credential, &auth_state)
        .map_err(|e| ApiError::unauthorized(format!("WebAuthn assertion failed: {e}")))?;

    // Update the corresponding stored Passkey: bump sign_counter,
    // refresh last_used_at. The webauthn-rs `Passkey::update_credential`
    // mutates the passkey in place if the assertion advances the
    // counter — we then re-serialize and write back.
    let cred_id_b64 = STANDARD_NO_PAD.encode(auth_result.cred_id().as_ref());
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT id, passkey_json FROM two_factor_webauthn_credentials
         WHERE user_id = $1 AND credential_id = $2",
    )
    .bind(user_id)
    .bind(&cred_id_b64)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some((row_id, passkey_json)) = row else {
        return Err(ApiError::unauthorized(
            "asserted credential is no longer enrolled",
        ));
    };
    let mut passkey: Passkey = serde_json::from_str(&passkey_json)
        .map_err(|e| ApiError::internal(format!("stored passkey corrupt: {e}")))?;
    let _changed = passkey.update_credential(&auth_result);
    let new_passkey_json =
        serde_json::to_string(&passkey).map_err(|e| ApiError::internal(e.to_string()))?;
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE two_factor_webauthn_credentials
         SET passkey_json = $1, last_used_at = $2
         WHERE id = $3",
    )
    .bind(&new_passkey_json)
    .bind(&now)
    .bind(&row_id)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(())
}
