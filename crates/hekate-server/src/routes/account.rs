//! Account-management endpoints: change password, delete account.
//!
//! Both endpoints require master-password re-authentication on top of
//! the bearer-token check, since they perform irreversible or
//! consequential changes.

use axum::{extract::State, http::StatusCode, response::Json, routing::post, Router};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    auth::{password, refresh, AuthUser},
    routes::accounts::ApiError,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/account/change-password", post(change_password))
        .route("/api/v1/account/delete", post(delete_account))
        .route("/api/v1/account/rotate-keys", post(rotate_keys))
}

// ---- change password -----------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    /// Current master_password_hash, base64-no-pad of 32 bytes. Used to
    /// verify the caller knows the current password before rotating.
    pub current_master_password_hash: String,
    /// New master_password_hash, base64-no-pad of 32 bytes.
    pub new_master_password_hash: String,
    /// New KDF parameters (typically the same as before, but the user
    /// can take this opportunity to bump them).
    #[schema(value_type = Object)]
    pub new_kdf_params: Value,
    /// New random salt for the new KDF derivation, base64-no-pad.
    pub new_kdf_salt: String,
    /// HMAC-SHA256 binding `new_kdf_params` + `new_kdf_salt` to the new
    /// master key. Base64-no-pad of 32 bytes. Required — without this,
    /// the next prelogin would surface unauthenticated KDF params (BW07).
    pub new_kdf_params_mac: String,
    /// Account key re-wrapped under the new stretched master key
    /// (EncString v3 wire form).
    pub new_protected_account_key: String,
    /// New Ed25519 account-signing public key, base64-no-pad of 32 bytes.
    /// Master password change rotates the master key, which rotates the
    /// signing seed (HKDF subkey), which rotates this pubkey. Server
    /// updates the column atomically and wipes the user's stored
    /// vault_manifest row — old manifests can no longer be verified
    /// under the new pubkey, and the next CLI/popup write uploads a
    /// fresh genesis (version=1, parent=zero).
    #[serde(default)]
    pub new_account_signing_pubkey: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChangePasswordResponse {
    /// Newly issued access token (JWT), 1-hour TTL. The old token is
    /// invalidated on the next request to any endpoint.
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    /// New refresh token in a fresh family. All prior refresh tokens
    /// for this user are revoked atomically with the password change.
    pub refresh_token: String,
}

/// Change the master password.
///
/// Requires re-auth via `current_master_password_hash`. Atomically
/// rotates the user's KDF salt/params, master_password_hash, the
/// account-key wrapping, and the security_stamp — invalidating every
/// outstanding access token across all devices on the next request.
/// All existing refresh tokens are revoked. Fresh access + refresh
/// tokens are returned for the caller's current session.
#[utoipa::path(
    post,
    path = "/api/v1/account/change-password",
    tag = "accounts",
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Rotated", body = ChangePasswordResponse),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Current password is wrong"),
    ),
    security(("bearerAuth" = [])),
)]
async fn change_password(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<ChangePasswordResponse>, ApiError> {
    // Decode + verify the supplied current password hash.
    let current_mph = STANDARD_NO_PAD
        .decode(&req.current_master_password_hash)
        .map_err(|_| ApiError::bad_request("current_master_password_hash is not base64-no-pad"))?;
    if current_mph.len() != 32 {
        return Err(ApiError::bad_request(
            "current_master_password_hash must be 32 bytes",
        ));
    }
    let new_mph = STANDARD_NO_PAD
        .decode(&req.new_master_password_hash)
        .map_err(|_| ApiError::bad_request("new_master_password_hash is not base64-no-pad"))?;
    if new_mph.len() != 32 {
        return Err(ApiError::bad_request(
            "new_master_password_hash must be 32 bytes",
        ));
    }
    if STANDARD_NO_PAD.decode(&req.new_kdf_salt).is_err() {
        return Err(ApiError::bad_request("new_kdf_salt is not base64-no-pad"));
    }
    let new_mac = STANDARD_NO_PAD
        .decode(&req.new_kdf_params_mac)
        .map_err(|_| ApiError::bad_request("new_kdf_params_mac is not base64-no-pad"))?;
    if new_mac.len() != 32 {
        return Err(ApiError::bad_request("new_kdf_params_mac must be 32 bytes"));
    }
    if !req.new_account_signing_pubkey.is_empty() {
        let bytes = STANDARD_NO_PAD
            .decode(&req.new_account_signing_pubkey)
            .map_err(|_| {
                ApiError::bad_request("new_account_signing_pubkey is not base64-no-pad")
            })?;
        if bytes.len() != 32 {
            return Err(ApiError::bad_request(
                "new_account_signing_pubkey must be 32 bytes",
            ));
        }
    }
    let new_kdf_params_str = serde_json::to_string(&req.new_kdf_params)
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // Look up the current stored password hash + email (for the response).
    let row: Option<(String,)> =
        sqlx::query_as("SELECT master_password_hash FROM users WHERE id = $1")
            .bind(&user.user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some((stored_phc,)) = row else {
        return Err(ApiError::unauthorized("user no longer exists"));
    };
    if !password::verify(&current_mph, &stored_phc) {
        return Err(ApiError::unauthorized("current password is wrong"));
    }

    let new_phc = password::hash(&new_mph).map_err(|e| ApiError::internal(e.to_string()))?;
    let new_stamp = Uuid::now_v7().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    // Atomically: update user fields, rotate stamp, revoke refresh tokens.
    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    sqlx::query(
        "UPDATE users
         SET master_password_hash = $1,
             kdf_params = $2,
             kdf_salt = $3,
             kdf_params_mac = $4,
             protected_account_key = $5,
             security_stamp = $6,
             revision_date = $7,
             account_revision_date = $7,
             account_signing_pubkey_b64 = COALESCE(NULLIF($8, ''), account_signing_pubkey_b64)
         WHERE id = $9",
    )
    .bind(&new_phc)
    .bind(&new_kdf_params_str)
    .bind(&req.new_kdf_salt)
    .bind(&req.new_kdf_params_mac)
    .bind(&req.new_protected_account_key)
    .bind(&new_stamp)
    .bind(&now)
    .bind(&req.new_account_signing_pubkey)
    .bind(&user.user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    sqlx::query(
        "UPDATE refresh_tokens
         SET revoked_at = $1
         WHERE user_id = $2 AND revoked_at IS NULL",
    )
    .bind(&now)
    .bind(&user.user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    // Wipe the stored vault manifest. Old signatures can no longer be
    // verified under the new pubkey; the next client write uploads a
    // fresh genesis (version=1, parent=zero).
    sqlx::query("DELETE FROM vault_manifests WHERE user_id = $1")
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // Issue fresh tokens carrying the new stamp.
    let (access_token, expires_in) = state
        .signer
        .issue_access_token(&user.user_id, &new_stamp)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let new_refresh = refresh::issue_new_family(state.db.pool(), &user.user_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(ChangePasswordResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        refresh_token: new_refresh.token,
    }))
}

// ---- delete account ------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct DeleteAccountRequest {
    /// Master password hash for re-auth.
    pub master_password_hash: String,
}

/// Delete the calling account and all its data. Cascade deletes ciphers,
/// folders, devices, refresh tokens, PATs, webhooks, deliveries.
///
/// Requires re-auth via `master_password_hash`. **Irreversible.**
#[utoipa::path(
    post,
    path = "/api/v1/account/delete",
    tag = "accounts",
    request_body = DeleteAccountRequest,
    responses(
        (status = 204, description = "Account deleted"),
        (status = 401, description = "Master password is wrong"),
    ),
    security(("bearerAuth" = [])),
)]
async fn delete_account(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<DeleteAccountRequest>,
) -> Result<StatusCode, ApiError> {
    let mph = STANDARD_NO_PAD
        .decode(&req.master_password_hash)
        .map_err(|_| ApiError::bad_request("master_password_hash is not base64-no-pad"))?;
    if mph.len() != 32 {
        return Err(ApiError::bad_request(
            "master_password_hash must be 32 bytes",
        ));
    }
    let row: Option<(String,)> =
        sqlx::query_as("SELECT master_password_hash FROM users WHERE id = $1")
            .bind(&user.user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some((stored_phc,)) = row else {
        return Err(ApiError::unauthorized("user no longer exists"));
    };
    if !password::verify(&mph, &stored_phc) {
        return Err(ApiError::unauthorized("master password is wrong"));
    }

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&user.user_id)
        .execute(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

// ---- M2.26: rotate account_key ------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CipherRewrap {
    pub cipher_id: String,
    /// Per-cipher key wrapped under the new account_key.
    pub new_protected_cipher_key: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SendRewrap {
    pub send_id: String,
    /// `protected_send_key` re-wrapped under the new account_key.
    pub new_protected_send_key: String,
    /// The Send's `name` field is also wrapped under the account_key
    /// (sender-side display only, never visible to recipients), so a
    /// rotation must re-wrap it too — otherwise the sender's own name
    /// becomes undecryptable post-rotate. EncString v3.
    pub new_name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct OrgMemberRewrap {
    pub org_id: String,
    /// `protected_org_key` re-wrapped under the new account_key.
    pub new_protected_org_key: String,
}

/// Body for `POST /api/v1/account/rotate-keys`.
///
/// The master password (and therefore the master key, signing seed, and
/// account-signing pubkey) is **unchanged** by this flow. What rotates:
///
/// - The 32-byte `account_key` (random new one, wrapped under the same
///   stretched master key in `new_protected_account_key`).
/// - The wrapping of the X25519 account private key (the keypair itself
///   is preserved by default — see commentary on the CLI side; rotating
///   the X25519 keypair forces every peer to re-pin so it's a separate
///   advanced flag).
/// - Every personal-cipher PCK wrap (re-wrapped under new account_key —
///   the PCKs themselves do not regenerate, so cipher field ciphertexts
///   stay untouched).
/// - Every Send `protected_send_key` (M2.25 / M2.25a).
/// - Every `organization_members.protected_org_key` for orgs the caller
///   is a member of.
///
/// Org-owned ciphers are unaffected: their PCK is wrapped under the org
/// symmetric key, not the user's account_key.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RotateKeysRequest {
    /// Master password hash for re-auth (caller must prove they know
    /// the current password before we accept the rewrap blob).
    pub master_password_hash: String,
    /// New `account_key` wrapped under the (unchanged) stretched
    /// master key. EncString v3.
    pub new_protected_account_key: String,
    /// X25519 private key wrapped under the new `account_key`. The
    /// raw private key is unchanged by default.
    pub new_protected_account_private_key: String,
    pub cipher_rewraps: Vec<CipherRewrap>,
    #[serde(default)]
    pub send_rewraps: Vec<SendRewrap>,
    #[serde(default)]
    pub org_member_rewraps: Vec<OrgMemberRewrap>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RotateKeysResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub refresh_token: String,
    /// How many rows the server actually rewrote in each category.
    /// Lets the client diff against the count it sent — a mismatch
    /// means the server saw a different vault than the client did,
    /// which the CLI surfaces as a warning.
    pub rewrote_ciphers: i64,
    pub rewrote_sends: i64,
    pub rewrote_org_memberships: i64,
}

/// Rotate the user's `account_key` and re-wrap all dependents in one
/// atomic transaction. Requires `account:admin` (M2.x scope; this
/// endpoint also re-auths via the master password hash).
#[utoipa::path(
    post,
    path = "/api/v1/account/rotate-keys",
    tag = "accounts",
    request_body = RotateKeysRequest,
    responses(
        (status = 200, description = "Rotated", body = RotateKeysResponse),
        (status = 400, description = "Validation failed",
         body = crate::routes::accounts::ErrorResponse),
        (status = 401, description = "Master password is wrong"),
        (status = 403, description = "Insufficient scope"),
    ),
    security(("bearerAuth" = [])),
)]
async fn rotate_keys(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<RotateKeysRequest>,
) -> Result<Json<RotateKeysResponse>, ApiError> {
    user.require(crate::auth::scope::ACCOUNT_ADMIN)?;

    // 1. Verify master password.
    let mph = STANDARD_NO_PAD
        .decode(&req.master_password_hash)
        .map_err(|_| ApiError::bad_request("master_password_hash is not base64-no-pad"))?;
    if mph.len() != 32 {
        return Err(ApiError::bad_request(
            "master_password_hash must be 32 bytes",
        ));
    }
    let row: Option<(String,)> =
        sqlx::query_as("SELECT master_password_hash FROM users WHERE id = $1")
            .bind(&user.user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some((stored_phc,)) = row else {
        return Err(ApiError::unauthorized("user no longer exists"));
    };
    if !password::verify(&mph, &stored_phc) {
        return Err(ApiError::unauthorized("master password is wrong"));
    }

    // 2. Validate every rewrap target. Each error returns 400 with a
    //    pointer at the bad row so the client can correct + retry.
    use hekate_core::encstring::EncString;
    EncString::parse(&req.new_protected_account_key)
        .map_err(|e| ApiError::bad_request(format!("new_protected_account_key: {e}")))?;
    EncString::parse(&req.new_protected_account_private_key)
        .map_err(|e| ApiError::bad_request(format!("new_protected_account_private_key: {e}")))?;
    for c in &req.cipher_rewraps {
        EncString::parse(&c.new_protected_cipher_key)
            .map_err(|e| ApiError::bad_request(format!("cipher {}: {e}", c.cipher_id)))?;
    }
    for s in &req.send_rewraps {
        EncString::parse(&s.new_protected_send_key)
            .map_err(|e| ApiError::bad_request(format!("send {}: {e}", s.send_id)))?;
        EncString::parse(&s.new_name)
            .map_err(|e| ApiError::bad_request(format!("send {} name: {e}", s.send_id)))?;
    }
    for o in &req.org_member_rewraps {
        EncString::parse(&o.new_protected_org_key)
            .map_err(|e| ApiError::bad_request(format!("org {}: {e}", o.org_id)))?;
    }

    // 3. Apply atomically. The transaction touches three tables; if any
    //    UPDATE fails to match the expected row we abort with a 400 so
    //    the client knows to /sync + retry.
    let new_stamp = Uuid::now_v7().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // Update users row: new wrapped account_key + private_key, new
    // security stamp. account_signing_pubkey_b64, account_public_key,
    // and master_password_hash are NOT touched in this flow.
    sqlx::query(
        "UPDATE users
         SET protected_account_key = $1,
             protected_account_private_key = $2,
             security_stamp = $3,
             revision_date = $4,
             account_revision_date = $4
         WHERE id = $5",
    )
    .bind(&req.new_protected_account_key)
    .bind(&req.new_protected_account_private_key)
    .bind(&new_stamp)
    .bind(&now)
    .bind(&user.user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    // Personal ciphers: re-wrap PCKs. Bumping revision_date so /sync
    // surfaces the wrap change to other devices.
    let mut rewrote_ciphers: i64 = 0;
    for c in &req.cipher_rewraps {
        let res = sqlx::query(
            "UPDATE ciphers
             SET protected_cipher_key = $1, revision_date = $2
             WHERE id = $3 AND user_id = $4",
        )
        .bind(&c.new_protected_cipher_key)
        .bind(&now)
        .bind(&c.cipher_id)
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
        if res.rows_affected() == 0 {
            return Err(ApiError::bad_request(format!(
                "cipher {} not owned by caller (or org-owned — only personal \
                 ciphers wrap PCKs under the account key)",
                c.cipher_id
            )));
        }
        rewrote_ciphers += 1;
    }

    // Sends: re-wrap protected_send_key.
    let mut rewrote_sends: i64 = 0;
    for s in &req.send_rewraps {
        let res = sqlx::query(
            "UPDATE sends
             SET protected_send_key = $1, name = $2, revision_date = $3
             WHERE id = $4 AND user_id = $5",
        )
        .bind(&s.new_protected_send_key)
        .bind(&s.new_name)
        .bind(&now)
        .bind(&s.send_id)
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
        if res.rows_affected() == 0 {
            return Err(ApiError::bad_request(format!(
                "send {} not owned by caller",
                s.send_id
            )));
        }
        rewrote_sends += 1;
    }

    // Org memberships: re-wrap each protected_org_key. The roster /
    // org_sym_key_id stay the same — only the wrap to the caller's
    // account_key changes.
    let mut rewrote_org_memberships: i64 = 0;
    for o in &req.org_member_rewraps {
        let res = sqlx::query(
            "UPDATE organization_members
             SET protected_org_key = $1
             WHERE org_id = $2 AND user_id = $3",
        )
        .bind(&o.new_protected_org_key)
        .bind(&o.org_id)
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
        if res.rows_affected() == 0 {
            return Err(ApiError::bad_request(format!(
                "caller is not a member of org {}",
                o.org_id
            )));
        }
        rewrote_org_memberships += 1;
    }

    // Revoke all refresh tokens — old tokens decrypt the old
    // account_key, which is no longer the wrap target. Forces all
    // other devices to re-login + re-sync state.
    sqlx::query(
        "UPDATE refresh_tokens
         SET revoked_at = $1
         WHERE user_id = $2 AND revoked_at IS NULL",
    )
    .bind(&now)
    .bind(&user.user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // Issue fresh tokens carrying the new stamp.
    let (access_token, expires_in) = state
        .signer
        .issue_access_token(&user.user_id, &new_stamp)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let new_refresh = refresh::issue_new_family(state.db.pool(), &user.user_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(RotateKeysResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        refresh_token: new_refresh.token,
        rewrote_ciphers,
        rewrote_sends,
        rewrote_org_memberships,
    }))
}
