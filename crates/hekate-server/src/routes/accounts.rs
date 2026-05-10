use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{auth::password, AppState};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/accounts/register", post(register))
        .route("/api/v1/accounts/prelogin", post(prelogin))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    /// User email; lowercased server-side. Used as the unique account identifier.
    #[schema(example = "alice@example.com")]
    pub email: String,
    /// JSON object describing the KDF used to derive the master password hash.
    /// Currently only `{"alg":"argon2id","m_kib":...,"t":...,"p":...}` is recognized.
    #[schema(value_type = Object, example = json!({"alg":"argon2id","m_kib":131072,"t":3,"p":4}))]
    pub kdf_params: Value,
    /// 16+ random bytes, base64-no-pad (standard alphabet).
    pub kdf_salt: String,
    /// 32 bytes, base64-no-pad. HKDF-derived master password hash from the client.
    pub master_password_hash: String,
    /// 32 bytes, base64-no-pad. HMAC-SHA256(kdf_bind_key, canonical(kdf_params, kdf_salt))
    /// — binds the KDF parameters to the master key so a malicious server
    /// can't downgrade them between registration and login (BW07/LP04).
    pub kdf_params_mac: String,
    /// EncString v3 envelope of the account key, encrypted under the stretched master key.
    pub protected_account_key: String,
    /// X25519 account public key, 32 bytes base64-no-pad.
    pub account_public_key: String,
    /// EncString v3 envelope of the X25519 account private key, encrypted under the account key.
    pub protected_account_private_key: String,
    /// Ed25519 account-signing public key, 32 bytes base64-no-pad. Derived
    /// client-side from the master key via HKDF; the server stores it and
    /// uses it to verify signed vault manifests on upload (BW04).
    #[serde(default)]
    pub account_signing_pubkey: String,
    /// Client-supplied UUIDv7 for this account. Bound into the
    /// pubkey-bundle signature below so a server can't fabricate a
    /// (user_id, pubkey) pair without the user's signing key. If
    /// absent, server generates one — but in that mode the bundle
    /// signature can't be verified end-to-end (the client doesn't
    /// know the id at sign time), so callers SHOULD always supply it.
    #[serde(default)]
    pub user_id: Option<String>,
    /// 64-byte Ed25519 signature, base64-no-pad. Signs canonical
    /// `(user_id || account_signing_pubkey || account_public_key)` per
    /// `hekate-core::signcrypt::sign_pubkey_bundle`. Server validates
    /// the sig before persisting; consumers fetch the bundle via
    /// `GET /api/v1/users/{id}/pubkeys` and verify before using
    /// either pubkey for sharing or signcryption.
    #[serde(default)]
    pub account_pubkey_bundle_sig: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterResponse {
    #[schema(example = "019de950-667a-7373-bb12-ca50fbf60191")]
    pub user_id: String,
}

/// Create a new account. The client derives the master key locally via
/// Argon2id; only the HKDF-derived `master_password_hash` is sent.
#[utoipa::path(
    post,
    path = "/api/v1/accounts/register",
    tag = "accounts",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Created", body = RegisterResponse),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 409, description = "Email already registered", body = ErrorResponse),
    ),
)]
async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    let email = req.email.trim().to_lowercase();
    if !email.contains('@') {
        return Err(ApiError::bad_request("invalid email"));
    }

    let mph_bytes = STANDARD_NO_PAD
        .decode(&req.master_password_hash)
        .map_err(|_| ApiError::bad_request("master_password_hash is not base64-no-pad"))?;
    if mph_bytes.len() != 32 {
        return Err(ApiError::bad_request(
            "master_password_hash must be 32 bytes",
        ));
    }

    // Validate kdf_salt is decodable; we re-emit the original string verbatim.
    if STANDARD_NO_PAD.decode(&req.kdf_salt).is_err() {
        return Err(ApiError::bad_request("kdf_salt is not base64-no-pad"));
    }

    // Validate kdf_params_mac shape. The server can't itself check the MAC
    // (it doesn't know the bind key), but it enforces 32-byte length so a
    // missing/empty value fails fast rather than silently bypassing the
    // BW07/LP04 mitigation later.
    let mac_bytes = STANDARD_NO_PAD
        .decode(&req.kdf_params_mac)
        .map_err(|_| ApiError::bad_request("kdf_params_mac is not base64-no-pad"))?;
    if mac_bytes.len() != 32 {
        return Err(ApiError::bad_request("kdf_params_mac must be 32 bytes"));
    }

    // Same shape check on the Ed25519 signing pubkey. Empty is allowed only
    // for the duration of the M2.15a → M2.15b migration window — once the
    // CLI catches up, this becomes mandatory. For now, if present, validate.
    let signing_pk_bytes = if !req.account_signing_pubkey.is_empty() {
        let sig_pk_bytes = STANDARD_NO_PAD
            .decode(&req.account_signing_pubkey)
            .map_err(|_| ApiError::bad_request("account_signing_pubkey is not base64-no-pad"))?;
        if sig_pk_bytes.len() != 32 {
            return Err(ApiError::bad_request(
                "account_signing_pubkey must be 32 bytes",
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&sig_pk_bytes);
        Some(arr)
    } else {
        None
    };

    // X25519 account public key shape. Empty allowed for back-compat
    // until the bundle-sig path is mandatory; once present, must be 32B.
    let x25519_pk_bytes = if !req.account_public_key.is_empty() {
        let bytes = STANDARD_NO_PAD
            .decode(&req.account_public_key)
            .map_err(|_| ApiError::bad_request("account_public_key is not base64-no-pad"))?;
        if bytes.len() != 32 {
            return Err(ApiError::bad_request("account_public_key must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    };

    // Server-side Argon2id hashing of the client-side master password hash.
    let stored_phc = password::hash(&mph_bytes).map_err(|e| ApiError::internal(e.to_string()))?;

    // Use the client-supplied UUIDv7 if present (so it can be bound into
    // the self-signed pubkey bundle), otherwise generate. We validate
    // any client-supplied value as a real UUID to keep the column shape
    // stable.
    let user_id = match req.user_id.as_deref() {
        Some(s) => {
            Uuid::parse_str(s).map_err(|_| ApiError::bad_request("user_id is not a valid UUID"))?;
            s.to_string()
        }
        None => Uuid::now_v7().to_string(),
    };

    // Verify the self-signed pubkey bundle if all three components are
    // present. M2.19 onward, clients SHOULD always supply this; absence
    // for now keeps existing tests passing — the consumer side
    // (GET /api/v1/users/{id}/pubkeys) returns 404 when the sig is
    // empty so the directory never serves an unverifiable bundle.
    if !req.account_pubkey_bundle_sig.is_empty() {
        let sig_bytes = STANDARD_NO_PAD
            .decode(&req.account_pubkey_bundle_sig)
            .map_err(|_| ApiError::bad_request("account_pubkey_bundle_sig is not base64-no-pad"))?;
        if sig_bytes.len() != 64 {
            return Err(ApiError::bad_request(
                "account_pubkey_bundle_sig must be 64 bytes",
            ));
        }
        let signing_pk = signing_pk_bytes.ok_or_else(|| {
            ApiError::bad_request("account_pubkey_bundle_sig requires account_signing_pubkey")
        })?;
        let x25519_pk = x25519_pk_bytes.ok_or_else(|| {
            ApiError::bad_request("account_pubkey_bundle_sig requires account_public_key")
        })?;
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        hekate_core::signcrypt::verify_pubkey_bundle(&user_id, &signing_pk, &x25519_pk, &sig_arr)
            .map_err(|_| {
            ApiError::bad_request(
                "account_pubkey_bundle_sig did not verify against (user_id, signing_pk, x25519_pk)",
            )
        })?;
    }

    let security_stamp = Uuid::now_v7().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let kdf_params_str =
        serde_json::to_string(&req.kdf_params).map_err(|e| ApiError::internal(e.to_string()))?;

    let result = sqlx::query(
        "INSERT INTO users (
            id, email, kdf_params, kdf_salt, kdf_params_mac, master_password_hash,
            protected_account_key, account_public_key,
            protected_account_private_key, account_signing_pubkey_b64,
            account_pubkey_bundle_sig_b64,
            revision_date, security_stamp, account_revision_date
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(&user_id)
    .bind(&email)
    .bind(&kdf_params_str)
    .bind(&req.kdf_salt)
    .bind(&req.kdf_params_mac)
    .bind(&stored_phc)
    .bind(&req.protected_account_key)
    .bind(&req.account_public_key)
    .bind(&req.protected_account_private_key)
    .bind(&req.account_signing_pubkey)
    .bind(&req.account_pubkey_bundle_sig)
    .bind(&now)
    .bind(&security_stamp)
    .bind(&now)
    .execute(state.db.pool())
    .await;

    // Audit S-H2 (2026-05-07): registration must not leak email
    // existence. The prelogin endpoint went to lengths to look the
    // same for known and unknown emails (deterministic fake KDF
    // salts/MACs); password_grant runs Argon2id against a dummy PHC
    // for unknown-email cases. Returning 409 "email already
    // registered" here defeats both — an enumeration probe can call
    // /accounts/register and read off existence from the status code.
    //
    // Instead, on a unique-violation we return 201 with a freshly
    // synthesized user_id so the response is indistinguishable from a
    // genuinely new registration. The probing client can't actually
    // log in with the password they just sent (the existing account
    // has different keys, so master_password_hash won't match), and
    // the legitimate-but-confused user who double-submitted simply
    // gets the same "OK" they expected.
    //
    // Timing is roughly preserved: Argon2id hashing (≈80 ms) dominates
    // both branches, the failed INSERT pays roughly the same cost as a
    // successful one.
    match result {
        Ok(_) => Ok((StatusCode::CREATED, Json(RegisterResponse { user_id }))),
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            tracing::debug!(
                email_lower = %email,
                "register hit duplicate email; returning synthetic 201 to avoid enumeration"
            );
            Ok((
                StatusCode::CREATED,
                Json(RegisterResponse {
                    user_id: Uuid::now_v7().to_string(),
                }),
            ))
        }
        Err(e) => Err(ApiError::internal(e.to_string())),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PreloginRequest {
    #[schema(example = "alice@example.com")]
    pub email: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PreloginResponse {
    /// KDF parameter object for re-deriving the client-side master password hash.
    /// For unknown emails, returns deterministic fake values to prevent enumeration.
    #[schema(value_type = Object)]
    pub kdf_params: Value,
    /// base64-no-pad salt to use in derivation.
    pub kdf_salt: String,
    /// 32 bytes, base64-no-pad. Stored at registration; binds (kdf_params,
    /// kdf_salt) to the master key. The client MUST verify this before
    /// sending the master_password_hash on token grant — otherwise a
    /// malicious server can downgrade the KDF (BW07/LP04). For unknown
    /// emails the server returns a deterministic-but-fake 32-byte value
    /// so timing/structure does not leak existence.
    pub kdf_params_mac: String,
}

/// Returns the KDF parameters needed to derive the master password hash
/// for `email`. For unknown emails, returns deterministic-but-fake values
/// to avoid user enumeration.
#[utoipa::path(
    post,
    path = "/api/v1/accounts/prelogin",
    tag = "accounts",
    request_body = PreloginRequest,
    responses((status = 200, description = "OK", body = PreloginResponse)),
)]
async fn prelogin(
    State(state): State<AppState>,
    Json(req): Json<PreloginRequest>,
) -> Result<Json<PreloginResponse>, ApiError> {
    let email = req.email.trim().to_lowercase();

    let row: Option<(String, String, String)> =
        sqlx::query_as("SELECT kdf_params, kdf_salt, kdf_params_mac FROM users WHERE email = $1")
            .bind(&email)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;

    let (kdf_params_str, kdf_salt, kdf_params_mac) = match row {
        Some(r) => r,
        None => {
            // Stable, fake-but-realistic response so timing/structure don't
            // leak existence. Real users get real values. The fake MAC will
            // necessarily fail client-side verification — that's correct:
            // login attempts against unknown emails should not succeed, and
            // a wrong-password login is indistinguishable from this case.
            return Ok(Json(PreloginResponse {
                kdf_params: serde_json::json!({
                    "alg": "argon2id",
                    "m_kib": 131072,
                    "t": 3,
                    "p": 4
                }),
                kdf_salt: deterministic_fake_salt(&email, &state.config.fake_salt_pepper),
                kdf_params_mac: deterministic_fake_mac(&email, &state.config.fake_salt_pepper),
            }));
        }
    };
    let kdf_params: Value =
        serde_json::from_str(&kdf_params_str).map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(PreloginResponse {
        kdf_params,
        kdf_salt,
        kdf_params_mac,
    }))
}

/// Stable per-email salt for unknown users so the response looks identical
/// to a real user's response on every call. Pepper is a server-local secret
/// (not in the DB) so an attacker can't reproduce it offline.
fn deterministic_fake_salt(email: &str, pepper: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"pmgr-prelogin-fake-salt-v1");
    h.update(pepper);
    h.update(email.as_bytes());
    let digest = h.finalize();
    STANDARD_NO_PAD.encode(&digest[..16])
}

/// Stable per-email fake MAC, same purpose as `deterministic_fake_salt`.
/// Independent domain tag so the two values can't collide.
fn deterministic_fake_mac(email: &str, pepper: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"pmgr-prelogin-fake-mac-v1");
    h.update(pepper);
    h.update(email.as_bytes());
    let digest = h.finalize();
    STANDARD_NO_PAD.encode(digest)
}

/// Standard JSON error body returned by every endpoint on failure.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    /// Human-readable error message.
    pub error: String,
}

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    PreconditionRequired(String),
    Internal(String),
}

impl ApiError {
    pub fn bad_request(s: impl Into<String>) -> Self {
        Self::BadRequest(s.into())
    }
    pub fn unauthorized(s: impl Into<String>) -> Self {
        Self::Unauthorized(s.into())
    }
    pub fn forbidden(s: impl Into<String>) -> Self {
        Self::Forbidden(s.into())
    }
    pub fn not_found(s: impl Into<String>) -> Self {
        Self::NotFound(s.into())
    }
    pub fn conflict(s: impl Into<String>) -> Self {
        Self::Conflict(s.into())
    }
    pub fn internal(s: impl Into<String>) -> Self {
        Self::Internal(s.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        // Audit S-M1 (2026-05-07): the Internal arm used to echo the
        // raw error message (e.g. an `sqlx::Error` carrying column /
        // constraint names, or a blob-store error carrying filesystem
        // paths) into the response body. That helps an attacker map
        // the schema and storage layout. Now we log the full message
        // server-side at error level and return a constant client-
        // facing string. Other arms (4xx) already use only
        // server-controlled / handler-supplied strings, so they're
        // safe to return verbatim.
        match self {
            ApiError::BadRequest(m) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": m })),
            )
                .into_response(),
            ApiError::Unauthorized(m) => (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": m })),
            )
                .into_response(),
            ApiError::Forbidden(m) => (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": m })),
            )
                .into_response(),
            ApiError::NotFound(m) => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": m })),
            )
                .into_response(),
            ApiError::Conflict(m) => (
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "error": m })),
            )
                .into_response(),
            ApiError::PreconditionRequired(m) => (
                StatusCode::PRECONDITION_REQUIRED,
                Json(serde_json::json!({ "error": m })),
            )
                .into_response(),
            ApiError::Internal(m) => {
                tracing::error!(error = %m, "api error (returning generic 500)");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "internal error" })),
                )
                    .into_response()
            }
        }
    }
}

/// Translate a scope-denied AuthError into an ApiError so handlers can
/// `?` it in their result chains.
impl From<crate::auth::extractor::AuthError> for ApiError {
    fn from(e: crate::auth::extractor::AuthError) -> Self {
        match e {
            crate::auth::extractor::AuthError::Forbidden(m) => ApiError::Forbidden(m),
            _ => ApiError::Unauthorized("unauthorized".into()),
        }
    }
}
