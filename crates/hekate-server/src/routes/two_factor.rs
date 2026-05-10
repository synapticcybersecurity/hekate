//! TOTP 2FA + recovery codes (M2.22).
//!
//! Recovery codes are an authentication-only 2FA bypass — they let the
//! user finish a login challenge when their TOTP authenticator is gone,
//! but they do NOT decrypt the vault. The master password remains the
//! only path to vault plaintext (zero-knowledge invariant). See
//! `docs/threat-model-gaps.md` "2FA" and the M2.22 CHANGELOG entry.
//!
//! Endpoints (all require master-password re-auth):
//! - `POST /api/v1/account/2fa/totp/setup`     — phase 1 of enrollment
//! - `POST /api/v1/account/2fa/totp/confirm`   — phase 2: verify TOTP, commit
//! - `POST /api/v1/account/2fa/totp/disable`   — drop enrollment + recovery codes
//! - `POST /api/v1/account/2fa/recovery-codes/regenerate` — rotate the 10-code set
//! - `GET  /api/v1/account/2fa/status`         — `{enabled, recovery_codes_remaining}`

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    auth::{password, AuthUser},
    routes::accounts::ApiError,
    AppState,
};

/// How long the user has between `setup` and `confirm` before the pending
/// enrollment row is treated as abandoned. Long enough to find the
/// authenticator app + scan the QR; short enough that an abandoned
/// enrollment doesn't sit on the wire forever.
const PENDING_ENROLL_TTL_SECS: i64 = 600;

/// Number of recovery codes minted per enrollment / regeneration.
pub(crate) const RECOVERY_CODE_COUNT: usize = 10;

/// Length in characters of each recovery code (uppercase base32, no
/// padding, no dashes). 16 chars = 80 bits of entropy — well outside
/// online-attack reach even if rate-limiting fails.
pub(crate) const RECOVERY_CODE_LEN: usize = 16;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/account/2fa/totp/setup", post(totp_setup))
        .route("/api/v1/account/2fa/totp/confirm", post(totp_confirm))
        .route("/api/v1/account/2fa/totp/disable", post(totp_disable))
        .route(
            "/api/v1/account/2fa/recovery-codes/regenerate",
            post(recovery_regenerate),
        )
        .route("/api/v1/account/2fa/status", get(status))
}

// ---- shared helpers ------------------------------------------------------

/// Normalize a user-typed recovery code so we hash a stable form:
/// strip whitespace + dashes, uppercase. The on-the-wire format with
/// dashes is `XXXX-XXXX-XXXX-XXXX`; the stored PHC is over the dashless
/// uppercase form.
pub(crate) fn normalize_recovery_code(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(|c| c.to_uppercase())
        .collect()
}

/// Format a 16-char recovery code as four dash-separated 4-char groups
/// for human transcription. Caller has already normalized.
pub(crate) fn format_recovery_code(normalized: &str) -> String {
    let bytes = normalized.as_bytes();
    debug_assert_eq!(bytes.len(), RECOVERY_CODE_LEN);
    format!(
        "{}-{}-{}-{}",
        std::str::from_utf8(&bytes[0..4]).unwrap_or(""),
        std::str::from_utf8(&bytes[4..8]).unwrap_or(""),
        std::str::from_utf8(&bytes[8..12]).unwrap_or(""),
        std::str::from_utf8(&bytes[12..16]).unwrap_or(""),
    )
}

/// Generate a single recovery code. 16 base32 characters, uppercase,
/// drawn from a CSPRNG with rejection-free index sampling (the alphabet
/// has exactly 32 entries so `byte & 0x1f` is unbiased).
fn generate_recovery_code() -> String {
    let mut buf = [0u8; RECOVERY_CODE_LEN];
    OsRng.fill_bytes(&mut buf);
    let mut out = String::with_capacity(RECOVERY_CODE_LEN);
    for b in buf.iter() {
        out.push(BASE32_ALPHABET[(*b & 0x1f) as usize] as char);
    }
    out
}

/// Mint `RECOVERY_CODE_COUNT` codes, returning `(plaintext_dashed, phc_strings)`.
/// `plaintext_dashed[i]` is what we show the user once; `phc_strings[i]`
/// is the Argon2id PHC of the dashless uppercase form, what we store.
fn mint_recovery_codes() -> anyhow::Result<(Vec<String>, Vec<String>)> {
    let mut plaintexts = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut phcs = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let normalized = generate_recovery_code();
        let phc = password::hash(normalized.as_bytes())?;
        plaintexts.push(format_recovery_code(&normalized));
        phcs.push(phc);
    }
    Ok((plaintexts, phcs))
}

/// Build a `TOTP` from a base32-encoded secret. Pmgr ships the
/// RFC 6238 default profile: SHA-1, 6 digits, 30-second step, ±1 step
/// skew tolerance.
pub(crate) fn build_totp(secret_b32: &str) -> anyhow::Result<TOTP> {
    let bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|e| anyhow::anyhow!("decode TOTP secret: {e:?}"))?;
    // The `otpauth` feature requires issuer + account_name; both are
    // only consumed when `to_url()` is called (we never do server-side),
    // so placeholder values are fine.
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        bytes,
        Some("hekate".to_string()),
        "hekate".to_string(),
    )
    .map_err(|e| anyhow::anyhow!("init TOTP: {e}"))
}

/// Generate a fresh 20-byte (160-bit) base32 secret.
fn fresh_totp_secret_b32() -> String {
    let mut raw = [0u8; 20];
    OsRng.fill_bytes(&mut raw);
    Secret::Raw(raw.to_vec()).to_encoded().to_string()
}

/// Decode + verify the master_password_hash supplied for re-auth on
/// every privileged 2FA endpoint.
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

/// Probe whether the user already has 2FA enabled. Used both at the
/// status endpoint and in the identity grant to decide whether to
/// short-circuit into the challenge dance.
pub(crate) async fn lookup_totp_secret(
    state: &AppState,
    user_id: &str,
) -> Result<Option<String>, ApiError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT secret_b32 FROM two_factor_totp WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(row.map(|(s,)| s))
}

// ---- setup ---------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct TotpSetupRequest {
    /// Master password hash, base64-no-pad of 32 bytes. Re-auth so a
    /// stolen access token can't enable 2FA on someone else's account.
    pub master_password_hash: String,
    /// Email/account label rendered in the otpauth URL (and therefore
    /// in the user's authenticator app). Defaults to `"hekate"` if empty.
    #[serde(default)]
    pub account_label: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TotpSetupResponse {
    /// Base32-encoded TOTP secret. The client renders the `otpauth_url`
    /// as a QR code; this raw value is included so users can also type
    /// the secret manually.
    pub secret_b32: String,
    /// `otpauth://totp/<issuer>:<label>?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30`
    pub otpauth_url: String,
    /// Plaintext recovery codes shown ONCE. The CLI MUST surface them
    /// to the user before calling `confirm`. After enrollment commits,
    /// the server only retains Argon2id PHCs.
    pub recovery_codes: Vec<String>,
}

/// Phase 1 of TOTP enrollment. Generates the secret + recovery codes
/// and stages them in `two_factor_totp_pending`. Nothing is active
/// until the user proves they can read a code from their authenticator
/// via `confirm`.
#[utoipa::path(
    post,
    path = "/api/v1/account/2fa/totp/setup",
    tag = "two-factor",
    request_body = TotpSetupRequest,
    responses(
        (status = 200, description = "Pending enrollment created", body = TotpSetupResponse),
        (status = 401, description = "Master password is wrong"),
        (status = 409, description = "TOTP already enabled — disable first"),
    ),
    security(("bearerAuth" = [])),
)]
async fn totp_setup(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<TotpSetupRequest>,
) -> Result<Json<TotpSetupResponse>, ApiError> {
    require_master_password(&state, &user.user_id, &req.master_password_hash).await?;

    if lookup_totp_secret(&state, &user.user_id).await?.is_some() {
        return Err(ApiError::conflict("TOTP already enabled"));
    }

    let secret_b32 = fresh_totp_secret_b32();
    let (plaintexts, phcs) =
        mint_recovery_codes().map_err(|e| ApiError::internal(e.to_string()))?;
    let code_phcs_blob = phcs.join("\n");
    let now = chrono::Utc::now();
    let expires_at = (now + chrono::Duration::seconds(PENDING_ENROLL_TTL_SECS)).to_rfc3339();
    let now_str = now.to_rfc3339();

    // Upsert the pending row — replacing any earlier abandoned attempt
    // for this user. SQLite + Postgres both accept `INSERT ... ON CONFLICT`.
    sqlx::query(
        "INSERT INTO two_factor_totp_pending
            (user_id, secret_b32, code_phcs, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (user_id) DO UPDATE SET
            secret_b32 = EXCLUDED.secret_b32,
            code_phcs  = EXCLUDED.code_phcs,
            created_at = EXCLUDED.created_at,
            expires_at = EXCLUDED.expires_at",
    )
    .bind(&user.user_id)
    .bind(&secret_b32)
    .bind(&code_phcs_blob)
    .bind(&now_str)
    .bind(&expires_at)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let label = if req.account_label.trim().is_empty() {
        "hekate".to_string()
    } else {
        req.account_label.trim().to_string()
    };
    let otpauth_url = format!(
        "otpauth://totp/hekate:{}?secret={}&issuer=hekate&algorithm=SHA1&digits=6&period=30",
        urlencode(&label),
        secret_b32,
    );

    Ok(Json(TotpSetupResponse {
        secret_b32,
        otpauth_url,
        recovery_codes: plaintexts,
    }))
}

fn urlencode(s: &str) -> String {
    // Lightweight: escape only the characters that would break a query
    // string. otpauth labels are typically email addresses.
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~' => out.push(c),
            _ => {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).bytes() {
                    out.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    out
}

// ---- confirm -------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct TotpConfirmRequest {
    /// 6-digit TOTP code from the user's authenticator. Server verifies
    /// against the pending secret with ±1 period of clock skew.
    pub totp_code: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TotpConfirmResponse {
    /// Number of recovery codes minted. Always equals
    /// `RECOVERY_CODE_COUNT` on success — included so the client can
    /// sanity-check before showing them as committed.
    pub recovery_codes_count: u32,
    /// New access token. The previous access tokens for this user are
    /// invalidated immediately by the rotated `security_stamp`.
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    /// New refresh token in a fresh family. All prior refresh tokens
    /// for this user are revoked atomically with the enrollment.
    pub refresh_token: String,
}

/// Phase 2: verify the TOTP code, commit the secret + Argon2id PHCs of
/// the recovery codes, rotate the security_stamp, revoke all other
/// refresh tokens, and issue fresh tokens for the caller.
#[utoipa::path(
    post,
    path = "/api/v1/account/2fa/totp/confirm",
    tag = "two-factor",
    request_body = TotpConfirmRequest,
    responses(
        (status = 200, description = "2FA enrolled", body = TotpConfirmResponse),
        (status = 400, description = "Wrong TOTP code, no pending enrollment, or pending expired"),
    ),
    security(("bearerAuth" = [])),
)]
async fn totp_confirm(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<TotpConfirmRequest>,
) -> Result<Json<TotpConfirmResponse>, ApiError> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT secret_b32, code_phcs, expires_at
         FROM two_factor_totp_pending WHERE user_id = $1",
    )
    .bind(&user.user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some((secret_b32, code_phcs, expires_at)) = row else {
        return Err(ApiError::bad_request(
            "no pending TOTP enrollment — call /setup first",
        ));
    };

    let expires = chrono::DateTime::parse_from_rfc3339(&expires_at)
        .map_err(|e| ApiError::internal(format!("bad expires_at: {e}")))?;
    if chrono::Utc::now() > expires {
        // Expired — drop the stale row so the next /setup is clean.
        let _ = sqlx::query("DELETE FROM two_factor_totp_pending WHERE user_id = $1")
            .bind(&user.user_id)
            .execute(state.db.pool())
            .await;
        return Err(ApiError::bad_request(
            "pending enrollment expired — call /setup again",
        ));
    }

    let totp = build_totp(&secret_b32).map_err(|e| ApiError::internal(e.to_string()))?;
    let code_str = req.totp_code.trim().to_string();
    if !totp
        .check_current(&code_str)
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::bad_request(
            "TOTP code did not verify against pending secret",
        ));
    }

    // Commit atomically: insert the active TOTP row + all recovery rows,
    // delete the pending row, rotate stamp, revoke other refresh tokens.
    let new_stamp = Uuid::now_v7().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    sqlx::query(
        "INSERT INTO two_factor_totp (user_id, secret_b32, enabled_at) VALUES ($1, $2, $3)",
    )
    .bind(&user.user_id)
    .bind(&secret_b32)
    .bind(&now)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    for phc in code_phcs.split('\n').filter(|p| !p.is_empty()) {
        sqlx::query(
            "INSERT INTO two_factor_recovery_codes (id, user_id, code_phc, created_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(&user.user_id)
        .bind(phc)
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    }

    sqlx::query("DELETE FROM two_factor_totp_pending WHERE user_id = $1")
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    sqlx::query("UPDATE users SET security_stamp = $1, revision_date = $2 WHERE id = $3")
        .bind(&new_stamp)
        .bind(&now)
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = $1
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

    let (access_token, expires_in) = state
        .signer
        .issue_access_token(&user.user_id, &new_stamp)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let new_refresh = crate::auth::refresh::issue_new_family(state.db.pool(), &user.user_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(TotpConfirmResponse {
        recovery_codes_count: RECOVERY_CODE_COUNT as u32,
        access_token,
        token_type: "Bearer",
        expires_in,
        refresh_token: new_refresh.token,
    }))
}

// ---- disable -------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct TotpDisableRequest {
    pub master_password_hash: String,
}

/// Drop the user's 2FA enrollment + all recovery codes (consumed and
/// unconsumed). Rotates `security_stamp`, revoking all other sessions.
#[utoipa::path(
    post,
    path = "/api/v1/account/2fa/totp/disable",
    tag = "two-factor",
    request_body = TotpDisableRequest,
    responses(
        (status = 204, description = "2FA disabled"),
        (status = 401, description = "Master password is wrong"),
    ),
    security(("bearerAuth" = [])),
)]
async fn totp_disable(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<TotpDisableRequest>,
) -> Result<StatusCode, ApiError> {
    require_master_password(&state, &user.user_id, &req.master_password_hash).await?;

    let new_stamp = Uuid::now_v7().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    sqlx::query("DELETE FROM two_factor_totp WHERE user_id = $1")
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    sqlx::query("DELETE FROM two_factor_totp_pending WHERE user_id = $1")
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    sqlx::query("DELETE FROM two_factor_recovery_codes WHERE user_id = $1")
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    sqlx::query("UPDATE users SET security_stamp = $1, revision_date = $2 WHERE id = $3")
        .bind(&new_stamp)
        .bind(&now)
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- recovery codes regenerate ------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct RecoveryRegenerateRequest {
    pub master_password_hash: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RecoveryRegenerateResponse {
    /// Plaintext recovery codes shown ONCE. Replaces every prior code
    /// (consumed and unconsumed). No key material is rotated.
    pub recovery_codes: Vec<String>,
}

/// Burn all existing recovery codes and mint `RECOVERY_CODE_COUNT` new
/// ones. Master-password re-auth required. Does NOT rotate
/// `security_stamp` — recovery codes don't grant decryption, so no key
/// invalidation chain applies.
#[utoipa::path(
    post,
    path = "/api/v1/account/2fa/recovery-codes/regenerate",
    tag = "two-factor",
    request_body = RecoveryRegenerateRequest,
    responses(
        (status = 200, description = "Codes rotated", body = RecoveryRegenerateResponse),
        (status = 400, description = "2FA is not enabled"),
        (status = 401, description = "Master password is wrong"),
    ),
    security(("bearerAuth" = [])),
)]
async fn recovery_regenerate(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<RecoveryRegenerateRequest>,
) -> Result<Json<RecoveryRegenerateResponse>, ApiError> {
    require_master_password(&state, &user.user_id, &req.master_password_hash).await?;
    if lookup_totp_secret(&state, &user.user_id).await?.is_none() {
        return Err(ApiError::bad_request(
            "2FA is not enabled — recovery codes are scoped to TOTP",
        ));
    }

    let (plaintexts, phcs) =
        mint_recovery_codes().map_err(|e| ApiError::internal(e.to_string()))?;
    let now = chrono::Utc::now().to_rfc3339();

    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    sqlx::query("DELETE FROM two_factor_recovery_codes WHERE user_id = $1")
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    for phc in &phcs {
        sqlx::query(
            "INSERT INTO two_factor_recovery_codes (id, user_id, code_phc, created_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(&user.user_id)
        .bind(phc)
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    }
    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(RecoveryRegenerateResponse {
        recovery_codes: plaintexts,
    }))
}

// ---- status --------------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct StatusResponse {
    pub enabled: bool,
    pub recovery_codes_remaining: u32,
}

/// Cheap probe — does the caller have 2FA enabled, and if so, how many
/// unconsumed recovery codes remain. Clients should nag when remaining
/// is small (≤ 3 is the typical threshold).
#[utoipa::path(
    get,
    path = "/api/v1/account/2fa/status",
    tag = "two-factor",
    responses((status = 200, description = "2FA status", body = StatusResponse)),
    security(("bearerAuth" = [])),
)]
async fn status(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<StatusResponse>, ApiError> {
    let enabled = lookup_totp_secret(&state, &user.user_id).await?.is_some();
    let remaining: i64 = if enabled {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM two_factor_recovery_codes
             WHERE user_id = $1 AND consumed_at IS NULL",
        )
        .bind(&user.user_id)
        .fetch_one(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
        row.0
    } else {
        0
    };
    Ok(Json(StatusResponse {
        enabled,
        recovery_codes_remaining: remaining as u32,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_dashes_whitespace_uppercases() {
        assert_eq!(
            normalize_recovery_code("abcd-efgh-ijkl-mnop"),
            "ABCDEFGHIJKLMNOP"
        );
        assert_eq!(
            normalize_recovery_code("  AbCd EfGh\nIjKl-MnOp  "),
            "ABCDEFGHIJKLMNOP"
        );
    }

    #[test]
    fn format_recovery_code_inserts_dashes() {
        assert_eq!(
            format_recovery_code("ABCDEFGHIJKLMNOP"),
            "ABCD-EFGH-IJKL-MNOP"
        );
    }

    #[test]
    fn generated_recovery_codes_are_alphabet_only() {
        for _ in 0..50 {
            let code = generate_recovery_code();
            assert_eq!(code.len(), RECOVERY_CODE_LEN);
            for c in code.chars() {
                assert!(
                    BASE32_ALPHABET.contains(&(c as u8)),
                    "char {c} not in base32 alphabet"
                );
            }
        }
    }

    #[test]
    fn fresh_secret_decodes_to_20_bytes() {
        let s = fresh_totp_secret_b32();
        let bytes = Secret::Encoded(s).to_bytes().unwrap();
        assert_eq!(bytes.len(), 20);
    }
}
