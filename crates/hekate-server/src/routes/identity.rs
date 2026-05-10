//! OAuth 2.0 token endpoint. Supports `grant_type=password` and
//! `grant_type=refresh_token`.
//!
//! Password grants flow through an optional 2FA challenge (M2.22): if
//! the user has TOTP enabled, the first call returns 401 +
//! `two_factor_required` + a 5-minute challenge JWT; the client retries
//! with the challenge token + provider + value. Refresh grants do NOT
//! gate on 2FA — the second factor is bound at the password leg only,
//! same as Bitwarden.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::post,
    Form, Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::{
    auth::{password, refresh},
    routes::{accounts::ApiError, two_factor, two_factor_webauthn},
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new().route("/identity/connect/token", post(token))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TokenRequest {
    /// `password` or `refresh_token`.
    #[schema(example = "password")]
    pub grant_type: String,
    /// For grant_type=password — the user's email.
    #[schema(example = "alice@example.com")]
    pub username: Option<String>,
    /// For grant_type=password — base64-no-pad master_password_hash (32 bytes).
    pub password: Option<String>,
    /// For grant_type=refresh_token — `<id>.<secret>` from a prior login.
    pub refresh_token: Option<String>,
    /// 2FA challenge JWT returned by the previous 401 from this endpoint.
    /// Required when the user has TOTP enabled. Bound to (user_id,
    /// security_stamp) at issue time.
    pub two_factor_token: Option<String>,
    /// `"totp"` or `"recovery"`. Required when `two_factor_token` is set.
    pub two_factor_provider: Option<String>,
    /// 6-digit TOTP code or 16-char recovery code (any case, dashes
    /// optional). Required when `two_factor_token` is set.
    pub two_factor_value: Option<String>,
}

/// Body returned with HTTP 401 when the user has 2FA enabled and the
/// password leg succeeded. The client is expected to prompt for the
/// second factor and retry the password grant with `two_factor_token`,
/// `two_factor_provider`, `two_factor_value` set.
#[derive(Debug, Serialize, ToSchema)]
pub struct TwoFactorChallenge {
    /// Always `"two_factor_required"`.
    pub error: &'static str,
    /// Provider names the user has enrolled. M2.22 shipped `"totp"` +
    /// `"recovery"`; M2.23 adds `"webauthn"`. Order is informational —
    /// clients pick whichever they can satisfy.
    pub two_factor_providers: Vec<&'static str>,
    /// Short-lived JWT (`purpose="tfa"`, 5-min TTL) bound to
    /// `(user_id, security_stamp)`. Echo back on the retry.
    pub two_factor_token: String,
    /// `RequestChallengeResponse` JSON when `"webauthn"` is in
    /// `two_factor_providers` — clients pass this straight to
    /// `navigator.credentials.get({ publicKey: ... })`. Absent
    /// otherwise so the field is opt-in.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Object)]
    pub webauthn_challenge: Option<Value>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    /// 1-hour HS256 JWT for `Authorization: Bearer …`.
    pub access_token: String,
    /// Always `"Bearer"`.
    pub token_type: &'static str,
    /// Access token TTL in seconds.
    pub expires_in: u64,
    /// Single-use rolling refresh token; URL-safe base64.
    pub refresh_token: String,

    /// Returned only on initial password grant; absent on refresh.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Object)]
    pub kdf_params: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_salt: Option<String>,
    /// 32-byte MAC binding `kdf_params`+`kdf_salt` to the master key. Only
    /// populated on the initial password grant; clients persist this for
    /// future verifications and refuse to derive a new master_password_hash
    /// without re-validating it (BW07/LP04).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_params_mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_account_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_account_private_key: Option<String>,
    /// Server-stable user_id (UUIDv7). Returned on initial password grant
    /// so clients can persist it locally — needed for pinning peers'
    /// pubkey bundles (M2.19/M2.20). Absent on refresh.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

const DUMMY_PHC: &str = "$argon2id$v=19$m=65536,t=3,p=4$YWFhYWFhYWFhYWFhYWFhYQ$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxw";

/// OAuth 2.0 token endpoint. Form-encoded body. Two grant types
/// supported: `password` (returns access + refresh + account material)
/// and `refresh_token` (returns access + refresh only).
#[utoipa::path(
    post,
    path = "/identity/connect/token",
    tag = "identity",
    request_body(content = TokenRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Tokens issued", body = TokenResponse),
        (status = 400, description = "Bad request", body = crate::routes::accounts::ErrorResponse),
        (status = 401, description = "Invalid credentials or refresh token", body = crate::routes::accounts::ErrorResponse),
    ),
)]
async fn token(State(state): State<AppState>, Form(req): Form<TokenRequest>) -> Response {
    match req.grant_type.as_str() {
        "password" => password_grant(state, req).await,
        "refresh_token" => match refresh_grant(state, req).await {
            Ok(json) => json.into_response(),
            Err(e) => e.into_response(),
        },
        other => ApiError::bad_request(format!("unsupported grant_type: {other}")).into_response(),
    }
}

/// Extracted from the `password_grant` flow so the 2FA-required and
/// 2FA-supplied paths share a single code path: both must re-verify
/// the password (defense in depth) before the second factor is even
/// looked at.
async fn password_grant(state: AppState, req: TokenRequest) -> Response {
    match password_grant_inner(state, req).await {
        Ok(Continuation::Issue(resp)) => Json(resp).into_response(),
        Ok(Continuation::TwoFactor(ch)) => (StatusCode::UNAUTHORIZED, Json(ch)).into_response(),
        Err(e) => e.into_response(),
    }
}

enum Continuation {
    Issue(TokenResponse),
    TwoFactor(TwoFactorChallenge),
}

async fn password_grant_inner(
    state: AppState,
    req: TokenRequest,
) -> Result<Continuation, ApiError> {
    let email = req
        .username
        .ok_or_else(|| ApiError::bad_request("missing username"))?
        .trim()
        .to_lowercase();
    let password_b64 = req
        .password
        .ok_or_else(|| ApiError::bad_request("missing password"))?;
    let mph = STANDARD_NO_PAD
        .decode(password_b64)
        .map_err(|_| ApiError::bad_request("password is not base64-no-pad"))?;
    if mph.len() != 32 {
        return Err(ApiError::bad_request("password must be 32 bytes"));
    }

    #[allow(clippy::type_complexity)]
    let row: Option<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT id, master_password_hash, kdf_params, kdf_salt, kdf_params_mac,
                protected_account_key, account_public_key,
                protected_account_private_key, security_stamp
         FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let Some((
        user_id,
        stored_phc,
        kdf_params_str,
        kdf_salt,
        kdf_params_mac,
        protected_account_key,
        account_public_key,
        protected_account_private_key,
        security_stamp,
    )) = row
    else {
        let _ = password::verify(&mph, DUMMY_PHC);
        return Err(ApiError::unauthorized("invalid credentials"));
    };

    if !password::verify(&mph, &stored_phc) {
        return Err(ApiError::unauthorized("invalid credentials"));
    }

    // 2FA gate. The user is in 2FA flow if they have *any* second
    // factor enrolled (TOTP, WebAuthn, or both — recovery codes are
    // gated on TOTP enrollment per M2.22).
    let totp_secret = two_factor::lookup_totp_secret(&state, &user_id).await?;
    let has_webauthn = two_factor_webauthn::has_credentials(&state, &user_id).await?;
    if totp_secret.is_some() || has_webauthn {
        let providers = enrolled_providers(totp_secret.is_some(), has_webauthn);
        match req.two_factor_token.as_deref() {
            None => {
                // First leg — issue the challenge.
                let challenge_jwt = state
                    .signer
                    .issue_tfa_challenge_token(&user_id, &security_stamp)
                    .map_err(|e| ApiError::internal(e.to_string()))?;
                let webauthn_challenge = if has_webauthn {
                    let rcr = two_factor_webauthn::start_login_challenge(&state, &user_id).await?;
                    Some(serde_json::to_value(rcr).map_err(|e| ApiError::internal(e.to_string()))?)
                } else {
                    None
                };
                return Ok(Continuation::TwoFactor(TwoFactorChallenge {
                    error: "two_factor_required",
                    two_factor_providers: providers,
                    two_factor_token: challenge_jwt,
                    webauthn_challenge,
                }));
            }
            Some(token) => {
                // Second leg — verify the challenge token, then the factor.
                let claims = state
                    .signer
                    .verify_tfa_challenge(token)
                    .map_err(|_| ApiError::unauthorized("invalid two_factor_token"))?;
                if claims.sub != user_id || claims.stamp != security_stamp {
                    return Err(ApiError::unauthorized(
                        "two_factor_token does not match credentials",
                    ));
                }
                let provider = req
                    .two_factor_provider
                    .as_deref()
                    .ok_or_else(|| ApiError::bad_request("missing two_factor_provider"))?;
                let value = req
                    .two_factor_value
                    .as_deref()
                    .ok_or_else(|| ApiError::bad_request("missing two_factor_value"))?;
                verify_second_factor(&state, &user_id, provider, value, totp_secret.as_deref())
                    .await?;
            }
        }
    }

    let (access_token, expires_in) = state
        .signer
        .issue_access_token(&user_id, &security_stamp)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let refresh = refresh::issue_new_family(state.db.pool(), &user_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let kdf_params: Value =
        serde_json::from_str(&kdf_params_str).map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Continuation::Issue(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        refresh_token: refresh.token,
        kdf_params: Some(kdf_params),
        kdf_salt: Some(kdf_salt),
        kdf_params_mac: Some(kdf_params_mac),
        protected_account_key: Some(protected_account_key),
        account_public_key: Some(account_public_key),
        protected_account_private_key: Some(protected_account_private_key),
        user_id: Some(user_id),
    }))
}

fn enrolled_providers(has_totp: bool, has_webauthn: bool) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = Vec::with_capacity(3);
    if has_webauthn {
        v.push("webauthn");
    }
    if has_totp {
        v.push("totp");
        // Recovery codes are only useful when TOTP is the primary
        // factor. M2.22 made enrollment of recovery codes part of the
        // TOTP setup flow; WebAuthn enrollment doesn't mint new codes.
        // Surface "recovery" alongside TOTP so users know it's an
        // option; if a WebAuthn-only user ever needs recovery, they
        // need to enable TOTP first.
        v.push("recovery");
    }
    v
}

/// Verify the supplied 2FA factor.
/// - TOTP: ±1 step skew + monotonic `last_used_period` replay block.
/// - Recovery: Argon2id PHC compare across unconsumed codes; atomic
///   single-use consume on match.
/// - WebAuthn: take the pending PasskeyAuthentication state, verify
///   the assertion under the stored Passkey, advance sign_counter +
///   last_used_at on success.
async fn verify_second_factor(
    state: &AppState,
    user_id: &str,
    provider: &str,
    value: &str,
    totp_secret_b32: Option<&str>,
) -> Result<(), ApiError> {
    match provider {
        "totp" => {
            let secret = totp_secret_b32
                .ok_or_else(|| ApiError::bad_request("TOTP is not enrolled for this user"))?;
            verify_totp(state, user_id, value, secret).await
        }
        "recovery" => verify_recovery(state, user_id, value).await,
        "webauthn" => {
            let credential: Value = serde_json::from_str(value).map_err(|e| {
                ApiError::bad_request(format!("two_factor_value is not valid JSON: {e}"))
            })?;
            two_factor_webauthn::finish_login_assertion(state, user_id, credential).await
        }
        other => Err(ApiError::bad_request(format!(
            "unsupported two_factor_provider: {other}"
        ))),
    }
}

async fn verify_totp(
    state: &AppState,
    user_id: &str,
    code: &str,
    secret_b32: &str,
) -> Result<(), ApiError> {
    let totp = two_factor::build_totp(secret_b32).map_err(|e| ApiError::internal(e.to_string()))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ApiError::internal(e.to_string()))?
        .as_secs();
    let current_period = (now / 30) as i64;

    // Accept ±1 step. We compute candidates explicitly so we can store
    // the highest accepted period and refuse re-use of an earlier one
    // within its 90-second window.
    let candidates: [i64; 3] = [current_period - 1, current_period, current_period + 1];
    let trimmed = code.trim();
    let mut matched: Option<i64> = None;
    for &p in &candidates {
        if p < 0 {
            continue;
        }
        let t = (p as u64) * 30;
        let generated = totp.generate(t);
        if subtle::ConstantTimeEq::ct_eq(generated.as_bytes(), trimmed.as_bytes()).unwrap_u8() == 1
        {
            matched = Some(p);
            break;
        }
    }
    let Some(period) = matched else {
        return Err(ApiError::unauthorized("invalid TOTP code"));
    };

    // Replay block: if the row's last_used_period is >= matched, refuse.
    // Otherwise advance it. Single statement so concurrent logins race
    // safely on the WHERE.
    let updated = sqlx::query(
        "UPDATE two_factor_totp
         SET last_used_period = $1
         WHERE user_id = $2
           AND (last_used_period IS NULL OR last_used_period < $1)",
    )
    .bind(period)
    .bind(user_id)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::unauthorized(
            "TOTP code already consumed within its window",
        ));
    }
    Ok(())
}

async fn verify_recovery(state: &AppState, user_id: &str, presented: &str) -> Result<(), ApiError> {
    let normalized = two_factor::normalize_recovery_code(presented);
    if normalized.is_empty() {
        return Err(ApiError::bad_request("empty recovery code"));
    }

    // Walk only the unconsumed rows. Worst case: 10 Argon2id-verifies.
    // Argon2id at the server-side params (~80 ms) keeps the worst case
    // under a second — acceptable for a recovery flow.
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, code_phc FROM two_factor_recovery_codes
         WHERE user_id = $1 AND consumed_at IS NULL",
    )
    .bind(user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let normalized_bytes = normalized.as_bytes();
    let mut matched_id: Option<String> = None;
    for (id, phc) in &rows {
        if password::verify(normalized_bytes, phc) {
            matched_id = Some(id.clone());
            break;
        }
    }
    let Some(id) = matched_id else {
        return Err(ApiError::unauthorized("invalid recovery code"));
    };

    // Atomic consume — refuse if a concurrent request already burned it.
    let now = chrono::Utc::now().to_rfc3339();
    let res = sqlx::query(
        "UPDATE two_factor_recovery_codes
         SET consumed_at = $1
         WHERE id = $2 AND consumed_at IS NULL",
    )
    .bind(&now)
    .bind(&id)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    if res.rows_affected() == 0 {
        return Err(ApiError::unauthorized("recovery code already consumed"));
    }
    tracing::info!(user_id, code_id = %id, "2fa recovery code redeemed");
    Ok(())
}

async fn refresh_grant(
    state: AppState,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, ApiError> {
    let presented = req
        .refresh_token
        .ok_or_else(|| ApiError::bad_request("missing refresh_token"))?;

    let outcome = refresh::rotate(state.db.pool(), &presented)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let (user_id, new) = match outcome {
        refresh::RotateOutcome::Ok { user_id, new_token } => (user_id, new_token),
        refresh::RotateOutcome::Reused => {
            return Err(ApiError::unauthorized(
                "refresh token replayed; family revoked",
            ));
        }
        refresh::RotateOutcome::Invalid => {
            return Err(ApiError::unauthorized("invalid refresh_token"));
        }
    };

    // Look up the current security_stamp so the new JWT remains valid as
    // long as no privileged action invalidates it.
    let stamp_row: Option<(String,)> =
        sqlx::query_as("SELECT security_stamp FROM users WHERE id = $1")
            .bind(&user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let security_stamp = stamp_row
        .ok_or_else(|| ApiError::unauthorized("user no longer exists"))?
        .0;

    let (access_token, expires_in) = state
        .signer
        .issue_access_token(&user_id, &security_stamp)
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        refresh_token: new.token,
        kdf_params: None,
        kdf_salt: None,
        kdf_params_mac: None,
        protected_account_key: None,
        account_public_key: None,
        protected_account_private_key: None,
        user_id: None,
    }))
}
