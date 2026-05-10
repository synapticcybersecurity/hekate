//! Service-account lifecycle (M2.5). Org-owner-only management of
//! org-scoped machine identities. See `auth/sat.rs` for the wire
//! format and verification path; this module handles the human-driven
//! create / list / disable / delete + token issue / list / revoke
//! flows.
//!
//! Routes:
//! - `POST  /api/v1/orgs/{org_id}/service-accounts` (owner)
//! - `GET   /api/v1/orgs/{org_id}/service-accounts` (owner)
//! - `POST  /api/v1/orgs/{org_id}/service-accounts/{sa_id}/disable` (owner)
//! - `DELETE /api/v1/orgs/{org_id}/service-accounts/{sa_id}` (owner)
//! - `POST  /api/v1/orgs/{org_id}/service-accounts/{sa_id}/tokens` (owner)
//! - `GET   /api/v1/orgs/{org_id}/service-accounts/{sa_id}/tokens` (owner)
//! - `DELETE /api/v1/orgs/{org_id}/service-accounts/{sa_id}/tokens/{token_id}` (owner)
//! - `GET   /api/v1/service-accounts/me` (SA-token, introspection)

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    auth::{sat, scope, AuthService, AuthUser},
    routes::accounts::ApiError,
    AppState,
};

const NAME_MAX: usize = 64;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/orgs/{org_id}/service-accounts",
            post(create_sa).get(list_sa),
        )
        .route(
            "/api/v1/orgs/{org_id}/service-accounts/{sa_id}/disable",
            post(disable_sa),
        )
        .route(
            "/api/v1/orgs/{org_id}/service-accounts/{sa_id}",
            delete(delete_sa),
        )
        .route(
            "/api/v1/orgs/{org_id}/service-accounts/{sa_id}/tokens",
            post(create_token).get(list_tokens),
        )
        .route(
            "/api/v1/orgs/{org_id}/service-accounts/{sa_id}/tokens/{token_id}",
            delete(revoke_token),
        )
        .route("/api/v1/service-accounts/me", get(me))
}

// ---- shared owner check -------------------------------------------------

/// Returns Ok(()) iff `user_id` is the owner of `org_id`. Single source
/// of truth for the SA management routes' permission gate.
async fn require_org_owner(state: &AppState, user_id: &str, org_id: &str) -> Result<(), ApiError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT owner_user_id FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some((owner_id,)) = row else {
        return Err(ApiError::not_found("organization not found"));
    };
    if owner_id != user_id {
        return Err(ApiError::forbidden(
            "only the organization owner may manage service accounts",
        ));
    }
    Ok(())
}

async fn require_sa_in_org(state: &AppState, sa_id: &str, org_id: &str) -> Result<(), ApiError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT org_id FROM service_accounts WHERE id = $1")
            .bind(sa_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some((stored_org,)) = row else {
        return Err(ApiError::not_found("service account not found"));
    };
    if stored_org != org_id {
        return Err(ApiError::not_found("service account not found"));
    }
    Ok(())
}

fn check_name(name: &str) -> Result<(), ApiError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > NAME_MAX {
        return Err(ApiError::bad_request(format!(
            "name must be 1..={NAME_MAX} characters"
        )));
    }
    Ok(())
}

// ---- create / list / disable / delete service accounts -----------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateServiceAccountRequest {
    pub name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceAccountView {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub created_by_user_id: String,
    pub created_at: String,
    pub disabled_at: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/orgs/{org_id}/service-accounts",
    tag = "service-accounts",
    request_body = CreateServiceAccountRequest,
    params(("org_id" = String, Path)),
    responses(
        (status = 201, description = "Created", body = ServiceAccountView),
        (status = 403, description = "Caller is not the org owner"),
        (status = 404, description = "Organization not found"),
    ),
    security(("bearerAuth" = [])),
)]
async fn create_sa(
    user: AuthUser,
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Json(req): Json<CreateServiceAccountRequest>,
) -> Result<(StatusCode, Json<ServiceAccountView>), ApiError> {
    check_name(&req.name)?;
    require_org_owner(&state, &user.user_id, &org_id).await?;

    let id = Uuid::now_v7().to_string();
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO service_accounts (id, org_id, name, created_by_user_id, created_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&id)
    .bind(&org_id)
    .bind(req.name.trim())
    .bind(&user.user_id)
    .bind(&now)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        Json(ServiceAccountView {
            id,
            org_id,
            name: req.name.trim().to_string(),
            created_by_user_id: user.user_id,
            created_at: now,
            disabled_at: None,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/orgs/{org_id}/service-accounts",
    tag = "service-accounts",
    params(("org_id" = String, Path)),
    responses(
        (status = 200, description = "OK", body = Vec<ServiceAccountView>),
        (status = 403, description = "Caller is not the org owner"),
    ),
    security(("bearerAuth" = [])),
)]
async fn list_sa(
    user: AuthUser,
    State(state): State<AppState>,
    Path(org_id): Path<String>,
) -> Result<Json<Vec<ServiceAccountView>>, ApiError> {
    require_org_owner(&state, &user.user_id, &org_id).await?;

    let rows: Vec<(String, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, name, created_by_user_id, created_at, disabled_at
         FROM service_accounts WHERE org_id = $1 ORDER BY created_at DESC",
    )
    .bind(&org_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(
        rows.into_iter()
            .map(
                |(id, name, created_by_user_id, created_at, disabled_at)| ServiceAccountView {
                    id,
                    org_id: org_id.clone(),
                    name,
                    created_by_user_id,
                    created_at,
                    disabled_at,
                },
            )
            .collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/orgs/{org_id}/service-accounts/{sa_id}/disable",
    tag = "service-accounts",
    params(("org_id" = String, Path), ("sa_id" = String, Path)),
    responses(
        (status = 204, description = "Disabled — every existing and future token is now invalid"),
        (status = 403, description = "Caller is not the org owner"),
        (status = 404, description = "Service account not found"),
    ),
    security(("bearerAuth" = [])),
)]
async fn disable_sa(
    user: AuthUser,
    State(state): State<AppState>,
    Path((org_id, sa_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    require_org_owner(&state, &user.user_id, &org_id).await?;
    require_sa_in_org(&state, &sa_id, &org_id).await?;
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE service_accounts SET disabled_at = $1
         WHERE id = $2 AND disabled_at IS NULL",
    )
    .bind(now)
    .bind(&sa_id)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/api/v1/orgs/{org_id}/service-accounts/{sa_id}",
    tag = "service-accounts",
    params(("org_id" = String, Path), ("sa_id" = String, Path)),
    responses(
        (status = 204, description = "Deleted — cascades to all tokens"),
        (status = 403, description = "Caller is not the org owner"),
        (status = 404, description = "Service account not found"),
    ),
    security(("bearerAuth" = [])),
)]
async fn delete_sa(
    user: AuthUser,
    State(state): State<AppState>,
    Path((org_id, sa_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    require_org_owner(&state, &user.user_id, &org_id).await?;
    let res = sqlx::query("DELETE FROM service_accounts WHERE id = $1 AND org_id = $2")
        .bind(&sa_id)
        .bind(&org_id)
        .execute(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("service account not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---- create / list / revoke tokens ----------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTokenRequest {
    pub name: String,
    /// Comma-separated scopes. M2.5 ships `org:read`. Future M6 work
    /// adds `secrets:read` / `secrets:write`. Each entry is validated
    /// against `ALL_SCOPES`.
    pub scopes: String,
    /// Days until expiry. Omit / null for no expiry.
    #[serde(default)]
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateTokenResponse {
    pub id: String,
    /// **Only returned once.** Wire format `pmgr_sat_<id>.<secret>`.
    pub token: String,
    pub name: String,
    pub scopes: String,
    pub expires_at: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/orgs/{org_id}/service-accounts/{sa_id}/tokens",
    tag = "service-accounts",
    request_body = CreateTokenRequest,
    params(("org_id" = String, Path), ("sa_id" = String, Path)),
    responses(
        (status = 201, description = "Created — token shown ONCE", body = CreateTokenResponse),
        (status = 400, description = "Bad name or scope"),
        (status = 403, description = "Caller is not the org owner"),
        (status = 404, description = "Service account not found"),
        (status = 409, description = "Service account is disabled"),
    ),
    security(("bearerAuth" = [])),
)]
async fn create_token(
    user: AuthUser,
    State(state): State<AppState>,
    Path((org_id, sa_id)): Path<(String, String)>,
    Json(req): Json<CreateTokenRequest>,
) -> Result<(StatusCode, Json<CreateTokenResponse>), ApiError> {
    check_name(&req.name)?;
    require_org_owner(&state, &user.user_id, &org_id).await?;
    require_sa_in_org(&state, &sa_id, &org_id).await?;

    // Refuse to issue a token against a disabled SA — even though the
    // token would already fail at verify(), this gives the user
    // immediate feedback rather than a silent dud.
    let disabled: Option<(Option<String>,)> =
        sqlx::query_as("SELECT disabled_at FROM service_accounts WHERE id = $1")
            .bind(&sa_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    if let Some((Some(_),)) = disabled {
        return Err(ApiError::conflict(
            "service account is disabled — re-enable before issuing tokens",
        ));
    }

    let requested = scope::parse_requested_scopes(&req.scopes).map_err(ApiError::bad_request)?;
    let scopes_csv = {
        let mut v: Vec<&String> = requested.iter().collect();
        v.sort();
        v.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")
    };
    let expires_at = req
        .expires_in_days
        .map(|d| (Utc::now() + Duration::days(d)).to_rfc3339());

    let issued = sat::issue(
        state.db.pool(),
        &sa_id,
        req.name.trim(),
        &scopes_csv,
        expires_at.as_deref(),
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        Json(CreateTokenResponse {
            id: issued.id,
            token: issued.wire_token,
            name: req.name.trim().to_string(),
            scopes: scopes_csv,
            expires_at,
        }),
    ))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenListItem {
    pub id: String,
    pub name: String,
    pub scopes: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub last_used_at: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/orgs/{org_id}/service-accounts/{sa_id}/tokens",
    tag = "service-accounts",
    params(("org_id" = String, Path), ("sa_id" = String, Path)),
    responses((status = 200, description = "OK", body = Vec<TokenListItem>)),
    security(("bearerAuth" = [])),
)]
async fn list_tokens(
    user: AuthUser,
    State(state): State<AppState>,
    Path((org_id, sa_id)): Path<(String, String)>,
) -> Result<Json<Vec<TokenListItem>>, ApiError> {
    require_org_owner(&state, &user.user_id, &org_id).await?;
    require_sa_in_org(&state, &sa_id, &org_id).await?;

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, name, scopes, created_at, expires_at, revoked_at, last_used_at
         FROM service_account_tokens
         WHERE service_account_id = $1
         ORDER BY created_at DESC",
    )
    .bind(&sa_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(
        rows.into_iter()
            .map(
                |(id, name, scopes, created_at, expires_at, revoked_at, last_used_at)| {
                    TokenListItem {
                        id,
                        name,
                        scopes,
                        created_at,
                        expires_at,
                        revoked_at,
                        last_used_at,
                    }
                },
            )
            .collect(),
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/orgs/{org_id}/service-accounts/{sa_id}/tokens/{token_id}",
    tag = "service-accounts",
    params(
        ("org_id" = String, Path),
        ("sa_id" = String, Path),
        ("token_id" = String, Path),
    ),
    responses(
        (status = 204, description = "Revoked"),
        (status = 404, description = "Token not found"),
    ),
    security(("bearerAuth" = [])),
)]
async fn revoke_token(
    user: AuthUser,
    State(state): State<AppState>,
    Path((org_id, sa_id, token_id)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    require_org_owner(&state, &user.user_id, &org_id).await?;
    require_sa_in_org(&state, &sa_id, &org_id).await?;
    let revoked = sat::revoke(state.db.pool(), &sa_id, &token_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if !revoked {
        return Err(ApiError::not_found("token not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---- introspection (consumed by the SA itself) -------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct MeResponse {
    pub service_account_id: String,
    pub org_id: String,
    pub token_id: String,
    pub scopes: String,
}

/// "Who am I" introspection for SA tokens. Lets a deployed agent
/// sanity-check that its token is valid and what it can do, without
/// having to attempt a real call. M2.5's only SA-callable endpoint;
/// M6 will add the Secrets Manager surface.
#[utoipa::path(
    get,
    path = "/api/v1/service-accounts/me",
    tag = "service-accounts",
    responses(
        (status = 200, description = "Identity + scopes", body = MeResponse),
        (status = 401, description = "No SA token"),
    ),
    security(("bearerAuth" = [])),
)]
async fn me(svc: AuthService) -> Result<Json<MeResponse>, ApiError> {
    Ok(Json(MeResponse {
        service_account_id: svc.service_account_id,
        org_id: svc.org_id,
        token_id: svc.token_id,
        scopes: svc.scopes.to_csv(),
    }))
}
