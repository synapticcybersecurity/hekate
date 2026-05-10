//! Personal Access Token management.
//!
//! Requires `account:admin` scope. PATs are scoped at issue time and can
//! never exceed the issuer's permissions; for an interactive session
//! (JWT, ScopeSet::All) this is unrestricted.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::post,
    Router,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    auth::{pat, scope, AuthUser},
    routes::accounts::ApiError,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/account/tokens", post(create).get(list))
        .route("/api/v1/account/tokens/{id}", axum::routing::delete(revoke))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRequest {
    /// Human-readable label.
    #[schema(example = "ci-script")]
    pub name: String,
    /// Comma-separated scope list. Available: `vault:read`, `vault:write`, `account:admin`.
    #[schema(example = "vault:read,vault:write")]
    pub scopes: String,
    /// Days until the token expires. Omit / null for never-expires.
    #[serde(default)]
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateResponse {
    pub id: String,
    /// **Only returned once.** The wire-form bearer token
    /// (`pmgr_pat_<id>.<secret>`) — store it now.
    pub token: String,
    pub name: String,
    pub scopes: String,
    pub expires_at: Option<String>,
}

/// Issue a new Personal Access Token. Requires `account:admin`. The
/// secret is returned **only once** — store it immediately.
#[utoipa::path(
    post,
    path = "/api/v1/account/tokens",
    tag = "tokens",
    request_body = CreateRequest,
    responses(
        (status = 201, description = "Created", body = CreateResponse),
        (status = 400, description = "Invalid scope"),
        (status = 403, description = "Lacks account:admin or requested scope"),
    ),
    security(("bearerAuth" = [])),
)]
async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateRequest>,
) -> Result<(StatusCode, Json<CreateResponse>), ApiError> {
    user.require(scope::ACCOUNT_ADMIN)?;

    if req.name.trim().is_empty() {
        return Err(ApiError::bad_request("name is required"));
    }
    let requested = scope::parse_requested_scopes(&req.scopes).map_err(ApiError::bad_request)?;
    // The token cannot exceed the issuer's permissions.
    for s in &requested {
        if !user.scopes.permits(s) {
            return Err(ApiError::forbidden(format!(
                "issuing user lacks scope `{s}`"
            )));
        }
    }
    let scopes_csv = {
        let mut v: Vec<&String> = requested.iter().collect();
        v.sort();
        v.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")
    };

    let expires_at = req
        .expires_in_days
        .map(|d| (Utc::now() + Duration::days(d)).to_rfc3339());

    let issued = pat::issue(
        state.db.pool(),
        &user.user_id,
        req.name.trim(),
        &scopes_csv,
        expires_at.as_deref(),
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        Json(CreateResponse {
            id: issued.id,
            token: issued.wire_token,
            name: req.name.trim().to_string(),
            scopes: scopes_csv,
            expires_at,
        }),
    ))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ListItem {
    pub id: String,
    pub name: String,
    pub scopes: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub last_used_at: Option<String>,
}

/// List your PATs (metadata only — secrets are never returned again).
/// Requires `account:admin`.
#[utoipa::path(
    get,
    path = "/api/v1/account/tokens",
    tag = "tokens",
    responses((status = 200, description = "OK", body = Vec<ListItem>)),
    security(("bearerAuth" = [])),
)]
async fn list(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<Vec<ListItem>>, ApiError> {
    user.require(scope::ACCOUNT_ADMIN)?;

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
             FROM personal_access_tokens
             WHERE user_id = $1
             ORDER BY created_at DESC",
    )
    .bind(&user.user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let items = rows
        .into_iter()
        .map(
            |(id, name, scopes, created_at, expires_at, revoked_at, last_used_at)| ListItem {
                id,
                name,
                scopes,
                created_at,
                expires_at,
                revoked_at,
                last_used_at,
            },
        )
        .collect();
    Ok(Json(items))
}

/// Revoke a PAT immediately. Requires `account:admin`.
#[utoipa::path(
    delete,
    path = "/api/v1/account/tokens/{id}",
    tag = "tokens",
    params(("id" = String, Path)),
    responses(
        (status = 204, description = "Revoked"),
        (status = 404, description = "Not found"),
    ),
    security(("bearerAuth" = [])),
)]
async fn revoke(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    user.require(scope::ACCOUNT_ADMIN)?;
    let revoked = pat::revoke(state.db.pool(), &user.user_id, &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if !revoked {
        return Err(ApiError::not_found("token not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}
