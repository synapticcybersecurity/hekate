//! Webhook subscription management. All endpoints require `account:admin`.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    auth::{scope, AuthUser},
    routes::accounts::ApiError,
    webhook_url::{resolve_safe, WebhookUrlError},
    webhooks::generate_secret_b64,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/account/webhooks", post(create).get(list))
        .route(
            "/api/v1/account/webhooks/{id}",
            axum::routing::delete(delete),
        )
        .route(
            "/api/v1/account/webhooks/{id}/deliveries",
            axum::routing::get(deliveries),
        )
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRequest {
    /// Human-readable label.
    #[schema(example = "ops-channel")]
    pub name: String,
    /// HTTPS endpoint that will receive POSTs.
    #[schema(example = "https://example.com/hooks/hekate")]
    pub url: String,
    /// Optional comma-separated event filter. Omit or `*` for all.
    /// Known kinds: `cipher.changed`, `cipher.deleted`, `cipher.tombstoned`,
    /// `folder.changed`, `folder.tombstoned`.
    #[serde(default)]
    pub events: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateResponse {
    pub id: String,
    pub name: String,
    pub url: String,
    pub events: String,
    /// HMAC secret. **Returned once** — store it now to verify incoming
    /// webhook signatures. Cannot be recovered later.
    pub secret: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookListItem {
    pub id: String,
    pub name: String,
    pub url: String,
    pub events: String,
    pub created_at: String,
    pub disabled_at: Option<String>,
}

/// Create a webhook subscription. The HMAC secret is returned **only at
/// creation time**.
#[utoipa::path(
    post,
    path = "/api/v1/account/webhooks",
    tag = "webhooks",
    request_body = CreateRequest,
    responses(
        (status = 201, description = "Created", body = CreateResponse),
        (status = 400, description = "Invalid input"),
        (status = 403, description = "Lacks account:admin"),
    ),
    security(("bearerAuth" = [])),
)]
async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateRequest>,
) -> Result<(StatusCode, Json<CreateResponse>), ApiError> {
    user.require(scope::ACCOUNT_ADMIN)?;
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("name is required"));
    }
    // Audit S-M5 (2026-05-07): cap webhooks per user. Combined with
    // S-H1 (no SSRF allowed) this caps the amplification a compromised
    // account_admin token can mount against any single destination.
    // 20 is generous for any realistic ops/notifications setup; bump
    // via config if a user genuinely needs more.
    const MAX_WEBHOOKS_PER_USER: i64 = 20;
    let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhooks WHERE user_id = $1")
        .bind(&user.user_id)
        .fetch_one(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if existing >= MAX_WEBHOOKS_PER_USER {
        return Err(ApiError::bad_request(format!(
            "webhook limit reached ({MAX_WEBHOOKS_PER_USER} per account); delete an unused subscription first"
        )));
    }
    // Audit S-H1 (2026-05-07): SSRF defense. Resolve the URL up front
    // and refuse private / loopback / link-local destinations (the
    // canonical targets for cloud-metadata + internal-admin probes).
    // We re-validate at every delivery attempt too — this gate is to
    // give the caller a clean 400 instead of letting a bogus webhook
    // sit in the table forever silently failing every dispatch.
    let url = req.url.trim();
    let allow_unsafe = state.config.webhooks_allow_unsafe_destinations;
    let _resolved = resolve_safe(url, allow_unsafe).await.map_err(|e| match e {
        WebhookUrlError::Parse(_)
        | WebhookUrlError::UnsupportedScheme
        | WebhookUrlError::NoHost => ApiError::bad_request(format!("invalid url: {e}")),
        WebhookUrlError::NonHttps => ApiError::bad_request(
            "webhook url must use https; set HEKATE_WEBHOOKS_ALLOW_UNSAFE_DESTINATIONS=true for dev",
        ),
        WebhookUrlError::NoIp | WebhookUrlError::Dns(_) => {
            ApiError::bad_request(format!("could not resolve webhook host: {e}"))
        }
        WebhookUrlError::BlockedIp(_) => {
            ApiError::bad_request(format!("webhook destination refused: {e}"))
        }
    })?;
    let events = req
        .events
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("*")
        .to_string();

    let id = Uuid::now_v7().to_string();
    let secret_b64 = generate_secret_b64();

    sqlx::query(
        "INSERT INTO webhooks (id, user_id, name, url, secret_b64, events)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(name)
    .bind(url)
    .bind(&secret_b64)
    .bind(&events)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        Json(CreateResponse {
            id,
            name: name.to_string(),
            url: url.to_string(),
            events,
            secret: secret_b64,
        }),
    ))
}

/// List all webhook subscriptions for the caller.
#[utoipa::path(
    get,
    path = "/api/v1/account/webhooks",
    tag = "webhooks",
    responses((status = 200, description = "OK", body = Vec<WebhookListItem>)),
    security(("bearerAuth" = [])),
)]
async fn list(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<Vec<WebhookListItem>>, ApiError> {
    user.require(scope::ACCOUNT_ADMIN)?;
    let rows: Vec<(String, String, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, name, url, events, created_at, disabled_at
         FROM webhooks
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
            |(id, name, url, events, created_at, disabled_at)| WebhookListItem {
                id,
                name,
                url,
                events,
                created_at,
                disabled_at,
            },
        )
        .collect();
    Ok(Json(items))
}

/// Delete a webhook subscription.
#[utoipa::path(
    delete,
    path = "/api/v1/account/webhooks/{id}",
    tag = "webhooks",
    params(("id" = String, Path)),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Not found"),
    ),
    security(("bearerAuth" = [])),
)]
async fn delete(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    user.require(scope::ACCOUNT_ADMIN)?;
    let res = sqlx::query("DELETE FROM webhooks WHERE id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&user.user_id)
        .execute(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("webhook not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DeliveryItem {
    pub id: String,
    pub event_id: String,
    pub event_type: String,
    pub created_at: String,
    pub attempts: i32,
    pub next_attempt_at: String,
    pub last_status: Option<i32>,
    pub last_error: Option<String>,
    pub delivered_at: Option<String>,
    pub failed_permanently_at: Option<String>,
}

/// List the most recent 50 delivery attempts for a webhook (newest first).
/// Useful for debugging "why isn't my webhook firing".
#[utoipa::path(
    get,
    path = "/api/v1/account/webhooks/{id}/deliveries",
    tag = "webhooks",
    params(("id" = String, Path)),
    responses(
        (status = 200, description = "OK", body = Vec<DeliveryItem>),
        (status = 404, description = "Webhook not found"),
    ),
    security(("bearerAuth" = [])),
)]
async fn deliveries(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<DeliveryItem>>, ApiError> {
    user.require(scope::ACCOUNT_ADMIN)?;

    // Confirm the webhook is owned by the caller; 404 otherwise.
    let owned: Option<(String,)> =
        sqlx::query_as("SELECT id FROM webhooks WHERE id = $1 AND user_id = $2")
            .bind(&id)
            .bind(&user.user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    if owned.is_none() {
        return Err(ApiError::not_found("webhook not found"));
    }

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        String,
        String,
        i32,
        String,
        Option<i32>,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, event_id, event_type, created_at, attempts, next_attempt_at,
                last_status, last_error, delivered_at, failed_permanently_at
         FROM webhook_deliveries
         WHERE webhook_id = $1
         ORDER BY created_at DESC
         LIMIT 50",
    )
    .bind(&id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let items = rows
        .into_iter()
        .map(
            |(
                id,
                event_id,
                event_type,
                created_at,
                attempts,
                next_attempt_at,
                last_status,
                last_error,
                delivered_at,
                failed_permanently_at,
            )| DeliveryItem {
                id,
                event_id,
                event_type,
                created_at,
                attempts,
                next_attempt_at,
                last_status,
                last_error,
                delivered_at,
                failed_permanently_at,
            },
        )
        .collect();
    Ok(Json(items))
}
