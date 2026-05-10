//! Folder CRUD. Folders are user-private and not shared (orgs use
//! collections, which arrive in M2).

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use hekate_core::encstring::EncString;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    auth::{scope, AuthUser},
    push::{PushEvent, PushKind},
    routes::accounts::ApiError,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/folders", post(create))
        .route("/api/v1/folders/{id}", get(read).put(update).delete(purge))
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct FolderInput {
    /// EncString v3 envelope of the folder's display name.
    pub name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FolderView {
    pub id: String,
    pub name: String,
    pub revision_date: String,
    pub creation_date: String,
}

fn validate(input: &FolderInput) -> Result<(), ApiError> {
    EncString::parse(&input.name)
        .map(|_| ())
        .map_err(|e| ApiError::bad_request(format!("name: {e}")))
}

/// Create a new folder. Requires `vault:write`.
#[utoipa::path(
    post,
    path = "/api/v1/folders",
    tag = "vault",
    request_body = FolderInput,
    responses(
        (status = 201, description = "Created", body = FolderView),
    ),
    security(("bearerAuth" = [])),
)]
async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(input): Json<FolderInput>,
) -> Result<(StatusCode, Json<FolderView>), ApiError> {
    user.require(scope::VAULT_WRITE)?;
    validate(&input)?;
    let id = Uuid::now_v7().to_string();
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO folders (id, user_id, name, revision_date, creation_date)
         VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(&input.name)
    .bind(&now)
    .bind(&now)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    state.push.publish(PushEvent {
        user_id: user.user_id.clone(),
        kind: PushKind::FolderChanged,
        id: id.clone(),
        revision: now.clone(),
    });
    Ok((
        StatusCode::CREATED,
        Json(FolderView {
            id,
            name: input.name,
            revision_date: now.clone(),
            creation_date: now,
        }),
    ))
}

/// Read a folder. Requires `vault:read`.
#[utoipa::path(
    get,
    path = "/api/v1/folders/{id}",
    tag = "vault",
    params(("id" = String, Path)),
    responses(
        (status = 200, description = "OK", body = FolderView),
        (status = 404, description = "Not found"),
    ),
    security(("bearerAuth" = [])),
)]
async fn read(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<FolderView>, ApiError> {
    user.require(scope::VAULT_READ)?;
    let view = load(&state, &user.user_id, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("folder not found"))?;
    Ok(Json(view))
}

/// Update a folder. Requires `vault:write` + `If-Match` header. On
/// conflict returns 409 with `current` folder in the body.
#[utoipa::path(
    put,
    path = "/api/v1/folders/{id}",
    tag = "vault",
    params(("id" = String, Path)),
    request_body = FolderInput,
    responses(
        (status = 200, description = "Updated", body = FolderView),
        (status = 404, description = "Not found"),
        (status = 409, description = "Revision conflict"),
        (status = 428, description = "If-Match header missing"),
    ),
    security(("bearerAuth" = [])),
)]
async fn update(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<FolderInput>,
) -> Result<Response, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    let if_match = headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_matches('"').to_string());
    let Some(expected) = if_match else {
        return Err(ApiError::PreconditionRequired(
            "If-Match header required".into(),
        ));
    };

    validate(&input)?;
    let current = load(&state, &user.user_id, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("folder not found"))?;

    if current.revision_date != expected {
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({"error": "revision conflict", "current": current})),
        )
            .into_response());
    }

    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE folders SET name=$1, revision_date=$2
         WHERE id=$3 AND user_id=$4 AND revision_date=$5",
    )
    .bind(&input.name)
    .bind(&now)
    .bind(&id)
    .bind(&user.user_id)
    .bind(&current.revision_date)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let view = load(&state, &user.user_id, &id)
        .await?
        .expect("just updated");
    state.push.publish(PushEvent {
        user_id: user.user_id.clone(),
        kind: PushKind::FolderChanged,
        id: view.id.clone(),
        revision: view.revision_date.clone(),
    });
    Ok((StatusCode::OK, Json(view)).into_response())
}

/// Permanently delete a folder (writes a tombstone). Requires
/// `vault:write`. Ciphers in the folder have their `folder_id` cleared.
#[utoipa::path(
    delete,
    path = "/api/v1/folders/{id}",
    tag = "vault",
    params(("id" = String, Path)),
    responses(
        (status = 204, description = "Deleted; tombstone created"),
        (status = 404, description = "Not found"),
    ),
    security(("bearerAuth" = [])),
)]
async fn purge(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let res = sqlx::query("DELETE FROM folders WHERE id=$1 AND user_id=$2")
        .bind(&id)
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("folder not found"));
    }

    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO tombstones (kind, id, user_id, deleted_at)
         VALUES ('folder', $1, $2, $3)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(&now)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    state.push.publish(PushEvent {
        user_id: user.user_id.clone(),
        kind: PushKind::FolderTombstoned,
        id: id.clone(),
        revision: now,
    });
    Ok(StatusCode::NO_CONTENT)
}

async fn load(state: &AppState, user_id: &str, id: &str) -> Result<Option<FolderView>, ApiError> {
    let row: Option<(String, String, String, String)> = sqlx::query_as(
        "SELECT id, name, revision_date, creation_date
         FROM folders WHERE id=$1 AND user_id=$2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(
        row.map(|(id, name, revision_date, creation_date)| FolderView {
            id,
            name,
            revision_date,
            creation_date,
        }),
    )
}
