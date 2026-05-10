//! M4.3 — collections.
//!
//! A collection is a logical grouping of org-owned ciphers. Names are
//! EncString-encrypted under the org's symmetric key (so the server
//! cannot read them), but the `id` and `org_id` are plaintext for
//! routing and joins.
//!
//! M4.3 simplification: writes (create, delete) are owner-only.
//! Reads are allowed for any accepted member of the org. The
//! per-collection permissions matrix (`read` / `read_hide_passwords`
//! / `manage`) lands in M4.4.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::post,
    Router,
};
use chrono::Utc;
use hekate_core::encstring::EncString;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    auth::{scope, AuthUser},
    perms::Permission,
    routes::accounts::ApiError,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/orgs/{org_id}/collections", post(create).get(list))
        .route(
            "/api/v1/orgs/{org_id}/collections/{collection_id}",
            axum::routing::delete(delete_one),
        )
        .route(
            "/api/v1/orgs/{org_id}/collections/{collection_id}/members",
            axum::routing::get(list_members),
        )
        .route(
            "/api/v1/orgs/{org_id}/collections/{collection_id}/members/{user_id}",
            axum::routing::put(grant).delete(revoke),
        )
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCollectionRequest {
    /// Client-supplied UUIDv7.
    pub id: String,
    /// EncString v3 of the collection name, encrypted under the org
    /// symmetric key. Server only validates envelope shape.
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct CollectionView {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub revision_date: String,
    pub creation_date: String,
}

/// Owner-only. Create a new collection in this org. Name is opaque
/// EncString under the org sym key.
#[utoipa::path(
    post,
    path = "/api/v1/orgs/{org_id}/collections",
    tag = "orgs",
    params(("org_id" = String, Path)),
    request_body = CreateCollectionRequest,
    responses(
        (status = 201, description = "Created", body = CollectionView),
        (status = 400, description = "Validation failed", body = crate::routes::accounts::ErrorResponse),
        (status = 403, description = "Not the org owner"),
        (status = 404, description = "Org not found"),
    ),
    security(("bearerAuth" = [])),
)]
async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Json(req): Json<CreateCollectionRequest>,
) -> Result<(StatusCode, Json<CollectionView>), ApiError> {
    user.require(scope::VAULT_WRITE)?;
    Uuid::parse_str(&req.id).map_err(|_| ApiError::bad_request("id must be a UUID string"))?;
    EncString::parse(&req.name).map_err(|e| ApiError::bad_request(format!("name: {e}")))?;

    require_org_owner(&state, &org_id, &user.user_id).await?;

    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO organization_collections (id, org_id, name, revision_date, creation_date)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&req.id)
    .bind(&org_id)
    .bind(&req.name)
    .bind(&now)
    .bind(&now)
    .execute(state.db.pool())
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => {
            ApiError::conflict("collection id already exists")
        }
        e => ApiError::internal(e.to_string()),
    })?;

    Ok((
        StatusCode::CREATED,
        Json(CollectionView {
            id: req.id,
            org_id,
            name: req.name,
            revision_date: now.clone(),
            creation_date: now,
        }),
    ))
}

/// Member-only. List collections in the org.
#[utoipa::path(
    get,
    path = "/api/v1/orgs/{org_id}/collections",
    tag = "orgs",
    params(("org_id" = String, Path)),
    responses(
        (status = 200, description = "OK", body = Vec<CollectionView>),
        (status = 404, description = "Org not found / not a member"),
    ),
    security(("bearerAuth" = [])),
)]
async fn list(
    user: AuthUser,
    State(state): State<AppState>,
    Path(org_id): Path<String>,
) -> Result<Json<Vec<CollectionView>>, ApiError> {
    user.require(scope::VAULT_READ)?;
    require_org_member(&state, &org_id, &user.user_id).await?;

    let rows: Vec<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT id, org_id, name, revision_date, creation_date
         FROM organization_collections
         WHERE org_id = $1
         ORDER BY creation_date ASC",
    )
    .bind(&org_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(
        rows.into_iter()
            .map(
                |(id, org_id, name, revision_date, creation_date)| CollectionView {
                    id,
                    org_id,
                    name,
                    revision_date,
                    creation_date,
                },
            )
            .collect(),
    ))
}

/// Owner-only. Delete a collection. Cascades to `cipher_collections`
/// (the cipher rows themselves remain — they just lose this
/// assignment). M4.5 will revisit when org-cipher tombstones land.
#[utoipa::path(
    delete,
    path = "/api/v1/orgs/{org_id}/collections/{collection_id}",
    tag = "orgs",
    params(
        ("org_id" = String, Path),
        ("collection_id" = String, Path),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 403, description = "Not the org owner"),
        (status = 404, description = "Org or collection not found"),
    ),
    security(("bearerAuth" = [])),
)]
async fn delete_one(
    user: AuthUser,
    State(state): State<AppState>,
    Path((org_id, collection_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    require_org_owner(&state, &org_id, &user.user_id).await?;

    let res = sqlx::query("DELETE FROM organization_collections WHERE id = $1 AND org_id = $2")
        .bind(&collection_id)
        .bind(&org_id)
        .execute(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("collection"));
    }
    Ok(StatusCode::NO_CONTENT)
}

// ===========================================================================
// M4.4 — collection_members (grant / revoke / list)
// ===========================================================================

#[derive(Debug, Deserialize, ToSchema)]
pub struct GrantPermissionRequest {
    /// "manage" | "read" | "read_hide_passwords"
    pub permission: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CollectionMemberView {
    pub collection_id: String,
    pub user_id: String,
    pub permission: String,
}

/// Owner-only. Set (or update) a user's permission on this collection.
/// Idempotent: PUT replaces any existing row for this `(collection,
/// user)` pair.
#[utoipa::path(
    put,
    path = "/api/v1/orgs/{org_id}/collections/{collection_id}/members/{user_id}",
    tag = "orgs",
    params(
        ("org_id" = String, Path),
        ("collection_id" = String, Path),
        ("user_id" = String, Path),
    ),
    request_body = GrantPermissionRequest,
    responses(
        (status = 200, description = "OK", body = CollectionMemberView),
        (status = 400, description = "Validation failed", body = crate::routes::accounts::ErrorResponse),
        (status = 403, description = "Not the org owner"),
        (status = 404, description = "Org or collection not found, or invitee not a member"),
    ),
    security(("bearerAuth" = [])),
)]
async fn grant(
    user: AuthUser,
    State(state): State<AppState>,
    Path((org_id, collection_id, target_user_id)): Path<(String, String, String)>,
    Json(req): Json<GrantPermissionRequest>,
) -> Result<Json<CollectionMemberView>, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    require_org_owner(&state, &org_id, &user.user_id).await?;

    let perm = Permission::parse(&req.permission).ok_or_else(|| {
        ApiError::bad_request("permission must be one of: manage, read, read_hide_passwords")
    })?;

    // Confirm the collection belongs to this org and the target is an
    // accepted member of the org. (Granting permission to a non-member
    // would be silently useless and surfaces as a confusing UX bug
    // later, so reject up front.)
    require_collection_in_org(&state, &collection_id, &org_id).await?;
    let member_row: Option<(i64,)> =
        sqlx::query_as("SELECT 1 FROM organization_members WHERE org_id = $1 AND user_id = $2")
            .bind(&org_id)
            .bind(&target_user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    if member_row.is_none() {
        return Err(ApiError::not_found(
            "target user is not a member of this org",
        ));
    }

    // Upsert. Postgres uses ON CONFLICT; SQLite supports the same
    // syntax since 3.24, which is well below hekate's floor.
    sqlx::query(
        "INSERT INTO collection_members (collection_id, user_id, permissions)
         VALUES ($1, $2, $3)
         ON CONFLICT (collection_id, user_id) DO UPDATE SET permissions = $3",
    )
    .bind(&collection_id)
    .bind(&target_user_id)
    .bind(perm.as_str())
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(CollectionMemberView {
        collection_id,
        user_id: target_user_id,
        permission: perm.as_str().to_string(),
    }))
}

/// Owner-only. Revoke a user's permission on this collection. Idempotent:
/// 204 even if the row was already absent.
#[utoipa::path(
    delete,
    path = "/api/v1/orgs/{org_id}/collections/{collection_id}/members/{user_id}",
    tag = "orgs",
    params(
        ("org_id" = String, Path),
        ("collection_id" = String, Path),
        ("user_id" = String, Path),
    ),
    responses(
        (status = 204, description = "Revoked"),
        (status = 403, description = "Not the org owner"),
        (status = 404, description = "Org or collection not found"),
    ),
    security(("bearerAuth" = [])),
)]
async fn revoke(
    user: AuthUser,
    State(state): State<AppState>,
    Path((org_id, collection_id, target_user_id)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    require_org_owner(&state, &org_id, &user.user_id).await?;
    require_collection_in_org(&state, &collection_id, &org_id).await?;
    sqlx::query("DELETE FROM collection_members WHERE collection_id = $1 AND user_id = $2")
        .bind(&collection_id)
        .bind(&target_user_id)
        .execute(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// List all permission rows for a collection. Owner-visible; other
/// members can call this only if they have `manage` on the collection
/// themselves (gives them visibility on who else has access).
#[utoipa::path(
    get,
    path = "/api/v1/orgs/{org_id}/collections/{collection_id}/members",
    tag = "orgs",
    params(
        ("org_id" = String, Path),
        ("collection_id" = String, Path),
    ),
    responses(
        (status = 200, description = "OK", body = Vec<CollectionMemberView>),
        (status = 404, description = "Org or collection not found"),
    ),
    security(("bearerAuth" = [])),
)]
async fn list_members(
    user: AuthUser,
    State(state): State<AppState>,
    Path((org_id, collection_id)): Path<(String, String)>,
) -> Result<Json<Vec<CollectionMemberView>>, ApiError> {
    user.require(scope::VAULT_READ)?;
    require_collection_in_org(&state, &collection_id, &org_id).await?;
    // Owner OR caller has `manage` on this collection.
    let owner_row: Option<(String,)> =
        sqlx::query_as("SELECT owner_user_id FROM organizations WHERE id = $1")
            .bind(&org_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let is_owner = owner_row.map(|(o,)| o == user.user_id).unwrap_or(false);
    if !is_owner {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT permissions FROM collection_members
             WHERE collection_id = $1 AND user_id = $2",
        )
        .bind(&collection_id)
        .bind(&user.user_id)
        .fetch_optional(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
        let allowed = row
            .as_ref()
            .and_then(|(p,)| Permission::parse(p))
            .map(|p| p.can_write())
            .unwrap_or(false);
        if !allowed {
            return Err(ApiError::not_found("collection"));
        }
    }
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT user_id, permissions FROM collection_members WHERE collection_id = $1
         ORDER BY user_id ASC",
    )
    .bind(&collection_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(
        rows.into_iter()
            .map(|(uid, p)| CollectionMemberView {
                collection_id: collection_id.clone(),
                user_id: uid,
                permission: p,
            })
            .collect(),
    ))
}

async fn require_collection_in_org(
    state: &AppState,
    collection_id: &str,
    org_id: &str,
) -> Result<(), ApiError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT id FROM organization_collections WHERE id = $1 AND org_id = $2")
            .bind(collection_id)
            .bind(org_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    if row.is_none() {
        return Err(ApiError::not_found("collection"));
    }
    Ok(())
}

// ---------------- helpers --------------------------------------------------

/// Caller must be the org owner. Returns 404 (not 403) for non-owners
/// to avoid leaking org existence.
async fn require_org_owner(state: &AppState, org_id: &str, user_id: &str) -> Result<(), ApiError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT owner_user_id FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    match row {
        Some((owner,)) if owner == user_id => Ok(()),
        Some(_) => Err(ApiError::not_found("org")),
        None => Err(ApiError::not_found("org")),
    }
}

async fn require_org_member(state: &AppState, org_id: &str, user_id: &str) -> Result<(), ApiError> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT 1 FROM organization_members WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    if row.is_some() {
        Ok(())
    } else {
        Err(ApiError::not_found("org"))
    }
}
