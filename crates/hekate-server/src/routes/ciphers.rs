//! Cipher CRUD.
//!
//! Server treats every encrypted field as an opaque `EncString` — it is
//! validated for envelope shape on the way in, never decrypted.
//!
//! Mutations are gated by an `If-Match: "<revision_date>"` header. Writes
//! without `If-Match` are rejected with 428 — explicit conflict surfacing
//! is design pillar #1, so we never accept blind last-writer-wins.

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
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
    perms::{effective_permission, Permission},
    push::{PushEvent, PushKind},
    routes::accounts::ApiError,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/ciphers", post(create))
        .route(
            "/api/v1/ciphers/{id}",
            get(read).put(update).delete(soft_delete),
        )
        .route("/api/v1/ciphers/{id}/restore", post(restore))
        .route("/api/v1/ciphers/{id}/permanent", delete(purge))
        .route("/api/v1/ciphers/{id}/move-to-org", post(move_to_org))
        .route(
            "/api/v1/ciphers/{id}/move-to-personal",
            post(move_to_personal),
        )
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CipherInput {
    /// UUIDv7, generated client-side. Bound into the AAD of the cipher's
    /// encrypted fields (BW04/LP06 mitigation) so the server cannot swap
    /// rows or rewrite ids without breaking decryption.
    #[serde(default)]
    pub id: Option<String>,
    /// Cipher type: 1 login, 2 secure_note, 3 card, 4 identity, 5 ssh, 6 totp.
    /// Bound into the AAD of `name`/`notes`/`data` so a server-side flip
    /// breaks decryption client-side.
    #[serde(rename = "type")]
    #[schema(minimum = 1, maximum = 6, example = 1)]
    pub cipher_type: i32,
    pub folder_id: Option<String>,
    /// EncString v3 envelope wrapping the per-cipher key under either
    /// the account key (personal) or the org symmetric key (org-owned).
    pub protected_cipher_key: String,
    /// EncString v3 envelope of the display name.
    pub name: String,
    /// EncString v3 envelope of free-text notes (optional).
    pub notes: Option<String>,
    /// EncString v3 envelope of the type-specific data JSON. The
    /// (formerly plaintext) `reprompt` flag now lives inside this blob.
    pub data: String,
    #[serde(default)]
    pub favorite: bool,
    /// (M4.3) When set, the cipher is owned by this org and stored
    /// with `user_id = NULL`. Caller must be a member of the org.
    /// `collection_ids` must reference collections within that same
    /// org. `folder_id` is not allowed on org-owned ciphers.
    #[serde(default)]
    pub org_id: Option<String>,
    /// (M4.3) For org-owned ciphers, the collections this cipher is
    /// pinned to. Must be ⊆ the org's collections. Empty for personal.
    #[serde(default)]
    pub collection_ids: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CipherView {
    pub id: String,
    #[serde(rename = "type")]
    pub cipher_type: i32,
    pub folder_id: Option<String>,
    pub protected_cipher_key: String,
    pub name: String,
    pub notes: Option<String>,
    pub data: String,
    pub favorite: bool,
    pub revision_date: String,
    pub creation_date: String,
    pub deleted_date: Option<String>,
    /// `Some` for org-owned ciphers (M4.3), `None` for personal.
    /// Clients use this to decide which key (account_key vs
    /// org_sym_key) to unwrap `protected_cipher_key` under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// Collections this cipher belongs to (M4.3). Empty for personal
    /// ciphers; one or more `organization_collections.id` values for
    /// org-owned ciphers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collection_ids: Vec<String>,
    /// (M4.4) The caller's effective permission on this cipher:
    /// "manage" | "read" | "read_hide_passwords". Always "manage"
    /// for personal ciphers (you own them) or for the org owner.
    /// `None` is never serialized — every visible cipher has a
    /// permission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
}

fn validate_input(c: &CipherInput) -> Result<(), ApiError> {
    if !(1..=6).contains(&c.cipher_type) {
        return Err(ApiError::bad_request(format!(
            "type must be 1..=6, got {}",
            c.cipher_type
        )));
    }
    validate_enc(&c.protected_cipher_key, "protected_cipher_key")?;
    validate_enc(&c.name, "name")?;
    if let Some(n) = &c.notes {
        validate_enc(n, "notes")?;
    }
    validate_enc(&c.data, "data")?;
    if c.org_id.is_some() && c.folder_id.is_some() {
        return Err(ApiError::bad_request(
            "folder_id is not allowed on org-owned ciphers (folders are personal)",
        ));
    }
    Ok(())
}

fn validate_enc(s: &str, field: &str) -> Result<(), ApiError> {
    EncString::parse(s)
        .map(|_| ())
        .map_err(|e| ApiError::bad_request(format!("{field}: {e}")))
}

/// Create a new cipher. Requires `vault:write`.
#[utoipa::path(
    post,
    path = "/api/v1/ciphers",
    tag = "vault",
    request_body = CipherInput,
    responses(
        (status = 201, description = "Created", body = CipherView),
        (status = 400, description = "Validation failed", body = crate::routes::accounts::ErrorResponse),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Insufficient scope"),
    ),
    security(("bearerAuth" = [])),
)]
async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(input): Json<CipherInput>,
) -> Result<(StatusCode, Json<CipherView>), ApiError> {
    user.require(scope::VAULT_WRITE)?;
    validate_input(&input)?;
    if let Some(fid) = &input.folder_id {
        ensure_folder_owned(&state, &user.user_id, fid).await?;
    }
    if let Some(org_id) = &input.org_id {
        ensure_org_member(&state, org_id, &user.user_id).await?;
        ensure_collections_in_org(&state, org_id, &input.collection_ids).await?;

        // M4.4 permission check — must run BEFORE we open the
        // transaction. With sqlite::memory (single-connection pool)
        // any pool query inside the tx would deadlock against the
        // already-held connection.
        let is_owner = is_org_owner(&state, org_id, &user.user_id).await?;
        if !is_owner {
            for cid in &input.collection_ids {
                let row: Option<(String,)> = sqlx::query_as(
                    "SELECT permissions FROM collection_members
                     WHERE collection_id = $1 AND user_id = $2",
                )
                .bind(cid)
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
                    return Err(ApiError::forbidden(format!(
                        "need `manage` on collection {cid} to add ciphers"
                    )));
                }
            }
            if input.collection_ids.is_empty() {
                return Err(ApiError::forbidden(
                    "non-owner must pin org cipher to at least one collection \
                     they have `manage` on",
                ));
            }
        }
    } else if !input.collection_ids.is_empty() {
        return Err(ApiError::bad_request(
            "collection_ids only valid when org_id is set",
        ));
    }

    // The client-supplied `id` is bound into the AAD of every encrypted
    // field on this cipher. Required: a server-generated id would let the
    // server later substitute one cipher's row for another's. Validate
    // shape so we don't accept arbitrary strings as PKs.
    let id = match input.id.as_deref() {
        Some(s) => Uuid::parse_str(s)
            .map_err(|_| ApiError::bad_request("id must be a UUID string"))?
            .to_string(),
        None => {
            return Err(ApiError::bad_request(
                "id (UUIDv7) is required — clients generate ids before \
                 encrypting fields so AAD binding can authenticate them",
            ));
        }
    };
    let now = Utc::now().to_rfc3339();

    // For org-owned ciphers, user_id is NULL and org_id is set. The
    // schema CHECK enforces exactly-one-of.
    let (row_user_id, row_org_id): (Option<&str>, Option<&str>) = match &input.org_id {
        Some(org) => (None, Some(org.as_str())),
        None => (Some(user.user_id.as_str()), None),
    };

    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let res = sqlx::query(
        "INSERT INTO ciphers (
            id, user_id, org_id, folder_id, cipher_type, protected_cipher_key,
            name, notes, data, favorite,
            revision_date, creation_date
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(&id)
    .bind(row_user_id)
    .bind(row_org_id)
    .bind(&input.folder_id)
    .bind(input.cipher_type)
    .bind(&input.protected_cipher_key)
    .bind(&input.name)
    .bind(&input.notes)
    .bind(&input.data)
    .bind(if input.favorite { 1i32 } else { 0i32 })
    .bind(&now)
    .bind(&now)
    .execute(&mut *tx)
    .await;
    match res {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(ApiError::conflict("cipher id already exists"));
        }
        Err(e) => return Err(ApiError::internal(e.to_string())),
    }

    if input.org_id.is_some() {
        for cid in &input.collection_ids {
            sqlx::query(
                "INSERT INTO cipher_collections (cipher_id, collection_id) VALUES ($1, $2)",
            )
            .bind(&id)
            .bind(cid)
            .execute(&mut *tx)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
        }
    }

    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let view = load_visible(&state, &user.user_id, &id)
        .await?
        .expect("just inserted");
    state.push.publish(PushEvent {
        user_id: user.user_id.clone(),
        kind: PushKind::CipherChanged,
        id: view.id.clone(),
        revision: view.revision_date.clone(),
    });
    Ok((StatusCode::CREATED, Json(view)))
}

/// Read a single cipher by id. Requires `vault:read`.
#[utoipa::path(
    get,
    path = "/api/v1/ciphers/{id}",
    tag = "vault",
    params(("id" = String, Path, description = "UUIDv7 cipher id")),
    responses(
        (status = 200, description = "OK", body = CipherView),
        (status = 404, description = "Not found", body = crate::routes::accounts::ErrorResponse),
    ),
    security(("bearerAuth" = [])),
)]
async fn read(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<CipherView>, ApiError> {
    user.require(scope::VAULT_READ)?;
    let view = load_visible(&state, &user.user_id, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("cipher not found"))?;
    Ok(Json(view))
}

/// Update a cipher. Requires `vault:write` and a matching
/// `If-Match: "<revision_date>"` header. On revision mismatch, returns 409
/// with the server's current cipher in the body so the client can resolve
/// the conflict explicitly.
#[utoipa::path(
    put,
    path = "/api/v1/ciphers/{id}",
    tag = "vault",
    params(("id" = String, Path)),
    request_body = CipherInput,
    responses(
        (status = 200, description = "Updated", body = CipherView),
        (status = 404, description = "Not found"),
        (status = 409, description = "Revision conflict — body includes server's current cipher"),
        (status = 428, description = "If-Match header missing"),
    ),
    security(("bearerAuth" = [])),
)]
async fn update(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<CipherInput>,
) -> Result<Response, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    let if_match = headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_matches('"').to_string());

    let Some(expected_revision) = if_match else {
        return Err(ApiError::PreconditionRequired(
            "If-Match header required".into(),
        ));
    };

    validate_input(&input)?;
    if let Some(fid) = &input.folder_id {
        ensure_folder_owned(&state, &user.user_id, fid).await?;
    }

    let current = load_visible(&state, &user.user_id, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("cipher not found"))?;

    // M4.4: writes require `manage` (or owner for personal/org).
    require_write_permission(&current)?;

    // Reject ownership changes on update — moves are an explicit
    // separate flow (M4.5 move-to-org / move-to-personal).
    let current_org = current.org_id.clone();
    if input.org_id != current_org {
        return Err(ApiError::bad_request(
            "org_id cannot change on update — use move-to-org / move-to-personal (M4.5)",
        ));
    }

    if current.revision_date != expected_revision {
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "revision conflict",
                "current": current,
            })),
        )
            .into_response());
    }

    // Run cross-table validations BEFORE opening the tx — sqlite::memory
    // uses a single-connection pool and any pool query inside the tx
    // would deadlock against the held connection.
    if let Some(org_id) = &current_org {
        ensure_org_member(&state, org_id, &user.user_id).await?;
        ensure_collections_in_org(&state, org_id, &input.collection_ids).await?;
    }

    let now = Utc::now().to_rfc3339();

    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // The WHERE clause matches owner OR org_id, mirroring the
    // visibility check — if the cipher is org-owned, user_id is NULL
    // so the personal predicate is `user_id = $auth_user`. We
    // structure the query around the expected ownership shape.
    let updated = if let Some(org_id) = &current_org {
        sqlx::query(
            "UPDATE ciphers SET
                folder_id=$1, cipher_type=$2, protected_cipher_key=$3,
                name=$4, notes=$5, data=$6, favorite=$7,
                revision_date=$8
             WHERE id=$9 AND org_id=$10 AND revision_date=$11",
        )
        .bind(&input.folder_id)
        .bind(input.cipher_type)
        .bind(&input.protected_cipher_key)
        .bind(&input.name)
        .bind(&input.notes)
        .bind(&input.data)
        .bind(if input.favorite { 1i32 } else { 0i32 })
        .bind(&now)
        .bind(&id)
        .bind(org_id)
        .bind(&current.revision_date)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    } else {
        sqlx::query(
            "UPDATE ciphers SET
                folder_id=$1, cipher_type=$2, protected_cipher_key=$3,
                name=$4, notes=$5, data=$6, favorite=$7,
                revision_date=$8
             WHERE id=$9 AND user_id=$10 AND revision_date=$11",
        )
        .bind(&input.folder_id)
        .bind(input.cipher_type)
        .bind(&input.protected_cipher_key)
        .bind(&input.name)
        .bind(&input.notes)
        .bind(&input.data)
        .bind(if input.favorite { 1i32 } else { 0i32 })
        .bind(&now)
        .bind(&id)
        .bind(&user.user_id)
        .bind(&current.revision_date)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    };
    let _ = updated;

    // Replace cipher_collections membership for org ciphers. This is
    // M4.3 simplification — every PUT carries the full desired set;
    // no partial diffs.
    if current_org.is_some() {
        sqlx::query("DELETE FROM cipher_collections WHERE cipher_id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
        for cid in &input.collection_ids {
            sqlx::query(
                "INSERT INTO cipher_collections (cipher_id, collection_id) VALUES ($1, $2)",
            )
            .bind(&id)
            .bind(cid)
            .execute(&mut *tx)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
        }
    }

    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let view = load_visible(&state, &user.user_id, &id)
        .await?
        .expect("just updated");
    state.push.publish(PushEvent {
        user_id: user.user_id.clone(),
        kind: PushKind::CipherChanged,
        id: view.id.clone(),
        revision: view.revision_date.clone(),
    });
    Ok((StatusCode::OK, Json(view)).into_response())
}

/// Soft-delete (move to trash). Requires `vault:write`.
#[utoipa::path(
    delete,
    path = "/api/v1/ciphers/{id}",
    tag = "vault",
    params(("id" = String, Path)),
    responses(
        (status = 204, description = "Trashed"),
        (status = 404, description = "Not found"),
    ),
    security(("bearerAuth" = [])),
)]
async fn soft_delete(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    let current = load_visible(&state, &user.user_id, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("cipher not found"))?;
    require_write_permission(&current)?;
    let now = Utc::now().to_rfc3339();
    let res = if let Some(org_id) = &current.org_id {
        sqlx::query(
            "UPDATE ciphers SET deleted_date=$1, revision_date=$2
             WHERE id=$3 AND org_id=$4 AND deleted_date IS NULL",
        )
        .bind(&now)
        .bind(&now)
        .bind(&id)
        .bind(org_id)
        .execute(state.db.pool())
        .await
    } else {
        sqlx::query(
            "UPDATE ciphers SET deleted_date=$1, revision_date=$2
             WHERE id=$3 AND user_id=$4 AND deleted_date IS NULL",
        )
        .bind(&now)
        .bind(&now)
        .bind(&id)
        .bind(&user.user_id)
        .execute(state.db.pool())
        .await
    }
    .map_err(|e| ApiError::internal(e.to_string()))?;

    if res.rows_affected() != 0 {
        state.push.publish(PushEvent {
            user_id: user.user_id.clone(),
            kind: PushKind::CipherDeleted,
            id: id.clone(),
            revision: now.clone(),
        });
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Un-trash a soft-deleted cipher. Requires `vault:write`.
#[utoipa::path(
    post,
    path = "/api/v1/ciphers/{id}/restore",
    tag = "vault",
    params(("id" = String, Path)),
    responses(
        (status = 200, description = "Restored", body = CipherView),
        (status = 404, description = "Not found"),
    ),
    security(("bearerAuth" = [])),
)]
async fn restore(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<CipherView>, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    let current = load_visible(&state, &user.user_id, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("cipher not found"))?;
    require_write_permission(&current)?;
    let now = Utc::now().to_rfc3339();
    if let Some(org_id) = &current.org_id {
        sqlx::query(
            "UPDATE ciphers SET deleted_date=NULL, revision_date=$1
             WHERE id=$2 AND org_id=$3 AND deleted_date IS NOT NULL",
        )
        .bind(&now)
        .bind(&id)
        .bind(org_id)
        .execute(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    } else {
        sqlx::query(
            "UPDATE ciphers SET deleted_date=NULL, revision_date=$1
             WHERE id=$2 AND user_id=$3 AND deleted_date IS NOT NULL",
        )
        .bind(&now)
        .bind(&id)
        .bind(&user.user_id)
        .execute(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    }
    let view = load_visible(&state, &user.user_id, &id)
        .await?
        .expect("just restored");
    state.push.publish(PushEvent {
        user_id: user.user_id.clone(),
        kind: PushKind::CipherChanged,
        id: view.id.clone(),
        revision: view.revision_date.clone(),
    });
    Ok(Json(view))
}

/// Permanently delete a cipher (writes a tombstone). Requires `vault:write`.
#[utoipa::path(
    delete,
    path = "/api/v1/ciphers/{id}/permanent",
    tag = "vault",
    params(("id" = String, Path)),
    responses(
        (status = 204, description = "Purged; tombstone created"),
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
    let current = load_visible(&state, &user.user_id, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("cipher not found"))?;
    require_write_permission(&current)?;
    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let res = if let Some(org_id) = &current.org_id {
        sqlx::query("DELETE FROM ciphers WHERE id=$1 AND org_id=$2")
            .bind(&id)
            .bind(org_id)
            .execute(&mut *tx)
            .await
    } else {
        sqlx::query("DELETE FROM ciphers WHERE id=$1 AND user_id=$2")
            .bind(&id)
            .bind(&user.user_id)
            .execute(&mut *tx)
            .await
    }
    .map_err(|e| ApiError::internal(e.to_string()))?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("cipher not found"));
    }

    let now = Utc::now().to_rfc3339();
    // Tombstones are per-user today (M1.5 schema). For org-owned
    // ciphers we write a tombstone for the actor; M4.5 will introduce
    // per-org tombstones so other members converge cleanly.
    sqlx::query(
        "INSERT INTO tombstones (kind, id, user_id, deleted_at)
         VALUES ('cipher', $1, $2, $3)",
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
        kind: PushKind::CipherTombstoned,
        id: id.clone(),
        revision: now,
    });
    Ok(StatusCode::NO_CONTENT)
}

async fn ensure_folder_owned(
    state: &AppState,
    user_id: &str,
    folder_id: &str,
) -> Result<(), ApiError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT id FROM folders WHERE id=$1 AND user_id=$2")
            .bind(folder_id)
            .bind(user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    if row.is_none() {
        return Err(ApiError::bad_request("folder_id does not exist"));
    }
    Ok(())
}

/// Load a cipher visible to `user_id`. Visibility is:
///   - `ciphers.user_id = $auth_user` (personal), OR
///   - `ciphers.org_id IS NOT NULL` AND $auth_user is the org owner, OR
///   - `ciphers.org_id IS NOT NULL` AND $auth_user has any
///     `collection_members` row on at least one of the cipher's
///     collections (M4.4 — read/read_hide_passwords/manage).
///
/// Returns the row + the caller's effective permission. Permission is
/// `Manage` for personal ciphers (you own them) and for the org owner.
async fn load_visible(
    state: &AppState,
    user_id: &str,
    id: &str,
) -> Result<Option<CipherView>, ApiError> {
    let row: Option<CipherRow> = sqlx::query_as(
        "SELECT c.id, c.user_id, c.org_id, c.folder_id, c.cipher_type,
                c.protected_cipher_key,
                c.name, c.notes, c.data, c.favorite,
                c.revision_date, c.creation_date, c.deleted_date
         FROM ciphers c
         WHERE c.id = $1",
    )
    .bind(id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some(row) = row else { return Ok(None) };

    // Personal cipher — must be owned by caller.
    if row.user_id.as_deref() == Some(user_id) {
        let v = row.into_view(Vec::new());
        return Ok(Some(CipherView {
            permission: Some(Permission::Manage.as_str().to_string()),
            ..v
        }));
    }
    // Org cipher — caller must be owner or have a permission row on
    // at least one of the cipher's collections.
    if row.org_id.is_some() {
        let perm = effective_permission(state, user_id, id).await?;
        if let Some(perm) = perm {
            let collection_ids = load_collection_ids(state, &row.id).await?;
            let v = row.into_view(collection_ids);
            return Ok(Some(CipherView {
                permission: Some(perm.as_str().to_string()),
                ..v
            }));
        }
    }
    Ok(None)
}

async fn is_org_owner(state: &AppState, org_id: &str, user_id: &str) -> Result<bool, ApiError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT owner_user_id FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(row.map(|(o,)| o == user_id).unwrap_or(false))
}

// ===========================================================================
// M4.5a — cipher org-move (move-to-org / move-to-personal)
// ===========================================================================

/// Body for `POST /api/v1/ciphers/{id}/move-to-org`. The caller has
/// already re-keyed every encrypted field client-side under the org
/// symmetric key, including a fresh `protected_cipher_key`. Server
/// just stores the opaque ciphertexts and updates ownership.
#[derive(Debug, Deserialize, ToSchema)]
pub struct MoveToOrgRequest {
    pub org_id: String,
    /// Must be ⊆ this org's collections, and the caller must have
    /// `manage` on every one (or be the org owner).
    pub collection_ids: Vec<String>,
    /// Per-cipher key wrapped under the new org sym key.
    pub protected_cipher_key: String,
    pub name: String,
    pub notes: Option<String>,
    pub data: String,
    #[serde(default)]
    pub favorite: bool,
}

/// Body for `POST /api/v1/ciphers/{id}/move-to-personal`. The caller
/// has re-keyed under their own account_key. The cipher loses every
/// collection assignment.
#[derive(Debug, Deserialize, ToSchema)]
pub struct MoveToPersonalRequest {
    pub protected_cipher_key: String,
    pub name: String,
    pub notes: Option<String>,
    pub data: String,
    #[serde(default)]
    pub favorite: bool,
}

/// Move a personal cipher into an org. Requires `vault:write` and a
/// matching `If-Match: "<revision_date>"` header. Caller must currently
/// own the cipher (personal). For non-owners of the org, caller must
/// have `manage` on every target collection.
#[utoipa::path(
    post,
    path = "/api/v1/ciphers/{id}/move-to-org",
    tag = "vault",
    params(("id" = String, Path)),
    request_body = MoveToOrgRequest,
    responses(
        (status = 200, description = "Moved", body = CipherView),
        (status = 400, description = "Validation failed", body = crate::routes::accounts::ErrorResponse),
        (status = 403, description = "Permission denied"),
        (status = 404, description = "Not found"),
        (status = 409, description = "Revision conflict"),
        (status = 428, description = "If-Match required"),
    ),
    security(("bearerAuth" = [])),
)]
async fn move_to_org(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<MoveToOrgRequest>,
) -> Result<Response, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    let if_match = headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_matches('"').to_string());
    let Some(expected_revision) = if_match else {
        return Err(ApiError::PreconditionRequired(
            "If-Match header required".into(),
        ));
    };

    validate_enc(&body.protected_cipher_key, "protected_cipher_key")?;
    validate_enc(&body.name, "name")?;
    if let Some(n) = &body.notes {
        validate_enc(n, "notes")?;
    }
    validate_enc(&body.data, "data")?;

    let current = load_visible(&state, &user.user_id, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("cipher not found"))?;
    if current.org_id.is_some() {
        return Err(ApiError::bad_request(
            "cipher is already org-owned; use move-to-personal first or move-to-org \
             on a personal cipher",
        ));
    }
    if current.revision_date != expected_revision {
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({"error": "revision conflict", "current": current})),
        )
            .into_response());
    }

    // Cross-table validations BEFORE the tx (single-conn sqlite).
    ensure_org_member(&state, &body.org_id, &user.user_id).await?;
    ensure_collections_in_org(&state, &body.org_id, &body.collection_ids).await?;
    let is_owner = is_org_owner(&state, &body.org_id, &user.user_id).await?;
    if !is_owner {
        if body.collection_ids.is_empty() {
            return Err(ApiError::forbidden(
                "non-owner must pin moved cipher to at least one collection \
                 they have `manage` on",
            ));
        }
        for cid in &body.collection_ids {
            let row: Option<(String,)> = sqlx::query_as(
                "SELECT permissions FROM collection_members
                 WHERE collection_id = $1 AND user_id = $2",
            )
            .bind(cid)
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
                return Err(ApiError::forbidden(format!(
                    "need `manage` on collection {cid} to move ciphers in"
                )));
            }
        }
    }

    let now = Utc::now().to_rfc3339();
    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    sqlx::query(
        "UPDATE ciphers SET
            user_id = NULL, org_id = $1, folder_id = NULL,
            protected_cipher_key = $2,
            name = $3, notes = $4, data = $5,
            favorite = $6, revision_date = $7
         WHERE id = $8 AND user_id = $9 AND revision_date = $10",
    )
    .bind(&body.org_id)
    .bind(&body.protected_cipher_key)
    .bind(&body.name)
    .bind(&body.notes)
    .bind(&body.data)
    .bind(if body.favorite { 1i32 } else { 0i32 })
    .bind(&now)
    .bind(&id)
    .bind(&user.user_id)
    .bind(&current.revision_date)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    sqlx::query("DELETE FROM cipher_collections WHERE cipher_id = $1")
        .bind(&id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    for cid in &body.collection_ids {
        sqlx::query("INSERT INTO cipher_collections (cipher_id, collection_id) VALUES ($1, $2)")
            .bind(&id)
            .bind(cid)
            .execute(&mut *tx)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    }
    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let view = load_visible(&state, &user.user_id, &id)
        .await?
        .expect("just moved");
    state.push.publish(PushEvent {
        user_id: user.user_id.clone(),
        kind: PushKind::CipherChanged,
        id: view.id.clone(),
        revision: view.revision_date.clone(),
    });
    Ok((StatusCode::OK, Json(view)).into_response())
}

/// Move an org-owned cipher into the caller's personal vault. Requires
/// `vault:write` + If-Match. Caller must currently have `manage` on
/// the cipher (or be org owner). All `cipher_collections` rows are
/// dropped.
#[utoipa::path(
    post,
    path = "/api/v1/ciphers/{id}/move-to-personal",
    tag = "vault",
    params(("id" = String, Path)),
    request_body = MoveToPersonalRequest,
    responses(
        (status = 200, description = "Moved", body = CipherView),
        (status = 400, description = "Validation failed", body = crate::routes::accounts::ErrorResponse),
        (status = 403, description = "Permission denied"),
        (status = 404, description = "Not found"),
        (status = 409, description = "Revision conflict"),
        (status = 428, description = "If-Match required"),
    ),
    security(("bearerAuth" = [])),
)]
async fn move_to_personal(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<MoveToPersonalRequest>,
) -> Result<Response, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    let if_match = headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_matches('"').to_string());
    let Some(expected_revision) = if_match else {
        return Err(ApiError::PreconditionRequired(
            "If-Match header required".into(),
        ));
    };

    validate_enc(&body.protected_cipher_key, "protected_cipher_key")?;
    validate_enc(&body.name, "name")?;
    if let Some(n) = &body.notes {
        validate_enc(n, "notes")?;
    }
    validate_enc(&body.data, "data")?;

    let current = load_visible(&state, &user.user_id, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("cipher not found"))?;
    if current.org_id.is_none() {
        return Err(ApiError::bad_request(
            "cipher is already personal; nothing to do",
        ));
    }
    require_write_permission(&current)?;
    if current.revision_date != expected_revision {
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({"error": "revision conflict", "current": current})),
        )
            .into_response());
    }

    let now = Utc::now().to_rfc3339();
    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    sqlx::query("DELETE FROM cipher_collections WHERE cipher_id = $1")
        .bind(&id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    sqlx::query(
        "UPDATE ciphers SET
            user_id = $1, org_id = NULL, folder_id = NULL,
            protected_cipher_key = $2,
            name = $3, notes = $4, data = $5,
            favorite = $6, revision_date = $7
         WHERE id = $8 AND revision_date = $9",
    )
    .bind(&user.user_id)
    .bind(&body.protected_cipher_key)
    .bind(&body.name)
    .bind(&body.notes)
    .bind(&body.data)
    .bind(if body.favorite { 1i32 } else { 0i32 })
    .bind(&now)
    .bind(&id)
    .bind(&current.revision_date)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let view = load_visible(&state, &user.user_id, &id)
        .await?
        .expect("just moved");
    state.push.publish(PushEvent {
        user_id: user.user_id.clone(),
        kind: PushKind::CipherChanged,
        id: view.id.clone(),
        revision: view.revision_date.clone(),
    });
    Ok((StatusCode::OK, Json(view)).into_response())
}

/// 403 if the caller's effective permission on this cipher does NOT
/// allow writes. Personal ciphers are always Manage-equivalent (caller
/// owns them); org ciphers require `manage`.
fn require_write_permission(view: &CipherView) -> Result<(), ApiError> {
    let perm = view
        .permission
        .as_deref()
        .and_then(Permission::parse)
        .unwrap_or(Permission::Manage);
    if perm.can_write() {
        Ok(())
    } else {
        Err(ApiError::forbidden(
            "permission denied: this cipher requires `manage` to modify",
        ))
    }
}

async fn load_collection_ids(state: &AppState, cipher_id: &str) -> Result<Vec<String>, ApiError> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT collection_id FROM cipher_collections WHERE cipher_id = $1")
            .bind(cipher_id)
            .fetch_all(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(rows.into_iter().map(|(c,)| c).collect())
}

async fn ensure_org_member(state: &AppState, org_id: &str, user_id: &str) -> Result<(), ApiError> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT 1 FROM organization_members WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    if row.is_none() {
        return Err(ApiError::not_found("org"));
    }
    Ok(())
}

async fn ensure_collections_in_org(
    state: &AppState,
    org_id: &str,
    collection_ids: &[String],
) -> Result<(), ApiError> {
    for cid in collection_ids {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT id FROM organization_collections WHERE id = $1 AND org_id = $2")
                .bind(cid)
                .bind(org_id)
                .fetch_optional(state.db.pool())
                .await
                .map_err(|e| ApiError::internal(e.to_string()))?;
        if row.is_none() {
            return Err(ApiError::bad_request(format!(
                "collection {cid} is not in org {org_id}"
            )));
        }
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
pub(crate) struct CipherRow {
    pub id: String,
    /// Owner-user. Used by sync's visibility predicate; not surfaced
    /// on `CipherView` since the caller's auth already implies their
    /// own user_id.
    #[allow(dead_code)]
    pub user_id: Option<String>,
    pub org_id: Option<String>,
    pub folder_id: Option<String>,
    pub cipher_type: i32,
    pub protected_cipher_key: String,
    pub name: String,
    pub notes: Option<String>,
    pub data: String,
    pub favorite: i32,
    pub revision_date: String,
    pub creation_date: String,
    pub deleted_date: Option<String>,
}

impl CipherRow {
    pub(crate) fn into_view(self, collection_ids: Vec<String>) -> CipherView {
        CipherView {
            id: self.id,
            cipher_type: self.cipher_type,
            folder_id: self.folder_id,
            protected_cipher_key: self.protected_cipher_key,
            name: self.name,
            notes: self.notes,
            data: self.data,
            favorite: self.favorite != 0,
            revision_date: self.revision_date,
            creation_date: self.creation_date,
            deleted_date: self.deleted_date,
            org_id: self.org_id,
            collection_ids,
            permission: None,
        }
    }
}
