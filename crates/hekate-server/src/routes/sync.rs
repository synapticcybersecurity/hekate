//! Delta sync — design pillar #1.
//!
//! `GET /api/v1/sync?since=<rfc3339>` returns every cipher and folder owned
//! by the caller whose `revision_date > since`, plus tombstones recorded
//! after `since`. The response carries a `high_water` cursor that the
//! client persists and passes back next call.
//!
//! Pagination via cursor is reserved for M2; for personal vault sizes a
//! single page is fine.

use axum::{
    extract::{Query, State},
    response::Json,
    routing::get,
    Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::{
    auth::{scope, AuthUser},
    routes::{
        accounts::ApiError,
        attachments::{AttachmentRow, AttachmentView},
        ciphers::CipherView,
        collections::CollectionView,
        folders::FolderView,
        org_cipher_manifest::{
            latest_manifest as latest_org_cipher_manifest, OrgCipherManifestView,
        },
        orgs::SignedOrgRosterWire,
        policies::{load_policies, PolicyView},
        sends::{SendRow, SendView},
        vault_manifest::{latest_manifest, ManifestView},
    },
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new().route("/api/v1/sync", get(sync))
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct SyncQuery {
    /// RFC3339 watermark. Omit on first call to receive everything.
    pub since: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SyncResponse {
    pub changes: Changes,
    /// Pass this back as `since` on the next call.
    pub high_water: String,
    /// Server-side now() at response generation, RFC3339.
    pub server_time: String,
    /// `true` if the response covers all changes; reserved for future
    /// pagination where multiple pages may be needed.
    pub complete: bool,
    /// Latest signed vault manifest (BW04). `null` until the user's first
    /// upload. Clients verify this against their own copy of the account
    /// signing pubkey and cross-check that every cipher in `changes.ciphers`
    /// matches its corresponding manifest entry.
    pub manifest: Option<ManifestView>,
    /// One entry per org the caller belongs to (M4.2 BW08 mitigation on
    /// the read path). Each carries the latest signed roster; the client
    /// verifies the signature under its locally-pinned org signing
    /// pubkey, checks roster_version is monotonically non-decreasing
    /// against its prior cache, and confirms self-membership at `role`.
    pub orgs: Vec<OrgSyncEntry>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OrgSyncEntry {
    pub org_id: String,
    pub name: String,
    pub role: String,
    pub org_sym_key_id: String,
    pub roster_version: i64,
    pub roster_updated_at: String,
    pub roster: SignedOrgRosterWire,
    /// (M4.5b) Set when the owner has rotated the org sym key but the
    /// caller hasn't yet confirmed pickup. The envelope wraps the new
    /// sym key under the caller's TOFU-pinned X25519 pubkey
    /// (signcryption); the client decrypts, re-wraps under their own
    /// account_key, and POSTs `/rotate-confirm` to clear it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_envelope: Option<serde_json::Value>,
    /// (M4.6) Active policies for this org, surfaced inline so the
    /// client can apply max-strictness across orgs without a per-org
    /// policy round trip. Includes both enabled and disabled rows;
    /// clients filter on `enabled` themselves.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<PolicyView>,
    /// (M2.21 / M4.5 follow-up) Latest signed cipher manifest for this
    /// org. `None` until the owner uploads the genesis. Members verify
    /// the signature under the TOFU-pinned org signing pubkey, then
    /// cross-check every org-owned cipher in `changes.ciphers` against
    /// the manifest entries — drops, replays, and resurrections of
    /// org-owned ciphers all surface as warnings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher_manifest: Option<OrgCipherManifestView>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Changes {
    pub ciphers: Vec<CipherView>,
    pub folders: Vec<FolderView>,
    pub tombstones: Vec<Tombstone>,
    /// (M4.3) Collections the caller has visibility on, across every
    /// org they belong to. Plaintext `id` and `org_id`; `name` is
    /// EncString under the org sym key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collections: Vec<CollectionView>,
    /// (M2.24) Attachment metadata changed since `since`. Status=1
    /// (finalized) only; in-progress uploads are not surfaced. The
    /// CLI feeds these into `compute_attachments_root` to verify the
    /// BW04 manifest's per-cipher attachments_root binding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentView>,
    /// (M2.25) Sender-owned Sends changed since `since`. Recipients
    /// don't sync — they go through `/api/v1/public/sends/{id}/access`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sends: Vec<SendView>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Tombstone {
    /// `cipher` or `folder`.
    pub kind: String,
    pub id: String,
    pub deleted_at: String,
}

/// Delta sync — returns ciphers, folders, and tombstones changed since
/// `?since=<rfc3339>`. Requires `vault:read`. Persist `high_water` and
/// pass it as the next call's `since`.
#[utoipa::path(
    get,
    path = "/api/v1/sync",
    tag = "vault",
    params(SyncQuery),
    responses(
        (status = 200, description = "OK", body = SyncResponse),
    ),
    security(("bearerAuth" = [])),
)]
async fn sync(
    user: AuthUser,
    State(state): State<AppState>,
    Query(q): Query<SyncQuery>,
) -> Result<Json<SyncResponse>, ApiError> {
    user.require(scope::VAULT_READ)?;
    // Watermark of "epoch" if missing — return everything.
    let since = q.since.unwrap_or_else(|| "1970-01-01T00:00:00Z".into());
    let server_time = Utc::now().to_rfc3339();

    // M4.4: caller sees ciphers they own (user_id) AND org ciphers
    // they have access to (org owner OR has any collection permission
    // row on at least one of the cipher's collections). Effective
    // permission is computed per-cipher below.
    let cipher_rows: Vec<CipherRow> = sqlx::query_as(
        "SELECT c.id, c.user_id, c.org_id, c.folder_id, c.cipher_type,
                c.protected_cipher_key,
                c.name, c.notes, c.data, c.favorite,
                c.revision_date, c.creation_date, c.deleted_date
         FROM ciphers c
         WHERE c.revision_date > $2
           AND (c.user_id = $1
                OR (c.org_id IS NOT NULL AND EXISTS
                     (SELECT 1 FROM organizations o
                      WHERE o.id = c.org_id AND o.owner_user_id = $1))
                OR EXISTS
                     (SELECT 1
                      FROM cipher_collections cc
                      JOIN collection_members m
                        ON m.collection_id = cc.collection_id
                      WHERE cc.cipher_id = c.id AND m.user_id = $1))
         ORDER BY c.revision_date ASC",
    )
    .bind(&user.user_id)
    .bind(&since)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let folder_rows: Vec<FolderRow> = sqlx::query_as(
        "SELECT id, name, revision_date, creation_date
         FROM folders
         WHERE user_id = $1 AND revision_date > $2
         ORDER BY revision_date ASC",
    )
    .bind(&user.user_id)
    .bind(&since)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let tombstones: Vec<Tombstone> = sqlx::query_as::<_, (String, String, String)>(
        "SELECT kind, id, deleted_at FROM tombstones
         WHERE user_id = $1 AND deleted_at > $2
         ORDER BY deleted_at ASC",
    )
    .bind(&user.user_id)
    .bind(&since)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .into_iter()
    .map(|(kind, id, deleted_at)| Tombstone {
        kind,
        id,
        deleted_at,
    })
    .collect();

    // Watermark: max of any returned timestamp (or `since` itself if empty).
    let high_water = std::iter::empty::<&str>()
        .chain(cipher_rows.iter().map(|r| r.revision_date.as_str()))
        .chain(folder_rows.iter().map(|r| r.revision_date.as_str()))
        .chain(tombstones.iter().map(|t| t.deleted_at.as_str()))
        .max()
        .unwrap_or(&since)
        .to_string();

    // For org-owned ciphers, attach their collection_ids in one batch
    // query rather than N+1.
    let org_cipher_ids: Vec<&str> = cipher_rows
        .iter()
        .filter(|r| r.org_id.is_some())
        .map(|r| r.id.as_str())
        .collect();
    let cipher_collections = load_cipher_collections(&state, &org_cipher_ids).await?;

    let mut ciphers: Vec<CipherView> = Vec::with_capacity(cipher_rows.len());
    for r in cipher_rows {
        let cids = cipher_collections
            .get(r.id.as_str())
            .cloned()
            .unwrap_or_default();
        let permission = if r.user_id.as_deref() == Some(user.user_id.as_str()) {
            // Personal cipher — caller owns it, can do anything.
            Some(crate::perms::Permission::Manage.as_str().to_string())
        } else if r.org_id.is_some() {
            // Org cipher — compute effective permission.
            crate::perms::effective_permission(&state, &user.user_id, &r.id)
                .await?
                .map(|p| p.as_str().to_string())
        } else {
            None
        };
        let mut v = r.into_view(cids);
        v.permission = permission;
        ciphers.push(v);
    }
    let folders: Vec<FolderView> = folder_rows.into_iter().map(Into::into).collect();
    let collections = collections_for_user(&state, &user.user_id).await?;
    let attachments = attachments_for_user(&state, &user.user_id, &since).await?;
    let sends = sends_for_user(&state, &user.user_id, &since).await?;

    // Fold attachment + send revision_dates into the high-water cursor
    // so the next /sync call doesn't miss attachment- or send-only
    // changes that happen without bumping any cipher/folder/tombstone
    // row directly.
    let high_water = std::iter::once(high_water.as_str())
        .chain(attachments.iter().map(|a| a.revision_date.as_str()))
        .chain(sends.iter().map(|s| s.revision_date.as_str()))
        .max()
        .unwrap_or(high_water.as_str())
        .to_string();

    let manifest = latest_manifest(&state, &user.user_id).await?;
    let orgs = orgs_for_user(&state, &user.user_id).await?;

    Ok(Json(SyncResponse {
        changes: Changes {
            ciphers,
            folders,
            tombstones,
            collections,
            attachments,
            sends,
        },
        high_water,
        server_time,
        complete: true,
        manifest,
        orgs,
    }))
}

/// Sender's own Sends with `revision_date > since`. Recipients never
/// hit /sync — they go through the public access endpoint.
async fn sends_for_user(
    state: &AppState,
    user_id: &str,
    since: &str,
) -> Result<Vec<SendView>, ApiError> {
    let rows: Vec<SendRow> = sqlx::query_as(
        "SELECT id, user_id, send_type, name, notes, protected_send_key, data,
                password_phc, max_access_count, access_count,
                expiration_date, deletion_date, disabled,
                revision_date, creation_date
         FROM sends
         WHERE user_id = $1 AND revision_date > $2
         ORDER BY revision_date ASC",
    )
    .bind(user_id)
    .bind(since)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(rows.into_iter().map(SendRow::into_view).collect())
}

/// Return finalized attachment rows visible to the caller whose
/// `revision_date > since`. Visibility mirrors cipher visibility:
/// caller owns the parent cipher (personal) OR has any
/// `effective_permission` on it (org).
async fn attachments_for_user(
    state: &AppState,
    user_id: &str,
    since: &str,
) -> Result<Vec<AttachmentView>, ApiError> {
    // Personal: rows whose parent cipher is owned by user. Org: rows
    // whose parent cipher is org-owned and the caller has a permission
    // row in any of its collections (or is org owner). We compute that
    // by joining ciphers + collection_members the same way /sync does
    // for ciphers, but for the attachment row.
    let rows: Vec<AttachmentRow> = sqlx::query_as(
        "SELECT a.id, a.cipher_id, a.filename, a.content_key,
                a.size_pt, a.size_ct, a.content_hash_b3,
                a.revision_date, a.creation_date, a.status
         FROM attachments a
         JOIN ciphers c ON c.id = a.cipher_id
         WHERE a.status = 1
           AND a.revision_date > $2
           AND (c.user_id = $1
                OR (c.org_id IS NOT NULL AND EXISTS
                     (SELECT 1 FROM organizations o
                      WHERE o.id = c.org_id AND o.owner_user_id = $1))
                OR EXISTS
                     (SELECT 1
                      FROM cipher_collections cc
                      JOIN collection_members m
                        ON m.collection_id = cc.collection_id
                      WHERE cc.cipher_id = c.id AND m.user_id = $1))
         ORDER BY a.revision_date ASC",
    )
    .bind(user_id)
    .bind(since)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(rows.into_iter().map(|r| r.into_view()).collect())
}

/// Every org the user is currently a member of (status accepted),
/// with the latest signed roster inline. Used by M4.2 BW08
/// roster-verification on /sync.
async fn orgs_for_user(state: &AppState, user_id: &str) -> Result<Vec<OrgSyncEntry>, ApiError> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        String,
        String,
        i64,
        String,
        String,
        String,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT o.id, o.name, m.role, m.org_sym_key_id,
                o.roster_version, o.roster_updated_at,
                o.roster_canonical_b64, o.roster_signature_b64,
                m.pending_org_key_envelope_json
         FROM organization_members m
         JOIN organizations o ON o.id = m.org_id
         WHERE m.user_id = $1
         ORDER BY o.id ASC",
    )
    .bind(user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let mut out = Vec::with_capacity(rows.len());
    for (
        org_id,
        name,
        role,
        org_sym_key_id,
        roster_version,
        roster_updated_at,
        roster_canonical_b64,
        roster_signature_b64,
        pending_json,
    ) in rows
    {
        let pending_envelope = match pending_json.as_deref() {
            Some(j) if !j.is_empty() => Some(
                serde_json::from_str::<serde_json::Value>(j)
                    .map_err(|e| ApiError::internal(e.to_string()))?,
            ),
            _ => None,
        };
        let policies = load_policies(state, &org_id).await?;
        let cipher_manifest = latest_org_cipher_manifest(state, &org_id).await?;
        out.push(OrgSyncEntry {
            org_id,
            name,
            role,
            org_sym_key_id,
            roster_version,
            roster_updated_at,
            roster: SignedOrgRosterWire {
                canonical_b64: roster_canonical_b64,
                signature_b64: roster_signature_b64,
            },
            pending_envelope,
            policies,
            cipher_manifest,
        });
    }
    Ok(out)
}

// --- private row types (mirror the public Views; private to avoid leaking
//     sqlx::FromRow into the wire-type modules)

use crate::routes::ciphers::CipherRow;
use std::collections::HashMap;

/// Batch-fetch the cipher_collections rows for the given cipher ids,
/// returning `cipher_id -> [collection_id]`. Empty vec for ids with
/// no rows.
async fn load_cipher_collections(
    state: &AppState,
    cipher_ids: &[&str],
) -> Result<HashMap<String, Vec<String>>, ApiError> {
    if cipher_ids.is_empty() {
        return Ok(HashMap::new());
    }
    // sqlx doesn't support array binds across both Postgres+SQLite
    // uniformly with `Any`, so issue one query per id. Fine here:
    // the org-cipher count is small in the M4.3 era.
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for id in cipher_ids {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT collection_id FROM cipher_collections WHERE cipher_id = $1")
                .bind(*id)
                .fetch_all(state.db.pool())
                .await
                .map_err(|e| ApiError::internal(e.to_string()))?;
        out.insert((*id).to_string(), rows.into_iter().map(|(c,)| c).collect());
    }
    Ok(out)
}

/// Every collection across every org the user belongs to. Plaintext
/// id + org_id; encrypted name (under the org sym key).
async fn collections_for_user(
    state: &AppState,
    user_id: &str,
) -> Result<Vec<CollectionView>, ApiError> {
    let rows: Vec<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT c.id, c.org_id, c.name, c.revision_date, c.creation_date
         FROM organization_collections c
         JOIN organization_members m ON m.org_id = c.org_id
         WHERE m.user_id = $1
         ORDER BY c.creation_date ASC",
    )
    .bind(user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(rows
        .into_iter()
        .map(
            |(id, org_id, name, revision_date, creation_date)| CollectionView {
                id,
                org_id,
                name,
                revision_date,
                creation_date,
            },
        )
        .collect())
}

#[derive(sqlx::FromRow)]
struct FolderRow {
    id: String,
    name: String,
    revision_date: String,
    creation_date: String,
}

impl From<FolderRow> for FolderView {
    fn from(r: FolderRow) -> Self {
        FolderView {
            id: r.id,
            name: r.name,
            revision_date: r.revision_date,
            creation_date: r.creation_date,
        }
    }
}
