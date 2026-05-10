//! Organization endpoints (M4.0).
//!
//! ## Routes shipped
//!
//!   * `POST /api/v1/orgs`              create an org
//!   * `GET  /api/v1/account/orgs`      list orgs the caller belongs to
//!   * `GET  /api/v1/orgs/{id}`         org view (caller must be a member)
//!
//! Future M4.x milestones light up invites/accept (M4.1), roster
//! verification on `/sync` (M4.2), collections (M4.3), permissions
//! (M4.4), member removal + key rotation (M4.5), and policies (M4.6).
//! See `docs/m4-organizations.md` for the design rationale.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hekate_core::{
    encstring::EncString,
    org_roster::{decode_canonical as decode_roster_canonical, NO_PARENT_HASH},
    signcrypt,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    auth::{scope, AuthUser},
    routes::{accounts::ApiError, policies::user_is_pinned_to_single_org},
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/orgs", post(create))
        .route("/api/v1/account/orgs", get(list_mine))
        .route("/api/v1/orgs/{org_id}", get(get_one))
        .route("/api/v1/orgs/{org_id}/invites", post(invite))
        .route(
            "/api/v1/orgs/{org_id}/invites/{invitee_user_id}",
            delete(cancel_invite),
        )
        .route("/api/v1/orgs/{org_id}/accept", post(accept))
        .route("/api/v1/account/invites", get(list_my_invites))
        .route(
            "/api/v1/orgs/{org_id}/members/{user_id}/revoke",
            post(revoke_member),
        )
        .route("/api/v1/orgs/{org_id}/rotate-confirm", post(rotate_confirm))
        .route("/api/v1/orgs/{org_id}/prune-roster", post(prune_roster))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateOrgRequest {
    /// Client-supplied UUIDv7. Bound into bundle_sig and roster.
    pub id: String,
    /// Plaintext display name. Non-secret.
    pub name: String,
    /// 32-byte Ed25519 public key for the org, base64-no-pad.
    pub signing_pubkey: String,
    /// 64-byte Ed25519 signature by the *owner's* account signing key
    /// over canonical(org_id, name, signing_pubkey, owner_user_id).
    pub bundle_sig: String,
    /// EncString v3 of the org's signing seed, wrapped under the owner's
    /// account_key. Server stores verbatim; never decrypts.
    pub protected_signing_seed: String,
    /// UUIDv7 for the initial org symmetric key version.
    pub org_sym_key_id: String,
    /// EncString v3 of the org symmetric key, wrapped under the owner's
    /// account_key. The owner's `protected_org_key` row.
    pub owner_protected_org_key: String,
    /// Genesis roster (version=1, parent=zeros, single entry: the
    /// owner). Server validates the signature under `signing_pubkey`.
    pub roster: SignedOrgRosterWire,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct SignedOrgRosterWire {
    pub canonical_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OrgView {
    pub id: String,
    pub name: String,
    pub signing_pubkey: String,
    pub bundle_sig: String,
    pub owner_user_id: String,
    pub org_sym_key_id: String,
    pub roster: SignedOrgRosterWire,
    pub roster_version: i64,
    pub roster_updated_at: String,
    /// The caller's role in this org. Convenience for clients.
    pub my_role: String,
    /// EncString v3, the caller's wrapped copy of the org symmetric key.
    pub my_protected_org_key: String,
    /// EncString v3 of the org signing seed under the OWNER's
    /// account_key. Only populated when the caller is the owner —
    /// they need it to sign new rosters when inviting / removing
    /// members. `None` for admins / users.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_protected_signing_seed: Option<String>,
    /// Map of `user_id → email` for every co-member of this org.
    /// Lets clients render human-readable identifiers in the member
    /// list instead of raw UUIDs. Not an enumeration leak: every
    /// caller of this endpoint is already an org member, so they can
    /// already see the full user_id list via the signed roster.
    /// Empty when no members are in the users table (shouldn't happen
    /// in practice — defensive default for ON DELETE CASCADE races).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub member_emails: HashMap<String, String>,
    /// GH #2/#3: users who have a pending invite for this org but
    /// haven't accepted yet. Owner sees this so they know who's been
    /// invited; non-owner members see an empty map (nothing to act
    /// on). Each value is `{role, email}` so the UI can render the
    /// row identically to accepted members but tag it as pending.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub pending_invitees: HashMap<String, PendingInviteeView>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PendingInviteeView {
    pub role: String,
    /// Optional — pulled from the users JOIN; missing for cascade-race
    /// edge cases.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

/// Create an organization. Caller becomes the sole owner.
#[utoipa::path(
    post,
    path = "/api/v1/orgs",
    tag = "orgs",
    request_body = CreateOrgRequest,
    responses(
        (status = 201, description = "Created", body = OrgView),
        (status = 400, description = "Validation failed", body = crate::routes::accounts::ErrorResponse),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Insufficient scope"),
        (status = 409, description = "Org id already exists", body = crate::routes::accounts::ErrorResponse),
    ),
    security(("bearerAuth" = [])),
)]
async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateOrgRequest>,
) -> Result<(StatusCode, Json<OrgView>), ApiError> {
    user.require(scope::VAULT_WRITE)?;

    Uuid::parse_str(&req.id).map_err(|_| ApiError::bad_request("id is not a valid UUID"))?;
    Uuid::parse_str(&req.org_sym_key_id)
        .map_err(|_| ApiError::bad_request("org_sym_key_id is not a valid UUID"))?;
    if req.name.trim().is_empty() {
        return Err(ApiError::bad_request("name must not be empty"));
    }

    // Decode + length-check the cryptographic fields.
    let signing_pk = decode_fixed::<32>(&req.signing_pubkey, "signing_pubkey")?;
    let bundle_sig_bytes = decode_fixed::<64>(&req.bundle_sig, "bundle_sig")?;

    // Look up the owner's pubkey bundle so we can verify bundle_sig.
    // The owner *is* the authenticated user.
    let owner_signing_pk_b64: Option<(String,)> =
        sqlx::query_as("SELECT account_signing_pubkey_b64 FROM users WHERE id = $1")
            .bind(&user.user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let owner_signing_pk_b64 = owner_signing_pk_b64
        .map(|(s,)| s)
        .ok_or_else(|| ApiError::internal("owner row missing"))?;
    if owner_signing_pk_b64.is_empty() {
        return Err(ApiError::bad_request(
            "owner has no account_signing_pubkey — re-register on a fresh DB",
        ));
    }
    let owner_signing_pk = decode_fixed::<32>(&owner_signing_pk_b64, "owner_signing_pubkey")?;

    // bundle_sig binds the owner's identity to this org. canonical() form
    // mirrors `hekate-core::signcrypt::pubkey_bundle_canonical_bytes` — same
    // length-prefixed layout, different DST. Hand-roll here so a future
    // refactor doesn't accidentally re-use the pubkey-bundle DST.
    let bundle_canonical = build_bundle_canonical(&req.id, &req.name, &signing_pk, &user.user_id);
    let owner_vk = VerifyingKey::from_bytes(&owner_signing_pk)
        .map_err(|_| ApiError::bad_request("owner signing pubkey is not Ed25519"))?;
    let bundle_sig = Signature::from_slice(&bundle_sig_bytes)
        .map_err(|_| ApiError::bad_request("bundle_sig has wrong length"))?;
    owner_vk
        .verify(&bundle_canonical, &bundle_sig)
        .map_err(|_| {
            ApiError::bad_request("bundle_sig did not verify under owner's signing key")
        })?;

    // Validate the genesis roster: signed under the *new* org signing
    // pubkey, version=1, parent=zeros, exactly one entry == (owner, "owner"),
    // and org_sym_key_id matches.
    let roster_canonical = STANDARD_NO_PAD
        .decode(&req.roster.canonical_b64)
        .map_err(|_| ApiError::bad_request("roster.canonical_b64 not base64-no-pad"))?;
    let roster_sig_bytes = decode_fixed::<64>(&req.roster.signature_b64, "roster.signature_b64")?;
    let roster_sig = Signature::from_slice(&roster_sig_bytes)
        .map_err(|_| ApiError::bad_request("roster signature has wrong length"))?;
    let org_vk = VerifyingKey::from_bytes(&signing_pk)
        .map_err(|_| ApiError::bad_request("signing_pubkey is not Ed25519"))?;
    org_vk
        .verify(&roster_canonical, &roster_sig)
        .map_err(|_| ApiError::bad_request("roster signature did not verify"))?;
    let roster = decode_roster_canonical(&roster_canonical)
        .map_err(|e| ApiError::bad_request(format!("roster canonical parse: {e}")))?;
    if roster.org_id != req.id {
        return Err(ApiError::bad_request("roster org_id != request id"));
    }
    if roster.version != 1 {
        return Err(ApiError::bad_request("genesis roster must have version=1"));
    }
    if roster.parent_canonical_sha256 != NO_PARENT_HASH {
        return Err(ApiError::bad_request(
            "genesis roster must have parent_canonical_sha256 = zeros",
        ));
    }
    if roster.org_sym_key_id != req.org_sym_key_id {
        return Err(ApiError::bad_request(
            "roster org_sym_key_id != request org_sym_key_id",
        ));
    }
    if roster.entries.len() != 1
        || roster.entries[0].user_id != user.user_id
        || roster.entries[0].role != "owner"
    {
        return Err(ApiError::bad_request(
            "genesis roster must have exactly one entry == (owner_user_id, \"owner\")",
        ));
    }

    // M4.6 single_org enforcement: same gate as /accept — if the caller
    // is already in any org with `single_org` enabled, they can't open
    // a second one (creating an org makes them a member of it).
    if user_is_pinned_to_single_org(&state, &user.user_id).await? {
        return Err(ApiError::forbidden(
            "blocked by `single_org` policy on a current org membership",
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let result = sqlx::query(
        "INSERT INTO organizations (
            id, name, signing_pubkey_b64, bundle_sig_b64, owner_user_id,
            org_sym_key_id,
            roster_version, roster_canonical_b64, roster_signature_b64, roster_updated_at,
            created_at, revision_date
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(&req.id)
    .bind(&req.name)
    .bind(&req.signing_pubkey)
    .bind(&req.bundle_sig)
    .bind(&user.user_id)
    .bind(&req.org_sym_key_id)
    .bind(1_i64)
    .bind(&req.roster.canonical_b64)
    .bind(&req.roster.signature_b64)
    .bind(&now)
    .bind(&now)
    .bind(&now)
    .execute(&mut *tx)
    .await;
    match result {
        Ok(_) => {}
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            return Err(ApiError::conflict("org id already exists"));
        }
        Err(e) => return Err(ApiError::internal(e.to_string())),
    }

    sqlx::query(
        "INSERT INTO organization_owner_keys (org_id, protected_signing_seed)
         VALUES ($1, $2)",
    )
    .bind(&req.id)
    .bind(&req.protected_signing_seed)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    sqlx::query(
        "INSERT INTO organization_members
            (org_id, user_id, role, protected_org_key, org_sym_key_id, joined_at)
         VALUES ($1, $2, 'owner', $3, $4, $5)",
    )
    .bind(&req.id)
    .bind(&user.user_id)
    .bind(&req.owner_protected_org_key)
    .bind(&req.org_sym_key_id)
    .bind(&now)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // Suppress unused-import warning for `signcrypt` — M4.1 will use
    // it when the invite flow lands. Keep the import grouped now so
    // that diff stays small.
    let _ = signcrypt::sign_pubkey_bundle;

    // Genesis create: the owner is the only member, so member_emails
    // has exactly their own row. Look it up for parity with the GET
    // path so first-load clients see the email straight away.
    let owner_email_row: Option<(String,)> =
        sqlx::query_as("SELECT email FROM users WHERE id = $1")
            .bind(&user.user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let mut member_emails: HashMap<String, String> = HashMap::new();
    if let Some((email,)) = owner_email_row {
        member_emails.insert(user.user_id.clone(), email);
    }

    Ok((
        StatusCode::CREATED,
        Json(OrgView {
            id: req.id,
            name: req.name,
            signing_pubkey: req.signing_pubkey,
            bundle_sig: req.bundle_sig,
            owner_user_id: user.user_id,
            org_sym_key_id: req.org_sym_key_id,
            roster: req.roster,
            roster_version: 1,
            roster_updated_at: now,
            my_role: "owner".into(),
            my_protected_org_key: req.owner_protected_org_key,
            owner_protected_signing_seed: Some(req.protected_signing_seed),
            member_emails,
            // Newly-minted org has no pending invites yet.
            pending_invitees: HashMap::new(),
        }),
    ))
}

/// Helper: canonical bytes the owner Ed25519-signs to bind their
/// identity to the org. Layout:
///
///   "pmgr-org-bundle-v1\\0"
///   || u32(org_id.len)         || org_id
///   || u32(name.len)            || name
///   || signing_pubkey (32B)
///   || u32(owner_user_id.len)  || owner_user_id
fn build_bundle_canonical(
    org_id: &str,
    name: &str,
    signing_pubkey: &[u8; 32],
    owner_user_id: &str,
) -> Vec<u8> {
    hekate_core::org_roster::org_bundle_canonical_bytes(org_id, name, signing_pubkey, owner_user_id)
}

fn decode_fixed<const N: usize>(b64: &str, field: &str) -> Result<[u8; N], ApiError> {
    let bytes = STANDARD_NO_PAD
        .decode(b64)
        .map_err(|_| ApiError::bad_request(format!("{field} not base64-no-pad")))?;
    if bytes.len() != N {
        return Err(ApiError::bad_request(format!(
            "{field} expected {N} bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OrgListItem {
    pub id: String,
    pub name: String,
    pub role: String,
    pub roster_version: i64,
    pub member_count: i64,
}

/// List orgs the caller is a member of.
#[utoipa::path(
    get,
    path = "/api/v1/account/orgs",
    tag = "orgs",
    responses(
        (status = 200, description = "OK", body = Vec<OrgListItem>),
        (status = 401, description = "Unauthenticated"),
    ),
    security(("bearerAuth" = [])),
)]
async fn list_mine(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<Vec<OrgListItem>>, ApiError> {
    user.require(scope::VAULT_READ)?;

    let rows: Vec<(String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT o.id, o.name, m.role, o.roster_version,
                (SELECT COUNT(*) FROM organization_members m2 WHERE m2.org_id = o.id) AS member_count
         FROM organization_members m
         JOIN organizations o ON o.id = m.org_id
         WHERE m.user_id = $1
         ORDER BY o.created_at ASC",
    )
    .bind(&user.user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(
        rows.into_iter()
            .map(
                |(id, name, role, roster_version, member_count)| OrgListItem {
                    id,
                    name,
                    role,
                    roster_version,
                    member_count,
                },
            )
            .collect(),
    ))
}

/// Org view — caller must be a member.
#[utoipa::path(
    get,
    path = "/api/v1/orgs/{org_id}",
    tag = "orgs",
    params(("org_id" = String, Path, description = "Org UUID")),
    responses(
        (status = 200, description = "OK", body = OrgView),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Not a member"),
        (status = 404, description = "Org not found"),
    ),
    security(("bearerAuth" = [])),
)]
async fn get_one(
    user: AuthUser,
    State(state): State<AppState>,
    Path(org_id): Path<String>,
) -> Result<Json<OrgView>, ApiError> {
    user.require(scope::VAULT_READ)?;

    #[allow(clippy::type_complexity)]
    let row: Option<(
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
        String,
        String,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT o.id, o.name, o.signing_pubkey_b64, o.bundle_sig_b64, o.owner_user_id,
                o.roster_version, o.roster_canonical_b64, o.roster_signature_b64,
                o.roster_updated_at, o.org_sym_key_id, m.protected_org_key
         FROM organizations o
         JOIN organization_members m ON m.org_id = o.id AND m.user_id = $2
         WHERE o.id = $1",
    )
    .bind(&org_id)
    .bind(&user.user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let Some((
        id,
        name,
        signing_pubkey,
        bundle_sig,
        owner_user_id,
        roster_version,
        roster_canonical,
        roster_signature,
        roster_updated_at,
        org_sym_key_id,
        my_protected_org_key,
    )) = row
    else {
        return Err(ApiError::not_found("org"));
    };

    // Look up role separately — it's on the same row but we already
    // joined for membership; one more query keeps the SELECT readable.
    let role_row: Option<(String,)> =
        sqlx::query_as("SELECT role FROM organization_members WHERE org_id = $1 AND user_id = $2")
            .bind(&org_id)
            .bind(&user.user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let my_role = role_row
        .map(|(r,)| r)
        .ok_or_else(|| ApiError::internal("member row missing"))?;

    // Owners get the wrapped signing seed back so they can sign new
    // rosters from the CLI without an extra round trip.
    let owner_protected_signing_seed = if owner_user_id == user.user_id {
        let seed_row: Option<(String,)> = sqlx::query_as(
            "SELECT protected_signing_seed FROM organization_owner_keys WHERE org_id = $1",
        )
        .bind(&org_id)
        .fetch_optional(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
        seed_row.map(|(s,)| s)
    } else {
        None
    };

    // Co-member emails. JOIN organization_members → users so the
    // client can render `email` instead of `user_id` when known. Only
    // emails of users who actually have a row are returned (deleted
    // users / cascade races simply don't appear).
    let email_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT m.user_id, u.email
         FROM organization_members m
         JOIN users u ON u.id = m.user_id
         WHERE m.org_id = $1",
    )
    .bind(&org_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let member_emails: HashMap<String, String> = email_rows.into_iter().collect();

    // GH #2/#3: pending invitees. Only the owner needs (or can act
    // on) this view; non-owner members see an empty map. Surfacing
    // it lets the UI distinguish "in the roster" from "actually a
    // member" — the GH #3 symptom.
    let pending_invitees: HashMap<String, PendingInviteeView> = if owner_user_id == user.user_id {
        let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT i.invitee_user_id, i.invited_role, u.email
                 FROM organization_invites i
                 LEFT JOIN users u ON u.id = i.invitee_user_id
                 WHERE i.org_id = $1",
        )
        .bind(&org_id)
        .fetch_all(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
        rows.into_iter()
            .map(|(uid, role, email)| (uid, PendingInviteeView { role, email }))
            .collect()
    } else {
        HashMap::new()
    };

    Ok(Json(OrgView {
        id,
        name,
        signing_pubkey,
        bundle_sig,
        owner_user_id,
        org_sym_key_id,
        roster: SignedOrgRosterWire {
            canonical_b64: roster_canonical,
            signature_b64: roster_signature,
        },
        roster_version,
        roster_updated_at,
        my_role,
        my_protected_org_key,
        owner_protected_signing_seed,
        member_emails,
        pending_invitees,
    }))
}

// ===========================================================================
// M4.1 — invites
// ===========================================================================

#[derive(Debug, Deserialize, ToSchema)]
pub struct InviteRequest {
    pub invitee_user_id: String,
    pub role: String, // "admin" | "user"
    /// SealedEnvelope JSON (M2.18 signcrypt). Server stores verbatim;
    /// only the invitee can decrypt.
    pub envelope: serde_json::Value,
    /// Roster v(n+1) including the invitee. Owner pre-signs at invite
    /// time per the design doc §6.2 — invited members are immediately
    /// in the signed roster (intended-membership semantics).
    pub next_roster: SignedOrgRosterWire,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct InviteView {
    pub org_id: String,
    pub org_name: String,
    pub inviter_user_id: String,
    pub role: String,
    pub envelope: serde_json::Value,
    pub invited_at: String,
    pub roster_version: i64,
    /// Latest signed roster (canonical + Ed25519 sig under org signing
    /// key). Bundled here so the invitee can verify membership entirely
    /// from invite-time data — they have no membership row to JOIN
    /// against on `GET /api/v1/orgs/{id}` until they accept.
    pub roster: SignedOrgRosterWire,
}

/// Owner-only. Invite a user to the org. The signcryption envelope
/// wraps the org symmetric key + signing pubkey + role to the invitee
/// under the recipient's M2.19 X25519 pubkey, signed by the owner
/// under their account signing key. The accompanying `next_roster`
/// adds the invitee to the signed roster ahead of acceptance.
#[utoipa::path(
    post,
    path = "/api/v1/orgs/{org_id}/invites",
    tag = "orgs",
    params(("org_id" = String, Path, description = "Org UUID")),
    request_body = InviteRequest,
    responses(
        (status = 201, description = "Invited"),
        (status = 400, description = "Validation failed", body = crate::routes::accounts::ErrorResponse),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Caller is not the org owner"),
        (status = 404, description = "Org or invitee not found"),
        (status = 409, description = "Roster version not next-after-current", body = crate::routes::accounts::ErrorResponse),
    ),
    security(("bearerAuth" = [])),
)]
pub async fn invite(
    user: AuthUser,
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Json(req): Json<InviteRequest>,
) -> Result<StatusCode, ApiError> {
    user.require(scope::VAULT_WRITE)?;

    if req.invitee_user_id == user.user_id {
        return Err(ApiError::bad_request(
            "cannot invite yourself; you're already the owner",
        ));
    }
    if req.role != "admin" && req.role != "user" {
        return Err(ApiError::bad_request("role must be \"admin\" or \"user\""));
    }

    // Org + owner check.
    let org = load_org_for_owner(&state, &org_id, &user.user_id).await?;

    // Invitee must exist (we don't validate their pubkey here — the
    // envelope's recipient is the invitee's X25519 from the M2.19
    // directory and the owner already TOFU-pinned them client-side).
    let exists: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM users WHERE id = $1")
        .bind(&req.invitee_user_id)
        .fetch_optional(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if exists.is_none() {
        return Err(ApiError::not_found("invitee user"));
    }

    // Single-pending-per-org invariant: the next_roster is built off
    // the live roster's parent_canonical, so two simultaneous pending
    // invites would both target the same v=current+1 with diverging
    // entries. Reject up-front and ask the owner to cancel/wait.
    // GH #2.
    let pending_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM organization_invites WHERE org_id = $1")
            .bind(&org_id)
            .fetch_one(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    if pending_count.0 > 0 {
        return Err(ApiError::conflict(
            "another invite for this org is still pending — cancel it or wait for accept before issuing another",
        ));
    }

    // Verify next_roster signature + chain (it must build on the
    // current live roster). Don't advance live yet — we store this
    // roster as PENDING on the invite row, then promote it on accept.
    let parsed_roster = verify_and_advance_roster(&state, &org, &req.next_roster).await?;
    if !parsed_roster
        .entries
        .iter()
        .any(|e| e.user_id == req.invitee_user_id && e.role == req.role)
    {
        return Err(ApiError::bad_request(
            "next_roster does not include the invitee at the claimed role",
        ));
    }

    let envelope_json =
        serde_json::to_string(&req.envelope).map_err(|e| ApiError::internal(e.to_string()))?;
    let now = chrono::Utc::now().to_rfc3339();

    // Single INSERT — no transaction needed since we no longer touch
    // the organizations table. PK (org_id, invitee_user_id) catches
    // the same-user duplicate; the count check above catches the
    // different-user case.
    let result = sqlx::query(
        "INSERT INTO organization_invites
            (org_id, invitee_user_id, envelope_json, invited_role, invited_at,
             pending_roster_canonical_b64, pending_roster_signature_b64,
             pending_roster_version)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&org_id)
    .bind(&req.invitee_user_id)
    .bind(&envelope_json)
    .bind(&req.role)
    .bind(&now)
    .bind(&req.next_roster.canonical_b64)
    .bind(&req.next_roster.signature_b64)
    .bind(parsed_roster.version as i64)
    .execute(state.db.pool())
    .await;
    match result {
        Ok(_) => {}
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            return Err(ApiError::conflict(
                "invitee already has a pending invite for this org",
            ));
        }
        Err(e) => return Err(ApiError::internal(e.to_string())),
    }
    Ok(StatusCode::CREATED)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AcceptRequest {
    /// EncString v3 of the org symmetric key, wrapped under the
    /// invitee's account_key. Persists post-accept so future cipher
    /// unwraps don't need re-running signcryption.
    pub protected_org_key: String,
    /// Must match the org's current `org_sym_key_id` so an old
    /// invite (referring to a rotated-out key) can't be accepted
    /// against a newer org_sym_key_id.
    pub org_sym_key_id: String,
}

/// Invitee accepts an outstanding invitation. They've already
/// verified the envelope client-side (signcryption + bundle sig +
/// roster sig); the server moves the invite row to a member row.
#[utoipa::path(
    post,
    path = "/api/v1/orgs/{org_id}/accept",
    tag = "orgs",
    params(("org_id" = String, Path, description = "Org UUID")),
    request_body = AcceptRequest,
    responses(
        (status = 200, description = "Accepted"),
        (status = 400, description = "Validation failed", body = crate::routes::accounts::ErrorResponse),
        (status = 401, description = "Unauthenticated"),
        (status = 404, description = "No pending invite"),
    ),
    security(("bearerAuth" = [])),
)]
pub async fn accept(
    user: AuthUser,
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Json(req): Json<AcceptRequest>,
) -> Result<StatusCode, ApiError> {
    user.require(scope::VAULT_WRITE)?;

    let invite_row: Option<(String, String, String, String, i64)> = sqlx::query_as(
        "SELECT invited_role, invited_at,
                pending_roster_canonical_b64, pending_roster_signature_b64,
                pending_roster_version
           FROM organization_invites
          WHERE org_id = $1 AND invitee_user_id = $2",
    )
    .bind(&org_id)
    .bind(&user.user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let (role, _invited_at, pending_canonical_b64, pending_signature_b64, pending_version) =
        match invite_row {
            Some(r) => r,
            None => return Err(ApiError::not_found("no pending invite")),
        };
    // GH #2 legacy guard: rows from before migration 0023 have empty
    // pending_roster fields. They predate the protocol change and
    // can't be promoted; surface a clear error so the owner cancels +
    // re-issues.
    if pending_canonical_b64.is_empty() || pending_version == 0 {
        return Err(ApiError::bad_request(
            "this invite predates the pending-roster protocol change; ask the owner to cancel and re-issue",
        ));
    }

    let key_id_row: Option<(String,)> =
        sqlx::query_as("SELECT org_sym_key_id FROM organizations WHERE id = $1")
            .bind(&org_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let current_key_id = match key_id_row {
        Some((k,)) => k,
        None => return Err(ApiError::not_found("org")),
    };
    if current_key_id != req.org_sym_key_id {
        return Err(ApiError::bad_request(
            "org_sym_key_id no longer current — refetch the invite envelope",
        ));
    }

    // M4.6 single_org enforcement: if any org the caller is already in
    // has an enabled `single_org` policy, refuse to add a second
    // membership.
    if user_is_pinned_to_single_org(&state, &user.user_id).await? {
        return Err(ApiError::forbidden(
            "blocked by `single_org` policy on a current org membership",
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    sqlx::query(
        "INSERT INTO organization_members
            (org_id, user_id, role, protected_org_key, org_sym_key_id, joined_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&org_id)
    .bind(&user.user_id)
    .bind(&role)
    .bind(&req.protected_org_key)
    .bind(&req.org_sym_key_id)
    .bind(&now)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    // GH #2: promote the pending roster to live. The invitee already
    // verified the signature client-side under the org's TOFU-pinned
    // signing key before posting accept, so we just trust + apply.
    apply_roster(
        &mut tx,
        &org_id,
        &SignedOrgRosterWire {
            canonical_b64: pending_canonical_b64,
            signature_b64: pending_signature_b64,
        },
        &now,
        pending_version as u64,
    )
    .await?;

    sqlx::query("DELETE FROM organization_invites WHERE org_id = $1 AND invitee_user_id = $2")
        .bind(&org_id)
        .bind(&user.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(StatusCode::OK)
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct CancelInviteRequest {
    /// **Ignored as of GH #2.** Older clients sent a roster
    /// rolling back the cancelled invitee. With pending-roster
    /// semantics the live roster never advanced in the first place,
    /// so there's nothing to roll back. Field is accepted (and
    /// dropped) for backward-compat with un-upgraded CLI/popup
    /// builds; future clients can omit it entirely.
    #[serde(default)]
    pub next_roster: Option<SignedOrgRosterWire>,
}

/// Owner-only. Cancel an outstanding (un-accepted) invite. Deletes
/// the invite row including its pending roster — live roster is
/// untouched since it was never advanced (GH #2).
#[utoipa::path(
    delete,
    path = "/api/v1/orgs/{org_id}/invites/{invitee_user_id}",
    tag = "orgs",
    params(
        ("org_id" = String, Path, description = "Org UUID"),
        ("invitee_user_id" = String, Path, description = "User to un-invite"),
    ),
    request_body = CancelInviteRequest,
    responses(
        (status = 204, description = "Cancelled"),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Caller is not the org owner"),
        (status = 404, description = "No pending invite"),
    ),
    security(("bearerAuth" = [])),
)]
pub async fn cancel_invite(
    user: AuthUser,
    State(state): State<AppState>,
    Path((org_id, invitee_user_id)): Path<(String, String)>,
    Json(_req): Json<CancelInviteRequest>,
) -> Result<StatusCode, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    // load_org_for_owner gates on the caller being the org owner —
    // returns 403/404 otherwise.
    let _ = load_org_for_owner(&state, &org_id, &user.user_id).await?;

    let res = sqlx::query(
        "DELETE FROM organization_invites
          WHERE org_id = $1 AND invitee_user_id = $2",
    )
    .bind(&org_id)
    .bind(&invitee_user_id)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("no pending invite"));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// List invitations the caller has received and not yet accepted.
#[utoipa::path(
    get,
    path = "/api/v1/account/invites",
    tag = "orgs",
    responses(
        (status = 200, description = "OK", body = Vec<InviteView>),
        (status = 401, description = "Unauthenticated"),
    ),
    security(("bearerAuth" = [])),
)]
pub async fn list_my_invites(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<Vec<InviteView>>, ApiError> {
    user.require(scope::VAULT_READ)?;

    // GH #2: roster fields come from the INVITE row's pending columns
    // now, not the live `organizations` row. The pending roster is the
    // one the invitee verifies against (it includes them at the
    // claimed role); promoting it to live is the server-side effect
    // of accept.
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT i.org_id, o.name, o.owner_user_id, i.invited_role,
                    i.envelope_json, i.invited_at,
                    i.pending_roster_version,
                    i.pending_roster_canonical_b64,
                    i.pending_roster_signature_b64
             FROM organization_invites i
             JOIN organizations o ON o.id = i.org_id
             WHERE i.invitee_user_id = $1
             ORDER BY i.invited_at ASC",
    )
    .bind(&user.user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let mut out = Vec::with_capacity(rows.len());
    for (
        org_id,
        org_name,
        inviter,
        role,
        envelope_json,
        invited_at,
        roster_version,
        roster_canonical_b64,
        roster_signature_b64,
    ) in rows
    {
        let envelope: serde_json::Value =
            serde_json::from_str(&envelope_json).map_err(|e| ApiError::internal(e.to_string()))?;
        out.push(InviteView {
            org_id,
            org_name,
            inviter_user_id: inviter,
            role,
            envelope,
            invited_at,
            roster_version,
            roster: SignedOrgRosterWire {
                canonical_b64: roster_canonical_b64,
                signature_b64: roster_signature_b64,
            },
        });
    }
    Ok(Json(out))
}

// ===========================================================================
// helpers
// ===========================================================================

struct OrgForOwner {
    id: String,
    signing_pubkey_b64: String,
    org_sym_key_id: String,
    roster_version: i64,
    roster_canonical_b64: String,
}

async fn load_org_for_owner(
    state: &AppState,
    org_id: &str,
    user_id: &str,
) -> Result<OrgForOwner, ApiError> {
    let row: Option<(String, String, String, String, String, i64, String)> = sqlx::query_as(
        "SELECT id, owner_user_id, name, signing_pubkey_b64, org_sym_key_id,
                roster_version, roster_canonical_b64
         FROM organizations WHERE id = $1",
    )
    .bind(org_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let Some((
        id,
        owner_user_id,
        _name,
        signing_pubkey_b64,
        org_sym_key_id,
        roster_version,
        roster_canonical_b64,
    )) = row
    else {
        return Err(ApiError::not_found("org"));
    };
    if owner_user_id != user_id {
        // 404 (not 403) so a non-owner can't probe org existence.
        return Err(ApiError::not_found("org"));
    }
    Ok(OrgForOwner {
        id,
        signing_pubkey_b64,
        org_sym_key_id,
        roster_version,
        roster_canonical_b64,
    })
}

async fn verify_and_advance_roster(
    _state: &AppState,
    org: &OrgForOwner,
    next: &SignedOrgRosterWire,
) -> Result<hekate_core::org_roster::OrgRoster, ApiError> {
    let signing_pk = decode_fixed::<32>(&org.signing_pubkey_b64, "org signing_pubkey")?;
    let canonical = STANDARD_NO_PAD
        .decode(&next.canonical_b64)
        .map_err(|_| ApiError::bad_request("next_roster.canonical_b64 not base64-no-pad"))?;
    let sig_bytes = decode_fixed::<64>(&next.signature_b64, "next_roster.signature_b64")?;
    let vk = VerifyingKey::from_bytes(&signing_pk)
        .map_err(|_| ApiError::internal("malformed org signing pubkey"))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| ApiError::bad_request("next_roster signature has wrong length"))?;
    vk.verify(&canonical, &sig)
        .map_err(|_| ApiError::bad_request("next_roster signature did not verify"))?;
    let parsed = hekate_core::org_roster::decode_canonical(&canonical)
        .map_err(|e| ApiError::bad_request(format!("next_roster canonical parse: {e}")))?;

    if parsed.org_id != org.id {
        return Err(ApiError::bad_request("next_roster.org_id != org id"));
    }
    if parsed.org_sym_key_id != org.org_sym_key_id {
        return Err(ApiError::bad_request(
            "next_roster.org_sym_key_id != current org_sym_key_id",
        ));
    }
    if parsed.version as i64 != org.roster_version + 1 {
        return Err(ApiError::conflict(format!(
            "next_roster.version must be {} (current+1), got {}",
            org.roster_version + 1,
            parsed.version,
        )));
    }
    let cur_canonical = STANDARD_NO_PAD
        .decode(&org.roster_canonical_b64)
        .map_err(|_| ApiError::internal("malformed stored canonical_b64"))?;
    let expected_parent = hekate_core::org_roster::hash_canonical(&cur_canonical);
    if parsed.parent_canonical_sha256 != expected_parent {
        return Err(ApiError::conflict(
            "next_roster.parent_canonical_sha256 does not chain forward — pull current roster and rebuild",
        ));
    }
    Ok(parsed)
}

async fn apply_roster(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: &str,
    roster: &SignedOrgRosterWire,
    now: &str,
    version: u64,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE organizations
            SET roster_version = $1,
                roster_canonical_b64 = $2,
                roster_signature_b64 = $3,
                roster_updated_at = $4,
                revision_date = $4
          WHERE id = $5",
    )
    .bind(version as i64)
    .bind(&roster.canonical_b64)
    .bind(&roster.signature_b64)
    .bind(now)
    .bind(org_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(())
}

// ===========================================================================
// M4.5b — member removal + org key rotation
// ===========================================================================

#[derive(Debug, Deserialize, ToSchema)]
pub struct RewrapEnvelope {
    pub user_id: String,
    /// SealedEnvelope JSON (M2.18 signcrypt). Server stores verbatim.
    pub envelope: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CipherRewrap {
    pub cipher_id: String,
    /// EncString v3 of the per-cipher key under the NEW org sym key.
    pub protected_cipher_key: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CollectionRewrap {
    pub collection_id: String,
    /// EncString v3 of the collection name under the NEW org sym key.
    /// AAD is the same as the original
    /// (`hekate_core::aad::collection_name(id, org_id)`), so server-driven
    /// id/org_id substitution still breaks decryption.
    pub name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeMemberRequest {
    /// Roster v(n+1) WITHOUT the revoked member. Bound to the NEW
    /// org_sym_key_id so the signature simultaneously authorises the
    /// key rotation.
    pub next_roster: SignedOrgRosterWire,
    /// Fresh UUIDv7 for the new org symmetric key version. MUST differ
    /// from the org's current `org_sym_key_id`.
    pub next_org_sym_key_id: String,
    /// EncString v3 — the new org sym key wrapped under the OWNER's
    /// account_key. Owner unwraps directly; no signcryption needed.
    pub owner_protected_org_key: String,
    /// One signcryption envelope per remaining non-owner member, each
    /// wrapping the new org sym key under the recipient's TOFU-pinned
    /// X25519 pubkey. Members consume these on their next /sync via
    /// /rotate-confirm.
    #[serde(default)]
    pub rewrap_envelopes: Vec<RewrapEnvelope>,
    /// One entry per org-owned cipher (deleted ciphers included so this
    /// can be a 1:1 enumeration). Server rejects if any org cipher is
    /// missing from this list — silent skips would leave ciphers
    /// readable only by the revoked member.
    #[serde(default)]
    pub cipher_rewraps: Vec<CipherRewrap>,
    /// One entry per org collection. Collection names are encrypted
    /// under the org sym key with AAD bound to (collection_id, org_id);
    /// after rotation they need to be re-encrypted under the new key
    /// or members lose the ability to decrypt them. Server rejects if
    /// any org collection is missing from this list — silent skips
    /// would leave the collection name permanently undecryptable.
    /// Same shape contract as `cipher_rewraps`.
    #[serde(default)]
    pub collection_rewraps: Vec<CollectionRewrap>,
}

/// Owner-only. Remove a member and rotate the org symmetric key in one
/// atomic operation. Every remaining non-owner member receives a
/// pending signcryption envelope for the new key; org-owned ciphers
/// are re-wrapped under it. The revoked member's rows are deleted; the
/// org's roster + key_id move forward.
///
/// See `docs/m4-organizations.md` §6.6 for the wire-flow design.
#[utoipa::path(
    post,
    path = "/api/v1/orgs/{org_id}/members/{user_id}/revoke",
    tag = "orgs",
    params(
        ("org_id" = String, Path),
        ("user_id" = String, Path, description = "Member to revoke"),
    ),
    request_body = RevokeMemberRequest,
    responses(
        (status = 200, description = "Revoked + rotated"),
        (status = 400, description = "Validation failed", body = crate::routes::accounts::ErrorResponse),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Caller is not the org owner"),
        (status = 404, description = "Org or member not found"),
        (status = 409, description = "Roster version not next-after-current", body = crate::routes::accounts::ErrorResponse),
    ),
    security(("bearerAuth" = [])),
)]
pub async fn revoke_member(
    user: AuthUser,
    State(state): State<AppState>,
    Path((org_id, target_user_id)): Path<(String, String)>,
    Json(req): Json<RevokeMemberRequest>,
) -> Result<StatusCode, ApiError> {
    user.require(scope::VAULT_WRITE)?;

    if target_user_id == user.user_id {
        return Err(ApiError::bad_request(
            "the owner cannot revoke themselves; transfer ownership first (M4 v2)",
        ));
    }
    Uuid::parse_str(&req.next_org_sym_key_id)
        .map_err(|_| ApiError::bad_request("next_org_sym_key_id must be a UUID"))?;

    // Owner check (and load current roster + key_id).
    let org = load_org_for_owner(&state, &org_id, &user.user_id).await?;
    if req.next_org_sym_key_id == org.org_sym_key_id {
        return Err(ApiError::bad_request(
            "next_org_sym_key_id must differ from the current org_sym_key_id",
        ));
    }

    // Validate the new EncStrings up front so we don't open a tx for
    // garbage. Server doesn't decrypt, just shape-checks.
    EncString::parse(&req.owner_protected_org_key)
        .map_err(|e| ApiError::bad_request(format!("owner_protected_org_key: {e}")))?;
    for r in &req.rewrap_envelopes {
        if r.user_id == target_user_id {
            return Err(ApiError::bad_request(
                "rewrap_envelopes must not include the revoked member",
            ));
        }
        if r.user_id == user.user_id {
            return Err(ApiError::bad_request(
                "rewrap_envelopes must not include the owner; \
                 owner uses owner_protected_org_key",
            ));
        }
    }
    for c in &req.cipher_rewraps {
        EncString::parse(&c.protected_cipher_key).map_err(|e| {
            ApiError::bad_request(format!(
                "cipher_rewraps[{}].protected_cipher_key: {e}",
                c.cipher_id
            ))
        })?;
    }
    for c in &req.collection_rewraps {
        EncString::parse(&c.name).map_err(|e| {
            ApiError::bad_request(format!("collection_rewraps[{}].name: {e}", c.collection_id))
        })?;
    }

    // Verify the next roster signature + chain, AND that its
    // org_sym_key_id matches the requested NEW one (this binds the
    // rotation to the signed roster — server can't apply the new key
    // under an old roster sig).
    let parsed_roster =
        verify_and_advance_rotated_roster(&org, &req.next_roster, &req.next_org_sym_key_id)?;

    // Roster MUST omit the revoked member.
    if parsed_roster
        .entries
        .iter()
        .any(|e| e.user_id == target_user_id)
    {
        return Err(ApiError::bad_request(
            "next_roster still includes the revoked member",
        ));
    }
    // Owner MUST still be present as `owner`.
    if !parsed_roster
        .entries
        .iter()
        .any(|e| e.user_id == user.user_id && e.role == "owner")
    {
        return Err(ApiError::bad_request(
            "next_roster must keep the owner at role=owner",
        ));
    }

    // Confirm the revoked user is a current member (so we don't 200
    // on a no-op revoke that bypasses the rotation rationale).
    let member_row: Option<(i64,)> =
        sqlx::query_as("SELECT 1 FROM organization_members WHERE org_id = $1 AND user_id = $2")
            .bind(&org_id)
            .bind(&target_user_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    if member_row.is_none() {
        return Err(ApiError::not_found("member"));
    }

    // Build expected non-owner remaining set from the roster, then
    // assert the rewrap_envelopes cover it exactly.
    let expected_non_owner: BTreeSet<&str> = parsed_roster
        .entries
        .iter()
        .filter(|e| e.user_id != user.user_id)
        .map(|e| e.user_id.as_str())
        .collect();
    let provided: BTreeSet<&str> = req
        .rewrap_envelopes
        .iter()
        .map(|r| r.user_id.as_str())
        .collect();
    if provided != expected_non_owner {
        let missing: Vec<&&str> = expected_non_owner.difference(&provided).collect();
        let extra: Vec<&&str> = provided.difference(&expected_non_owner).collect();
        return Err(ApiError::bad_request(format!(
            "rewrap_envelopes must cover every remaining non-owner member exactly \
             (missing={missing:?}, extra={extra:?})"
        )));
    }

    // Enumerate every org-owned cipher (including soft-deleted — they
    // can still be restored later; server can't tell the revoked
    // member to stop watching the old wraps). Reject if any is missing
    // from cipher_rewraps. Duplicates in cipher_rewraps are also
    // rejected to avoid ambiguity.
    let cipher_ids: Vec<(String,)> = sqlx::query_as("SELECT id FROM ciphers WHERE org_id = $1")
        .bind(&org_id)
        .fetch_all(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let expected_ciphers: BTreeSet<String> = cipher_ids.into_iter().map(|(id,)| id).collect();
    let mut provided_ciphers: BTreeSet<String> = BTreeSet::new();
    for c in &req.cipher_rewraps {
        if !provided_ciphers.insert(c.cipher_id.clone()) {
            return Err(ApiError::bad_request(format!(
                "cipher_rewraps contains duplicate cipher_id {}",
                c.cipher_id
            )));
        }
    }
    if provided_ciphers != expected_ciphers {
        let missing: Vec<&String> = expected_ciphers.difference(&provided_ciphers).collect();
        let extra: Vec<&String> = provided_ciphers.difference(&expected_ciphers).collect();
        return Err(ApiError::bad_request(format!(
            "cipher_rewraps must cover every org-owned cipher exactly \
             (missing={missing:?}, extra={extra:?})"
        )));
    }

    // Same 1:1 coverage requirement for collection names. Without this
    // every collection name becomes permanently undecryptable after
    // the rotation (encrypted under the old sym key, which the owner
    // discards locally + the server doesn't store the plaintext).
    let collection_ids: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM organization_collections WHERE org_id = $1")
            .bind(&org_id)
            .fetch_all(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let expected_collections: BTreeSet<String> =
        collection_ids.into_iter().map(|(id,)| id).collect();
    let mut provided_collections: BTreeSet<String> = BTreeSet::new();
    for c in &req.collection_rewraps {
        if !provided_collections.insert(c.collection_id.clone()) {
            return Err(ApiError::bad_request(format!(
                "collection_rewraps contains duplicate collection_id {}",
                c.collection_id
            )));
        }
    }
    if provided_collections != expected_collections {
        let missing: Vec<&String> = expected_collections
            .difference(&provided_collections)
            .collect();
        let extra: Vec<&String> = provided_collections
            .difference(&expected_collections)
            .collect();
        return Err(ApiError::bad_request(format!(
            "collection_rewraps must cover every org collection exactly \
             (missing={missing:?}, extra={extra:?})"
        )));
    }

    // Pre-build maps for fast lookup inside the tx.
    let cipher_rewrap_map: HashMap<&str, &str> = req
        .cipher_rewraps
        .iter()
        .map(|c| (c.cipher_id.as_str(), c.protected_cipher_key.as_str()))
        .collect();
    let collection_rewrap_map: HashMap<&str, &str> = req
        .collection_rewraps
        .iter()
        .map(|c| (c.collection_id.as_str(), c.name.as_str()))
        .collect();

    let now = chrono::Utc::now().to_rfc3339();
    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // 1. Drop the revoked member's rows. ON DELETE CASCADE on
    //    collection_members (FK to users) is best-effort — explicit
    //    delete is the source of truth.
    sqlx::query(
        "DELETE FROM collection_members WHERE user_id = $1
            AND collection_id IN (SELECT id FROM organization_collections WHERE org_id = $2)",
    )
    .bind(&target_user_id)
    .bind(&org_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    sqlx::query("DELETE FROM organization_members WHERE org_id = $1 AND user_id = $2")
        .bind(&org_id)
        .bind(&target_user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // 2. Apply the new roster + new key_id atomically.
    sqlx::query(
        "UPDATE organizations
            SET roster_version = $1,
                roster_canonical_b64 = $2,
                roster_signature_b64 = $3,
                roster_updated_at = $4,
                revision_date = $4,
                org_sym_key_id = $5
          WHERE id = $6",
    )
    .bind(parsed_roster.version as i64)
    .bind(&req.next_roster.canonical_b64)
    .bind(&req.next_roster.signature_b64)
    .bind(&now)
    .bind(&req.next_org_sym_key_id)
    .bind(&org_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    // 3. Owner: replace protected_org_key with the new EncString and
    //    advance their org_sym_key_id pointer to the new key.
    sqlx::query(
        "UPDATE organization_members
            SET protected_org_key = $1, org_sym_key_id = $2,
                pending_org_key_envelope_json = NULL
          WHERE org_id = $3 AND user_id = $4",
    )
    .bind(&req.owner_protected_org_key)
    .bind(&req.next_org_sym_key_id)
    .bind(&org_id)
    .bind(&user.user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    // 4. Non-owners: stash the signcryption envelope as pending. Their
    //    protected_org_key + org_sym_key_id stay pointed at the OLD
    //    key until they confirm rotation.
    for r in &req.rewrap_envelopes {
        let envelope_json =
            serde_json::to_string(&r.envelope).map_err(|e| ApiError::internal(e.to_string()))?;
        let res = sqlx::query(
            "UPDATE organization_members
                SET pending_org_key_envelope_json = $1
              WHERE org_id = $2 AND user_id = $3",
        )
        .bind(&envelope_json)
        .bind(&org_id)
        .bind(&r.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
        if res.rows_affected() == 0 {
            // Either the user_id isn't actually a member or the row
            // was raced out from under us — treat as a validation
            // error so the caller can rebuild from a fresh roster.
            return Err(ApiError::bad_request(format!(
                "rewrap target {} is not a member of this org",
                r.user_id
            )));
        }
    }

    // 5. Replace every org-owned cipher's protected_cipher_key + bump
    //    its revision_date so subscribers refetch.
    for (cipher_id, new_wire) in &cipher_rewrap_map {
        sqlx::query(
            "UPDATE ciphers SET protected_cipher_key = $1, revision_date = $2
              WHERE id = $3 AND org_id = $4",
        )
        .bind(*new_wire)
        .bind(&now)
        .bind(*cipher_id)
        .bind(&org_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    }

    // 6. Replace every collection name with the new-key ciphertext +
    //    bump revision_date so /sync refetches.
    for (collection_id, new_name) in &collection_rewrap_map {
        sqlx::query(
            "UPDATE organization_collections SET name = $1, revision_date = $2
              WHERE id = $3 AND org_id = $4",
        )
        .bind(*new_name)
        .bind(&now)
        .bind(*collection_id)
        .bind(&org_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    }

    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RotateConfirmRequest {
    /// EncString v3 — the NEW org sym key wrapped under the caller's
    /// account_key. Caller has already decrypted the pending envelope
    /// client-side and re-wrapped under their own key.
    pub protected_org_key: String,
    /// Must equal the org's current `org_sym_key_id` so a stale
    /// envelope from a superseded rotation can't be confirmed.
    pub org_sym_key_id: String,
}

/// Member-only. After /sync surfaces a `pending_envelope`, the client
/// decrypts the new org sym key, re-wraps under their own
/// account_key, and POSTs here to swap their `protected_org_key` and
/// clear the pending field.
#[utoipa::path(
    post,
    path = "/api/v1/orgs/{org_id}/rotate-confirm",
    tag = "orgs",
    params(("org_id" = String, Path)),
    request_body = RotateConfirmRequest,
    responses(
        (status = 200, description = "Confirmed"),
        (status = 400, description = "Validation failed", body = crate::routes::accounts::ErrorResponse),
        (status = 401, description = "Unauthenticated"),
        (status = 404, description = "No pending envelope for this caller"),
        (status = 409, description = "org_sym_key_id no longer current", body = crate::routes::accounts::ErrorResponse),
    ),
    security(("bearerAuth" = [])),
)]
pub async fn rotate_confirm(
    user: AuthUser,
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Json(req): Json<RotateConfirmRequest>,
) -> Result<StatusCode, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    EncString::parse(&req.protected_org_key)
        .map_err(|e| ApiError::bad_request(format!("protected_org_key: {e}")))?;

    // Org must exist and current key_id must match what the caller
    // is confirming. Mismatch means another rotation overtook this
    // one — re-sync to pick up the new envelope.
    let key_row: Option<(String,)> =
        sqlx::query_as("SELECT org_sym_key_id FROM organizations WHERE id = $1")
            .bind(&org_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    let current_key_id = match key_row {
        Some((k,)) => k,
        None => return Err(ApiError::not_found("org")),
    };
    if current_key_id != req.org_sym_key_id {
        return Err(ApiError::conflict(
            "org_sym_key_id is no longer current — re-sync to pick up the new envelope",
        ));
    }

    // Caller must be a member with a pending envelope outstanding.
    let pending: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT pending_org_key_envelope_json FROM organization_members
          WHERE org_id = $1 AND user_id = $2",
    )
    .bind(&org_id)
    .bind(&user.user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    match pending {
        Some((Some(_),)) => {}
        Some((None,)) => return Err(ApiError::not_found("no pending envelope")),
        None => return Err(ApiError::not_found("no pending envelope")),
    }

    sqlx::query(
        "UPDATE organization_members
            SET protected_org_key = $1,
                org_sym_key_id = $2,
                pending_org_key_envelope_json = NULL
          WHERE org_id = $3 AND user_id = $4",
    )
    .bind(&req.protected_org_key)
    .bind(&req.org_sym_key_id)
    .bind(&org_id)
    .bind(&user.user_id)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(StatusCode::OK)
}

/// Like `verify_and_advance_roster` but the new roster is bound to a
/// NEW org_sym_key_id (the rotation target) rather than the org's
/// current key_id. We still verify the signature under the org's
/// (unrotated) signing pubkey and chain forward from the prior
/// canonical hash.
fn verify_and_advance_rotated_roster(
    org: &OrgForOwner,
    next: &SignedOrgRosterWire,
    next_org_sym_key_id: &str,
) -> Result<hekate_core::org_roster::OrgRoster, ApiError> {
    let signing_pk = decode_fixed::<32>(&org.signing_pubkey_b64, "org signing_pubkey")?;
    let canonical = STANDARD_NO_PAD
        .decode(&next.canonical_b64)
        .map_err(|_| ApiError::bad_request("next_roster.canonical_b64 not base64-no-pad"))?;
    let sig_bytes = decode_fixed::<64>(&next.signature_b64, "next_roster.signature_b64")?;
    let vk = VerifyingKey::from_bytes(&signing_pk)
        .map_err(|_| ApiError::internal("malformed org signing pubkey"))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| ApiError::bad_request("next_roster signature has wrong length"))?;
    vk.verify(&canonical, &sig)
        .map_err(|_| ApiError::bad_request("next_roster signature did not verify"))?;
    let parsed = hekate_core::org_roster::decode_canonical(&canonical)
        .map_err(|e| ApiError::bad_request(format!("next_roster canonical parse: {e}")))?;

    if parsed.org_id != org.id {
        return Err(ApiError::bad_request("next_roster.org_id != org id"));
    }
    if parsed.org_sym_key_id != next_org_sym_key_id {
        return Err(ApiError::bad_request(
            "next_roster.org_sym_key_id != next_org_sym_key_id",
        ));
    }
    if parsed.version as i64 != org.roster_version + 1 {
        return Err(ApiError::conflict(format!(
            "next_roster.version must be {} (current+1), got {}",
            org.roster_version + 1,
            parsed.version,
        )));
    }
    let cur_canonical = STANDARD_NO_PAD
        .decode(&org.roster_canonical_b64)
        .map_err(|_| ApiError::internal("malformed stored canonical_b64"))?;
    let expected_parent = hekate_core::org_roster::hash_canonical(&cur_canonical);
    if parsed.parent_canonical_sha256 != expected_parent {
        return Err(ApiError::conflict(
            "next_roster.parent_canonical_sha256 does not chain forward — pull current roster and rebuild",
        ));
    }
    Ok(parsed)
}

// ===========================================================================
// Roster prune — scrub orphans without removing anyone
// ===========================================================================
//
// Recovery primitive for the data-model split between the signed roster
// (`organizations.roster_canonical_b64`, the cryptographic source of
// truth) and `organization_members` (the server's authorization index).
// They're supposed to be equivalent, but they can diverge:
//
//   - Pre-GH#2 (migration 0023), the roster advanced at invite-time.
//     Any invitee who never accepted is permanently in the live signed
//     roster but has no `organization_members` row. The 0023 migration
//     comment explicitly punts on the backfill ("the deploy runbook
//     should drain pending invites first") which leaves dev/legacy
//     orgs corrupt.
//   - Even post-GH#2, a transient failure between the membership-row
//     insert and the roster bump (or vice versa during revoke) could
//     leave the two stores out of sync. There's no automatic
//     reconciliation today; prune is the manual recovery.
//
// /revoke can't double as the prune path because its safety nets gate
// on `organization_members` (require check + rewrap-target check) —
// applying it to a roster orphan returns 404 (target not in members)
// or 400 (rewrap target not in members). Those checks are correct
// for the revoke semantics; they just don't match what prune needs.
//
// Prune does NOT rotate the org sym key. Orphans never received it
// (they never accepted; the sym key is signcrypted to the invitee's
// X25519 pubkey at accept time, not invite time), so there's nothing
// to defend against. The endpoint is therefore much smaller than
// /revoke — just a re-sign with chain continuity preserved.

#[derive(Debug, Deserialize, ToSchema)]
pub struct PruneRosterRequest {
    /// Owner-signed roster v(N+1) that drops orphan entries while
    /// leaving every real member intact. Must chain forward from the
    /// current roster (parent hash + version+1). Server validates
    /// every surviving entry exists in `organization_members` — that
    /// is the load-bearing check that defines what prune means.
    pub next_roster: SignedOrgRosterWire,
}

/// Owner-only. Re-sign the org's signed roster after dropping entries
/// that have no matching `organization_members` row. Idempotent
/// against orphans (running it on a clean roster errors at the
/// strict-subset check because the new roster would be identical to
/// the current one — the chain still advances cleanly, but there's
/// nothing to drop, so callers shouldn't issue it).
#[utoipa::path(
    post,
    path = "/api/v1/orgs/{org_id}/prune-roster",
    tag = "orgs",
    params(("org_id" = String, Path)),
    request_body = PruneRosterRequest,
    responses(
        (status = 204, description = "Pruned"),
        (status = 400, description = "Validation failed", body = crate::routes::accounts::ErrorResponse),
        (status = 401, description = "Unauthenticated"),
        (status = 404, description = "Org not found / not owner"),
        (status = 409, description = "Roster does not chain forward"),
    ),
    security(("bearerAuth" = [])),
)]
pub async fn prune_roster(
    user: AuthUser,
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Json(req): Json<PruneRosterRequest>,
) -> Result<StatusCode, ApiError> {
    user.require(scope::VAULT_WRITE)?;

    // Owner check + load current.
    let org = load_org_for_owner(&state, &org_id, &user.user_id).await?;

    // Verify sig + chain forward + version+1. Reuses the same helper
    // accept/invite use, so the cryptographic invariants are identical.
    // Important: this helper requires the new roster's
    // `org_sym_key_id == current` — prune is NOT a key rotation.
    let parsed = verify_and_advance_roster(&state, &org, &req.next_roster).await?;

    // Owner must remain.
    if !parsed
        .entries
        .iter()
        .any(|e| e.user_id == user.user_id && e.role == "owner")
    {
        return Err(ApiError::bad_request(
            "next_roster must keep the owner at role=owner",
        ));
    }

    // Diff against the current roster: every entry in next_roster
    // MUST already exist in current, and with the same role. Prune
    // is a strict subset operation — adding members or changing roles
    // goes through invite/accept or future role-change flows, not
    // this endpoint.
    let cur_canonical = STANDARD_NO_PAD
        .decode(&org.roster_canonical_b64)
        .map_err(|_| ApiError::internal("malformed stored canonical_b64"))?;
    let cur_parsed = hekate_core::org_roster::decode_canonical(&cur_canonical)
        .map_err(|e| ApiError::internal(format!("current roster decode: {e}")))?;
    let cur_by_id: HashMap<&str, &str> = cur_parsed
        .entries
        .iter()
        .map(|e| (e.user_id.as_str(), e.role.as_str()))
        .collect();
    for entry in &parsed.entries {
        match cur_by_id.get(entry.user_id.as_str()) {
            None => {
                return Err(ApiError::bad_request(format!(
                    "next_roster entry {} is not in the current roster — prune \
                     cannot add members",
                    entry.user_id
                )));
            }
            Some(cur_role) if *cur_role != entry.role.as_str() => {
                return Err(ApiError::bad_request(format!(
                    "next_roster entry {} has role {:?} but current roster has \
                     role {:?}; prune cannot change roles",
                    entry.user_id, entry.role, cur_role
                )));
            }
            Some(_) => { /* match — fine */ }
        }
    }

    // The load-bearing check: every surviving entry must be a real
    // member. If next_roster keeps an orphan, the call is malformed —
    // prune means dropping orphans, not retaining them.
    for entry in &parsed.entries {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM organization_members WHERE org_id = $1 AND user_id = $2")
                .bind(&org_id)
                .bind(&entry.user_id)
                .fetch_optional(state.db.pool())
                .await
                .map_err(|e| ApiError::internal(e.to_string()))?;
        if row.is_none() {
            return Err(ApiError::bad_request(format!(
                "next_roster entry {} is not a current member \
                 (not in organization_members) — prune means dropping \
                 orphans, not retaining them",
                entry.user_id
            )));
        }
    }

    // Apply atomically. apply_roster bumps version + canonical + sig +
    // updated_at + revision_date in a single UPDATE.
    let now = chrono::Utc::now().to_rfc3339();
    let mut tx = state
        .db
        .pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    apply_roster(&mut tx, &org_id, &req.next_roster, &now, parsed.version).await?;
    tx.commit()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}
