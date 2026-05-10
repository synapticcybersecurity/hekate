//! M4.6 — org policies.
//!
//! Owner-set knobs that constrain how member clients behave. Only
//! `single_org` is enforced server-side (see [`accept`]); the rest are
//! delivered to clients via /sync and enforced client-side.
//!
//! Policy types — see `docs/m4-organizations.md` §8 (M4.6):
//!   * `master_password_complexity` — client-enforced on register /
//!     change-password
//!   * `vault_timeout`              — client-enforced in the unlock-cache
//!     daemon TTL
//!   * `password_generator_rules`   — client-enforced in `hekate generate`
//!   * `single_org`                 — server-enforced on /accept (this
//!     module) and via the create-org guard (kept inline there)
//!   * `restrict_send`              — column reserved; enforcement
//!     deferred to the Send subsystem (no-op today)

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, put},
    Router,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    auth::{scope, AuthUser},
    routes::accounts::ApiError,
    AppState,
};

/// All policy types this server build understands. Anything outside
/// this set is rejected at upsert time so the wire never carries
/// garbage that older clients won't know what to do with.
pub const POLICY_TYPES: &[&str] = &[
    "master_password_complexity",
    "vault_timeout",
    "password_generator_rules",
    "single_org",
    "restrict_send",
];

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/orgs/{org_id}/policies", get(list))
        .route(
            "/api/v1/orgs/{org_id}/policies/{policy_type}",
            put(upsert).delete(remove),
        )
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpsertPolicyRequest {
    pub enabled: bool,
    /// Opaque JSON; schema depends on policy_type. Server validates
    /// shape per type but does not enforce semantics (other than
    /// `single_org`, which is enforced at /accept).
    pub config: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct PolicyView {
    pub policy_type: String,
    pub enabled: bool,
    pub config: serde_json::Value,
    pub updated_at: String,
}

/// Owner-only. Set or replace a policy. Idempotent.
#[utoipa::path(
    put,
    path = "/api/v1/orgs/{org_id}/policies/{policy_type}",
    tag = "orgs",
    params(
        ("org_id" = String, Path),
        ("policy_type" = String, Path),
    ),
    request_body = UpsertPolicyRequest,
    responses(
        (status = 200, description = "Set", body = PolicyView),
        (status = 400, description = "Validation failed", body = crate::routes::accounts::ErrorResponse),
        (status = 401, description = "Unauthenticated"),
        (status = 404, description = "Org not found / not owner"),
    ),
    security(("bearerAuth" = [])),
)]
async fn upsert(
    user: AuthUser,
    State(state): State<AppState>,
    Path((org_id, policy_type)): Path<(String, String)>,
    Json(req): Json<UpsertPolicyRequest>,
) -> Result<Json<PolicyView>, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    require_known_policy(&policy_type)?;
    validate_config(&policy_type, &req.config)?;
    require_org_owner(&state, &org_id, &user.user_id).await?;

    let config_json =
        serde_json::to_string(&req.config).map_err(|e| ApiError::internal(e.to_string()))?;
    let now = chrono::Utc::now().to_rfc3339();
    let enabled_int: i64 = if req.enabled { 1 } else { 0 };

    sqlx::query(
        "INSERT INTO org_policies (org_id, policy_type, config_json, enabled, updated_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (org_id, policy_type) DO UPDATE
            SET config_json = $3, enabled = $4, updated_at = $5",
    )
    .bind(&org_id)
    .bind(&policy_type)
    .bind(&config_json)
    .bind(enabled_int)
    .bind(&now)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(PolicyView {
        policy_type,
        enabled: req.enabled,
        config: req.config,
        updated_at: now,
    }))
}

/// Member-only. List all policies set on this org.
#[utoipa::path(
    get,
    path = "/api/v1/orgs/{org_id}/policies",
    tag = "orgs",
    params(("org_id" = String, Path)),
    responses(
        (status = 200, description = "OK", body = Vec<PolicyView>),
        (status = 401, description = "Unauthenticated"),
        (status = 404, description = "Org not found / not a member"),
    ),
    security(("bearerAuth" = [])),
)]
async fn list(
    user: AuthUser,
    State(state): State<AppState>,
    Path(org_id): Path<String>,
) -> Result<Json<Vec<PolicyView>>, ApiError> {
    user.require(scope::VAULT_READ)?;
    require_org_member(&state, &org_id, &user.user_id).await?;
    Ok(Json(load_policies(&state, &org_id).await?))
}

/// Owner-only. Delete a policy outright. Idempotent: succeeds with 204
/// even if the row was already absent.
#[utoipa::path(
    delete,
    path = "/api/v1/orgs/{org_id}/policies/{policy_type}",
    tag = "orgs",
    params(
        ("org_id" = String, Path),
        ("policy_type" = String, Path),
    ),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Unauthenticated"),
        (status = 404, description = "Org not found / not owner"),
    ),
    security(("bearerAuth" = [])),
)]
async fn remove(
    user: AuthUser,
    State(state): State<AppState>,
    Path((org_id, policy_type)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    user.require(scope::VAULT_WRITE)?;
    require_known_policy(&policy_type)?;
    require_org_owner(&state, &org_id, &user.user_id).await?;
    sqlx::query("DELETE FROM org_policies WHERE org_id = $1 AND policy_type = $2")
        .bind(&org_id)
        .bind(&policy_type)
        .execute(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

// --------------------------------------------------------------------
// Internals shared with sync.rs / orgs.rs
// --------------------------------------------------------------------

/// Load every policy for an org (regardless of enabled). Order is
/// stable so the sync payload is deterministic.
pub async fn load_policies(state: &AppState, org_id: &str) -> Result<Vec<PolicyView>, ApiError> {
    let rows: Vec<(String, i64, String, String)> = sqlx::query_as(
        "SELECT policy_type, enabled, config_json, updated_at
         FROM org_policies WHERE org_id = $1
         ORDER BY policy_type ASC",
    )
    .bind(org_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let mut out = Vec::with_capacity(rows.len());
    for (policy_type, enabled, config_json, updated_at) in rows {
        let config: serde_json::Value =
            serde_json::from_str(&config_json).map_err(|e| ApiError::internal(e.to_string()))?;
        out.push(PolicyView {
            policy_type,
            enabled: enabled != 0,
            config,
            updated_at,
        });
    }
    Ok(out)
}

/// Returns true iff `user_id` is in any org that has an enabled
/// `single_org` policy. Used by /accept to block joining a second org
/// when at least one current org forbids it.
pub async fn user_is_pinned_to_single_org(
    state: &AppState,
    user_id: &str,
) -> Result<bool, ApiError> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT 1
           FROM organization_members m
           JOIN org_policies p
             ON p.org_id = m.org_id
            AND p.policy_type = 'single_org'
            AND p.enabled = 1
          WHERE m.user_id = $1
          LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(row.is_some())
}

fn require_known_policy(policy_type: &str) -> Result<(), ApiError> {
    if !POLICY_TYPES.contains(&policy_type) {
        return Err(ApiError::bad_request(format!(
            "unknown policy_type {policy_type:?}; supported: {}",
            POLICY_TYPES.join(", ")
        )));
    }
    Ok(())
}

/// Per-type config validation. Lenient: every field is optional, but
/// any field that IS supplied must be the right shape so silent typos
/// don't produce policies that no client will honor.
fn validate_config(policy_type: &str, config: &serde_json::Value) -> Result<(), ApiError> {
    let obj = config
        .as_object()
        .ok_or_else(|| ApiError::bad_request("config must be a JSON object"))?;
    match policy_type {
        "master_password_complexity" => {
            check_opt_u64(obj, "min_length")?;
            check_opt_u64(obj, "min_unique_chars")?;
            for k in [
                "require_upper",
                "require_lower",
                "require_digit",
                "require_special",
            ] {
                check_opt_bool(obj, k)?;
            }
        }
        "vault_timeout" => {
            check_opt_u64(obj, "max_seconds")?;
            if let Some(action) = obj.get("action") {
                let s = action.as_str().ok_or_else(|| {
                    ApiError::bad_request("vault_timeout.action must be a string")
                })?;
                if s != "lock" && s != "logout" {
                    return Err(ApiError::bad_request(
                        "vault_timeout.action must be \"lock\" or \"logout\"",
                    ));
                }
            }
        }
        "password_generator_rules" => {
            check_opt_u64(obj, "min_length")?;
            check_opt_bool(obj, "no_ambiguous")?;
            // character_classes: optional array of strings, any of:
            // "lower" | "upper" | "digit" | "symbol".
            if let Some(cc) = obj.get("character_classes") {
                let arr = cc.as_array().ok_or_else(|| {
                    ApiError::bad_request(
                        "password_generator_rules.character_classes must be an array",
                    )
                })?;
                for v in arr {
                    let s = v.as_str().ok_or_else(|| {
                        ApiError::bad_request("character_classes entries must be strings")
                    })?;
                    if !matches!(s, "lower" | "upper" | "digit" | "symbol") {
                        return Err(ApiError::bad_request(format!(
                            "unknown character class {s:?}; supported: lower, upper, digit, symbol"
                        )));
                    }
                }
            }
        }
        // Empty-config policies — accept any object but ignore extra fields.
        "single_org" | "restrict_send" => {}
        _ => unreachable!("require_known_policy ran first"),
    }
    Ok(())
}

fn check_opt_u64(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<(), ApiError> {
    if let Some(v) = obj.get(key) {
        let n = v.as_u64().ok_or_else(|| {
            ApiError::bad_request(format!("{key} must be a non-negative integer"))
        })?;
        if n > i64::MAX as u64 {
            return Err(ApiError::bad_request(format!("{key} is too large")));
        }
    }
    Ok(())
}

fn check_opt_bool(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<(), ApiError> {
    if let Some(v) = obj.get(key) {
        if !v.is_boolean() {
            return Err(ApiError::bad_request(format!("{key} must be a boolean")));
        }
    }
    Ok(())
}

async fn require_org_owner(state: &AppState, org_id: &str, user_id: &str) -> Result<(), ApiError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT owner_user_id FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    match row {
        Some((owner,)) if owner == user_id => Ok(()),
        // 404 (not 403) — same convention as collections / orgs.
        _ => Err(ApiError::not_found("org")),
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
