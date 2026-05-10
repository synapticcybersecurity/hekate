//! Service-Account Token issuance, parsing, verification.
//!
//! Wire format: `pmgr_sat_<uuidv7>.<secret_url_safe_b64>`. Parallel to
//! the PAT format in `pat.rs`, but the bearer extractor maps SAT tokens
//! to `Principal::ServiceAccount` (no user_id; carries org_id instead).
//!
//! Hash-at-rest: SHA-256("pmgr-sat-v1" || secret). 256-bit entropy.
//!
//! See `docs/design.md` §6 "Authentication tokens" — service accounts
//! are org-owned machine identities. M2.5 ships the wire format +
//! lifecycle (issue / list / revoke / disable). The actual call sites
//! that gate on SA scopes (Secrets Manager, org metadata read) start
//! arriving alongside M6.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::AnyPool;
use subtle::ConstantTimeEq;
use uuid::Uuid;

const WIRE_PREFIX: &str = "pmgr_sat_";

#[derive(Debug)]
pub struct IssuedSat {
    pub id: String,
    pub wire_token: String,
}

#[derive(Debug)]
pub struct VerifiedSat {
    pub token_id: String,
    pub service_account_id: String,
    pub org_id: String,
    pub scopes: String,
}

pub fn looks_like_sat(token: &str) -> bool {
    token.starts_with(WIRE_PREFIX)
}

/// Issue a new service-account token. The wire token is returned **only
/// once** — caller surfaces it to the user, server only retains the
/// SHA-256 hash.
pub async fn issue(
    pool: &AnyPool,
    service_account_id: &str,
    name: &str,
    scopes_csv: &str,
    expires_at: Option<&str>,
) -> anyhow::Result<IssuedSat> {
    let id = Uuid::now_v7().to_string();
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let secret_b64 = URL_SAFE_NO_PAD.encode(secret);
    let token_hash = hash_secret(&secret);
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO service_account_tokens
            (id, service_account_id, name, token_hash, scopes, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id)
    .bind(service_account_id)
    .bind(name)
    .bind(&token_hash)
    .bind(scopes_csv)
    .bind(&now)
    .bind(expires_at)
    .execute(pool)
    .await?;

    let wire_token = format!("{WIRE_PREFIX}{id}.{secret_b64}");
    Ok(IssuedSat { id, wire_token })
}

/// Verify a presented bearer string. Returns `Some` on success, `None`
/// for any failure (unknown id, wrong secret, expired, revoked, parent
/// SA disabled). Bumps `last_used_at` on success.
pub async fn verify(pool: &AnyPool, wire: &str) -> anyhow::Result<Option<VerifiedSat>> {
    let Some(rest) = wire.strip_prefix(WIRE_PREFIX) else {
        return Ok(None);
    };
    let Some((id, secret_b64)) = rest.split_once('.') else {
        return Ok(None);
    };
    let presented_secret = match URL_SAFE_NO_PAD.decode(secret_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => return Ok(None),
    };

    // Join the token to its parent SA so we can check `disabled_at`
    // and surface the org_id in a single round trip.
    #[allow(clippy::type_complexity)]
    let row: Option<(
        String,         // service_account_id
        String,         // token_hash
        String,         // scopes
        Option<String>, // token expires_at
        Option<String>, // token revoked_at
        String,         // org_id
        Option<String>, // sa disabled_at
    )> = sqlx::query_as(
        "SELECT t.service_account_id, t.token_hash, t.scopes, t.expires_at,
                t.revoked_at, sa.org_id, sa.disabled_at
         FROM service_account_tokens t
         JOIN service_accounts sa ON sa.id = t.service_account_id
         WHERE t.id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    let Some((
        service_account_id,
        stored_hash,
        scopes,
        expires_at,
        revoked_at,
        org_id,
        disabled_at,
    )) = row
    else {
        return Ok(None);
    };

    if revoked_at.is_some() || disabled_at.is_some() {
        return Ok(None);
    }
    if let Some(exp) = expires_at {
        if let Ok(t) = chrono::DateTime::parse_from_rfc3339(&exp) {
            if Utc::now() >= t {
                return Ok(None);
            }
        }
    }

    let presented_hash = hash_secret(&presented_secret);
    if presented_hash
        .as_bytes()
        .ct_eq(stored_hash.as_bytes())
        .unwrap_u8()
        == 0
    {
        return Ok(None);
    }

    let now = Utc::now().to_rfc3339();
    let _ = sqlx::query("UPDATE service_account_tokens SET last_used_at = $1 WHERE id = $2")
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await;

    Ok(Some(VerifiedSat {
        token_id: id.to_string(),
        service_account_id,
        org_id,
        scopes,
    }))
}

pub async fn revoke(pool: &AnyPool, service_account_id: &str, id: &str) -> anyhow::Result<bool> {
    let now = Utc::now().to_rfc3339();
    let res = sqlx::query(
        "UPDATE service_account_tokens
         SET revoked_at = $1
         WHERE id = $2 AND service_account_id = $3 AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(id)
    .bind(service_account_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

fn hash_secret(secret: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"pmgr-sat-v1");
    h.update(secret);
    URL_SAFE_NO_PAD.encode(h.finalize())
}
