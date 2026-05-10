//! Personal Access Token issuance, parsing, verification.
//!
//! Wire format: `pmgr_pat_<uuidv7>.<secret_url_safe_b64>`. Identification
//! by the `pmgr_pat_` prefix lets the bearer extractor distinguish PATs
//! from JWTs without a parse attempt on each.
//!
//! Hash-at-rest: SHA-256("pmgr-pat-v1" || secret). 256-bit entropy.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::AnyPool;
use subtle::ConstantTimeEq;
use uuid::Uuid;

const WIRE_PREFIX: &str = "pmgr_pat_";

#[derive(Debug)]
pub struct IssuedPat {
    pub id: String,
    pub wire_token: String,
}

#[derive(Debug)]
pub struct VerifiedPat {
    pub id: String,
    pub user_id: String,
    pub scopes: String,
}

pub fn looks_like_pat(token: &str) -> bool {
    token.starts_with(WIRE_PREFIX)
}

/// Insert a new PAT row. Returns the wire token (only chance to see the
/// secret). `expires_at` is optional RFC3339; pass None for no expiry.
pub async fn issue(
    pool: &AnyPool,
    user_id: &str,
    name: &str,
    scopes_csv: &str,
    expires_at: Option<&str>,
) -> anyhow::Result<IssuedPat> {
    let id = Uuid::now_v7().to_string();
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let secret_b64 = URL_SAFE_NO_PAD.encode(secret);
    let token_hash = hash_secret(&secret);
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO personal_access_tokens
            (id, user_id, name, token_hash, scopes, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(&token_hash)
    .bind(scopes_csv)
    .bind(&now)
    .bind(expires_at)
    .execute(pool)
    .await?;

    let wire_token = format!("{WIRE_PREFIX}{id}.{secret_b64}");
    Ok(IssuedPat { id, wire_token })
}

/// Verify a presented bearer string. Returns Some on success, None on any
/// failure (unknown id, wrong secret, expired, revoked). Bumps
/// `last_used_at` on success.
pub async fn verify(pool: &AnyPool, wire: &str) -> anyhow::Result<Option<VerifiedPat>> {
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

    #[allow(clippy::type_complexity)]
    let row: Option<(String, String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT user_id, token_hash, scopes, expires_at, revoked_at
         FROM personal_access_tokens WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    let Some((user_id, stored_hash, scopes, expires_at, revoked_at)) = row else {
        return Ok(None);
    };

    if revoked_at.is_some() {
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

    // Best-effort last_used_at update; failure does not affect the response.
    let now = Utc::now().to_rfc3339();
    let _ = sqlx::query("UPDATE personal_access_tokens SET last_used_at = $1 WHERE id = $2")
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await;

    Ok(Some(VerifiedPat {
        id: id.to_string(),
        user_id,
        scopes,
    }))
}

pub async fn revoke(pool: &AnyPool, user_id: &str, id: &str) -> anyhow::Result<bool> {
    let now = Utc::now().to_rfc3339();
    let res = sqlx::query(
        "UPDATE personal_access_tokens
         SET revoked_at = $1
         WHERE id = $2 AND user_id = $3 AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

fn hash_secret(secret: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"pmgr-pat-v1");
    h.update(secret);
    URL_SAFE_NO_PAD.encode(h.finalize())
}
