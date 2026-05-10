//! Refresh-token rotation.
//!
//! Wire format: `<id>.<secret_b64>` where `id` is a UUIDv7 (lookup key) and
//! `secret` is 32 random bytes. Stored: SHA-256("pmgr-refresh-v1" || secret).
//! 256 bits of entropy means a memory-hard KDF would be wasted CPU.
//!
//! Rotation:
//! - Initial password grant → new family_id, new (id, secret).
//! - Refresh grant → atomic revoke-old + issue-new in same family.
//! - Reuse detection: presenting an already-revoked token revokes the
//!   ENTIRE family (all descendants) and returns 401 — the legitimate
//!   client and the attacker are both signed out, attacker can't continue.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::AnyPool;
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub const REFRESH_TTL_DAYS: i64 = 30;

#[derive(Debug, Clone)]
pub struct IssuedRefresh {
    /// Wire-form token: `<id>.<secret_b64>`.
    pub token: String,
    pub family_id: String,
}

#[derive(Debug)]
pub enum RotateOutcome {
    /// Refresh accepted; old token revoked, new token issued.
    Ok {
        user_id: String,
        new_token: IssuedRefresh,
    },
    /// Token presented twice (already revoked) — entire family killed.
    Reused,
    /// Token unknown, malformed, expired, or wrong-secret.
    Invalid,
}

/// Issue a fresh refresh token for `user_id` in a brand-new family. Use
/// this on initial password grant.
pub async fn issue_new_family(pool: &AnyPool, user_id: &str) -> anyhow::Result<IssuedRefresh> {
    let family_id = Uuid::now_v7().to_string();
    insert_token(pool, user_id, &family_id).await
}

/// Verify and rotate. The presented token is revoked; a new one in the
/// same family is returned.
pub async fn rotate(pool: &AnyPool, presented: &str) -> anyhow::Result<RotateOutcome> {
    let Some((id, secret_b64)) = presented.split_once('.') else {
        return Ok(RotateOutcome::Invalid);
    };
    let presented_secret = match URL_SAFE_NO_PAD.decode(secret_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => return Ok(RotateOutcome::Invalid),
    };

    let row: Option<(String, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT user_id, family_id, token_hash, expires_at, revoked_at
         FROM refresh_tokens WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    let Some((user_id, family_id, stored_hash, expires_at, revoked_at)) = row else {
        return Ok(RotateOutcome::Invalid);
    };

    let presented_hash = hash_secret(&presented_secret);
    if presented_hash
        .as_bytes()
        .ct_eq(stored_hash.as_bytes())
        .unwrap_u8()
        == 0
    {
        return Ok(RotateOutcome::Invalid);
    }

    if revoked_at.is_some() {
        // Reuse — kill the family.
        revoke_family(pool, &family_id).await?;
        return Ok(RotateOutcome::Reused);
    }

    let now = Utc::now();
    let exp = chrono::DateTime::parse_from_rfc3339(&expires_at)?;
    if now >= exp {
        return Ok(RotateOutcome::Invalid);
    }

    // Atomic: revoke old, insert new in same family.
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE refresh_tokens SET revoked_at = $1 WHERE id = $2")
        .bind(now.to_rfc3339())
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let new_token = insert_token_tx(&mut tx, &user_id, &family_id).await?;
    tx.commit().await?;

    Ok(RotateOutcome::Ok { user_id, new_token })
}

pub async fn revoke_family(pool: &AnyPool, family_id: &str) -> anyhow::Result<()> {
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = $1
         WHERE family_id = $2 AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(family_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_token(
    pool: &AnyPool,
    user_id: &str,
    family_id: &str,
) -> anyhow::Result<IssuedRefresh> {
    let (id, secret_b64, token_hash, now_str, expires_at) = generate();
    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, created_at, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(family_id)
    .bind(&token_hash)
    .bind(&now_str)
    .bind(&expires_at)
    .execute(pool)
    .await?;
    Ok(IssuedRefresh {
        token: format!("{id}.{secret_b64}"),
        family_id: family_id.to_string(),
    })
}

async fn insert_token_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    user_id: &str,
    family_id: &str,
) -> anyhow::Result<IssuedRefresh> {
    let (id, secret_b64, token_hash, now_str, expires_at) = generate();
    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, created_at, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(family_id)
    .bind(&token_hash)
    .bind(&now_str)
    .bind(&expires_at)
    .execute(&mut **tx)
    .await?;
    Ok(IssuedRefresh {
        token: format!("{id}.{secret_b64}"),
        family_id: family_id.to_string(),
    })
}

fn generate() -> (String, String, String, String, String) {
    let id = Uuid::now_v7().to_string();
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let secret_b64 = URL_SAFE_NO_PAD.encode(secret);
    let token_hash = hash_secret(&secret);
    let now = Utc::now();
    let now_str = now.to_rfc3339();
    let expires_at = (now + Duration::days(REFRESH_TTL_DAYS)).to_rfc3339();
    (id, secret_b64, token_hash, now_str, expires_at)
}

fn hash_secret(secret: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"pmgr-refresh-v1");
    h.update(secret);
    let digest = h.finalize();
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::any::{install_default_drivers, AnyPoolOptions};

    async fn pool() -> AnyPool {
        install_default_drivers();
        let pool = AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        // Minimal schema slice for the test.
        sqlx::query(
            "CREATE TABLE refresh_tokens (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                family_id TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT)",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn happy_rotate() {
        let pool = pool().await;
        let issued = issue_new_family(&pool, "alice").await.unwrap();
        let rotated = rotate(&pool, &issued.token).await.unwrap();
        match rotated {
            RotateOutcome::Ok { user_id, new_token } => {
                assert_eq!(user_id, "alice");
                assert_eq!(new_token.family_id, issued.family_id);
                assert_ne!(new_token.token, issued.token);
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reuse_revokes_family() {
        let pool = pool().await;
        let issued = issue_new_family(&pool, "alice").await.unwrap();
        // Use once: ok.
        let next = match rotate(&pool, &issued.token).await.unwrap() {
            RotateOutcome::Ok { new_token, .. } => new_token,
            o => panic!("first rotate should succeed, got {o:?}"),
        };
        // Use the original token AGAIN: reuse detected.
        assert!(matches!(
            rotate(&pool, &issued.token).await.unwrap(),
            RotateOutcome::Reused
        ));
        // The descendant token issued in step 1 is now also revoked.
        assert!(matches!(
            rotate(&pool, &next.token).await.unwrap(),
            RotateOutcome::Reused | RotateOutcome::Invalid
        ));
    }

    #[tokio::test]
    async fn malformed_token_is_invalid() {
        let pool = pool().await;
        for s in ["", "no-dot", "abc.notbase64!!!", "abc.AAAA"] {
            assert!(matches!(
                rotate(&pool, s).await.unwrap(),
                RotateOutcome::Invalid
            ));
        }
    }

    #[tokio::test]
    async fn unknown_id_is_invalid() {
        let pool = pool().await;
        let bogus = format!("{}.{}", Uuid::now_v7(), URL_SAFE_NO_PAD.encode([0u8; 32]));
        assert!(matches!(
            rotate(&pool, &bogus).await.unwrap(),
            RotateOutcome::Invalid
        ));
    }
}
