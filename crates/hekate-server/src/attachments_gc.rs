//! Background GC for the attachments subsystem (M2.24 follow-up).
//!
//! Two responsibilities, both periodic and durable across restarts:
//!
//! 1. **Drain `attachment_blob_tombstones`** — every row in this table
//!    points at a `storage_key` whose database row has already been
//!    removed; the worker deletes the blob from the configured
//!    `BlobStore` and then deletes the tombstone row. Order matters:
//!    if the blob delete fails we leave the tombstone row in place
//!    so the next tick retries. If the row delete fails after the
//!    blob is gone, the next tick re-issues an idempotent blob delete
//!    (LocalFs treats a missing file as success) and tries again.
//!
//! 2. **Prune expired `attachment_uploads`** — rows past `expires_at`
//!    represent in-progress uploads the client never finished.
//!    The worker deletes the partial blob, the upload row, and the
//!    parent `attachments` row (which is in `status=0` for any
//!    upload we'd be expiring). One transaction per row keeps the
//!    blob in sync with the rows on a crash.
//!
//! The GC tick is deliberately slow (60 s) — neither operation is
//! latency-sensitive. A startup tick runs immediately so a server
//! that crashed mid-cleanup catches up before serving traffic.

use std::time::Duration;

use chrono::Utc;
use sqlx::AnyPool;

use crate::blob::DynBlobStore;

const TICK: Duration = Duration::from_secs(60);
/// Cap rows-per-tick so a huge backlog doesn't monopolize the worker.
/// 256 covers a multi-thousand-tombstone backlog inside a few minutes.
const BATCH: i64 = 256;

/// Spawn the GC worker. Mirrors `webhooks::spawn_dispatcher`.
pub fn spawn(pool: AnyPool, blob: DynBlobStore) {
    tokio::spawn(async move {
        // Run once immediately on startup so we catch up after a crash
        // before the periodic cadence kicks in.
        if let Err(e) = tick(&pool, &blob).await {
            tracing::warn!(error = %e, "attachments GC startup tick error");
        }
        loop {
            tokio::time::sleep(TICK).await;
            if let Err(e) = tick(&pool, &blob).await {
                tracing::warn!(error = %e, "attachments GC tick error");
            }
        }
    });
}

/// One full pass: drain blob tombstones, prune expired uploads, drop
/// past-deletion-date Sends, expire stale download tokens. Public so
/// tests can drive it deterministically.
pub async fn tick(pool: &AnyPool, blob: &DynBlobStore) -> anyhow::Result<()> {
    drain_blob_tombstones(pool, blob).await?;
    prune_expired_uploads(pool, blob).await?;
    prune_expired_send_uploads(pool, blob).await?;
    prune_expired_sends(pool).await?;
    prune_expired_send_download_tokens(pool).await?;
    Ok(())
}

async fn drain_blob_tombstones(pool: &AnyPool, blob: &DynBlobStore) -> anyhow::Result<()> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT storage_key FROM attachment_blob_tombstones
         ORDER BY enqueued_at ASC
         LIMIT $1",
    )
    .bind(BATCH)
    .fetch_all(pool)
    .await?;
    for (storage_key,) in rows {
        match blob.delete(&storage_key).await {
            Ok(()) => {
                // Now drop the row. If this fails, the next tick
                // re-issues an idempotent blob delete and tries again.
                if let Err(e) =
                    sqlx::query("DELETE FROM attachment_blob_tombstones WHERE storage_key = $1")
                        .bind(&storage_key)
                        .execute(pool)
                        .await
                {
                    tracing::warn!(
                        error = %e,
                        storage_key = %storage_key,
                        "could not delete attachment_blob_tombstones row after blob delete"
                    );
                }
            }
            Err(e) => {
                // Blob delete failed (permission, mount unavailable,
                // etc.). Leave the tombstone row in place — next tick
                // retries.
                tracing::warn!(
                    error = %e,
                    storage_key = %storage_key,
                    "blob delete failed; will retry next tick"
                );
            }
        }
    }
    Ok(())
}

/// Drop Sends whose `deletion_date` has passed. Writes a tombstone so
/// owners' /sync surfaces the removal, plus enqueues a blob tombstone
/// for any file-Send body so the next tick (or the same tick's
/// `drain_blob_tombstones` call) cleans up the bytes.
async fn prune_expired_sends(pool: &AnyPool) -> anyhow::Result<()> {
    let now = Utc::now().to_rfc3339();
    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, user_id, storage_key FROM sends
         WHERE deletion_date < $1
         ORDER BY deletion_date ASC
         LIMIT $2",
    )
    .bind(&now)
    .bind(BATCH)
    .fetch_all(pool)
    .await?;
    for (id, user_id, storage_key) in rows {
        let mut tx = pool.begin().await?;
        sqlx::query("DELETE FROM sends WHERE id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO tombstones (kind, id, user_id, deleted_at)
             VALUES ('send', $1, $2, $3)",
        )
        .bind(&id)
        .bind(&user_id)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
        // File Sends: queue the body for cleanup. The drain pass on the
        // next tick (or already-running tick) deletes the blob.
        if let Some(sk) = storage_key {
            sqlx::query(
                "INSERT INTO attachment_blob_tombstones (storage_key, enqueued_at)
                 VALUES ($1, $2)",
            )
            .bind(&sk)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
    }
    Ok(())
}

/// Prune `send_uploads` rows past `expires_at` — the sender abandoned
/// the upload. Drops the partial blob, the upload row, and resets the
/// parent send back to `body_status = 0` so a re-upload can start
/// fresh (or the next deletion_date GC pass drops it entirely).
async fn prune_expired_send_uploads(pool: &AnyPool, blob: &DynBlobStore) -> anyhow::Result<()> {
    let now = Utc::now().to_rfc3339();
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT u.id, s.storage_key
         FROM send_uploads u
         JOIN sends s ON s.id = u.id
         WHERE u.expires_at < $1
         ORDER BY u.expires_at ASC
         LIMIT $2",
    )
    .bind(&now)
    .bind(BATCH)
    .fetch_all(pool)
    .await?;
    for (id, storage_key) in rows {
        if let Some(sk) = storage_key.as_deref() {
            if let Err(e) = blob.delete(sk).await {
                tracing::warn!(
                    error = %e,
                    storage_key = %sk,
                    "could not delete partial send blob; rows kept for retry"
                );
                continue;
            }
        }
        let mut tx = pool.begin().await?;
        sqlx::query("DELETE FROM send_uploads WHERE id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE sends SET storage_key = NULL, size_ct = NULL,
                              content_hash_b3 = NULL, body_status = 0
             WHERE id = $1 AND body_status = 0",
        )
        .bind(&id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

/// Drop `send_download_tokens` rows past `expires_at`. The /blob
/// endpoint already rejects expired rows; this cleanup keeps the
/// table from growing unboundedly under high access volume.
async fn prune_expired_send_download_tokens(pool: &AnyPool) -> anyhow::Result<()> {
    let now = Utc::now().to_rfc3339();
    sqlx::query("DELETE FROM send_download_tokens WHERE expires_at < $1")
        .bind(&now)
        .execute(pool)
        .await?;
    Ok(())
}

async fn prune_expired_uploads(pool: &AnyPool, blob: &DynBlobStore) -> anyhow::Result<()> {
    let now = Utc::now().to_rfc3339();
    // Pull (id, storage_key) for every expired upload. Join keeps it
    // to one round trip for the metadata.
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT u.id, a.storage_key
         FROM attachment_uploads u
         JOIN attachments a ON a.id = u.id
         WHERE u.expires_at < $1
         ORDER BY u.expires_at ASC
         LIMIT $2",
    )
    .bind(&now)
    .bind(BATCH)
    .fetch_all(pool)
    .await?;
    for (id, storage_key) in rows {
        if let Err(e) = blob.delete(&storage_key).await {
            tracing::warn!(
                error = %e,
                storage_key = %storage_key,
                "could not delete partial blob for expired upload; rows kept for retry"
            );
            continue;
        }
        let mut tx = pool.begin().await?;
        sqlx::query("DELETE FROM attachment_uploads WHERE id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        // Only tear down the attachments row if it's still in
        // status=0. A race where the upload completed at the last
        // millisecond and someone called finalize between our SELECT
        // and our DELETE would otherwise nuke a healthy row.
        sqlx::query("DELETE FROM attachments WHERE id = $1 AND status = 0")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::LocalFsBlobStore;
    use chrono::Duration as ChronoDuration;
    use std::sync::Arc;

    async fn test_pool() -> AnyPool {
        sqlx::any::install_default_drivers();
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrate");
        pool
    }

    fn test_blob() -> (DynBlobStore, tempdir_lite::TempDir) {
        let dir = tempdir_lite::TempDir::new("hekate-gc-test").expect("tempdir");
        let store = LocalFsBlobStore::new(dir.path()).expect("blob store");
        (Arc::new(store) as DynBlobStore, dir)
    }

    /// Insert a placeholder cipher and a (registered, then deleted)
    /// user the foreign keys can hang off of.
    async fn seed_user_and_cipher(pool: &AnyPool) -> (String, String) {
        let user_id = uuid::Uuid::now_v7().to_string();
        let cipher_id = uuid::Uuid::now_v7().to_string();
        // The `users` schema has grown across migrations (kdf_salt,
        // kdf_params_mac, account_signing_pubkey_b64, etc.) all NOT
        // NULL with empty-string defaults. The minimal columns this
        // test needs are id + email + a security_stamp; the rest fall
        // through to defaults.
        sqlx::query(
            "INSERT INTO users (
                id, email, kdf_params,
                master_password_hash, protected_account_key,
                account_public_key, protected_account_private_key,
                revision_date, security_stamp
             ) VALUES ($1, $2, '{}', 'AA', 'AA', 'AA', 'AA',
                CURRENT_TIMESTAMP, $3)",
        )
        .bind(&user_id)
        .bind(format!("{user_id}@test"))
        .bind(uuid::Uuid::now_v7().to_string())
        .execute(pool)
        .await
        .expect("seed user");
        sqlx::query(
            "INSERT INTO ciphers (
                id, user_id, org_id, folder_id, cipher_type,
                protected_cipher_key, name, notes, data, favorite,
                revision_date, creation_date
             ) VALUES ($1, $2, NULL, NULL, 1,
                'v3.xc20p.kid.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA',
                'v3.xc20p.kid.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA',
                NULL,
                'v3.xc20p.kid.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA',
                0,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(&cipher_id)
        .bind(&user_id)
        .execute(pool)
        .await
        .expect("seed cipher");
        (user_id, cipher_id)
    }

    #[tokio::test]
    async fn drain_removes_tombstoned_blobs() {
        let pool = test_pool().await;
        let (blob, _tmp) = test_blob();
        // Place a blob and enqueue a tombstone for it.
        blob.append("u1/a1", b"bytes").await.unwrap();
        sqlx::query(
            "INSERT INTO attachment_blob_tombstones (storage_key, enqueued_at)
             VALUES ($1, CURRENT_TIMESTAMP)",
        )
        .bind("u1/a1")
        .execute(&pool)
        .await
        .unwrap();
        tick(&pool, &blob).await.unwrap();
        assert!(!blob.exists("u1/a1").await.unwrap());
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM attachment_blob_tombstones")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn prune_removes_expired_in_progress_upload() {
        let pool = test_pool().await;
        let (blob, _tmp) = test_blob();
        let (user_id, cipher_id) = seed_user_and_cipher(&pool).await;
        let att_id = uuid::Uuid::now_v7().to_string();
        let storage_key = format!("{user_id}/{att_id}");
        blob.append(&storage_key, b"partial").await.unwrap();
        sqlx::query(
            "INSERT INTO attachments (
                id, cipher_id, user_id, org_id, filename, content_key,
                size_ct, size_pt, storage_key, content_hash_b3, status,
                revision_date, creation_date
             ) VALUES ($1, $2, $3, NULL,
                'v3.xc20p.kid.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA',
                'v3.xc20p.kid.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA',
                100, 50, $4, 'AAAA', 0,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(&att_id)
        .bind(&cipher_id)
        .bind(&user_id)
        .bind(&storage_key)
        .execute(&pool)
        .await
        .unwrap();
        // Expired: 1 hour in the past.
        let expired = (Utc::now() - ChronoDuration::hours(1)).to_rfc3339();
        sqlx::query(
            "INSERT INTO attachment_uploads
                (id, upload_token, bytes_received, expected_size, expires_at, upload_metadata)
             VALUES ($1, $2, 7, 100, $3, '')",
        )
        .bind(&att_id)
        .bind(format!("tok-{att_id}"))
        .bind(&expired)
        .execute(&pool)
        .await
        .unwrap();

        tick(&pool, &blob).await.unwrap();

        // Blob gone, both rows gone.
        assert!(!blob.exists(&storage_key).await.unwrap());
        let (uploads,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM attachment_uploads")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(uploads, 0);
        let (atts,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM attachments")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(atts, 0);
    }

    #[tokio::test]
    async fn prune_skips_unexpired_uploads() {
        let pool = test_pool().await;
        let (blob, _tmp) = test_blob();
        let (user_id, cipher_id) = seed_user_and_cipher(&pool).await;
        let att_id = uuid::Uuid::now_v7().to_string();
        let storage_key = format!("{user_id}/{att_id}");
        blob.append(&storage_key, b"in flight").await.unwrap();
        sqlx::query(
            "INSERT INTO attachments (
                id, cipher_id, user_id, org_id, filename, content_key,
                size_ct, size_pt, storage_key, content_hash_b3, status,
                revision_date, creation_date
             ) VALUES ($1, $2, $3, NULL,
                'v3.xc20p.kid.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA',
                'v3.xc20p.kid.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA',
                100, 50, $4, 'AAAA', 0,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(&att_id)
        .bind(&cipher_id)
        .bind(&user_id)
        .bind(&storage_key)
        .execute(&pool)
        .await
        .unwrap();
        // Unexpired: 1 hour in the future.
        let expires = (Utc::now() + ChronoDuration::hours(1)).to_rfc3339();
        sqlx::query(
            "INSERT INTO attachment_uploads
                (id, upload_token, bytes_received, expected_size, expires_at, upload_metadata)
             VALUES ($1, $2, 9, 100, $3, '')",
        )
        .bind(&att_id)
        .bind(format!("tok-{att_id}"))
        .bind(&expires)
        .execute(&pool)
        .await
        .unwrap();

        tick(&pool, &blob).await.unwrap();

        // Blob and rows survive.
        assert!(blob.exists(&storage_key).await.unwrap());
        let (uploads,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM attachment_uploads")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(uploads, 1);
    }

    #[tokio::test]
    async fn drain_is_idempotent_when_blob_already_missing() {
        let pool = test_pool().await;
        let (blob, _tmp) = test_blob();
        // Tombstone for a blob that was never created (e.g. a crash
        // between blob-delete and row-delete on the prior tick).
        sqlx::query(
            "INSERT INTO attachment_blob_tombstones (storage_key, enqueued_at)
             VALUES ('u/missing', CURRENT_TIMESTAMP)",
        )
        .execute(&pool)
        .await
        .unwrap();
        tick(&pool, &blob).await.unwrap();
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM attachment_blob_tombstones")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0, "missing-blob tombstone should still drain");
    }

    // Tiny in-tree tempdir helper, mirrors `crate::blob` test helper.
    mod tempdir_lite {
        use std::path::{Path, PathBuf};

        pub struct TempDir {
            path: PathBuf,
        }
        impl TempDir {
            pub fn new(prefix: &str) -> std::io::Result<Self> {
                use rand::Rng;
                let suffix: String = rand::thread_rng()
                    .sample_iter(&rand::distributions::Alphanumeric)
                    .take(12)
                    .map(char::from)
                    .collect();
                let mut path = std::env::temp_dir();
                path.push(format!("{prefix}-{suffix}"));
                std::fs::create_dir_all(&path)?;
                Ok(Self { path })
            }
            pub fn path(&self) -> &Path {
                &self.path
            }
        }
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }
}
