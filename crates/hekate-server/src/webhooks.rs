//! Outbound webhook delivery with persistent retries.
//!
//! Two background tasks:
//!
//! 1. **Enqueuer** — subscribes to the `PushBus`, looks up webhooks
//!    matching each event, persists one `webhook_deliveries` row per
//!    matching webhook with `next_attempt_at = now`.
//!
//! 2. **Worker** — polls every 2 s for rows where:
//!    `delivered_at IS NULL AND failed_permanently_at IS NULL AND
//!     next_attempt_at <= now`. For each, signs + POSTs the payload.
//!    On 2xx success: stamps `delivered_at`. On non-2xx / network error:
//!    increments `attempts`, sets `last_status` / `last_error`, computes
//!    `next_attempt_at = now + backoff(attempts)`. After `MAX_ATTEMPTS`
//!    failures, stamps `failed_permanently_at`.
//!
//! ## Wire format (unchanged)
//!
//! ```text
//! POST <url>
//! Content-Type: application/json
//! User-Agent: hekate-webhooks/<version>
//! X-Hekate-Event-Id: <uuidv7>
//! X-Hekate-Event-Type: cipher.changed
//! X-Hekate-Signature: t=<unix>,v1=<hex>
//!
//! {"id":"<event-uuid>","type":"cipher.changed","created_at":"<rfc3339>","data":{...}}
//! ```

use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use sha2::Sha256;
use sqlx::AnyPool;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::push::{PushBus, PushEvent};

const USER_AGENT: &str = concat!("hekate-webhooks/", env!("CARGO_PKG_VERSION"));
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);
const WORKER_TICK: Duration = Duration::from_secs(2);
const WORKER_BATCH: i64 = 50;
pub const MAX_ATTEMPTS: i32 = 12;

#[derive(Debug, Serialize)]
pub struct EventPayload {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub created_at: String,
    pub data: EventData,
}

#[derive(Debug, Serialize)]
pub struct EventData {
    pub id: String,
    pub revision: String,
}

/// Generate a fresh 32-byte secret encoded as URL-safe base64 (no pad).
pub fn generate_secret_b64() -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

pub fn sign(secret: &[u8], timestamp_secs: i64, body: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).expect("HMAC-SHA-256 accepts any key length");
    mac.update(format!("{timestamp_secs}.").as_bytes());
    mac.update(body);
    let digest = mac.finalize().into_bytes();
    format!("t={timestamp_secs},v1={}", hex::encode(digest))
}

/// Backoff schedule for failed deliveries. Returns seconds until next
/// attempt for the given (1-based) attempt number.
pub fn backoff_for(attempts: i32) -> i64 {
    match attempts {
        0 | 1 => 30,
        2 => 60,
        3 => 120,
        4 => 300,
        5 => 900,
        6 => 1800,
        7 => 3600,
        8 => 7200,
        9 => 21600,
        10 => 43200,
        _ => 86400,
    }
}

/// Spawn enqueuer + worker as long-lived tokio tasks.
///
/// `allow_unsafe_destinations` mirrors `Config::webhooks_allow_unsafe_destinations`
/// — when false (the production default), the worker resolves every
/// destination URL on every attempt and refuses private / loopback /
/// link-local IPs (audit S-H1, 2026-05-07).
pub fn spawn_dispatcher(pool: AnyPool, bus: PushBus, allow_unsafe_destinations: bool) {
    spawn_enqueuer(pool.clone(), bus);
    spawn_worker(pool, allow_unsafe_destinations);
}

fn spawn_enqueuer(pool: AnyPool, bus: PushBus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if let Err(e) = enqueue_event(&pool, event).await {
                        tracing::warn!(error = %e, "webhook enqueue error");
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(missed = n, "webhook enqueuer lagged");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::info!("webhook enqueuer exiting (push bus closed)");
                    return;
                }
            }
        }
    });
}

fn spawn_worker(pool: AnyPool, allow_unsafe_destinations: bool) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(WORKER_TICK).await;
            if let Err(e) = drain_due(&pool, allow_unsafe_destinations).await {
                tracing::warn!(error = %e, "webhook worker tick error");
            }
        }
    });
}

async fn enqueue_event(pool: &AnyPool, event: PushEvent) -> anyhow::Result<()> {
    let kind_str = event.kind.as_str().to_string();

    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, events FROM webhooks
         WHERE user_id = $1 AND disabled_at IS NULL",
    )
    .bind(&event.user_id)
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        return Ok(());
    }

    let payload = EventPayload {
        id: Uuid::now_v7().to_string(),
        kind: kind_str.clone(),
        created_at: Utc::now().to_rfc3339(),
        data: EventData {
            id: event.id.clone(),
            revision: event.revision.clone(),
        },
    };
    let body_json = serde_json::to_string(&payload)?;
    let now = Utc::now().to_rfc3339();

    for (webhook_id, events_csv) in rows {
        if !filter_matches(&events_csv, &kind_str) {
            continue;
        }
        let delivery_id = Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO webhook_deliveries
                (id, webhook_id, user_id, event_id, event_type, payload, next_attempt_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&delivery_id)
        .bind(&webhook_id)
        .bind(&event.user_id)
        .bind(&payload.id)
        .bind(&kind_str)
        .bind(&body_json)
        .bind(&now)
        .execute(pool)
        .await?;
    }
    Ok(())
}

fn filter_matches(filter_csv: &str, kind: &str) -> bool {
    let trimmed = filter_csv.trim();
    if trimmed.is_empty() || trimmed == "*" {
        return true;
    }
    trimmed.split(',').any(|f| f.trim() == kind)
}

async fn drain_due(pool: &AnyPool, allow_unsafe_destinations: bool) -> anyhow::Result<()> {
    let now = Utc::now().to_rfc3339();
    #[allow(clippy::type_complexity)]
    let rows: Vec<(String, String, String, String, String, String, i32)> = sqlx::query_as(
        "SELECT d.id, d.event_id, d.event_type, d.payload, w.url, w.secret_b64, d.attempts
         FROM webhook_deliveries d
         JOIN webhooks w ON w.id = d.webhook_id
         WHERE d.delivered_at IS NULL
           AND d.failed_permanently_at IS NULL
           AND d.next_attempt_at <= $1
           AND w.disabled_at IS NULL
         ORDER BY d.next_attempt_at ASC
         LIMIT $2",
    )
    .bind(&now)
    .bind(WORKER_BATCH)
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        return Ok(());
    }

    for (delivery_id, event_id, event_type, body_json, url, secret_b64, attempts) in rows {
        let secret = match URL_SAFE_NO_PAD.decode(&secret_b64) {
            Ok(s) => s,
            Err(_) => {
                mark_failed_permanently(pool, &delivery_id, "malformed secret_b64").await?;
                continue;
            }
        };
        let outcome = attempt_one(
            allow_unsafe_destinations,
            &secret,
            &url,
            &event_id,
            &event_type,
            body_json.as_bytes(),
        )
        .await;
        record_attempt(pool, &delivery_id, attempts, outcome).await?;
    }
    Ok(())
}

#[derive(Debug)]
enum AttemptOutcome {
    Success(u16),
    HttpError(u16),
    Network(String),
}

async fn attempt_one(
    allow_unsafe_destinations: bool,
    secret: &[u8],
    url: &str,
    event_id: &str,
    event_type: &str,
    body: &[u8],
) -> AttemptOutcome {
    // Audit S-H1 (2026-05-07): re-resolve every attempt and pin the
    // connection to that exact IP. Defeats DNS rebinding — without
    // this, an attacker who registered a webhook against a public IP
    // could flip the DNS record to 169.254.169.254 between create and
    // delivery and the worker would happily POST to cloud metadata.
    let pinned = match crate::webhook_url::resolve_safe(url, allow_unsafe_destinations).await {
        Ok(p) => p,
        Err(e) => return AttemptOutcome::Network(format!("destination refused: {e}")),
    };

    // One-shot client per attempt so the resolve override doesn't
    // accumulate across deliveries. `.resolve(host, addr)` makes
    // reqwest connect to the IP we just validated; the TLS layer
    // still sees `host` for SNI / cert verification.
    let client = match reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(DELIVERY_TIMEOUT)
        .resolve(&pinned.host, pinned.addr)
        .build()
    {
        Ok(c) => c,
        Err(e) => return AttemptOutcome::Network(format!("could not build client: {e}")),
    };

    let timestamp = Utc::now().timestamp();
    let signature = sign(secret, timestamp, body);
    match client
        .post(url)
        .header("content-type", "application/json")
        .header("x-hekate-event-id", event_id)
        .header("x-hekate-event-type", event_type)
        .header("x-hekate-signature", signature)
        .body(body.to_vec())
        .send()
        .await
    {
        Ok(r) => {
            let status = r.status().as_u16();
            if r.status().is_success() {
                AttemptOutcome::Success(status)
            } else {
                AttemptOutcome::HttpError(status)
            }
        }
        Err(e) => AttemptOutcome::Network(e.to_string()),
    }
}

async fn record_attempt(
    pool: &AnyPool,
    delivery_id: &str,
    prior_attempts: i32,
    outcome: AttemptOutcome,
) -> anyhow::Result<()> {
    let now = Utc::now();
    let new_attempts = prior_attempts + 1;
    match outcome {
        AttemptOutcome::Success(status) => {
            sqlx::query(
                "UPDATE webhook_deliveries
                 SET attempts = $1, last_status = $2, last_error = NULL, delivered_at = $3
                 WHERE id = $4",
            )
            .bind(new_attempts)
            .bind(status as i32)
            .bind(now.to_rfc3339())
            .bind(delivery_id)
            .execute(pool)
            .await?;
        }
        AttemptOutcome::HttpError(status) => {
            update_failed_attempt(
                pool,
                delivery_id,
                new_attempts,
                Some(status as i32),
                Some(format!("HTTP {status}")),
                now,
            )
            .await?;
        }
        AttemptOutcome::Network(msg) => {
            update_failed_attempt(pool, delivery_id, new_attempts, None, Some(msg), now).await?;
        }
    }
    Ok(())
}

async fn update_failed_attempt(
    pool: &AnyPool,
    delivery_id: &str,
    new_attempts: i32,
    last_status: Option<i32>,
    last_error: Option<String>,
    now: DateTime<Utc>,
) -> anyhow::Result<()> {
    if new_attempts >= MAX_ATTEMPTS {
        sqlx::query(
            "UPDATE webhook_deliveries
             SET attempts = $1, last_status = $2, last_error = $3,
                 failed_permanently_at = $4, next_attempt_at = $4
             WHERE id = $5",
        )
        .bind(new_attempts)
        .bind(last_status)
        .bind(&last_error)
        .bind(now.to_rfc3339())
        .bind(delivery_id)
        .execute(pool)
        .await?;
    } else {
        let next = now + chrono::Duration::seconds(backoff_for(new_attempts));
        sqlx::query(
            "UPDATE webhook_deliveries
             SET attempts = $1, last_status = $2, last_error = $3, next_attempt_at = $4
             WHERE id = $5",
        )
        .bind(new_attempts)
        .bind(last_status)
        .bind(&last_error)
        .bind(next.to_rfc3339())
        .bind(delivery_id)
        .execute(pool)
        .await?;
    }
    Ok(())
}

async fn mark_failed_permanently(
    pool: &AnyPool,
    delivery_id: &str,
    reason: &str,
) -> anyhow::Result<()> {
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE webhook_deliveries
         SET failed_permanently_at = $1, last_error = $2, next_attempt_at = $1
         WHERE id = $3",
    )
    .bind(&now)
    .bind(reason)
    .bind(delivery_id)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_is_deterministic_and_includes_timestamp() {
        let secret = b"secret-key";
        let s1 = sign(secret, 1700000000, b"{\"x\":1}");
        let s2 = sign(secret, 1700000000, b"{\"x\":1}");
        assert_eq!(s1, s2);
        assert!(s1.starts_with("t=1700000000,v1="));
    }

    #[test]
    fn different_body_gives_different_sig() {
        let secret = b"secret-key";
        let s1 = sign(secret, 0, b"a");
        let s2 = sign(secret, 0, b"b");
        assert_ne!(s1, s2);
    }

    #[test]
    fn different_timestamp_gives_different_sig() {
        let secret = b"k";
        let s1 = sign(secret, 1, b"x");
        let s2 = sign(secret, 2, b"x");
        assert_ne!(s1, s2);
    }

    #[test]
    fn filter_wildcard_and_csv() {
        assert!(filter_matches("*", "cipher.changed"));
        assert!(filter_matches("", "cipher.changed"));
        assert!(filter_matches(
            "cipher.changed,cipher.tombstoned",
            "cipher.changed"
        ));
        assert!(!filter_matches("cipher.tombstoned", "cipher.changed"));
        assert!(filter_matches(
            " cipher.changed , folder.changed ",
            "folder.changed"
        ));
    }

    #[test]
    fn generated_secret_is_unique_and_decodable() {
        let s1 = generate_secret_b64();
        let s2 = generate_secret_b64();
        assert_ne!(s1, s2);
        let bytes = URL_SAFE_NO_PAD.decode(&s1).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn backoff_grows_then_caps() {
        assert_eq!(backoff_for(1), 30);
        assert_eq!(backoff_for(4), 300);
        assert_eq!(backoff_for(10), 43200);
        assert_eq!(backoff_for(99), 86400);
    }
}
