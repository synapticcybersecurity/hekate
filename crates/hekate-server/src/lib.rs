pub mod attachments_gc;
pub mod auth;
pub mod blob;
pub mod config;
pub mod cors;
pub mod db;
pub mod openapi;
pub mod perms;
pub mod push;
pub mod rate_limit;
pub mod routes;
pub mod webhook_url;
pub mod webhooks;

use std::sync::Arc;

use axum::http::StatusCode;
use axum::Router;
use tokio::net::TcpListener;
use tower_http::{compression::CompressionLayer, timeout::TimeoutLayer, trace::TraceLayer};

use crate::{
    auth::jwt::Signer,
    blob::{DynBlobStore, LocalFsBlobStore},
    config::Config,
    db::Db,
    push::PushBus,
};
use webauthn_rs::Webauthn;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub config: Arc<Config>,
    pub signer: Signer,
    pub push: PushBus,
    /// WebAuthn relying-party instance (M2.23). Constructed once from
    /// `(webauthn_rp_id, webauthn_rp_origin)` config; cheap to clone.
    pub webauthn: Arc<Webauthn>,
    /// (M2.24) Attachment blob backend. Local-FS in M2.24; S3/MinIO via
    /// `object_store` arrives in M2.24a behind the same trait.
    pub blob: DynBlobStore,
    /// Per-IP rate limiters (audit S-M3). Constructed once at bootstrap
    /// — `Arc`-internal so cloning AppState is cheap.
    pub limiters: rate_limit::Limiters,
}

pub fn tracing_init() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,hekate_server=debug,sqlx=warn"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json().with_target(true))
        .init();
}

/// Build the axum router for an already-bootstrapped `AppState`. Used by both
/// the production `run` path and integration tests.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .merge(routes::root::router())
        .merge(routes::health::router())
        .merge(routes::api::router())
        .merge(routes::accounts::router())
        .merge(routes::account::router())
        .merge(routes::account_tokens::router())
        .merge(routes::account_webhooks::router())
        .merge(routes::attachments::router())
        .merge(routes::identity::router())
        .merge(routes::ciphers::router())
        .merge(routes::collections::router())
        .merge(routes::folders::router())
        .merge(routes::org_cipher_manifest::router())
        .merge(routes::orgs::router())
        .merge(routes::policies::router())
        .merge(routes::pubkeys::router())
        .merge(routes::web_app::router(state.config.web_dir.as_deref()))
        .merge(routes::sends::router())
        .merge(routes::service_accounts::router())
        .merge(routes::sync::router())
        .merge(routes::two_factor::router())
        .merge(routes::two_factor_webauthn::router())
        .merge(routes::vault_manifest::router())
        .merge(routes::push::router())
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        // Audit S-M4 (2026-05-07): CORS on the API surface, gated on
        // Config::cors_allowed_origins. Empty allowlist (default) =
        // fully transparent middleware (same-origin only). Non-empty
        // = strict per-origin allowlist with surgical preflight
        // handling that doesn't preempt tus's OPTIONS discovery.
        // See crates/hekate-server/src/cors.rs for the full posture
        // (no wildcards, no Allow-Credentials, exact-match origin).
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::cors::cors_middleware,
        ))
        // Audit S-M3 (2026-05-07): per-IP rate limiting. Strict bucket
        // on auth-shaped paths (login, register, prelogin, public Send
        // password gate); lenient bucket as a backstop everywhere
        // else. Test mode (in-memory SQLite marker) short-circuits
        // the limiter so the suite doesn't self-throttle. See
        // src/rate_limit.rs for the bucket sizes + IP-extraction
        // policy (off-by-default proxy header trust).
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::rate_limit::rate_limit_middleware,
        ))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            // Production: 30s is plenty. In-memory SQLite is the test-mode
            // marker — bump the budget there because heavy parallel tests
            // (Argon2id-bound 2FA flows + recovery codes + a 4-core CI
            // runner) can otherwise trip the timeout on requests that
            // would never time out under non-contended local runs.
            if crate::db::is_memory_sqlite(&state.config.database_url) {
                std::time::Duration::from_secs(120)
            } else {
                std::time::Duration::from_secs(30)
            },
        ))
        .with_state(state)
}

/// Connect to the DB, run migrations, bootstrap signing key. Used by both
/// production startup and tests.
pub async fn bootstrap(cfg: Config) -> anyhow::Result<AppState> {
    let db = Db::connect(&cfg.database_url).await?;
    db.migrate().await?;
    let signer = Signer::bootstrap(db.pool()).await?;
    let push = PushBus::new();
    // Spawn the webhook dispatcher so events flow to registered URLs as
    // soon as the server is running. Best-effort, no retry queue.
    webhooks::spawn_dispatcher(
        db.pool().clone(),
        push.clone(),
        cfg.webhooks_allow_unsafe_destinations,
    );
    let webauthn = build_webauthn(&cfg)?;
    // In-memory SQLite is the test-mode marker. Tests construct
    // `Config { database_url: "sqlite::memory:", ..Default::default() }`,
    // so route the blob root to a per-process tempdir to avoid
    // touching `/data` (the production default that won't exist in a
    // non-root dev container). Real deployments always hit the
    // configured path.
    let attachments_dir = if crate::db::is_memory_sqlite(&cfg.database_url) {
        std::env::temp_dir()
            .join(format!("hekate-attachments-{}", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string()
    } else {
        cfg.attachments_dir.clone()
    };
    let blob: DynBlobStore = Arc::new(
        LocalFsBlobStore::new(&attachments_dir)
            .map_err(|e| anyhow::anyhow!("attachments_dir bootstrap ({attachments_dir}): {e}"))?,
    );
    // Spawn the attachments GC worker — drains blob tombstones and
    // prunes expired in-progress uploads. Mirrors the webhooks
    // dispatcher pattern: long-lived task on the same tokio runtime.
    attachments_gc::spawn(db.pool().clone(), blob.clone());
    Ok(AppState {
        db,
        config: Arc::new(cfg),
        signer,
        push,
        webauthn: Arc::new(webauthn),
        blob,
        limiters: rate_limit::Limiters::default(),
    })
}

fn build_webauthn(cfg: &Config) -> anyhow::Result<Webauthn> {
    use webauthn_rs::WebauthnBuilder;
    let origin = url::Url::parse(&cfg.webauthn_rp_origin)
        .map_err(|e| anyhow::anyhow!("webauthn_rp_origin is not a valid URL: {e}"))?;
    WebauthnBuilder::new(&cfg.webauthn_rp_id, &origin)
        .map_err(|e| anyhow::anyhow!("WebAuthn config invalid: {e}"))?
        .rp_name("hekate")
        .build()
        .map_err(|e| anyhow::anyhow!("WebAuthn build failed: {e}"))
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let listen = cfg.listen.clone();
    let state = bootstrap(cfg).await?;
    let app = build_router(state);

    let listener = TcpListener::bind(&listen).await?;
    tracing::info!(addr = %listen, "listening");
    // Audit S-M3 (2026-05-07): wire `ConnectInfo<SocketAddr>` so the
    // rate-limit middleware can read the direct peer IP. Without
    // this, the limiter falls back to the unspecified address and
    // every client shares one bucket.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
