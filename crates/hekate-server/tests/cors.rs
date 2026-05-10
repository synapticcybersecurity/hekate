//! CORS middleware behavior — audit S-M4.
//!
//! Coverage:
//!   * empty allowlist (default) is fully transparent
//!   * preflight from allowed origin → 204 + Allow-Origin / Allow-
//!     Methods / Allow-Headers / Max-Age / Vary
//!   * preflight from disallowed origin → 403, no CORS headers
//!   * non-preflight from allowed origin → handler runs, response
//!     gains Allow-Origin / Expose-Headers / Vary
//!   * tus discovery (OPTIONS without Access-Control-Request-Method)
//!     keeps returning 204 + Tus-* headers and ALSO gains Allow-Origin
//!     when the request comes with a matching Origin.
//!   * non-preflight from disallowed origin → handler runs, no CORS
//!     headers attached

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use hekate_server::{bootstrap, build_router, config::Config};
use tower::ServiceExt;

async fn app_with_origins(origins: Vec<&str>) -> Router {
    let cfg = Config {
        listen: "0.0.0.0:0".into(),
        database_url: "sqlite::memory:".into(),
        fake_salt_pepper: vec![0u8; 32],
        cors_allowed_origins: origins.into_iter().map(String::from).collect(),
        ..Default::default()
    };
    let state = bootstrap(cfg).await.expect("bootstrap");
    build_router(state)
}

async fn options(
    app: &Router,
    path: &str,
    origin: Option<&str>,
    request_method: Option<&str>,
) -> axum::http::Response<Body> {
    let mut req = Request::builder().method("OPTIONS").uri(path);
    if let Some(o) = origin {
        req = req.header(header::ORIGIN, o);
    }
    if let Some(m) = request_method {
        req = req.header("access-control-request-method", m);
    }
    app.clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn empty_allowlist_is_transparent() {
    let app = app_with_origins(vec![]).await;
    // tus discovery still returns 204 + Tus-* — nothing else changes.
    let resp = options(&app, "/api/v1/attachments", None, None).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(resp.headers().get("Tus-Resumable").is_some());
    assert!(resp
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());
}

#[tokio::test]
async fn preflight_from_allowed_origin_succeeds() {
    let app = app_with_origins(vec!["https://vault.example.com"]).await;
    let resp = options(
        &app,
        "/api/v1/ciphers",
        Some("https://vault.example.com"),
        Some("POST"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let h = resp.headers();
    assert_eq!(
        h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
        "https://vault.example.com"
    );
    assert!(h.get(header::ACCESS_CONTROL_ALLOW_METHODS).is_some());
    assert!(h.get(header::ACCESS_CONTROL_ALLOW_HEADERS).is_some());
    assert!(h.get(header::ACCESS_CONTROL_MAX_AGE).is_some());
    assert_eq!(h.get(header::VARY).unwrap(), "origin");
}

#[tokio::test]
async fn preflight_from_disallowed_origin_403() {
    let app = app_with_origins(vec!["https://vault.example.com"]).await;
    let resp = options(
        &app,
        "/api/v1/ciphers",
        Some("https://evil.example.com"),
        Some("POST"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(resp
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());
}

#[tokio::test]
async fn non_preflight_from_allowed_origin_gets_cors_headers() {
    let app = app_with_origins(vec!["https://vault.example.com"]).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health/ready")
                .header(header::ORIGIN, "https://vault.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://vault.example.com"
    );
    assert!(resp
        .headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .is_some());
}

#[tokio::test]
async fn tus_discovery_passes_through_with_origin() {
    // The tus + CORS coexistence test. OPTIONS without Access-Control-
    // Request-Method is NOT a preflight; the tus discovery handler
    // must still run and return 204 + Tus-*. CORS headers attach on
    // the way out.
    let app = app_with_origins(vec!["https://vault.example.com"]).await;
    let resp = options(
        &app,
        "/api/v1/attachments",
        Some("https://vault.example.com"),
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let h = resp.headers();
    assert_eq!(h.get("Tus-Resumable").unwrap(), "1.0.0");
    assert!(h.get("Tus-Max-Size").is_some());
    assert_eq!(
        h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
        "https://vault.example.com"
    );
}

#[tokio::test]
async fn non_preflight_from_disallowed_origin_no_cors_headers() {
    let app = app_with_origins(vec!["https://vault.example.com"]).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health/ready")
                .header(header::ORIGIN, "https://evil.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Server returns its normal response; CORS headers absent so the
    // browser blocks the JS from reading the body.
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());
}
