//! Refresh-token rotation, end-to-end through the HTTP token endpoint.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use hekate_server::{bootstrap, build_router, config::Config};
use serde_json::{json, Value};
use tower::ServiceExt;

const MPH: [u8; 32] = [42u8; 32];

fn b64(b: &[u8]) -> String {
    STANDARD_NO_PAD.encode(b)
}

fn enc() -> &'static str {
    "v3.xc20p.kid.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA"
}

async fn test_app() -> Router {
    let cfg = Config {
        listen: "0.0.0.0:0".into(),
        database_url: "sqlite::memory:".into(),
        fake_salt_pepper: vec![0u8; 32],
        ..Default::default()
    };
    let state = bootstrap(cfg).await.expect("bootstrap");
    build_router(state)
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| panic!("non-JSON body: {:?}", String::from_utf8_lossy(&bytes)))
}

async fn register(app: &Router, email: &str) {
    let body = json!({
        "email": email,
        "kdf_params": {"alg": "argon2id", "m_kib": 64, "t": 1, "p": 1},
        "kdf_salt": b64(&[7u8; 16]),
        "kdf_params_mac": b64(&[0xa5u8; 32]),
        "master_password_hash": b64(&MPH),
        "protected_account_key": enc(),
        "account_public_key": b64(&[1u8; 32]),
        "protected_account_private_key": enc(),
    });
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/accounts/register")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

async fn password_login(app: &Router, email: &str) -> Value {
    let body = format!(
        "grant_type=password&username={email}&password={}",
        b64(&MPH)
    );
    let resp = app
        .clone()
        .oneshot(
            Request::post("/identity/connect/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    body_json(resp).await
}

async fn refresh(app: &Router, refresh_token: &str) -> axum::response::Response {
    let body = format!("grant_type=refresh_token&refresh_token={refresh_token}");
    app.clone()
        .oneshot(
            Request::post("/identity/connect/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn password_grant_returns_refresh_token() {
    let app = test_app().await;
    register(&app, "alice@example.com").await;
    let body = password_login(&app, "alice@example.com").await;
    assert!(body["refresh_token"]
        .as_str()
        .is_some_and(|s| s.contains('.') && s.len() > 50));
    assert!(body["protected_account_key"].is_string()); // initial login still ships material
}

#[tokio::test]
async fn refresh_grant_rotates_and_returns_new_pair() {
    let app = test_app().await;
    register(&app, "bob@example.com").await;
    let initial = password_login(&app, "bob@example.com").await;
    let r1 = initial["refresh_token"].as_str().unwrap().to_string();
    let a1 = initial["access_token"].as_str().unwrap().to_string();

    let resp = refresh(&app, &r1).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let r2 = body["refresh_token"].as_str().unwrap().to_string();
    let a2 = body["access_token"].as_str().unwrap().to_string();
    assert_ne!(r1, r2, "refresh token must rotate");
    assert_ne!(a1, a2, "access token must be re-issued");
    // Refresh response should NOT re-ship account material.
    assert!(body["protected_account_key"].is_null());
}

#[tokio::test]
async fn replayed_refresh_token_revokes_family() {
    let app = test_app().await;
    register(&app, "carol@example.com").await;
    let initial = password_login(&app, "carol@example.com").await;
    let r1 = initial["refresh_token"].as_str().unwrap().to_string();

    // First refresh: ok.
    let resp = refresh(&app, &r1).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let r2 = body_json(resp).await["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Replay r1: should be 401 (reuse detected, family revoked).
    let resp = refresh(&app, &r1).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // r2 was descended from the same family — also revoked now.
    let resp = refresh(&app, &r2).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_grant_type_returns_400() {
    let app = test_app().await;
    let resp = app
        .oneshot(
            Request::post("/identity/connect/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=client_credentials"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
