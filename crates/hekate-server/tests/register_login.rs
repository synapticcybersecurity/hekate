//! Integration test: register → prelogin → token, end-to-end against an
//! in-memory SQLite-backed server (no Docker, no Postgres).

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use hekate_server::{bootstrap, build_router, config::Config};
use serde_json::{json, Value};
use tower::ServiceExt;

/// Construct a server backed by `sqlite::memory:`. Memory DB is single-conn
/// only; the pool is sized to 1 in `Db::connect` regardless, but we keep
/// the URL pattern simple here.
async fn test_app() -> axum::Router {
    let cfg = Config {
        listen: "0.0.0.0:0".into(),
        database_url: "sqlite::memory:".into(),
        fake_salt_pepper: vec![0u8; 32],
        ..Default::default()
    };
    let state = bootstrap(cfg).await.expect("bootstrap");
    build_router(state)
}

fn b64(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| panic!("non-JSON body: {:?}", String::from_utf8_lossy(&bytes)))
}

fn register_payload(email: &str) -> Value {
    json!({
        "email": email,
        "kdf_params": {"alg": "argon2id", "m_kib": 64, "t": 1, "p": 1},
        "kdf_salt": b64(&[7u8; 16]),
        // Real clients compute HMAC-SHA256 over (params, salt) under a
        // bind subkey of the master key. The server only validates length;
        // a constant 32-byte stub is fine for register/prelogin/token
        // endpoint tests, which don't exercise client-side verification.
        "kdf_params_mac": b64(&[0xa5u8; 32]),
        "master_password_hash": b64(&[42u8; 32]),
        "protected_account_key": "v3.xc20p.kid.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA",
        "account_public_key": b64(&[1u8; 32]),
        "protected_account_private_key": "v3.xc20p.kid.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA",
    })
}

#[tokio::test]
async fn register_creates_user() {
    let app = test_app().await;
    let resp = app
        .oneshot(
            Request::post("/api/v1/accounts/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    register_payload("alice@example.com").to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert!(body["user_id"].is_string());
}

#[tokio::test]
async fn duplicate_register_returns_synthetic_201_to_block_enumeration() {
    // Audit S-H2 (2026-05-07): the register endpoint must not leak
    // email existence. Both the first registration and a duplicate
    // resubmit return 201 Created; the duplicate gets a freshly
    // synthesized user_id so the response is shape-identical to a
    // genuinely new account. The probing client can't actually log
    // in with the password they sent (the existing row's keys are
    // different) — but the wire response can't be used to enumerate.
    let app = test_app().await;
    let body = register_payload("dup@example.com");
    let mut user_ids = Vec::new();
    for i in 0..2 {
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
        assert_eq!(resp.status(), StatusCode::CREATED, "iteration {i}");
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        user_ids.push(json["user_id"].as_str().unwrap().to_string());
    }
    // The two responses MUST carry different user_ids — otherwise an
    // attacker could detect the duplicate by re-submitting and
    // observing the same id.
    assert_ne!(
        user_ids[0], user_ids[1],
        "synthetic dup-register id must not collide with the real id"
    );
}

#[tokio::test]
async fn prelogin_known_user_returns_real_params() {
    let app = test_app().await;
    let _ = app
        .clone()
        .oneshot(
            Request::post("/api/v1/accounts/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    register_payload("known@example.com").to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .oneshot(
            Request::post("/api/v1/accounts/prelogin")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email": "known@example.com"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["kdf_params"]["alg"], "argon2id");
    assert_eq!(body["kdf_salt"], b64(&[7u8; 16]));
    assert_eq!(body["kdf_params_mac"], b64(&[0xa5u8; 32]));
}

#[tokio::test]
async fn prelogin_unknown_user_returns_fake_but_valid_response() {
    let app = test_app().await;
    let resp = app
        .oneshot(
            Request::post("/api/v1/accounts/prelogin")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email": "ghost@example.com"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    // Realistic shape — same as a real user — to avoid existence leak.
    assert_eq!(body["kdf_params"]["alg"], "argon2id");
    assert!(body["kdf_salt"].as_str().is_some_and(|s| !s.is_empty()));
    // Fake MAC must be present and 32 bytes when decoded so the response
    // is structurally indistinguishable from a known-user response.
    let mac = body["kdf_params_mac"].as_str().expect("string");
    assert_eq!(STANDARD_NO_PAD.decode(mac).unwrap().len(), 32);
}

#[tokio::test]
async fn register_rejects_missing_kdf_params_mac() {
    let app = test_app().await;
    let mut payload = register_payload("nomac@example.com");
    payload.as_object_mut().unwrap().remove("kdf_params_mac");
    let resp = app
        .oneshot(
            Request::post("/api/v1/accounts/register")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    // 422 from axum's JSON extractor when the required field is missing —
    // the type system catches it before the handler body runs. Either 400
    // or 422 demonstrates the server refuses to register a user without
    // a KDF bind MAC; we accept either.
    let s = resp.status();
    assert!(
        s == StatusCode::BAD_REQUEST || s == StatusCode::UNPROCESSABLE_ENTITY,
        "got {s}"
    );
}

#[tokio::test]
async fn register_rejects_short_kdf_params_mac() {
    let app = test_app().await;
    let mut payload = register_payload("shortmac@example.com");
    payload["kdf_params_mac"] = serde_json::Value::String(b64(&[0u8; 16]));
    let resp = app
        .oneshot(
            Request::post("/api/v1/accounts/register")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn token_with_correct_password_succeeds() {
    let app = test_app().await;
    let _ = app
        .clone()
        .oneshot(
            Request::post("/api/v1/accounts/register")
                .header("content-type", "application/json")
                .body(Body::from(register_payload("bob@example.com").to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = format!(
        "grant_type=password&username=bob@example.com&password={}",
        b64(&[42u8; 32])
    );
    let resp = app
        .oneshot(
            Request::post("/identity/connect/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["access_token"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(body["expires_in"], 3600);
    assert_eq!(
        body["protected_account_key"],
        "v3.xc20p.kid.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA"
    );
}

#[tokio::test]
async fn token_with_wrong_password_returns_401() {
    let app = test_app().await;
    let _ = app
        .clone()
        .oneshot(
            Request::post("/api/v1/accounts/register")
                .header("content-type", "application/json")
                .body(Body::from(register_payload("eve@example.com").to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = format!(
        "grant_type=password&username=eve@example.com&password={}",
        b64(&[99u8; 32])
    );
    let resp = app
        .oneshot(
            Request::post("/identity/connect/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_for_unknown_user_returns_401() {
    let app = test_app().await;
    let body = format!(
        "grant_type=password&username=nobody@example.com&password={}",
        b64(&[1u8; 32])
    );
    let resp = app
        .oneshot(
            Request::post("/identity/connect/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
