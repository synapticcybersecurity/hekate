//! End-to-end tests for ciphers, folders, and the sync delta protocol.

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use hekate_server::{bootstrap, build_router, config::Config};
use serde_json::{json, Value};
use tower::ServiceExt;

const MPH_BYTES: [u8; 32] = [42u8; 32];

fn b64(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

fn enc_placeholder() -> &'static str {
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

async fn register(app: &Router, email: &str) {
    let body = json!({
        "email": email,
        "kdf_params": {"alg": "argon2id", "m_kib": 64, "t": 1, "p": 1},
        "kdf_salt": b64(&[7u8; 16]),
        "kdf_params_mac": b64(&[0xa5u8; 32]),
        "master_password_hash": b64(&MPH_BYTES),
        "protected_account_key": enc_placeholder(),
        "account_public_key": b64(&[1u8; 32]),
        "protected_account_private_key": enc_placeholder(),
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

async fn login(app: &Router, email: &str) -> String {
    let body = format!(
        "grant_type=password&username={}&password={}",
        email,
        b64(&MPH_BYTES)
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
    let v = body_json(resp).await;
    v["access_token"].as_str().unwrap().to_string()
}

async fn auth_app(email: &str) -> (Router, String) {
    let app = test_app().await;
    register(&app, email).await;
    let token = login(&app, email).await;
    (app, token)
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| panic!("non-JSON body: {:?}", String::from_utf8_lossy(&bytes)))
}

fn cipher_payload(name_marker: &str) -> Value {
    json!({
        // BW04/LP06: client supplies a UUIDv7 so the server can authenticate
        // the row identity via AAD-bound encryption. Tests use UUIDv4 since
        // we only validate "is a UUID" server-side.
        "id": uuid::Uuid::new_v4().to_string(),
        "type": 1,
        "folder_id": null,
        "protected_cipher_key": enc_placeholder(),
        "name": format!("v3.xc20p.kid.AA.AA.{}.AAAAAAAAAAAAAAAAAAAAAA", b64(name_marker.as_bytes())),
        "notes": null,
        "data": enc_placeholder(),
        "favorite": false,
    })
}

fn req(method: &str, path: &str, token: &str, body: Option<&Value>) -> Request<Body> {
    let b = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("content-type", "application/json");
    if let Some(v) = body {
        b.body(Body::from(v.to_string())).unwrap()
    } else {
        b.body(Body::empty()).unwrap()
    }
}

// ---------------- Auth gate ----------------

#[tokio::test]
async fn cipher_endpoints_require_auth() {
    let app = test_app().await;
    let resp = app
        .oneshot(req(
            "POST",
            "/api/v1/ciphers",
            "garbage",
            Some(&cipher_payload("x")),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------- Cipher CRUD ----------------

#[tokio::test]
async fn create_then_read_cipher() {
    let (app, token) = auth_app("a@example.com").await;

    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/ciphers",
            &token,
            Some(&cipher_payload("hello")),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    let id = created["id"].as_str().unwrap();
    assert!(created["revision_date"].is_string());

    let resp = app
        .oneshot(req("GET", &format!("/api/v1/ciphers/{id}"), &token, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let read = body_json(resp).await;
    assert_eq!(read["id"], created["id"]);
    assert_eq!(read["type"], 1);
}

#[tokio::test]
async fn cipher_validation_rejects_bad_encstring() {
    let (app, token) = auth_app("b@example.com").await;
    let mut payload = cipher_payload("x");
    payload["data"] = json!("not-an-encstring");
    let resp = app
        .oneshot(req("POST", "/api/v1/ciphers", &token, Some(&payload)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_without_if_match_returns_428() {
    let (app, token) = auth_app("c@example.com").await;
    let created = body_json(
        app.clone()
            .oneshot(req(
                "POST",
                "/api/v1/ciphers",
                &token,
                Some(&cipher_payload("a")),
            ))
            .await
            .unwrap(),
    )
    .await;
    let id = created["id"].as_str().unwrap();

    let resp = app
        .oneshot(req(
            "PUT",
            &format!("/api/v1/ciphers/{id}"),
            &token,
            Some(&cipher_payload("a")),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_REQUIRED);
}

#[tokio::test]
async fn put_with_stale_if_match_returns_conflict_with_current() {
    let (app, token) = auth_app("d@example.com").await;
    let created = body_json(
        app.clone()
            .oneshot(req(
                "POST",
                "/api/v1/ciphers",
                &token,
                Some(&cipher_payload("a")),
            ))
            .await
            .unwrap(),
    )
    .await;
    let id = created["id"].as_str().unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/ciphers/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .header(header::IF_MATCH, "\"1970-01-01T00:00:00Z\"")
                .body(Body::from(cipher_payload("b").to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "revision conflict");
    assert_eq!(body["current"]["id"], created["id"]);
}

#[tokio::test]
async fn put_with_correct_if_match_succeeds_and_bumps_revision() {
    let (app, token) = auth_app("e@example.com").await;
    let created = body_json(
        app.clone()
            .oneshot(req(
                "POST",
                "/api/v1/ciphers",
                &token,
                Some(&cipher_payload("a")),
            ))
            .await
            .unwrap(),
    )
    .await;
    let id = created["id"].as_str().unwrap();
    let rev = created["revision_date"].as_str().unwrap().to_string();

    // Sleep 50ms so revision_date has a chance to differ even on fast clocks.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/ciphers/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .header(header::IF_MATCH, format!("\"{rev}\""))
                .body(Body::from(cipher_payload("b").to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let updated = body_json(resp).await;
    assert_ne!(updated["revision_date"], created["revision_date"]);
}

#[tokio::test]
async fn soft_delete_then_restore() {
    let (app, token) = auth_app("f@example.com").await;
    let created = body_json(
        app.clone()
            .oneshot(req(
                "POST",
                "/api/v1/ciphers",
                &token,
                Some(&cipher_payload("a")),
            ))
            .await
            .unwrap(),
    )
    .await;
    let id = created["id"].as_str().unwrap();

    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/ciphers/{id}"),
            &token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let read = body_json(
        app.clone()
            .oneshot(req("GET", &format!("/api/v1/ciphers/{id}"), &token, None))
            .await
            .unwrap(),
    )
    .await;
    assert!(read["deleted_date"].as_str().is_some());

    let restored = body_json(
        app.oneshot(req(
            "POST",
            &format!("/api/v1/ciphers/{id}/restore"),
            &token,
            None,
        ))
        .await
        .unwrap(),
    )
    .await;
    assert!(restored["deleted_date"].is_null());
}

#[tokio::test]
async fn permanent_delete_creates_tombstone_in_sync() {
    let (app, token) = auth_app("g@example.com").await;
    let created = body_json(
        app.clone()
            .oneshot(req(
                "POST",
                "/api/v1/ciphers",
                &token,
                Some(&cipher_payload("a")),
            ))
            .await
            .unwrap(),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/ciphers/{id}/permanent"),
            &token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = app
        .oneshot(req("GET", "/api/v1/sync", &token, None))
        .await
        .unwrap();
    let body = body_json(resp).await;
    let tombstones = body["changes"]["tombstones"].as_array().unwrap();
    assert!(
        tombstones
            .iter()
            .any(|t| t["id"] == id && t["kind"] == "cipher"),
        "expected tombstone for purged cipher"
    );
}

// ---------------- Folder CRUD ----------------

fn folder_payload(marker: &str) -> Value {
    json!({
        "name": format!(
            "v3.xc20p.kid.AA.AA.{}.AAAAAAAAAAAAAAAAAAAAAA",
            b64(marker.as_bytes())
        ),
    })
}

#[tokio::test]
async fn folder_crud_round_trip() {
    let (app, token) = auth_app("h@example.com").await;
    let created = body_json(
        app.clone()
            .oneshot(req(
                "POST",
                "/api/v1/folders",
                &token,
                Some(&folder_payload("Personal")),
            ))
            .await
            .unwrap(),
    )
    .await;
    let id = created["id"].as_str().unwrap();
    let rev = created["revision_date"].as_str().unwrap().to_string();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/folders/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .header(header::IF_MATCH, format!("\"{rev}\""))
                .body(Body::from(folder_payload("Renamed").to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/folders/{id}"),
            &token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

// ---------------- Sync ----------------

#[tokio::test]
async fn sync_returns_everything_when_no_since() {
    let (app, token) = auth_app("i@example.com").await;
    for n in ["a", "b", "c"] {
        app.clone()
            .oneshot(req(
                "POST",
                "/api/v1/ciphers",
                &token,
                Some(&cipher_payload(n)),
            ))
            .await
            .unwrap();
    }
    let resp = app
        .oneshot(req("GET", "/api/v1/sync", &token, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["changes"]["ciphers"].as_array().unwrap().len(), 3);
    assert!(body["high_water"].is_string());
    assert!(body["complete"].as_bool().unwrap());
}

#[tokio::test]
async fn sync_with_since_returns_only_later_changes() {
    let (app, token) = auth_app("j@example.com").await;

    // Create A, sync to get high_water, then create B, then sync again.
    app.clone()
        .oneshot(req(
            "POST",
            "/api/v1/ciphers",
            &token,
            Some(&cipher_payload("A")),
        ))
        .await
        .unwrap();

    let body = body_json(
        app.clone()
            .oneshot(req("GET", "/api/v1/sync", &token, None))
            .await
            .unwrap(),
    )
    .await;
    let watermark = body["high_water"].as_str().unwrap().to_string();
    assert_eq!(body["changes"]["ciphers"].as_array().unwrap().len(), 1);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    app.clone()
        .oneshot(req(
            "POST",
            "/api/v1/ciphers",
            &token,
            Some(&cipher_payload("B")),
        ))
        .await
        .unwrap();

    let body = body_json(
        app.oneshot(req(
            "GET",
            &format!("/api/v1/sync?since={}", urlencoded(&watermark)),
            &token,
            None,
        ))
        .await
        .unwrap(),
    )
    .await;
    let ciphers = body["changes"]["ciphers"].as_array().unwrap();
    assert_eq!(ciphers.len(), 1, "should only see the new cipher");
}

fn urlencoded(s: &str) -> String {
    s.replace(':', "%3A").replace('+', "%2B")
}
