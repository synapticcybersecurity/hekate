//! Personal Access Token integration tests.

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
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

async fn login_jwt(app: &Router, email: &str) -> String {
    // Register.
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
    let r = app
        .clone()
        .oneshot(
            Request::post("/api/v1/accounts/register")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);

    // Login.
    let body = format!(
        "grant_type=password&username={email}&password={}",
        b64(&MPH)
    );
    let r = app
        .clone()
        .oneshot(
            Request::post("/identity/connect/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    body_json(r).await["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn create_pat(app: &Router, jwt: &str, name: &str, scopes_csv: &str) -> (String, String) {
    let body = json!({"name": name, "scopes": scopes_csv});
    let r = app
        .clone()
        .oneshot(
            Request::post("/api/v1/account/tokens")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let v = body_json(r).await;
    (
        v["id"].as_str().unwrap().to_string(),
        v["token"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn pat_with_read_scope_can_sync_but_not_create() {
    let app = test_app().await;
    let jwt = login_jwt(&app, "alice@example.com").await;
    let (_id, pat) = create_pat(&app, &jwt, "ci-readonly", "vault:read").await;

    // Read works.
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/sync")
                .header(header::AUTHORIZATION, format!("Bearer {pat}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Write is forbidden.
    let cipher_payload = json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "type": 1,
        "folder_id": null,
        "protected_cipher_key": enc(),
        "name": enc(),
        "data": enc(),
        "favorite": false,
    });
    let resp = app
        .oneshot(
            Request::post("/api/v1/ciphers")
                .header(header::AUTHORIZATION, format!("Bearer {pat}"))
                .header("content-type", "application/json")
                .body(Body::from(cipher_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn pat_with_write_scope_can_create() {
    let app = test_app().await;
    let jwt = login_jwt(&app, "bob@example.com").await;
    let (_id, pat) = create_pat(&app, &jwt, "ci-rw", "vault:read,vault:write").await;

    let cipher_payload = json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "type": 1,
        "folder_id": null,
        "protected_cipher_key": enc(),
        "name": enc(),
        "data": enc(),
        "favorite": false,
    });
    let resp = app
        .oneshot(
            Request::post("/api/v1/ciphers")
                .header(header::AUTHORIZATION, format!("Bearer {pat}"))
                .header("content-type", "application/json")
                .body(Body::from(cipher_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn pat_cannot_manage_other_pats_without_account_admin() {
    let app = test_app().await;
    let jwt = login_jwt(&app, "carol@example.com").await;
    let (_id, pat) = create_pat(&app, &jwt, "vault-only", "vault:read,vault:write").await;

    // Listing tokens via the PAT itself should be 403 (lacks account:admin).
    let resp = app
        .oneshot(
            Request::get("/api/v1/account/tokens")
                .header(header::AUTHORIZATION, format!("Bearer {pat}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn revoked_pat_returns_401() {
    let app = test_app().await;
    let jwt = login_jwt(&app, "dave@example.com").await;
    let (id, pat) = create_pat(&app, &jwt, "throwaway", "vault:read").await;

    // Revoke via the JWT (which has account:admin implicitly).
    let resp = app
        .clone()
        .oneshot(
            Request::delete(format!("/api/v1/account/tokens/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // PAT is now rejected.
    let resp = app
        .oneshot(
            Request::get("/api/v1/sync")
                .header(header::AUTHORIZATION, format!("Bearer {pat}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_pat_returns_401() {
    let app = test_app().await;
    let resp = app
        .oneshot(
            Request::get("/api/v1/sync")
                .header(
                    header::AUTHORIZATION,
                    "Bearer pmgr_pat_00000000-0000-7000-8000-000000000000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_scope_in_create_returns_400() {
    let app = test_app().await;
    let jwt = login_jwt(&app, "eve@example.com").await;
    let body = json!({"name": "x", "scopes": "vault:read,bogus"});
    let resp = app
        .oneshot(
            Request::post("/api/v1/account/tokens")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
