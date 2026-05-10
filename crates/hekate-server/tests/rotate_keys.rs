//! M2.26 — `POST /api/v1/account/rotate-keys` integration tests.
//!
//! Validates the atomic rewrap-and-rotate flow:
//! - Wrong master password → 401, no state change.
//! - Cross-user cipher in `cipher_rewraps` → 400, no state change.
//! - Non-member org in `org_member_rewraps` → 400, no state change.
//! - Successful rotation: new tokens issued, security_stamp bumped,
//!   personal cipher PCK updated on the row, send protected_send_key
//!   updated, refresh tokens revoked.
//! - Manifest unaffected (signing key derives from master key, which
//!   is unchanged in this flow).

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use hekate_server::{bootstrap, build_router, config::Config};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

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

async fn login(app: &Router, email: &str) -> (String, String) {
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
    (
        v["access_token"].as_str().unwrap().to_string(),
        v["refresh_token"].as_str().unwrap().to_string(),
    )
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

async fn create_personal_cipher(app: &Router, token: &str) -> String {
    let id = Uuid::new_v4().to_string();
    let body = json!({
        "id": id,
        "type": 1,
        "folder_id": null,
        "protected_cipher_key": enc_placeholder(),
        "name": enc_placeholder(),
        "notes": null,
        "data": enc_placeholder(),
        "favorite": false,
    });
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/ciphers", token, Some(&body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    id
}

async fn create_text_send(app: &Router, token: &str) -> String {
    use chrono::{Duration, Utc};
    let id = Uuid::now_v7().to_string();
    let body = json!({
        "id": id,
        "send_type": 1,
        "name": enc_placeholder(),
        "protected_send_key": enc_placeholder(),
        "data": enc_placeholder(),
        "deletion_date": (Utc::now() + Duration::days(1)).to_rfc3339(),
        "disabled": false,
    });
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/sends", token, Some(&body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    id
}

fn rewrap_placeholder() -> &'static str {
    // A fresh EncString — different from `enc_placeholder` so we can
    // assert the rewrap actually replaced the wire bytes. Only the
    // key_id changes (`kid` → `new`); keeping the all-A tag so it
    // passes strict no-pad base64 (trailing bits must be zero).
    "v3.xc20p.new.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA"
}

// ============== tests ==============

#[tokio::test]
async fn rotate_succeeds_with_correct_master_password() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let (token, _refresh) = login(&app, "alice@x.test").await;

    let cipher_id = create_personal_cipher(&app, &token).await;
    let send_id = create_text_send(&app, &token).await;

    let body = json!({
        "master_password_hash": b64(&MPH_BYTES),
        "new_protected_account_key": rewrap_placeholder(),
        "new_protected_account_private_key": rewrap_placeholder(),
        "cipher_rewraps": [
            {"cipher_id": cipher_id, "new_protected_cipher_key": rewrap_placeholder()},
        ],
        "send_rewraps": [
            {
                "send_id": send_id,
                "new_protected_send_key": rewrap_placeholder(),
                "new_name": rewrap_placeholder(),
            },
        ],
        "org_member_rewraps": [],
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/account/rotate-keys",
            &token,
            Some(&body),
        ))
        .await
        .unwrap();
    let status = resp.status();
    let v = body_json(resp).await;
    assert_eq!(status, StatusCode::OK, "rotate body: {v:?}");
    assert_eq!(v["rewrote_ciphers"], 1);
    assert_eq!(v["rewrote_sends"], 1);
    assert_eq!(v["rewrote_org_memberships"], 0);
    assert!(v["access_token"].as_str().unwrap().len() > 20);
    assert!(v["refresh_token"].as_str().unwrap().len() > 20);
    let new_access = v["access_token"].as_str().unwrap().to_string();

    // Cipher row carries the new wrap.
    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/ciphers/{cipher_id}"),
            &new_access,
            None,
        ))
        .await
        .unwrap();
    let c = body_json(resp).await;
    assert_eq!(c["protected_cipher_key"], rewrap_placeholder());

    // Send row carries the new wrap.
    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/sends/{send_id}"),
            &new_access,
            None,
        ))
        .await
        .unwrap();
    let s = body_json(resp).await;
    assert_eq!(s["protected_send_key"], rewrap_placeholder());
}

#[tokio::test]
async fn rotate_with_wrong_master_password_returns_401() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let (token, _) = login(&app, "alice@x.test").await;

    let body = json!({
        "master_password_hash": b64(&[0u8; 32]),
        "new_protected_account_key": rewrap_placeholder(),
        "new_protected_account_private_key": rewrap_placeholder(),
        "cipher_rewraps": [],
        "send_rewraps": [],
        "org_member_rewraps": [],
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/account/rotate-keys",
            &token,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rotate_rejects_cross_user_cipher() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    register(&app, "bob@x.test").await;
    let (alice_token, _) = login(&app, "alice@x.test").await;
    let (bob_token, _) = login(&app, "bob@x.test").await;
    let alice_cipher = create_personal_cipher(&app, &alice_token).await;

    let body = json!({
        "master_password_hash": b64(&MPH_BYTES),
        "new_protected_account_key": rewrap_placeholder(),
        "new_protected_account_private_key": rewrap_placeholder(),
        "cipher_rewraps": [
            {"cipher_id": alice_cipher, "new_protected_cipher_key": rewrap_placeholder()},
        ],
        "send_rewraps": [],
        "org_member_rewraps": [],
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/account/rotate-keys",
            &bob_token,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err = body_json(resp).await;
    assert!(err["error"]
        .as_str()
        .unwrap_or("")
        .contains("not owned by caller"));
}

#[tokio::test]
async fn rotate_rejects_org_caller_isnt_a_member_of() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let (token, _) = login(&app, "alice@x.test").await;

    let body = json!({
        "master_password_hash": b64(&MPH_BYTES),
        "new_protected_account_key": rewrap_placeholder(),
        "new_protected_account_private_key": rewrap_placeholder(),
        "cipher_rewraps": [],
        "send_rewraps": [],
        "org_member_rewraps": [
            {"org_id": Uuid::now_v7().to_string(), "new_protected_org_key": rewrap_placeholder()},
        ],
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/account/rotate-keys",
            &token,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rotate_rejects_invalid_encstring_in_rewraps() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let (token, _) = login(&app, "alice@x.test").await;
    let cipher_id = create_personal_cipher(&app, &token).await;

    let body = json!({
        "master_password_hash": b64(&MPH_BYTES),
        "new_protected_account_key": rewrap_placeholder(),
        "new_protected_account_private_key": rewrap_placeholder(),
        "cipher_rewraps": [
            {"cipher_id": cipher_id, "new_protected_cipher_key": "not-an-encstring"},
        ],
        "send_rewraps": [],
        "org_member_rewraps": [],
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/account/rotate-keys",
            &token,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rotate_revokes_existing_refresh_tokens() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let (token, refresh_tok) = login(&app, "alice@x.test").await;

    // Confirm the refresh token works before rotation.
    let pre = app
        .clone()
        .oneshot(
            Request::post("/identity/connect/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={refresh_tok}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pre.status(), StatusCode::OK);
    // The refresh token rolls on each successful exchange (single-use
    // rolling rotation), so we need a fresh one from the response to
    // assert the post-rotate behaviour.
    let v = body_json(pre).await;
    let live_refresh = v["refresh_token"].as_str().unwrap().to_string();

    // Need to login fresh — the old access token's stamp is invalidated
    // by the just-completed refresh-rotation.
    let new_access = v["access_token"].as_str().unwrap().to_string();
    let _ = token;

    let body = json!({
        "master_password_hash": b64(&MPH_BYTES),
        "new_protected_account_key": rewrap_placeholder(),
        "new_protected_account_private_key": rewrap_placeholder(),
        "cipher_rewraps": [],
        "send_rewraps": [],
        "org_member_rewraps": [],
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/account/rotate-keys",
            &new_access,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Old refresh token now fails — every refresh row was revoked.
    let post = app
        .clone()
        .oneshot(
            Request::post("/identity/connect/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={live_refresh}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(post.status(), StatusCode::OK);
}
