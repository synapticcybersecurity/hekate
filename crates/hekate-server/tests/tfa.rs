//! M2.22 — TOTP 2FA + recovery codes integration tests.
//!
//! Covers: enroll round-trip, wrong-code rejected at confirm, login
//! TOTP, login recovery, recovery single-use, totp replay rejected,
//! invalid challenge token rejected, disable, regenerate.

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use hekate_server::{bootstrap, build_router, config::Config};
use serde_json::{json, Value};
use totp_rs::{Algorithm, Secret, TOTP};
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
}

async fn login_password(app: &Router, email: &str) -> Value {
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
    let status = r.status();
    let mut json = body_json(r).await;
    assert!(
        status == StatusCode::OK || status == StatusCode::UNAUTHORIZED,
        "unexpected status {status}: {json}"
    );
    if let Some(obj) = json.as_object_mut() {
        obj.insert(
            "status_code_for_test_marker".to_string(),
            json!(status.as_u16()),
        );
    }
    json
}

async fn login_with_2fa(
    app: &Router,
    email: &str,
    two_factor_token: &str,
    provider: &str,
    value: &str,
) -> (StatusCode, Value) {
    let body = format!(
        "grant_type=password&username={email}&password={}&two_factor_token={token}&two_factor_provider={p}&two_factor_value={v}",
        b64(&MPH),
        token = urlencode(two_factor_token),
        p = provider,
        v = urlencode(value),
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
    let status = r.status();
    (status, body_json(r).await)
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

async fn enroll_2fa(app: &Router, email: &str) -> (Vec<String>, String) {
    let bearer = login_password(app, email).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    // setup
    let body = json!({
        "master_password_hash": b64(&MPH),
        "account_label": email,
    });
    let r = app
        .clone()
        .oneshot(
            Request::post("/api/v1/account/2fa/totp/setup")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let setup = body_json(r).await;
    let secret_b32 = setup["secret_b32"].as_str().unwrap().to_string();
    let recovery_codes: Vec<String> = setup["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(recovery_codes.len(), 10);

    // confirm
    let totp = build_totp(&secret_b32);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let code = totp.generate(now);
    let body = json!({"totp_code": code});
    let r = app
        .clone()
        .oneshot(
            Request::post("/api/v1/account/2fa/totp/confirm")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let confirm = body_json(r).await;
    assert_eq!(confirm["recovery_codes_count"].as_u64().unwrap(), 10);

    (recovery_codes, secret_b32)
}

fn build_totp(secret_b32: &str) -> TOTP {
    let bytes = Secret::Encoded(secret_b32.to_string()).to_bytes().unwrap();
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        bytes,
        Some("hekate".to_string()),
        "hekate".to_string(),
    )
    .unwrap()
}

#[tokio::test]
async fn enroll_then_login_with_totp() {
    let app = test_app().await;
    register(&app, "alice@example.com").await;
    let (_codes, secret_b32) = enroll_2fa(&app, "alice@example.com").await;

    // First login leg → 401 + challenge.
    let v = login_password(&app, "alice@example.com").await;
    assert_eq!(v["status_code_for_test_marker"].as_u64().unwrap(), 401);
    assert_eq!(v["error"].as_str().unwrap(), "two_factor_required");
    let token = v["two_factor_token"].as_str().unwrap().to_string();
    let providers: Vec<String> = v["two_factor_providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    assert!(providers.contains(&"totp".to_string()));
    assert!(providers.contains(&"recovery".to_string()));

    // Second leg with a valid TOTP code → 200.
    let totp = build_totp(&secret_b32);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let code = totp.generate(now);
    let (s, body) = login_with_2fa(&app, "alice@example.com", &token, "totp", &code).await;
    assert_eq!(s, StatusCode::OK, "body: {body}");
    assert!(body["access_token"].as_str().is_some());
    assert!(body["refresh_token"].as_str().is_some());
}

#[tokio::test]
async fn login_with_recovery_code_consumes_it() {
    let app = test_app().await;
    register(&app, "bob@example.com").await;
    let (codes, _secret) = enroll_2fa(&app, "bob@example.com").await;

    let v = login_password(&app, "bob@example.com").await;
    let token = v["two_factor_token"].as_str().unwrap().to_string();

    let code = &codes[0];
    let (s, _) = login_with_2fa(&app, "bob@example.com", &token, "recovery", code).await;
    assert_eq!(s, StatusCode::OK);

    // Replay the same recovery code on a fresh challenge → must fail.
    let v2 = login_password(&app, "bob@example.com").await;
    let token2 = v2["two_factor_token"].as_str().unwrap().to_string();
    let (s2, body2) = login_with_2fa(&app, "bob@example.com", &token2, "recovery", code).await;
    assert_eq!(s2, StatusCode::UNAUTHORIZED, "body: {body2}");

    // Another, fresh code on the same challenge → succeeds.
    let (s3, _) = login_with_2fa(&app, "bob@example.com", &token2, "recovery", &codes[1]).await;
    assert_eq!(s3, StatusCode::OK);
}

#[tokio::test]
async fn confirm_rejects_wrong_totp_code() {
    let app = test_app().await;
    register(&app, "carol@example.com").await;
    let bearer = login_password(&app, "carol@example.com").await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let body = json!({
        "master_password_hash": b64(&MPH),
        "account_label": "carol@example.com",
    });
    let r = app
        .clone()
        .oneshot(
            Request::post("/api/v1/account/2fa/totp/setup")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // Send a clearly-wrong code.
    let body = json!({"totp_code": "000000"});
    let r = app
        .clone()
        .oneshot(
            Request::post("/api/v1/account/2fa/totp/confirm")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // 2FA must NOT be active; second login leg has no challenge.
    let v = login_password(&app, "carol@example.com").await;
    assert_eq!(
        v["status_code_for_test_marker"].as_u64().unwrap(),
        200,
        "should issue tokens directly when enrollment didn't commit: {v}"
    );
}

#[tokio::test]
async fn invalid_challenge_token_rejected() {
    let app = test_app().await;
    register(&app, "dan@example.com").await;
    let (_codes, secret_b32) = enroll_2fa(&app, "dan@example.com").await;

    // Fabricate a garbage two_factor_token; the server must refuse.
    let totp = build_totp(&secret_b32);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let code = totp.generate(now);
    let (s, body) = login_with_2fa(&app, "dan@example.com", "not.a.real.jwt", "totp", &code).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "body: {body}");
}

#[tokio::test]
async fn totp_replay_inside_window_rejected() {
    let app = test_app().await;
    register(&app, "eve@example.com").await;
    let (_codes, secret_b32) = enroll_2fa(&app, "eve@example.com").await;

    // First login with TOTP — succeeds.
    let v = login_password(&app, "eve@example.com").await;
    let token = v["two_factor_token"].as_str().unwrap().to_string();
    let totp = build_totp(&secret_b32);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let code = totp.generate(now);
    let (s1, _) = login_with_2fa(&app, "eve@example.com", &token, "totp", &code).await;
    assert_eq!(s1, StatusCode::OK);

    // Re-use the exact same code on a fresh challenge — must fail.
    let v2 = login_password(&app, "eve@example.com").await;
    let token2 = v2["two_factor_token"].as_str().unwrap().to_string();
    let (s2, body2) = login_with_2fa(&app, "eve@example.com", &token2, "totp", &code).await;
    assert_eq!(s2, StatusCode::UNAUTHORIZED, "body: {body2}");
}

#[tokio::test]
async fn disable_drops_2fa_and_codes() {
    let app = test_app().await;
    register(&app, "frank@example.com").await;
    let (_codes, _secret) = enroll_2fa(&app, "frank@example.com").await;

    // The confirm rotated the security_stamp + revoked refresh tokens,
    // so we need to re-login (with TOTP) to get a fresh access token.
    let v = login_password(&app, "frank@example.com").await;
    let token = v["two_factor_token"].as_str().unwrap().to_string();
    let (s_login, body_login) = login_with_2fa(
        &app,
        "frank@example.com",
        &token,
        "recovery",
        // Use a recovery code so we don't have to round-trip TOTP.
        &_codes[0],
    )
    .await;
    assert_eq!(s_login, StatusCode::OK, "body: {body_login}");
    let bearer = body_login["access_token"].as_str().unwrap().to_string();

    let body = json!({"master_password_hash": b64(&MPH)});
    let r = app
        .clone()
        .oneshot(
            Request::post("/api/v1/account/2fa/totp/disable")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);

    // Login should now skip the 2FA leg entirely.
    let v = login_password(&app, "frank@example.com").await;
    assert_eq!(v["status_code_for_test_marker"].as_u64().unwrap(), 200);
}

#[tokio::test]
async fn regenerate_invalidates_old_codes() {
    let app = test_app().await;
    register(&app, "gina@example.com").await;
    let (codes, _secret) = enroll_2fa(&app, "gina@example.com").await;

    // Re-login (with a recovery code) so we have a valid bearer.
    let v = login_password(&app, "gina@example.com").await;
    let token = v["two_factor_token"].as_str().unwrap().to_string();
    let (s_login, body_login) =
        login_with_2fa(&app, "gina@example.com", &token, "recovery", &codes[0]).await;
    assert_eq!(s_login, StatusCode::OK);
    let bearer = body_login["access_token"].as_str().unwrap().to_string();

    let body = json!({"master_password_hash": b64(&MPH)});
    let r = app
        .clone()
        .oneshot(
            Request::post("/api/v1/account/2fa/recovery-codes/regenerate")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let regen = body_json(r).await;
    let new_codes: Vec<String> = regen["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(new_codes.len(), 10);

    // An old (unused) code should NOT work anymore.
    let v = login_password(&app, "gina@example.com").await;
    let token = v["two_factor_token"].as_str().unwrap().to_string();
    let (s, _) = login_with_2fa(&app, "gina@example.com", &token, "recovery", &codes[2]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // A new code DOES work.
    let v = login_password(&app, "gina@example.com").await;
    let token = v["two_factor_token"].as_str().unwrap().to_string();
    let (s, _) = login_with_2fa(&app, "gina@example.com", &token, "recovery", &new_codes[0]).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn status_endpoint_reports_remaining() {
    let app = test_app().await;
    register(&app, "hank@example.com").await;
    let (codes, _secret) = enroll_2fa(&app, "hank@example.com").await;

    // Re-login with recovery to grab a fresh bearer.
    let v = login_password(&app, "hank@example.com").await;
    let token = v["two_factor_token"].as_str().unwrap().to_string();
    let (_, body) = login_with_2fa(&app, "hank@example.com", &token, "recovery", &codes[0]).await;
    let bearer = body["access_token"].as_str().unwrap().to_string();

    // 9 should remain (one was just consumed).
    let r = app
        .clone()
        .oneshot(
            Request::get("/api/v1/account/2fa/status")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let s = body_json(r).await;
    assert!(s["enabled"].as_bool().unwrap());
    assert_eq!(s["recovery_codes_remaining"].as_u64().unwrap(), 9);
}

#[tokio::test]
async fn refresh_grant_does_not_require_2fa() {
    // Refresh grants are not gated on the second factor — the second
    // factor is bound at the password leg only. Once issued, the
    // refresh chain can rotate without re-prompting.
    let app = test_app().await;
    register(&app, "ivan@example.com").await;
    let (codes, _secret) = enroll_2fa(&app, "ivan@example.com").await;

    let v = login_password(&app, "ivan@example.com").await;
    let token = v["two_factor_token"].as_str().unwrap().to_string();
    let (_, body) = login_with_2fa(&app, "ivan@example.com", &token, "recovery", &codes[0]).await;
    let refresh = body["refresh_token"].as_str().unwrap().to_string();

    let body = format!("grant_type=refresh_token&refresh_token={refresh}");
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
}
