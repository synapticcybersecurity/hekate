//! M2.23a — WebAuthn / FIDO2 second factor integration tests.
//!
//! Uses webauthn-authenticator-rs SoftPasskey as a software
//! authenticator that signs whatever the server hands it. This tests
//! the wire shape + the `webauthn-rs` integration end-to-end with the
//! real router and a fresh in-memory SQLite per test.

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use hekate_server::{bootstrap, build_router, config::Config};
use serde_json::{json, Value};
use tower::ServiceExt;
use url::Url;
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

const MPH: [u8; 32] = [42u8; 32];
const RP_ID: &str = "localhost";
const RP_ORIGIN: &str = "http://localhost";

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
        webauthn_rp_id: RP_ID.into(),
        webauthn_rp_origin: RP_ORIGIN.into(),
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

async fn password_login(app: &Router, email: &str) -> Value {
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
    if let Some(obj) = json.as_object_mut() {
        obj.insert(
            "status_code_for_test_marker".to_string(),
            json!(status.as_u16()),
        );
    }
    json
}

async fn enroll_webauthn(
    app: &Router,
    bearer: &str,
    name: &str,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
) -> String {
    // /register/start
    let body = json!({
        "master_password_hash": b64(&MPH),
        "name": name,
    });
    let r = app
        .clone()
        .oneshot(
            Request::post("/api/v1/account/2fa/webauthn/register/start")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let setup = body_json(r).await;
    let ccr: CreationChallengeResponse =
        serde_json::from_value(setup["creation_options"].clone()).unwrap();

    let credential = authenticator
        .do_registration(Url::parse(RP_ORIGIN).unwrap(), ccr)
        .expect("SoftPasskey registration");

    // /register/finish
    let body = json!({"credential": credential});
    let r = app
        .clone()
        .oneshot(
            Request::post("/api/v1/account/2fa/webauthn/register/finish")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "finish body: {:?}",
        body_json(r).await
    );

    // re-fetch the list to grab the row id assigned server-side
    list_credentials(app, bearer).await[0]["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn list_credentials(app: &Router, bearer: &str) -> Vec<Value> {
    let r = app
        .clone()
        .oneshot(
            Request::get("/api/v1/account/2fa/webauthn/credentials")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    body_json(r).await.as_array().unwrap().clone()
}

async fn login_with_webauthn(
    app: &Router,
    email: &str,
    two_factor_token: &str,
    assertion: Value,
) -> (StatusCode, Value) {
    // Send `two_factor_value` as the JSON-encoded assertion. The
    // identity grant deserializes it back via serde_json::from_str.
    let assertion_str = assertion.to_string();
    let body = format!(
        "grant_type=password&username={email}&password={pw}&two_factor_token={tok}&two_factor_provider=webauthn&two_factor_value={val}",
        pw = b64(&MPH),
        tok = urlencode(two_factor_token),
        val = urlencode(&assertion_str),
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

#[tokio::test]
async fn enroll_then_login_with_webauthn() {
    let app = test_app().await;
    register(&app, "alice@example.com").await;
    let bearer = password_login(&app, "alice@example.com").await["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let mut auth = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let _id = enroll_webauthn(&app, &bearer, "YubiKey 5C", &mut auth).await;

    // Login leg 1 → 401 + webauthn_challenge.
    let v = password_login(&app, "alice@example.com").await;
    assert_eq!(v["status_code_for_test_marker"].as_u64().unwrap(), 401);
    assert_eq!(v["error"].as_str().unwrap(), "two_factor_required");
    let providers: Vec<String> = v["two_factor_providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    assert!(providers.contains(&"webauthn".to_string()));
    let token = v["two_factor_token"].as_str().unwrap().to_string();
    let webauthn_challenge: RequestChallengeResponse =
        serde_json::from_value(v["webauthn_challenge"].clone()).unwrap();

    let assertion = auth
        .do_authentication(Url::parse(RP_ORIGIN).unwrap(), webauthn_challenge)
        .expect("SoftPasskey authentication");
    let assertion_v = serde_json::to_value(assertion).unwrap();

    let (s, body) = login_with_webauthn(&app, "alice@example.com", &token, assertion_v).await;
    assert_eq!(s, StatusCode::OK, "login body: {body}");
    assert!(body["access_token"].as_str().is_some());
}

#[tokio::test]
async fn webauthn_replay_rejected() {
    let app = test_app().await;
    register(&app, "bob@example.com").await;
    let bearer = password_login(&app, "bob@example.com").await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let mut auth = WebauthnAuthenticator::new(SoftPasskey::new(true));
    enroll_webauthn(&app, &bearer, "Test key", &mut auth).await;

    let v = password_login(&app, "bob@example.com").await;
    let token = v["two_factor_token"].as_str().unwrap().to_string();
    let challenge: RequestChallengeResponse =
        serde_json::from_value(v["webauthn_challenge"].clone()).unwrap();
    let assertion = auth
        .do_authentication(Url::parse(RP_ORIGIN).unwrap(), challenge)
        .unwrap();
    let assertion_v = serde_json::to_value(assertion).unwrap();

    // First use succeeds.
    let (s1, _) = login_with_webauthn(&app, "bob@example.com", &token, assertion_v.clone()).await;
    assert_eq!(s1, StatusCode::OK);

    // Re-use of the same assertion against a fresh challenge fails:
    // the second password_login burns the prior pending challenge state
    // and issues a new one, so the assertion's signed challenge no
    // longer matches.
    let v2 = password_login(&app, "bob@example.com").await;
    let token2 = v2["two_factor_token"].as_str().unwrap().to_string();
    let (s2, body2) = login_with_webauthn(&app, "bob@example.com", &token2, assertion_v).await;
    assert_eq!(s2, StatusCode::UNAUTHORIZED, "replay body: {body2}");
}

#[tokio::test]
async fn list_delete_rename_round_trip() {
    let app = test_app().await;
    register(&app, "carol@example.com").await;
    let bearer = password_login(&app, "carol@example.com").await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let mut auth = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let id = enroll_webauthn(&app, &bearer, "Original Name", &mut auth).await;

    // list
    let creds = list_credentials(&app, &bearer).await;
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0]["name"].as_str().unwrap(), "Original Name");

    // rename
    let r = app
        .clone()
        .oneshot(
            Request::patch(format!("/api/v1/account/2fa/webauthn/credentials/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"name": "MacBook TouchID"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let creds = list_credentials(&app, &bearer).await;
    assert_eq!(creds[0]["name"].as_str().unwrap(), "MacBook TouchID");

    // delete
    let r = app
        .clone()
        .oneshot(
            Request::delete(format!("/api/v1/account/2fa/webauthn/credentials/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let creds = list_credentials(&app, &bearer).await;
    assert!(creds.is_empty());

    // login should now skip the 2FA leg entirely.
    let v = password_login(&app, "carol@example.com").await;
    assert_eq!(v["status_code_for_test_marker"].as_u64().unwrap(), 200);
}

#[tokio::test]
async fn rename_rejects_other_users_credential() {
    let app = test_app().await;
    register(&app, "dan@example.com").await;
    register(&app, "eve@example.com").await;
    let dan_bearer = password_login(&app, "dan@example.com").await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let eve_bearer = password_login(&app, "eve@example.com").await["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let mut auth = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let dan_cred = enroll_webauthn(&app, &dan_bearer, "Dan's key", &mut auth).await;

    // Eve tries to rename Dan's credential — must 404.
    let r = app
        .clone()
        .oneshot(
            Request::patch(format!(
                "/api/v1/account/2fa/webauthn/credentials/{dan_cred}"
            ))
            .header(header::AUTHORIZATION, format!("Bearer {eve_bearer}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({"name": "stolen"}).to_string()))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn refresh_grant_does_not_require_webauthn() {
    let app = test_app().await;
    register(&app, "frank@example.com").await;
    let bearer = password_login(&app, "frank@example.com").await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let mut auth = WebauthnAuthenticator::new(SoftPasskey::new(true));
    enroll_webauthn(&app, &bearer, "Test key", &mut auth).await;

    // Initial login leg 1 → challenge; leg 2 → tokens.
    let v = password_login(&app, "frank@example.com").await;
    let token = v["two_factor_token"].as_str().unwrap().to_string();
    let challenge: RequestChallengeResponse =
        serde_json::from_value(v["webauthn_challenge"].clone()).unwrap();
    let assertion = auth
        .do_authentication(Url::parse(RP_ORIGIN).unwrap(), challenge)
        .unwrap();
    let assertion_v = serde_json::to_value(assertion).unwrap();
    let (_, body) = login_with_webauthn(&app, "frank@example.com", &token, assertion_v).await;
    let refresh = body["refresh_token"].as_str().unwrap().to_string();

    let r = app
        .clone()
        .oneshot(
            Request::post("/identity/connect/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={refresh}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}
