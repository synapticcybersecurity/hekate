//! M2.5 — Service-account lifecycle integration tests.
//!
//! Covers: org-owner-only management, token issue/list/revoke,
//! disable cascades to verify, delete cascades to tokens, scope
//! enforcement, cross-principal isolation (SAT can't substitute for
//! a user JWT and vice versa).

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use hekate_core::{
    org_roster::{OrgRoster, OrgRosterEntry, NO_PARENT_HASH},
    signcrypt::sign_pubkey_bundle,
};
use hekate_server::{bootstrap, build_router, config::Config};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

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

async fn register(app: &Router, email: &str, seed: u8) -> (String, SigningKey) {
    let user_id = Uuid::now_v7().to_string();
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let signing_pk = sk.verifying_key().to_bytes();
    let x25519_pk = [seed.wrapping_add(1); 32];
    let sig = sign_pubkey_bundle(&sk, &user_id, &signing_pk, &x25519_pk);
    let body = json!({
        "email": email,
        "kdf_params": {"alg": "argon2id", "m_kib": 64, "t": 1, "p": 1},
        "kdf_salt": b64(&[7u8; 16]),
        "kdf_params_mac": b64(&[0xa5u8; 32]),
        "master_password_hash": b64(&MPH),
        "protected_account_key": enc(),
        "account_public_key": b64(&x25519_pk),
        "protected_account_private_key": enc(),
        "account_signing_pubkey": b64(&signing_pk),
        "user_id": user_id,
        "account_pubkey_bundle_sig": b64(&sig),
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
    (user_id, sk)
}

async fn login(app: &Router, email: &str) -> String {
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

fn org_bundle_canonical(
    org_id: &str,
    name: &str,
    signing_pubkey: &[u8; 32],
    owner_user_id: &str,
) -> Vec<u8> {
    const DST: &[u8] = b"pmgr-org-bundle-v1\x00";
    let id = org_id.as_bytes();
    let n = name.as_bytes();
    let owner = owner_user_id.as_bytes();
    let mut out = Vec::with_capacity(DST.len() + 12 + id.len() + n.len() + 32 + owner.len());
    out.extend_from_slice(DST);
    out.extend_from_slice(&(id.len() as u32).to_le_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(&(n.len() as u32).to_le_bytes());
    out.extend_from_slice(n);
    out.extend_from_slice(signing_pubkey);
    out.extend_from_slice(&(owner.len() as u32).to_le_bytes());
    out.extend_from_slice(owner);
    out
}

async fn create_org(
    app: &Router,
    owner_user_id: &str,
    owner_signing_key: &SigningKey,
    token: &str,
    name: &str,
) -> String {
    let org_id = Uuid::now_v7().to_string();
    let org_sym_key_id = Uuid::now_v7().to_string();
    let org_signing_key = SigningKey::from_bytes(&[0xa5u8; 32]);
    let org_signing_pk = org_signing_key.verifying_key().to_bytes();
    let bundle_canonical = org_bundle_canonical(&org_id, name, &org_signing_pk, owner_user_id);
    let bundle_sig = owner_signing_key.sign(&bundle_canonical);
    let roster = OrgRoster {
        org_id: org_id.clone(),
        version: 1,
        parent_canonical_sha256: NO_PARENT_HASH,
        timestamp: "2026-05-03T00:00:00+00:00".into(),
        entries: vec![OrgRosterEntry {
            user_id: owner_user_id.to_string(),
            role: "owner".into(),
        }],
        org_sym_key_id: org_sym_key_id.clone(),
    };
    let signed = roster.sign(&org_signing_key);

    let body = json!({
        "id": org_id,
        "name": name,
        "signing_pubkey": b64(&org_signing_pk),
        "bundle_sig": b64(&bundle_sig.to_bytes()),
        "protected_signing_seed": enc(),
        "org_sym_key_id": org_sym_key_id,
        "owner_protected_org_key": enc(),
        "roster": {
            "canonical_b64": signed.canonical_b64,
            "signature_b64": signed.signature_b64,
        },
    });
    let r = app
        .clone()
        .oneshot(
            Request::post("/api/v1/orgs")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED, "{}", body_json(r).await);
    org_id
}

async fn create_sa(app: &Router, token: &str, org_id: &str, name: &str) -> Value {
    let body = json!({"name": name});
    let r = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/orgs/{org_id}/service-accounts"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    body_json(r).await
}

async fn create_token(
    app: &Router,
    bearer: &str,
    org_id: &str,
    sa_id: &str,
    name: &str,
    scopes: &str,
) -> Value {
    let body = json!({"name": name, "scopes": scopes});
    let r = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/v1/orgs/{org_id}/service-accounts/{sa_id}/tokens"
            ))
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED, "{}", body_json(r).await);
    body_json(r).await
}

#[tokio::test]
async fn owner_can_create_sa_and_token_authenticates() {
    let app = test_app().await;
    let (uid, sk) = register(&app, "alice@x.test", 1).await;
    let bearer = login(&app, "alice@x.test").await;
    let org_id = create_org(&app, &uid, &sk, &bearer, "Acme").await;

    let sa = create_sa(&app, &bearer, &org_id, "ci-bot").await;
    let sa_id = sa["id"].as_str().unwrap().to_string();

    let tok = create_token(&app, &bearer, &org_id, &sa_id, "ci-token", "org:read").await;
    let wire = tok["token"].as_str().unwrap().to_string();
    assert!(wire.starts_with("pmgr_sat_"), "wire format: {wire}");

    // /service-accounts/me with the SA token returns identity.
    let r = app
        .clone()
        .oneshot(
            Request::get("/api/v1/service-accounts/me")
                .header(header::AUTHORIZATION, format!("Bearer {wire}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let me = body_json(r).await;
    assert_eq!(me["service_account_id"].as_str().unwrap(), sa_id);
    assert_eq!(me["org_id"].as_str().unwrap(), org_id);
    assert_eq!(me["scopes"].as_str().unwrap(), "org:read");
}

#[tokio::test]
async fn non_owner_cannot_create_sa() {
    let app = test_app().await;
    let (uid, sk) = register(&app, "alice@x.test", 1).await;
    let alice_bearer = login(&app, "alice@x.test").await;
    let org_id = create_org(&app, &uid, &sk, &alice_bearer, "Acme").await;

    let (_bob_id, _bob_sk) = register(&app, "bob@x.test", 2).await;
    let bob_bearer = login(&app, "bob@x.test").await;

    let body = json!({"name": "evil"});
    let r = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/orgs/{org_id}/service-accounts"))
                .header(header::AUTHORIZATION, format!("Bearer {bob_bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn sa_token_refused_at_user_endpoints() {
    let app = test_app().await;
    let (uid, sk) = register(&app, "alice@x.test", 1).await;
    let bearer = login(&app, "alice@x.test").await;
    let org_id = create_org(&app, &uid, &sk, &bearer, "Acme").await;
    let sa = create_sa(&app, &bearer, &org_id, "bot").await;
    let tok = create_token(
        &app,
        &bearer,
        &org_id,
        sa["id"].as_str().unwrap(),
        "t",
        "org:read",
    )
    .await;
    let wire = tok["token"].as_str().unwrap().to_string();

    // /sync is a user-scoped endpoint — must refuse SA tokens.
    let r = app
        .clone()
        .oneshot(
            Request::get("/api/v1/sync")
                .header(header::AUTHORIZATION, format!("Bearer {wire}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn user_jwt_refused_at_sa_me_endpoint() {
    let app = test_app().await;
    let (_uid, _sk) = register(&app, "alice@x.test", 1).await;
    let bearer = login(&app, "alice@x.test").await;

    // /service-accounts/me requires a SAT, not a user JWT.
    let r = app
        .clone()
        .oneshot(
            Request::get("/api/v1/service-accounts/me")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn revoked_token_fails() {
    let app = test_app().await;
    let (uid, sk) = register(&app, "alice@x.test", 1).await;
    let bearer = login(&app, "alice@x.test").await;
    let org_id = create_org(&app, &uid, &sk, &bearer, "Acme").await;
    let sa = create_sa(&app, &bearer, &org_id, "bot").await;
    let sa_id = sa["id"].as_str().unwrap();
    let tok = create_token(&app, &bearer, &org_id, sa_id, "t", "org:read").await;
    let wire = tok["token"].as_str().unwrap().to_string();
    let token_id = tok["id"].as_str().unwrap();

    // Revoke.
    let r = app
        .clone()
        .oneshot(
            Request::delete(format!(
                "/api/v1/orgs/{org_id}/service-accounts/{sa_id}/tokens/{token_id}"
            ))
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);

    // Token no longer authenticates.
    let r = app
        .clone()
        .oneshot(
            Request::get("/api/v1/service-accounts/me")
                .header(header::AUTHORIZATION, format!("Bearer {wire}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn disabled_sa_existing_tokens_fail_and_new_tokens_refused() {
    let app = test_app().await;
    let (uid, sk) = register(&app, "alice@x.test", 1).await;
    let bearer = login(&app, "alice@x.test").await;
    let org_id = create_org(&app, &uid, &sk, &bearer, "Acme").await;
    let sa = create_sa(&app, &bearer, &org_id, "bot").await;
    let sa_id = sa["id"].as_str().unwrap();
    let tok = create_token(&app, &bearer, &org_id, sa_id, "t", "org:read").await;
    let wire = tok["token"].as_str().unwrap().to_string();

    // Disable.
    let r = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/v1/orgs/{org_id}/service-accounts/{sa_id}/disable"
            ))
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);

    // Existing token now fails.
    let r = app
        .clone()
        .oneshot(
            Request::get("/api/v1/service-accounts/me")
                .header(header::AUTHORIZATION, format!("Bearer {wire}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    // New token refused.
    let body = json!({"name": "no", "scopes": "org:read"});
    let r = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/v1/orgs/{org_id}/service-accounts/{sa_id}/tokens"
            ))
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_cascades_tokens() {
    let app = test_app().await;
    let (uid, sk) = register(&app, "alice@x.test", 1).await;
    let bearer = login(&app, "alice@x.test").await;
    let org_id = create_org(&app, &uid, &sk, &bearer, "Acme").await;
    let sa = create_sa(&app, &bearer, &org_id, "bot").await;
    let sa_id = sa["id"].as_str().unwrap();
    let tok = create_token(&app, &bearer, &org_id, sa_id, "t", "org:read").await;
    let wire = tok["token"].as_str().unwrap().to_string();

    // Delete the SA.
    let r = app
        .clone()
        .oneshot(
            Request::delete(format!("/api/v1/orgs/{org_id}/service-accounts/{sa_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);

    // Token's row is gone via CASCADE — verify is `None` → 401.
    let r = app
        .clone()
        .oneshot(
            Request::get("/api/v1/service-accounts/me")
                .header(header::AUTHORIZATION, format!("Bearer {wire}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_scope_rejected() {
    let app = test_app().await;
    let (uid, sk) = register(&app, "alice@x.test", 1).await;
    let bearer = login(&app, "alice@x.test").await;
    let org_id = create_org(&app, &uid, &sk, &bearer, "Acme").await;
    let sa = create_sa(&app, &bearer, &org_id, "bot").await;
    let sa_id = sa["id"].as_str().unwrap();

    let body = json!({"name": "t", "scopes": "totally:made:up"});
    let r = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/v1/orgs/{org_id}/service-accounts/{sa_id}/tokens"
            ))
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_returns_created_sas() {
    let app = test_app().await;
    let (uid, sk) = register(&app, "alice@x.test", 1).await;
    let bearer = login(&app, "alice@x.test").await;
    let org_id = create_org(&app, &uid, &sk, &bearer, "Acme").await;
    create_sa(&app, &bearer, &org_id, "first").await;
    create_sa(&app, &bearer, &org_id, "second").await;

    let r = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/orgs/{org_id}/service-accounts"))
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = body_json(r).await;
    let names: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"first"));
    assert!(names.contains(&"second"));
}
