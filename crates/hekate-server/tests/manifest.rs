//! End-to-end tests for the per-user signed vault manifest endpoints.
//!
//! Covers:
//!   * register sets `account_signing_pubkey_b64` on the user row
//!   * upload-then-get round-trips identical bytes
//!   * version monotonicity (server rejects equal-or-lesser versions)
//!   * wrapper version must match canonical version
//!   * server rejects signature under wrong key
//!   * `/sync` embeds the latest manifest after upload
//!   * a user with no signing pubkey cannot upload

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use hekate_core::manifest::{
    hash_canonical, ManifestEntry, VaultManifest, NO_ATTACHMENTS_ROOT, NO_PARENT_HASH,
};
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

/// Register a fresh account that has a known Ed25519 signing key. The
/// caller gets the `SigningKey` to produce manifests with.
async fn register_with_key(app: &Router, email: &str, sk: &SigningKey) {
    let body = json!({
        "email": email,
        "kdf_params": {"alg": "argon2id", "m_kib": 64, "t": 1, "p": 1},
        "kdf_salt": b64(&[7u8; 16]),
        "kdf_params_mac": b64(&[0xa5u8; 32]),
        "master_password_hash": b64(&MPH_BYTES),
        "protected_account_key": enc_placeholder(),
        "account_public_key": b64(&[1u8; 32]),
        "protected_account_private_key": enc_placeholder(),
        "account_signing_pubkey": b64(sk.verifying_key().as_bytes()),
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

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| panic!("non-JSON body: {:?}", String::from_utf8_lossy(&bytes)))
}

/// Build, sort, and Ed25519-sign a manifest with the given key. Mirrors
/// what `hekate-core::manifest::VaultManifest::sign` does, except we want
/// access to the wire shape directly to construct the upload body.
fn signed_payload(
    sk: &SigningKey,
    version: u64,
    parent_hash: [u8; 32],
    entries: Vec<ManifestEntry>,
) -> Value {
    let mut m = VaultManifest {
        version,
        timestamp: "2026-05-02T12:00:00+00:00".into(),
        parent_canonical_sha256: parent_hash,
        entries,
    };
    m.sort_entries();
    let canonical = m.canonical_bytes();
    let sig = sk.sign(&canonical);
    json!({
        "version": version as i64,
        "canonical_b64": b64(&canonical),
        "signature_b64": b64(&sig.to_bytes()),
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

// ----------- tests --------------------------------------------------------

#[tokio::test]
async fn upload_then_get_round_trips() {
    let sk = SigningKey::from_bytes(&[0xa5u8; 32]);
    let app = test_app().await;
    register_with_key(&app, "alice@example.com", &sk).await;
    let token = login(&app, "alice@example.com").await;

    let body = signed_payload(&sk, 1, NO_PARENT_HASH, vec![]);
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/vault/manifest", &token, Some(&body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/vault/manifest", &token, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let got = body_json(resp).await;
    assert_eq!(got["version"], 1);
    assert_eq!(got["canonical_b64"], body["canonical_b64"]);
    assert_eq!(got["signature_b64"], body["signature_b64"]);
}

#[tokio::test]
async fn upload_rejects_stale_version() {
    let sk = SigningKey::from_bytes(&[0xa5u8; 32]);
    let app = test_app().await;
    register_with_key(&app, "alice@example.com", &sk).await;
    let token = login(&app, "alice@example.com").await;

    // First upload — must be genesis (v1 with zero parent), then chain v2.
    let v1 = signed_payload(&sk, 1, NO_PARENT_HASH, vec![]);
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/vault/manifest", &token, Some(&v1)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v1_canonical = STANDARD_NO_PAD
        .decode(v1["canonical_b64"].as_str().unwrap())
        .unwrap();
    let v2 = signed_payload(&sk, 2, hash_canonical(&v1_canonical), vec![]);
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/vault/manifest", &token, Some(&v2)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Replay the earlier version — should be rejected as stale.
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/vault/manifest", &token, Some(&v1)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // Same-version replay also rejected.
    let v2_again = signed_payload(&sk, 2, hash_canonical(&v1_canonical), vec![]);
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/vault/manifest",
            &token,
            Some(&v2_again),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn upload_rejects_signature_under_wrong_key() {
    let registered = SigningKey::from_bytes(&[0xa5u8; 32]);
    let attacker = SigningKey::from_bytes(&[0x42u8; 32]);
    let app = test_app().await;
    register_with_key(&app, "alice@example.com", &registered).await;
    let token = login(&app, "alice@example.com").await;

    // Sign with attacker's key; server rejects because pubkey on user row
    // is `registered.verifying_key()`.
    let body = signed_payload(&attacker, 1, NO_PARENT_HASH, vec![]);
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/vault/manifest", &token, Some(&body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err = body_json(resp).await;
    assert!(
        err["error"].as_str().unwrap_or("").contains("signature"),
        "expected signature-related error, got: {err:?}"
    );
}

#[tokio::test]
async fn upload_rejects_wrapper_canonical_version_mismatch() {
    let sk = SigningKey::from_bytes(&[0xa5u8; 32]);
    let app = test_app().await;
    register_with_key(&app, "alice@example.com", &sk).await;
    let token = login(&app, "alice@example.com").await;

    // Sign canonical with version=1 but claim version=99 in the wrapper.
    let mut body = signed_payload(&sk, 1, NO_PARENT_HASH, vec![]);
    body["version"] = json!(99i64);
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/vault/manifest", &token, Some(&body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sync_includes_latest_manifest() {
    let sk = SigningKey::from_bytes(&[0xa5u8; 32]);
    let app = test_app().await;
    register_with_key(&app, "alice@example.com", &sk).await;
    let token = login(&app, "alice@example.com").await;

    // No manifest yet → /sync returns null.
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/sync", &token, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert!(v["manifest"].is_null());

    // Upload one.
    let body = signed_payload(
        &sk,
        1,
        NO_PARENT_HASH,
        vec![ManifestEntry {
            cipher_id: "cipher-1".into(),
            revision_date: "2026-05-02T11:59:00+00:00".into(),
            deleted: false,
            attachments_root: NO_ATTACHMENTS_ROOT,
        }],
    );
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/vault/manifest", &token, Some(&body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Now /sync embeds it verbatim.
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/sync", &token, None))
        .await
        .unwrap();
    let v = body_json(resp).await;
    let m = &v["manifest"];
    assert_eq!(m["version"], 1);
    assert_eq!(m["canonical_b64"], body["canonical_b64"]);
    assert_eq!(m["signature_b64"], body["signature_b64"]);
}

#[tokio::test]
async fn upload_requires_auth() {
    let app = test_app().await;
    let body = json!({
        "version": 1,
        "canonical_b64": b64(b"anything"),
        "signature_b64": b64(&[0u8; 64]),
    });
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/vault/manifest")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn upload_rejects_user_without_signing_pubkey() {
    // Register without sending the pubkey (back-compat path).
    let app = test_app().await;
    let body = json!({
        "email": "alice@example.com",
        "kdf_params": {"alg": "argon2id", "m_kib": 64, "t": 1, "p": 1},
        "kdf_salt": b64(&[7u8; 16]),
        "kdf_params_mac": b64(&[0xa5u8; 32]),
        "master_password_hash": b64(&MPH_BYTES),
        "protected_account_key": enc_placeholder(),
        "account_public_key": b64(&[1u8; 32]),
        "protected_account_private_key": enc_placeholder(),
        // account_signing_pubkey omitted — empty string in DB
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

    let token = login(&app, "alice@example.com").await;
    // Try to upload — must fail because there's no pubkey to verify against.
    let sk = SigningKey::from_bytes(&[0u8; 32]);
    let body = signed_payload(&sk, 1, NO_PARENT_HASH, vec![]);
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/vault/manifest", &token, Some(&body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn upload_rejects_genesis_with_nonzero_parent() {
    let sk = SigningKey::from_bytes(&[0xa5u8; 32]);
    let app = test_app().await;
    register_with_key(&app, "alice@example.com", &sk).await;
    let token = login(&app, "alice@example.com").await;

    let body = signed_payload(&sk, 1, [0xffu8; 32], vec![]);
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/vault/manifest", &token, Some(&body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err = body_json(resp).await;
    assert!(err["error"]
        .as_str()
        .unwrap_or("")
        .contains("first manifest upload must use parent_canonical_sha256 = zeros"));
}

#[tokio::test]
async fn upload_rejects_broken_chain() {
    let sk = SigningKey::from_bytes(&[0xa5u8; 32]);
    let app = test_app().await;
    register_with_key(&app, "alice@example.com", &sk).await;
    let token = login(&app, "alice@example.com").await;

    let v1 = signed_payload(&sk, 1, NO_PARENT_HASH, vec![]);
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/vault/manifest", &token, Some(&v1)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Forked chain: v2 chains back to a parent that is not v1.
    let v2_bad = signed_payload(&sk, 2, [0xabu8; 32], vec![]);
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/vault/manifest", &token, Some(&v2_bad)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let err = body_json(resp).await;
    assert!(err["error"].as_str().unwrap_or("").contains("chain broken"));
}
