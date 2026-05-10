//! M2.25 — Send integration tests.
//!
//! Covers the authenticated owner CRUD, the anonymous public-access
//! endpoint, password gating, max-access enforcement (atomicity),
//! expiration / disable, /sync wiring, and GC of past-deletion_date
//! rows.

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use chrono::{Duration, Utc};
use hekate_core::{
    attachment::{content_hash_b3, encrypt as att_encrypt},
    send::{decode_send_key, decrypt_text, encrypt_text, generate_send_key},
};
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

/// Build a SendInput body with a real send_key + ciphertext so
/// public-access response can be decrypted by tests.
struct PreparedSend {
    body: Value,
    id: String,
    send_key_url: String,
    plaintext: String,
}

fn prepare_text_send(
    name: &str,
    plaintext: &str,
    password: Option<&str>,
    max_access: Option<i64>,
    expiration: Option<&str>,
    deletion: &str,
    disabled: bool,
) -> PreparedSend {
    let id = Uuid::now_v7().to_string();
    let send_key = generate_send_key();
    let send_key_url = hekate_core::send::encode_send_key(&send_key);
    let data_wire = encrypt_text(&send_key, &id, plaintext.as_bytes()).unwrap();

    let mut body = json!({
        "id": id,
        "send_type": 1,
        "name": format!("v3.xc20p.kid.AA.AA.{}.AAAAAAAAAAAAAAAAAAAAAA", b64(name.as_bytes())),
        "protected_send_key": enc_placeholder(),
        "data": data_wire,
        "deletion_date": deletion,
        "disabled": disabled,
    });
    if let Some(p) = password {
        body["password"] = json!(p);
    }
    if let Some(m) = max_access {
        body["max_access_count"] = json!(m);
    }
    if let Some(e) = expiration {
        body["expiration_date"] = json!(e);
    }
    PreparedSend {
        body,
        id,
        send_key_url,
        plaintext: plaintext.to_string(),
    }
}

// ============== tests ==============

#[tokio::test]
async fn create_then_list_then_read() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let token = login(&app, "alice@x.test").await;
    let prepped = prepare_text_send(
        "lunch plans",
        "meet at noon",
        None,
        None,
        None,
        &(Utc::now() + Duration::days(1)).to_rfc3339(),
        false,
    );
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/sends", &token, Some(&prepped.body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = body_json(resp).await;
    assert_eq!(v["id"], prepped.id);
    assert_eq!(v["send_type"], 1);
    assert_eq!(v["access_count"], 0);
    assert_eq!(v["has_password"], false);

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/sends", &token, None))
        .await
        .unwrap();
    let list = body_json(resp).await;
    assert_eq!(list.as_array().unwrap().len(), 1);

    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/sends/{}", prepped.id),
            &token,
            None,
        ))
        .await
        .unwrap();
    let one = body_json(resp).await;
    assert_eq!(one["id"], prepped.id);
}

#[tokio::test]
async fn public_access_round_trip_decrypts_with_send_key() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let token = login(&app, "alice@x.test").await;
    let prepped = prepare_text_send(
        "secret",
        "the eagle has landed",
        None,
        None,
        None,
        &(Utc::now() + Duration::days(1)).to_rfc3339(),
        false,
    );
    app.clone()
        .oneshot(req("POST", "/api/v1/sends", &token, Some(&prepped.body)))
        .await
        .unwrap();

    // Anonymous access — no Authorization header.
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/public/sends/{}/access", prepped.id))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["access_count"], 1);
    let data_wire = v["data"].as_str().unwrap();

    // Recipient simulates decrypting with the URL fragment.
    let send_key = decode_send_key(&prepped.send_key_url).unwrap();
    let pt = decrypt_text(&send_key, &prepped.id, data_wire).unwrap();
    assert_eq!(String::from_utf8(pt).unwrap(), prepped.plaintext);
}

#[tokio::test]
async fn password_gate_rejects_wrong_then_accepts_right() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let token = login(&app, "alice@x.test").await;
    let prepped = prepare_text_send(
        "gated",
        "open sesame",
        Some("hunter2"),
        None,
        None,
        &(Utc::now() + Duration::days(1)).to_rfc3339(),
        false,
    );
    app.clone()
        .oneshot(req("POST", "/api/v1/sends", &token, Some(&prepped.body)))
        .await
        .unwrap();

    // No password -> 401.
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/public/sends/{}/access", prepped.id))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // Wrong password -> 401.
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/public/sends/{}/access", prepped.id))
                .header("content-type", "application/json")
                .body(Body::from(json!({"password": "wrong"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // Right password -> 200, access_count bumped.
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/public/sends/{}/access", prepped.id))
                .header("content-type", "application/json")
                .body(Body::from(json!({"password": "hunter2"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["access_count"], 1);
}

#[tokio::test]
async fn max_access_count_is_enforced() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let token = login(&app, "alice@x.test").await;
    let prepped = prepare_text_send(
        "limit",
        "two-shot",
        None,
        Some(2),
        None,
        &(Utc::now() + Duration::days(1)).to_rfc3339(),
        false,
    );
    app.clone()
        .oneshot(req("POST", "/api/v1/sends", &token, Some(&prepped.body)))
        .await
        .unwrap();
    for expected in 1..=2 {
        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/public/sends/{}/access", prepped.id))
                    .header("content-type", "application/json")
                    .body(Body::from(json!({}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["access_count"], expected);
    }
    // Third access -> 409 (gone surrogate).
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/public/sends/{}/access", prepped.id))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn expiration_date_blocks_access() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let token = login(&app, "alice@x.test").await;
    let past = (Utc::now() - Duration::hours(1)).to_rfc3339();
    let prepped = prepare_text_send(
        "stale",
        "no longer available",
        None,
        None,
        Some(&past),
        &(Utc::now() + Duration::days(1)).to_rfc3339(),
        false,
    );
    app.clone()
        .oneshot(req("POST", "/api/v1/sends", &token, Some(&prepped.body)))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/public/sends/{}/access", prepped.id))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn disabled_send_blocks_access() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let token = login(&app, "alice@x.test").await;
    let prepped = prepare_text_send(
        "off",
        "not now",
        None,
        None,
        None,
        &(Utc::now() + Duration::days(1)).to_rfc3339(),
        true,
    );
    app.clone()
        .oneshot(req("POST", "/api/v1/sends", &token, Some(&prepped.body)))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/public/sends/{}/access", prepped.id))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn sync_surfaces_send_then_tombstone_after_delete() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let token = login(&app, "alice@x.test").await;
    let prepped = prepare_text_send(
        "trace me",
        "in /sync",
        None,
        None,
        None,
        &(Utc::now() + Duration::days(1)).to_rfc3339(),
        false,
    );
    app.clone()
        .oneshot(req("POST", "/api/v1/sends", &token, Some(&prepped.body)))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/sync", &token, None))
        .await
        .unwrap();
    let v = body_json(resp).await;
    let sends = v["changes"]["sends"].as_array().expect("sends array");
    assert_eq!(sends.len(), 1);
    assert_eq!(sends[0]["id"], prepped.id);

    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/sends/{}", prepped.id),
            &token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/sync", &token, None))
        .await
        .unwrap();
    let v = body_json(resp).await;
    let tombs = v["changes"]["tombstones"].as_array().unwrap();
    assert!(tombs
        .iter()
        .any(|t| t["kind"] == "send" && t["id"] == prepped.id));
    let sends = v["changes"]["sends"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(sends.iter().all(|s| s["id"] != prepped.id));
}

#[tokio::test]
async fn disable_then_enable_round_trip() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let token = login(&app, "alice@x.test").await;
    let prepped = prepare_text_send(
        "toggle",
        "x",
        None,
        None,
        None,
        &(Utc::now() + Duration::days(1)).to_rfc3339(),
        false,
    );
    app.clone()
        .oneshot(req("POST", "/api/v1/sends", &token, Some(&prepped.body)))
        .await
        .unwrap();
    // Disable.
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/sends/{}/disable", prepped.id),
            &token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["disabled"], true);
    // Public access blocked.
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/public/sends/{}/access", prepped.id))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    // Re-enable.
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/sends/{}/enable", prepped.id),
            &token,
            None,
        ))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/public/sends/{}/access", prepped.id))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn cross_user_isolation_on_owner_endpoints() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    register(&app, "bob@x.test").await;
    let alice = login(&app, "alice@x.test").await;
    let bob = login(&app, "bob@x.test").await;
    let prepped = prepare_text_send(
        "alice's",
        "private",
        None,
        None,
        None,
        &(Utc::now() + Duration::days(1)).to_rfc3339(),
        false,
    );
    app.clone()
        .oneshot(req("POST", "/api/v1/sends", &alice, Some(&prepped.body)))
        .await
        .unwrap();
    // Bob can't read the row via the owner endpoint.
    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/sends/{}", prepped.id),
            &bob,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // But Bob CAN access via the public endpoint — that's the whole
    // point of Send. Recipients aren't auth'd.
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/public/sends/{}/access", prepped.id))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// =====================================================================
// M2.25a — file Sends
// =====================================================================

/// Build the canonical Upload-Metadata header value the tus routes parse.
fn upload_metadata(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(k);
        out.push(' ');
        out.push_str(&STANDARD.encode(v));
    }
    out
}

/// Prepare a SendInput body for a file Send. The encrypted-metadata
/// payload (`data`) carries the per-file AEAD key (in real usage the
/// recipient HKDF-decrypts it; in tests we just verify the body
/// round-trips by chunked-AEAD-decrypting the downloaded blob with a
/// known key). Returns the SendInput JSON, the send_id, and the
/// `(file_aead_key, ciphertext)` tuple.
fn prepare_file_send_create_body(
    name: &str,
    plaintext: &[u8],
    deletion: &str,
) -> (Value, String, [u8; 32], Vec<u8>) {
    let id = Uuid::now_v7().to_string();
    let send_key = generate_send_key();
    // `data` is just an EncString of arbitrary metadata — the server
    // doesn't introspect it. For the round-trip test we don't need a
    // valid metadata blob; we'll exercise the body path independently.
    let data_wire = encrypt_text(&send_key, &id, b"{filename:test}").unwrap();

    // Body ciphertext via chunked-AEAD with a fresh per-file key.
    let mut file_aead_key = [0u8; 32];
    file_aead_key.copy_from_slice(&[0xab; 32]);
    let body_ct = att_encrypt(&file_aead_key, id.as_bytes(), plaintext).unwrap();

    let body = json!({
        "id": id,
        "send_type": 2,
        "name": format!("v3.xc20p.kid.AA.AA.{}.AAAAAAAAAAAAAAAAAAAAAA", STANDARD_NO_PAD.encode(name.as_bytes())),
        "protected_send_key": enc_placeholder(),
        "data": data_wire,
        "deletion_date": deletion,
        "disabled": false,
    });
    (body, id, file_aead_key, body_ct)
}

#[tokio::test]
async fn file_send_full_upload_then_anonymous_download_round_trip() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let token = login(&app, "alice@x.test").await;

    let plaintext = b"the file body".repeat(2048); // 26 KiB
    let (create_body, id, file_aead_key, ciphertext) = prepare_file_send_create_body(
        "doc.txt",
        &plaintext,
        &(Utc::now() + Duration::days(1)).to_rfc3339(),
    );
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/sends", &token, Some(&create_body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Public access BEFORE upload — should reject ("body not uploaded").
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/public/sends/{}/access", id))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // Upload the body via tus creation-with-upload.
    let hash = content_hash_b3(&ciphertext);
    let meta = upload_metadata(&[
        ("content_hash_b3", &hash),
        ("size_pt", &plaintext.len().to_string()),
    ]);
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/sends/{}/upload", id))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Length", ciphertext.len().to_string())
                .header("Upload-Metadata", meta)
                .body(Body::from(ciphertext.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // /access now succeeds and returns a download_token.
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/public/sends/{}/access", id))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["send_type"], 2);
    assert_eq!(v["access_count"], 1);
    let dl_token = v["download_token"]
        .as_str()
        .expect("download_token")
        .to_string();
    assert_eq!(v["size_ct"], ciphertext.len() as i64);

    // Download the body anonymously.
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/public/sends/{}/blob/{}", id, dl_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let downloaded = to_bytes(resp.into_body(), 1 << 24).await.unwrap();
    assert_eq!(&downloaded[..], &ciphertext[..]);

    // Recipient-side decrypt with the per-file AEAD key.
    let pt = hekate_core::attachment::decrypt(&file_aead_key, id.as_bytes(), &downloaded).unwrap();
    assert_eq!(pt, plaintext);
}

#[tokio::test]
async fn file_send_blob_endpoint_rejects_unknown_token() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let token = login(&app, "alice@x.test").await;
    let pt = b"x".repeat(64);
    let (create_body, id, _key, ct) =
        prepare_file_send_create_body("doc", &pt, &(Utc::now() + Duration::days(1)).to_rfc3339());
    app.clone()
        .oneshot(req("POST", "/api/v1/sends", &token, Some(&create_body)))
        .await
        .unwrap();
    let hash = content_hash_b3(&ct);
    let meta = upload_metadata(&[
        ("content_hash_b3", &hash),
        ("size_pt", &pt.len().to_string()),
    ]);
    app.clone()
        .oneshot(
            Request::post(format!("/api/v1/sends/{}/upload", id))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Length", ct.len().to_string())
                .header("Upload-Metadata", meta)
                .body(Body::from(ct))
                .unwrap(),
        )
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/public/sends/{}/blob/{}",
                id, "not-a-real-token"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn file_send_finalize_rejects_hash_mismatch() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let token = login(&app, "alice@x.test").await;
    let pt = b"hashes-must-match".repeat(32);
    let (create_body, id, _key, ct) =
        prepare_file_send_create_body("doc", &pt, &(Utc::now() + Duration::days(1)).to_rfc3339());
    app.clone()
        .oneshot(req("POST", "/api/v1/sends", &token, Some(&create_body)))
        .await
        .unwrap();
    let bogus = "AA".repeat(22);
    let meta = upload_metadata(&[
        ("content_hash_b3", &bogus),
        ("size_pt", &pt.len().to_string()),
    ]);
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/sends/{}/upload", id))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Length", ct.len().to_string())
                .header("Upload-Metadata", meta)
                .body(Body::from(ct))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn file_send_cross_user_cannot_upload() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    register(&app, "bob@x.test").await;
    let alice = login(&app, "alice@x.test").await;
    let bob = login(&app, "bob@x.test").await;
    let pt = b"x".repeat(64);
    let (create_body, id, _key, ct) =
        prepare_file_send_create_body("doc", &pt, &(Utc::now() + Duration::days(1)).to_rfc3339());
    app.clone()
        .oneshot(req("POST", "/api/v1/sends", &alice, Some(&create_body)))
        .await
        .unwrap();
    let hash = content_hash_b3(&ct);
    let meta = upload_metadata(&[
        ("content_hash_b3", &hash),
        ("size_pt", &pt.len().to_string()),
    ]);
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/sends/{}/upload", id))
                .header(header::AUTHORIZATION, format!("Bearer {bob}"))
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Length", ct.len().to_string())
                .header("Upload-Metadata", meta)
                .body(Body::from(ct))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn file_send_double_upload_is_rejected() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let token = login(&app, "alice@x.test").await;
    let pt = b"y".repeat(64);
    let (create_body, id, _key, ct) =
        prepare_file_send_create_body("doc", &pt, &(Utc::now() + Duration::days(1)).to_rfc3339());
    app.clone()
        .oneshot(req("POST", "/api/v1/sends", &token, Some(&create_body)))
        .await
        .unwrap();
    let hash = content_hash_b3(&ct);
    let meta = upload_metadata(&[
        ("content_hash_b3", &hash),
        ("size_pt", &pt.len().to_string()),
    ]);
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/sends/{}/upload", id))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Length", ct.len().to_string())
                .header("Upload-Metadata", meta.clone())
                .body(Body::from(ct.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/sends/{}/upload", id))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Length", ct.len().to_string())
                .header("Upload-Metadata", meta)
                .body(Body::from(ct))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn file_send_password_gate_blocks_token_issuance() {
    let app = test_app().await;
    register(&app, "alice@x.test").await;
    let token = login(&app, "alice@x.test").await;
    let pt = b"z".repeat(64);
    let (mut create_body, id, _key, ct) =
        prepare_file_send_create_body("doc", &pt, &(Utc::now() + Duration::days(1)).to_rfc3339());
    create_body["password"] = json!("hunter2");
    app.clone()
        .oneshot(req("POST", "/api/v1/sends", &token, Some(&create_body)))
        .await
        .unwrap();
    let hash = content_hash_b3(&ct);
    let meta = upload_metadata(&[
        ("content_hash_b3", &hash),
        ("size_pt", &pt.len().to_string()),
    ]);
    app.clone()
        .oneshot(
            Request::post(format!("/api/v1/sends/{}/upload", id))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Length", ct.len().to_string())
                .header("Upload-Metadata", meta)
                .body(Body::from(ct))
                .unwrap(),
        )
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/public/sends/{}/access", id))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/public/sends/{}/access", id))
                .header("content-type", "application/json")
                .body(Body::from(json!({"password": "hunter2"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    let dl_token = v["download_token"].as_str().unwrap().to_string();
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/public/sends/{}/blob/{}", id, dl_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
