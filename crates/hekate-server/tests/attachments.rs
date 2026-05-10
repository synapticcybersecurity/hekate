//! End-to-end tests for attachments (M2.24).
//!
//! Covers the tus 1.0 protocol path, BLAKE3 verification, quota
//! enforcement, cross-user isolation, and /sync wiring.

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use hekate_core::attachment::{ciphertext_size_for, content_hash_b3, encrypt};
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
        // Tighten the per-account cap so we can exercise the quota
        // path without blowing memory in the per-file test.
        max_account_attachment_bytes: 4 * 1024 * 1024,
        max_cipher_attachment_bytes: 4 * 1024 * 1024,
        max_attachment_bytes: 4 * 1024 * 1024,
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

async fn create_cipher(app: &Router, token: &str) -> String {
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
        .oneshot(
            Request::post("/api/v1/ciphers")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    id
}

/// tus `Upload-Metadata` is `key value, key value, ...` with values
/// base64-encoded. Server accepts both padded and unpadded; we emit
/// padded for fidelity to the spec.
fn build_upload_metadata(pairs: &[(&str, &str)]) -> String {
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

/// Build a chunked-AEAD ciphertext for `plaintext`. Returns
/// `(attachment_id, ciphertext, content_hash_b3)`.
fn make_blob(plaintext: &[u8]) -> (String, Vec<u8>, String) {
    let attachment_id = Uuid::new_v4().to_string();
    let key = [0x42u8; 32];
    let ct = encrypt(&key, attachment_id.as_bytes(), plaintext).expect("encrypt");
    let hash = content_hash_b3(&ct);
    (attachment_id, ct, hash)
}

/// Drive a full upload — single-shot via `creation-with-upload`.
async fn upload_full(
    app: &Router,
    token: &str,
    cipher_id: &str,
    plaintext: &[u8],
) -> (String, String) {
    let (att_id, ct, hash) = make_blob(plaintext);
    let meta = build_upload_metadata(&[
        ("filename", enc_placeholder()),
        ("content_key", enc_placeholder()),
        ("cipher_id", cipher_id),
        ("attachment_id", &att_id),
        ("content_hash_b3", &hash),
        ("size_pt", &plaintext.len().to_string()),
    ]);
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/attachments")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Length", ct.len().to_string())
                .header("Upload-Metadata", meta)
                .body(Body::from(ct.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let location = resp
        .headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    assert!(
        status.is_success() || status == StatusCode::CREATED,
        "upload status {status}"
    );
    (att_id, location)
}

// ============== tests ==============

#[tokio::test]
async fn options_returns_tus_capabilities() {
    let app = test_app().await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/api/v1/attachments")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let h = resp.headers();
    assert_eq!(h.get("Tus-Resumable").unwrap(), "1.0.0");
    assert!(h
        .get("Tus-Extension")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("creation"));
    assert!(h.get("Tus-Max-Size").is_some());
}

#[tokio::test]
async fn full_upload_then_download_round_trip() {
    let app = test_app().await;
    register(&app, "a@example.com").await;
    let token = login(&app, "a@example.com").await;
    let cipher_id = create_cipher(&app, &token).await;

    let plaintext = b"the quick brown fox jumps over the lazy dog".repeat(1024);
    let (att_id, location) = upload_full(&app, &token, &cipher_id, &plaintext).await;
    assert!(location.starts_with("/api/v1/tus/"));

    // Download via /api/v1/attachments/{id}/blob.
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/attachments/{att_id}/blob"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1 << 24).await.unwrap();
    let pt2 = hekate_core::attachment::decrypt(&[0x42u8; 32], att_id.as_bytes(), &bytes)
        .expect("decrypt");
    assert_eq!(pt2, plaintext);
}

#[tokio::test]
async fn resume_via_head_after_partial_patch() {
    let app = test_app().await;
    register(&app, "a@example.com").await;
    let token = login(&app, "a@example.com").await;
    let cipher_id = create_cipher(&app, &token).await;

    // Create the upload empty (no creation-with-upload), then PATCH a
    // first half, HEAD to read the offset, then PATCH the rest.
    let pt = vec![0u8; 200_000];
    let (att_id, ct, hash) = make_blob(&pt);
    let meta = build_upload_metadata(&[
        ("filename", enc_placeholder()),
        ("content_key", enc_placeholder()),
        ("cipher_id", &cipher_id),
        ("attachment_id", &att_id),
        ("content_hash_b3", &hash),
        ("size_pt", &pt.len().to_string()),
    ]);
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/attachments")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Length", ct.len().to_string())
                .header("Upload-Metadata", meta)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // PATCH first 50 KiB.
    let half = 50 * 1024;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(&location)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Offset", "0")
                .header("Content-Type", "application/offset+octet-stream")
                .body(Body::from(ct[..half].to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        resp.headers().get("Upload-Offset").unwrap(),
        &half.to_string()
    );

    // HEAD: server should report Upload-Offset = half.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri(&location)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("Upload-Offset").unwrap(),
        &half.to_string()
    );

    // PATCH the remainder.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(&location)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Offset", half.to_string())
                .header("Content-Type", "application/offset+octet-stream")
                .body(Body::from(ct[half..].to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        resp.headers()
            .get("Upload-Offset")
            .unwrap()
            .to_str()
            .unwrap(),
        ct.len().to_string()
    );

    // Download should now succeed (finalize was triggered on the last byte).
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/attachments/{att_id}/blob"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn patch_with_wrong_offset_is_rejected() {
    let app = test_app().await;
    register(&app, "a@example.com").await;
    let token = login(&app, "a@example.com").await;
    let cipher_id = create_cipher(&app, &token).await;

    let pt = b"hello".to_vec();
    let (att_id, ct, hash) = make_blob(&pt);
    let meta = build_upload_metadata(&[
        ("filename", enc_placeholder()),
        ("content_key", enc_placeholder()),
        ("cipher_id", &cipher_id),
        ("attachment_id", &att_id),
        ("content_hash_b3", &hash),
        ("size_pt", &pt.len().to_string()),
    ]);
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/attachments")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Length", ct.len().to_string())
                .header("Upload-Metadata", meta)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let location = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // PATCH with a non-zero offset before any bytes have been received.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(&location)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Offset", "10")
                .header("Content-Type", "application/offset+octet-stream")
                .body(Body::from(ct.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn finalize_rejects_hash_mismatch() {
    let app = test_app().await;
    register(&app, "a@example.com").await;
    let token = login(&app, "a@example.com").await;
    let cipher_id = create_cipher(&app, &token).await;

    let pt = b"some bytes".to_vec();
    let (att_id, ct, _real_hash) = make_blob(&pt);
    // Lie about the hash. Server re-computes on finalize and rejects.
    let bogus = "AA".repeat(22);
    let meta = build_upload_metadata(&[
        ("filename", enc_placeholder()),
        ("content_key", enc_placeholder()),
        ("cipher_id", &cipher_id),
        ("attachment_id", &att_id),
        ("content_hash_b3", &bogus),
        ("size_pt", &pt.len().to_string()),
    ]);
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/attachments")
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
    let body = body_json(resp).await;
    let msg = body["error"].as_str().unwrap_or("");
    assert!(
        msg.contains("BLAKE3"),
        "expected hash mismatch message, got {msg}"
    );
}

#[tokio::test]
async fn cross_user_cannot_download() {
    let app = test_app().await;
    register(&app, "alice@example.com").await;
    register(&app, "bob@example.com").await;
    let alice = login(&app, "alice@example.com").await;
    let bob = login(&app, "bob@example.com").await;
    let cipher_id = create_cipher(&app, &alice).await;
    let (att_id, _) = upload_full(&app, &alice, &cipher_id, b"alice's secret").await;

    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/attachments/{att_id}/blob"))
                .header(header::AUTHORIZATION, format!("Bearer {bob}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn upload_to_unowned_cipher_is_rejected() {
    let app = test_app().await;
    register(&app, "alice@example.com").await;
    register(&app, "bob@example.com").await;
    let alice = login(&app, "alice@example.com").await;
    let bob = login(&app, "bob@example.com").await;
    let alice_cipher = create_cipher(&app, &alice).await;

    let pt = b"intruder".to_vec();
    let (att_id, ct, hash) = make_blob(&pt);
    let meta = build_upload_metadata(&[
        ("filename", enc_placeholder()),
        ("content_key", enc_placeholder()),
        ("cipher_id", &alice_cipher),
        ("attachment_id", &att_id),
        ("content_hash_b3", &hash),
        ("size_pt", &pt.len().to_string()),
    ]);
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/attachments")
                .header(header::AUTHORIZATION, format!("Bearer {bob}"))
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Length", ct.len().to_string())
                .header("Upload-Metadata", meta)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::NOT_FOUND,
        "expected 403 or 404, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn quota_per_file_rejects_oversize() {
    let app = test_app().await;
    register(&app, "a@example.com").await;
    let token = login(&app, "a@example.com").await;
    let cipher_id = create_cipher(&app, &token).await;

    // Size exceeds the 4 MiB per-file cap configured in test_app.
    let big_size = 5 * 1024 * 1024u64;
    let big_ct = ciphertext_size_for(big_size);
    let att_id = Uuid::new_v4().to_string();
    let meta = build_upload_metadata(&[
        ("filename", enc_placeholder()),
        ("content_key", enc_placeholder()),
        ("cipher_id", &cipher_id),
        ("attachment_id", &att_id),
        ("content_hash_b3", &"A".repeat(43)),
        ("size_pt", &big_size.to_string()),
    ]);
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/attachments")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Length", big_ct.to_string())
                .header("Upload-Metadata", meta)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert!(body["error"].as_str().unwrap_or("").contains("per-file"));
}

#[tokio::test]
async fn sync_surfaces_attachment_then_tombstone() {
    let app = test_app().await;
    register(&app, "a@example.com").await;
    let token = login(&app, "a@example.com").await;
    let cipher_id = create_cipher(&app, &token).await;
    let (att_id, _) = upload_full(&app, &token, &cipher_id, b"hello world").await;

    // /sync should include the attachment.
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/sync")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    let atts = v["changes"]["attachments"]
        .as_array()
        .expect("attachments array");
    assert_eq!(atts.len(), 1);
    assert_eq!(atts[0]["id"], att_id);
    assert_eq!(atts[0]["cipher_id"], cipher_id);

    // Delete and verify tombstone surfaces.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/attachments/{att_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/sync")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_json(resp).await;
    let tombstones = v["changes"]["tombstones"]
        .as_array()
        .expect("tombstones array");
    assert!(
        tombstones
            .iter()
            .any(|t| t["kind"] == "attachment" && t["id"] == att_id),
        "expected attachment tombstone, got {tombstones:?}"
    );
    // And the attachment is no longer in the list.
    let atts = v["changes"]["attachments"].as_array();
    assert!(
        atts.map(|a| a.iter().all(|x| x["id"] != att_id))
            .unwrap_or(true),
        "deleted attachment should not be in changes.attachments"
    );
}

#[tokio::test]
async fn terminate_aborts_in_progress_upload() {
    let app = test_app().await;
    register(&app, "a@example.com").await;
    let token = login(&app, "a@example.com").await;
    let cipher_id = create_cipher(&app, &token).await;

    let pt = vec![0u8; 100];
    let (att_id, ct, hash) = make_blob(&pt);
    let meta = build_upload_metadata(&[
        ("filename", enc_placeholder()),
        ("content_key", enc_placeholder()),
        ("cipher_id", &cipher_id),
        ("attachment_id", &att_id),
        ("content_hash_b3", &hash),
        ("size_pt", &pt.len().to_string()),
    ]);
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/attachments")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Length", ct.len().to_string())
                .header("Upload-Metadata", meta)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let location = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Terminate.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(&location)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Subsequent HEAD on the same token should 404.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri(&location)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn metadata_endpoint_returns_view() {
    let app = test_app().await;
    register(&app, "a@example.com").await;
    let token = login(&app, "a@example.com").await;
    let cipher_id = create_cipher(&app, &token).await;
    let (att_id, _) = upload_full(&app, &token, &cipher_id, b"blob").await;

    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/attachments/{att_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["id"], att_id);
    assert_eq!(v["cipher_id"], cipher_id);
    assert_eq!(v["size_pt"], 4);
}
