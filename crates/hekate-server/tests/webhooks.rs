//! Webhook integration test: spin up an axum receiver, register a webhook
//! pointing at it, trigger a cipher event, verify the receiver got a
//! POST with the correct headers, payload, and HMAC signature.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    body::{to_bytes, Body, Bytes},
    http::{header, HeaderMap, Request, StatusCode},
    routing::post,
    Router,
};
use base64::{
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine as _,
};
use hekate_server::{bootstrap, build_router, config::Config};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use tower::ServiceExt;

const MPH: [u8; 32] = [42u8; 32];

fn b64(b: &[u8]) -> String {
    STANDARD_NO_PAD.encode(b)
}
fn enc() -> &'static str {
    "v3.xc20p.kid.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA"
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn build_app() -> Router {
    let cfg = Config {
        listen: "0.0.0.0:0".into(),
        database_url: "sqlite::memory:".into(),
        fake_salt_pepper: vec![0u8; 32],
        // Tests register webhooks against 127.0.0.1; production-strict
        // SSRF defense (audit S-H1) blocks loopback by default. Tests
        // run against the dev escape hatch.
        webhooks_allow_unsafe_destinations: true,
        ..Default::default()
    };
    let state = bootstrap(cfg).await.expect("bootstrap");
    build_router(state)
}

async fn login(app: &Router, email: &str) -> String {
    let body = json!({
        "email": email,
        "kdf_params": {"alg":"argon2id","m_kib":64,"t":1,"p":1},
        "kdf_salt": b64(&[7u8;16]),
        "kdf_params_mac": b64(&[0xa5u8;32]),
        "master_password_hash": b64(&MPH),
        "protected_account_key": enc(),
        "account_public_key": b64(&[1u8;32]),
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

    let r = app
        .clone()
        .oneshot(
            Request::post("/identity/connect/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=password&username={email}&password={}",
                    b64(&MPH)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    body_json(r).await["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

#[derive(Clone)]
struct Received {
    headers: HeaderMap,
    body: Vec<u8>,
}

async fn spawn_receiver() -> (u16, Arc<Mutex<Vec<Received>>>) {
    let received: Arc<Mutex<Vec<Received>>> = Arc::new(Mutex::new(Vec::new()));
    let captured = received.clone();
    let app = Router::new().route(
        "/hook",
        post(move |headers: HeaderMap, body: Bytes| {
            let captured = captured.clone();
            async move {
                captured.lock().unwrap().push(Received {
                    headers,
                    body: body.to_vec(),
                });
                StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (port, received)
}

/// Spawn an attacker-controlled receiver that redirects every POST to
/// `location` with a `307 Temporary Redirect` (which preserves the method
/// and body — the worst case, since it replays the signed payload at the
/// redirect target). Models the SSRF-via-redirect vector (audit S-H1
/// follow-up): a public endpoint that passes `resolve_safe` at delivery
/// time but bounces the request to an internal address. Returns the bound
/// port plus a hit counter so a test can confirm the delivery was actually
/// attempted before asserting the redirect target was not reached.
async fn spawn_redirector(location: String) -> (u16, Arc<Mutex<usize>>) {
    let hits: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    let counter = hits.clone();
    let app = Router::new().route(
        "/hook",
        post(move || {
            let counter = counter.clone();
            let location = location.clone();
            async move {
                *counter.lock().unwrap() += 1;
                (
                    StatusCode::TEMPORARY_REDIRECT,
                    [(header::LOCATION, location)],
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (port, hits)
}

fn cipher_payload() -> Value {
    json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "type": 1,
        "folder_id": null,
        "protected_cipher_key": enc(),
        "name": enc(),
        "data": enc(),
        "favorite": false,
    })
}

fn parse_signature(h: &str) -> (i64, String) {
    let parts: HashMap<_, _> = h.split(',').filter_map(|p| p.split_once('=')).collect();
    let t = parts["t"].parse::<i64>().unwrap();
    let v1 = parts["v1"].to_string();
    (t, v1)
}

fn verify_signature(secret_b64: &str, t: i64, body: &[u8], v1: &str) -> bool {
    let secret = URL_SAFE_NO_PAD.decode(secret_b64).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
    mac.update(format!("{t}.").as_bytes());
    mac.update(body);
    let expected = hex::encode(mac.finalize().into_bytes());
    expected == v1
}

#[tokio::test]
async fn webhook_delivers_signed_event_on_cipher_create() {
    let (port, received) = spawn_receiver().await;
    let app = build_app().await;
    let jwt = login(&app, "alice@example.com").await;

    // Create webhook pointing at our receiver.
    let create = app
        .clone()
        .oneshot(
            Request::post("/api/v1/account/webhooks")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"name":"test","url":format!("http://127.0.0.1:{port}/hook")})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let secret_b64 = body_json(create).await["secret"]
        .as_str()
        .unwrap()
        .to_string();

    // Trigger an event by creating a cipher.
    let create_cipher = app
        .clone()
        .oneshot(
            Request::post("/api/v1/ciphers")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(cipher_payload().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_cipher.status(), StatusCode::CREATED);
    let cipher_body = body_json(create_cipher).await;
    let cipher_id = cipher_body["id"].as_str().unwrap().to_string();

    // Wait up to ~3 s for delivery.
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if !received.lock().unwrap().is_empty() {
            break;
        }
    }

    let captured = received.lock().unwrap().clone();
    assert_eq!(captured.len(), 1, "expected exactly one webhook delivery");
    let r = &captured[0];

    // Headers
    assert_eq!(
        r.headers
            .get("x-hekate-event-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "cipher.changed"
    );
    assert!(r.headers.get("x-hekate-event-id").is_some());
    let sig = r
        .headers
        .get("x-hekate-signature")
        .unwrap()
        .to_str()
        .unwrap();
    let (t, v1) = parse_signature(sig);

    // Verify signature against the body.
    assert!(
        verify_signature(&secret_b64, t, &r.body, &v1),
        "signature mismatch"
    );

    // Verify body shape.
    let payload: Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(payload["type"], "cipher.changed");
    assert!(payload["id"].is_string());
    assert_eq!(payload["data"]["id"], cipher_id);
}

#[tokio::test]
async fn webhook_with_filter_skips_non_matching_events() {
    let (port, received) = spawn_receiver().await;
    let app = build_app().await;
    let jwt = login(&app, "bob@example.com").await;

    // Webhook only listens for tombstones — cipher.changed should be ignored.
    let create = app
        .clone()
        .oneshot(
            Request::post("/api/v1/account/webhooks")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name":"tombstones-only",
                        "url":format!("http://127.0.0.1:{port}/hook"),
                        "events":"cipher.tombstoned",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);

    // Trigger a cipher.changed (should NOT deliver).
    let _ = app
        .clone()
        .oneshot(
            Request::post("/api/v1/ciphers")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(cipher_payload().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        received.lock().unwrap().len(),
        0,
        "non-matching event should not have been delivered"
    );
}

#[tokio::test]
async fn deleted_webhook_stops_receiving() {
    let (port, received) = spawn_receiver().await;
    let app = build_app().await;
    let jwt = login(&app, "carol@example.com").await;

    let create = app
        .clone()
        .oneshot(
            Request::post("/api/v1/account/webhooks")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"name":"x","url":format!("http://127.0.0.1:{port}/hook")}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let id = body_json(create).await["id"].as_str().unwrap().to_string();

    // Delete it.
    let del = app
        .clone()
        .oneshot(
            Request::delete(format!("/api/v1/account/webhooks/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del.status(), StatusCode::NO_CONTENT);

    // Trigger an event.
    let _ = app
        .clone()
        .oneshot(
            Request::post("/api/v1/ciphers")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(cipher_payload().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(received.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn webhook_does_not_follow_redirect_to_internal_target() {
    // SSRF-via-redirect (audit S-H1 follow-up). The delivery client pins
    // the connection to the validated IP of the *original* host, but a
    // redirect points at a *new* host that bypasses both the `resolve_safe`
    // IP check and the pin. An attacker registers a public-looking
    // endpoint that redirects the delivery at an internal address; if the
    // client followed it, the internal target would be hit. Redirect
    // following is disabled, so the internal target must stay untouched.
    let (internal_port, internal_received) = spawn_receiver().await;
    let (attacker_port, attacker_hits) =
        spawn_redirector(format!("http://127.0.0.1:{internal_port}/hook")).await;

    let app = build_app().await;
    let jwt = login(&app, "mallory@example.com").await;

    // Webhook points at the attacker's endpoint (not the internal one).
    let create = app
        .clone()
        .oneshot(
            Request::post("/api/v1/account/webhooks")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"name":"evil","url":format!("http://127.0.0.1:{attacker_port}/hook")})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);

    // Trigger an event.
    let create_cipher = app
        .clone()
        .oneshot(
            Request::post("/api/v1/ciphers")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(cipher_payload().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_cipher.status(), StatusCode::CREATED);

    // Wait until the delivery attempt reaches the attacker endpoint (proves
    // the worker actually ran a delivery), up to ~5 s.
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if *attacker_hits.lock().unwrap() >= 1 {
            break;
        }
    }
    assert!(
        *attacker_hits.lock().unwrap() >= 1,
        "expected the delivery to reach the attacker endpoint at least once"
    );

    // Give any (incorrectly) followed redirect time to land, then assert
    // the internal target was never contacted.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        internal_received.lock().unwrap().len(),
        0,
        "redirect to an internal target must NOT be followed (SSRF)"
    );
}
