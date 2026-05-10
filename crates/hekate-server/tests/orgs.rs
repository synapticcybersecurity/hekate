//! M4.0 organization-create integration tests.
//!
//! Covers the create + list-mine + get-one round trip plus the
//! validation paths the server enforces on `POST /api/v1/orgs`:
//! UUID shape, bundle-sig verification under the owner's signing
//! pubkey, and the genesis-roster preconditions
//! (version=1, parent=zeros, single owner entry).

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
use hekate_server::{bootstrap, build_router, config::Config, AppState};
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
    let (app, _state) = test_app_with_state().await;
    app
}

/// Same as `test_app()` but also hands back the `AppState` so a test
/// can poke the DB directly. Used by prune-roster tests to inject a
/// pre-GH#2-style roster orphan (an entry signed into the live roster
/// but absent from `organization_members`) — that's the recovery
/// scenario prune was built for, and there's no public API path that
/// produces it post-migration 0023.
async fn test_app_with_state() -> (Router, AppState) {
    let cfg = Config {
        listen: "0.0.0.0:0".into(),
        database_url: "sqlite::memory:".into(),
        fake_salt_pepper: vec![0u8; 32],
        ..Default::default()
    };
    let state = bootstrap(cfg).await.expect("bootstrap");
    let app = build_router(state.clone());
    (app, state)
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| panic!("non-JSON body: {:?}", String::from_utf8_lossy(&bytes)))
}

/// Register a fully-equipped account: chosen email, deterministic
/// signing key, M2.19 self-signed pubkey bundle. Returns
/// `(user_id, signing_key, x25519_pk)`.
async fn register(
    app: &Router,
    email: &str,
    signing_key_seed: u8,
) -> (String, SigningKey, [u8; 32]) {
    let user_id = Uuid::now_v7().to_string();
    let sk = SigningKey::from_bytes(&[signing_key_seed; 32]);
    let signing_pk = sk.verifying_key().to_bytes();
    let x25519_pk = [signing_key_seed.wrapping_add(1); 32];
    let sig = sign_pubkey_bundle(&sk, &user_id, &signing_pk, &x25519_pk);

    let body = json!({
        "email": email,
        "kdf_params": {"alg": "argon2id", "m_kib": 64, "t": 1, "p": 1},
        "kdf_salt": b64(&[7u8; 16]),
        "kdf_params_mac": b64(&[0xa5u8; 32]),
        "master_password_hash": b64(&MPH_BYTES),
        "protected_account_key": enc_placeholder(),
        "account_public_key": b64(&x25519_pk),
        "protected_account_private_key": enc_placeholder(),
        "account_signing_pubkey": b64(&signing_pk),
        "user_id": user_id,
        "account_pubkey_bundle_sig": b64(&sig),
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
    (user_id, sk, x25519_pk)
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

/// Mirror of `routes::orgs::build_bundle_canonical`. Tests must match.
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

/// Build a complete `POST /api/v1/orgs` body, ready to be tweaked
/// per-test for the negative cases.
fn build_create_body(
    owner_user_id: &str,
    owner_signing_key: &SigningKey,
    name: &str,
) -> (Value, String, SigningKey) {
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
        "protected_signing_seed": enc_placeholder(),
        "org_sym_key_id": org_sym_key_id,
        "owner_protected_org_key": enc_placeholder(),
        "roster": {
            "canonical_b64": signed.canonical_b64,
            "signature_b64": signed.signature_b64,
        },
    });
    (body, org_id, org_signing_key)
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

// --------------------------------------------------------------------------

#[tokio::test]
async fn create_org_round_trips_and_list_returns_it() {
    let app = test_app().await;
    let (uid, sk, _x25519) = register(&app, "alice@x.test", 1).await;
    let token = login(&app, "alice@x.test").await;
    let (body, org_id, _) = build_create_body(&uid, &sk, "ACME");

    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/orgs", &token, Some(&body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = body_json(resp).await;
    assert_eq!(v["id"], org_id);
    assert_eq!(v["name"], "ACME");
    assert_eq!(v["my_role"], "owner");
    assert_eq!(v["roster_version"], 1);

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/account/orgs", &token, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert!(v.is_array());
    assert_eq!(v[0]["id"], org_id);
    assert_eq!(v[0]["role"], "owner");
    assert_eq!(v[0]["member_count"], 1);

    let resp = app
        .clone()
        .oneshot(req("GET", &format!("/api/v1/orgs/{org_id}"), &token, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["id"], org_id);
    assert_eq!(v["my_role"], "owner");
    assert!(!v["roster"]["canonical_b64"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn create_org_rejects_bundle_sig_under_wrong_owner_key() {
    let app = test_app().await;
    let (uid, _real_sk, _) = register(&app, "alice@x.test", 1).await;
    let token = login(&app, "alice@x.test").await;
    // Sign the bundle with a different key than the one registered.
    let attacker = SigningKey::from_bytes(&[2u8; 32]);
    let (body, _, _) = build_create_body(&uid, &attacker, "ACME");

    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/orgs", &token, Some(&body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err = body_json(resp).await;
    assert!(err["error"].as_str().unwrap_or("").contains("bundle_sig"));
}

#[tokio::test]
async fn create_org_rejects_genesis_with_nonzero_parent() {
    let app = test_app().await;
    let (uid, sk, _) = register(&app, "alice@x.test", 1).await;
    let token = login(&app, "alice@x.test").await;
    let (mut body, org_id, org_sk) = build_create_body(&uid, &sk, "ACME");

    // Re-sign a roster with parent = 0xff.
    let key_id = body["org_sym_key_id"].as_str().unwrap().to_string();
    let roster = OrgRoster {
        org_id,
        version: 1,
        parent_canonical_sha256: [0xffu8; 32],
        timestamp: "2026-05-03T00:00:00+00:00".into(),
        entries: vec![OrgRosterEntry {
            user_id: uid,
            role: "owner".into(),
        }],
        org_sym_key_id: key_id,
    };
    let signed = roster.sign(&org_sk);
    body["roster"] = json!({
        "canonical_b64": signed.canonical_b64,
        "signature_b64": signed.signature_b64,
    });

    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/orgs", &token, Some(&body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_org_rejects_roster_with_extra_member() {
    // Genesis must be exactly the owner. A roster trying to sneak in
    // another user at create time is rejected.
    let app = test_app().await;
    let (uid, sk, _) = register(&app, "alice@x.test", 1).await;
    let token = login(&app, "alice@x.test").await;
    let (mut body, org_id, org_sk) = build_create_body(&uid, &sk, "ACME");

    let key_id = body["org_sym_key_id"].as_str().unwrap().to_string();
    let roster = OrgRoster {
        org_id,
        version: 1,
        parent_canonical_sha256: NO_PARENT_HASH,
        timestamp: "2026-05-03T00:00:00+00:00".into(),
        entries: vec![
            OrgRosterEntry {
                user_id: uid,
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: "0192e0a0-0000-7000-8000-cccccccccccc".into(),
                role: "user".into(),
            },
        ],
        org_sym_key_id: key_id,
    };
    let signed = roster.sign(&org_sk);
    body["roster"] = json!({
        "canonical_b64": signed.canonical_b64,
        "signature_b64": signed.signature_b64,
    });

    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/orgs", &token, Some(&body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_one_returns_404_for_non_member() {
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (_uid_b, _sk_b, _) = register(&app, "bob@x.test", 2).await;
    let token_alice = login(&app, "alice@x.test").await;
    let token_bob = login(&app, "bob@x.test").await;
    let (body, org_id, _) = build_create_body(&uid_a, &sk_a, "ACME");

    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_alice, Some(&body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/orgs/{org_id}"),
            &token_bob,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invite_and_accept_round_trip() {
    // M4.1 happy path: alice creates org → invites bob with a signed
    // next_roster v2 → bob lists, sees the envelope and roster v2 →
    // bob accepts → both sides see member_count = 2 and the pending
    // invite row is gone.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _sk_b, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // next_roster v2 = owner + bob (user); parent = sha256(genesis).
    let genesis_b64 = create_body["roster"]["canonical_b64"].as_str().unwrap();
    let genesis = STANDARD_NO_PAD.decode(genesis_b64).unwrap();
    let parent_hash = hekate_core::org_roster::hash_canonical(&genesis);
    let next = OrgRoster {
        org_id: org_id.clone(),
        version: 2,
        parent_canonical_sha256: parent_hash,
        timestamp: "2026-05-03T00:01:00+00:00".into(),
        entries: vec![
            OrgRosterEntry {
                user_id: uid_a.clone(),
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: uid_b.clone(),
                role: "user".into(),
            },
        ],
        org_sym_key_id: key_id.clone(),
    };
    let signed_next = next.sign(&org_sk);

    let invite_body = json!({
        "invitee_user_id": uid_b,
        "role": "user",
        // Server stores the envelope opaquely — never decrypts it.
        "envelope": {"opaque": "any-shape"},
        "next_roster": {
            "canonical_b64": signed_next.canonical_b64,
            "signature_b64": signed_next.signature_b64,
        },
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/invites"),
            &token_a,
            Some(&invite_body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // bob lists invites — sees the org + the latest signed roster v2.
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/account/invites", &token_b, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["org_id"], org_id);
    assert_eq!(arr[0]["org_name"], "Acme");
    assert_eq!(arr[0]["inviter_user_id"], uid_a);
    assert_eq!(arr[0]["role"], "user");
    assert_eq!(arr[0]["roster_version"], 2);
    assert!(!arr[0]["roster"]["canonical_b64"]
        .as_str()
        .unwrap()
        .is_empty());

    // bob accepts. Server doesn't decrypt protected_org_key — placeholder ok.
    let accept_body = json!({
        "protected_org_key": enc_placeholder(),
        "org_sym_key_id": key_id,
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/accept"),
            &token_b,
            Some(&accept_body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // bob list orgs → sees Acme as user, member_count = 2.
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/account/orgs", &token_b, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v[0]["id"], org_id);
    assert_eq!(v[0]["role"], "user");
    assert_eq!(v[0]["member_count"], 2);

    // bob's pending invite row was cleared on accept.
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/account/invites", &token_b, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn invite_rejects_non_owner() {
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let (uid_c, _, _) = register(&app, "carol@x.test", 3).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // bob (non-owner, non-member) tries to invite carol. Server should
    // refuse without revealing the org details.
    let genesis_b64 = create_body["roster"]["canonical_b64"].as_str().unwrap();
    let parent_hash =
        hekate_core::org_roster::hash_canonical(&STANDARD_NO_PAD.decode(genesis_b64).unwrap());
    let next = OrgRoster {
        org_id: org_id.clone(),
        version: 2,
        parent_canonical_sha256: parent_hash,
        timestamp: "2026-05-03T00:01:00+00:00".into(),
        entries: vec![
            OrgRosterEntry {
                user_id: uid_a,
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: uid_c.clone(),
                role: "user".into(),
            },
        ],
        org_sym_key_id: key_id,
    };
    let signed_next = next.sign(&org_sk);
    let invite_body = json!({
        "invitee_user_id": uid_c,
        "role": "user",
        "envelope": {"opaque": "x"},
        "next_roster": {
            "canonical_b64": signed_next.canonical_b64,
            "signature_b64": signed_next.signature_b64,
        },
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/invites"),
            &token_b,
            Some(&invite_body),
        ))
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::NOT_FOUND,
        "non-owner must be rejected (got {})",
        resp.status()
    );
    let _ = uid_b;
}

#[tokio::test]
async fn accept_rejects_when_no_pending_invite() {
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (_uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    let (create_body, org_id, _) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = json!({
        "protected_org_key": enc_placeholder(),
        "org_sym_key_id": key_id,
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/accept"),
            &token_b,
            Some(&body),
        ))
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::FORBIDDEN,
        "accept without invite must be rejected (got {})",
        resp.status()
    );
}

#[tokio::test]
async fn sync_returns_signed_roster_for_members() {
    // M4.2: GET /api/v1/sync returns each member's orgs[] entry with
    // the latest signed roster, so the client can verify it under the
    // pinned org signing pubkey on every routine read.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();

    // alice solo: /sync returns her org with the v1 (genesis) roster.
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/sync", &token_a, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    let orgs = v["orgs"].as_array().expect("orgs array");
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0]["org_id"], org_id);
    assert_eq!(orgs[0]["role"], "owner");
    assert_eq!(orgs[0]["roster_version"], 1);
    assert!(!orgs[0]["roster"]["canonical_b64"]
        .as_str()
        .unwrap()
        .is_empty());
    assert!(!orgs[0]["roster"]["signature_b64"]
        .as_str()
        .unwrap()
        .is_empty());

    // bob isn't a member yet → /sync returns no orgs.
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/sync", &token_b, None))
        .await
        .unwrap();
    let v = body_json(resp).await;
    assert_eq!(v["orgs"].as_array().unwrap().len(), 0);

    // alice invites bob, bob accepts, then /sync for bob should now
    // include the v2 roster.
    let genesis_b64 = create_body["roster"]["canonical_b64"].as_str().unwrap();
    let parent_hash =
        hekate_core::org_roster::hash_canonical(&STANDARD_NO_PAD.decode(genesis_b64).unwrap());
    let next = OrgRoster {
        org_id: org_id.clone(),
        version: 2,
        parent_canonical_sha256: parent_hash,
        timestamp: "2026-05-03T00:01:00+00:00".into(),
        entries: vec![
            OrgRosterEntry {
                user_id: uid_a.clone(),
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: uid_b.clone(),
                role: "user".into(),
            },
        ],
        org_sym_key_id: key_id.clone(),
    };
    let signed_next = next.sign(&org_sk);
    let invite_body = json!({
        "invitee_user_id": uid_b,
        "role": "user",
        "envelope": {"opaque": "x"},
        "next_roster": {
            "canonical_b64": signed_next.canonical_b64,
            "signature_b64": signed_next.signature_b64,
        },
    });
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/invites"),
            &token_a,
            Some(&invite_body),
        ))
        .await
        .unwrap();
    let accept_body = json!({
        "protected_org_key": enc_placeholder(),
        "org_sym_key_id": key_id,
    });
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/accept"),
            &token_b,
            Some(&accept_body),
        ))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/sync", &token_b, None))
        .await
        .unwrap();
    let v = body_json(resp).await;
    let orgs = v["orgs"].as_array().unwrap();
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0]["org_id"], org_id);
    assert_eq!(orgs[0]["role"], "user");
    assert_eq!(orgs[0]["roster_version"], 2);
}

#[allow(clippy::too_many_arguments)]
async fn accept_member(
    app: &Router,
    org_id: &str,
    org_sk: &SigningKey,
    owner_id: &str,
    owner_token: &str,
    invitee_id: &str,
    invitee_token: &str,
    key_id: &str,
    next_version: u64,
    parent_hash: [u8; 32],
) -> Vec<u8> {
    let next = OrgRoster {
        org_id: org_id.into(),
        version: next_version,
        parent_canonical_sha256: parent_hash,
        timestamp: "2026-05-03T00:01:00+00:00".into(),
        entries: vec![
            OrgRosterEntry {
                user_id: owner_id.into(),
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: invitee_id.into(),
                role: "user".into(),
            },
        ],
        org_sym_key_id: key_id.into(),
    };
    let signed = next.sign(org_sk);
    let invite_body = json!({
        "invitee_user_id": invitee_id,
        "role": "user",
        "envelope": {"opaque": "x"},
        "next_roster": {
            "canonical_b64": signed.canonical_b64.clone(),
            "signature_b64": signed.signature_b64,
        },
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/invites"),
            owner_token,
            Some(&invite_body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let accept = json!({
        "protected_org_key": enc_placeholder(),
        "org_sym_key_id": key_id,
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/accept"),
            invitee_token,
            Some(&accept),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    STANDARD_NO_PAD.decode(signed.canonical_b64).unwrap()
}

#[tokio::test]
async fn collection_crud_round_trip() {
    // M4.3: owner creates a collection; member can list it; non-member
    // cannot.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let (_uid_c, _, _) = register(&app, "carol@x.test", 3).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;
    let token_c = login(&app, "carol@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();

    // Bring bob in as a member.
    let genesis_b64 = create_body["roster"]["canonical_b64"].as_str().unwrap();
    let parent =
        hekate_core::org_roster::hash_canonical(&STANDARD_NO_PAD.decode(genesis_b64).unwrap());
    let _ = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent,
    )
    .await;

    // alice (owner) creates a collection.
    let coll_id = Uuid::now_v7().to_string();
    let body = json!({"id": coll_id, "name": enc_placeholder()});
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/collections"),
            &token_a,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // bob (member) sees it on list.
    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/orgs/{org_id}/collections"),
            &token_b,
            None,
        ))
        .await
        .unwrap();
    let v = body_json(resp).await;
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!(v[0]["id"], coll_id);

    // carol (non-member) gets 404.
    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/orgs/{org_id}/collections"),
            &token_c,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // bob (non-owner) can't delete.
    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/orgs/{org_id}/collections/{coll_id}"),
            &token_b,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND); // disguised as 404

    // alice (owner) deletes.
    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/orgs/{org_id}/collections/{coll_id}"),
            &token_a,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn org_cipher_create_and_sync_visible_to_members() {
    // M4.3: a member creates an org-owned cipher pinned to a
    // collection; another member sees it on /sync with org_id and
    // collection_ids set.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let (_uid_c, _, _) = register(&app, "carol@x.test", 3).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;
    let token_c = login(&app, "carol@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let genesis_b64 = create_body["roster"]["canonical_b64"].as_str().unwrap();
    let parent =
        hekate_core::org_roster::hash_canonical(&STANDARD_NO_PAD.decode(genesis_b64).unwrap());
    let _ = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent,
    )
    .await;

    // alice creates a collection.
    let coll_id = Uuid::now_v7().to_string();
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/collections"),
            &token_a,
            Some(&json!({"id": coll_id, "name": enc_placeholder()})),
        ))
        .await
        .unwrap();

    // alice creates an org-owned cipher in that collection.
    let cipher_id = Uuid::now_v7().to_string();
    let cipher_body = json!({
        "id": cipher_id,
        "type": 1, // login
        "protected_cipher_key": enc_placeholder(),
        "name": enc_placeholder(),
        "data": enc_placeholder(),
        "favorite": false,
        "org_id": org_id,
        "collection_ids": [coll_id],
    });
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/ciphers", &token_a, Some(&cipher_body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = body_json(resp).await;
    assert_eq!(v["id"], cipher_id);
    assert_eq!(v["org_id"], org_id);
    assert_eq!(v["collection_ids"][0], coll_id);
    assert_eq!(v["folder_id"], serde_json::Value::Null);
    // Owner gets implicit `manage` on every cipher.
    assert_eq!(v["permission"], "manage");

    // M4.4: bob is a member of the org but has NO collection_members
    // row, so bob's /sync returns no ciphers (M4.3's "every member
    // sees everything" was tightened in M4.4).
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/sync", &token_b, None))
        .await
        .unwrap();
    let v = body_json(resp).await;
    assert_eq!(
        v["changes"]["ciphers"].as_array().unwrap().len(),
        0,
        "without a collection_members row, bob should not see the org cipher"
    );

    // alice grants bob `read` on the collection.
    let resp = app
        .clone()
        .oneshot(req(
            "PUT",
            &format!("/api/v1/orgs/{org_id}/collections/{coll_id}/members/{uid_b}"),
            &token_a,
            Some(&json!({"permission": "read"})),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Now bob's /sync sees the cipher with permission=read.
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/sync", &token_b, None))
        .await
        .unwrap();
    let v = body_json(resp).await;
    let ciphers = v["changes"]["ciphers"].as_array().unwrap();
    assert_eq!(ciphers.len(), 1);
    assert_eq!(ciphers[0]["id"], cipher_id);
    assert_eq!(ciphers[0]["org_id"], org_id);
    assert_eq!(ciphers[0]["collection_ids"][0], coll_id);
    assert_eq!(ciphers[0]["permission"], "read");

    // carol (non-member) does NOT see the cipher.
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/sync", &token_c, None))
        .await
        .unwrap();
    let v = body_json(resp).await;
    assert_eq!(v["changes"]["ciphers"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn org_cipher_rejects_collection_in_other_org() {
    // M4.3: server must validate that every collection_id belongs to
    // the cipher's claimed org_id.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let token_a = login(&app, "alice@x.test").await;

    // Two orgs: Acme (alice owner) and Bogus (also alice, different org_sk).
    let (acme_body, acme_id, _acme_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&acme_body)))
        .await
        .unwrap();
    // Second org with a different signing key seed (build_create_body
    // uses [0xa5; 32] every call — manually override).
    let other_org_id = Uuid::now_v7().to_string();
    let other_sk = SigningKey::from_bytes(&[0xb6u8; 32]);
    let other_pk = other_sk.verifying_key().to_bytes();
    let bundle = org_bundle_canonical(&other_org_id, "Other", &other_pk, &uid_a);
    let bundle_sig = sk_a.sign(&bundle);
    let other_sym_id = Uuid::now_v7().to_string();
    let roster = OrgRoster {
        org_id: other_org_id.clone(),
        version: 1,
        parent_canonical_sha256: NO_PARENT_HASH,
        timestamp: "2026-05-03T00:00:00+00:00".into(),
        entries: vec![OrgRosterEntry {
            user_id: uid_a.clone(),
            role: "owner".into(),
        }],
        org_sym_key_id: other_sym_id.clone(),
    };
    let signed = roster.sign(&other_sk);
    let body = json!({
        "id": other_org_id,
        "name": "Other",
        "signing_pubkey": b64(&other_pk),
        "bundle_sig": b64(&bundle_sig.to_bytes()),
        "protected_signing_seed": enc_placeholder(),
        "org_sym_key_id": other_sym_id,
        "owner_protected_org_key": enc_placeholder(),
        "roster": {"canonical_b64": signed.canonical_b64, "signature_b64": signed.signature_b64},
    });
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&body)))
        .await
        .unwrap();

    // Create a collection in Acme.
    let acme_coll = Uuid::now_v7().to_string();
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{acme_id}/collections"),
            &token_a,
            Some(&json!({"id": acme_coll, "name": enc_placeholder()})),
        ))
        .await
        .unwrap();

    // Try to create a cipher in `other_org_id` referencing Acme's collection.
    let cipher_id = Uuid::now_v7().to_string();
    let cipher_body = json!({
        "id": cipher_id,
        "type": 1,
        "protected_cipher_key": enc_placeholder(),
        "name": enc_placeholder(),
        "data": enc_placeholder(),
        "favorite": false,
        "org_id": other_org_id,
        "collection_ids": [acme_coll],
    });
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/ciphers", &token_a, Some(&cipher_body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err = body_json(resp).await;
    assert!(err["error"].as_str().unwrap_or("").contains("not in org"));
}

#[tokio::test]
async fn permission_grant_revoke_round_trip() {
    // Owner grants bob `read` on a collection, then revokes it. Bob
    // first gains and then loses access to the cipher in that
    // collection.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD
            .decode(create_body["roster"]["canonical_b64"].as_str().unwrap())
            .unwrap(),
    );
    let _ = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent,
    )
    .await;

    // alice creates collection + cipher.
    let coll_id = Uuid::now_v7().to_string();
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/collections"),
            &token_a,
            Some(&json!({"id": coll_id, "name": enc_placeholder()})),
        ))
        .await
        .unwrap();
    let cipher_id = Uuid::now_v7().to_string();
    app.clone()
        .oneshot(req(
            "POST",
            "/api/v1/ciphers",
            &token_a,
            Some(&json!({
                "id": cipher_id,
                "type": 1,
                "protected_cipher_key": enc_placeholder(),
                "name": enc_placeholder(),
                "data": enc_placeholder(),
                "favorite": false,
                "org_id": org_id,
                "collection_ids": [coll_id],
            })),
        ))
        .await
        .unwrap();

    // grant read
    let resp = app
        .clone()
        .oneshot(req(
            "PUT",
            &format!("/api/v1/orgs/{org_id}/collections/{coll_id}/members/{uid_b}"),
            &token_a,
            Some(&json!({"permission": "read"})),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["permission"], "read");

    // bob can read but not write
    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/ciphers/{cipher_id}"),
            &token_b,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["permission"], "read");

    let mut update = json!({
        "id": cipher_id,
        "type": 1,
        "protected_cipher_key": enc_placeholder(),
        "name": enc_placeholder(),
        "data": enc_placeholder(),
        "favorite": false,
        "org_id": org_id,
        "collection_ids": [coll_id],
    });
    update["favorite"] = json!(true);
    let put = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/ciphers/{cipher_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {token_b}"))
        .header("content-type", "application/json")
        .header("if-match", v["revision_date"].as_str().unwrap())
        .body(Body::from(update.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(put).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // upgrade to manage — bob can now write
    let resp = app
        .clone()
        .oneshot(req(
            "PUT",
            &format!("/api/v1/orgs/{org_id}/collections/{coll_id}/members/{uid_b}"),
            &token_a,
            Some(&json!({"permission": "manage"})),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let put = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/ciphers/{cipher_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {token_b}"))
        .header("content-type", "application/json")
        .header("if-match", v["revision_date"].as_str().unwrap())
        .body(Body::from(update.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(put).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // revoke — bob loses visibility entirely
    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/orgs/{org_id}/collections/{coll_id}/members/{uid_b}"),
            &token_a,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/ciphers/{cipher_id}"),
            &token_b,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn permission_max_across_collections() {
    // Cipher in two collections; bob has `read_hide_passwords` in
    // one and `manage` in the other → effective permission is
    // `manage`.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD
            .decode(create_body["roster"]["canonical_b64"].as_str().unwrap())
            .unwrap(),
    );
    let _ = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent,
    )
    .await;

    let coll_a = Uuid::now_v7().to_string();
    let coll_b = Uuid::now_v7().to_string();
    for c in [&coll_a, &coll_b] {
        app.clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/orgs/{org_id}/collections"),
                &token_a,
                Some(&json!({"id": c, "name": enc_placeholder()})),
            ))
            .await
            .unwrap();
    }
    let cipher_id = Uuid::now_v7().to_string();
    app.clone()
        .oneshot(req(
            "POST",
            "/api/v1/ciphers",
            &token_a,
            Some(&json!({
                "id": cipher_id,
                "type": 1,
                "protected_cipher_key": enc_placeholder(),
                "name": enc_placeholder(),
                "data": enc_placeholder(),
                "favorite": false,
                "org_id": org_id,
                "collection_ids": [coll_a, coll_b],
            })),
        ))
        .await
        .unwrap();

    // bob: read_hide_passwords on A, manage on B
    app.clone()
        .oneshot(req(
            "PUT",
            &format!("/api/v1/orgs/{org_id}/collections/{coll_a}/members/{uid_b}"),
            &token_a,
            Some(&json!({"permission": "read_hide_passwords"})),
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(req(
            "PUT",
            &format!("/api/v1/orgs/{org_id}/collections/{coll_b}/members/{uid_b}"),
            &token_a,
            Some(&json!({"permission": "manage"})),
        ))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/ciphers/{cipher_id}"),
            &token_b,
            None,
        ))
        .await
        .unwrap();
    let v = body_json(resp).await;
    assert_eq!(v["permission"], "manage");
}

#[tokio::test]
async fn grant_rejects_non_owner() {
    // Even a member with `manage` on the collection cannot grant
    // permissions — that's owner-only in M4.4.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let (uid_c, _, _) = register(&app, "carol@x.test", 3).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD
            .decode(create_body["roster"]["canonical_b64"].as_str().unwrap())
            .unwrap(),
    );
    let _ = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent,
    )
    .await;

    let coll_id = Uuid::now_v7().to_string();
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/collections"),
            &token_a,
            Some(&json!({"id": coll_id, "name": enc_placeholder()})),
        ))
        .await
        .unwrap();
    // alice grants bob manage so bob has a strong permission on
    // the collection. Bob still can't grant carol permissions.
    app.clone()
        .oneshot(req(
            "PUT",
            &format!("/api/v1/orgs/{org_id}/collections/{coll_id}/members/{uid_b}"),
            &token_a,
            Some(&json!({"permission": "manage"})),
        ))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(req(
            "PUT",
            &format!("/api/v1/orgs/{org_id}/collections/{coll_id}/members/{uid_c}"),
            &token_b,
            Some(&json!({"permission": "read"})),
        ))
        .await
        .unwrap();
    // 404 (disguised; same shape as other owner-only endpoints).
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn move_to_org_then_move_to_personal_round_trip() {
    // M4.5a: alice creates a personal cipher, moves it into the org
    // (placing it in a collection), then moves it back. After each
    // step the cipher's ownership and collection assignment is
    // updated and the revision_date bumps.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let token_a = login(&app, "alice@x.test").await;

    let (create_body, org_id, _org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();

    let coll_id = Uuid::now_v7().to_string();
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/collections"),
            &token_a,
            Some(&json!({"id": coll_id, "name": enc_placeholder()})),
        ))
        .await
        .unwrap();

    // alice creates a personal cipher.
    let cipher_id = Uuid::now_v7().to_string();
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/ciphers",
            &token_a,
            Some(&json!({
                "id": cipher_id,
                "type": 1,
                "protected_cipher_key": enc_placeholder(),
                "name": enc_placeholder(),
                "data": enc_placeholder(),
                "favorite": false,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v0 = body_json(resp).await;
    assert_eq!(v0["org_id"], serde_json::Value::Null);
    let rev0 = v0["revision_date"].as_str().unwrap().to_string();

    // move-to-org
    let move_body = json!({
        "org_id": org_id,
        "collection_ids": [coll_id],
        "protected_cipher_key": enc_placeholder(),
        "name": enc_placeholder(),
        "data": enc_placeholder(),
        "favorite": false,
    });
    let post = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/ciphers/{cipher_id}/move-to-org"))
        .header(header::AUTHORIZATION, format!("Bearer {token_a}"))
        .header("content-type", "application/json")
        .header("if-match", &rev0)
        .body(Body::from(move_body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(post).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v1 = body_json(resp).await;
    assert_eq!(v1["id"], cipher_id);
    assert_eq!(v1["org_id"], org_id);
    assert_eq!(v1["collection_ids"][0], coll_id);
    assert_ne!(v1["revision_date"].as_str().unwrap(), rev0);
    assert_eq!(v1["permission"], "manage");
    let rev1 = v1["revision_date"].as_str().unwrap().to_string();

    // move-to-personal
    let back_body = json!({
        "protected_cipher_key": enc_placeholder(),
        "name": enc_placeholder(),
        "data": enc_placeholder(),
        "favorite": false,
    });
    let post = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/ciphers/{cipher_id}/move-to-personal"))
        .header(header::AUTHORIZATION, format!("Bearer {token_a}"))
        .header("content-type", "application/json")
        .header("if-match", &rev1)
        .body(Body::from(back_body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(post).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v2 = body_json(resp).await;
    assert_eq!(v2["id"], cipher_id);
    assert_eq!(v2["org_id"], serde_json::Value::Null);
    assert!(v2["collection_ids"]
        .as_array()
        .map(|a| a.is_empty())
        .unwrap_or(true));
    assert_ne!(v2["revision_date"].as_str().unwrap(), rev1);
    assert_eq!(v2["permission"], "manage");
}

#[tokio::test]
async fn move_to_org_rejects_collection_in_other_org() {
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let token_a = login(&app, "alice@x.test").await;

    // Two orgs: Acme + Other.
    let (acme_body, _acme_id, _) = build_create_body(&uid_a, &sk_a, "Acme");
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&acme_body)))
        .await
        .unwrap();
    let other_id = Uuid::now_v7().to_string();
    let other_sk = SigningKey::from_bytes(&[0xb6u8; 32]);
    let other_pk = other_sk.verifying_key().to_bytes();
    let bundle = org_bundle_canonical(&other_id, "Other", &other_pk, &uid_a);
    let bundle_sig = sk_a.sign(&bundle);
    let other_sym_id = Uuid::now_v7().to_string();
    let roster = OrgRoster {
        org_id: other_id.clone(),
        version: 1,
        parent_canonical_sha256: NO_PARENT_HASH,
        timestamp: "2026-05-03T00:00:00+00:00".into(),
        entries: vec![OrgRosterEntry {
            user_id: uid_a.clone(),
            role: "owner".into(),
        }],
        org_sym_key_id: other_sym_id.clone(),
    };
    let signed = roster.sign(&other_sk);
    app.clone()
        .oneshot(req(
            "POST",
            "/api/v1/orgs",
            &token_a,
            Some(&json!({
                "id": other_id,
                "name": "Other",
                "signing_pubkey": b64(&other_pk),
                "bundle_sig": b64(&bundle_sig.to_bytes()),
                "protected_signing_seed": enc_placeholder(),
                "org_sym_key_id": other_sym_id,
                "owner_protected_org_key": enc_placeholder(),
                "roster": {
                    "canonical_b64": signed.canonical_b64,
                    "signature_b64": signed.signature_b64,
                },
            })),
        ))
        .await
        .unwrap();
    // Acme's collection
    let acme_coll = Uuid::now_v7().to_string();
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{_acme_id}/collections"),
            &token_a,
            Some(&json!({"id": acme_coll, "name": enc_placeholder()})),
        ))
        .await
        .unwrap();

    // Personal cipher.
    let cipher_id = Uuid::now_v7().to_string();
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/ciphers",
            &token_a,
            Some(&json!({
                "id": cipher_id,
                "type": 1,
                "protected_cipher_key": enc_placeholder(),
                "name": enc_placeholder(),
                "data": enc_placeholder(),
                "favorite": false,
            })),
        ))
        .await
        .unwrap();
    let rev = body_json(resp).await["revision_date"]
        .as_str()
        .unwrap()
        .to_string();

    // Try to move into "Other" with acme's collection.
    let post = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/ciphers/{cipher_id}/move-to-org"))
        .header(header::AUTHORIZATION, format!("Bearer {token_a}"))
        .header("content-type", "application/json")
        .header("if-match", &rev)
        .body(Body::from(
            json!({
                "org_id": other_id,
                "collection_ids": [acme_coll],
                "protected_cipher_key": enc_placeholder(),
                "name": enc_placeholder(),
                "data": enc_placeholder(),
                "favorite": false,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(post).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err = body_json(resp).await;
    assert!(err["error"].as_str().unwrap_or("").contains("not in org"));
}

#[tokio::test]
async fn move_to_org_rejects_when_caller_lacks_manage() {
    // bob (member, no perms) tries to move his personal cipher into
    // alice's org → 403.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD
            .decode(create_body["roster"]["canonical_b64"].as_str().unwrap())
            .unwrap(),
    );
    let _ = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent,
    )
    .await;

    let coll_id = Uuid::now_v7().to_string();
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/collections"),
            &token_a,
            Some(&json!({"id": coll_id, "name": enc_placeholder()})),
        ))
        .await
        .unwrap();

    let cipher_id = Uuid::now_v7().to_string();
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/ciphers",
            &token_b,
            Some(&json!({
                "id": cipher_id,
                "type": 1,
                "protected_cipher_key": enc_placeholder(),
                "name": enc_placeholder(),
                "data": enc_placeholder(),
                "favorite": false,
            })),
        ))
        .await
        .unwrap();
    let rev = body_json(resp).await["revision_date"]
        .as_str()
        .unwrap()
        .to_string();

    let post = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/ciphers/{cipher_id}/move-to-org"))
        .header(header::AUTHORIZATION, format!("Bearer {token_b}"))
        .header("content-type", "application/json")
        .header("if-match", &rev)
        .body(Body::from(
            json!({
                "org_id": org_id,
                "collection_ids": [coll_id],
                "protected_cipher_key": enc_placeholder(),
                "name": enc_placeholder(),
                "data": enc_placeholder(),
                "favorite": false,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(post).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_org_requires_auth() {
    let app = test_app().await;
    let body = json!({"id": "x"});
    let resp = app
        .oneshot(
            Request::post("/api/v1/orgs")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================================
// M4.5b — member removal + org-key rotation
// ============================================================================

/// Build a signed roster for the rotation flow. Sym key id is the
/// rotation TARGET (must differ from current); parent must chain from
/// the prior canonical bytes.
#[allow(clippy::too_many_arguments)]
fn rotated_roster(
    org_id: &str,
    org_sk: &SigningKey,
    version: u64,
    parent: [u8; 32],
    entries: Vec<OrgRosterEntry>,
    new_key_id: &str,
) -> (String, String) {
    let r = OrgRoster {
        org_id: org_id.into(),
        version,
        parent_canonical_sha256: parent,
        timestamp: "2026-05-03T00:02:00+00:00".into(),
        entries,
        org_sym_key_id: new_key_id.into(),
    };
    let signed = r.sign(org_sk);
    (signed.canonical_b64, signed.signature_b64)
}

/// Drop one cipher into the org so the smoke + revoke flows have
/// something to rotate. Returns `cipher_id`.
async fn make_org_cipher(app: &Router, token: &str, org_id: &str, coll_id: &str) -> String {
    let cipher_id = Uuid::now_v7().to_string();
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/ciphers",
            token,
            Some(&json!({
                "id": cipher_id,
                "type": 1,
                "protected_cipher_key": enc_placeholder(),
                "name": enc_placeholder(),
                "data": enc_placeholder(),
                "favorite": false,
                "org_id": org_id,
                "collection_ids": [coll_id],
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    cipher_id
}

#[tokio::test]
async fn revoke_round_trip() {
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();

    let genesis_b64 = create_body["roster"]["canonical_b64"].as_str().unwrap();
    let parent_v1 =
        hekate_core::org_roster::hash_canonical(&STANDARD_NO_PAD.decode(genesis_b64).unwrap());
    let v2_canonical = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent_v1,
    )
    .await;

    // alice creates a collection + cipher in it.
    let coll_id = Uuid::now_v7().to_string();
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/collections"),
            &token_a,
            Some(&json!({"id": coll_id, "name": enc_placeholder()})),
        ))
        .await
        .unwrap();
    let cipher_id = make_org_cipher(&app, &token_a, &org_id, &coll_id).await;

    // Capture alice's cipher view BEFORE revoke so we can compare wraps.
    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/ciphers/{cipher_id}"),
            &token_a,
            None,
        ))
        .await
        .unwrap();
    let pre = body_json(resp).await;
    let pre_protected = pre["protected_cipher_key"].as_str().unwrap().to_string();

    // Alice revokes bob, rotating the org sym key. Owner-only flow:
    // build a v3 roster signed under the org signing key bound to the
    // NEW key_id; rewrap_envelopes is empty (alice is the only
    // remaining member after revoke); cipher_rewraps must cover the
    // single org cipher.
    let new_key_id = Uuid::now_v7().to_string();
    let parent_v2 = hekate_core::org_roster::hash_canonical(&v2_canonical);
    let (v3_canonical_b64, v3_sig_b64) = rotated_roster(
        &org_id,
        &org_sk,
        3,
        parent_v2,
        vec![OrgRosterEntry {
            user_id: uid_a.clone(),
            role: "owner".into(),
        }],
        &new_key_id,
    );
    // A different placeholder (different key_id) so we can verify the
    // DB row was updated. Wire shape is otherwise identical so the
    // server's EncString::parse still passes.
    let new_protected_cipher_key = "v3.xc20p.ok2.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA";
    // Placeholder for the new collection-name ciphertext under the new
    // org sym key — wire shape just has to parse as EncString v3.
    let new_collection_name = "v3.xc20p.ok2.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA";
    let revoke_body = json!({
        "next_roster": {
            "canonical_b64": v3_canonical_b64,
            "signature_b64": v3_sig_b64,
        },
        "next_org_sym_key_id": new_key_id,
        "owner_protected_org_key": "v3.xc20p.ak1.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA",
        "rewrap_envelopes": [],
        "cipher_rewraps": [
            {"cipher_id": cipher_id, "protected_cipher_key": new_protected_cipher_key},
        ],
        "collection_rewraps": [
            {"collection_id": coll_id, "name": new_collection_name},
        ],
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/members/{uid_b}/revoke"),
            &token_a,
            Some(&revoke_body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "revoke must succeed");

    // bob's /sync no longer shows the cipher (his membership is gone)
    // and his orgs[] list is empty.
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/sync", &token_b, None))
        .await
        .unwrap();
    let v = body_json(resp).await;
    assert_eq!(v["orgs"].as_array().unwrap().len(), 0);
    assert_eq!(v["changes"]["ciphers"].as_array().unwrap().len(), 0);

    // alice's /sync shows the org with v3 roster + new key_id, and the
    // cipher with the new protected_cipher_key.
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/sync", &token_a, None))
        .await
        .unwrap();
    let v = body_json(resp).await;
    let orgs = v["orgs"].as_array().unwrap();
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0]["roster_version"], 3);
    assert_eq!(orgs[0]["org_sym_key_id"], new_key_id);
    let ciphers = v["changes"]["ciphers"].as_array().unwrap();
    let post = ciphers
        .iter()
        .find(|c| c["id"] == cipher_id)
        .expect("cipher present");
    assert_eq!(post["protected_cipher_key"], new_protected_cipher_key);
    assert_ne!(post["protected_cipher_key"], pre_protected);
    // Collection name was re-encrypted under the new sym key. Pre-fix
    // (M4.5b shipped without collection_rewraps) the name was left
    // encrypted under the old key, becoming permanently undecryptable.
    let collections = v["changes"]["collections"].as_array().unwrap();
    let post_coll = collections
        .iter()
        .find(|c| c["id"] == coll_id)
        .expect("collection present");
    assert_eq!(post_coll["name"], new_collection_name);
}

#[tokio::test]
async fn revoke_rejects_non_owner() {
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD
            .decode(create_body["roster"]["canonical_b64"].as_str().unwrap())
            .unwrap(),
    );
    let _ = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent,
    )
    .await;

    // Bob (member, not owner) tries to revoke alice. Server hides org
    // existence with 404 to avoid leaking ownership info.
    let new_key_id = Uuid::now_v7().to_string();
    let body = json!({
        "next_roster": {
            "canonical_b64": "AA",
            "signature_b64": "AA",
        },
        "next_org_sym_key_id": new_key_id,
        "owner_protected_org_key": enc_placeholder(),
        "rewrap_envelopes": [],
        "cipher_rewraps": [],
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/members/{uid_a}/revoke"),
            &token_b,
            Some(&body),
        ))
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::FORBIDDEN,
        "non-owner must be rejected (got {})",
        resp.status()
    );
}

#[tokio::test]
async fn revoke_rejects_skipped_member_rewrap() {
    // Alice + bob + carol; alice revokes bob. Server must reject the
    // request when the rewrap_envelopes list is missing carol (a
    // remaining non-owner member).
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let (uid_c, _, _) = register(&app, "carol@x.test", 3).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;
    let token_c = login(&app, "carol@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();

    let genesis_b64 = create_body["roster"]["canonical_b64"].as_str().unwrap();
    let parent_v1 =
        hekate_core::org_roster::hash_canonical(&STANDARD_NO_PAD.decode(genesis_b64).unwrap());
    let v2_canonical = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent_v1,
    )
    .await;
    // Bring carol in at v3 (still under the OLD sym key — invite path).
    let parent_v2 = hekate_core::org_roster::hash_canonical(&v2_canonical);
    let v3_carol = OrgRoster {
        org_id: org_id.clone(),
        version: 3,
        parent_canonical_sha256: parent_v2,
        timestamp: "2026-05-03T00:01:30+00:00".into(),
        entries: vec![
            OrgRosterEntry {
                user_id: uid_a.clone(),
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: uid_b.clone(),
                role: "user".into(),
            },
            OrgRosterEntry {
                user_id: uid_c.clone(),
                role: "user".into(),
            },
        ],
        org_sym_key_id: key_id.clone(),
    };
    let signed_v3 = v3_carol.sign(&org_sk);
    let invite_body = json!({
        "invitee_user_id": uid_c,
        "role": "user",
        "envelope": {"opaque": "x"},
        "next_roster": {
            "canonical_b64": signed_v3.canonical_b64.clone(),
            "signature_b64": signed_v3.signature_b64,
        },
    });
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/invites"),
            &token_a,
            Some(&invite_body),
        ))
        .await
        .unwrap();
    let accept_body = json!({
        "protected_org_key": enc_placeholder(),
        "org_sym_key_id": key_id,
    });
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/accept"),
            &token_c,
            Some(&accept_body),
        ))
        .await
        .unwrap();

    // Build v4 with bob removed. carol stays. Provide NO rewrap for
    // carol → server must reject.
    let new_key_id = Uuid::now_v7().to_string();
    let parent_v3 = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD.decode(&signed_v3.canonical_b64).unwrap(),
    );
    let (v4_canonical, v4_sig) = rotated_roster(
        &org_id,
        &org_sk,
        4,
        parent_v3,
        vec![
            OrgRosterEntry {
                user_id: uid_a.clone(),
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: uid_c.clone(),
                role: "user".into(),
            },
        ],
        &new_key_id,
    );
    let revoke_body = json!({
        "next_roster": {"canonical_b64": v4_canonical, "signature_b64": v4_sig},
        "next_org_sym_key_id": new_key_id,
        "owner_protected_org_key": enc_placeholder(),
        "rewrap_envelopes": [],   // missing carol
        "cipher_rewraps": [],
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/members/{uid_b}/revoke"),
            &token_a,
            Some(&revoke_body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err = body_json(resp).await;
    assert!(
        err["error"]
            .as_str()
            .unwrap_or("")
            .contains("rewrap_envelopes"),
        "expected rewrap_envelopes coverage error, got {err}"
    );
}

#[tokio::test]
async fn revoke_rejects_skipped_cipher_rewrap() {
    // Two org-owned ciphers; revoke supplies only one rewrap → must
    // reject so the other cipher isn't left under the old key.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let genesis_b64 = create_body["roster"]["canonical_b64"].as_str().unwrap();
    let parent_v1 =
        hekate_core::org_roster::hash_canonical(&STANDARD_NO_PAD.decode(genesis_b64).unwrap());
    let v2_canonical = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent_v1,
    )
    .await;

    let coll_id = Uuid::now_v7().to_string();
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/collections"),
            &token_a,
            Some(&json!({"id": coll_id, "name": enc_placeholder()})),
        ))
        .await
        .unwrap();
    let c1 = make_org_cipher(&app, &token_a, &org_id, &coll_id).await;
    let _c2 = make_org_cipher(&app, &token_a, &org_id, &coll_id).await;

    let new_key_id = Uuid::now_v7().to_string();
    let parent_v2 = hekate_core::org_roster::hash_canonical(&v2_canonical);
    let (v3_canonical, v3_sig) = rotated_roster(
        &org_id,
        &org_sk,
        3,
        parent_v2,
        vec![OrgRosterEntry {
            user_id: uid_a.clone(),
            role: "owner".into(),
        }],
        &new_key_id,
    );
    let revoke_body = json!({
        "next_roster": {"canonical_b64": v3_canonical, "signature_b64": v3_sig},
        "next_org_sym_key_id": new_key_id,
        "owner_protected_org_key": enc_placeholder(),
        "rewrap_envelopes": [],
        // Only rewrap c1 — c2 is skipped.
        "cipher_rewraps": [{"cipher_id": c1, "protected_cipher_key": enc_placeholder()}],
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/members/{uid_b}/revoke"),
            &token_a,
            Some(&revoke_body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err = body_json(resp).await;
    assert!(
        err["error"]
            .as_str()
            .unwrap_or("")
            .contains("cipher_rewraps"),
        "expected cipher_rewraps coverage error, got {err}"
    );
}

#[tokio::test]
async fn revoke_rejects_skipped_collection_rewrap() {
    // Two org collections; revoke supplies only one rewrap → must
    // reject so the other collection's name isn't left encrypted under
    // the dead old key (which would make it permanently undecryptable).
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let genesis_b64 = create_body["roster"]["canonical_b64"].as_str().unwrap();
    let parent_v1 =
        hekate_core::org_roster::hash_canonical(&STANDARD_NO_PAD.decode(genesis_b64).unwrap());
    let v2_canonical = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent_v1,
    )
    .await;

    let coll1 = Uuid::now_v7().to_string();
    let coll2 = Uuid::now_v7().to_string();
    for cid in [&coll1, &coll2] {
        app.clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/orgs/{org_id}/collections"),
                &token_a,
                Some(&json!({"id": cid, "name": enc_placeholder()})),
            ))
            .await
            .unwrap();
    }

    let new_key_id = Uuid::now_v7().to_string();
    let parent_v2 = hekate_core::org_roster::hash_canonical(&v2_canonical);
    let (v3_canonical, v3_sig) = rotated_roster(
        &org_id,
        &org_sk,
        3,
        parent_v2,
        vec![OrgRosterEntry {
            user_id: uid_a.clone(),
            role: "owner".into(),
        }],
        &new_key_id,
    );
    let revoke_body = json!({
        "next_roster": {"canonical_b64": v3_canonical, "signature_b64": v3_sig},
        "next_org_sym_key_id": new_key_id,
        "owner_protected_org_key": enc_placeholder(),
        "rewrap_envelopes": [],
        // No org-owned ciphers, so cipher_rewraps can be empty (the
        // 1:1 enumeration matches against an empty server-side set).
        "cipher_rewraps": [],
        // Only rewrap coll1 — coll2 is skipped, must reject.
        "collection_rewraps": [
            {"collection_id": coll1, "name": enc_placeholder()},
        ],
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/members/{uid_b}/revoke"),
            &token_a,
            Some(&revoke_body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err = body_json(resp).await;
    assert!(
        err["error"]
            .as_str()
            .unwrap_or("")
            .contains("collection_rewraps"),
        "expected collection_rewraps coverage error, got {err}"
    );
}

#[tokio::test]
async fn revoke_rejects_same_key_id() {
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let genesis_b64 = create_body["roster"]["canonical_b64"].as_str().unwrap();
    let parent_v1 =
        hekate_core::org_roster::hash_canonical(&STANDARD_NO_PAD.decode(genesis_b64).unwrap());
    let _v2 = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent_v1,
    )
    .await;

    // next_org_sym_key_id == current → must 400.
    let body = json!({
        "next_roster": {"canonical_b64": "AA", "signature_b64": "AA"},
        "next_org_sym_key_id": key_id,    // same as current
        "owner_protected_org_key": enc_placeholder(),
        "rewrap_envelopes": [],
        "cipher_rewraps": [],
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/members/{uid_b}/revoke"),
            &token_a,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err = body_json(resp).await;
    assert!(err["error"]
        .as_str()
        .unwrap_or("")
        .contains("differ from the current"));
}

#[tokio::test]
async fn rotate_confirm_clears_envelope() {
    // alice + bob + carol; alice revokes bob. Carol's /sync surfaces
    // a pending_envelope; after carol POSTs /rotate-confirm, the
    // pending field is cleared and her org_sym_key_id has advanced.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let (uid_c, _, _) = register(&app, "carol@x.test", 3).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;
    let token_c = login(&app, "carol@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let genesis_b64 = create_body["roster"]["canonical_b64"].as_str().unwrap();
    let parent_v1 =
        hekate_core::org_roster::hash_canonical(&STANDARD_NO_PAD.decode(genesis_b64).unwrap());
    let v2_canonical = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent_v1,
    )
    .await;
    // Bring carol in at v3.
    let parent_v2 = hekate_core::org_roster::hash_canonical(&v2_canonical);
    let v3_carol = OrgRoster {
        org_id: org_id.clone(),
        version: 3,
        parent_canonical_sha256: parent_v2,
        timestamp: "2026-05-03T00:01:30+00:00".into(),
        entries: vec![
            OrgRosterEntry {
                user_id: uid_a.clone(),
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: uid_b.clone(),
                role: "user".into(),
            },
            OrgRosterEntry {
                user_id: uid_c.clone(),
                role: "user".into(),
            },
        ],
        org_sym_key_id: key_id.clone(),
    };
    let signed_v3 = v3_carol.sign(&org_sk);
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/invites"),
            &token_a,
            Some(&json!({
                "invitee_user_id": uid_c,
                "role": "user",
                "envelope": {"opaque": "x"},
                "next_roster": {
                    "canonical_b64": signed_v3.canonical_b64.clone(),
                    "signature_b64": signed_v3.signature_b64,
                },
            })),
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/accept"),
            &token_c,
            Some(&json!({
                "protected_org_key": enc_placeholder(),
                "org_sym_key_id": key_id,
            })),
        ))
        .await
        .unwrap();

    // Revoke bob, rotate to new key. Provide a (server-opaque)
    // rewrap envelope for carol.
    let new_key_id = Uuid::now_v7().to_string();
    let parent_v3 = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD.decode(&signed_v3.canonical_b64).unwrap(),
    );
    let (v4_canonical, v4_sig) = rotated_roster(
        &org_id,
        &org_sk,
        4,
        parent_v3,
        vec![
            OrgRosterEntry {
                user_id: uid_a.clone(),
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: uid_c.clone(),
                role: "user".into(),
            },
        ],
        &new_key_id,
    );
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/members/{uid_b}/revoke"),
            &token_a,
            Some(&json!({
                "next_roster": {"canonical_b64": v4_canonical, "signature_b64": v4_sig},
                "next_org_sym_key_id": new_key_id,
                "owner_protected_org_key": enc_placeholder(),
                "rewrap_envelopes": [
                    {"user_id": uid_c, "envelope": {"opaque-rotation-envelope": "x"}}
                ],
                "cipher_rewraps": [],
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Carol's /sync surfaces pending_envelope, with org_sym_key_id =
    // new (the org's current). Her membership row still references
    // the OLD key_id until she confirms — but the OrgSyncEntry
    // reports the org_sym_key_id from the *member row*, which we
    // expose so the client can compare against the (verified) roster.
    // What matters here is that pending_envelope is non-null.
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/sync", &token_c, None))
        .await
        .unwrap();
    let v = body_json(resp).await;
    let orgs = v["orgs"].as_array().unwrap();
    let me = orgs.iter().find(|o| o["org_id"] == org_id).unwrap();
    assert!(
        !me["pending_envelope"].is_null(),
        "carol should see a pending_envelope after rotation"
    );

    // Carol confirms with a fresh EncString and the NEW key_id.
    // Different key_id (ak2) so we can confirm the DB row swapped.
    let new_protected = "v3.xc20p.ak2.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA";
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/rotate-confirm"),
            &token_c,
            Some(&json!({
                "protected_org_key": new_protected,
                "org_sym_key_id": new_key_id,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Pending field cleared; org_sym_key_id advanced.
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/sync", &token_c, None))
        .await
        .unwrap();
    let v = body_json(resp).await;
    let orgs = v["orgs"].as_array().unwrap();
    let me = orgs.iter().find(|o| o["org_id"] == org_id).unwrap();
    assert!(
        me.get("pending_envelope")
            .map(|p| p.is_null())
            .unwrap_or(true),
        "pending_envelope should be cleared after /rotate-confirm"
    );
    assert_eq!(me["org_sym_key_id"], new_key_id);

    // /api/v1/orgs/:id should return Carol's NEW protected_org_key.
    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/orgs/{org_id}"),
            &token_c,
            None,
        ))
        .await
        .unwrap();
    let v = body_json(resp).await;
    assert_eq!(v["my_protected_org_key"], new_protected);
    assert_eq!(v["org_sym_key_id"], new_key_id);
}

// ============================================================================
// M4.6 — policies
// ============================================================================

#[tokio::test]
async fn policy_set_get_list_round_trip() {
    // Owner sets master_password_complexity, member reads it; list
    // returns it. Idempotent re-PUT updates the row in place.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD
            .decode(create_body["roster"]["canonical_b64"].as_str().unwrap())
            .unwrap(),
    );
    let _ = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent,
    )
    .await;

    // Owner sets the policy.
    let body = json!({
        "enabled": true,
        "config": {"min_length": 16, "require_upper": true, "require_digit": true},
    });
    let resp = app
        .clone()
        .oneshot(req(
            "PUT",
            &format!("/api/v1/orgs/{org_id}/policies/master_password_complexity"),
            &token_a,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["policy_type"], "master_password_complexity");
    assert_eq!(v["enabled"], true);
    assert_eq!(v["config"]["min_length"], 16);

    // Re-PUT with different config — must update in place (no duplicate row).
    let body2 = json!({
        "enabled": false,
        "config": {"min_length": 24},
    });
    let resp = app
        .clone()
        .oneshot(req(
            "PUT",
            &format!("/api/v1/orgs/{org_id}/policies/master_password_complexity"),
            &token_a,
            Some(&body2),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Member can list.
    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/orgs/{org_id}/policies"),
            &token_b,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1, "PUT was upsert, not insert");
    assert_eq!(arr[0]["policy_type"], "master_password_complexity");
    assert_eq!(arr[0]["enabled"], false);
    assert_eq!(arr[0]["config"]["min_length"], 24);

    // Owner can delete.
    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/orgs/{org_id}/policies/master_password_complexity"),
            &token_a,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/orgs/{org_id}/policies"),
            &token_b,
            None,
        ))
        .await
        .unwrap();
    let v = body_json(resp).await;
    assert_eq!(v.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn policy_set_rejects_non_owner() {
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD
            .decode(create_body["roster"]["canonical_b64"].as_str().unwrap())
            .unwrap(),
    );
    let _ = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent,
    )
    .await;

    // Member (not owner) tries to set a policy. Server hides owner
    // status with 404.
    let body = json!({
        "enabled": true,
        "config": {"min_length": 16},
    });
    let resp = app
        .clone()
        .oneshot(req(
            "PUT",
            &format!("/api/v1/orgs/{org_id}/policies/master_password_complexity"),
            &token_b,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn policy_set_rejects_unknown_type() {
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let token_a = login(&app, "alice@x.test").await;
    let (create_body, org_id, _) = build_create_body(&uid_a, &sk_a, "Acme");
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();

    let body = json!({"enabled": true, "config": {}});
    let resp = app
        .clone()
        .oneshot(req(
            "PUT",
            &format!("/api/v1/orgs/{org_id}/policies/no_such_policy"),
            &token_a,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err = body_json(resp).await;
    assert!(err["error"]
        .as_str()
        .unwrap_or("")
        .contains("unknown policy_type"));
}

#[tokio::test]
async fn policy_appears_in_sync() {
    // Alice sets a policy on her org; her /sync OrgSyncEntry surfaces it.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let token_a = login(&app, "alice@x.test").await;

    let (create_body, org_id, _) = build_create_body(&uid_a, &sk_a, "Acme");
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();

    let body = json!({
        "enabled": true,
        "config": {"min_length": 20, "require_special": true},
    });
    app.clone()
        .oneshot(req(
            "PUT",
            &format!("/api/v1/orgs/{org_id}/policies/master_password_complexity"),
            &token_a,
            Some(&body),
        ))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/sync", &token_a, None))
        .await
        .unwrap();
    let v = body_json(resp).await;
    let orgs = v["orgs"].as_array().unwrap();
    let me = orgs.iter().find(|o| o["org_id"] == org_id).unwrap();
    let policies = me["policies"].as_array().expect("policies array");
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0]["policy_type"], "master_password_complexity");
    assert_eq!(policies[0]["enabled"], true);
    assert_eq!(policies[0]["config"]["min_length"], 20);
    assert_eq!(policies[0]["config"]["require_special"], true);
}

#[tokio::test]
async fn single_org_blocks_second_org_accept() {
    // Alice creates orgA, sets single_org on orgA, creates orgB BEFORE
    // single_org becomes binding for her own creates. She invites bob
    // to orgA; bob accepts (his only membership). She then invites
    // bob to orgB — bob must be blocked at /accept because his
    // existing membership in orgA carries single_org.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    // orgA
    let (org_a_body, org_a_id, org_a_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_a = org_a_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&org_a_body)))
        .await
        .unwrap();

    // orgB — distinct signing key + id.
    let org_b_id = Uuid::now_v7().to_string();
    let org_b_sk = SigningKey::from_bytes(&[0xb6u8; 32]);
    let org_b_pk = org_b_sk.verifying_key().to_bytes();
    let bundle = org_bundle_canonical(&org_b_id, "Bogus", &org_b_pk, &uid_a);
    let bundle_sig = sk_a.sign(&bundle);
    let key_b = Uuid::now_v7().to_string();
    let roster_b = OrgRoster {
        org_id: org_b_id.clone(),
        version: 1,
        parent_canonical_sha256: NO_PARENT_HASH,
        timestamp: "2026-05-03T00:00:00+00:00".into(),
        entries: vec![OrgRosterEntry {
            user_id: uid_a.clone(),
            role: "owner".into(),
        }],
        org_sym_key_id: key_b.clone(),
    };
    let signed_b = roster_b.sign(&org_b_sk);
    app.clone()
        .oneshot(req(
            "POST",
            "/api/v1/orgs",
            &token_a,
            Some(&json!({
                "id": org_b_id,
                "name": "Bogus",
                "signing_pubkey": b64(&org_b_pk),
                "bundle_sig": b64(&bundle_sig.to_bytes()),
                "protected_signing_seed": enc_placeholder(),
                "org_sym_key_id": key_b,
                "owner_protected_org_key": enc_placeholder(),
                "roster": {
                    "canonical_b64": signed_b.canonical_b64.clone(),
                    "signature_b64": signed_b.signature_b64,
                },
            })),
        ))
        .await
        .unwrap();

    // single_org on orgA.
    app.clone()
        .oneshot(req(
            "PUT",
            &format!("/api/v1/orgs/{org_a_id}/policies/single_org"),
            &token_a,
            Some(&json!({"enabled": true, "config": {}})),
        ))
        .await
        .unwrap();

    // Bring bob into orgA — he has no prior memberships, so single_org
    // doesn't apply yet.
    let parent_a = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD
            .decode(org_a_body["roster"]["canonical_b64"].as_str().unwrap())
            .unwrap(),
    );
    let _ = accept_member(
        &app, &org_a_id, &org_a_sk, &uid_a, &token_a, &uid_b, &token_b, &key_a, 2, parent_a,
    )
    .await;

    // Now invite bob to orgB and let him try to accept. Server must
    // reject because his orgA membership carries single_org.
    let parent_b = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD.decode(&signed_b.canonical_b64).unwrap(),
    );
    let v2_b = OrgRoster {
        org_id: org_b_id.clone(),
        version: 2,
        parent_canonical_sha256: parent_b,
        timestamp: "2026-05-03T00:01:00+00:00".into(),
        entries: vec![
            OrgRosterEntry {
                user_id: uid_a.clone(),
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: uid_b.clone(),
                role: "user".into(),
            },
        ],
        org_sym_key_id: key_b.clone(),
    };
    let signed_v2_b = v2_b.sign(&org_b_sk);
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_b_id}/invites"),
            &token_a,
            Some(&json!({
                "invitee_user_id": uid_b,
                "role": "user",
                "envelope": {"opaque": "x"},
                "next_roster": {
                    "canonical_b64": signed_v2_b.canonical_b64,
                    "signature_b64": signed_v2_b.signature_b64,
                },
            })),
        ))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_b_id}/accept"),
            &token_b,
            Some(&json!({
                "protected_org_key": enc_placeholder(),
                "org_sym_key_id": key_b,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let err = body_json(resp).await;
    assert!(err["error"].as_str().unwrap_or("").contains("single_org"));
}

// ============================================================================
// M2.21 / M4.5 follow-up — per-org signed cipher manifest
// ============================================================================

use hekate_core::org_cipher_manifest::{
    hash_canonical as hash_oc_canonical, OrgCipherEntry, OrgCipherManifest,
    NO_PARENT_HASH as OC_NO_PARENT,
};

#[tokio::test]
async fn org_cipher_manifest_round_trip_and_appears_in_sync() {
    // Owner uploads a manifest covering one cipher; member /sync
    // surfaces it; owner-only enforcement; replay rejected.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD
            .decode(create_body["roster"]["canonical_b64"].as_str().unwrap())
            .unwrap(),
    );
    let _ = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent,
    )
    .await;

    // Alice creates a collection + cipher.
    let coll_id = Uuid::now_v7().to_string();
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/collections"),
            &token_a,
            Some(&json!({"id": coll_id, "name": enc_placeholder()})),
        ))
        .await
        .unwrap();
    let cipher_id = make_org_cipher(&app, &token_a, &org_id, &coll_id).await;

    // Read the cipher's revision_date so the manifest entry matches.
    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/ciphers/{cipher_id}"),
            &token_a,
            None,
        ))
        .await
        .unwrap();
    let cipher = body_json(resp).await;
    let revision_date = cipher["revision_date"].as_str().unwrap().to_string();

    // Build + sign the genesis cipher manifest.
    let manifest_v1 = OrgCipherManifest {
        org_id: org_id.clone(),
        version: 1,
        parent_canonical_sha256: OC_NO_PARENT,
        timestamp: "2026-05-03T01:00:00+00:00".into(),
        entries: vec![OrgCipherEntry {
            cipher_id: cipher_id.clone(),
            revision_date: revision_date.clone(),
            deleted: false,
        }],
    };
    let signed = manifest_v1.sign(&org_sk);

    // Owner uploads.
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/cipher-manifest"),
            &token_a,
            Some(&json!({
                "version": 1,
                "canonical_b64": signed.canonical_b64,
                "signature_b64": signed.signature_b64,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["version"], 1);

    // Bob's /sync surfaces it under OrgSyncEntry.cipher_manifest.
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/sync", &token_b, None))
        .await
        .unwrap();
    let v = body_json(resp).await;
    let orgs = v["orgs"].as_array().unwrap();
    let me = orgs.iter().find(|o| o["org_id"] == org_id).unwrap();
    let cm = me
        .get("cipher_manifest")
        .expect("cipher_manifest field present");
    assert_eq!(cm["version"], 1);

    // Same-version replay → 409.
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/cipher-manifest"),
            &token_a,
            Some(&json!({
                "version": 1,
                "canonical_b64": signed.canonical_b64,
                "signature_b64": signed.signature_b64,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // v2 with correct parent chain succeeds.
    let canonical_v1 = STANDARD_NO_PAD.decode(&signed.canonical_b64).unwrap();
    let parent_v2 = hash_oc_canonical(&canonical_v1);
    let manifest_v2 = OrgCipherManifest {
        org_id: org_id.clone(),
        version: 2,
        parent_canonical_sha256: parent_v2,
        timestamp: "2026-05-03T01:01:00+00:00".into(),
        entries: vec![OrgCipherEntry {
            cipher_id: cipher_id.clone(),
            revision_date,
            deleted: false,
        }],
    };
    let signed_v2 = manifest_v2.sign(&org_sk);
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/cipher-manifest"),
            &token_a,
            Some(&json!({
                "version": 2,
                "canonical_b64": signed_v2.canonical_b64,
                "signature_b64": signed_v2.signature_b64,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Forked v3 — parent doesn't chain forward → 409.
    let manifest_v3_bad = OrgCipherManifest {
        org_id: org_id.clone(),
        version: 3,
        parent_canonical_sha256: [0xffu8; 32], // wrong parent
        timestamp: "2026-05-03T01:02:00+00:00".into(),
        entries: vec![],
    };
    let signed_v3 = manifest_v3_bad.sign(&org_sk);
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/cipher-manifest"),
            &token_a,
            Some(&json!({
                "version": 3,
                "canonical_b64": signed_v3.canonical_b64,
                "signature_b64": signed_v3.signature_b64,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn org_cipher_manifest_rejects_non_owner() {
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD
            .decode(create_body["roster"]["canonical_b64"].as_str().unwrap())
            .unwrap(),
    );
    let _ = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent,
    )
    .await;

    // Bob (member, not owner) tries to upload. Even with a valid
    // signature under the org signing key (which he doesn't actually
    // have, but for the test we sign it ourselves), the server hides
    // owner status with 404.
    let manifest = OrgCipherManifest {
        org_id: org_id.clone(),
        version: 1,
        parent_canonical_sha256: OC_NO_PARENT,
        timestamp: "t".into(),
        entries: vec![],
    };
    let signed = manifest.sign(&org_sk);
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/cipher-manifest"),
            &token_b,
            Some(&json!({
                "version": 1,
                "canonical_b64": signed.canonical_b64,
                "signature_b64": signed.signature_b64,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn org_cipher_manifest_rejects_bad_signature() {
    // Server validates the Ed25519 sig on upload using the org's
    // stored signing pubkey. A manifest signed by some other key —
    // even an Ed25519 key under the owner's control — fails.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let token_a = login(&app, "alice@x.test").await;
    let (create_body, org_id, _org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();

    // Sign under a key that ISN'T the org's signing key.
    let attacker = SigningKey::from_bytes(&[0xfdu8; 32]);
    let manifest = OrgCipherManifest {
        org_id: org_id.clone(),
        version: 1,
        parent_canonical_sha256: OC_NO_PARENT,
        timestamp: "t".into(),
        entries: vec![],
    };
    let signed = manifest.sign(&attacker);
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/cipher-manifest"),
            &token_a,
            Some(&json!({
                "version": 1,
                "canonical_b64": signed.canonical_b64,
                "signature_b64": signed.signature_b64,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err = body_json(resp).await;
    assert!(err["error"]
        .as_str()
        .unwrap_or("")
        .contains("signature did not verify"));
}

#[tokio::test]
async fn org_cipher_manifest_rejects_genesis_with_nonzero_parent() {
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let token_a = login(&app, "alice@x.test").await;
    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();

    let manifest = OrgCipherManifest {
        org_id: org_id.clone(),
        version: 1,
        parent_canonical_sha256: [0xa5u8; 32], // not all-zeros
        timestamp: "t".into(),
        entries: vec![],
    };
    let signed = manifest.sign(&org_sk);
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/cipher-manifest"),
            &token_a,
            Some(&json!({
                "version": 1,
                "canonical_b64": signed.canonical_b64,
                "signature_b64": signed.signature_b64,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err = body_json(resp).await;
    assert!(err["error"]
        .as_str()
        .unwrap_or("")
        .contains("parent_canonical_sha256 = zeros"));
}

// =============================================================================
// GH #2 regression coverage
// =============================================================================
//
// Before the fix, an invite atomically advanced the live signed roster
// to v=N+1 with the invitee added. Pending invites that never accepted
// left the live roster claiming a member who didn't actually exist in
// `organization_members`. These tests pin the new semantics.

#[tokio::test]
async fn invite_does_not_advance_live_roster() {
    // After invite, GET /orgs/{id} should still return the GENESIS roster
    // (v=1, owner only). The pending roster lives on the invite row, not
    // on `organizations.roster_canonical_b64`.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    let genesis_b64 = create_body["roster"]["canonical_b64"]
        .as_str()
        .unwrap()
        .to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();

    // Invite Bob.
    let parent_hash =
        hekate_core::org_roster::hash_canonical(&STANDARD_NO_PAD.decode(&genesis_b64).unwrap());
    let next = OrgRoster {
        org_id: org_id.clone(),
        version: 2,
        parent_canonical_sha256: parent_hash,
        timestamp: "2026-05-06T00:00:00+00:00".into(),
        entries: vec![
            OrgRosterEntry {
                user_id: uid_a.clone(),
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: uid_b.clone(),
                role: "user".into(),
            },
        ],
        org_sym_key_id: key_id,
    };
    let signed_next = next.sign(&org_sk);
    let invite_body = json!({
        "invitee_user_id": uid_b,
        "role": "user",
        "envelope": {"opaque": "x"},
        "next_roster": {
            "canonical_b64": signed_next.canonical_b64,
            "signature_b64": signed_next.signature_b64,
        },
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/invites"),
            &token_a,
            Some(&invite_body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Live roster should STILL be at v=1 (genesis).
    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/orgs/{org_id}"),
            &token_a,
            None,
        ))
        .await
        .unwrap();
    let v = body_json(resp).await;
    assert_eq!(v["roster_version"], 1);
    assert_eq!(v["roster"]["canonical_b64"], genesis_b64);
    // Owner sees the pending invitee on the org GET (GH #3 surface).
    assert_eq!(v["pending_invitees"][&uid_b]["role"], "user");
    assert_eq!(v["pending_invitees"][&uid_b]["email"], "bob@x.test");
}

#[tokio::test]
async fn invite_rejects_second_pending_for_same_org() {
    // Single-pending-per-org invariant: with a Bob invite outstanding,
    // a Carol invite for the same org must 409.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let (uid_c, _, _) = register(&app, "carol@x.test", 3).await;
    let token_a = login(&app, "alice@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    let genesis_b64 = create_body["roster"]["canonical_b64"]
        .as_str()
        .unwrap()
        .to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();

    let parent_hash =
        hekate_core::org_roster::hash_canonical(&STANDARD_NO_PAD.decode(&genesis_b64).unwrap());

    let next_b = OrgRoster {
        org_id: org_id.clone(),
        version: 2,
        parent_canonical_sha256: parent_hash,
        timestamp: "2026-05-06T00:00:00+00:00".into(),
        entries: vec![
            OrgRosterEntry {
                user_id: uid_a.clone(),
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: uid_b.clone(),
                role: "user".into(),
            },
        ],
        org_sym_key_id: key_id.clone(),
    };
    let signed_b = next_b.sign(&org_sk);
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/invites"),
            &token_a,
            Some(&json!({
                "invitee_user_id": uid_b,
                "role": "user",
                "envelope": {"opaque": "x"},
                "next_roster": {
                    "canonical_b64": signed_b.canonical_b64,
                    "signature_b64": signed_b.signature_b64,
                },
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Now try Carol with another v=2 → 409 single-pending invariant.
    let next_c = OrgRoster {
        org_id: org_id.clone(),
        version: 2,
        parent_canonical_sha256: parent_hash,
        timestamp: "2026-05-06T00:00:01+00:00".into(),
        entries: vec![
            OrgRosterEntry {
                user_id: uid_a,
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: uid_c.clone(),
                role: "user".into(),
            },
        ],
        org_sym_key_id: key_id,
    };
    let signed_c = next_c.sign(&org_sk);
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/invites"),
            &token_a,
            Some(&json!({
                "invitee_user_id": uid_c,
                "role": "user",
                "envelope": {"opaque": "y"},
                "next_roster": {
                    "canonical_b64": signed_c.canonical_b64,
                    "signature_b64": signed_c.signature_b64,
                },
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn cancel_invite_does_not_require_next_roster() {
    // Pre-fix the cancel handler required a re-signed rolled-back roster.
    // Post-fix it just deletes the invite row; live roster never moved
    // so there's nothing to roll back.
    let app = test_app().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    let genesis_b64 = create_body["roster"]["canonical_b64"]
        .as_str()
        .unwrap()
        .to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();

    let parent_hash =
        hekate_core::org_roster::hash_canonical(&STANDARD_NO_PAD.decode(&genesis_b64).unwrap());
    let next = OrgRoster {
        org_id: org_id.clone(),
        version: 2,
        parent_canonical_sha256: parent_hash,
        timestamp: "2026-05-06T00:00:00+00:00".into(),
        entries: vec![
            OrgRosterEntry {
                user_id: uid_a,
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: uid_b.clone(),
                role: "user".into(),
            },
        ],
        org_sym_key_id: key_id,
    };
    let signed = next.sign(&org_sk);
    app.clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/invites"),
            &token_a,
            Some(&json!({
                "invitee_user_id": uid_b,
                "role": "user",
                "envelope": {"opaque": "x"},
                "next_roster": {
                    "canonical_b64": signed.canonical_b64,
                    "signature_b64": signed.signature_b64,
                },
            })),
        ))
        .await
        .unwrap();

    // Cancel with EMPTY body — server must not require next_roster.
    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/orgs/{org_id}/invites/{uid_b}"),
            &token_a,
            Some(&json!({})),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // After cancel, live roster is still v=1 (genesis) and pending list
    // is empty.
    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/orgs/{org_id}"),
            &token_a,
            None,
        ))
        .await
        .unwrap();
    let v = body_json(resp).await;
    assert_eq!(v["roster_version"], 1);
    assert!(
        v["pending_invitees"]
            .as_object()
            .map(|o| o.is_empty())
            .unwrap_or(true),
        "pending_invitees should be empty/absent after cancel: {}",
        v["pending_invitees"]
    );
}

// ============================================================================
// Roster prune — recovery from roster ↔ organization_members divergence
// ============================================================================
//
// Prune is the recovery primitive for the case where the signed roster
// claims a user is in the org but `organization_members` says they
// aren't. Pre-GH#2 (migration 0023), this happened naturally because
// the roster advanced at invite-time. Post-GH#2 it's only reachable
// via a partial-failure DB state, so the tests below construct it
// directly via the AppState pool.
//
// The owner-only endpoint accepts a v(N+1) roster that is a STRICT
// SUBSET of the current roster, every surviving entry maps to
// `organization_members`, and the owner is still present. It does
// NOT rotate the org sym key (orphans never received it because the
// key is signcrypted at accept-time, not invite-time).

/// Inject a stale roster v(N+1) signed by `org_sk` containing
/// `extra_orphan_user_id` in addition to whatever the current roster
/// already has. Bypasses the API — the post-GH#2 server won't produce
/// this state on its own. Returns the new (canonical_b64, version).
async fn inject_orphan_into_roster(
    state: &AppState,
    org_id: &str,
    org_sk: &SigningKey,
    extra_orphan_user_id: &str,
    extra_orphan_role: &str,
) -> (String, u64) {
    // Pull current roster.
    let row: (i64, String, String) = sqlx::query_as(
        "SELECT roster_version, roster_canonical_b64, org_sym_key_id
           FROM organizations WHERE id = $1",
    )
    .bind(org_id)
    .fetch_one(state.db.pool())
    .await
    .expect("read current roster");
    let (cur_version, cur_canonical_b64, cur_sym_key_id) = row;
    let cur_canonical = STANDARD_NO_PAD.decode(&cur_canonical_b64).unwrap();
    let cur = hekate_core::org_roster::decode_canonical(&cur_canonical).unwrap();

    let mut entries = cur.entries.clone();
    entries.push(OrgRosterEntry {
        user_id: extra_orphan_user_id.into(),
        role: extra_orphan_role.into(),
    });
    let next_version = cur_version as u64 + 1;
    let next = OrgRoster {
        org_id: org_id.into(),
        version: next_version,
        parent_canonical_sha256: hekate_core::org_roster::hash_canonical(&cur_canonical),
        timestamp: "2026-05-09T00:00:00+00:00".into(),
        entries,
        org_sym_key_id: cur_sym_key_id,
    };
    let signed = next.sign(org_sk);
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE organizations
            SET roster_version = $1,
                roster_canonical_b64 = $2,
                roster_signature_b64 = $3,
                roster_updated_at = $4,
                revision_date = $4
          WHERE id = $5",
    )
    .bind(next_version as i64)
    .bind(&signed.canonical_b64)
    .bind(&signed.signature_b64)
    .bind(&now)
    .bind(org_id)
    .execute(state.db.pool())
    .await
    .expect("inject stale roster");
    (signed.canonical_b64, next_version)
}

/// Build + sign a roster from explicit entries. Caller controls
/// version, parent hash, and entry list — used to construct
/// next-roster bodies for prune POSTs.
fn build_signed_roster(
    org_id: &str,
    version: u64,
    parent_canonical_sha256: [u8; 32],
    org_sk: &SigningKey,
    org_sym_key_id: &str,
    entries: Vec<OrgRosterEntry>,
) -> (String, String) {
    let r = OrgRoster {
        org_id: org_id.into(),
        version,
        parent_canonical_sha256,
        timestamp: "2026-05-09T00:01:00+00:00".into(),
        entries,
        org_sym_key_id: org_sym_key_id.into(),
    };
    let signed = r.sign(org_sk);
    (signed.canonical_b64, signed.signature_b64)
}

#[tokio::test]
async fn prune_drops_orphan_happy_path() {
    let (app, state) = test_app_with_state().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();

    // Inject orphan: bob is in the live signed roster but NOT in
    // organization_members (he never accepted).
    let (stale_canonical_b64, stale_version) =
        inject_orphan_into_roster(&state, &org_id, &org_sk, &uid_b, "user").await;
    assert_eq!(
        stale_version, 2,
        "genesis was v=1, orphan injection bumps to v=2"
    );

    // Confirm the divergence: roster has 2 entries, members table has 1.
    let stale = hekate_core::org_roster::decode_canonical(
        &STANDARD_NO_PAD.decode(&stale_canonical_b64).unwrap(),
    )
    .unwrap();
    assert_eq!(stale.entries.len(), 2);
    let member_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM organization_members WHERE org_id = $1")
            .bind(&org_id)
            .fetch_one(state.db.pool())
            .await
            .unwrap();
    assert_eq!(member_count.0, 1, "only alice is in organization_members");

    // Owner posts a prune dropping bob.
    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD.decode(&stale_canonical_b64).unwrap(),
    );
    let (next_canonical_b64, next_signature_b64) = build_signed_roster(
        &org_id,
        stale_version + 1,
        parent,
        &org_sk,
        &key_id,
        vec![OrgRosterEntry {
            user_id: uid_a.clone(),
            role: "owner".into(),
        }],
    );
    let body = json!({
        "next_roster": {
            "canonical_b64": next_canonical_b64,
            "signature_b64": next_signature_b64,
        }
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/prune-roster"),
            &token_a,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Roster is v=3 with just alice. Members table unchanged.
    let row: (i64, String) = sqlx::query_as(
        "SELECT roster_version, roster_canonical_b64 FROM organizations WHERE id = $1",
    )
    .bind(&org_id)
    .fetch_one(state.db.pool())
    .await
    .unwrap();
    assert_eq!(row.0, 3);
    let pruned =
        hekate_core::org_roster::decode_canonical(&STANDARD_NO_PAD.decode(&row.1).unwrap())
            .unwrap();
    assert_eq!(pruned.entries.len(), 1);
    assert_eq!(pruned.entries[0].user_id, uid_a);
    let member_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM organization_members WHERE org_id = $1")
            .bind(&org_id)
            .fetch_one(state.db.pool())
            .await
            .unwrap();
    assert_eq!(
        member_count.0, 1,
        "prune does not touch organization_members"
    );
}

#[tokio::test]
async fn prune_rejects_non_owner() {
    // A non-owner POSTing prune-roster gets 404 (same convention as
    // other owner-gated endpoints — hides org existence from members).
    let (app, state) = test_app_with_state().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let (uid_c, _, _) = register(&app, "carol@x.test", 3).await;
    let token_a = login(&app, "alice@x.test").await;
    let token_b = login(&app, "bob@x.test").await;
    let token_c = login(&app, "carol@x.test").await;

    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    // Bring bob in legitimately so he's a real member.
    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD
            .decode(create_body["roster"]["canonical_b64"].as_str().unwrap())
            .unwrap(),
    );
    let _ = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent,
    )
    .await;
    // Inject a carol orphan to give bob something to "prune".
    let (stale_canonical_b64, stale_version) =
        inject_orphan_into_roster(&state, &org_id, &org_sk, &uid_c, "user").await;

    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD.decode(&stale_canonical_b64).unwrap(),
    );
    let (next_canonical_b64, next_signature_b64) = build_signed_roster(
        &org_id,
        stale_version + 1,
        parent,
        &org_sk,
        &key_id,
        vec![
            OrgRosterEntry {
                user_id: uid_a.clone(),
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: uid_b.clone(),
                role: "user".into(),
            },
        ],
    );
    let body = json!({
        "next_roster": {
            "canonical_b64": next_canonical_b64,
            "signature_b64": next_signature_b64,
        }
    });
    // Bob is a real member but not the owner.
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/prune-roster"),
            &token_b,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // Carol isn't a member at all — also 404.
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/prune-roster"),
            &token_c,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn prune_rejects_owner_dropped() {
    // Owner can't accidentally prune themselves out — the new roster
    // must keep them at role=owner.
    let (app, state) = test_app_with_state().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let (stale_canonical_b64, stale_version) =
        inject_orphan_into_roster(&state, &org_id, &org_sk, &uid_b, "user").await;
    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD.decode(&stale_canonical_b64).unwrap(),
    );
    // Empty roster — drop both alice and bob.
    let (next_canonical_b64, next_signature_b64) =
        build_signed_roster(&org_id, stale_version + 1, parent, &org_sk, &key_id, vec![]);
    let body = json!({
        "next_roster": {
            "canonical_b64": next_canonical_b64,
            "signature_b64": next_signature_b64,
        }
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/prune-roster"),
            &token_a,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = body_json(resp).await;
    assert!(
        v["error"]
            .as_str()
            .unwrap_or("")
            .contains("must keep the owner"),
        "expected owner-required error, got {v}",
    );
}

#[tokio::test]
async fn prune_rejects_unknown_addition() {
    // Prune is strict subset — adding a user_id that wasn't in the
    // current roster gets rejected.
    let (app, _state) = test_app_with_state().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD
            .decode(create_body["roster"]["canonical_b64"].as_str().unwrap())
            .unwrap(),
    );
    // Genesis roster has just alice (v=1). Try to prune to a v=2
    // that adds bob — bob isn't in v=1 so this is an addition, not
    // a prune.
    let (next_canonical_b64, next_signature_b64) = build_signed_roster(
        &org_id,
        2,
        parent,
        &org_sk,
        &key_id,
        vec![
            OrgRosterEntry {
                user_id: uid_a.clone(),
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: uid_b.clone(),
                role: "user".into(),
            },
        ],
    );
    let body = json!({
        "next_roster": {
            "canonical_b64": next_canonical_b64,
            "signature_b64": next_signature_b64,
        }
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/prune-roster"),
            &token_a,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = body_json(resp).await;
    assert!(
        v["error"]
            .as_str()
            .unwrap_or("")
            .contains("cannot add members"),
        "expected addition-rejected error, got {v}",
    );
}

#[tokio::test]
async fn prune_rejects_role_change() {
    // Prune is strict subset for entries — same user_id must keep the
    // same role. Changing alice from owner→user is rejected (also
    // hits the owner-required check, but we check the role-change
    // code path directly with bob).
    let (app, state) = test_app_with_state().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD
            .decode(create_body["roster"]["canonical_b64"].as_str().unwrap())
            .unwrap(),
    );
    let token_b = login(&app, "bob@x.test").await;
    let _ = accept_member(
        &app, &org_id, &org_sk, &uid_a, &token_a, &uid_b, &token_b, &key_id, 2, parent,
    )
    .await;
    // Inject a carol orphan so we have something to "prune" — but
    // also flip bob's role from "user" to "admin" in the next roster.
    let (uid_c, _, _) = register(&app, "carol@x.test", 3).await;
    let (stale_canonical_b64, stale_version) =
        inject_orphan_into_roster(&state, &org_id, &org_sk, &uid_c, "user").await;
    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD.decode(&stale_canonical_b64).unwrap(),
    );
    let (next_canonical_b64, next_signature_b64) = build_signed_roster(
        &org_id,
        stale_version + 1,
        parent,
        &org_sk,
        &key_id,
        vec![
            OrgRosterEntry {
                user_id: uid_a.clone(),
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: uid_b.clone(),
                role: "admin".into(),
            },
        ],
    );
    let body = json!({
        "next_roster": {
            "canonical_b64": next_canonical_b64,
            "signature_b64": next_signature_b64,
        }
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/prune-roster"),
            &token_a,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = body_json(resp).await;
    assert!(
        v["error"]
            .as_str()
            .unwrap_or("")
            .contains("cannot change roles"),
        "expected role-change error, got {v}",
    );
}

#[tokio::test]
async fn prune_rejects_orphan_retained() {
    // The whole point of prune: every surviving entry must be in
    // organization_members. Trying to "prune" while keeping an orphan
    // is malformed.
    let (app, state) = test_app_with_state().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let (uid_c, _, _) = register(&app, "carol@x.test", 3).await;
    let token_a = login(&app, "alice@x.test").await;
    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    // Inject TWO orphans so the next-roster can plausibly drop one
    // but keep the other.
    let _ = inject_orphan_into_roster(&state, &org_id, &org_sk, &uid_b, "user").await;
    let (stale_canonical_b64, stale_version) =
        inject_orphan_into_roster(&state, &org_id, &org_sk, &uid_c, "user").await;
    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD.decode(&stale_canonical_b64).unwrap(),
    );
    // Drop bob, keep carol — but carol is also an orphan.
    let (next_canonical_b64, next_signature_b64) = build_signed_roster(
        &org_id,
        stale_version + 1,
        parent,
        &org_sk,
        &key_id,
        vec![
            OrgRosterEntry {
                user_id: uid_a.clone(),
                role: "owner".into(),
            },
            OrgRosterEntry {
                user_id: uid_c.clone(),
                role: "user".into(),
            },
        ],
    );
    let body = json!({
        "next_roster": {
            "canonical_b64": next_canonical_b64,
            "signature_b64": next_signature_b64,
        }
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/prune-roster"),
            &token_a,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = body_json(resp).await;
    assert!(
        v["error"]
            .as_str()
            .unwrap_or("")
            .contains("not a current member"),
        "expected orphan-retained error, got {v}",
    );
}

#[tokio::test]
async fn prune_rejects_chain_break() {
    // next_roster's parent_canonical_sha256 must hash to the current
    // canonical. Otherwise return 409 — caller is operating on stale
    // data.
    let (app, state) = test_app_with_state().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let (_stale_canonical_b64, stale_version) =
        inject_orphan_into_roster(&state, &org_id, &org_sk, &uid_b, "user").await;
    // Wrong parent — use all-zeros (genesis-style).
    let (next_canonical_b64, next_signature_b64) = build_signed_roster(
        &org_id,
        stale_version + 1,
        NO_PARENT_HASH,
        &org_sk,
        &key_id,
        vec![OrgRosterEntry {
            user_id: uid_a.clone(),
            role: "owner".into(),
        }],
    );
    let body = json!({
        "next_roster": {
            "canonical_b64": next_canonical_b64,
            "signature_b64": next_signature_b64,
        }
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/prune-roster"),
            &token_a,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn prune_rejects_bad_signature() {
    // Tampered signature — bytes ok but don't verify under the org
    // signing key.
    let (app, state) = test_app_with_state().await;
    let (uid_a, sk_a, _) = register(&app, "alice@x.test", 1).await;
    let (uid_b, _, _) = register(&app, "bob@x.test", 2).await;
    let token_a = login(&app, "alice@x.test").await;
    let (create_body, org_id, org_sk) = build_create_body(&uid_a, &sk_a, "Acme");
    let key_id = create_body["org_sym_key_id"].as_str().unwrap().to_string();
    app.clone()
        .oneshot(req("POST", "/api/v1/orgs", &token_a, Some(&create_body)))
        .await
        .unwrap();
    let (stale_canonical_b64, stale_version) =
        inject_orphan_into_roster(&state, &org_id, &org_sk, &uid_b, "user").await;
    let parent = hekate_core::org_roster::hash_canonical(
        &STANDARD_NO_PAD.decode(&stale_canonical_b64).unwrap(),
    );
    let (next_canonical_b64, _good_sig) = build_signed_roster(
        &org_id,
        stale_version + 1,
        parent,
        &org_sk,
        &key_id,
        vec![OrgRosterEntry {
            user_id: uid_a.clone(),
            role: "owner".into(),
        }],
    );
    // Replace signature with a different valid 64-byte ed25519 sig
    // (signs an unrelated message under a different key) — same
    // length so the bytes-shape check passes, but verify fails.
    let other_sk = SigningKey::from_bytes(&[0xde; 32]);
    let bogus_sig = other_sk.sign(b"unrelated").to_bytes();
    let body = json!({
        "next_roster": {
            "canonical_b64": next_canonical_b64,
            "signature_b64": b64(&bogus_sig),
        }
    });
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/orgs/{org_id}/prune-roster"),
            &token_a,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
