//! SPA static-mount behavior (`routes::web_app`).
//!
//! Coverage (#53): the wasm core is served at a stable filename and loaded via
//! a runtime dynamic `import()`, so it must be served with `Cache-Control:
//! no-cache` to force revalidation across deploys — otherwise the browser keeps
//! a stale crypto core. The content-hashed JS/CSS bundles change name per build
//! and must NOT be forced to no-cache, so the directive is scoped to `**/wasm/`.

use std::path::{Path, PathBuf};

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use hekate_server::{bootstrap, build_router, config::Config};
use tower::ServiceExt;

/// Build a temp SPA dir with an index.html + a wasm/ subdir, returning its path.
fn make_web_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hekate-web53-{}-{}", std::process::id(), tag));
    let wasm = dir.join("wasm");
    std::fs::create_dir_all(&wasm).expect("create web dir");
    std::fs::write(dir.join("index.html"), b"<!doctype html><title>t</title>").expect("index");
    std::fs::write(wasm.join("hekate_core.js"), b"export const x = 1;").expect("wasm js");
    std::fs::write(wasm.join("hekate_core_bg.wasm"), b"\0asm").expect("wasm bin");
    dir
}

async fn app_with_web_dir(dir: &Path) -> Router {
    let cfg = Config {
        listen: "0.0.0.0:0".into(),
        database_url: "sqlite::memory:".into(),
        fake_salt_pepper: vec![0u8; 32],
        web_dir: Some(dir.to_string_lossy().into_owned()),
        ..Default::default()
    };
    let state = bootstrap(cfg).await.expect("bootstrap");
    build_router(state)
}

async fn get(app: &Router, path: &str) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn cache_control(resp: &axum::http::Response<Body>) -> Option<String> {
    resp.headers()
        .get(header::CACHE_CONTROL)
        .map(|v| v.to_str().unwrap().to_owned())
}

#[tokio::test]
async fn wasm_assets_are_served_no_cache() {
    let dir = make_web_dir("nocache");
    let app = app_with_web_dir(&dir).await;
    for path in [
        "/web/wasm/hekate_core.js",
        "/web/wasm/hekate_core_bg.wasm",
        "/send/wasm/hekate_core.js",
    ] {
        let resp = get(&app, path).await;
        assert_eq!(resp.status(), StatusCode::OK, "{path} should serve");
        assert_eq!(
            cache_control(&resp).as_deref(),
            Some("no-cache"),
            "{path} should carry Cache-Control: no-cache",
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn non_wasm_assets_are_not_forced_no_cache() {
    let dir = make_web_dir("scoped");
    let app = app_with_web_dir(&dir).await;
    // index.html (served at /web/) and any non-wasm path (which falls back to
    // index.html for SPA client routing) must NOT get the wasm no-cache header,
    // so the content-hashed bundles keep their default caching.
    for path in ["/web/", "/web/assets/index-abc123.js"] {
        let resp = get(&app, path).await;
        assert_eq!(resp.status(), StatusCode::OK, "{path} should serve");
        assert!(
            cache_control(&resp).is_none(),
            "{path} should not be forced no-cache; got {:?}",
            cache_control(&resp),
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
