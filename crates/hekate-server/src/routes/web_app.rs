//! Static SPA mount for the Hekate web vault (`clients/web/`).
//!
//! The same SolidJS bundle is served at two URL prefixes:
//!
//! - `/web/*` — owner mode (login, vault, sends, orgs, settings).
//! - `/send/*` — recipient mode for share URLs of the form
//!   `<server>/send/#/<send_id>/<send_key>`. The recipient key lives
//!   in the URL fragment so it never reaches the server; the SPA's
//!   recipient route reads `location.hash` client-side.
//!
//! The SPA picks its mode from `location.pathname`. A single `index.html`
//! is served at both prefixes; assets resolve relative to the same dist
//! directory.
//!
//! When `Config::web_dir` is unset or the directory is missing (e.g. a
//! dev server started before `make web` ran), both prefixes fall back
//! to a tiny placeholder page that surfaces the share URL and points
//! the user at the browser extension or `hekate` CLI. This keeps existing
//! share URLs informationally functional while the SPA isn't built.

use std::path::{Path, PathBuf};

use axum::{
    response::{Html, Redirect},
    routing::get,
    Router,
};
use tower_http::services::{ServeDir, ServeFile};

use crate::AppState;

pub fn router(web_dir: Option<&str>) -> Router<AppState> {
    if let Some(dir) = web_dir {
        let path = PathBuf::from(dir);
        if path.is_dir() {
            return spa_router(&path);
        }
        tracing::warn!(
            dir = %dir,
            "HEKATE_WEB_DIR is set but not a directory; serving placeholder at /web/* and /send/*"
        );
    }
    placeholder_router()
}

fn spa_router(dir: &Path) -> Router<AppState> {
    let index = dir.join("index.html");
    let make_serve = || {
        ServeDir::new(dir)
            .append_index_html_on_directories(true)
            .fallback(ServeFile::new(&index))
    };
    // `nest_service` doesn't auto-redirect the bare prefix to its
    // trailing-slash form, so `/web` (no slash) would otherwise hit
    // axum's NOT_FOUND fallback. Redirect explicitly so SPA links work
    // either way.
    Router::new()
        .route("/web", get(|| async { Redirect::permanent("/web/") }))
        .route("/send", get(|| async { Redirect::permanent("/send/") }))
        .nest_service("/web/", make_serve())
        .nest_service("/send/", make_serve())
}

fn placeholder_router() -> Router<AppState> {
    Router::new()
        .route("/web", get(|| async { Redirect::permanent("/web/") }))
        .route("/send", get(|| async { Redirect::permanent("/send/") }))
        .route("/web/", get(placeholder))
        .route("/web/{*rest}", get(placeholder))
        .route("/send/", get(placeholder))
        .route("/send/{*rest}", get(placeholder))
}

async fn placeholder() -> Html<&'static str> {
    Html(PLACEHOLDER_HTML)
}

const PLACEHOLDER_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hekate — web vault not built</title>
<style>
  :root { color-scheme: light dark; }
  body {
    font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    max-width: 640px; margin: 4rem auto; padding: 0 1.5rem;
  }
  h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
  .muted { color: #666; }
  code, pre { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 0.9em; }
  .url-box {
    word-break: break-all; padding: 0.75rem 1rem;
    background: rgba(127,127,127,0.1); border-radius: 6px;
    margin: 1rem 0;
  }
  button {
    font: inherit; padding: 0.5rem 1rem;
    background: #007AFF; color: white; border: 0; border-radius: 6px;
    cursor: pointer;
  }
  button:hover { background: #0066cc; }
  ol li { margin-bottom: 0.5rem; }
  .key-warn {
    background: rgba(220, 38, 38, 0.08);
    border-left: 3px solid #dc2626;
    padding: 0.5rem 1rem; margin: 1rem 0; font-size: 0.95em;
  }
</style>
</head>
<body>
<h1>Hekate</h1>
<p class="muted">The web vault hasn't been built on this server yet.</p>

<div class="key-warn">
  Run <code>make web</code> on the server, or set
  <code>HEKATE_WEB_DIR</code> to the directory containing the SPA's
  <code>index.html</code>. Until then, share URLs can be opened via
  the Hekate browser extension or the <code>hekate</code> CLI.
</div>

<p><strong>If this is a share URL:</strong></p>
<ol>
  <li>Copy the URL below.</li>
  <li>Open the Hekate browser extension popup, click <strong>Share</strong>
      → <strong>Open shared link…</strong>, paste the URL, decrypt.</li>
  <li>Or, in a shell: <code>hekate send open '&lt;the URL below&gt;'</code></li>
</ol>

<p><strong>The URL:</strong></p>
<div class="url-box" id="urlBox">…</div>
<p><button id="copy">Copy URL</button>
   <span id="copied" class="muted" hidden> Copied.</span></p>

<script>
  const url = window.location.href;
  document.getElementById("urlBox").textContent = url;
  document.getElementById("copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(url);
      document.getElementById("copied").hidden = false;
      setTimeout(() => (document.getElementById("copied").hidden = true), 2500);
    } catch (_) {
      window.prompt("Copy this URL:", url);
    }
  });
</script>
</body>
</html>
"#;
