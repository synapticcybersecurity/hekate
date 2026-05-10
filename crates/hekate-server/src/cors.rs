//! Hand-rolled CORS middleware (audit S-M4, 2026-05-07).
//!
//! `tower_http::cors::CorsLayer` short-circuits *every* OPTIONS
//! request, regardless of whether it's a real CORS preflight. That
//! breaks the tus 1.0 protocol's `OPTIONS /api/v1/attachments` capability-
//! discovery handler (which has to return 204 + `Tus-*` headers — same
//! HTTP method, completely different semantics). Rather than forking
//! tower-http or wrapping the tus discovery in a side-channel, we run
//! a small middleware here that:
//!
//!   * Adds CORS response headers when the request origin is in the
//!     configured allowlist — non-preflight requests pass through to
//!     the inner handler untouched, and the headers attach on the way
//!     back. This means the tus 204 + `Tus-*` response gains
//!     `Access-Control-Allow-Origin` / `Access-Control-Expose-Headers`
//!     on top, satisfying both protocols at once.
//!   * Short-circuits *only* genuine CORS preflights (OPTIONS +
//!     `Origin` + `Access-Control-Request-Method` headers all present)
//!     with a strict 204 + method/header/max-age allowlist.
//!   * Refuses requests from origins not in the allowlist by *not*
//!     emitting any CORS headers — the browser's same-origin check
//!     then blocks the response from being read by JS. Non-browser
//!     clients aren't affected (CORS is browser-only).
//!
//! Posture: explicit per-origin allowlist (no `*`), exact-match on
//! scheme + host + port, no wildcards, no `Access-Control-Allow-
//! Credentials` (we use bearer tokens, not cookies — a wildcard would
//! be unsafe but our explicit-origin scheme is fine either way).
//!
//! Configuration: `Config::cors_allowed_origins`. Empty (default) means
//! same-origin only, no CORS layer behavior at all — the simplest
//! `make up` deployment carries no CORS plumbing.

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::Response,
};

use crate::AppState;

/// Headers we let cross-origin clients send. Covers the bearer-token
/// flow (`authorization`), JSON bodies, optimistic-concurrency
/// (`if-match`), and the tus 1.0 client request headers used by file
/// uploads.
const ALLOW_REQUEST_HEADERS: &str = concat!(
    "authorization, ",
    "content-type, ",
    "if-match, ",
    "tus-resumable, ",
    "upload-length, ",
    "upload-offset, ",
    "upload-metadata, ",
    "upload-checksum"
);

/// Headers we let cross-origin browsers *read* on responses. The tus
/// `Tus-*` capability headers + upload progress + `Location` for the
/// discovery flow.
const EXPOSE_RESPONSE_HEADERS: &str = concat!(
    "tus-resumable, ",
    "tus-version, ",
    "tus-extension, ",
    "tus-max-size, ",
    "upload-offset, ",
    "upload-length, ",
    "location, ",
    "etag"
);

/// Methods callable via cross-origin browser fetch. Mirrors what the
/// API actually exposes; OPTIONS is implicit (browsers don't preflight
/// OPTIONS itself — it's the preflight method).
const ALLOW_METHODS: &str = "GET, POST, PUT, PATCH, DELETE, HEAD";

/// Cache preflights for 24 h; reasonable for a stable API surface.
const PREFLIGHT_MAX_AGE_SECS: &str = "86400";

/// Tower middleware. Applied with `axum::middleware::from_fn_with_state`
/// so we can read `cors_allowed_origins` per request.
pub async fn cors_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let allowed = &state.config.cors_allowed_origins;

    // No allowlist configured → fully transparent. Same-origin
    // deployments don't touch CORS code paths.
    if allowed.is_empty() {
        return next.run(req).await;
    }

    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let origin_is_allowed = origin
        .as_deref()
        .is_some_and(|o| allowed.iter().any(|a| a == o));

    let is_preflight = req.method() == Method::OPTIONS
        && req.headers().contains_key("access-control-request-method");

    if is_preflight {
        // Genuine CORS preflight. Short-circuit ourselves so the
        // application's OPTIONS handlers (e.g. the tus discovery
        // endpoint) don't run on browser-driven preflight traffic.
        if let Some(origin) = origin.filter(|_| origin_is_allowed) {
            return preflight_response(&origin);
        }
        // Origin absent or not in allowlist: 403 with no CORS headers,
        // so the browser fails the preflight loudly.
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::empty())
            .expect("static response builds");
    }

    // Non-preflight (or OPTIONS without `Access-Control-Request-Method`,
    // i.e. tus discovery). Run the handler as normal; on the way back,
    // attach CORS response headers if the origin is allowed.
    let mut resp = next.run(req).await;
    if let Some(origin) = origin.filter(|_| origin_is_allowed) {
        attach_cors_response_headers(resp.headers_mut(), &origin);
    }
    resp
}

fn preflight_response(origin: &str) -> Response {
    let mut resp = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .expect("static response builds");
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(origin) {
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
    }
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(ALLOW_METHODS),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(ALLOW_REQUEST_HEADERS),
    );
    h.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static(PREFLIGHT_MAX_AGE_SECS),
    );
    h.insert(header::VARY, HeaderValue::from_static("origin"));
    resp
}

fn attach_cors_response_headers(headers: &mut HeaderMap, origin: &str) {
    if let Ok(v) = HeaderValue::from_str(origin) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
    }
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(EXPOSE_RESPONSE_HEADERS),
    );
    // Append rather than overwrite — some downstream layers may already
    // be varying on other headers and we don't want to clobber them.
    if !headers
        .get_all(header::VARY)
        .iter()
        .any(|v| v.as_bytes().eq_ignore_ascii_case(b"origin"))
    {
        headers.append(header::VARY, HeaderValue::from_static("origin"));
    }
}
