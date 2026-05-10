//! Per-IP rate limiting (audit S-M3, 2026-05-07).
//!
//! Two `governor`-backed token-bucket limiters share the request path:
//!
//!   * **Auth** (strict): 10 req/min, burst 3 — applied to login,
//!     register, prelogin, the public Send password gate, and the 2FA
//!     challenge replay leg. These endpoints either run Argon2id
//!     server-side (cheap-attack-by-design) or expose
//!     low-entropy probes (existence checks, recovery codes) and
//!     deserve tight per-IP caps.
//!   * **General** (lenient): 600 req/min, burst 50 — applied to
//!     everything else as a backstop against runaway clients.
//!
//! Bucket key: client IP. Source priority:
//!
//!   1. If `Config::trust_proxy_headers == true`, the leftmost entry
//!      of `X-Forwarded-For` (or `Forwarded: for=`).
//!   2. Otherwise the direct peer IP via `ConnectInfo<SocketAddr>`.
//!
//! The proxy-header path is **off by default**: trusting these headers
//! on a directly-exposed deployment lets any client spoof their IP and
//! defeat per-IP rate limiting.
//!
//! Test mode (`Config::database_url` starts with `sqlite::memory:`) is
//! short-circuited in the middleware — Argon2id-bound tests would
//! otherwise self-rate-limit on shared CI runners. The same marker
//! gates the request-timeout bump and the attachment temp-dir.
//!
//! Response on hit: `429 Too Many Requests` + `Retry-After: <secs>`
//! per RFC 6585 / 7231.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, Request, Response, StatusCode},
    middleware::Next,
};
use governor::{
    clock::{Clock, DefaultClock},
    Quota, RateLimiter,
};

use crate::AppState;

/// Aliases hiding the slightly hairy governor type. We use the keyed
/// variant under a `dashmap` storage so look-up is lock-free.
pub type IpRateLimiter = Arc<
    RateLimiter<
        IpAddr,
        governor::state::keyed::DashMapStateStore<IpAddr>,
        DefaultClock,
        governor::middleware::NoOpMiddleware,
    >,
>;

/// Build a strict per-IP limiter for auth-shaped endpoints.
/// 10 req/min, burst 3.
pub fn auth_limiter() -> IpRateLimiter {
    let quota = Quota::per_minute(NonZeroU32::new(10).expect("nonzero literal"))
        .allow_burst(NonZeroU32::new(3).expect("nonzero literal"));
    Arc::new(RateLimiter::dashmap(quota))
}

/// Build a lenient per-IP limiter for everything else.
/// 600 req/min, burst 50.
pub fn general_limiter() -> IpRateLimiter {
    let quota = Quota::per_minute(NonZeroU32::new(600).expect("nonzero literal"))
        .allow_burst(NonZeroU32::new(50).expect("nonzero literal"));
    Arc::new(RateLimiter::dashmap(quota))
}

/// Holds both limiters; embedded in `AppState`.
#[derive(Clone)]
pub struct Limiters {
    pub auth: IpRateLimiter,
    pub general: IpRateLimiter,
}

impl Default for Limiters {
    fn default() -> Self {
        Self {
            auth: auth_limiter(),
            general: general_limiter(),
        }
    }
}

/// Endpoints that get the strict bucket. Order doesn't matter; first
/// match wins (paths are mutually exclusive in practice).
fn is_auth_path(path: &str) -> bool {
    matches!(
        path,
        "/identity/connect/token" | "/api/v1/accounts/register" | "/api/v1/accounts/prelogin"
    ) || (path.starts_with("/api/v1/public/sends/") && path.ends_with("/access"))
}

/// Extract the client IP per the configured proxy-trust posture.
fn client_ip(req: &Request<Body>, trust_proxy_headers: bool) -> IpAddr {
    if trust_proxy_headers {
        if let Some(ip) = read_x_forwarded_for(req).or_else(|| read_forwarded(req)) {
            return ip;
        }
    }
    // Fall back to the direct peer address. axum injects ConnectInfo
    // when `into_make_service_with_connect_info::<SocketAddr>()` is
    // wired (see `lib.rs::run`). Tower-test invocations don't have it
    // — for those we return the unspecified address (0.0.0.0), which
    // is fine because test mode short-circuits the limiter anyway.
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

fn read_x_forwarded_for(req: &Request<Body>) -> Option<IpAddr> {
    let raw = req.headers().get("x-forwarded-for")?.to_str().ok()?;
    // Leftmost entry is the original client per the de facto convention.
    raw.split(',').next()?.trim().parse().ok()
}

fn read_forwarded(req: &Request<Body>) -> Option<IpAddr> {
    let raw = req.headers().get("forwarded")?.to_str().ok()?;
    // Minimal RFC 7239 parser — picks the leftmost `for=...` token.
    // Handles `for=1.2.3.4`, `for=1.2.3.4:5678`,
    // `for="[2001:db8::1]"`, and `for="[2001:db8::1]:8080"`.
    for part in raw.split(',') {
        for kv in part.split(';') {
            let kv = kv.trim();
            if !kv.to_ascii_lowercase().starts_with("for=") {
                continue;
            }
            let val = kv[4..].trim().trim_matches('"');
            if let Some(ip) = parse_forwarded_for_value(val) {
                return Some(ip);
            }
        }
    }
    None
}

fn parse_forwarded_for_value(v: &str) -> Option<IpAddr> {
    // Bracketed IPv6 — `[<addr>]` or `[<addr>]:<port>`. The port (if
    // any) sits after the closing bracket; the address is between the
    // brackets, no port stripping needed.
    if let Some(after_lb) = v.strip_prefix('[') {
        let end = after_lb.find(']')?;
        return after_lb[..end].parse().ok();
    }
    // No brackets: bare IPv4 or IPv4:port. Try the whole thing first,
    // then split off a trailing port.
    if let Ok(ip) = v.parse::<IpAddr>() {
        return Some(ip);
    }
    let (host, _port) = v.rsplit_once(':')?;
    host.parse().ok()
}

pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    // Tests run thousands of requests against in-memory SQLite under
    // contention; per-IP rate limiting would force the suite serial.
    if crate::db::is_memory_sqlite(&state.config.database_url) {
        return next.run(req).await;
    }

    let path = req.uri().path().to_string();
    let limiter = if is_auth_path(&path) {
        &state.limiters.auth
    } else {
        &state.limiters.general
    };
    let ip = client_ip(&req, state.config.trust_proxy_headers);

    match limiter.check_key(&ip) {
        Ok(()) => next.run(req).await,
        Err(neg) => too_many_requests(neg.wait_time_from(DefaultClock::default().now())),
    }
}

fn too_many_requests(wait: std::time::Duration) -> Response<Body> {
    let secs = wait.as_secs().max(1);
    let body = format!("{{\"error\":\"too many requests\",\"retry_after\":{secs}}}");
    let mut resp = Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(header::RETRY_AFTER, secs.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("static response builds");
    // Bonus header for caches/proxies.
    resp.headers_mut()
        .insert(header::VARY, header::HeaderValue::from_static("origin"));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_path_classifier() {
        assert!(is_auth_path("/identity/connect/token"));
        assert!(is_auth_path("/api/v1/accounts/register"));
        assert!(is_auth_path("/api/v1/accounts/prelogin"));
        assert!(is_auth_path("/api/v1/public/sends/abc-123/access"));
        assert!(!is_auth_path("/api/v1/sync"));
        assert!(!is_auth_path("/api/v1/public/sends/abc-123/blob/tok"));
        assert!(!is_auth_path("/api/v1/accounts/register/anything"));
    }

    fn req_with_header(name: &str, value: &str) -> Request<Body> {
        Request::builder()
            .uri("/")
            .header(name, value)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn xff_picks_leftmost_entry() {
        let r = req_with_header("x-forwarded-for", "203.0.113.5, 10.0.0.1");
        assert_eq!(
            read_x_forwarded_for(&r),
            Some("203.0.113.5".parse().unwrap())
        );
    }

    #[test]
    fn forwarded_for_token_strips_brackets_and_port() {
        let r = req_with_header("forwarded", "for=\"[2001:db8::1]:8080\";proto=https");
        assert_eq!(read_forwarded(&r), Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn forwarded_for_picks_first_segment() {
        let r = req_with_header("forwarded", "for=198.51.100.7, for=10.0.0.5");
        assert_eq!(read_forwarded(&r), Some("198.51.100.7".parse().unwrap()));
    }
}
