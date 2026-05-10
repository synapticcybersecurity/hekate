//! SSRF defense for outbound webhook delivery (audit S-H1, 2026-05-07).
//!
//! Two checks, applied at *both* webhook-create time and at every
//! delivery attempt:
//!
//!   1. **Scheme**: must be `https://` unless
//!      `Config::webhooks_allow_unsafe_destinations` is on (dev only).
//!   2. **Resolved IP**: every A/AAAA record must be a public-internet
//!      address. We reject loopback (127/8, ::1), unspecified, RFC 1918
//!      (10/8, 172.16/12, 192.168/16), CGNAT (100.64/10), link-local
//!      (169.254/16, fe80::/10 — covers the AWS/GCP metadata service),
//!      multicast / broadcast, and IPv6 ULA (fc00::/7).
//!
//! At delivery time we resolve the host, check the IP, then bind the
//! TCP connection to that exact address via reqwest's `.resolve()`
//! override. This defeats DNS rebinding: the attacker can't make the
//! domain resolve to a public IP at create time and a private IP at
//! delivery time, because we re-resolve and re-validate on every
//! attempt.
//!
//! HTTPS is required so the HMAC signature header isn't transmitted in
//! plaintext (prevents a network attacker from re-using the timestamped
//! signature against a different body). The dev-mode escape hatch is
//! gated behind a config flag that production will never set.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::lookup_host;
use url::Url;

/// Outcome of [`resolve_safe`] — the (host, port) pair we should pass
/// to `reqwest::ClientBuilder::resolve` to pin the destination IP for
/// this attempt.
#[derive(Debug, Clone)]
pub struct PinnedDestination {
    /// The hostname from the original URL — needed by reqwest's
    /// `.resolve()` override and by the TLS layer for SNI / cert
    /// validation. Lowercased.
    pub host: String,
    /// The exact `SocketAddr` we will connect to. Resolved + checked
    /// + chosen now; reqwest will not re-resolve.
    pub addr: SocketAddr,
}

#[derive(Debug, thiserror::Error)]
pub enum WebhookUrlError {
    #[error("url is not valid: {0}")]
    Parse(String),
    #[error("url scheme must be https (or set webhooks_allow_unsafe_destinations for dev)")]
    NonHttps,
    #[error("url scheme must be http or https")]
    UnsupportedScheme,
    #[error("url is missing a host")]
    NoHost,
    #[error("hostname did not resolve to any IP address")]
    NoIp,
    #[error("hostname resolved to a blocked IP ({0}); private/loopback/link-local destinations are refused")]
    BlockedIp(IpAddr),
    #[error("dns lookup failed: {0}")]
    Dns(String),
}

/// Parse-and-shape-check only (no DNS). Used at create time before we
/// even try to resolve, so a clearly-malformed URL fails fast with a
/// 400 rather than waiting on a lookup timeout.
pub fn parse_and_check_scheme(url: &str, allow_unsafe: bool) -> Result<Url, WebhookUrlError> {
    let parsed = Url::parse(url).map_err(|e| WebhookUrlError::Parse(e.to_string()))?;
    match parsed.scheme() {
        "https" => {}
        "http" => {
            if !allow_unsafe {
                return Err(WebhookUrlError::NonHttps);
            }
        }
        _ => return Err(WebhookUrlError::UnsupportedScheme),
    }
    if parsed.host_str().is_none() {
        return Err(WebhookUrlError::NoHost);
    }
    Ok(parsed)
}

/// Resolve `url`'s hostname and pick a single safe destination IP. The
/// caller passes the resolved pair to
/// `reqwest::ClientBuilder::resolve(host, addr)` to pin the connection.
///
/// `allow_unsafe = true` skips both the scheme check and the IP-block
/// check — only set in dev environments where webhooks point at
/// `http://localhost`-style targets.
pub async fn resolve_safe(
    url: &str,
    allow_unsafe: bool,
) -> Result<PinnedDestination, WebhookUrlError> {
    let parsed = parse_and_check_scheme(url, allow_unsafe)?;
    let host = parsed
        .host_str()
        .ok_or(WebhookUrlError::NoHost)?
        .to_lowercase();
    let port = parsed.port_or_known_default().unwrap_or(443);

    let addrs: Vec<SocketAddr> = lookup_host((host.as_str(), port))
        .await
        .map_err(|e| WebhookUrlError::Dns(e.to_string()))?
        .collect();

    if addrs.is_empty() {
        return Err(WebhookUrlError::NoIp);
    }

    // Reject if *any* resolved IP is blocked — partial blocks are a
    // DNS-rebinding hole (attacker controls TTL + ordering, can flip).
    if !allow_unsafe {
        for a in &addrs {
            if is_blocked_ip(a.ip()) {
                return Err(WebhookUrlError::BlockedIp(a.ip()));
            }
        }
    }

    // Pin the first survivor. With per-attempt re-resolution this is
    // already ephemeral; we don't need rotation.
    Ok(PinnedDestination {
        host,
        addr: addrs[0],
    })
}

/// True if `ip` is in any range we refuse to send webhooks to. Covers
/// the canonical SSRF targets: loopback, RFC 1918, link-local
/// (including the AWS/GCP/Azure metadata service at 169.254.169.254),
/// CGNAT, IPv6 ULA, multicast, broadcast, unspecified, and the 0/8
/// "this network" prefix.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => {
            // IPv4-mapped (::ffff:0:0/96) — unwrap and re-check as IPv4
            // so an attacker can't bypass the v4 list by rewriting as a
            // mapped address.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_v4(mapped);
            }
            is_blocked_v6(v6)
        }
    }
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_broadcast() {
        return true;
    }
    if ip.is_private() || ip.is_link_local() || ip.is_multicast() {
        return true;
    }
    let octets = ip.octets();
    // 0.0.0.0/8 — "this network" / unrouted. is_unspecified() only
    // covers 0.0.0.0; the rest of /8 is also reserved.
    if octets[0] == 0 {
        return true;
    }
    // 100.64.0.0/10 — Carrier-grade NAT. Not technically private but
    // shouldn't be a webhook target from the public internet.
    if octets[0] == 100 && (octets[1] & 0xc0) == 64 {
        return true;
    }
    // 192.0.0.0/24 (IETF protocol assignments), 192.0.2.0/24 (TEST-NET-1),
    // 198.18.0.0/15 (benchmarking), 198.51.100.0/24 (TEST-NET-2),
    // 203.0.113.0/24 (TEST-NET-3), 240.0.0.0/4 (reserved/future).
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return true;
    }
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return true;
    }
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return true;
    }
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }
    if octets[0] >= 240 {
        return true;
    }
    false
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    let segs = ip.segments();
    // fe80::/10 — link-local
    if (segs[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // fc00::/7 — unique-local addresses (ULA, IPv6 equivalent of RFC 1918)
    if (segs[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // 2001:db8::/32 — documentation prefix
    if segs[0] == 0x2001 && segs[1] == 0x0db8 {
        return true;
    }
    // 64:ff9b::/96 — NAT64 well-known prefix; the embedded /32 is a
    // public IPv4 we already check after to_ipv4_mapped — but
    // to_ipv4_mapped only matches ::ffff:/96, not 64:ff9b::, so be
    // conservative and block (NAT64 endpoints belong to operators, not
    // arbitrary users).
    if segs[0] == 0x0064 && segs[1] == 0xff9b {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn blocks_canonical_ssrf_v4_targets() {
        // Cloud metadata
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
        // RFC 1918
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        // Loopback
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        // Unspecified / broadcast
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
        // CGNAT (100.64/10)
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254))));
        // TEST-NET-* and reserved future
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))));
    }

    #[test]
    fn allows_public_v4_addresses() {
        assert!(!is_blocked_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_blocked_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_blocked_ip(IpAddr::V4(Ipv4Addr::new(140, 82, 121, 4)))); // github.com sample
    }

    #[test]
    fn blocks_canonical_ssrf_v6_targets() {
        // ::1 (loopback)
        assert!(is_blocked_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // :: (unspecified)
        assert!(is_blocked_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        // fe80:: (link-local)
        assert!(is_blocked_ip(IpAddr::V6(
            Ipv6Addr::from_str("fe80::1").unwrap()
        )));
        // fc00:: (ULA)
        assert!(is_blocked_ip(IpAddr::V6(
            Ipv6Addr::from_str("fc00::1").unwrap()
        )));
        assert!(is_blocked_ip(IpAddr::V6(
            Ipv6Addr::from_str("fd00::1").unwrap()
        )));
        // ff00:: (multicast)
        assert!(is_blocked_ip(IpAddr::V6(
            Ipv6Addr::from_str("ff02::1").unwrap()
        )));
        // 2001:db8:: (documentation)
        assert!(is_blocked_ip(IpAddr::V6(
            Ipv6Addr::from_str("2001:db8::1").unwrap()
        )));
        // IPv4-mapped private — must follow the v4 list
        assert!(is_blocked_ip(IpAddr::V6(
            Ipv6Addr::from_str("::ffff:127.0.0.1").unwrap()
        )));
        assert!(is_blocked_ip(IpAddr::V6(
            Ipv6Addr::from_str("::ffff:169.254.169.254").unwrap()
        )));
        // NAT64 well-known
        assert!(is_blocked_ip(IpAddr::V6(
            Ipv6Addr::from_str("64:ff9b::1.2.3.4").unwrap()
        )));
    }

    #[test]
    fn allows_public_v6_addresses() {
        // 2606:4700:4700::1111 — Cloudflare DNS
        assert!(!is_blocked_ip(IpAddr::V6(
            Ipv6Addr::from_str("2606:4700:4700::1111").unwrap()
        )));
    }

    #[test]
    fn parse_rejects_non_https_when_strict() {
        let err = parse_and_check_scheme("http://example.com/hook", false).unwrap_err();
        assert!(matches!(err, WebhookUrlError::NonHttps));
    }

    #[test]
    fn parse_accepts_http_when_unsafe_allowed() {
        let url = parse_and_check_scheme("http://example.com/hook", true).unwrap();
        assert_eq!(url.scheme(), "http");
    }

    #[test]
    fn parse_rejects_unsupported_schemes() {
        for url in [
            "ftp://example.com/x",
            "file:///etc/passwd",
            "gopher://example.com/x",
            "data:text/plain,hello",
        ] {
            let err = parse_and_check_scheme(url, true).unwrap_err();
            assert!(
                matches!(err, WebhookUrlError::UnsupportedScheme),
                "expected UnsupportedScheme for {url}, got {err:?}"
            );
        }
    }

    // The NoHost branch is a safety net for `Url::parse` configurations
    // that accept scheme-only inputs; under our current url crate version
    // both `http://` and `https://` always require a host so the path
    // isn't easily reachable from a parse-error fixture. Left in as
    // defense-in-depth.
}
