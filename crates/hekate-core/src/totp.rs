//! RFC 6238 TOTP code generation for cipher TOTP fields.
//!
//! Single source of truth for both clients (the web vault and the browser
//! extension call this through the wasm bindings) — replacing two hand-rolled
//! JS reimplementations that had no test coverage.
//!
//! The default HMAC-SHA1 is an RFC 6238 / RFC 4226 **interop requirement**, not
//! a collision-resistance use of SHA-1: HMAC's security does not depend on the
//! hash being collision-resistant, and there are no practical attacks on
//! HMAC-SHA1. SHA-256 / SHA-512 are supported for issuers that select them.
//! See `docs/secure-coding.md` §3.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// A computed TOTP code plus the live countdown, mirroring the shape the JS
/// callers expect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Totp {
    /// Zero-padded decimal code, `digits` characters wide.
    pub code: String,
    /// Seconds remaining in the current period.
    pub remaining: u32,
    /// The period (step) in seconds the code was computed with.
    pub period: u32,
}

#[derive(Clone, Copy)]
enum Algo {
    Sha1,
    Sha256,
    Sha512,
}

const DEFAULT_PERIOD: u32 = 30;
const DEFAULT_DIGITS: u32 = 6;
// Bound digits so `10u64.pow(digits)` can never overflow / panic and absurd
// values are rejected rather than silently accepted (no-panic-on-input rule).
const MAX_DIGITS: u32 = 10;

/// Compute a TOTP code for `secret_or_uri` at unix time `now_secs`.
///
/// `secret_or_uri` is either a bare base32 secret or a full `otpauth://` URI;
/// in the URI form the `secret`, `period`, `digits` and `algorithm` parameters
/// are honoured (anything else is ignored). Callers pass the current unix time
/// so this stays pure and testable (no clock access inside core / wasm).
pub fn totp_code(secret_or_uri: &str, now_secs: u64) -> Result<Totp> {
    let trimmed = secret_or_uri.trim();

    let mut secret_b32 = trimmed.to_string();
    let mut period = DEFAULT_PERIOD;
    let mut digits = DEFAULT_DIGITS;
    let mut algo = Algo::Sha1;

    if trimmed.starts_with("otpauth://") {
        let parsed = parse_otpauth(trimmed)?;
        secret_b32 = parsed.secret;
        period = parsed.period.unwrap_or(DEFAULT_PERIOD);
        digits = parsed.digits.unwrap_or(DEFAULT_DIGITS);
        algo = parsed.algo;
    }

    if secret_b32.is_empty() {
        return Err(Error::InvalidEncoding("totp: no secret".into()));
    }
    if !(1..=MAX_DIGITS).contains(&digits) {
        return Err(Error::InvalidEncoding(format!(
            "totp: unsupported digit count: {digits}"
        )));
    }

    let mut key = base32_decode(&secret_b32)?;
    let counter = now_secs / u64::from(period);
    let code = hotp(&key, counter, digits, algo);
    key.zeroize();
    secret_b32.zeroize();

    let remaining = period - (now_secs % u64::from(period)) as u32;
    Ok(Totp {
        code,
        remaining,
        period,
    })
}

struct Otpauth {
    secret: String,
    period: Option<u32>,
    digits: Option<u32>,
    algo: Algo,
}

/// Parse the parameters of an `otpauth://` URI. Mirrors the JS `URLSearchParams`
/// reads: the only values we consume (`secret`, `period`, `digits`,
/// `algorithm`) are base32 / numeric / a fixed keyword set, none of which carry
/// percent-encoding in practice, so the query is split directly rather than
/// pulling a URL parser into the wasm build.
fn parse_otpauth(uri: &str) -> Result<Otpauth> {
    let query = uri.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut out = Otpauth {
        secret: String::new(),
        period: None,
        digits: None,
        algo: Algo::Sha1,
    };
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "secret" => out.secret = value.to_string(),
            // A zero/invalid period or digit count falls back to the default,
            // matching the JS `parseInt(...) || DEFAULT` behaviour.
            "period" => out.period = value.parse::<u32>().ok().filter(|n| *n > 0),
            "digits" => out.digits = value.parse::<u32>().ok().filter(|n| *n > 0),
            // Absent or empty algorithm defaults to SHA-1 (JS `(... || "SHA1")`):
            // an empty value fails the guard and falls through to the default.
            "algorithm" if !value.is_empty() => {
                let normalized = value.to_ascii_uppercase().replace('-', "");
                out.algo = match normalized.as_str() {
                    "SHA1" => Algo::Sha1,
                    "SHA256" => Algo::Sha256,
                    "SHA512" => Algo::Sha512,
                    _ => {
                        return Err(Error::InvalidEncoding(format!(
                            "totp: unsupported algorithm: {value}"
                        )))
                    }
                };
            }
            _ => {}
        }
    }
    Ok(out)
}

/// RFC 4648 base32 decode. Hand-rolled (an *encoding*, not crypto) to stay
/// byte-for-byte identical to the JS implementation it replaces: whitespace is
/// stripped, trailing `=` padding removed, input upper-cased, and a non-alphabet
/// character is an error.
fn base32_decode(s: &str) -> Result<Vec<u8>> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let cleaned = cleaned.trim_end_matches('=');

    let mut out = Vec::with_capacity(cleaned.len() * 5 / 8);
    let mut bits: u32 = 0;
    let mut value: u32 = 0;
    for ch in cleaned.chars() {
        let up = (ch as u8).to_ascii_uppercase();
        let idx = match ALPHABET.iter().position(|&a| a == up) {
            Some(i) => i as u32,
            None => {
                return Err(Error::InvalidEncoding(format!(
                    "totp: bad base32 char: {ch}"
                )))
            }
        };
        value = (value << 5) | idx;
        bits += 5;
        if bits >= 8 {
            out.push((value >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Ok(out)
}

/// HOTP (RFC 4226) dynamic-truncation step shared by all algorithms.
fn hotp(key: &[u8], counter: u64, digits: u32, algo: Algo) -> String {
    let msg = counter.to_be_bytes();
    // HMAC accepts any key length, so `new_from_slice` cannot fail here.
    let mac: Vec<u8> = match algo {
        Algo::Sha1 => {
            let mut m = Hmac::<Sha1>::new_from_slice(key).expect("hmac accepts any key length");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
        Algo::Sha256 => {
            let mut m = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
        Algo::Sha512 => {
            let mut m = Hmac::<Sha512>::new_from_slice(key).expect("hmac accepts any key length");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
    };

    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(mac[offset] & 0x7f) << 24)
        | (u32::from(mac[offset + 1]) << 16)
        | (u32::from(mac[offset + 2]) << 8)
        | u32::from(mac[offset + 3]);
    let modulo = 10u64.pow(digits);
    let code = u64::from(bin) % modulo;
    format!("{code:0width$}", width = digits as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors. T0 = 0, X = 30s, 8-digit codes. Each
    // algorithm uses a different ASCII seed length.
    const SEED_SHA1: &[u8] = b"12345678901234567890";
    const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    fn counter(t: u64) -> u64 {
        t / 30
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        let cases = [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];
        for (t, expected) in cases {
            assert_eq!(
                hotp(SEED_SHA1, counter(t), 8, Algo::Sha1),
                expected,
                "T={t}"
            );
        }
    }

    #[test]
    fn rfc6238_sha256_vectors() {
        let cases = [
            (59u64, "46119246"),
            (1111111109, "68084774"),
            (1111111111, "67062674"),
            (1234567890, "91819424"),
            (2000000000, "90698825"),
            (20000000000, "77737706"),
        ];
        for (t, expected) in cases {
            assert_eq!(
                hotp(SEED_SHA256, counter(t), 8, Algo::Sha256),
                expected,
                "T={t}"
            );
        }
    }

    #[test]
    fn rfc6238_sha512_vectors() {
        let cases = [
            (59u64, "90693936"),
            (1111111109, "25091201"),
            (1111111111, "99943326"),
            (1234567890, "93441116"),
            (2000000000, "38618901"),
            (20000000000, "47863826"),
        ];
        for (t, expected) in cases {
            assert_eq!(
                hotp(SEED_SHA512, counter(t), 8, Algo::Sha512),
                expected,
                "T={t}"
            );
        }
    }

    #[test]
    fn base32_decodes_rfc_seed() {
        // base32("12345678901234567890"), RFC 4648, no padding.
        assert_eq!(
            base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
            SEED_SHA1
        );
    }

    #[test]
    fn base32_is_lenient_like_js() {
        // Whitespace stripped, trailing padding removed, lower-case accepted.
        assert_eq!(
            base32_decode("gezd gnbv  gy3t qojq gezd gnbv gy3t qojq").unwrap(),
            SEED_SHA1
        );
        assert!(base32_decode("nv2!").is_err());
    }

    #[test]
    fn public_path_bare_base32() {
        // Default 6 digits, SHA-1, period 30 — the common case. Cross-checked
        // against the SHA-1 vector truncated to 6 digits (94287082 -> 287082).
        let r = totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).unwrap();
        assert_eq!(r.code, "287082");
        assert_eq!(r.period, 30);
        assert_eq!(r.remaining, 1); // 30 - (59 % 30)
    }

    #[test]
    fn public_path_otpauth_uri_with_params() {
        let uri = "otpauth://totp/ACME:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&digits=8&period=30&algorithm=SHA1";
        let r = totp_code(uri, 59).unwrap();
        assert_eq!(r.code, "94287082");
        assert_eq!(r.period, 30);
    }

    #[test]
    fn otpauth_algorithm_default_and_dash_forms() {
        // Absent algorithm -> SHA-1; "SHA-256" with a dash normalizes.
        let base = "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8";
        assert_eq!(totp_code(base, 59).unwrap().code, "94287082");
        let sha256 = format!("{base}&algorithm=SHA-256");
        assert_eq!(
            totp_code(&sha256, 59).unwrap().code,
            hotp(SEED_SHA1, 1, 8, Algo::Sha256)
        );
    }

    #[test]
    fn rejects_empty_secret_and_bad_inputs() {
        assert!(totp_code("", 59).is_err());
        assert!(totp_code("otpauth://totp/x?secret=", 59).is_err());
        assert!(totp_code("otpauth://totp/x?secret=AAAA&algorithm=MD5", 59).is_err());
    }
}
