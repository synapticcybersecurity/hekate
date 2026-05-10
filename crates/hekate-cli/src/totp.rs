//! Wraps the `totp-rs` crate for current-code computation.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use totp_rs::TOTP;

/// Compute the current TOTP code for the given otpauth URL.
/// Accepts both `otpauth://totp/...?secret=BASE32` and bare base32 secrets
/// (in which case sensible defaults are used: SHA-1, 6 digits, 30 s period).
pub fn current_code(otpauth_or_secret: &str) -> Result<(String, u64)> {
    let totp = if otpauth_or_secret.starts_with("otpauth://") {
        TOTP::from_url(otpauth_or_secret).map_err(|e| anyhow!("parse otpauth: {e}"))?
    } else {
        // The `otpauth` feature requires issuer + account_name. We use
        // placeholders for bare-secret mode since the values aren't shown
        // anywhere — they're only needed for QR/URL generation.
        TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            totp_rs::Secret::Encoded(otpauth_or_secret.to_string())
                .to_bytes()
                .map_err(|e| anyhow!("decode TOTP secret: {e:?}"))?,
            None,
            "hekate".to_string(),
        )
        .map_err(|e| anyhow!("init TOTP: {e}"))?
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow!("clock: {e}"))?
        .as_secs();
    let period = totp.step;
    let remaining = period - (now % period);
    let code = totp.generate(now);
    Ok((code, remaining))
}
