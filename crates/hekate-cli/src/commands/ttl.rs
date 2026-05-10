//! Tiny TTL parser for strings like "15m", "1h", "300s".

use std::time::Duration;

use anyhow::{anyhow, Result};

pub fn parse_ttl(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return Err(anyhow!("empty TTL"));
    }
    let (num, unit) = s.split_at(s.len() - 1);
    // Allow plain digits to default to seconds.
    if unit.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        let n: u64 = s.parse()?;
        return Ok(Duration::from_secs(n));
    }
    let n: u64 = num.trim().parse()?;
    let mul = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        other => return Err(anyhow!("unknown TTL unit: {other:?}")),
    };
    Ok(Duration::from_secs(n.saturating_mul(mul)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units() {
        assert_eq!(parse_ttl("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_ttl("15m").unwrap(), Duration::from_secs(15 * 60));
        assert_eq!(parse_ttl("2h").unwrap(), Duration::from_secs(2 * 3600));
        assert_eq!(parse_ttl("1d").unwrap(), Duration::from_secs(86400));
    }

    #[test]
    fn defaults_bare_digits_to_seconds() {
        assert_eq!(parse_ttl("90").unwrap(), Duration::from_secs(90));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("abc").is_err());
        assert!(parse_ttl("5x").is_err());
    }
}
