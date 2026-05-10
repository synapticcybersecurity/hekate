//! M4.6 client-side policy enforcement.
//!
//! Three policy types arrive via /sync (`OrgSyncView.policies`) and
//! are enforced client-side because the server can't see plaintext:
//!
//!   * `master_password_complexity` — `hekate register` (no-op until
//!     joining an org), `hekate account change-password`
//!   * `vault_timeout`              — caps the unlock-cache daemon TTL
//!   * `password_generator_rules`   — `hekate generate` defaults +
//!     CLI-flag overrides
//!
//! Across orgs the user belongs to, every policy field aggregates via
//! **max strictness** (largest min, every required-flag a logical OR).
//! A user in two orgs sees the toughest rule from either.

use anyhow::{anyhow, Result};
use serde::Deserialize;

use crate::api::Api;

#[derive(Debug, Default, Clone, Copy)]
pub struct MasterPasswordComplexity {
    pub min_length: u64,
    pub require_upper: bool,
    pub require_lower: bool,
    pub require_digit: bool,
    pub require_special: bool,
    pub min_unique_chars: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct VaultTimeout {
    pub max_seconds: u64,
}

#[derive(Debug, Default, Clone)]
pub struct PasswordGeneratorRules {
    pub min_length: u64,
    /// Required character classes — superset of what generation must
    /// include. Each entry is one of "lower" | "upper" | "digit" | "symbol".
    pub character_classes: Vec<String>,
    pub no_ambiguous: bool,
}

#[derive(Default, Debug, Deserialize)]
struct ComplexityFields {
    #[serde(default)]
    min_length: Option<u64>,
    #[serde(default)]
    require_upper: Option<bool>,
    #[serde(default)]
    require_lower: Option<bool>,
    #[serde(default)]
    require_digit: Option<bool>,
    #[serde(default)]
    require_special: Option<bool>,
    #[serde(default)]
    min_unique_chars: Option<u64>,
}

#[derive(Default, Debug, Deserialize)]
struct VaultTimeoutFields {
    #[serde(default)]
    max_seconds: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)] // "lock" vs "logout" is a UX policy the daemon doesn't enact yet
    action: Option<String>,
}

#[derive(Default, Debug, Deserialize)]
struct GeneratorFields {
    #[serde(default)]
    min_length: Option<u64>,
    #[serde(default)]
    character_classes: Option<Vec<String>>,
    #[serde(default)]
    no_ambiguous: Option<bool>,
}

/// Pull all enabled policies from /sync and aggregate them. Returns
/// `Ok(None)` if /sync fails (we treat enforcement as best-effort:
/// can't enforce → fail open rather than blocking offline use).
pub fn fetch_aggregate(api: &Api) -> Result<Option<Aggregated>> {
    let resp = match api.sync(None) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    let mut acc = Aggregated::default();
    for org in &resp.orgs {
        for p in &org.policies {
            if !p.enabled {
                continue;
            }
            match p.policy_type.as_str() {
                "master_password_complexity" => merge_complexity(&mut acc.complexity, &p.config)?,
                "vault_timeout" => merge_vault_timeout(&mut acc.vault_timeout, &p.config)?,
                "password_generator_rules" => merge_generator(&mut acc.generator, &p.config)?,
                // single_org / restrict_send: no client-side merge.
                _ => {}
            }
        }
    }
    Ok(Some(acc))
}

#[derive(Default, Debug, Clone)]
pub struct Aggregated {
    pub complexity: MasterPasswordComplexity,
    pub vault_timeout: VaultTimeout,
    pub generator: PasswordGeneratorRules,
}

fn merge_complexity(out: &mut MasterPasswordComplexity, config: &serde_json::Value) -> Result<()> {
    let f: ComplexityFields = serde_json::from_value(config.clone())
        .map_err(|e| anyhow!("master_password_complexity config: {e}"))?;
    if let Some(n) = f.min_length {
        out.min_length = out.min_length.max(n);
    }
    if let Some(n) = f.min_unique_chars {
        out.min_unique_chars = out.min_unique_chars.max(n);
    }
    out.require_upper |= f.require_upper.unwrap_or(false);
    out.require_lower |= f.require_lower.unwrap_or(false);
    out.require_digit |= f.require_digit.unwrap_or(false);
    out.require_special |= f.require_special.unwrap_or(false);
    Ok(())
}

fn merge_vault_timeout(out: &mut VaultTimeout, config: &serde_json::Value) -> Result<()> {
    let f: VaultTimeoutFields =
        serde_json::from_value(config.clone()).map_err(|e| anyhow!("vault_timeout config: {e}"))?;
    if let Some(n) = f.max_seconds {
        // Strictest = smallest cap. Initialize to "no cap" via 0 sentinel.
        out.max_seconds = if out.max_seconds == 0 {
            n
        } else {
            out.max_seconds.min(n)
        };
    }
    Ok(())
}

fn merge_generator(out: &mut PasswordGeneratorRules, config: &serde_json::Value) -> Result<()> {
    let f: GeneratorFields = serde_json::from_value(config.clone())
        .map_err(|e| anyhow!("password_generator_rules config: {e}"))?;
    if let Some(n) = f.min_length {
        out.min_length = out.min_length.max(n);
    }
    out.no_ambiguous |= f.no_ambiguous.unwrap_or(false);
    if let Some(classes) = f.character_classes {
        for c in classes {
            if !out.character_classes.contains(&c) {
                out.character_classes.push(c);
            }
        }
    }
    Ok(())
}

/// Validate a candidate master password against the aggregated
/// complexity policy. Returns `Err` listing every rule that fails so
/// the user can fix them all in one prompt instead of trying again.
pub fn enforce_master_password(pw: &str, policy: &MasterPasswordComplexity) -> Result<()> {
    let mut errs: Vec<String> = Vec::new();
    if policy.min_length > 0 && (pw.chars().count() as u64) < policy.min_length {
        errs.push(format!("must be at least {} characters", policy.min_length));
    }
    if policy.require_upper && !pw.chars().any(|c| c.is_ascii_uppercase()) {
        errs.push("must contain an uppercase letter".into());
    }
    if policy.require_lower && !pw.chars().any(|c| c.is_ascii_lowercase()) {
        errs.push("must contain a lowercase letter".into());
    }
    if policy.require_digit && !pw.chars().any(|c| c.is_ascii_digit()) {
        errs.push("must contain a digit".into());
    }
    if policy.require_special && !pw.chars().any(|c| !c.is_alphanumeric()) {
        errs.push("must contain a special (non-alphanumeric) character".into());
    }
    if policy.min_unique_chars > 0 {
        let unique = pw.chars().collect::<std::collections::BTreeSet<_>>().len() as u64;
        if unique < policy.min_unique_chars {
            errs.push(format!(
                "must contain at least {} distinct characters",
                policy.min_unique_chars
            ));
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "master password fails org policy:\n  - {}",
            errs.join("\n  - "),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complexity_merges_max_strictness() {
        let mut acc = MasterPasswordComplexity::default();
        merge_complexity(
            &mut acc,
            &serde_json::json!({"min_length": 12, "require_upper": true}),
        )
        .unwrap();
        merge_complexity(
            &mut acc,
            &serde_json::json!({"min_length": 16, "require_digit": true}),
        )
        .unwrap();
        assert_eq!(acc.min_length, 16);
        assert!(acc.require_upper);
        assert!(acc.require_digit);
        assert!(!acc.require_lower);
    }

    #[test]
    fn vault_timeout_takes_smallest_cap() {
        let mut acc = VaultTimeout::default();
        merge_vault_timeout(&mut acc, &serde_json::json!({"max_seconds": 3600})).unwrap();
        merge_vault_timeout(&mut acc, &serde_json::json!({"max_seconds": 900})).unwrap();
        assert_eq!(acc.max_seconds, 900);
    }

    #[test]
    fn enforce_master_password_collects_all_errors() {
        let policy = MasterPasswordComplexity {
            min_length: 12,
            require_upper: true,
            require_digit: true,
            ..Default::default()
        };
        let err = enforce_master_password("short", &policy).unwrap_err();
        let s = format!("{err}");
        assert!(s.contains("at least 12"));
        assert!(s.contains("uppercase"));
        assert!(s.contains("digit"));
    }

    #[test]
    fn enforce_master_password_passes_when_compliant() {
        let policy = MasterPasswordComplexity {
            min_length: 12,
            require_upper: true,
            require_lower: true,
            require_digit: true,
            ..Default::default()
        };
        enforce_master_password("Strong-Password-123", &policy).unwrap();
    }

    #[test]
    fn generator_classes_union() {
        let mut acc = PasswordGeneratorRules::default();
        merge_generator(
            &mut acc,
            &serde_json::json!({"character_classes": ["upper", "digit"]}),
        )
        .unwrap();
        merge_generator(
            &mut acc,
            &serde_json::json!({"character_classes": ["digit", "symbol"]}),
        )
        .unwrap();
        // dedup'd
        assert_eq!(acc.character_classes.len(), 3);
        assert!(acc.character_classes.contains(&"upper".to_string()));
        assert!(acc.character_classes.contains(&"symbol".to_string()));
    }
}
