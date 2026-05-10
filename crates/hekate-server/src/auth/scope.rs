//! Scope grammar shared by JWTs (interactive sessions, all scopes) and
//! PATs (limited set declared at issue time).

use std::collections::HashSet;

/// All scopes recognized by the server. Keep this list in sync with the
/// strings used in handlers and in PAT issuance.
pub const VAULT_READ: &str = "vault:read";
pub const VAULT_WRITE: &str = "vault:write";
pub const ACCOUNT_ADMIN: &str = "account:admin";
/// Service-account scope (M2.5): read org metadata. Future M6 work
/// adds `secrets:read` / `secrets:write` for the Secrets Manager.
pub const ORG_READ: &str = "org:read";

pub const ALL_SCOPES: &[&str] = &[VAULT_READ, VAULT_WRITE, ACCOUNT_ADMIN, ORG_READ];

#[derive(Debug, Clone)]
pub enum ScopeSet {
    /// Interactive session — implicitly carries every scope.
    All,
    /// Restricted PAT — only the listed scopes are permitted.
    Limited(HashSet<String>),
}

impl ScopeSet {
    pub fn permits(&self, scope: &str) -> bool {
        match self {
            Self::All => true,
            Self::Limited(s) => s.contains(scope),
        }
    }

    pub fn from_csv(s: &str) -> Self {
        let set: HashSet<String> = s
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Self::Limited(set)
    }

    pub fn to_csv(&self) -> String {
        match self {
            Self::All => "*".to_string(),
            Self::Limited(s) => {
                let mut v: Vec<&String> = s.iter().collect();
                v.sort();
                v.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")
            }
        }
    }
}

/// Parse a comma-separated scope list, validating each entry against
/// `ALL_SCOPES`. Returns the deduplicated set on success.
pub fn parse_requested_scopes(s: &str) -> Result<HashSet<String>, String> {
    let mut out = HashSet::new();
    for raw in s.split(',') {
        let scope = raw.trim();
        if scope.is_empty() {
            continue;
        }
        if !ALL_SCOPES.contains(&scope) {
            return Err(format!("unknown scope: {scope}"));
        }
        out.insert(scope.to_string());
    }
    if out.is_empty() {
        return Err("at least one scope is required".to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_permits_anything() {
        assert!(ScopeSet::All.permits("vault:read"));
        assert!(ScopeSet::All.permits("anything"));
    }

    #[test]
    fn limited_only_listed() {
        let s = ScopeSet::from_csv("vault:read");
        assert!(s.permits("vault:read"));
        assert!(!s.permits("vault:write"));
    }

    #[test]
    fn parse_validates_against_known() {
        assert!(parse_requested_scopes("vault:read,vault:write").is_ok());
        assert!(parse_requested_scopes("vault:read,bogus").is_err());
        assert!(parse_requested_scopes("").is_err());
    }
}
