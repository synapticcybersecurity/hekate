//! M4.4 — collection permission helpers (server side).
//!
//! Permission ordering:
//!   `manage` > `read` > `read_hide_passwords`
//!
//! - `manage`: read + edit (passes server-side write checks).
//! - `read`: read with password visible (decrypts client-side).
//! - `read_hide_passwords`: read but the client UX hides the password.
//!   Server cannot enforce hiding (E2EE) — it's a hint to the client.
//!
//! Effective permission for a cipher = max() across every collection the
//! cipher is in for which the user has a `collection_members` row,
//! short-circuited to `manage` if the user is the org owner.

use crate::{routes::accounts::ApiError, AppState};

/// Permission a user has on a single cipher (or collection). Wire form
/// is the same lowercase strings the schema stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    ReadHidePasswords,
    Read,
    Manage,
}

impl Permission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::Manage => "manage",
            Permission::Read => "read",
            Permission::ReadHidePasswords => "read_hide_passwords",
        }
    }

    pub fn parse(s: &str) -> Option<Permission> {
        match s {
            "manage" => Some(Permission::Manage),
            "read" => Some(Permission::Read),
            "read_hide_passwords" => Some(Permission::ReadHidePasswords),
            _ => None,
        }
    }

    /// True if this permission allows server-side write operations
    /// (PUT / DELETE / restore / purge) on the underlying cipher.
    pub fn can_write(&self) -> bool {
        matches!(self, Permission::Manage)
    }

    /// Lattice merge: take the higher permission. Used when a cipher
    /// is in multiple collections and the user has rows in several.
    pub fn max(self, other: Permission) -> Permission {
        let a = self.rank();
        let b = other.rank();
        if a >= b {
            self
        } else {
            other
        }
    }

    fn rank(&self) -> u8 {
        match self {
            Permission::ReadHidePasswords => 1,
            Permission::Read => 2,
            Permission::Manage => 3,
        }
    }
}

/// Compute the user's effective permission on `cipher_id`. Returns
/// `None` if the user has no access. Owners get implicit `Manage`.
pub async fn effective_permission(
    state: &AppState,
    user_id: &str,
    cipher_id: &str,
) -> Result<Option<Permission>, ApiError> {
    // Owner short-circuit. If the cipher is org-owned and the caller
    // owns the org, return Manage.
    let owner_row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT o.owner_user_id
         FROM ciphers c
         LEFT JOIN organizations o ON o.id = c.org_id
         WHERE c.id = $1",
    )
    .bind(cipher_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    if let Some((Some(owner),)) = owner_row {
        if owner == user_id {
            return Ok(Some(Permission::Manage));
        }
    }

    // Non-owner: walk every collection containing the cipher and
    // gather any permission rows for this user.
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT m.permissions
         FROM cipher_collections cc
         JOIN collection_members m ON m.collection_id = cc.collection_id
         WHERE cc.cipher_id = $1 AND m.user_id = $2",
    )
    .bind(cipher_id)
    .bind(user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let mut best: Option<Permission> = None;
    for (s,) in rows {
        if let Some(p) = Permission::parse(&s) {
            best = Some(match best {
                None => p,
                Some(prev) => prev.max(p),
            });
        }
    }
    Ok(best)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rank_order_is_total_and_correct() {
        let m = Permission::Manage;
        let r = Permission::Read;
        let h = Permission::ReadHidePasswords;
        assert!(m.rank() > r.rank());
        assert!(r.rank() > h.rank());
    }

    #[test]
    fn max_picks_higher() {
        assert_eq!(
            Permission::Read.max(Permission::ReadHidePasswords),
            Permission::Read
        );
        assert_eq!(
            Permission::ReadHidePasswords.max(Permission::Manage),
            Permission::Manage
        );
        assert_eq!(Permission::Manage.max(Permission::Read), Permission::Manage);
    }

    #[test]
    fn only_manage_can_write() {
        assert!(Permission::Manage.can_write());
        assert!(!Permission::Read.can_write());
        assert!(!Permission::ReadHidePasswords.can_write());
    }

    #[test]
    fn parse_round_trips_known_strings() {
        for p in [
            Permission::Manage,
            Permission::Read,
            Permission::ReadHidePasswords,
        ] {
            assert_eq!(Permission::parse(p.as_str()), Some(p));
        }
        assert_eq!(Permission::parse("admin"), None);
        assert_eq!(Permission::parse(""), None);
    }
}
