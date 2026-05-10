//! M4.2 — verify org rosters returned by `/api/v1/sync` against the
//! locally-pinned org signing pubkeys.
//!
//! This is the BW08 mitigation on the routine read path. M4.1 already
//! does it once at accept time; M4.2 closes the loop so a server can't
//! later replay a stale roster, hide a removal, or sneak in a member
//! the org owner never signed.
//!
//! Per-org check on every `/sync`:
//!
//!   1. We must have a local pin for the org. No pin → we never
//!      accepted; any roster the server is now claiming to be ours is
//!      forged. Surface as a warning (load-bearing — caller decides
//!      whether to refuse subsequent operations).
//!   2. Roster signature verifies under the *pinned* signing pubkey
//!      (not whatever pubkey the server claims today).
//!   3. `roster.version >= pin.last_roster_version`. Server cannot
//!      replay an older signed roster to mask a more recent change.
//!   4. If `roster.version > pin.last_roster_version`, the new
//!      `parent_canonical_sha256` must equal `SHA256(pin.last_canonical)`
//!      — chain integrity, identical to the M2.15c manifest chain.
//!   5. The caller (us) is listed in the roster at the role the server
//!      claims for us. Server can't unilaterally promote/demote us.
//!
//! On success the pin advances (`last_roster_version` + canonical bytes).
//! Returned warnings are user-facing and printed by `hekate sync`.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use hekate_core::org_roster::{decode_canonical, hash_canonical};

use crate::{
    api::{OrgSyncView, SyncResponse},
    state::{OrgPin, State},
};

/// Verify every org roster in `sync.orgs` against the pin map.
///
/// Returns `(warnings, pin_advances)`. `pin_advances` carries the
/// updated `OrgPin` rows the caller should write back; we don't mutate
/// state in place because the caller may want to skip the save (e.g.
/// when warnings make us want to refuse the whole sync). The pin
/// advance is only emitted when verification fully succeeded for the
/// org.
pub fn verify_against_sync(
    sync: &SyncResponse,
    state: &State,
    expected_user_id: &str,
) -> Result<(Vec<String>, Vec<OrgPin>)> {
    let mut warnings = Vec::new();
    let mut advances = Vec::new();

    for entry in &sync.orgs {
        match verify_one(entry, state, expected_user_id) {
            Ok(advance) => advances.push(advance),
            Err(w) => warnings.push(w),
        }
    }
    Ok((warnings, advances))
}

fn verify_one(
    entry: &OrgSyncView,
    state: &State,
    expected_user_id: &str,
) -> std::result::Result<OrgPin, String> {
    let pin = state.org_pins.get(&entry.org_id).ok_or_else(|| {
        format!(
            "org {} returned by /sync but we have no local pin — \
             we never accepted. Server is fabricating membership (BW08).",
            entry.org_id
        )
    })?;

    let pubkey = parse_pubkey(&pin.signing_pubkey_b64).map_err(|e| {
        format!(
            "org {}: pinned signing pubkey could not be decoded: {e}",
            entry.org_id
        )
    })?;

    let canonical = STANDARD_NO_PAD
        .decode(&entry.roster.canonical_b64)
        .map_err(|e| format!("org {}: roster canonical_b64 not base64: {e}", entry.org_id))?;
    let sig_bytes = STANDARD_NO_PAD
        .decode(&entry.roster.signature_b64)
        .map_err(|e| format!("org {}: roster signature_b64 not base64: {e}", entry.org_id))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| format!("org {}: roster signature has wrong length", entry.org_id))?;
    pubkey.verify_strict(&canonical, &signature).map_err(|_| {
        format!(
            "org {}: roster signature did NOT verify under the pinned \
                 signing key — server is serving a forged or substituted roster",
            entry.org_id
        )
    })?;

    let parsed = decode_canonical(&canonical).map_err(|e| {
        format!(
            "org {}: roster canonical bytes did not parse: {e}",
            entry.org_id
        )
    })?;

    if parsed.org_id != entry.org_id {
        return Err(format!(
            "org {}: roster's embedded org_id ({}) does not match the \
             outer entry — server tampering",
            entry.org_id, parsed.org_id
        ));
    }
    if parsed.version != entry.roster_version as u64 {
        return Err(format!(
            "org {}: outer roster_version ({}) does not match canonical \
             bytes ({}) — server tampering",
            entry.org_id, entry.roster_version, parsed.version
        ));
    }

    // Forward-progress: the server cannot replay a stale roster to
    // hide a more-recent change.
    if (parsed.version as i64) < pin.last_roster_version {
        return Err(format!(
            "org {}: server returned roster v{}, but we previously verified \
             v{} — possible roster rollback",
            entry.org_id, parsed.version, pin.last_roster_version
        ));
    }

    // Chain integrity: when the version advances, the new roster's
    // parent must equal SHA256 of our last-seen canonical bytes.
    if (parsed.version as i64) > pin.last_roster_version
        && pin.last_roster_version > 0
        && !pin.last_roster_canonical_b64.is_empty()
    {
        let prior = STANDARD_NO_PAD
            .decode(&pin.last_roster_canonical_b64)
            .map_err(|e| format!("org {}: cached canonical not base64: {e}", entry.org_id))?;
        let expected_parent = hash_canonical(&prior);
        if parsed.parent_canonical_sha256 != expected_parent {
            return Err(format!(
                "org {}: roster v{} parent hash does not chain from our \
                 cached v{} — possible server-fork or roster substitution",
                entry.org_id, parsed.version, pin.last_roster_version
            ));
        }
    }

    // Self-membership at claimed role.
    let mine = parsed
        .entries
        .iter()
        .find(|e| e.user_id == expected_user_id);
    match mine {
        None => {
            return Err(format!(
                "org {}: signed roster does not list us — server is \
                 lying about our membership",
                entry.org_id
            ));
        }
        Some(e) if e.role != entry.role => {
            return Err(format!(
                "org {}: server says we are \"{}\" but the signed roster \
                 says \"{}\" — server-side role substitution",
                entry.org_id, entry.role, e.role
            ));
        }
        Some(_) => {}
    }

    Ok(OrgPin {
        last_roster_version: parsed.version as i64,
        last_roster_canonical_b64: entry.roster.canonical_b64.clone(),
        ..pin.clone()
    })
}

fn parse_pubkey(b64: &str) -> Result<VerifyingKey> {
    let bytes = STANDARD_NO_PAD
        .decode(b64)
        .map_err(|e| anyhow!("not base64-no-pad: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("pubkey not 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|_| anyhow!("not a valid Ed25519 pubkey"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::{OrgSyncView, SignedOrgRosterWire, SyncChanges, SyncResponse},
        state::{AccountMaterial, OrgPin, State, Tokens, User},
    };
    use ed25519_dalek::SigningKey;
    use hekate_core::org_roster::{OrgRoster, OrgRosterEntry, NO_PARENT_HASH};
    use std::collections::BTreeMap;

    fn empty_sync(orgs: Vec<OrgSyncView>) -> SyncResponse {
        SyncResponse {
            changes: SyncChanges {
                ciphers: vec![],
                folders: vec![],
                tombstones: vec![],
                collections: vec![],
                attachments: vec![],
                sends: vec![],
            },
            high_water: "1970-01-01T00:00:00Z".into(),
            server_time: "1970-01-01T00:00:00Z".into(),
            complete: true,
            manifest: None,
            orgs,
        }
    }

    fn state_with_pin(pin: OrgPin) -> State {
        let mut org_pins = BTreeMap::new();
        org_pins.insert(pin.org_id.clone(), pin);
        State {
            server_url: "http://x".into(),
            user: User {
                user_id: "0192e0a0-0000-7000-8000-aaaaaaaaaaaa".into(),
                email: "a@x.test".into(),
                kdf_params: serde_json::json!({}),
                kdf_salt_b64: "AA".into(),
                kdf_params_mac_b64: "AA".into(),
                account_public_key_b64: "AA".into(),
                account_signing_pubkey_b64: "AA".into(),
            },
            tokens: Tokens {
                access_token: "x".into(),
                expires_at: "1970-01-01T00:00:00Z".into(),
                refresh_token: "x".into(),
            },
            account_material: AccountMaterial {
                protected_account_key: "x".into(),
                protected_account_private_key: "x".into(),
            },
            peer_pins: BTreeMap::new(),
            org_pins,
            prefs: Default::default(),
        }
    }

    fn pubkey_b64(sk: &SigningKey) -> String {
        STANDARD_NO_PAD.encode(sk.verifying_key().to_bytes())
    }

    fn roster_view(
        org_id: &str,
        version: u64,
        parent: [u8; 32],
        entries: Vec<OrgRosterEntry>,
        sk: &SigningKey,
        role: &str,
    ) -> OrgSyncView {
        let r = OrgRoster {
            org_id: org_id.into(),
            version,
            parent_canonical_sha256: parent,
            timestamp: "1970-01-01T00:00:00Z".into(),
            entries,
            org_sym_key_id: "key1".into(),
        };
        let signed = r.sign(sk);
        OrgSyncView {
            org_id: org_id.into(),
            name: "Acme".into(),
            role: role.into(),
            org_sym_key_id: "key1".into(),
            roster_version: version as i64,
            roster_updated_at: "1970-01-01T00:00:00Z".into(),
            roster: SignedOrgRosterWire {
                canonical_b64: signed.canonical_b64,
                signature_b64: signed.signature_b64,
            },
            pending_envelope: None,
            policies: Vec::new(),
            cipher_manifest: None,
        }
    }

    #[test]
    fn fresh_pin_accepts_first_roster_and_advances() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let me = "0192e0a0-0000-7000-8000-aaaaaaaaaaaa";
        let view = roster_view(
            "org-1",
            1,
            NO_PARENT_HASH,
            vec![OrgRosterEntry {
                user_id: me.into(),
                role: "owner".into(),
            }],
            &sk,
            "owner",
        );
        let pin = OrgPin {
            org_id: "org-1".into(),
            signing_pubkey_b64: pubkey_b64(&sk),
            fingerprint: "x".into(),
            first_seen_at: "x".into(),
            last_roster_version: 0,
            last_roster_canonical_b64: String::new(),
        };
        let st = state_with_pin(pin);
        let (w, a) = verify_against_sync(&empty_sync(vec![view.clone()]), &st, me).unwrap();
        assert!(w.is_empty(), "no warnings: {w:?}");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].last_roster_version, 1);
        assert_eq!(a[0].last_roster_canonical_b64, view.roster.canonical_b64);
    }

    #[test]
    fn rejects_unpinned_org() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let me = "0192e0a0-0000-7000-8000-aaaaaaaaaaaa";
        let view = roster_view(
            "org-fake",
            1,
            NO_PARENT_HASH,
            vec![OrgRosterEntry {
                user_id: me.into(),
                role: "user".into(),
            }],
            &sk,
            "user",
        );
        let pin = OrgPin {
            org_id: "different-org".into(),
            signing_pubkey_b64: pubkey_b64(&sk),
            fingerprint: "x".into(),
            first_seen_at: "x".into(),
            last_roster_version: 0,
            last_roster_canonical_b64: String::new(),
        };
        let st = state_with_pin(pin);
        let (w, a) = verify_against_sync(&empty_sync(vec![view]), &st, me).unwrap();
        assert_eq!(a.len(), 0);
        assert!(w[0].contains("we have no local pin"));
    }

    #[test]
    fn rejects_signature_under_wrong_key() {
        let real = SigningKey::from_bytes(&[1u8; 32]);
        let attacker = SigningKey::from_bytes(&[2u8; 32]);
        let me = "0192e0a0-0000-7000-8000-aaaaaaaaaaaa";
        let view = roster_view(
            "org-1",
            1,
            NO_PARENT_HASH,
            vec![OrgRosterEntry {
                user_id: me.into(),
                role: "owner".into(),
            }],
            &attacker,
            "owner",
        );
        let pin = OrgPin {
            org_id: "org-1".into(),
            signing_pubkey_b64: pubkey_b64(&real),
            fingerprint: "x".into(),
            first_seen_at: "x".into(),
            last_roster_version: 0,
            last_roster_canonical_b64: String::new(),
        };
        let st = state_with_pin(pin);
        let (w, a) = verify_against_sync(&empty_sync(vec![view]), &st, me).unwrap();
        assert_eq!(a.len(), 0);
        assert!(w[0].contains("did NOT verify"));
    }

    #[test]
    fn rejects_stale_roster_version() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let me = "0192e0a0-0000-7000-8000-aaaaaaaaaaaa";
        let v1 = roster_view(
            "org-1",
            1,
            NO_PARENT_HASH,
            vec![OrgRosterEntry {
                user_id: me.into(),
                role: "owner".into(),
            }],
            &sk,
            "owner",
        );
        // Pin already at v3; server tries to replay v1.
        let pin = OrgPin {
            org_id: "org-1".into(),
            signing_pubkey_b64: pubkey_b64(&sk),
            fingerprint: "x".into(),
            first_seen_at: "x".into(),
            last_roster_version: 3,
            last_roster_canonical_b64: v1.roster.canonical_b64.clone(),
        };
        let st = state_with_pin(pin);
        let (w, a) = verify_against_sync(&empty_sync(vec![v1]), &st, me).unwrap();
        assert_eq!(a.len(), 0);
        assert!(w[0].contains("rollback"));
    }

    #[test]
    fn rejects_broken_parent_chain() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let me = "0192e0a0-0000-7000-8000-aaaaaaaaaaaa";
        // Pin says we last saw v1 with canonical X, but the new v2's
        // parent_hash is 0xff (not SHA256(X)).
        let real_v1 = roster_view(
            "org-1",
            1,
            NO_PARENT_HASH,
            vec![OrgRosterEntry {
                user_id: me.into(),
                role: "owner".into(),
            }],
            &sk,
            "owner",
        );
        let v2_bad_parent = roster_view(
            "org-1",
            2,
            [0xffu8; 32],
            vec![OrgRosterEntry {
                user_id: me.into(),
                role: "owner".into(),
            }],
            &sk,
            "owner",
        );
        let pin = OrgPin {
            org_id: "org-1".into(),
            signing_pubkey_b64: pubkey_b64(&sk),
            fingerprint: "x".into(),
            first_seen_at: "x".into(),
            last_roster_version: 1,
            last_roster_canonical_b64: real_v1.roster.canonical_b64,
        };
        let st = state_with_pin(pin);
        let (w, a) = verify_against_sync(&empty_sync(vec![v2_bad_parent]), &st, me).unwrap();
        assert_eq!(a.len(), 0);
        assert!(w[0].contains("does not chain"));
    }

    #[test]
    fn rejects_self_missing_from_roster() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let me = "0192e0a0-0000-7000-8000-aaaaaaaaaaaa";
        let view = roster_view(
            "org-1",
            1,
            NO_PARENT_HASH,
            vec![OrgRosterEntry {
                user_id: "someone-else".into(),
                role: "owner".into(),
            }],
            &sk,
            "user", // server claims I'm a user
        );
        let pin = OrgPin {
            org_id: "org-1".into(),
            signing_pubkey_b64: pubkey_b64(&sk),
            fingerprint: "x".into(),
            first_seen_at: "x".into(),
            last_roster_version: 0,
            last_roster_canonical_b64: String::new(),
        };
        let st = state_with_pin(pin);
        let (w, a) = verify_against_sync(&empty_sync(vec![view]), &st, me).unwrap();
        assert_eq!(a.len(), 0);
        assert!(w[0].contains("does not list us"));
    }

    #[test]
    fn rejects_role_substitution() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let me = "0192e0a0-0000-7000-8000-aaaaaaaaaaaa";
        // Roster says I'm "user" but the outer entry claims "owner".
        let view = roster_view(
            "org-1",
            1,
            NO_PARENT_HASH,
            vec![OrgRosterEntry {
                user_id: me.into(),
                role: "user".into(),
            }],
            &sk,
            "owner",
        );
        let pin = OrgPin {
            org_id: "org-1".into(),
            signing_pubkey_b64: pubkey_b64(&sk),
            fingerprint: "x".into(),
            first_seen_at: "x".into(),
            last_roster_version: 0,
            last_roster_canonical_b64: String::new(),
        };
        let st = state_with_pin(pin);
        let (w, a) = verify_against_sync(&empty_sync(vec![view]), &st, me).unwrap();
        assert_eq!(a.len(), 0);
        assert!(w[0].contains("role substitution"));
    }
}
