//! Local session state: server URL, user identity, OAuth tokens, and the
//! protected (server-encrypted) account material so we can re-derive keys
//! on demand without storing plaintext.
//!
//! Persisted to `<config_dir>/hekate/state.json` with mode 0600 on Unix. The
//! file does NOT contain the master password, the master key, or the
//! decrypted account key — those live only in process memory and are wiped
//! on drop.

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub server_url: String,
    pub user: User,
    pub tokens: Tokens,
    pub account_material: AccountMaterial,
    /// TOFU-pinned pubkey bundles for peers we've fetched. First fetch
    /// records the pin; subsequent fetches require a byte-identical
    /// match. See M2.20 / `commands::peer`.
    #[serde(default)]
    pub peer_pins: std::collections::BTreeMap<String, PeerPin>,
    /// TOFU-pinned org signing pubkeys. Populated on `hekate org accept`
    /// (M4.1) — the invitee verifies the org signing pubkey carried in
    /// the signcryption envelope and pins it locally so subsequent
    /// roster verifications can't be substituted.
    #[serde(default)]
    pub org_pins: std::collections::BTreeMap<String, OrgPin>,
    /// Per-user CLI preferences. Stored on the same state file as
    /// everything else (the file is per-(server, account) and lives
    /// in $XDG_CONFIG_HOME/hekate-cli/). New fields ALWAYS need
    /// `#[serde(default)]` so an older state file can be read by a
    /// newer CLI build without upgrade ceremony.
    #[serde(default)]
    pub prefs: Prefs,
}

/// CLI-side preferences. Defaults are conservative ("warn, don't
/// block") so an upgrade can never lock a user out of their own
/// vault. Strict mode is opt-in via `hekate config strict-manifest on`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Prefs {
    /// When true, BW04 personal-manifest mismatches on `hekate sync`
    /// become a hard error (non-zero exit) instead of a warning.
    /// Default false. See `docs/threat-model-gaps.md` "Open: Vault-
    /// level integrity (followups) — Treat warnings as errors".
    ///
    /// Scope is intentionally limited to the **personal** manifest:
    /// org roster + org cipher manifest still surface as warnings
    /// because they have legitimate transient states (M4 v1 single-
    /// signer model can leave the org cipher manifest stale until
    /// the owner refreshes).
    #[serde(default)]
    pub strict_manifest: bool,
}

/// Pinned pubkey-bundle entry — see M2.20 TOFU pinning. Matched
/// byte-for-byte on every subsequent fetch; mismatch is a load-bearing
/// error event surfacing as either a mid-flight server attack or a
/// legitimate peer key rotation, distinguished only by out-of-band
/// inspection.
/// Pinned org signing-pubkey entry — see M4.1 invite/accept. Recorded
/// at accept-time and verified on every subsequent roster fetch.
/// Distinct from `PeerPin` because orgs aren't users — they have their
/// own signing key (held by the owner) and the trust path comes via
/// the inviter's signcryption envelope rather than the M2.19
/// directory.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct OrgPin {
    pub org_id: String,
    pub signing_pubkey_b64: String,
    /// `SHA256:<base64-no-pad>` over the org bundle canonical bytes
    /// (`pmgr-org-bundle-v1\0` + lp(org_id) + lp(name) + signing_pk +
    /// lp(owner_user_id)). Stable; users compare it OOB if they want
    /// to verify the inviter wasn't compromised.
    pub fingerprint: String,
    pub first_seen_at: String,
    /// Highest roster version the CLI has verified for this org. Used
    /// on every `/sync` to enforce monotonic forward progress (BW08:
    /// the server can't replay an older signed roster to hide a
    /// membership change). Defaults to 0 for pins created before M4.2.
    #[serde(default)]
    pub last_roster_version: i64,
    /// Canonical bytes (base64-no-pad) of the most-recently verified
    /// roster. The next roster's `parent_canonical_sha256` must equal
    /// `SHA256(decode(last_roster_canonical_b64))` — this chains the
    /// rosters together exactly like the M2.15c manifest chain.
    #[serde(default)]
    pub last_roster_canonical_b64: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PeerPin {
    pub user_id: String,
    pub account_signing_pubkey_b64: String,
    pub account_public_key_b64: String,
    pub account_pubkey_bundle_sig_b64: String,
    /// Stable canonical fingerprint — `SHA256:<base64-no-pad>` over the
    /// pmgr-pubkey-bundle-v1 canonical bytes. Compare this aloud / via
    /// Signal / etc. to anchor the TOFU pin.
    pub fingerprint: String,
    pub first_seen_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    /// Server-stable UUIDv7. Persisted from register response (M2.19+) or
    /// from the password-grant token response (M2.20+). May be empty for
    /// pre-M2.19 dev-DB sessions; commands that need it bail with a clear
    /// "re-login" message.
    #[serde(default)]
    pub user_id: String,
    pub email: String,
    /// JSON-encoded KdfParams from hekate-core
    pub kdf_params: serde_json::Value,
    pub kdf_salt_b64: String,
    /// HMAC-SHA256 binding kdf_params + kdf_salt to the master key. Persisted
    /// so subsequent unlocks can re-verify without an additional round trip,
    /// and to detect post-login tampering of the on-disk state file.
    /// Base64-no-pad of 32 bytes.
    #[serde(default)]
    pub kdf_params_mac_b64: String,
    pub account_public_key_b64: String,
    /// Ed25519 account-signing public key (32 bytes, base64-no-pad).
    /// Derived deterministically from the master key on every unlock,
    /// so persistence here is purely a fast-path so the CLI knows which
    /// pubkey the server is verifying signed manifests under without
    /// re-running Argon2id. Empty for accounts registered before M2.15b.
    #[serde(default)]
    pub account_signing_pubkey_b64: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Tokens {
    pub access_token: String,
    /// RFC3339; populated locally from issued_at + expires_in.
    pub expires_at: String,
    pub refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccountMaterial {
    /// EncString wire form, encrypted under the stretched master key.
    pub protected_account_key: String,
    /// EncString wire form, encrypted under the account key.
    pub protected_account_private_key: String,
}

pub fn config_dir() -> Result<PathBuf> {
    let pd = ProjectDirs::from("", "", "hekate")
        .ok_or_else(|| anyhow!("could not resolve XDG config directory"))?;
    Ok(pd.config_dir().to_path_buf())
}

pub fn state_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("state.json"))
}

pub fn load() -> Result<Option<State>> {
    let path = state_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let state: State =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(state))
}

pub fn save(state: &State) -> Result<()> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = state_path()?;
    let bytes = serde_json::to_vec_pretty(state)?;
    write_private(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

pub fn delete() -> Result<bool> {
    let path = state_path()?;
    if path.exists() {
        fs::remove_file(&path)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    use std::io::Write;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! State-file forward/backward compatibility for the new
    //! `prefs` field. The strict-manifest knob lives here; the
    //! `hekate config strict-manifest` command flips it. These tests
    //! make sure pre-M2.x state files (no `prefs` key) still load,
    //! and that round-tripping preserves the bool.
    use super::*;

    fn legacy_state_json() -> &'static str {
        // Verbatim shape of a pre-M2.5-config state.json — the very
        // first thing we check is that this still deserializes.
        r#"{
          "server_url": "http://x",
          "user": {
            "user_id": "uid",
            "email": "a@x.test",
            "kdf_params": {},
            "kdf_salt_b64": "",
            "kdf_params_mac_b64": "",
            "account_public_key_b64": "",
            "account_signing_pubkey_b64": ""
          },
          "tokens": {
            "access_token": "x",
            "expires_at": "1970-01-01T00:00:00Z",
            "refresh_token": "x"
          },
          "account_material": {
            "protected_account_key": "x",
            "protected_account_private_key": "x"
          }
        }"#
    }

    #[test]
    fn default_prefs_is_off() {
        let p = Prefs::default();
        assert!(!p.strict_manifest);
    }

    #[test]
    fn legacy_state_loads_with_default_prefs() {
        let s: State = serde_json::from_str(legacy_state_json()).unwrap();
        assert!(!s.prefs.strict_manifest);
        assert!(s.peer_pins.is_empty());
        assert!(s.org_pins.is_empty());
    }

    #[test]
    fn prefs_round_trips() {
        let mut s: State = serde_json::from_str(legacy_state_json()).unwrap();
        s.prefs.strict_manifest = true;
        let bytes = serde_json::to_vec(&s).unwrap();
        let s2: State = serde_json::from_slice(&bytes).unwrap();
        assert!(s2.prefs.strict_manifest);
    }
}
