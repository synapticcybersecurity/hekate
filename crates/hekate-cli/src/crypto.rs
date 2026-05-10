//! CLI-side crypto: unlock the vault from a master password, wrap/unwrap
//! per-cipher keys, and encrypt/decrypt individual cipher fields.
//!
//! AAD strategy (v2, BW04/LP06 mitigation): every cipher's encrypted
//! fields bind the cipher's UUIDv7 `id` and `cipher_type` into the
//! AAD. The `id` is generated client-side at create time so the
//! server can never substitute one cipher's row for another's, and a
//! type flip (e.g. card → login) breaks decryption rather than
//! silently mis-rendering. The wrap key on `protected_cipher_key`
//! binds the `id` (but not the type — the type isn't a property of
//! the wrap key itself).

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use hekate_core::{
    encstring::EncString,
    kdf::{
        derive_kdf_bind_key, derive_master_key, derive_stretched_master_key, verify_kdf_bind_mac,
        KdfParams,
    },
    keypair::random_key_32,
    manifest::{derive_account_signing_seed, AccountSigningSeed},
};
use zeroize::Zeroizing;

use crate::state::State;

// AAD constants — also used in hekate-cli/src/commands/register.rs and account.rs.
pub const AAD_PROTECTED_ACCOUNT_KEY: &[u8] = b"pmgr-account-key";

/// AAD on the per-cipher key wrap (`protected_cipher_key`). Binds the
/// wrapped key to its cipher id so the server can't reassign a wrap
/// from one cipher to another.
pub fn aad_protected_cipher_key(cipher_id: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + cipher_id.len());
    v.extend_from_slice(b"pmgr-cipher-key-v2:");
    v.extend_from_slice(cipher_id.as_bytes());
    v
}

/// AAD on the encrypted `name` field. Binds plaintext to id + type.
pub fn aad_cipher_name(cipher_id: &str, cipher_type: i32) -> Vec<u8> {
    aad_field(b"name", cipher_id, cipher_type)
}

/// AAD on the encrypted `notes` field. Binds plaintext to id + type.
pub fn aad_cipher_notes(cipher_id: &str, cipher_type: i32) -> Vec<u8> {
    aad_field(b"notes", cipher_id, cipher_type)
}

/// AAD on the encrypted `data` JSON. Binds plaintext to id + type so a
/// server-flipped type doesn't silently make a card render as a login.
pub fn aad_cipher_data(cipher_id: &str, cipher_type: i32) -> Vec<u8> {
    aad_field(b"data", cipher_id, cipher_type)
}

fn aad_field(role: &[u8], cipher_id: &str, cipher_type: i32) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + cipher_id.len());
    v.extend_from_slice(b"pmgr-cipher-");
    v.extend_from_slice(role);
    v.extend_from_slice(b"-v2:");
    v.extend_from_slice(cipher_id.as_bytes());
    v.push(b':');
    // i32 max is ~10 chars; use itoa-equivalent via Display.
    v.extend_from_slice(cipher_type.to_string().as_bytes());
    v
}

/// Held in memory only; wipes on drop.
pub struct Unlocked {
    pub account_key: Zeroizing<[u8; 32]>,
    /// Ed25519 seed derived from the master key. Used to sign the
    /// per-user vault manifest. See `hekate-core::manifest`. Wrapped in
    /// `Zeroizing` because possession is equivalent to the master
    /// password from the signing perspective.
    pub signing_seed: AccountSigningSeed,
}

/// Run Argon2id over `password`, derive the stretched master key, and use
/// it to unwrap the account key from the state file. This is the slow
/// (~500 ms) step on every CLI command that touches encrypted data.
pub fn unlock(state: &State, password: &str) -> Result<Unlocked> {
    let kdf_params: KdfParams = serde_json::from_value(state.user.kdf_params.clone())
        .context("state file kdf_params is unrecognized")?;
    let salt = STANDARD_NO_PAD
        .decode(&state.user.kdf_salt_b64)
        .context("kdf_salt_b64 in state is not base64-no-pad")?;
    if state.user.kdf_params_mac_b64.is_empty() {
        return Err(anyhow!(
            "state file is missing kdf_params_mac (older login). \
             Run `hekate login` to refresh."
        ));
    }
    let mac_bytes = STANDARD_NO_PAD
        .decode(&state.user.kdf_params_mac_b64)
        .context("kdf_params_mac_b64 in state is not base64-no-pad")?;
    if mac_bytes.len() != 32 {
        return Err(anyhow!("kdf_params_mac in state has wrong length"));
    }
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&mac_bytes);

    let mk = derive_master_key(password.as_bytes(), kdf_params, &salt)
        .context("Argon2id derivation failed")?;

    // Defense-in-depth against on-disk state-file tampering: an attacker
    // who can write the state file but doesn't know the master password
    // could otherwise downgrade kdf_params there so a future re-login
    // captures a brute-forceable mph. Verifying the MAC under the just-
    // derived master key catches that — and is also the only way to
    // distinguish "wrong master password" from "state file was tampered".
    let bind_key = derive_kdf_bind_key(&mk);
    if !verify_kdf_bind_mac(&bind_key, kdf_params, &salt, &tag) {
        return Err(anyhow!(
            "state file's kdf params do not match the MAC — possible \
             tampering, or the master password is wrong. Re-run \
             `hekate login` to recover."
        ));
    }
    let smk = derive_stretched_master_key(&mk);

    let pak = EncString::parse(&state.account_material.protected_account_key)
        .context("state file's protected_account_key is malformed")?;
    let bytes = pak
        .decrypt_xc20p(&smk, Some(AAD_PROTECTED_ACCOUNT_KEY))
        .map_err(|_| anyhow!("wrong master password"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("decrypted account key has wrong length"));
    }
    let mut account_key = Zeroizing::new([0u8; 32]);
    account_key.copy_from_slice(&bytes);
    let signing_seed = derive_account_signing_seed(&mk);
    Ok(Unlocked {
        account_key,
        signing_seed,
    })
}

/// Generate a fresh per-cipher key, wrap it under the account key with
/// the cipher's id bound into the AAD.
pub fn new_cipher_key(
    unlocked: &Unlocked,
    cipher_id: &str,
) -> Result<(Zeroizing<[u8; 32]>, String)> {
    new_cipher_key_under(&unlocked.account_key, "ak:1", cipher_id)
}

pub fn unwrap_cipher_key(
    unlocked: &Unlocked,
    wire: &str,
    cipher_id: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    unwrap_cipher_key_under(&unlocked.account_key, wire, cipher_id)
}

/// Generate a per-cipher key and wrap it under the supplied 32-byte
/// key. Same shape as `new_cipher_key` but parameterized over the
/// wrap key — used for org-owned ciphers (M4.3) where the wrap key
/// is the org symmetric key, not the user's account key.
pub fn new_cipher_key_under(
    wrap_key: &[u8; 32],
    key_id: &str,
    cipher_id: &str,
) -> Result<(Zeroizing<[u8; 32]>, String)> {
    let cipher_key = random_key_32();
    let aad = aad_protected_cipher_key(cipher_id);
    let wrapped = EncString::encrypt_xc20p(key_id, wrap_key, &cipher_key[..], &aad)
        .map_err(|e| anyhow!("wrap cipher key: {e}"))?
        .to_wire();
    Ok((cipher_key, wrapped))
}

pub fn unwrap_cipher_key_under(
    wrap_key: &[u8; 32],
    wire: &str,
    cipher_id: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    let s = EncString::parse(wire).context("malformed protected_cipher_key")?;
    let aad = aad_protected_cipher_key(cipher_id);
    let bytes = s.decrypt_xc20p(wrap_key, Some(&aad)).map_err(|_| {
        anyhow!(
            "could not decrypt cipher key — server may have substituted \
             the wrap or the row id (BW04/LP06 mitigation tripped)"
        )
    })?;
    if bytes.len() != 32 {
        return Err(anyhow!("decrypted cipher key has wrong length"));
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&bytes);
    Ok(k)
}

pub fn encrypt_field(cipher_key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<String> {
    Ok(EncString::encrypt_xc20p("ck:1", cipher_key, plaintext, aad)
        .map_err(|e| anyhow!("encrypt: {e}"))?
        .to_wire())
}

pub fn decrypt_field(cipher_key: &[u8; 32], wire: &str, aad: &[u8]) -> Result<Vec<u8>> {
    let s = EncString::parse(wire).context("malformed cipher field")?;
    s.decrypt_xc20p(cipher_key, Some(aad))
        .map_err(|e| anyhow!("decrypt: {e}"))
}

pub fn decrypt_field_string(cipher_key: &[u8; 32], wire: &str, aad: &[u8]) -> Result<String> {
    let bytes = decrypt_field(cipher_key, wire, aad)?;
    String::from_utf8(bytes).map_err(|_| anyhow!("decrypted field is not valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{self, AccountMaterial, State, Tokens, User};
    use hekate_core::kdf::{compute_kdf_bind_mac, derive_master_key, KdfParams};

    fn fast_params() -> KdfParams {
        // Same weak params the hekate-core kdf tests use; keeps this test
        // sub-second.
        KdfParams::Argon2id {
            m_kib: 64,
            t: 1,
            p: 1,
        }
    }

    fn build_state(password: &str, params: KdfParams, salt: &[u8; 16]) -> State {
        let mk = derive_master_key(password.as_bytes(), params, salt).unwrap();
        let smk = derive_stretched_master_key(&mk);
        let bind_key = hekate_core::kdf::derive_kdf_bind_key(&mk);
        let tag = compute_kdf_bind_mac(&bind_key, params, salt);

        // Random account key, wrapped under the stretched master key with
        // the same AAD the production unlock checks.
        let account_key = random_key_32();
        let pak =
            EncString::encrypt_xc20p("smk:1", &smk, &account_key[..], AAD_PROTECTED_ACCOUNT_KEY)
                .unwrap()
                .to_wire();

        State {
            server_url: "http://test".into(),
            user: User {
                user_id: String::new(),
                email: "alice@example.com".into(),
                kdf_params: serde_json::to_value(params).unwrap(),
                kdf_salt_b64: STANDARD_NO_PAD.encode(salt),
                kdf_params_mac_b64: STANDARD_NO_PAD.encode(tag),
                account_public_key_b64: String::new(),
                account_signing_pubkey_b64: String::new(),
            },
            tokens: Tokens {
                access_token: String::new(),
                expires_at: String::new(),
                refresh_token: String::new(),
            },
            account_material: AccountMaterial {
                protected_account_key: pak,
                protected_account_private_key: String::new(),
            },
            peer_pins: std::collections::BTreeMap::new(),
            org_pins: std::collections::BTreeMap::new(),
            prefs: state::Prefs::default(),
        }
    }

    #[test]
    fn unlock_succeeds_on_unmodified_state() {
        let s = build_state("hunter2", fast_params(), &[0u8; 16]);
        unlock(&s, "hunter2").expect("valid state should unlock");
    }

    #[test]
    fn unlock_rejects_tampered_kdf_params() {
        let mut s = build_state("hunter2", fast_params(), &[0u8; 16]);
        // Attacker downgrades the on-disk params after login. Argon2id
        // would still produce *a* master key, but the MAC won't match.
        s.user.kdf_params = serde_json::to_value(KdfParams::Argon2id {
            m_kib: 64,
            t: 1,
            p: 4, // changed from p=1 above
        })
        .unwrap();
        let err = unlock(&s, "hunter2").err().unwrap().to_string();
        assert!(
            err.contains("kdf params do not match the MAC"),
            "expected tampering error, got: {err}"
        );
    }

    #[test]
    fn unlock_rejects_tampered_salt() {
        let mut s = build_state("hunter2", fast_params(), &[0u8; 16]);
        s.user.kdf_salt_b64 = STANDARD_NO_PAD.encode([0xa5u8; 16]);
        let err = unlock(&s, "hunter2").err().unwrap().to_string();
        assert!(
            err.contains("kdf params do not match the MAC"),
            "expected tampering error, got: {err}"
        );
    }

    #[test]
    fn unlock_rejects_missing_mac() {
        let mut s = build_state("hunter2", fast_params(), &[0u8; 16]);
        s.user.kdf_params_mac_b64.clear();
        let err = unlock(&s, "hunter2").err().unwrap().to_string();
        assert!(
            err.contains("missing kdf_params_mac"),
            "expected missing-MAC error, got: {err}"
        );
    }

    #[test]
    fn unlock_rejects_wrong_password_with_mac_verify_failure() {
        // With a wrong password, the derived master key — and therefore
        // the bind key — is wrong; the MAC check fails before we even
        // attempt to decrypt the account key. That's fine: the user
        // sees a "kdf params do not match" message which is already
        // covered by the wording of the production error.
        let s = build_state("hunter2", fast_params(), &[0u8; 16]);
        assert!(unlock(&s, "wrong").is_err());
    }
}
