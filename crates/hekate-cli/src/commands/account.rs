//! `hekate account` — change-password, delete, export.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use clap::{Parser, Subcommand};
use hekate_core::{
    encstring::EncString,
    kdf::{
        compute_kdf_bind_mac, derive_kdf_bind_key, derive_master_key, derive_master_password_hash,
        derive_stretched_master_key, KdfParams,
    },
};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;

use crate::{
    api::{Api, ChangePasswordRequest},
    commands::persist_refreshed_tokens,
    crypto::AAD_PROTECTED_ACCOUNT_KEY,
    prompt, state,
};

#[derive(Debug, Parser)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Debug, Subcommand)]
pub enum Action {
    /// Change the master password. Rotates the account-key wrapping and
    /// invalidates every other session.
    ChangePassword,
    /// (M2.26) Rotate the account_key — generates a fresh symmetric
    /// account_key, re-wraps the X25519 private key, every personal
    /// cipher PCK, every Send key, and every org membership wrap, in
    /// one atomic server call. Master password is unchanged. Other
    /// devices need to re-login (their refresh tokens are revoked) but
    /// pinned peer pubkeys + the BW04 manifest are unaffected.
    RotateKeys,
    /// Permanently delete the account and all its data on the server.
    Delete(DeleteArgs),
    /// Write an encrypted backup of the entire vault to a file.
    Export(ExportArgs),
    /// TOTP 2FA + recovery codes (M2.22).
    #[command(name = "2fa")]
    TwoFactor(crate::commands::two_factor::Args),
}

#[derive(Debug, Parser)]
pub struct DeleteArgs {
    /// Skip the typed-confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Parser)]
pub struct ExportArgs {
    /// Output file. Will be overwritten if it exists.
    pub file: PathBuf,
}

pub fn run(args: Args) -> Result<()> {
    match args.action {
        Action::ChangePassword => change_password(),
        Action::RotateKeys => rotate_keys(),
        Action::Delete(d) => delete(d),
        Action::Export(e) => export(e),
        Action::TwoFactor(a) => crate::commands::two_factor::run(a),
    }
}

// ---- change password -----------------------------------------------------

fn change_password() -> Result<()> {
    let st = state::load()?.ok_or_else(|| anyhow!("not logged in. Run `hekate login` first."))?;
    let api = Api::new(&st.server_url)?
        .with_bearer(st.tokens.access_token.clone())
        .with_refresh(st.tokens.refresh_token.clone());

    let cur_pw = prompt::password("Current master password: ")?;
    let new_pw = prompt::password("New master password: ")?;
    let new_pw2 = prompt::password("Repeat new master password: ")?;
    if new_pw != new_pw2 {
        return Err(anyhow!("new passwords did not match"));
    }
    if new_pw.len() < 8 {
        return Err(anyhow!("new master password must be at least 8 characters"));
    }
    if cur_pw == new_pw {
        return Err(anyhow!(
            "new master password must differ from the current one"
        ));
    }

    // M4.6 master_password_complexity: aggregate every enabled policy
    // across the orgs we belong to and apply max strictness to the
    // candidate password before any keys are derived.
    if let Some(agg) = crate::policies::fetch_aggregate(&api)? {
        crate::policies::enforce_master_password(&new_pw, &agg.complexity)?;
    }

    println!("Deriving keys (Argon2id, twice — this is the slow part)...");
    let cur_kdf: KdfParams = serde_json::from_value(st.user.kdf_params.clone())?;
    let cur_salt = STANDARD_NO_PAD.decode(&st.user.kdf_salt_b64)?;
    let cur_mk = derive_master_key(cur_pw.as_bytes(), cur_kdf, &cur_salt)?;
    let cur_smk = derive_stretched_master_key(&cur_mk);
    let cur_mph = derive_master_password_hash(&cur_mk);

    // Decrypt the existing account key.
    let pak = EncString::parse(&st.account_material.protected_account_key)?;
    let bytes = pak
        .decrypt_xc20p(&cur_smk, Some(AAD_PROTECTED_ACCOUNT_KEY))
        .map_err(|_| anyhow!("wrong current master password"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("decrypted account key has wrong length"));
    }
    let mut account_key = [0u8; 32];
    account_key.copy_from_slice(&bytes);

    // Derive the new wrapping key.
    let mut new_salt = [0u8; 16];
    OsRng.fill_bytes(&mut new_salt);
    // Reuse the current KDF params; users can bump them via a future flag.
    let new_kdf = cur_kdf;
    let new_mk = derive_master_key(new_pw.as_bytes(), new_kdf, &new_salt)?;
    let new_smk = derive_stretched_master_key(&new_mk);
    let new_mph = derive_master_password_hash(&new_mk);
    let new_bind_key = derive_kdf_bind_key(&new_mk);
    let new_kdf_params_mac = compute_kdf_bind_mac(&new_bind_key, new_kdf, &new_salt);
    let new_kdf_params_mac_b64 = STANDARD_NO_PAD.encode(new_kdf_params_mac);

    // Re-wrap the account key under the new stretched master key.
    let new_pak = EncString::encrypt_xc20p(
        "smk:1",
        &new_smk,
        &account_key[..],
        AAD_PROTECTED_ACCOUNT_KEY,
    )
    .map_err(|e| anyhow!("re-wrap account key: {e}"))?
    .to_wire();

    // BW04: master-key change rotates the Ed25519 signing seed too. Send
    // the new pubkey atomically so the server can re-key its stored
    // pubkey alongside the wrapped account key. The server also wipes
    // its vault_manifests row so the next write uploads a fresh genesis.
    let new_signing_pubkey_b64 = STANDARD_NO_PAD.encode(
        hekate_core::manifest::verifying_key_from_seed(
            &hekate_core::manifest::derive_account_signing_seed(&new_mk),
        )
        .as_bytes(),
    );

    // Send to server.
    let resp = api.change_password(&ChangePasswordRequest {
        current_master_password_hash: STANDARD_NO_PAD.encode(cur_mph),
        new_master_password_hash: STANDARD_NO_PAD.encode(new_mph),
        new_kdf_params: serde_json::to_value(new_kdf)?,
        new_kdf_salt: STANDARD_NO_PAD.encode(new_salt),
        new_kdf_params_mac: new_kdf_params_mac_b64.clone(),
        new_protected_account_key: new_pak.clone(),
        new_account_signing_pubkey: new_signing_pubkey_b64.clone(),
    })?;

    // Persist new state — KDF salt, protected_account_key, and fresh tokens.
    let new_state = state::State {
        server_url: st.server_url,
        user: state::User {
            user_id: st.user.user_id,
            email: st.user.email,
            kdf_params: serde_json::to_value(new_kdf)?,
            kdf_salt_b64: STANDARD_NO_PAD.encode(new_salt),
            kdf_params_mac_b64: new_kdf_params_mac_b64,
            account_public_key_b64: st.user.account_public_key_b64,
            // The signing pubkey is derived from the master key. Master
            // password changed → master key changed → signing key changed
            // too. The matching server-side update happens elsewhere (see
            // change_password handler / account_signing_pubkey_b64 column).
            account_signing_pubkey_b64: STANDARD_NO_PAD.encode(
                hekate_core::manifest::verifying_key_from_seed(
                    &hekate_core::manifest::derive_account_signing_seed(&new_mk),
                )
                .as_bytes(),
            ),
        },
        tokens: state::Tokens {
            access_token: resp.access_token,
            expires_at: (chrono::Utc::now() + chrono::Duration::seconds(resp.expires_in as i64))
                .to_rfc3339(),
            refresh_token: resp.refresh_token,
        },
        account_material: state::AccountMaterial {
            protected_account_key: new_pak,
            // The X25519 private key is wrapped under the account_key (not
            // the stretched master key), so it doesn't need re-wrapping.
            protected_account_private_key: st.account_material.protected_account_private_key,
        },
        // Pinned peers survive a password rotation untouched — pinning is
        // about THEIR identity, not ours.
        peer_pins: st.peer_pins,
        org_pins: st.org_pins,
        prefs: st.prefs,
    };
    state::save(&new_state)?;

    println!("✓ Master password changed.");
    println!("  All other sessions are now invalid; re-authenticate on each device.");
    println!("  Local state updated; this CLI is logged in with fresh tokens.");
    Ok(())
}

// ---- rotate keys (M2.26) -------------------------------------------------

fn rotate_keys() -> Result<()> {
    let st = state::load()?.ok_or_else(|| anyhow!("not logged in. Run `hekate login` first."))?;
    let api = Api::new(&st.server_url)?
        .with_bearer(st.tokens.access_token.clone())
        .with_refresh(st.tokens.refresh_token.clone());

    let pw = prompt::password("Master password: ")?;
    let kdf: KdfParams = serde_json::from_value(st.user.kdf_params.clone())?;
    let salt = STANDARD_NO_PAD.decode(&st.user.kdf_salt_b64)?;
    println!("Deriving master key (Argon2id)...");
    let mk = derive_master_key(pw.as_bytes(), kdf, &salt)?;
    let smk = derive_stretched_master_key(&mk);
    let mph = derive_master_password_hash(&mk);

    // Decrypt the existing account_key.
    let pak = EncString::parse(&st.account_material.protected_account_key)?;
    let bytes = pak
        .decrypt_xc20p(&smk, Some(AAD_PROTECTED_ACCOUNT_KEY))
        .map_err(|_| anyhow!("wrong master password"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("decrypted account key has wrong length"));
    }
    let mut old_account_key = [0u8; 32];
    old_account_key.copy_from_slice(&bytes);

    // Pull /sync to enumerate everything that needs re-wrapping.
    let sync = api.sync(None)?;

    // Re-wraps for personal ciphers. Org-owned ciphers wrap PCK under
    // the org sym key, so they're untouched here — the org sym key
    // *is* re-wrapped below as part of `org_member_rewraps`, which
    // covers all org-owned content via one symmetric-key swap.
    let mut cipher_rewraps: Vec<crate::api::AccountCipherRewrap> = Vec::new();
    let mut new_account_key = [0u8; 32];
    OsRng.fill_bytes(&mut new_account_key);

    for c in &sync.changes.ciphers {
        if c.org_id.is_some() {
            continue;
        }
        let aad = crate::crypto::aad_protected_cipher_key(&c.id);
        let parsed = EncString::parse(&c.protected_cipher_key)
            .with_context(|| format!("parse cipher {} PCK", c.id))?;
        let pck_bytes = parsed
            .decrypt_xc20p(&old_account_key, Some(&aad))
            .map_err(|_| {
                anyhow!(
                    "could not decrypt PCK for cipher {} — server may have substituted the wrap",
                    c.id
                )
            })?;
        let new_wire = EncString::encrypt_xc20p("ak:1", &new_account_key, &pck_bytes, &aad)
            .map_err(|e| anyhow!("re-wrap cipher {}: {e}", c.id))?
            .to_wire();
        cipher_rewraps.push(crate::api::AccountCipherRewrap {
            cipher_id: c.id.clone(),
            new_protected_cipher_key: new_wire,
        });
    }

    // Re-wraps for Sends. Two fields per send wrap under the
    // account_key: `protected_send_key` and `name`. If either fails
    // (orphaned send from a prior broken rotation, AAD-format drift,
    // ...), skip that send and continue — refusing to rotate because
    // of one corrupt row would strand the user.
    let mut send_rewraps: Vec<crate::api::AccountSendRewrap> = Vec::new();
    let mut skipped_sends: Vec<String> = Vec::new();
    for s in &sync.changes.sends {
        let result: Result<crate::api::AccountSendRewrap> = (|| {
            let key_aad = hekate_core::send::key_wrap_aad(&s.id);
            let parsed_key = EncString::parse(&s.protected_send_key)
                .with_context(|| format!("parse send {} key wrap", s.id))?;
            let send_key_bytes = parsed_key
                .decrypt_xc20p(&old_account_key, Some(&key_aad))
                .map_err(|_| anyhow!("decrypt send_key"))?;
            let new_key_wire =
                EncString::encrypt_xc20p("ak:1", &new_account_key, &send_key_bytes, &key_aad)?
                    .to_wire();

            let name_aad = hekate_core::send::name_aad(&s.id);
            let parsed_name = EncString::parse(&s.name)
                .with_context(|| format!("parse send {} name wrap", s.id))?;
            let name_bytes = parsed_name
                .decrypt_xc20p(&old_account_key, Some(&name_aad))
                .map_err(|_| anyhow!("decrypt name"))?;
            let new_name_wire =
                EncString::encrypt_xc20p("ak:1", &new_account_key, &name_bytes, &name_aad)?
                    .to_wire();

            Ok(crate::api::AccountSendRewrap {
                send_id: s.id.clone(),
                new_protected_send_key: new_key_wire,
                new_name: new_name_wire,
            })
        })();
        match result {
            Ok(r) => send_rewraps.push(r),
            Err(err) => {
                eprintln!("rotate: skipping orphaned send {} ({err})", s.id);
                skipped_sends.push(s.id.clone());
            }
        }
    }
    if !skipped_sends.is_empty() {
        eprintln!(
            "warning: {} send(s) could not be re-wrapped — delete them and retry.",
            skipped_sends.len()
        );
    }

    // Re-wraps for org memberships. We need each membership's
    // `my_protected_org_key`, which lives on `GET /api/v1/orgs/{id}`
    // — /sync's OrgSyncEntry doesn't carry it.
    let mut org_member_rewraps: Vec<crate::api::AccountOrgMemberRewrap> = Vec::new();
    for o in &sync.orgs {
        let org = api
            .get_org(&o.org_id)
            .with_context(|| format!("fetch org {}", o.org_id))?;
        let parsed = EncString::parse(&org.my_protected_org_key)
            .with_context(|| format!("parse org {} sym-key wrap", o.org_id))?;
        // AAD matches what fetch_org_and_unwrap uses today
        // (AAD_PROTECTED_ACCOUNT_KEY). Keeping symmetry so the server
        // round-trip works against the existing read path.
        let sym_key_bytes = parsed
            .decrypt_xc20p(&old_account_key, Some(AAD_PROTECTED_ACCOUNT_KEY))
            .map_err(|_| anyhow!("could not decrypt org_sym_key for org {}", o.org_id))?;
        let new_wire = EncString::encrypt_xc20p(
            "ak:1",
            &new_account_key,
            &sym_key_bytes,
            AAD_PROTECTED_ACCOUNT_KEY,
        )
        .map_err(|e| anyhow!("re-wrap org {}: {e}", o.org_id))?
        .to_wire();
        org_member_rewraps.push(crate::api::AccountOrgMemberRewrap {
            org_id: o.org_id.clone(),
            new_protected_org_key: new_wire,
        });
    }

    // Re-wrap the X25519 private key under the new account_key.
    // Same AAD as register-time (`pmgr-account-x25519-priv`); server
    // never decrypts this.
    let parsed = EncString::parse(&st.account_material.protected_account_private_key)
        .context("parse stored protected_account_private_key")?;
    let priv_bytes = parsed
        .decrypt_xc20p(&old_account_key, Some(b"pmgr-account-x25519-priv"))
        .map_err(|_| anyhow!("could not decrypt account private key"))?;
    let new_protected_priv = EncString::encrypt_xc20p(
        "ak:1",
        &new_account_key,
        &priv_bytes,
        b"pmgr-account-x25519-priv",
    )
    .map_err(|e| anyhow!("re-wrap private key: {e}"))?
    .to_wire();

    // Wrap the new account_key under the (unchanged) stretched master
    // key. Master password isn't rotating; only the account_key is.
    let new_pak = EncString::encrypt_xc20p(
        "smk:1",
        &smk,
        &new_account_key[..],
        AAD_PROTECTED_ACCOUNT_KEY,
    )
    .map_err(|e| anyhow!("re-wrap account key: {e}"))?
    .to_wire();

    println!(
        "Submitting rotation: {} cipher(s), {} send(s), {} org membership(s)",
        cipher_rewraps.len(),
        send_rewraps.len(),
        org_member_rewraps.len()
    );
    let resp = api.rotate_keys(&crate::api::RotateKeysRequest {
        master_password_hash: STANDARD_NO_PAD.encode(mph),
        new_protected_account_key: new_pak.clone(),
        new_protected_account_private_key: new_protected_priv.clone(),
        cipher_rewraps,
        send_rewraps,
        org_member_rewraps,
    })?;

    // Persist the new account_key wrap + tokens. Master password,
    // KDF salt/params, signing pubkey, and account public key are
    // unchanged in this flow.
    let new_state = state::State {
        server_url: st.server_url,
        user: st.user,
        tokens: state::Tokens {
            access_token: resp.access_token,
            expires_at: (chrono::Utc::now() + chrono::Duration::seconds(resp.expires_in as i64))
                .to_rfc3339(),
            refresh_token: resp.refresh_token,
        },
        account_material: state::AccountMaterial {
            protected_account_key: new_pak,
            protected_account_private_key: new_protected_priv,
        },
        peer_pins: st.peer_pins,
        org_pins: st.org_pins,
        prefs: st.prefs,
    };
    state::save(&new_state)?;

    // Re-sign the BW04 manifest. The server bumped every personal
    // cipher's revision_date when it re-wrapped the PCKs; the
    // previously-signed manifest still has the old timestamps, so
    // future /sync verifications would warn about drift unless we
    // re-sign now. The signing seed is unchanged (HKDF from master
    // key), so this just refreshes the entries + signature.
    let refreshed_unlocked = crate::crypto::Unlocked {
        account_key: {
            let mut k = zeroize::Zeroizing::new([0u8; 32]);
            k.copy_from_slice(&new_account_key);
            k
        },
        signing_seed: hekate_core::manifest::derive_account_signing_seed(&mk),
    };
    if let Err(e) = crate::manifest::sync_and_upload(&api, &refreshed_unlocked) {
        eprintln!("warning: signed manifest re-upload after rotate failed: {e}");
    }

    println!("✓ Rotated account_key.");
    println!(
        "  Re-wrote {} cipher(s), {} send(s), {} org membership(s) on the server.",
        resp.rewrote_ciphers, resp.rewrote_sends, resp.rewrote_org_memberships
    );
    println!("  Other devices need to re-login (their refresh tokens are revoked).");
    println!("  Pinned peers + the BW04 manifest are unaffected (master password unchanged).");
    Ok(())
}

// ---- delete --------------------------------------------------------------

fn delete(args: DeleteArgs) -> Result<()> {
    let st = state::load()?.ok_or_else(|| anyhow!("not logged in. Run `hekate login` first."))?;
    let api = Api::new(&st.server_url)?
        .with_bearer(st.tokens.access_token.clone())
        .with_refresh(st.tokens.refresh_token.clone());

    println!(
        "This will PERMANENTLY delete the account `{}` on `{}`",
        st.user.email, st.server_url
    );
    println!("along with all ciphers, folders, tokens, and webhooks. This cannot be undone.");
    if !args.yes {
        eprint!("Type the email address to confirm: ");
        std::io::Write::flush(&mut std::io::stderr())?;
        let mut typed = String::new();
        std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut typed)?;
        if typed.trim() != st.user.email {
            return Err(anyhow!("aborted (email did not match)"));
        }
    }

    let pw = prompt::password("Master password: ")?;
    let kdf: KdfParams = serde_json::from_value(st.user.kdf_params.clone())?;
    let salt = STANDARD_NO_PAD.decode(&st.user.kdf_salt_b64)?;
    let mk = derive_master_key(pw.as_bytes(), kdf, &salt)?;
    let mph = derive_master_password_hash(&mk);

    api.delete_account(&STANDARD_NO_PAD.encode(mph))?;
    state::delete()?;
    println!("✓ Account deleted; local state cleared.");
    Ok(())
}

// ---- export --------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ExportFile {
    /// Format identifier.
    format: &'static str,
    version: u32,
    /// KDF parameters used to derive the file's encryption key.
    kdf: serde_json::Value,
    salt_b64: String,
    /// EncString v3 envelope of the inner contents.
    encrypted: String,
}

#[derive(Debug, Serialize)]
struct ExportContents {
    exported_at: String,
    server_url: String,
    email: String,
    /// Plaintext account key. Bundle is encrypted under the export
    /// password, so this only "leaks" if the file + password leak
    /// together — but treat the file as you would the master password.
    account_key_b64: String,
    account_public_key_b64: String,
    ciphers: Vec<serde_json::Value>,
    folders: Vec<serde_json::Value>,
}

fn export(args: ExportArgs) -> Result<()> {
    let (st, api, unlocked) = crate::commands::unlock_session()?;
    let resp = api.sync(None)?;
    persist_refreshed_tokens(&api, st.clone())?;

    let pw = prompt::password("Export password (used to encrypt the file): ")?;
    let pw2 = prompt::password("Repeat export password: ")?;
    if pw != pw2 {
        return Err(anyhow!("export passwords did not match"));
    }
    if pw.len() < 8 {
        return Err(anyhow!("export password must be at least 8 characters"));
    }

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let kdf = KdfParams::default_argon2id();
    println!("Deriving export key (Argon2id, ~500 ms)...");
    let mk = derive_master_key(pw.as_bytes(), kdf, &salt)?;
    let smk = derive_stretched_master_key(&mk);

    let contents = ExportContents {
        exported_at: chrono::Utc::now().to_rfc3339(),
        server_url: st.server_url.clone(),
        email: st.user.email.clone(),
        account_key_b64: STANDARD_NO_PAD.encode(&unlocked.account_key[..]),
        account_public_key_b64: st.user.account_public_key_b64.clone(),
        ciphers: resp
            .changes
            .ciphers
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<_, _>>()?,
        folders: resp.changes.folders.clone(),
    };
    let inner_json = serde_json::to_vec(&contents)?;

    let encrypted = EncString::encrypt_xc20p("expk:1", &smk, &inner_json, b"pmgr-export-v1")
        .map_err(|e| anyhow!("encrypt export: {e}"))?
        .to_wire();

    let file = ExportFile {
        format: "pmgr-export-v1",
        version: 1,
        kdf: serde_json::to_value(kdf)?,
        salt_b64: STANDARD_NO_PAD.encode(salt),
        encrypted,
    };
    let bytes = serde_json::to_vec_pretty(&file)?;
    std::fs::write(&args.file, &bytes)
        .with_context(|| format!("writing {}", args.file.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&args.file, std::fs::Permissions::from_mode(0o600));
    }

    println!(
        "✓ Wrote {} ({} ciphers, {} folders)",
        args.file.display(),
        resp.changes.ciphers.len(),
        resp.changes.folders.len()
    );
    Ok(())
}
