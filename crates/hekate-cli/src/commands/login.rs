//! `hekate login --server URL --email EMAIL`
//!
//! Calls /prelogin to fetch the server's KDF params for this email, derives
//! the master password hash locally, exchanges it for tokens, and persists
//! state.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use clap::Parser;
use hekate_core::kdf::{
    derive_kdf_bind_key, derive_master_key, derive_master_password_hash, verify_kdf_bind_mac,
    KdfParams,
};

use crate::{
    api::{Api, PasswordGrantOutcome},
    prompt,
    state::{self, AccountMaterial, State, Tokens, User},
};

#[derive(Debug, Parser)]
pub struct Args {
    #[arg(long, env = "HEKATE_SERVER")]
    pub server: String,
    #[arg(long)]
    pub email: String,
}

pub fn run(args: Args) -> Result<()> {
    if state::load()?.is_some() {
        return Err(anyhow!(
            "local state already exists at {} — run `hekate logout` first",
            state::state_path()?.display()
        ));
    }

    let email = args.email.trim().to_lowercase();
    let api = Api::new(&args.server)?;

    let prelogin = api.prelogin(&email).context("prelogin request failed")?;
    let kdf_params: KdfParams = serde_json::from_value(prelogin.kdf_params.clone())
        .context("server returned KDF params we don't understand")?;

    // BW07/LP04 mitigation #1: enforce a hard floor on the params before we
    // even compute Argon2id. A server returning weak params (or fake params
    // for an unknown email) gets rejected here.
    if !kdf_params.is_safe() {
        return Err(anyhow!(
            "server returned KDF parameters below the safe floor — refusing \
             to derive a master_password_hash that could be brute-forced. \
             This may indicate a malicious or misconfigured server."
        ));
    }
    let salt = STANDARD_NO_PAD
        .decode(&prelogin.kdf_salt)
        .context("kdf_salt is not base64-no-pad")?;
    let server_mac = STANDARD_NO_PAD
        .decode(&prelogin.kdf_params_mac)
        .context("kdf_params_mac is not base64-no-pad")?;

    let pw = prompt::password(&format!("Master password for {email}: "))?;
    println!("Deriving master key...");
    let mk = derive_master_key(pw.as_bytes(), kdf_params, &salt)?;

    // BW07/LP04 mitigation #2: verify the bind MAC the server stored at
    // registration. If it doesn't match, the server is either tampering
    // with our params/salt or we typed the wrong password (an attacker can't
    // forge a valid MAC without the master key). Bail BEFORE deriving and
    // sending the master_password_hash.
    let bind_key = derive_kdf_bind_key(&mk);
    if !verify_kdf_bind_mac(&bind_key, kdf_params, &salt, &server_mac) {
        return Err(anyhow!(
            "server's KDF parameter MAC did not verify — refusing to send \
             credentials. Either the master password is wrong, the email is \
             unknown to the server, or the server is attempting to downgrade \
             the KDF (BW07/LP04). Re-check the email and password; if both \
             are correct, do NOT trust this server."
        ));
    }

    let mph = derive_master_password_hash(&mk);
    let mph_b64 = STANDARD_NO_PAD.encode(mph);

    // BW04 set-level integrity: derive the Ed25519 signing pubkey now so we
    // can persist it on the local state file (the seed itself stays in
    // memory only). The pubkey is non-secret and identical across devices —
    // any device for this account derives the same one from the master key.
    let signing_pubkey_b64 = STANDARD_NO_PAD.encode(
        hekate_core::manifest::verifying_key_from_seed(
            &hekate_core::manifest::derive_account_signing_seed(&mk),
        )
        .as_bytes(),
    );

    let outcome = api
        .token_password(&email, &mph_b64)
        .context("login failed (wrong password or unknown user)")?;
    let token = match outcome {
        PasswordGrantOutcome::Tokens(t) => t,
        PasswordGrantOutcome::TwoFactorRequired(challenge) => {
            complete_two_factor(&api, &email, &mph_b64, &challenge)?
        }
    };

    // The token response on a fresh login MUST include account material; if
    // not we can't bootstrap state.
    let protected_account_key = token
        .protected_account_key
        .ok_or_else(|| anyhow!("server omitted protected_account_key"))?;
    let account_public_key = token
        .account_public_key
        .ok_or_else(|| anyhow!("server omitted account_public_key"))?;
    let protected_account_private_key = token
        .protected_account_private_key
        .ok_or_else(|| anyhow!("server omitted protected_account_private_key"))?;
    let kdf_salt = token.kdf_salt.unwrap_or(prelogin.kdf_salt);
    let kdf_params_v = token.kdf_params.unwrap_or(prelogin.kdf_params);
    let kdf_params_mac_b64 = token.kdf_params_mac.unwrap_or(prelogin.kdf_params_mac);

    let expires_at =
        (chrono::Utc::now() + chrono::Duration::seconds(token.expires_in as i64)).to_rfc3339();

    let user_id = token.user_id.clone().unwrap_or_default();

    let st = State {
        server_url: args.server,
        user: User {
            user_id,
            email,
            kdf_params: kdf_params_v,
            kdf_salt_b64: kdf_salt,
            kdf_params_mac_b64,
            account_public_key_b64: account_public_key,
            account_signing_pubkey_b64: signing_pubkey_b64,
        },
        tokens: Tokens {
            access_token: token.access_token,
            expires_at,
            refresh_token: token.refresh_token,
        },
        account_material: AccountMaterial {
            protected_account_key,
            protected_account_private_key,
        },
        peer_pins: std::collections::BTreeMap::new(),
        org_pins: std::collections::BTreeMap::new(),
        prefs: state::Prefs::default(),
    };
    state::save(&st)?;

    println!("✓ Logged in as {}.", st.user.email);
    println!("  State saved to {}", state::state_path()?.display());
    Ok(())
}

/// Prompt the user for a TOTP code (6 digits) or recovery code (any
/// case, dashes optional) and replay the password grant. The challenge
/// token is single-use server-side, but it stays valid for 5 minutes —
/// so a typo on the first attempt just bounces back to the prompt.
fn complete_two_factor(
    api: &Api,
    email: &str,
    mph_b64: &str,
    challenge: &crate::api::TwoFactorChallenge,
) -> Result<crate::api::TokenResponse> {
    println!(
        "Two-factor authentication required ({}).",
        challenge.two_factor_providers.join(", ")
    );
    let raw = prompt::line("Enter TOTP code, or `r` followed by a recovery code: ")?;
    let trimmed = raw.trim();
    let (provider, value) = if let Some(rest) = trimmed.strip_prefix(['r', 'R']) {
        ("recovery", rest.trim_start().to_string())
    } else {
        ("totp", trimmed.to_string())
    };
    if value.is_empty() {
        return Err(anyhow!("no second-factor value supplied"));
    }
    let outcome = api
        .token_password_with_2fa(
            email,
            mph_b64,
            &challenge.two_factor_token,
            provider,
            &value,
        )
        .context("2FA verification failed")?;
    match outcome {
        PasswordGrantOutcome::Tokens(t) => Ok(t),
        PasswordGrantOutcome::TwoFactorRequired(_) => {
            // Server should never re-issue another challenge to the
            // second leg — this would be a server bug.
            Err(anyhow!(
                "server unexpectedly returned a second 2FA challenge"
            ))
        }
    }
}
