//! `hekate register --server URL --email EMAIL`
//!
//! Generates the user's account key and X25519 keypair entirely client-side.
//! The master password never leaves the device. After register succeeds, we
//! immediately log in to capture access + refresh tokens.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use clap::Parser;
use hekate_core::{
    encstring::EncString,
    kdf::{
        compute_kdf_bind_mac, derive_kdf_bind_key, derive_master_key, derive_master_password_hash,
        derive_stretched_master_key, KdfParams,
    },
    keypair::{generate_x25519, random_key_32},
    manifest::{derive_account_signing_seed, signing_key_from_seed, verifying_key_from_seed},
    signcrypt::sign_pubkey_bundle,
};
use rand::{rngs::OsRng, RngCore};
use uuid::Uuid;

use crate::{
    api::{Api, RegisterRequest},
    crypto::AAD_PROTECTED_ACCOUNT_KEY,
    prompt,
    state::{self, AccountMaterial, State, Tokens, User},
};

#[derive(Debug, Parser)]
pub struct Args {
    /// Server base URL (e.g. http://hekate.localhost or https://vault.example.com).
    #[arg(long, env = "HEKATE_SERVER")]
    pub server: String,
    /// Email address to register.
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
    println!("Setting up account for {email} on {}.", args.server);
    println!("Choose a strong master password — you cannot recover the vault if you forget it.");
    let pw = prompt::password("Master password: ")?;
    let pw2 = prompt::password("Repeat master password: ")?;
    if pw != pw2 {
        return Err(anyhow!("passwords did not match"));
    }
    if pw.len() < 8 {
        return Err(anyhow!("master password must be at least 8 characters"));
    }

    // 1. KDF parameters + salt
    let kdf_params = KdfParams::default_argon2id();
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    println!("Deriving master key (Argon2id m=128 MiB, t=3, p=4)...");
    let mk = derive_master_key(pw.as_bytes(), kdf_params, &salt)
        .context("Argon2id derivation failed")?;
    let mph = derive_master_password_hash(&mk);
    let smk = derive_stretched_master_key(&mk);

    // BW07/LP04 mitigation: bind (kdf_params, kdf_salt) to the master key.
    // The server stores this MAC and returns it on every prelogin so the
    // client can detect KDF parameter tampering before deriving a new mph.
    let bind_key = derive_kdf_bind_key(&mk);
    let kdf_params_mac = compute_kdf_bind_mac(&bind_key, kdf_params, &salt);
    let kdf_params_mac_b64 = STANDARD_NO_PAD.encode(kdf_params_mac);

    // 2. Account key (the key that wraps cipher keys), random 32 bytes.
    let account_key = random_key_32();

    // 3. X25519 keypair for the account.
    let (account_priv, account_pub) = generate_x25519();

    // 4. EncString-encrypt the account key under the stretched master key.
    //    `&smk` deref-coerces to &[u8;32]; `&account_key[..]` is &[u8].
    let protected_account_key =
        EncString::encrypt_xc20p("smk:1", &smk, &account_key[..], AAD_PROTECTED_ACCOUNT_KEY)
            .map_err(|e| anyhow!("encrypt account key: {e}"))?
            .to_wire();

    // 5. EncString-encrypt the X25519 private key under the account key.
    let protected_account_private_key = EncString::encrypt_xc20p(
        "ak:1",
        &account_key,
        &account_priv[..],
        b"pmgr-account-x25519-priv",
    )
    .map_err(|e| anyhow!("encrypt account private key: {e}"))?
    .to_wire();

    // BW04 set-level integrity: derive the Ed25519 signing seed and
    // its public key. Server records the pubkey at register time and
    // verifies signed manifests under it on every upload.
    let signing_seed = derive_account_signing_seed(&mk);
    let signing_pubkey = verifying_key_from_seed(&signing_seed);
    let signing_pubkey_bytes = signing_pubkey.to_bytes();
    let signing_pubkey_b64 = STANDARD_NO_PAD.encode(signing_pubkey_bytes);

    // M2.19 self-signed pubkey bundle: client picks user_id BEFORE the
    // registration round-trip so it can be bound into the bundle sig.
    // Server validates the sig and stores it; consumers fetch via
    // GET /api/v1/users/{id}/pubkeys and verify before trusting either
    // pubkey for sharing or signcryption.
    let user_id = Uuid::now_v7().to_string();
    let signing_key = signing_key_from_seed(&signing_seed);
    let bundle_sig =
        sign_pubkey_bundle(&signing_key, &user_id, &signing_pubkey_bytes, &account_pub);
    let bundle_sig_b64 = STANDARD_NO_PAD.encode(bundle_sig);

    let kdf_salt_b64 = STANDARD_NO_PAD.encode(salt);
    let mph_b64 = STANDARD_NO_PAD.encode(mph);
    let pub_b64 = STANDARD_NO_PAD.encode(account_pub);
    let kdf_params_json = serde_json::to_value(kdf_params)?;

    // 6. POST /accounts/register
    let api = Api::new(&args.server)?;
    let _ = api
        .register(&RegisterRequest {
            email: email.clone(),
            kdf_params: kdf_params_json.clone(),
            kdf_salt: kdf_salt_b64.clone(),
            kdf_params_mac: kdf_params_mac_b64.clone(),
            master_password_hash: mph_b64.clone(),
            protected_account_key: protected_account_key.clone(),
            account_public_key: pub_b64.clone(),
            protected_account_private_key: protected_account_private_key.clone(),
            account_signing_pubkey: signing_pubkey_b64.clone(),
            user_id: Some(user_id.clone()),
            account_pubkey_bundle_sig: bundle_sig_b64.clone(),
        })
        .context("register failed")?;

    // 7. Immediately log in to capture access + refresh tokens. A
    // freshly-registered account can't have 2FA enabled yet, so we
    // never expect a TwoFactorRequired outcome here.
    let token = match api
        .token_password(&email, &mph_b64)
        .context("login after register failed")?
    {
        crate::api::PasswordGrantOutcome::Tokens(t) => t,
        crate::api::PasswordGrantOutcome::TwoFactorRequired(_) => {
            return Err(anyhow!(
                "server unexpectedly required 2FA on a freshly-registered account"
            ));
        }
    };

    // 8. Persist state (no plaintext keys on disk).
    let expires_at =
        (chrono::Utc::now() + chrono::Duration::seconds(token.expires_in as i64)).to_rfc3339();

    let st = State {
        server_url: args.server,
        user: User {
            user_id: user_id.clone(),
            email,
            kdf_params: kdf_params_json,
            kdf_salt_b64,
            kdf_params_mac_b64,
            account_public_key_b64: pub_b64,
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

    println!("✓ Registered and logged in as {}.", st.user.email);
    println!("  State saved to {}", state::state_path()?.display());
    Ok(())
}
