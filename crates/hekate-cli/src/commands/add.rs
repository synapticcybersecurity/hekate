//! `hekate add <kind> ...` — create a cipher of the given type. Kinds
//! supported: `login`, `note`, `card`, `identity`, `ssh-key`, `totp`.

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    api::CipherInput,
    commands::{persist_refreshed_tokens, unlock_session},
    crypto::{
        aad_cipher_data, aad_cipher_name, aad_cipher_notes, encrypt_field, new_cipher_key,
        new_cipher_key_under,
    },
};

#[derive(Debug, Parser)]
pub struct Args {
    #[command(subcommand)]
    pub kind: Kind,

    /// (M4.3) Add this cipher into an org instead of the personal
    /// vault. The cipher's per-cipher key is wrapped under the org
    /// symmetric key. Caller must be a member.
    #[arg(long, global = true)]
    pub org: Option<String>,

    /// (M4.3) Pin the cipher to one or more collections in the org.
    /// Repeat the flag to attach to multiple. Requires `--org`.
    #[arg(long = "collection", global = true)]
    pub collections: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub enum Kind {
    /// Login (username / password / URI).
    Login(LoginArgs),
    /// Secure note (text content only).
    Note(NoteArgs),
    /// Payment card (number, expiry, CVV).
    Card(CardArgs),
    /// Identity (name, address, contact details, government IDs).
    Identity(Box<IdentityArgs>),
    /// SSH keypair (public + protected private; optional fingerprint).
    SshKey(SshKeyArgs),
    /// TOTP-only entry. Stores the otpauth:// URL or a base32 secret;
    /// `hekate show` prints the current 6-digit code.
    Totp(TotpArgs),
}

#[derive(Debug, Parser)]
pub struct LoginArgs {
    /// Display name (e.g. "GitHub").
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub username: Option<String>,
    /// Password value. For scripts only — visible in shell history.
    #[arg(long)]
    pub password: Option<String>,
    #[arg(long)]
    pub uri: Option<String>,
    /// Optional plaintext notes (encrypted client-side).
    #[arg(long)]
    pub notes: Option<String>,
    #[arg(long)]
    pub favorite: bool,
}

#[derive(Debug, Parser)]
pub struct NoteArgs {
    #[arg(long)]
    pub name: String,
    /// Note body. Encrypted client-side.
    #[arg(long)]
    pub notes: String,
    #[arg(long)]
    pub favorite: bool,
}

#[derive(Debug, Parser)]
pub struct CardArgs {
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub cardholder: Option<String>,
    /// Brand (Visa, Mastercard, Amex, …).
    #[arg(long)]
    pub brand: Option<String>,
    #[arg(long)]
    pub number: Option<String>,
    /// Expiry month, 1-12.
    #[arg(long)]
    pub exp_month: Option<u8>,
    /// Expiry year, four-digit.
    #[arg(long)]
    pub exp_year: Option<u16>,
    /// CVV / security code.
    #[arg(long)]
    pub cvv: Option<String>,
    #[arg(long)]
    pub notes: Option<String>,
    #[arg(long)]
    pub favorite: bool,
}

#[derive(Debug, Parser)]
pub struct IdentityArgs {
    /// Display name for the entry (e.g. "Personal" or "Work Travel").
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub title: Option<String>,
    #[arg(long)]
    pub first: Option<String>,
    #[arg(long)]
    pub middle: Option<String>,
    #[arg(long)]
    pub last: Option<String>,
    #[arg(long)]
    pub company: Option<String>,
    #[arg(long)]
    pub email: Option<String>,
    #[arg(long)]
    pub phone: Option<String>,
    #[arg(long)]
    pub address1: Option<String>,
    #[arg(long)]
    pub address2: Option<String>,
    #[arg(long)]
    pub city: Option<String>,
    #[arg(long)]
    pub state: Option<String>,
    #[arg(long)]
    pub postal: Option<String>,
    #[arg(long)]
    pub country: Option<String>,
    #[arg(long)]
    pub ssn: Option<String>,
    #[arg(long)]
    pub passport: Option<String>,
    #[arg(long)]
    pub license: Option<String>,
    #[arg(long)]
    pub notes: Option<String>,
    #[arg(long)]
    pub favorite: bool,
}

#[derive(Debug, Parser)]
pub struct SshKeyArgs {
    #[arg(long)]
    pub name: String,
    /// Public key (e.g. `ssh-ed25519 AAAA…`).
    #[arg(long)]
    pub public_key: Option<String>,
    /// Private key in OpenSSH or PEM format. Stored client-side encrypted.
    #[arg(long)]
    pub private_key: Option<String>,
    /// Optional fingerprint (e.g. `SHA256:abcdef…`). Computation is
    /// deferred to a future iteration; supply explicitly if you have it.
    #[arg(long)]
    pub fingerprint: Option<String>,
    #[arg(long)]
    pub notes: Option<String>,
    #[arg(long)]
    pub favorite: bool,
}

#[derive(Debug, Parser)]
pub struct TotpArgs {
    #[arg(long)]
    pub name: String,
    /// Either an `otpauth://totp/...?secret=BASE32` URL or a bare base32
    /// secret (defaults to SHA-1 / 6 digits / 30 s if bare).
    #[arg(long)]
    pub secret: String,
    #[arg(long)]
    pub issuer: Option<String>,
    #[arg(long)]
    pub account: Option<String>,
    #[arg(long)]
    pub notes: Option<String>,
    #[arg(long)]
    pub favorite: bool,
}

#[derive(Debug, Serialize)]
struct LoginData {
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
}

#[derive(Debug, Default, Serialize)]
struct IdentityData {
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(rename = "firstName", skip_serializing_if = "Option::is_none")]
    first_name: Option<String>,
    #[serde(rename = "middleName", skip_serializing_if = "Option::is_none")]
    middle_name: Option<String>,
    #[serde(rename = "lastName", skip_serializing_if = "Option::is_none")]
    last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    company: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(rename = "postalCode", skip_serializing_if = "Option::is_none")]
    postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssn: Option<String>,
    #[serde(rename = "passportNumber", skip_serializing_if = "Option::is_none")]
    passport_number: Option<String>,
    #[serde(rename = "licenseNumber", skip_serializing_if = "Option::is_none")]
    license_number: Option<String>,
}

#[derive(Debug, Default, Serialize)]
struct SshKeyData {
    #[serde(rename = "publicKey", skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    #[serde(rename = "privateKey", skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
    #[serde(rename = "keyFingerprint", skip_serializing_if = "Option::is_none")]
    key_fingerprint: Option<String>,
}

#[derive(Debug, Serialize)]
struct TotpData {
    /// otpauth URL or a bare base32 secret.
    secret: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(rename = "accountName", skip_serializing_if = "Option::is_none")]
    account_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct CardData {
    #[serde(rename = "cardholderName", skip_serializing_if = "Option::is_none")]
    cardholder_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    brand: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    number: Option<String>,
    #[serde(rename = "expMonth", skip_serializing_if = "Option::is_none")]
    exp_month: Option<String>,
    #[serde(rename = "expYear", skip_serializing_if = "Option::is_none")]
    exp_year: Option<String>,
    /// Bitwarden-style "code" so the wire schema is simple/stable.
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
}

/// Plaintext form of a new cipher, before encryption. Each kind contributes
/// (cipher_type, name, notes, data_json, favorite); the AAD-bound encryption
/// is then done uniformly so the cipher_id+type can be stitched into the
/// AAD in one place.
struct PlainCipher {
    cipher_type: i32,
    name: String,
    notes: Option<String>,
    data_json: String,
    favorite: bool,
}

pub fn run(args: Args) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;

    if !args.collections.is_empty() && args.org.is_none() {
        return Err(anyhow::anyhow!(
            "--collection requires --org (collections live inside an org)"
        ));
    }
    let org_id = args.org.clone();

    // Generate the cipher id BEFORE encrypting any field — every encrypted
    // slot binds the id into its AAD so the server can't substitute rows.
    let cipher_id = Uuid::now_v7().to_string();

    let plain = match args.kind {
        Kind::Login(la) => {
            let data = LoginData {
                username: la.username,
                password: la.password,
                uri: la.uri,
            };
            PlainCipher {
                cipher_type: 1,
                name: la.name,
                notes: la.notes,
                data_json: serde_json::to_string(&data)?,
                favorite: la.favorite,
            }
        }
        Kind::Note(na) => PlainCipher {
            cipher_type: 2,
            name: na.name,
            // Secure-note data is empty; the note body lives in the notes field.
            notes: Some(na.notes),
            data_json: "{}".into(),
            favorite: na.favorite,
        },
        Kind::Card(ca) => {
            let data = CardData {
                cardholder_name: ca.cardholder,
                brand: ca.brand,
                number: ca.number,
                exp_month: ca.exp_month.map(|m| m.to_string()),
                exp_year: ca.exp_year.map(|y| y.to_string()),
                code: ca.cvv,
            };
            PlainCipher {
                cipher_type: 3,
                name: ca.name,
                notes: ca.notes,
                data_json: serde_json::to_string(&data)?,
                favorite: ca.favorite,
            }
        }
        Kind::Identity(boxed) => {
            let ia = *boxed;
            let data = IdentityData {
                title: ia.title,
                first_name: ia.first,
                middle_name: ia.middle,
                last_name: ia.last,
                company: ia.company,
                email: ia.email,
                phone: ia.phone,
                address1: ia.address1,
                address2: ia.address2,
                city: ia.city,
                state: ia.state,
                postal_code: ia.postal,
                country: ia.country,
                ssn: ia.ssn,
                passport_number: ia.passport,
                license_number: ia.license,
            };
            PlainCipher {
                cipher_type: 4,
                name: ia.name,
                notes: ia.notes,
                data_json: serde_json::to_string(&data)?,
                favorite: ia.favorite,
            }
        }
        Kind::SshKey(sa) => {
            let data = SshKeyData {
                public_key: sa.public_key,
                private_key: sa.private_key,
                key_fingerprint: sa.fingerprint,
            };
            PlainCipher {
                cipher_type: 5,
                name: sa.name,
                notes: sa.notes,
                data_json: serde_json::to_string(&data)?,
                favorite: sa.favorite,
            }
        }
        Kind::Totp(ta) => {
            // Validate the secret/URL parses before storing it, so users
            // get an immediate error rather than at view time.
            crate::totp::current_code(&ta.secret)?;
            let data = TotpData {
                secret: ta.secret,
                issuer: ta.issuer,
                account_name: ta.account,
            };
            PlainCipher {
                cipher_type: 6,
                name: ta.name,
                notes: ta.notes,
                data_json: serde_json::to_string(&data)?,
                favorite: ta.favorite,
            }
        }
    };

    // For org ciphers, wrap the per-cipher key under the org sym key
    // (key_id = "ok:1") rather than the user's account key. The org
    // sym key comes from `GET /api/v1/orgs/{id}` after unwrap under
    // the user's account_key.
    let (cipher_key, protected_cipher_key) = match &org_id {
        None => new_cipher_key(&unlocked, &cipher_id)?,
        Some(oid) => {
            let (_org, org_sym_key) =
                crate::commands::org::fetch_org_and_unwrap(&api, &unlocked, oid)?;
            new_cipher_key_under(&org_sym_key, "ok:1", &cipher_id)?
        }
    };
    let aad_n = aad_cipher_name(&cipher_id, plain.cipher_type);
    let aad_o = aad_cipher_notes(&cipher_id, plain.cipher_type);
    let aad_d = aad_cipher_data(&cipher_id, plain.cipher_type);

    let body = CipherInput {
        id: cipher_id.clone(),
        cipher_type: plain.cipher_type,
        folder_id: None,
        protected_cipher_key,
        name: encrypt_field(&cipher_key, plain.name.as_bytes(), &aad_n)?,
        notes: plain
            .notes
            .as_deref()
            .map(|n| encrypt_field(&cipher_key, n.as_bytes(), &aad_o))
            .transpose()?,
        data: encrypt_field(&cipher_key, plain.data_json.as_bytes(), &aad_d)?,
        favorite: plain.favorite,
        org_id: org_id.clone(),
        collection_ids: args.collections.clone(),
    };

    let view = api.create_cipher(&body)?;
    println!("✓ Created {} ({})", type_name(view.cipher_type), view.id);
    // M4.3: only personal ciphers participate in the BW04 per-user
    // signed manifest.
    if org_id.is_none() {
        if let Err(e) = crate::manifest::sync_and_upload(&api, &unlocked) {
            eprintln!("warning: signed manifest upload failed: {e}");
        }
    } else if let Some(oid) = org_id.as_deref() {
        // M2.21 / M4.5 follow-up: refresh the per-org signed cipher
        // manifest if the caller is the org owner. Non-owner writes
        // leave the manifest stale until the owner runs
        // `hekate org cipher-manifest refresh`.
        if let Err(e) = crate::org_cipher_manifest::maybe_refresh_owner(&api, &unlocked, oid) {
            eprintln!("warning: org cipher manifest refresh failed: {e}");
        }
    }
    persist_refreshed_tokens(&api, state)?;
    Ok(())
}

fn type_name(t: i32) -> &'static str {
    match t {
        1 => "login",
        2 => "secure_note",
        3 => "card",
        4 => "identity",
        5 => "ssh_key",
        6 => "totp",
        _ => "cipher",
    }
}
