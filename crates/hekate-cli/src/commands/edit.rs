//! `hekate edit <kind> <id> [...overrides]` — modify an existing cipher.
//!
//! Strategy: fetch the current cipher, decrypt every field with its
//! per-cipher key, apply the requested overrides, re-encrypt with the
//! SAME cipher key (key rotation is a separate operation), and PUT with
//! `If-Match: "<current_revision>"`. On 409 conflict, surface the server
//! version in the error so the user can decide.
//!
//! All six cipher types are supported. Per-type data structs and JSON
//! key names match `hekate-cli/src/commands/add.rs` exactly so a cipher
//! created in one client (CLI / popup) can be edited in another.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use crate::{
    api::{Api, CipherInput, CipherView, PutOutcome},
    commands::{persist_refreshed_tokens, unlock_session},
    crypto::{
        aad_cipher_data, aad_cipher_name, aad_cipher_notes, decrypt_field_string, encrypt_field,
        unwrap_cipher_key, Unlocked,
    },
};

#[derive(Debug, Parser)]
pub struct Args {
    #[command(subcommand)]
    pub kind: Kind,
}

#[derive(Debug, Subcommand)]
pub enum Kind {
    /// Edit a login cipher.
    Login(LoginArgs),
    /// Edit a secure-note cipher.
    Note(NoteArgs),
    /// Edit a payment-card cipher.
    Card(Box<CardArgs>),
    /// Edit an identity cipher.
    Identity(Box<IdentityArgs>),
    /// Edit an SSH-key cipher.
    SshKey(SshKeyArgs),
    /// Edit a TOTP-only cipher.
    Totp(TotpArgs),
}

// --- arg structs ----------------------------------------------------------

/// Common fields available on every type. Mirrored as a flat top-level
/// in each `*Args` so clap's help is readable; the merge is done in
/// `apply_common`.
#[derive(Debug, Parser, Default)]
pub struct CommonArgs {
    /// Display name (rename).
    #[arg(long)]
    pub name: Option<String>,
    /// Replace the encrypted notes field. Mutually exclusive with `--clear-notes`.
    #[arg(long)]
    pub notes: Option<String>,
    /// Drop the notes field entirely.
    #[arg(long, conflicts_with = "notes")]
    pub clear_notes: bool,
    /// Set or unset favorite (e.g. `--favorite true`).
    #[arg(long)]
    pub favorite: Option<bool>,
}

#[derive(Debug, Parser)]
pub struct LoginArgs {
    pub id: String,
    #[command(flatten)]
    pub common: CommonArgs,
    #[arg(long)]
    pub username: Option<String>,
    /// Password value. For scripts only — visible in shell history.
    #[arg(long)]
    pub password: Option<String>,
    #[arg(long)]
    pub uri: Option<String>,
}

#[derive(Debug, Parser)]
pub struct NoteArgs {
    pub id: String,
    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Debug, Parser)]
pub struct CardArgs {
    pub id: String,
    #[command(flatten)]
    pub common: CommonArgs,
    #[arg(long)]
    pub cardholder: Option<String>,
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
}

#[derive(Debug, Parser)]
pub struct IdentityArgs {
    pub id: String,
    #[command(flatten)]
    pub common: CommonArgs,
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
}

#[derive(Debug, Parser)]
pub struct SshKeyArgs {
    pub id: String,
    #[command(flatten)]
    pub common: CommonArgs,
    #[arg(long)]
    pub public_key: Option<String>,
    #[arg(long)]
    pub private_key: Option<String>,
    #[arg(long)]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Parser)]
pub struct TotpArgs {
    pub id: String,
    #[command(flatten)]
    pub common: CommonArgs,
    /// Either an `otpauth://totp/...?secret=BASE32` URL or a bare base32
    /// secret. Validated immediately.
    #[arg(long)]
    pub secret: Option<String>,
    #[arg(long)]
    pub issuer: Option<String>,
    #[arg(long)]
    pub account: Option<String>,
}

// --- per-type data structs (Deserialize + Serialize for read/modify/write) -

#[derive(Debug, Serialize, Deserialize, Default)]
struct LoginData {
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
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

#[derive(Debug, Serialize, Deserialize, Default)]
struct SshKeyData {
    #[serde(rename = "publicKey", skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    #[serde(rename = "privateKey", skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
    #[serde(rename = "keyFingerprint", skip_serializing_if = "Option::is_none")]
    key_fingerprint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct TotpData {
    #[serde(default)]
    secret: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(rename = "accountName", skip_serializing_if = "Option::is_none")]
    account_name: Option<String>,
}

// --- entry ----------------------------------------------------------------

pub fn run(args: Args) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;
    let edited_org_id = match args.kind {
        Kind::Login(la) => edit_login(&api, &unlocked, la)?,
        Kind::Note(na) => edit_note(&api, &unlocked, na)?,
        Kind::Card(ca) => edit_card(&api, &unlocked, *ca)?,
        Kind::Identity(ia) => edit_identity(&api, &unlocked, *ia)?,
        Kind::SshKey(sa) => edit_ssh_key(&api, &unlocked, sa)?,
        Kind::Totp(ta) => edit_totp(&api, &unlocked, ta)?,
    };
    match edited_org_id {
        None => {
            // Personal cipher edit: refresh the BW04 per-user manifest.
            if let Err(e) = crate::manifest::sync_and_upload(&api, &unlocked) {
                eprintln!("warning: signed manifest upload failed: {e}");
            }
        }
        Some(oid) => {
            // M2.21 / M4.5 follow-up: org-cipher edit refreshes the
            // per-org signed cipher manifest if the caller is the
            // owner; non-owners leave it stale.
            if let Err(e) = crate::org_cipher_manifest::maybe_refresh_owner(&api, &unlocked, &oid) {
                eprintln!("warning: org cipher manifest refresh failed: {e}");
            }
        }
    }
    persist_refreshed_tokens(&api, state)?;
    Ok(())
}

// --- per-type editors -----------------------------------------------------

fn edit_login(api: &Api, unlocked: &Unlocked, args: LoginArgs) -> Result<Option<String>> {
    let LoginArgs {
        id,
        common,
        username,
        password,
        uri,
    } = args;
    let edit = load_for_edit(api, unlocked, &id, 1)?;
    let mut data: LoginData = serde_json::from_str(&edit.cur_data_json).unwrap_or_default();
    if let Some(u) = username {
        data.username = Some(u);
    }
    if let Some(p) = password {
        data.password = Some(p);
    }
    if let Some(u) = uri {
        data.uri = Some(u);
    }
    write_back(api, &edit, common, serde_json::to_string(&data)?)
}

fn edit_note(api: &Api, unlocked: &Unlocked, args: NoteArgs) -> Result<Option<String>> {
    let edit = load_for_edit(api, unlocked, &args.id, 2)?;
    // Secure notes carry no per-type data; everything is in name + notes.
    write_back(api, &edit, args.common, "{}".into())
}

fn edit_card(api: &Api, unlocked: &Unlocked, args: CardArgs) -> Result<Option<String>> {
    let edit = load_for_edit(api, unlocked, &args.id, 3)?;
    let mut data: CardData = serde_json::from_str(&edit.cur_data_json).unwrap_or_default();
    if let Some(v) = args.cardholder {
        data.cardholder_name = Some(v);
    }
    if let Some(v) = args.brand {
        data.brand = Some(v);
    }
    if let Some(v) = args.number {
        data.number = Some(v);
    }
    if let Some(v) = args.exp_month {
        data.exp_month = Some(v.to_string());
    }
    if let Some(v) = args.exp_year {
        data.exp_year = Some(v.to_string());
    }
    if let Some(v) = args.cvv {
        data.code = Some(v);
    }
    write_back(api, &edit, args.common, serde_json::to_string(&data)?)
}

fn edit_identity(api: &Api, unlocked: &Unlocked, args: IdentityArgs) -> Result<Option<String>> {
    let edit = load_for_edit(api, unlocked, &args.id, 4)?;
    let mut d: IdentityData = serde_json::from_str(&edit.cur_data_json).unwrap_or_default();
    if let Some(v) = args.title {
        d.title = Some(v);
    }
    if let Some(v) = args.first {
        d.first_name = Some(v);
    }
    if let Some(v) = args.middle {
        d.middle_name = Some(v);
    }
    if let Some(v) = args.last {
        d.last_name = Some(v);
    }
    if let Some(v) = args.company {
        d.company = Some(v);
    }
    if let Some(v) = args.email {
        d.email = Some(v);
    }
    if let Some(v) = args.phone {
        d.phone = Some(v);
    }
    if let Some(v) = args.address1 {
        d.address1 = Some(v);
    }
    if let Some(v) = args.address2 {
        d.address2 = Some(v);
    }
    if let Some(v) = args.city {
        d.city = Some(v);
    }
    if let Some(v) = args.state {
        d.state = Some(v);
    }
    if let Some(v) = args.postal {
        d.postal_code = Some(v);
    }
    if let Some(v) = args.country {
        d.country = Some(v);
    }
    if let Some(v) = args.ssn {
        d.ssn = Some(v);
    }
    if let Some(v) = args.passport {
        d.passport_number = Some(v);
    }
    if let Some(v) = args.license {
        d.license_number = Some(v);
    }
    write_back(api, &edit, args.common, serde_json::to_string(&d)?)
}

fn edit_ssh_key(api: &Api, unlocked: &Unlocked, args: SshKeyArgs) -> Result<Option<String>> {
    let edit = load_for_edit(api, unlocked, &args.id, 5)?;
    let mut d: SshKeyData = serde_json::from_str(&edit.cur_data_json).unwrap_or_default();
    if let Some(v) = args.public_key {
        d.public_key = Some(v);
    }
    if let Some(v) = args.private_key {
        d.private_key = Some(v);
    }
    if let Some(v) = args.fingerprint {
        d.key_fingerprint = Some(v);
    }
    write_back(api, &edit, args.common, serde_json::to_string(&d)?)
}

fn edit_totp(api: &Api, unlocked: &Unlocked, args: TotpArgs) -> Result<Option<String>> {
    let edit = load_for_edit(api, unlocked, &args.id, 6)?;
    let mut d: TotpData = serde_json::from_str(&edit.cur_data_json).unwrap_or_default();
    if let Some(v) = args.secret {
        // Validate before persisting so the user gets immediate feedback.
        crate::totp::current_code(&v)?;
        d.secret = v;
    }
    if let Some(v) = args.issuer {
        d.issuer = Some(v);
    }
    if let Some(v) = args.account {
        d.account_name = Some(v);
    }
    write_back(api, &edit, args.common, serde_json::to_string(&d)?)
}

// --- shared load / write helpers ------------------------------------------

/// Everything we need from the server to reconstruct a re-encryption: the
/// current cipher, its decrypted name and notes (so unspecified args
/// preserve them), and its decrypted-but-not-yet-parsed `data` JSON.
struct EditContext {
    current: CipherView,
    cipher_key: zeroize::Zeroizing<[u8; 32]>,
    cur_name: String,
    cur_notes: Option<String>,
    cur_data_json: String,
}

fn load_for_edit(
    api: &Api,
    unlocked: &Unlocked,
    id: &str,
    expected_type: i32,
) -> Result<EditContext> {
    let current = api.get_cipher(id)?;
    if current.cipher_type != expected_type {
        return Err(anyhow!(
            "cipher {} is type {} ({}), not {}",
            id,
            current.cipher_type,
            type_name(current.cipher_type),
            type_name(expected_type),
        ));
    }
    // M4.3: org-owned ciphers wrap the per-cipher key under the org
    // sym key. Fetch + unwrap before decrypting fields.
    let cipher_key = match &current.org_id {
        None => unwrap_cipher_key(unlocked, &current.protected_cipher_key, &current.id)?,
        Some(oid) => {
            let (_org, org_sym_key) =
                crate::commands::org::fetch_org_and_unwrap(api, unlocked, oid)?;
            crate::crypto::unwrap_cipher_key_under(
                &org_sym_key,
                &current.protected_cipher_key,
                &current.id,
            )?
        }
    };
    let aad_n = aad_cipher_name(&current.id, current.cipher_type);
    let aad_o = aad_cipher_notes(&current.id, current.cipher_type);
    let aad_d = aad_cipher_data(&current.id, current.cipher_type);
    let cur_name = decrypt_field_string(&cipher_key, &current.name, &aad_n)?;
    let cur_notes = match &current.notes {
        Some(w) => Some(decrypt_field_string(&cipher_key, w, &aad_o)?),
        None => None,
    };
    let cur_data_json =
        decrypt_field_string(&cipher_key, &current.data, &aad_d).unwrap_or_default();
    Ok(EditContext {
        current,
        cipher_key,
        cur_name,
        cur_notes,
        cur_data_json,
    })
}

fn write_back(
    api: &Api,
    edit: &EditContext,
    common: CommonArgs,
    new_data_json: String,
) -> Result<Option<String>> {
    let new_name = common.name.unwrap_or_else(|| edit.cur_name.clone());
    let new_notes = if common.clear_notes {
        None
    } else if let Some(n) = common.notes {
        Some(n)
    } else {
        edit.cur_notes.clone()
    };
    let favorite = common.favorite.unwrap_or(edit.current.favorite);

    let aad_n = aad_cipher_name(&edit.current.id, edit.current.cipher_type);
    let aad_o = aad_cipher_notes(&edit.current.id, edit.current.cipher_type);
    let aad_d = aad_cipher_data(&edit.current.id, edit.current.cipher_type);

    let name_enc = encrypt_field(&edit.cipher_key, new_name.as_bytes(), &aad_n)?;
    let data_enc = encrypt_field(&edit.cipher_key, new_data_json.as_bytes(), &aad_d)?;
    let notes_enc = match &new_notes {
        Some(n) => Some(encrypt_field(&edit.cipher_key, n.as_bytes(), &aad_o)?),
        None => None,
    };

    let body = CipherInput {
        id: edit.current.id.clone(),
        cipher_type: edit.current.cipher_type,
        folder_id: edit.current.folder_id.clone(),
        protected_cipher_key: edit.current.protected_cipher_key.clone(),
        name: name_enc,
        notes: notes_enc,
        data: data_enc,
        favorite,
        // Edit is a no-op for ownership; the server enforces that the
        // caller can't switch a cipher between personal and org. M4.5
        // adds the explicit move-to-org / move-to-personal flow.
        org_id: edit.current.org_id.clone(),
        collection_ids: edit.current.collection_ids.clone(),
    };

    match api.put_cipher(&edit.current.id, &body, &edit.current.revision_date)? {
        PutOutcome::Ok(view) => {
            println!(
                "✓ Updated {} ({}) — revision {}",
                new_name, view.id, view.revision_date
            );
            Ok(view.org_id)
        }
        PutOutcome::Conflict(server_current) => Err(format_conflict(&server_current)),
    }
}

fn format_conflict(server: &CipherView) -> anyhow::Error {
    anyhow!(
        "revision conflict — another writer changed this cipher.\n\
         Server's current revision: {}\n\
         Re-run after `hekate show {}` to inspect, then retry your edit.",
        server.revision_date,
        server.id
    )
}

fn type_name(t: i32) -> &'static str {
    match t {
        1 => "login",
        2 => "secure_note",
        3 => "card",
        4 => "identity",
        5 => "ssh_key",
        6 => "totp",
        _ => "unknown",
    }
}
