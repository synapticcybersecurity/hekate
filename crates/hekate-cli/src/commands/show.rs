//! `hekate show <id>` — decrypt and display one cipher. Display is
//! type-specific.

use anyhow::Result;
use clap::Parser;
use serde::Deserialize;

use crate::{
    commands::{persist_refreshed_tokens, unlock_session},
    crypto::{
        aad_cipher_data, aad_cipher_name, aad_cipher_notes, decrypt_field_string, unwrap_cipher_key,
    },
};

#[derive(Debug, Parser)]
pub struct Args {
    /// Cipher id (UUID).
    pub id: String,
    /// Reveal sensitive fields (passwords, card numbers, CVV) instead of
    /// masking them.
    #[arg(long)]
    pub reveal: bool,
}

#[derive(Debug, Deserialize, Default)]
struct LoginData {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    totp: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct CardData {
    #[serde(rename = "cardholderName", default)]
    cardholder_name: Option<String>,
    #[serde(default)]
    brand: Option<String>,
    #[serde(default)]
    number: Option<String>,
    #[serde(rename = "expMonth", default)]
    exp_month: Option<String>,
    #[serde(rename = "expYear", default)]
    exp_year: Option<String>,
    #[serde(default)]
    code: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct IdentityData {
    #[serde(default)]
    title: Option<String>,
    #[serde(rename = "firstName", default)]
    first_name: Option<String>,
    #[serde(rename = "middleName", default)]
    middle_name: Option<String>,
    #[serde(rename = "lastName", default)]
    last_name: Option<String>,
    #[serde(default)]
    company: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    phone: Option<String>,
    #[serde(default)]
    address1: Option<String>,
    #[serde(default)]
    address2: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(rename = "postalCode", default)]
    postal_code: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    ssn: Option<String>,
    #[serde(rename = "passportNumber", default)]
    passport_number: Option<String>,
    #[serde(rename = "licenseNumber", default)]
    license_number: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct SshKeyData {
    #[serde(rename = "publicKey", default)]
    public_key: Option<String>,
    #[serde(rename = "privateKey", default)]
    private_key: Option<String>,
    #[serde(rename = "keyFingerprint", default)]
    key_fingerprint: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct TotpData {
    #[serde(default)]
    secret: String,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(rename = "accountName", default)]
    account_name: Option<String>,
}

pub fn run(args: Args) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;
    let c = api.get_cipher(&args.id)?;
    persist_refreshed_tokens(&api, state)?;
    // M4.4: when the server reports `read_hide_passwords` the user
    // is allowed to see the structure but not the password — refuse
    // `--reveal` and force masking for sensitive fields. The server
    // can't enforce hiding (E2EE), but the client honors it.
    let hide_passwords = c.permission.as_deref() == Some("read_hide_passwords");
    let allow_reveal = args.reveal && !hide_passwords;
    if args.reveal && hide_passwords {
        eprintln!(
            "warning: --reveal ignored — your permission on this cipher is \
             read_hide_passwords"
        );
    }
    // M4.3: org-owned ciphers wrap their per-cipher key under the org
    // sym key, not the account key. Fetch + unwrap the org sym key
    // first, then decrypt under it.
    let cipher_key = match &c.org_id {
        None => unwrap_cipher_key(&unlocked, &c.protected_cipher_key, &c.id)?,
        Some(oid) => {
            let (_org, org_sym_key) =
                crate::commands::org::fetch_org_and_unwrap(&api, &unlocked, oid)?;
            crate::crypto::unwrap_cipher_key_under(&org_sym_key, &c.protected_cipher_key, &c.id)?
        }
    };
    let aad_n = aad_cipher_name(&c.id, c.cipher_type);
    let aad_o = aad_cipher_notes(&c.id, c.cipher_type);
    let aad_d = aad_cipher_data(&c.id, c.cipher_type);

    let name = decrypt_field_string(&cipher_key, &c.name, &aad_n)?;
    println!("{name}");
    println!("  id:       {}", c.id);
    println!("  type:     {}", type_name(c.cipher_type));
    if let Some(folder) = &c.folder_id {
        println!("  folder:   {folder}");
    }
    println!("  revision: {}", c.revision_date);

    match c.cipher_type {
        1 => {
            let pt = decrypt_field_string(&cipher_key, &c.data, &aad_d)?;
            let login: LoginData = serde_json::from_str(&pt).unwrap_or_default();
            if let Some(u) = login.username {
                println!("  username: {u}");
            }
            if let Some(p) = login.password {
                if allow_reveal {
                    println!("  password: {p}");
                } else if hide_passwords {
                    println!("  password: <hidden by collection permission>");
                } else {
                    println!("  password: {} (use --reveal to show)", mask(&p));
                }
            }
            if let Some(uri) = login.uri {
                println!("  uri:      {uri}");
            }
            if let Some(totp) = login.totp {
                if hide_passwords {
                    println!("  totp:     <hidden by collection permission>");
                } else {
                    println!("  totp:     {totp}");
                }
            }
        }
        2 => {
            // Secure note — body is in `notes`. Render below.
        }
        4 => {
            let pt = decrypt_field_string(&cipher_key, &c.data, &aad_d)?;
            let id: IdentityData = serde_json::from_str(&pt).unwrap_or_default();
            if let Some(t) = id.title {
                println!("  title:    {t}");
            }
            let full_name = [id.first_name, id.middle_name, id.last_name]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            if !full_name.is_empty() {
                println!("  name:     {full_name}");
            }
            if let Some(c) = id.company {
                println!("  company:  {c}");
            }
            if let Some(e) = id.email {
                println!("  email:    {e}");
            }
            if let Some(p) = id.phone {
                println!("  phone:    {p}");
            }
            let addr_parts: Vec<String> = [
                id.address1.clone(),
                id.address2.clone(),
                id.city.clone(),
                id.state.clone(),
                id.postal_code.clone(),
                id.country.clone(),
            ]
            .into_iter()
            .flatten()
            .filter(|s| !s.is_empty())
            .collect();
            if !addr_parts.is_empty() {
                println!("  address:  {}", addr_parts.join(", "));
            }
            for (label, value, sensitive) in [
                ("ssn", id.ssn, true),
                ("passport", id.passport_number, true),
                ("license", id.license_number, true),
            ] {
                if let Some(v) = value {
                    if sensitive && !args.reveal {
                        println!("  {label:<8}: {} (use --reveal to show)", mask(&v));
                    } else {
                        println!("  {label:<8}: {v}");
                    }
                }
            }
        }
        5 => {
            let pt = decrypt_field_string(&cipher_key, &c.data, &aad_d)?;
            let k: SshKeyData = serde_json::from_str(&pt).unwrap_or_default();
            if let Some(fp) = k.key_fingerprint {
                println!("  fingerprint: {fp}");
            }
            if let Some(pub_key) = k.public_key {
                println!("  public:      {pub_key}");
            }
            if let Some(priv_key) = k.private_key {
                if hide_passwords {
                    println!("  private:     <hidden by collection permission>");
                } else if allow_reveal {
                    println!("  private:");
                    for line in priv_key.lines() {
                        println!("    {line}");
                    }
                } else {
                    println!(
                        "  private:     <{} bytes; --reveal to show>",
                        priv_key.len()
                    );
                }
            }
        }
        6 => {
            let pt = decrypt_field_string(&cipher_key, &c.data, &aad_d)?;
            let t: TotpData = serde_json::from_str(&pt).unwrap_or_default();
            if let Some(i) = t.issuer {
                println!("  issuer:   {i}");
            }
            if let Some(a) = t.account_name {
                println!("  account:  {a}");
            }
            match crate::totp::current_code(&t.secret) {
                Ok((code, remaining)) => {
                    println!("  code:     {code}  ({remaining}s remaining)");
                }
                Err(e) => {
                    println!("  code:     <error: {e}>");
                }
            }
            if hide_passwords {
                println!("  secret:   <hidden by collection permission>");
            } else if allow_reveal {
                println!("  secret:   {}", t.secret);
            } else {
                println!("  secret:   <stored; --reveal to show>");
            }
        }
        3 => {
            let pt = decrypt_field_string(&cipher_key, &c.data, &aad_d)?;
            let card: CardData = serde_json::from_str(&pt).unwrap_or_default();
            if let Some(ch) = card.cardholder_name {
                println!("  holder:   {ch}");
            }
            if let Some(b) = card.brand {
                println!("  brand:    {b}");
            }
            if let Some(n) = card.number {
                if args.reveal {
                    println!("  number:   {n}");
                } else {
                    println!("  number:   {} (use --reveal to show)", mask_card(&n));
                }
            }
            if let (Some(m), Some(y)) = (card.exp_month, card.exp_year) {
                println!("  expires:  {m}/{y}");
            }
            if let Some(code) = card.code {
                if args.reveal {
                    println!("  cvv:      {code}");
                } else {
                    println!("  cvv:      *** (use --reveal to show)");
                }
            }
        }
        _ => {}
    }

    if let Some(notes_wire) = &c.notes {
        let notes = decrypt_field_string(&cipher_key, notes_wire, &aad_o)?;
        if c.cipher_type == 2 {
            println!();
            println!("{notes}");
        } else {
            println!("  notes:    {notes}");
        }
    }
    if let Some(d) = &c.deleted_date {
        println!("  trashed:  {d}");
    }
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
        _ => "unknown",
    }
}

fn mask(s: &str) -> String {
    "*".repeat(s.len().min(20))
}

fn mask_card(n: &str) -> String {
    // Show only the last 4 digits.
    let digits: String = n.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() <= 4 {
        return "*".repeat(digits.len());
    }
    let last4 = &digits[digits.len() - 4..];
    format!("**** **** **** {last4}")
}
