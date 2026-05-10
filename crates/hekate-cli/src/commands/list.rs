//! `hekate list` — pull the vault, decrypt every cipher's name, print a
//! table. Trash items (deleted_date set) are skipped unless --all.

use anyhow::Result;
use clap::Parser;
use serde::Deserialize;

use crate::{
    api::CipherView,
    commands::{persist_refreshed_tokens, unlock_session},
    crypto::{aad_cipher_data, aad_cipher_name, decrypt_field_string, unwrap_cipher_key, Unlocked},
};

#[derive(Debug, Parser)]
pub struct Args {
    /// Include trashed items.
    #[arg(long)]
    pub all: bool,
}

#[derive(Debug, Deserialize, Default)]
struct LoginData {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct CardData {
    #[serde(default)]
    brand: Option<String>,
    #[serde(default)]
    number: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct IdentityRowData {
    #[serde(rename = "firstName", default)]
    first_name: Option<String>,
    #[serde(rename = "lastName", default)]
    last_name: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct TotpRowData {
    #[serde(default)]
    issuer: Option<String>,
    #[serde(rename = "accountName", default)]
    account_name: Option<String>,
}

pub fn run(args: Args) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;
    let resp = api.sync(None)?;

    // Pre-fetch org sym keys once per org we'll need to decrypt under.
    // Avoids one round-trip per org-owned cipher.
    let mut org_keys: std::collections::HashMap<String, zeroize::Zeroizing<[u8; 32]>> =
        std::collections::HashMap::new();
    for c in &resp.changes.ciphers {
        if let Some(oid) = &c.org_id {
            if !org_keys.contains_key(oid) {
                let (_org, k) = crate::commands::org::fetch_org_and_unwrap(&api, &unlocked, oid)?;
                org_keys.insert(oid.clone(), k);
            }
        }
    }

    let rows: Vec<Row> = resp
        .changes
        .ciphers
        .iter()
        .filter(|c| args.all || c.deleted_date.is_none())
        .map(|c| decode_row(&unlocked, c, &org_keys))
        .collect::<Result<_>>()?;

    persist_refreshed_tokens(&api, state)?;

    if rows.is_empty() {
        println!("(no items)");
        return Ok(());
    }

    let id_w = rows.iter().map(|r| r.id.len()).max().unwrap_or(36).min(38);
    let type_w = rows.iter().map(|r| r.kind.len()).max().unwrap_or(8);
    let name_w = rows
        .iter()
        .map(|r| r.name.len())
        .max()
        .unwrap_or(20)
        .min(40);
    let detail_w = rows
        .iter()
        .map(|r| r.detail.len())
        .max()
        .unwrap_or(12)
        .min(40);

    println!(
        "{:<id_w$}  {:<type_w$}  {:<name_w$}  {:<detail_w$}  EXTRA",
        "ID",
        "TYPE",
        "NAME",
        "DETAIL",
        id_w = id_w,
        type_w = type_w,
        name_w = name_w,
        detail_w = detail_w,
    );
    for r in rows {
        let suffix = if r.trashed { " [trash]" } else { "" };
        println!(
            "{:<id_w$}  {:<type_w$}  {:<name_w$}  {:<detail_w$}  {}{}",
            r.id,
            r.kind,
            r.name,
            r.detail,
            r.extra,
            suffix,
            id_w = id_w,
            type_w = type_w,
            name_w = name_w,
            detail_w = detail_w,
        );
    }
    Ok(())
}

struct Row {
    id: String,
    kind: String,
    name: String,
    detail: String,
    extra: String,
    trashed: bool,
}

fn decode_row(
    unlocked: &Unlocked,
    c: &CipherView,
    org_keys: &std::collections::HashMap<String, zeroize::Zeroizing<[u8; 32]>>,
) -> Result<Row> {
    let cipher_key = match &c.org_id {
        None => unwrap_cipher_key(unlocked, &c.protected_cipher_key, &c.id)?,
        Some(oid) => {
            let k = org_keys
                .get(oid)
                .ok_or_else(|| anyhow::anyhow!("missing org sym key for {oid}"))?;
            crate::crypto::unwrap_cipher_key_under(k, &c.protected_cipher_key, &c.id)?
        }
    };
    let aad_n = aad_cipher_name(&c.id, c.cipher_type);
    let aad_d = aad_cipher_data(&c.id, c.cipher_type);
    let name = decrypt_field_string(&cipher_key, &c.name, &aad_n)
        .unwrap_or_else(|_| "<undecryptable>".to_string());

    let kind = type_name(c.cipher_type).to_string();

    let (detail, extra) = match c.cipher_type {
        1 => {
            let pt = decrypt_field_string(&cipher_key, &c.data, &aad_d).unwrap_or_default();
            let parsed: LoginData = serde_json::from_str(&pt).unwrap_or_default();
            (
                parsed.username.unwrap_or_default(),
                parsed.uri.unwrap_or_default(),
            )
        }
        3 => {
            let pt = decrypt_field_string(&cipher_key, &c.data, &aad_d).unwrap_or_default();
            let card: CardData = serde_json::from_str(&pt).unwrap_or_default();
            let last4 = card
                .number
                .as_deref()
                .map(|n| n.chars().filter(|c| c.is_ascii_digit()).collect::<String>())
                .filter(|d| d.len() >= 4)
                .map(|d| format!("**** {}", &d[d.len() - 4..]))
                .unwrap_or_default();
            (card.brand.unwrap_or_default(), last4)
        }
        4 => {
            let pt = decrypt_field_string(&cipher_key, &c.data, &aad_d).unwrap_or_default();
            let id: IdentityRowData = serde_json::from_str(&pt).unwrap_or_default();
            let full = [id.first_name, id.last_name]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            (full, id.email.unwrap_or_default())
        }
        6 => {
            let pt = decrypt_field_string(&cipher_key, &c.data, &aad_d).unwrap_or_default();
            let t: TotpRowData = serde_json::from_str(&pt).unwrap_or_default();
            (
                t.issuer.unwrap_or_default(),
                t.account_name.unwrap_or_default(),
            )
        }
        2 | 5 => (String::new(), String::new()),
        _ => (String::new(), String::new()),
    };

    Ok(Row {
        id: c.id.clone(),
        kind,
        name,
        detail,
        extra,
        trashed: c.deleted_date.is_some(),
    })
}

fn type_name(t: i32) -> &'static str {
    match t {
        1 => "login",
        2 => "note",
        3 => "card",
        4 => "identity",
        5 => "ssh",
        6 => "totp",
        _ => "?",
    }
}
