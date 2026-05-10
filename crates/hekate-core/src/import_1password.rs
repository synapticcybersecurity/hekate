//! M2.27a — 1Password 1PUX import (pure parser).
//!
//! 1PUX is a ZIP file with a fixed inner shape (1Password 8+):
//!
//! ```text
//! export.attributes        — JSON metadata (version, createdAt, ...)
//! export.data              — JSON of accounts → vaults → items
//! files/<id>__<filename>   — attachment bodies (defer; M2.27a-followup)
//! ```
//!
//! Within `export.data`, each item carries a `categoryUuid` that
//! identifies its type. We map a curated set onto hekate's cipher
//! types; everything else is skipped with a per-item warning so
//! users see what didn't make it across.
//!
//! Same output contract as `import_bitwarden::project` — returns
//! `ProjectedImport` (folders, ciphers, warnings) so the CLI's
//! folder-create + cipher-create orchestration is shared across
//! both formats.
//!
//! ## Categories handled in the first cut
//!
//! | 1Password categoryUuid | name           | hekate cipher_type |
//! |------------------------|----------------|-----------------:|
//! | 001                    | Login          | 1 (login)        |
//! | 002                    | Credit Card    | 3 (card)         |
//! | 003                    | Secure Note    | 2 (secure_note)  |
//! | 004                    | Identity       | 4 (identity)     |
//! | 005                    | Password       | 1 (login w/o username) |
//!
//! Skipped with a warning (per-item) in this milestone:
//! 006 Document, 100 Software License, 101 Bank Account,
//! 102 Database, 103 Driver License, 104 Outdoor License,
//! 105 Membership, 106 Passport, 107 Reward Program,
//! 108 Social Security Number, 109 Wireless Router, 110 Server,
//! 111 Email Account, 112 API Credential, 113 Medical Record,
//! 114 SSH Key. SSH Key (114) lands in a follow-up — it needs
//! per-item field walking that maps onto hekate's ssh-key data shape.
//!
//! ## Vaults → folders
//!
//! 1Password's "vault" is the closest analogue to hekate's "folder"
//! today (we don't have a separate vaults concept). Each non-empty
//! vault name becomes a folder; items thread their server-allocated
//! folder id by name lookup. Multiple 1Password accounts in the
//! same export are flattened — vault names are taken at face value
//! and collisions are first-write-wins (rare in real exports).

use std::io::Read;

use serde::Deserialize;

use crate::{Error, Result};

// Re-use the BW import's output types so the CLI can share orchestration.
pub use crate::import_bitwarden::{ImportedCipher, ProjectedImport};

/// Top-level entry: read a 1PUX ZIP from bytes and project it onto
/// hekate's plaintext cipher model. Refuses zip files that don't
/// contain the expected `export.data` member.
pub fn project_from_zip(bytes: &[u8]) -> Result<ProjectedImport> {
    let cursor = std::io::Cursor::new(bytes);
    let mut zip = zip::ZipArchive::new(cursor)
        .map_err(|e| Error::InvalidEncoding(format!("1pux not a valid zip: {e}")))?;

    let mut data_json = String::new();
    {
        let mut entry = zip.by_name("export.data").map_err(|_| {
            Error::InvalidEncoding("1pux missing required member `export.data`".into())
        })?;
        entry
            .read_to_string(&mut data_json)
            .map_err(|e| Error::InvalidEncoding(format!("read export.data: {e}")))?;
    }

    project_from_data_json(&data_json)
}

/// Used directly by tests when we want to skip the zip wrapper.
/// Public for cross-crate test setup; production code goes through
/// `project_from_zip`.
pub fn project_from_data_json(data_json: &str) -> Result<ProjectedImport> {
    let data: ExportData = serde_json::from_str(data_json)
        .map_err(|e| Error::InvalidEncoding(format!("export.data not valid JSON: {e}")))?;

    let mut folders: Vec<String> = Vec::new();
    let mut ciphers: Vec<ImportedCipher> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    for account in &data.accounts {
        for vault in &account.vaults {
            let vault_name = vault
                .attrs
                .name
                .clone()
                .or_else(|| vault.attrs.desc.clone())
                .unwrap_or_default();
            let folder_id = if !vault_name.is_empty() {
                if !folders.contains(&vault_name) {
                    folders.push(vault_name.clone());
                }
                Some(vault_name.clone())
            } else {
                None
            };

            for item in &vault.items {
                if item.trashed.unwrap_or(false) {
                    warnings.push(format!(
                        "skipping trashed item {:?}",
                        item.overview.title.as_deref().unwrap_or("<no title>")
                    ));
                    continue;
                }
                match project_item(item, folder_id.as_deref()) {
                    Ok(Some(c)) => ciphers.push(c),
                    Ok(None) => {} // category skipped silently — unlikely
                    Err(reason) => warnings.push(format!(
                        "skipping {:?}: {reason}",
                        item.overview.title.as_deref().unwrap_or("<no title>")
                    )),
                }
            }
        }
    }

    Ok(ProjectedImport {
        folders,
        ciphers,
        warnings,
    })
}

// =====================================================================
// Wire types
// =====================================================================

#[derive(Debug, Deserialize)]
struct ExportData {
    #[serde(default)]
    accounts: Vec<Account>,
}

#[derive(Debug, Deserialize)]
struct Account {
    #[serde(default)]
    vaults: Vec<Vault>,
}

#[derive(Debug, Deserialize)]
struct Vault {
    attrs: VaultAttrs,
    #[serde(default)]
    items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
struct VaultAttrs {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    desc: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Item {
    #[serde(rename = "categoryUuid")]
    category_uuid: String,
    #[serde(default)]
    trashed: Option<bool>,
    #[serde(default)]
    #[serde(rename = "favIndex")]
    fav_index: Option<i32>,
    #[serde(default)]
    overview: Overview,
    #[serde(default)]
    details: Details,
}

#[derive(Debug, Default, Deserialize)]
struct Overview {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    urls: Vec<UrlEntry>,
}

#[derive(Debug, Deserialize)]
struct UrlEntry {
    #[serde(default)]
    url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Details {
    #[serde(default)]
    #[serde(rename = "loginFields")]
    login_fields: Vec<LoginField>,
    #[serde(default)]
    #[serde(rename = "notesPlain")]
    notes_plain: Option<String>,
    #[serde(default)]
    sections: Vec<Section>,
    /// `password` only on category 005 (Password) — login uses
    /// loginFields[].
    #[serde(default)]
    password: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginField {
    #[serde(default)]
    designation: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Section {
    /// 1Password section header text. Not used in the projection
    /// today (we match by per-field id/title, not section grouping)
    /// but kept on the parsed struct so future debug tooling can
    /// surface it.
    #[serde(default)]
    #[allow(dead_code)]
    title: Option<String>,
    #[serde(default)]
    fields: Vec<SectionField>,
}

#[derive(Debug, Default, Deserialize)]
struct SectionField {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    value: SectionValue,
}

/// 1Password tags the value variant by JSON key. We deserialize all
/// known shapes lazily (each is `Option<String>`) and pick the first
/// non-None when reading.
#[derive(Debug, Default, Deserialize)]
struct SectionValue {
    #[serde(default)]
    string: Option<String>,
    #[serde(default)]
    concealed: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    phone: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    #[serde(rename = "creditCardNumber")]
    credit_card_number: Option<String>,
    #[serde(default)]
    #[serde(rename = "creditCardType")]
    credit_card_type: Option<String>,
    #[serde(default, rename = "monthYear")]
    month_year: Option<String>,
    /// 1Password "date" variant — Unix epoch seconds. Not used by
    /// any current hekate cipher type but parsed to keep the deserializer
    /// permissive against this variant existing in the input.
    #[serde(default)]
    #[allow(dead_code)]
    date: Option<i64>,
    #[serde(default)]
    address: Option<AddressVariant>,
}

impl SectionValue {
    /// Pick the first present string-like variant. Used everywhere
    /// except address (which has its own struct).
    fn pick_string(&self) -> Option<String> {
        self.string
            .clone()
            .or_else(|| self.concealed.clone())
            .or_else(|| self.email.clone())
            .or_else(|| self.phone.clone())
            .or_else(|| self.url.clone())
            .or_else(|| self.totp.clone())
            .or_else(|| self.credit_card_number.clone())
            .or_else(|| self.credit_card_type.clone())
            .or_else(|| self.month_year.as_ref().map(|s| s.to_string()))
    }
}

#[derive(Debug, Deserialize)]
struct AddressVariant {
    #[serde(default)]
    street: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    zip: Option<String>,
    #[serde(default)]
    country: Option<String>,
}

// =====================================================================
// Projection
// =====================================================================

fn project_item(
    item: &Item,
    folder_name: Option<&str>,
) -> std::result::Result<Option<ImportedCipher>, String> {
    let title = item
        .overview
        .title
        .clone()
        .unwrap_or_else(|| "<untitled>".to_string());

    match item.category_uuid.as_str() {
        "001" => Ok(Some(project_login(item, &title, folder_name))),
        "002" => Ok(Some(project_card(item, &title, folder_name))),
        "003" => Ok(Some(project_secure_note(item, &title, folder_name))),
        "004" => Ok(Some(project_identity(item, &title, folder_name))),
        "005" => Ok(Some(project_password_only(item, &title, folder_name))),
        // Everything else is in the deferred set.
        other => Err(format!(
            "unsupported 1Password category {other} (only Login/Card/Note/Identity/Password import in M2.27a)"
        )),
    }
}

fn project_login(item: &Item, title: &str, folder_name: Option<&str>) -> ImportedCipher {
    let username = pick_login_field(item, "username");
    let password = pick_login_field(item, "password");
    let uri = item
        .overview
        .url
        .clone()
        .or_else(|| item.overview.urls.first().and_then(|u| u.url.clone()));
    // TOTPs land in section fields with a `totp` value variant.
    let totp = item
        .details
        .sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .find_map(|f| f.value.totp.clone());

    let mut data = serde_json::Map::new();
    if let Some(v) = username {
        data.insert("username".into(), serde_json::Value::String(v));
    }
    if let Some(v) = password {
        data.insert("password".into(), serde_json::Value::String(v));
    }
    if let Some(v) = uri {
        data.insert("uri".into(), serde_json::Value::String(v));
    }
    if let Some(v) = totp {
        data.insert("totp".into(), serde_json::Value::String(v));
    }
    ImportedCipher {
        cipher_type: 1,
        name: title.into(),
        notes: merged_notes(item),
        data_json: serde_json::Value::Object(data).to_string(),
        favorite: item.fav_index.unwrap_or(0) > 0,
        bitwarden_folder_id: folder_name.map(str::to_string),
    }
}

fn project_password_only(item: &Item, title: &str, folder_name: Option<&str>) -> ImportedCipher {
    let mut data = serde_json::Map::new();
    let password = item
        .details
        .password
        .clone()
        .or_else(|| pick_login_field(item, "password"));
    if let Some(v) = password {
        data.insert("password".into(), serde_json::Value::String(v));
    }
    if let Some(u) = &item.overview.url {
        data.insert("uri".into(), serde_json::Value::String(u.clone()));
    }
    ImportedCipher {
        cipher_type: 1,
        name: title.into(),
        notes: merged_notes(item),
        data_json: serde_json::Value::Object(data).to_string(),
        favorite: item.fav_index.unwrap_or(0) > 0,
        bitwarden_folder_id: folder_name.map(str::to_string),
    }
}

fn project_secure_note(item: &Item, title: &str, folder_name: Option<&str>) -> ImportedCipher {
    ImportedCipher {
        cipher_type: 2,
        name: title.into(),
        notes: merged_notes(item),
        data_json: "{}".into(),
        favorite: item.fav_index.unwrap_or(0) > 0,
        bitwarden_folder_id: folder_name.map(str::to_string),
    }
}

fn project_card(item: &Item, title: &str, folder_name: Option<&str>) -> ImportedCipher {
    // 1Password's card details live in section fields. Match by the
    // section field's `id` (which is stable across exports) when
    // possible, falling back to title-keyword matching.
    let mut data = serde_json::Map::new();
    let cardholder = pick_section_field(item, &["cardholder", "name"]);
    let brand = pick_section_field(item, &["type", "brand"]);
    let number = pick_section_field(item, &["ccnum", "number"]);
    let expiry = pick_section_field(item, &["expiry"]);
    let cvv = pick_section_field(item, &["cvv"]);
    if let Some(v) = cardholder {
        data.insert("cardholderName".into(), serde_json::Value::String(v));
    }
    if let Some(v) = brand {
        data.insert("brand".into(), serde_json::Value::String(v));
    }
    if let Some(v) = number {
        data.insert("number".into(), serde_json::Value::String(v));
    }
    if let Some(exp) = expiry {
        // 1Password exports expiry as YYYYMM in some versions and
        // "MM/YYYY" or "YYYYMM" string in others. Normalize to
        // (expMonth, expYear) on a best-effort basis.
        let (mo, yr) = split_expiry(&exp);
        if let Some(m) = mo {
            data.insert("expMonth".into(), serde_json::Value::String(m));
        }
        if let Some(y) = yr {
            data.insert("expYear".into(), serde_json::Value::String(y));
        }
    }
    if let Some(v) = cvv {
        data.insert("code".into(), serde_json::Value::String(v));
    }
    ImportedCipher {
        cipher_type: 3,
        name: title.into(),
        notes: merged_notes(item),
        data_json: serde_json::Value::Object(data).to_string(),
        favorite: item.fav_index.unwrap_or(0) > 0,
        bitwarden_folder_id: folder_name.map(str::to_string),
    }
}

fn project_identity(item: &Item, title: &str, folder_name: Option<&str>) -> ImportedCipher {
    let mut data = serde_json::Map::new();
    let put =
        |data: &mut serde_json::Map<String, serde_json::Value>, key: &str, v: Option<String>| {
            if let Some(v) = v {
                if !v.is_empty() {
                    data.insert(key.into(), serde_json::Value::String(v));
                }
            }
        };

    put(&mut data, "title", pick_section_field(item, &["honorific"]));
    put(
        &mut data,
        "firstName",
        pick_section_field(item, &["firstname"]),
    );
    put(
        &mut data,
        "middleName",
        pick_section_field(item, &["initial", "middlename"]),
    );
    put(
        &mut data,
        "lastName",
        pick_section_field(item, &["lastname"]),
    );
    put(
        &mut data,
        "company",
        pick_section_field(item, &["company", "businessname"]),
    );
    put(&mut data, "email", pick_section_field(item, &["email"]));
    put(
        &mut data,
        "phone",
        pick_section_field(item, &["defphone", "phone"]),
    );

    // Address may be a structured value variant (street/city/state/...) on
    // some sections, or split across separate fields on others. Try the
    // structured one first, then fall back to per-key lookups.
    let mut found_addr = false;
    for section in &item.details.sections {
        for f in &section.fields {
            if let Some(addr) = &f.value.address {
                put(&mut data, "address1", addr.street.clone());
                put(&mut data, "city", addr.city.clone());
                put(&mut data, "state", addr.state.clone());
                put(&mut data, "postalCode", addr.zip.clone());
                put(&mut data, "country", addr.country.clone());
                found_addr = true;
                break;
            }
        }
        if found_addr {
            break;
        }
    }
    if !found_addr {
        put(
            &mut data,
            "address1",
            pick_section_field(item, &["address1", "street"]),
        );
        put(&mut data, "city", pick_section_field(item, &["city"]));
        put(&mut data, "state", pick_section_field(item, &["state"]));
        put(
            &mut data,
            "postalCode",
            pick_section_field(item, &["zip", "postalcode"]),
        );
        put(&mut data, "country", pick_section_field(item, &["country"]));
    }

    ImportedCipher {
        cipher_type: 4,
        name: title.into(),
        notes: merged_notes(item),
        data_json: serde_json::Value::Object(data).to_string(),
        favorite: item.fav_index.unwrap_or(0) > 0,
        bitwarden_folder_id: folder_name.map(str::to_string),
    }
}

// =====================================================================
// Field-walking helpers
// =====================================================================

/// Pick a top-level login field by `designation` (1Password's stable
/// hint for which slot is username vs. password). Falls back to a
/// case-insensitive match on `name`.
fn pick_login_field(item: &Item, designation: &str) -> Option<String> {
    item.details
        .login_fields
        .iter()
        .find(|f| {
            f.designation.as_deref() == Some(designation)
                || f.name
                    .as_deref()
                    .map(|n| n.eq_ignore_ascii_case(designation))
                    .unwrap_or(false)
        })
        .and_then(|f| f.value.clone())
}

/// Pick a section field by id or title. `keys` is a list of ASCII
/// keywords that match (case-insensitively) against the field's
/// `id` first (1Password exports use stable ids like "ccnum") and
/// then its `title`.
fn pick_section_field(item: &Item, keys: &[&str]) -> Option<String> {
    for section in &item.details.sections {
        for f in &section.fields {
            let id_match =
                f.id.as_deref()
                    .map(|s| keys.iter().any(|k| s.eq_ignore_ascii_case(k)))
                    .unwrap_or(false);
            let title_match = f
                .title
                .as_deref()
                .map(|s| keys.iter().any(|k| s.eq_ignore_ascii_case(k)))
                .unwrap_or(false);
            if id_match || title_match {
                if let Some(v) = f.value.pick_string() {
                    if !v.is_empty() {
                        return Some(v);
                    }
                }
            }
        }
    }
    None
}

/// Combine 1Password's `notesPlain` with any "extra" section fields
/// we didn't already harvest into the typed data, so transcripts are
/// never silently lost. Pure best-effort.
fn merged_notes(item: &Item) -> Option<String> {
    let primary = item.details.notes_plain.clone().filter(|s| !s.is_empty());
    // Nothing to gather from sections at this layer — the
    // type-specific projectors already pulled the structured fields
    // they care about. We deliberately don't append every section
    // field on top of typed data because that would duplicate values
    // the user just imported into structured slots.
    primary
}

/// Split a 1Password expiry value into `(month, year)`. Accepts
/// `YYYYMM` (their canonical i64 format expressed as string), `MM/YY`,
/// or `MM/YYYY`. Anything else returns `(None, None)` and the field
/// is dropped.
fn split_expiry(s: &str) -> (Option<String>, Option<String>) {
    let s = s.trim();
    if let Some((mo, yr)) = s.split_once('/') {
        return (Some(mo.trim().to_string()), Some(normalize_year(yr.trim())));
    }
    if s.len() == 6 && s.chars().all(|c| c.is_ascii_digit()) {
        // YYYYMM
        return (Some(s[4..].to_string()), Some(s[..4].to_string()));
    }
    (None, None)
}

fn normalize_year(s: &str) -> String {
    if s.len() == 2 && s.chars().all(|c| c.is_ascii_digit()) {
        format!("20{s}")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_json() -> &'static str {
        r#"{
          "accounts": [
            {
              "vaults": [
                {
                  "attrs": {"name": "Personal"},
                  "items": [
                    {
                      "categoryUuid": "001",
                      "favIndex": 1,
                      "trashed": false,
                      "overview": {"title": "GitHub", "url": "https://github.com"},
                      "details": {
                        "loginFields": [
                          {"designation": "username", "value": "alice"},
                          {"designation": "password", "value": "hunter2"}
                        ],
                        "sections": [
                          {
                            "title": "MFA",
                            "fields": [
                              {"title": "one-time password", "value": {"totp": "otpauth://totp/GH"}}
                            ]
                          }
                        ],
                        "notesPlain": "primary dev"
                      }
                    },
                    {
                      "categoryUuid": "003",
                      "overview": {"title": "Wifi"},
                      "details": {"notesPlain": "home: tacocat"}
                    },
                    {
                      "categoryUuid": "002",
                      "overview": {"title": "Visa"},
                      "details": {
                        "sections": [
                          {
                            "title": "Card Details",
                            "fields": [
                              {"id": "cardholder", "value": {"string": "Alice Doe"}},
                              {"id": "type", "value": {"creditCardType": "visa"}},
                              {"id": "ccnum", "value": {"creditCardNumber": "4111111111111111"}},
                              {"id": "expiry", "value": {"monthYear": "203012"}},
                              {"id": "cvv", "value": {"concealed": "123"}}
                            ]
                          }
                        ]
                      }
                    },
                    {
                      "categoryUuid": "004",
                      "overview": {"title": "My Identity"},
                      "details": {
                        "sections": [
                          {
                            "title": "Identification",
                            "fields": [
                              {"id": "firstname", "value": {"string": "Alice"}},
                              {"id": "lastname",  "value": {"string": "Doe"}},
                              {"id": "email",     "value": {"email": "a@example.com"}},
                              {"id": "address",   "value": {"address": {
                                "street":"123 Main","city":"Anywhere","state":"CA",
                                "zip":"94000","country":"US"}}}
                            ]
                          }
                        ]
                      }
                    },
                    {
                      "categoryUuid": "005",
                      "overview": {"title": "Standalone password"},
                      "details": {"password": "letmein"}
                    },
                    {
                      "categoryUuid": "114",
                      "overview": {"title": "SSH key (skipped)"},
                      "details": {}
                    },
                    {
                      "categoryUuid": "001",
                      "trashed": true,
                      "overview": {"title": "Old (trashed)"},
                      "details": {"loginFields": [{"designation":"password","value":"x"}]}
                    }
                  ]
                },
                {
                  "attrs": {"name": "Work"},
                  "items": [
                    {
                      "categoryUuid": "001",
                      "overview": {"title": "Slack", "urls":[{"url":"https://acme.slack.com"}]},
                      "details": {
                        "loginFields": [
                          {"designation":"username","value":"alice@acme"},
                          {"designation":"password","value":"slacking"}
                        ]
                      }
                    }
                  ]
                }
              ]
            }
          ]
        }"#
    }

    #[test]
    fn projects_each_supported_category() {
        let p = project_from_data_json(data_json()).unwrap();
        // 7 items total → -1 trashed, -1 unsupported (114) = 5 ciphers
        // + the Slack entry from the second vault = 6.
        assert_eq!(p.ciphers.len(), 6);
        assert_eq!(p.folders, vec!["Personal", "Work"]);
        assert!(p
            .warnings
            .iter()
            .any(|w| w.contains("SSH key (skipped)") && w.contains("114")));
        assert!(p.warnings.iter().any(|w| w.contains("trashed")));
    }

    #[test]
    fn login_round_trip_uri_username_password_totp() {
        let p = project_from_data_json(data_json()).unwrap();
        let github = p.ciphers.iter().find(|c| c.name == "GitHub").unwrap();
        assert_eq!(github.cipher_type, 1);
        assert!(github.favorite);
        let data: serde_json::Value = serde_json::from_str(&github.data_json).unwrap();
        assert_eq!(data["username"], "alice");
        assert_eq!(data["password"], "hunter2");
        assert_eq!(data["uri"], "https://github.com");
        assert_eq!(data["totp"], "otpauth://totp/GH");
        assert_eq!(github.notes.as_deref(), Some("primary dev"));
    }

    #[test]
    fn login_falls_back_to_overview_urls_array() {
        let p = project_from_data_json(data_json()).unwrap();
        let slack = p.ciphers.iter().find(|c| c.name == "Slack").unwrap();
        let data: serde_json::Value = serde_json::from_str(&slack.data_json).unwrap();
        assert_eq!(data["uri"], "https://acme.slack.com");
    }

    #[test]
    fn secure_note_keeps_body_in_notes() {
        let p = project_from_data_json(data_json()).unwrap();
        let n = p.ciphers.iter().find(|c| c.name == "Wifi").unwrap();
        assert_eq!(n.cipher_type, 2);
        assert_eq!(n.data_json, "{}");
        assert!(n.notes.as_deref().unwrap().contains("tacocat"));
    }

    #[test]
    fn card_extracts_brand_number_expiry_cvv() {
        let p = project_from_data_json(data_json()).unwrap();
        let c = p.ciphers.iter().find(|c| c.name == "Visa").unwrap();
        assert_eq!(c.cipher_type, 3);
        let data: serde_json::Value = serde_json::from_str(&c.data_json).unwrap();
        assert_eq!(data["cardholderName"], "Alice Doe");
        assert_eq!(data["brand"], "visa");
        assert_eq!(data["number"], "4111111111111111");
        assert_eq!(data["expMonth"], "12");
        assert_eq!(data["expYear"], "2030");
        assert_eq!(data["code"], "123");
    }

    #[test]
    fn identity_extracts_structured_address() {
        let p = project_from_data_json(data_json()).unwrap();
        let id = p.ciphers.iter().find(|c| c.name == "My Identity").unwrap();
        let data: serde_json::Value = serde_json::from_str(&id.data_json).unwrap();
        assert_eq!(data["firstName"], "Alice");
        assert_eq!(data["lastName"], "Doe");
        assert_eq!(data["email"], "a@example.com");
        assert_eq!(data["address1"], "123 Main");
        assert_eq!(data["postalCode"], "94000");
        assert_eq!(data["country"], "US");
    }

    #[test]
    fn password_only_category_maps_to_login_with_no_username() {
        let p = project_from_data_json(data_json()).unwrap();
        let pw = p
            .ciphers
            .iter()
            .find(|c| c.name == "Standalone password")
            .unwrap();
        assert_eq!(pw.cipher_type, 1);
        let data: serde_json::Value = serde_json::from_str(&pw.data_json).unwrap();
        assert_eq!(data["password"], "letmein");
        assert!(data.get("username").is_none());
    }

    #[test]
    fn vaults_become_folders_in_export_order() {
        let p = project_from_data_json(data_json()).unwrap();
        assert_eq!(p.folders, vec!["Personal", "Work"]);
        let github = p.ciphers.iter().find(|c| c.name == "GitHub").unwrap();
        assert_eq!(github.bitwarden_folder_id.as_deref(), Some("Personal"));
        let slack = p.ciphers.iter().find(|c| c.name == "Slack").unwrap();
        assert_eq!(slack.bitwarden_folder_id.as_deref(), Some("Work"));
    }

    #[test]
    fn empty_export_is_handled() {
        let p = project_from_data_json(r#"{"accounts": []}"#).unwrap();
        assert!(p.folders.is_empty());
        assert!(p.ciphers.is_empty());
        assert!(p.warnings.is_empty());
    }

    #[test]
    fn split_expiry_handles_yyyymm() {
        assert_eq!(
            split_expiry("203012"),
            (Some("12".into()), Some("2030".into()))
        );
    }

    #[test]
    fn split_expiry_handles_slash_format() {
        assert_eq!(
            split_expiry("12/2030"),
            (Some("12".into()), Some("2030".into()))
        );
        assert_eq!(
            split_expiry("12/30"),
            (Some("12".into()), Some("2030".into()))
        );
    }

    #[test]
    fn unparseable_expiry_drops_to_none() {
        assert_eq!(split_expiry("not a date"), (None, None));
    }

    #[test]
    fn project_from_zip_rejects_missing_export_data() {
        // Empty zip — no `export.data` member.
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            w.start_file::<_, ()>(
                "export.attributes",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
            std::io::Write::write_all(&mut w, b"{}").unwrap();
            w.finish().unwrap();
        }
        let err = project_from_zip(&buf).unwrap_err();
        assert!(format!("{err}").contains("export.data"));
    }

    #[test]
    fn project_from_zip_round_trips_a_minimal_export() {
        // Round-trip: write a zip containing valid `export.data` and
        // verify the projection comes through.
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            w.start_file::<_, ()>("export.data", zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut w, data_json().as_bytes()).unwrap();
            w.finish().unwrap();
        }
        let p = project_from_zip(&buf).unwrap();
        assert_eq!(p.ciphers.len(), 6);
    }
}
