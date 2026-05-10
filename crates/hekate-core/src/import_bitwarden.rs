//! M2.27 — Bitwarden unencrypted JSON import (pure parser).
//!
//! Parses the canonical Bitwarden export shape and projects it onto
//! hekate's `ImportedCipher` plaintext model. No I/O, no crypto, no
//! async. The CLI layer is responsible for:
//!
//! 1. Generating a UUIDv7 cipher_id per ImportedCipher.
//! 2. Allocating per-cipher keys (PCKs) under the user's account_key.
//! 3. AAD-binding each encrypted field to (cipher_id, cipher_type)
//!    via the existing `hekate-cli/src/crypto.rs::aad_*` helpers.
//! 4. Creating server-side folders first, then ciphers (with the
//!    folder_id we got back).
//! 5. Re-signing + uploading the BW04 vault manifest at the end.
//!
//! ## Wire shape (Bitwarden side)
//!
//! Bitwarden's *unencrypted* "JSON (.json)" export looks like this
//! (every field except `name`/`type` is optional from our parser's
//! point of view):
//!
//! ```text
//! {
//!   "encrypted": false,
//!   "folders": [{"id":"<bw-uuid>","name":"…"}],
//!   "items": [
//!     {
//!       "id": "<bw-uuid>",
//!       "organizationId": null,        // we only import personal items
//!       "folderId": "<bw-uuid>"|null,
//!       "type": 1|2|3|4,                // 1 login 2 note 3 card 4 identity
//!       "name": "…",
//!       "notes": "…"|null,
//!       "favorite": false,
//!       "login":     { "uris":[{"uri":"…"}], "username":…, "password":…, "totp":… },
//!       "secureNote":{ "type": 0 },
//!       "card":      { "cardholderName":…, "brand":…, "number":…, "expMonth":…, "expYear":…, "code":… },
//!       "identity":  { "title":…, "firstName":…, … }
//!     }
//!   ]
//! }
//! ```
//!
//! ## What we drop (vs. preserve)
//!
//! - `organizationId` / `collectionIds` — only personal items in the
//!   first cut. Org-scoped imports could land later.
//! - `passwordHistory` — hekate doesn't store this today.
//! - `fields[]` (Bitwarden custom fields) — hekate's typed cipher
//!   shapes don't have a "custom fields" slot. We append them to
//!   notes (one line per field) so the data isn't lost; users can
//!   restructure manually later.
//! - `reprompt` — hekate v2 moved this into encrypted data per BW04
//!   mitigation; reading back from a Bitwarden export with
//!   `reprompt: 1` is an obsolete code path on our side.
//! - Secret types Bitwarden doesn't have (ssh-key, totp-only) —
//!   not present in the export, no mapping needed.

use serde::Deserialize;

use crate::{Error, Result};

#[derive(Debug, Deserialize)]
pub struct BitwardenExport {
    /// `false` for unencrypted exports — we refuse to parse the
    /// encrypted variant in M2.27 (would need the user to supply the
    /// password and us to implement Bitwarden's PBKDF2/AES path).
    #[serde(default)]
    pub encrypted: bool,
    #[serde(default)]
    pub folders: Vec<BitwardenFolder>,
    #[serde(default)]
    pub items: Vec<BitwardenItem>,
}

#[derive(Debug, Deserialize)]
pub struct BitwardenFolder {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct BitwardenItem {
    /// 1=login, 2=secureNote, 3=card, 4=identity. We drop ssh-key
    /// (5) and others Bitwarden never exports.
    #[serde(rename = "type")]
    pub item_type: i32,
    pub name: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(rename = "folderId", default)]
    pub folder_id: Option<String>,
    #[serde(rename = "organizationId", default)]
    pub organization_id: Option<String>,

    #[serde(default)]
    pub login: Option<BitwardenLogin>,
    #[serde(default)]
    pub card: Option<BitwardenCard>,
    #[serde(default)]
    pub identity: Option<BitwardenIdentity>,

    /// Custom fields — appended to notes if present.
    #[serde(default)]
    pub fields: Vec<BitwardenField>,
}

#[derive(Debug, Deserialize)]
pub struct BitwardenLogin {
    #[serde(default)]
    pub uris: Vec<BitwardenLoginUri>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub totp: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BitwardenLoginUri {
    pub uri: String,
}

#[derive(Debug, Deserialize)]
pub struct BitwardenCard {
    #[serde(rename = "cardholderName", default)]
    pub cardholder_name: Option<String>,
    #[serde(default)]
    pub brand: Option<String>,
    #[serde(default)]
    pub number: Option<String>,
    #[serde(rename = "expMonth", default)]
    pub exp_month: Option<String>,
    #[serde(rename = "expYear", default)]
    pub exp_year: Option<String>,
    /// CVV in Bitwarden parlance.
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BitwardenIdentity {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(rename = "firstName", default)]
    pub first_name: Option<String>,
    #[serde(rename = "middleName", default)]
    pub middle_name: Option<String>,
    #[serde(rename = "lastName", default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub address1: Option<String>,
    #[serde(default)]
    pub address2: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(rename = "postalCode", default)]
    pub postal_code: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub company: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub ssn: Option<String>,
    #[serde(rename = "passportNumber", default)]
    pub passport_number: Option<String>,
    #[serde(rename = "licenseNumber", default)]
    pub license_number: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BitwardenField {
    pub name: String,
    /// Bitwarden also has `type` (0 text, 1 hidden, 2 boolean, 3
    /// linked) but we render all of them as `name: value` lines in
    /// notes regardless, since hekate doesn't have a custom-fields
    /// slot today.
    #[serde(default)]
    pub value: Option<String>,
}

/// Parse the JSON. Refuses encrypted exports (callers should ask the
/// user to re-export as "JSON (unencrypted)").
pub fn parse_export(json: &str) -> Result<BitwardenExport> {
    let exp: BitwardenExport = serde_json::from_str(json)
        .map_err(|e| Error::InvalidEncoding(format!("bitwarden export not valid JSON: {e}")))?;
    if exp.encrypted {
        return Err(Error::InvalidEncoding(
            "encrypted Bitwarden exports are not supported in M2.27 — re-export as 'JSON (unencrypted)' from Bitwarden's web vault under Tools → Export Vault"
                .into(),
        ));
    }
    Ok(exp)
}

// =====================================================================
// Projection onto hekate's plaintext cipher model
// =====================================================================

/// Mirror of `hekate-cli::commands::add::PlainCipher` plus the inputs
/// the encryption layer needs (folder name → server folder id is
/// resolved by the CLI). Pure plaintext — must NOT be persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedCipher {
    /// 1=login, 2=secure_note, 3=card, 4=identity. Bitwarden's
    /// numbering happens to match hekate's for these four types.
    pub cipher_type: i32,
    pub name: String,
    /// Plaintext notes — may be a synthesized merge of the original
    /// notes plus any custom fields appended as `name: value` lines.
    pub notes: Option<String>,
    /// JSON string in the *hekate* type-specific data shape (not
    /// Bitwarden's). Empty `"{}"` for secure_notes.
    pub data_json: String,
    pub favorite: bool,
    /// Bitwarden folder id (if any) — the CLI resolves this to a
    /// server-allocated hekate folder id by name lookup against the
    /// `BitwardenExport.folders` array.
    pub bitwarden_folder_id: Option<String>,
}

/// Walk every Bitwarden item, project to `ImportedCipher`, and return
/// the `(folders, ciphers, skipped_warnings)` triple. Items we
/// can't represent (org-owned, unknown types) are skipped with a
/// warning so the CLI can surface them in the final summary.
///
/// The per-item `bitwarden_folder_id` field is rewritten from the
/// Bitwarden export's opaque id to the resolved folder *name*, so
/// the CLI orchestration can key by name uniformly across both
/// the Bitwarden and 1Password parsers (1Password has no separate
/// id concept — vault name is the key).
pub fn project(export: &BitwardenExport) -> ProjectedImport {
    let mut ciphers: Vec<ImportedCipher> = Vec::with_capacity(export.items.len());
    let mut warnings: Vec<String> = Vec::new();

    let id_to_name: std::collections::HashMap<&str, &str> = export
        .folders
        .iter()
        .map(|f| (f.id.as_str(), f.name.as_str()))
        .collect();

    for item in &export.items {
        if item.organization_id.is_some() {
            warnings.push(format!(
                "skipping org-owned item {:?} — only personal items import in M2.27",
                item.name
            ));
            continue;
        }
        match project_item(item) {
            Ok(mut c) => {
                // Rewrite the export's opaque folder id → resolved name.
                if let Some(id) = c.bitwarden_folder_id.take() {
                    if let Some(name) = id_to_name.get(id.as_str()) {
                        c.bitwarden_folder_id = Some((*name).to_string());
                    }
                    // If id doesn't resolve (orphan reference), leave None
                    // so the cipher imports at the root.
                }
                ciphers.push(c);
            }
            Err(reason) => warnings.push(format!("skipping {:?}: {reason}", item.name)),
        }
    }

    ProjectedImport {
        folders: export.folders.iter().map(|f| f.name.clone()).collect(),
        ciphers,
        warnings,
    }
}

#[derive(Debug, Clone)]
pub struct ProjectedImport {
    /// Distinct folder names, preserving export order. Duplicates are
    /// kept (rare in real exports; the CLI dedupes server-side via
    /// the create-folder response).
    pub folders: Vec<String>,
    pub ciphers: Vec<ImportedCipher>,
    /// Human-readable lines describing items that were skipped.
    pub warnings: Vec<String>,
}

fn project_item(item: &BitwardenItem) -> std::result::Result<ImportedCipher, String> {
    let merged_notes = merge_notes_and_fields(item.notes.as_deref(), &item.fields);

    match item.item_type {
        1 => {
            // Login.
            let l = item
                .login
                .as_ref()
                .ok_or_else(|| "type=1 (login) but no `login` object".to_string())?;
            let uri = l.uris.first().map(|u| u.uri.clone());
            let mut data = serde_json::Map::new();
            if let Some(u) = &l.username {
                data.insert("username".into(), serde_json::Value::String(u.clone()));
            }
            if let Some(p) = &l.password {
                data.insert("password".into(), serde_json::Value::String(p.clone()));
            }
            if let Some(u) = uri {
                data.insert("uri".into(), serde_json::Value::String(u));
            }
            if let Some(t) = &l.totp {
                data.insert("totp".into(), serde_json::Value::String(t.clone()));
            }
            Ok(ImportedCipher {
                cipher_type: 1,
                name: item.name.clone(),
                notes: merged_notes,
                data_json: serde_json::Value::Object(data).to_string(),
                favorite: item.favorite,
                bitwarden_folder_id: item.folder_id.clone(),
            })
        }
        2 => Ok(ImportedCipher {
            cipher_type: 2,
            name: item.name.clone(),
            // Secure note: body goes in `notes`. If Bitwarden had
            // custom fields they're already merged in via
            // `merge_notes_and_fields`.
            notes: merged_notes,
            data_json: "{}".into(),
            favorite: item.favorite,
            bitwarden_folder_id: item.folder_id.clone(),
        }),
        3 => {
            let c = item
                .card
                .as_ref()
                .ok_or_else(|| "type=3 (card) but no `card` object".to_string())?;
            // hekate's CardData uses the same field names Bitwarden does
            // (cardholderName, brand, number, expMonth, expYear, code)
            // — modeled after Bitwarden originally — so the mapping is
            // identity for non-null fields.
            let mut data = serde_json::Map::new();
            if let Some(v) = &c.cardholder_name {
                data.insert(
                    "cardholderName".into(),
                    serde_json::Value::String(v.clone()),
                );
            }
            if let Some(v) = &c.brand {
                data.insert("brand".into(), serde_json::Value::String(v.clone()));
            }
            if let Some(v) = &c.number {
                data.insert("number".into(), serde_json::Value::String(v.clone()));
            }
            if let Some(v) = &c.exp_month {
                data.insert("expMonth".into(), serde_json::Value::String(v.clone()));
            }
            if let Some(v) = &c.exp_year {
                data.insert("expYear".into(), serde_json::Value::String(v.clone()));
            }
            if let Some(v) = &c.code {
                data.insert("code".into(), serde_json::Value::String(v.clone()));
            }
            Ok(ImportedCipher {
                cipher_type: 3,
                name: item.name.clone(),
                notes: merged_notes,
                data_json: serde_json::Value::Object(data).to_string(),
                favorite: item.favorite,
                bitwarden_folder_id: item.folder_id.clone(),
            })
        }
        4 => {
            let i = item
                .identity
                .as_ref()
                .ok_or_else(|| "type=4 (identity) but no `identity` object".to_string())?;
            // Same field-name pattern: hekate's IdentityData uses
            // Bitwarden's keys verbatim (firstName, postalCode, etc.).
            let mut data = serde_json::Map::new();
            macro_rules! put {
                ($key:expr, $opt:expr) => {
                    if let Some(v) = $opt.as_deref() {
                        if !v.is_empty() {
                            data.insert($key.into(), serde_json::Value::String(v.into()));
                        }
                    }
                };
            }
            put!("title", i.title);
            put!("firstName", i.first_name);
            put!("middleName", i.middle_name);
            put!("lastName", i.last_name);
            put!("company", i.company);
            put!("email", i.email);
            put!("phone", i.phone);
            put!("address1", i.address1);
            put!("address2", i.address2);
            put!("city", i.city);
            put!("state", i.state);
            put!("postalCode", i.postal_code);
            put!("country", i.country);
            put!("ssn", i.ssn);
            put!("passportNumber", i.passport_number);
            put!("licenseNumber", i.license_number);
            Ok(ImportedCipher {
                cipher_type: 4,
                name: item.name.clone(),
                notes: merged_notes,
                data_json: serde_json::Value::Object(data).to_string(),
                favorite: item.favorite,
                bitwarden_folder_id: item.folder_id.clone(),
            })
        }
        other => Err(format!(
            "unsupported Bitwarden item type {other} (only 1=login, 2=note, 3=card, 4=identity)"
        )),
    }
}

/// Pmgr's typed ciphers don't have a "custom fields" slot. Bitwarden's
/// `fields` array is appended to notes as `name: value` lines so
/// the data isn't dropped on import. Original notes (if any) come
/// first, then a blank line separator, then the fields.
fn merge_notes_and_fields(notes: Option<&str>, fields: &[BitwardenField]) -> Option<String> {
    let trimmed_notes = notes.map(|s| s.trim_end_matches('\n').to_string());
    if fields.is_empty() {
        return trimmed_notes.filter(|s| !s.is_empty());
    }
    let field_lines: Vec<String> = fields
        .iter()
        .map(|f| {
            let v = f.value.as_deref().unwrap_or("");
            format!("{}: {v}", f.name)
        })
        .collect();
    let merged = match trimmed_notes {
        Some(n) if !n.is_empty() => format!("{n}\n\n{}", field_lines.join("\n")),
        _ => field_lines.join("\n"),
    };
    Some(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> &'static str {
        r#"{
          "encrypted": false,
          "folders": [
            {"id":"f1","name":"Personal"},
            {"id":"f2","name":"Work"}
          ],
          "items": [
            {
              "id":"i1", "type":1, "name":"GitHub",
              "folderId":"f2",
              "favorite":true,
              "login":{
                "uris":[{"uri":"https://github.com"}],
                "username":"alice","password":"hunter2","totp":"otpauth://totp/GH"
              }
            },
            {
              "id":"i2", "type":2, "name":"Wifi password",
              "notes":"home wifi: tacocat\nguest wifi: muffin",
              "folderId":"f1"
            },
            {
              "id":"i3", "type":3, "name":"My Visa",
              "card":{
                "cardholderName":"A. Doe","brand":"Visa","number":"4111111111111111",
                "expMonth":"12","expYear":"2030","code":"123"
              }
            },
            {
              "id":"i4", "type":4, "name":"My Identity",
              "identity":{
                "firstName":"Alice","lastName":"Doe","email":"a@example.com",
                "address1":"123 Main","city":"Anywhere","postalCode":"12345"
              }
            },
            {
              "id":"i5", "type":1, "name":"Skipped (org-owned)",
              "organizationId":"org-1",
              "login":{"username":"x","password":"y","uris":[]}
            },
            {
              "id":"i6", "type":99, "name":"Unsupported type"
            },
            {
              "id":"i7", "type":1, "name":"With custom fields",
              "notes":"primary note",
              "fields":[
                {"name":"recovery", "value":"abc-def"},
                {"name":"backup-email", "value":"alt@example.com"}
              ],
              "login":{"username":"u","password":"p","uris":[]}
            }
          ]
        }"#
    }

    #[test]
    fn parse_round_trips_top_level() {
        let exp = parse_export(fixture()).unwrap();
        assert!(!exp.encrypted);
        assert_eq!(exp.folders.len(), 2);
        assert_eq!(exp.items.len(), 7);
    }

    #[test]
    fn parse_rejects_encrypted_exports() {
        let json = r#"{"encrypted": true, "folders": [], "items": []}"#;
        let err = parse_export(json).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("encrypted"));
    }

    #[test]
    fn project_emits_each_supported_type() {
        let exp = parse_export(fixture()).unwrap();
        let p = project(&exp);
        assert_eq!(p.folders, vec!["Personal", "Work"]);
        // 7 items - 1 org-owned - 1 unsupported-type = 5 ciphers
        assert_eq!(p.ciphers.len(), 5);
        assert_eq!(p.warnings.len(), 2);
    }

    #[test]
    fn login_projection_preserves_username_password_uri_totp() {
        let exp = parse_export(fixture()).unwrap();
        let p = project(&exp);
        let github = p.ciphers.iter().find(|c| c.name == "GitHub").unwrap();
        assert_eq!(github.cipher_type, 1);
        assert!(github.favorite);
        let data: serde_json::Value = serde_json::from_str(&github.data_json).unwrap();
        assert_eq!(data["username"], "alice");
        assert_eq!(data["password"], "hunter2");
        assert_eq!(data["uri"], "https://github.com");
        assert_eq!(data["totp"], "otpauth://totp/GH");
        assert_eq!(github.bitwarden_folder_id, Some("Work".into()));
    }

    #[test]
    fn note_projection_keeps_body_in_notes() {
        let exp = parse_export(fixture()).unwrap();
        let p = project(&exp);
        let n = p
            .ciphers
            .iter()
            .find(|c| c.name == "Wifi password")
            .unwrap();
        assert_eq!(n.cipher_type, 2);
        assert_eq!(n.data_json, "{}");
        assert!(n.notes.as_deref().unwrap().contains("tacocat"));
    }

    #[test]
    fn card_projection_field_names_match_hekate_data_shape() {
        let exp = parse_export(fixture()).unwrap();
        let p = project(&exp);
        let c = p.ciphers.iter().find(|c| c.name == "My Visa").unwrap();
        assert_eq!(c.cipher_type, 3);
        let data: serde_json::Value = serde_json::from_str(&c.data_json).unwrap();
        assert_eq!(data["cardholderName"], "A. Doe");
        assert_eq!(data["brand"], "Visa");
        assert_eq!(data["number"], "4111111111111111");
        assert_eq!(data["expMonth"], "12");
        assert_eq!(data["expYear"], "2030");
        assert_eq!(data["code"], "123");
    }

    #[test]
    fn identity_projection_drops_empty_fields() {
        let exp = parse_export(fixture()).unwrap();
        let p = project(&exp);
        let id = p.ciphers.iter().find(|c| c.name == "My Identity").unwrap();
        let data: serde_json::Value = serde_json::from_str(&id.data_json).unwrap();
        assert_eq!(data["firstName"], "Alice");
        assert_eq!(data["lastName"], "Doe");
        assert_eq!(data["postalCode"], "12345");
        // Fields not in the source should not be in the output.
        assert!(data.get("middleName").is_none());
        assert!(data.get("phone").is_none());
    }

    #[test]
    fn org_owned_items_are_skipped_with_warning() {
        let exp = parse_export(fixture()).unwrap();
        let p = project(&exp);
        assert!(!p.ciphers.iter().any(|c| c.name.contains("org-owned")));
        assert!(p.warnings.iter().any(|w| w.contains("Skipped (org-owned)")));
    }

    #[test]
    fn unknown_types_are_skipped_with_warning() {
        let exp = parse_export(fixture()).unwrap();
        let p = project(&exp);
        assert!(!p.ciphers.iter().any(|c| c.name == "Unsupported type"));
        assert!(p
            .warnings
            .iter()
            .any(|w| w.contains("Unsupported type") && w.contains("type 99")));
    }

    #[test]
    fn custom_fields_are_merged_into_notes() {
        let exp = parse_export(fixture()).unwrap();
        let p = project(&exp);
        let item = p
            .ciphers
            .iter()
            .find(|c| c.name == "With custom fields")
            .unwrap();
        let n = item.notes.as_deref().unwrap();
        assert!(n.starts_with("primary note"));
        assert!(n.contains("recovery: abc-def"));
        assert!(n.contains("backup-email: alt@example.com"));
    }

    #[test]
    fn custom_fields_only_no_notes() {
        let json = r#"{
          "encrypted": false,
          "folders": [],
          "items": [{
            "type":1, "name":"x",
            "fields":[{"name":"k", "value":"v"}],
            "login":{"username":"u","password":"p","uris":[]}
          }]
        }"#;
        let p = project(&parse_export(json).unwrap());
        assert_eq!(p.ciphers.len(), 1);
        assert_eq!(p.ciphers[0].notes.as_deref(), Some("k: v"));
    }

    #[test]
    fn empty_export_is_handled() {
        let json = r#"{"encrypted": false, "folders": [], "items": []}"#;
        let p = project(&parse_export(json).unwrap());
        assert!(p.folders.is_empty());
        assert!(p.ciphers.is_empty());
        assert!(p.warnings.is_empty());
    }

    #[test]
    fn missing_optional_fields_default() {
        // Login with only a password — no uris, no username.
        let json = r#"{
          "encrypted": false,
          "folders": [],
          "items": [{
            "type":1, "name":"sparse",
            "login":{"password":"p"}
          }]
        }"#;
        let p = project(&parse_export(json).unwrap());
        assert_eq!(p.ciphers.len(), 1);
        let data: serde_json::Value = serde_json::from_str(&p.ciphers[0].data_json).unwrap();
        assert_eq!(data["password"], "p");
        assert!(data.get("uri").is_none());
        assert!(data.get("username").is_none());
    }

    #[test]
    fn bitwarden_folder_id_resolves_to_folder_name() {
        // The cipher came in with folderId="f2" pointing at the
        // "Work" folder. After projection the resolved name is what
        // sticks on the cipher (so both parsers can share the CLI
        // orchestration's name-keyed folder map).
        let exp = parse_export(fixture()).unwrap();
        let p = project(&exp);
        let github = p.ciphers.iter().find(|c| c.name == "GitHub").unwrap();
        assert_eq!(github.bitwarden_folder_id.as_deref(), Some("Work"));
    }
}
