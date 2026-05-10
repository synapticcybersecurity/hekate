//! M2.27c — LastPass CSV import (pure parser).
//!
//! LastPass exports a flat CSV with these columns (in order):
//!
//! ```text
//! url, username, password, totp, extra, name, grouping, fav
//! ```
//!
//! - **Standard logins**: `url` is a real URL. `extra` carries free-text
//!   notes. Mapped to hekate's login (`cipher_type = 1`).
//! - **Secure notes**: `url` is the sentinel `http://sn`. The note body
//!   is in `extra`. Mapped to hekate's secure_note (`cipher_type = 2`).
//! - **Grouping**: forward-slash-separated path (`Personal/Email`); we
//!   take the leaf segment as the folder name to match how the
//!   Bitwarden / 1Password / KeePass importers thread folders.
//! - **fav** column: `"1"` → favorite.
//!
//! ## What we drop
//!
//! - **Note types** (LastPass encodes credit cards, identities, bank
//!   accounts, etc. as secure notes whose `extra` field starts with
//!   `NoteType: <SomeType>` and contains `key:value` lines). Reverse-
//!   engineering them into hekate's typed cipher shapes is brittle and
//!   format-version-dependent. We skip them with a per-row warning so
//!   users can re-enter manually. Plain text-only secure notes still
//!   import as `cipher_type = 2`.
//! - LastPass also has an "Equivalent Domains" / "Sharing Center" /
//!   "Form Fills" set of features the CSV doesn't carry — nothing for
//!   us to do.

use serde::Deserialize;

use crate::{Error, Result};

// Re-use the BW import's output types so the CLI can share orchestration.
pub use crate::import_bitwarden::{ImportedCipher, ProjectedImport};

/// Sentinel URL LastPass uses on every secure-note row.
const SECURE_NOTE_URL: &str = "http://sn";

/// Parse a LastPass CSV export. Pure projection — no I/O.
pub fn parse_csv(csv_text: &str) -> Result<ProjectedImport> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true) // some LP exports omit trailing columns
        .from_reader(csv_text.as_bytes());

    let mut folders: Vec<String> = Vec::new();
    let mut ciphers: Vec<ImportedCipher> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    for (row_idx, record) in reader.deserialize::<LastPassRow>().enumerate() {
        let row = match record {
            Ok(r) => r,
            Err(e) => {
                warnings.push(format!("row {}: {e}", row_idx + 1));
                continue;
            }
        };
        match project_row(&row) {
            Ok(c) => {
                if let Some(f) = c.bitwarden_folder_id.as_deref() {
                    if !folders.iter().any(|s| s == f) {
                        folders.push(f.to_string());
                    }
                }
                ciphers.push(c);
            }
            Err(reason) => warnings.push(format!(
                "skipping {:?}: {reason}",
                row.name.as_deref().unwrap_or("<no title>")
            )),
        }
    }

    Ok(ProjectedImport {
        folders,
        ciphers,
        warnings,
    })
}

#[derive(Debug, Default, Deserialize)]
struct LastPassRow {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    extra: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    grouping: Option<String>,
    #[serde(default)]
    fav: Option<String>,
}

fn project_row(row: &LastPassRow) -> std::result::Result<ImportedCipher, String> {
    let title = row
        .name
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "<untitled>".into());
    let folder_name = row.grouping.as_deref().and_then(leaf_folder);
    let favorite = row.fav.as_deref() == Some("1");
    let extra = row.extra.as_deref().unwrap_or("");

    if row.url.as_deref() == Some(SECURE_NOTE_URL) {
        // Secure note (or a typed note if the body starts with
        // `NoteType:`). Reject typed notes; plain ones import.
        if extra.trim_start().starts_with("NoteType:") {
            // Pull the type off the first line for the warning so the
            // user knows what we skipped.
            let kind = extra
                .lines()
                .next()
                .unwrap_or("")
                .trim_start_matches("NoteType:")
                .trim();
            return Err(format!(
                "LastPass typed note ({kind}) — re-enter manually for now"
            ));
        }
        return Ok(ImportedCipher {
            cipher_type: 2,
            name: title,
            notes: optional_string(extra),
            data_json: "{}".into(),
            favorite,
            bitwarden_folder_id: folder_name,
        });
    }

    // Regular login row.
    let mut data = serde_json::Map::new();
    if let Some(v) = row.username.as_deref().filter(|s| !s.is_empty()) {
        data.insert("username".into(), serde_json::Value::String(v.into()));
    }
    if let Some(v) = row.password.as_deref().filter(|s| !s.is_empty()) {
        data.insert("password".into(), serde_json::Value::String(v.into()));
    }
    if let Some(v) = row.url.as_deref().filter(|s| !s.is_empty()) {
        data.insert("uri".into(), serde_json::Value::String(v.into()));
    }
    if let Some(v) = row.totp.as_deref().filter(|s| !s.is_empty()) {
        data.insert("totp".into(), serde_json::Value::String(v.into()));
    }
    Ok(ImportedCipher {
        cipher_type: 1,
        name: title,
        notes: optional_string(extra),
        data_json: serde_json::Value::Object(data).to_string(),
        favorite,
        bitwarden_folder_id: folder_name,
    })
}

fn leaf_folder(grouping: &str) -> Option<String> {
    let trimmed = grouping.trim();
    if trimmed.is_empty() {
        return None;
    }
    // LastPass nests via "/". Take the last non-empty segment.
    let leaf = trimmed.rsplit('/').find(|s| !s.is_empty())?.trim();
    if leaf.is_empty() {
        None
    } else {
        Some(leaf.to_string())
    }
}

fn optional_string(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

// `Error` constructors are only used to render the public error type;
// keep the import here even when serde_json::Value isn't pulled in.
#[allow(dead_code)]
fn _err_marker() -> Error {
    Error::InvalidEncoding(String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_csv() -> &'static str {
        // Minimal LP-shaped CSV: header + 4 rows. Quoted fields use
        // standard CSV quoting; embedded newlines in `extra` are fine.
        "url,username,password,totp,extra,name,grouping,fav\n\
         https://github.com,alice@example.com,hunter2,otpauth://totp/GH,primary dev,GitHub,Personal/Dev,1\n\
         http://sn,,,,\"home: tacocat\\nguest: muffin\",Wifi password,Personal,0\n\
         http://sn,,,,\"NoteType:Credit Card\\nNumber:4111\",Visa (skipped),Personal,0\n\
         https://acme.slack.com,alice@acme,slacking,,,Slack,Work,0\n"
    }

    fn fixture() -> ProjectedImport {
        // The fixture above uses `\\n` literal escapes so the test
        // string compiles inline; convert to real newlines before
        // handing to the CSV reader so the embedded note body is
        // multi-line as a real LP export would be.
        let csv = fixture_csv().replace("\\n", "\n");
        parse_csv(&csv).expect("parses")
    }

    #[test]
    fn projects_each_supported_row_type() {
        let p = fixture();
        // 4 rows total — 1 typed-note skipped → 3 ciphers.
        assert_eq!(p.ciphers.len(), 3);
        // Folders are the leaf segments of grouping. "Personal/Dev" → "Dev",
        // "Personal" → "Personal", "Work" → "Work".
        assert!(p.folders.iter().any(|f| f == "Dev"));
        assert!(p.folders.iter().any(|f| f == "Personal"));
        assert!(p.folders.iter().any(|f| f == "Work"));
        assert!(p
            .warnings
            .iter()
            .any(|w| w.contains("Visa (skipped)") && w.contains("Credit Card")));
    }

    #[test]
    fn login_row_data_round_trips() {
        let p = fixture();
        let github = p.ciphers.iter().find(|c| c.name == "GitHub").unwrap();
        assert_eq!(github.cipher_type, 1);
        assert!(github.favorite);
        assert_eq!(github.bitwarden_folder_id.as_deref(), Some("Dev"));
        let data: serde_json::Value = serde_json::from_str(&github.data_json).unwrap();
        assert_eq!(data["username"], "alice@example.com");
        assert_eq!(data["password"], "hunter2");
        assert_eq!(data["uri"], "https://github.com");
        assert_eq!(data["totp"], "otpauth://totp/GH");
        assert_eq!(github.notes.as_deref(), Some("primary dev"));
    }

    #[test]
    fn secure_note_keeps_body_in_notes() {
        let p = fixture();
        let n = p
            .ciphers
            .iter()
            .find(|c| c.name == "Wifi password")
            .unwrap();
        assert_eq!(n.cipher_type, 2);
        assert_eq!(n.data_json, "{}");
        assert!(n.notes.as_deref().unwrap().contains("tacocat"));
        assert!(n.notes.as_deref().unwrap().contains("muffin"));
    }

    #[test]
    fn typed_notes_are_skipped_with_warning() {
        let p = fixture();
        assert!(!p.ciphers.iter().any(|c| c.name == "Visa (skipped)"));
    }

    #[test]
    fn folder_is_leaf_segment_of_grouping() {
        let p = fixture();
        let github = p.ciphers.iter().find(|c| c.name == "GitHub").unwrap();
        assert_eq!(github.bitwarden_folder_id.as_deref(), Some("Dev"));
    }

    #[test]
    fn empty_csv_with_only_header_is_handled() {
        let csv = "url,username,password,totp,extra,name,grouping,fav\n";
        let p = parse_csv(csv).unwrap();
        assert!(p.ciphers.is_empty());
        assert!(p.folders.is_empty());
        assert!(p.warnings.is_empty());
    }

    #[test]
    fn missing_optional_columns_default_to_none() {
        // Some LP exports drop trailing columns. `flexible(true)` on
        // the reader accepts short rows; missing columns deserialize
        // to None.
        let csv = "url,username,password,totp,extra,name,grouping,fav\n\
                   https://example.com,u,p,,,Example,,\n";
        let p = parse_csv(csv).unwrap();
        assert_eq!(p.ciphers.len(), 1);
        let data: serde_json::Value = serde_json::from_str(&p.ciphers[0].data_json).unwrap();
        assert_eq!(data["password"], "p");
        assert!(data.get("totp").is_none());
        assert!(p.ciphers[0].bitwarden_folder_id.is_none());
        assert!(!p.ciphers[0].favorite);
    }

    #[test]
    fn nested_grouping_takes_only_leaf() {
        assert_eq!(leaf_folder("a/b/c"), Some("c".into()));
        assert_eq!(leaf_folder("solo"), Some("solo".into()));
        assert_eq!(leaf_folder(""), None);
        assert_eq!(leaf_folder("trailing/"), Some("trailing".into()));
        assert_eq!(leaf_folder("/leading"), Some("leading".into()));
    }

    #[test]
    fn quoted_field_with_embedded_comma_round_trips() {
        // Username with a comma: must be quoted in the CSV.
        let csv = "url,username,password,totp,extra,name,grouping,fav\n\
                   https://x,\"alice, the great\",p,,,X,,0\n";
        let p = parse_csv(csv).unwrap();
        assert_eq!(p.ciphers.len(), 1);
        let data: serde_json::Value = serde_json::from_str(&p.ciphers[0].data_json).unwrap();
        assert_eq!(data["username"], "alice, the great");
    }

    #[test]
    fn favorite_is_only_true_when_fav_is_one() {
        let csv = "url,username,password,totp,extra,name,grouping,fav\n\
                   https://a,u,p,,,A,,1\n\
                   https://b,u,p,,,B,,0\n\
                   https://c,u,p,,,C,,\n";
        let p = parse_csv(csv).unwrap();
        let by = |n: &str| -> bool { p.ciphers.iter().find(|c| c.name == n).unwrap().favorite };
        assert!(by("A"));
        assert!(!by("B"));
        assert!(!by("C"));
    }
}
