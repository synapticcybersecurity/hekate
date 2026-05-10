//! M2.27a — fixture-based smoke for the 1Password 1PUX parser.
//!
//! The unit tests in `hekate_core::import_1password::tests` cover each
//! projection branch with an inline JSON fixture; this test loads
//! the on-disk `tests/fixtures/1password_export.data.json` and wraps
//! it in an in-memory ZIP so the full parser path
//! (`project_from_zip`) gets exercised. The data fixture is a plain
//! JSON file so external eyes can read it without unzipping.

use std::io::Write;

use hekate_core::import_1password::project_from_zip;

const DATA_JSON: &str = include_str!("fixtures/1password_export.data.json");

/// Wrap the fixture JSON in a 1PUX-shaped zip (single
/// `export.data` member) so we exercise the same code path the CLI
/// hits when reading a real `.1pux` file.
fn fixture_zip() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        w.start_file::<_, ()>("export.data", zip::write::SimpleFileOptions::default())
            .unwrap();
        w.write_all(DATA_JSON.as_bytes()).unwrap();
        w.finish().unwrap();
    }
    buf
}

#[test]
fn fixture_projects_to_expected_counts() {
    let p = project_from_zip(&fixture_zip()).expect("fixture zip parses");
    assert_eq!(p.folders, vec!["Personal", "Work"]);
    // 7 items in Personal + 1 in Work = 8. Minus 1 trashed, minus 1
    // unsupported (114) = 6 ciphers.
    assert_eq!(p.ciphers.len(), 6);
    // Two warnings — the trashed item + the SSH key.
    assert!(p.warnings.iter().any(|w| w.contains("trashed")));
    assert!(p
        .warnings
        .iter()
        .any(|w| w.contains("SSH Key") && w.contains("114")));
}

#[test]
fn fixture_login_round_trips_username_password_uri_totp() {
    let p = project_from_zip(&fixture_zip()).unwrap();
    let github = p.ciphers.iter().find(|c| c.name == "GitHub").unwrap();
    assert!(github.favorite);
    assert_eq!(github.bitwarden_folder_id.as_deref(), Some("Personal"));
    let data: serde_json::Value = serde_json::from_str(&github.data_json).unwrap();
    assert_eq!(data["username"], "alice@example.com");
    assert_eq!(data["password"], "hunter2");
    assert_eq!(data["uri"], "https://github.com");
    assert!(data["totp"].as_str().unwrap().starts_with("otpauth://"));
    assert_eq!(github.notes.as_deref(), Some("primary dev account"));
}

#[test]
fn fixture_secure_note_keeps_body_in_notes() {
    let p = project_from_zip(&fixture_zip()).unwrap();
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
fn fixture_card_field_extraction_matches_hekate_data_shape() {
    let p = project_from_zip(&fixture_zip()).unwrap();
    let card = p
        .ciphers
        .iter()
        .find(|c| c.name == "Travel Visa")
        .expect("card present");
    assert_eq!(card.cipher_type, 3);
    let data: serde_json::Value = serde_json::from_str(&card.data_json).unwrap();
    for key in [
        "cardholderName",
        "brand",
        "number",
        "expMonth",
        "expYear",
        "code",
    ] {
        assert!(data[key].is_string(), "{key} missing on card");
    }
    assert_eq!(data["expMonth"], "12");
    assert_eq!(data["expYear"], "2030");
}

#[test]
fn fixture_identity_extracts_structured_address() {
    let p = project_from_zip(&fixture_zip()).unwrap();
    let id = p
        .ciphers
        .iter()
        .find(|c| c.name == "Travel identity")
        .unwrap();
    let data: serde_json::Value = serde_json::from_str(&id.data_json).unwrap();
    assert_eq!(data["firstName"], "Alice");
    assert_eq!(data["lastName"], "Doe");
    assert_eq!(data["email"], "alice@example.com");
    assert_eq!(data["address1"], "123 Main St");
    assert_eq!(data["postalCode"], "94000");
    assert_eq!(data["country"], "US");
}

#[test]
fn fixture_password_only_maps_to_login() {
    let p = project_from_zip(&fixture_zip()).unwrap();
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
fn fixture_vaults_become_folders_threaded_onto_ciphers() {
    let p = project_from_zip(&fixture_zip()).unwrap();
    let slack = p.ciphers.iter().find(|c| c.name == "Slack").unwrap();
    assert_eq!(slack.bitwarden_folder_id.as_deref(), Some("Work"));
    let github = p.ciphers.iter().find(|c| c.name == "GitHub").unwrap();
    assert_eq!(github.bitwarden_folder_id.as_deref(), Some("Personal"));
}
