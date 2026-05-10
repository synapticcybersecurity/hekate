//! M2.27 — fixture-based smoke for the Bitwarden import parser.
//!
//! The unit tests in `hekate_core::import_bitwarden::tests` cover each
//! branch with an inline JSON fixture; this test loads the on-disk
//! `tests/fixtures/bitwarden_export.json` so external eyes have a
//! concrete example of what a real input looks like, and so we
//! detect breakage if either the fixture or the parser drifts.
//!
//! Future format-additions (1Password, KeePass, LastPass) follow the
//! same pattern: `tests/fixtures/<format>_export.<ext>` plus a small
//! integration test that loads it.

use hekate_core::import_bitwarden::{parse_export, project};

const FIXTURE: &str = include_str!("fixtures/bitwarden_export.json");

#[test]
fn fixture_projects_to_expected_counts() {
    let exp = parse_export(FIXTURE).expect("fixture parses");
    let p = project(&exp);

    // 7 items total; 1 org-owned skipped → 6 ciphers projected.
    assert_eq!(p.ciphers.len(), 6);
    assert_eq!(p.folders, vec!["Personal", "Work"]);
    assert_eq!(p.warnings.len(), 1);
    assert!(p.warnings.iter().any(|w| w.contains("Org-owned (skipped)")));
}

#[test]
fn fixture_login_data_round_trips_every_field() {
    let exp = parse_export(FIXTURE).expect("fixture parses");
    let p = project(&exp);
    let github = p
        .ciphers
        .iter()
        .find(|c| c.name == "GitHub")
        .expect("GitHub item present");

    assert!(github.favorite);
    // After M2.27a the parser resolves the export's opaque folder
    // id to the human-readable name so both the Bitwarden and
    // 1Password parsers emit the same name-keyed convention.
    assert_eq!(github.bitwarden_folder_id.as_deref(), Some("Work"));
    let data: serde_json::Value =
        serde_json::from_str(&github.data_json).expect("login data is JSON");
    assert_eq!(data["username"], "alice@example.com");
    assert_eq!(data["password"], "hunter2");
    assert_eq!(data["uri"], "https://github.com/login");
    assert!(data["totp"].as_str().unwrap().starts_with("otpauth://"));
    // notes pass-through (no custom fields on this item).
    assert_eq!(github.notes.as_deref(), Some("primary dev account"));
}

#[test]
fn fixture_card_field_names_match_hekate_data_shape() {
    let exp = parse_export(FIXTURE).expect("fixture parses");
    let p = project(&exp);
    let card = p
        .ciphers
        .iter()
        .find(|c| c.name == "Travel Visa")
        .expect("card present");
    let data: serde_json::Value = serde_json::from_str(&card.data_json).unwrap();
    // hekate's CardData uses Bitwarden's exact key names — identity
    // mapping for non-null fields. (See hekate-cli::commands::add::CardData.)
    for key in [
        "cardholderName",
        "brand",
        "number",
        "expMonth",
        "expYear",
        "code",
    ] {
        assert!(data[key].is_string(), "{key} missing from card data");
    }
}

#[test]
fn fixture_identity_drops_unset_fields() {
    let exp = parse_export(FIXTURE).expect("fixture parses");
    let p = project(&exp);
    let id = p
        .ciphers
        .iter()
        .find(|c| c.name == "Travel identity")
        .expect("identity present");
    let data: serde_json::Value = serde_json::from_str(&id.data_json).unwrap();
    assert_eq!(data["firstName"], "Alice");
    assert_eq!(data["postalCode"], "94000");
    // The fixture omits middleName, ssn, passportNumber etc — they
    // must NOT appear in the projected data with empty strings.
    assert!(data.get("middleName").is_none());
    assert!(data.get("ssn").is_none());
    assert!(data.get("passportNumber").is_none());
}

#[test]
fn fixture_custom_fields_are_appended_to_notes() {
    let exp = parse_export(FIXTURE).expect("fixture parses");
    let p = project(&exp);
    let item = p
        .ciphers
        .iter()
        .find(|c| c.name == "Custom-fields example")
        .expect("custom-fields item present");
    let n = item.notes.as_deref().unwrap();
    assert!(n.starts_with("primary note body"));
    assert!(n.contains("recovery-code: abcd-efgh"));
    assert!(n.contains("backup-email: alt@example.com"));
}

#[test]
fn fixture_secure_note_keeps_body_in_notes_not_data() {
    let exp = parse_export(FIXTURE).expect("fixture parses");
    let p = project(&exp);
    let n = p
        .ciphers
        .iter()
        .find(|c| c.name == "Wifi password")
        .expect("note present");
    assert_eq!(n.cipher_type, 2);
    assert_eq!(n.data_json, "{}");
    assert!(n.notes.as_deref().unwrap().contains("tacocat"));
}
