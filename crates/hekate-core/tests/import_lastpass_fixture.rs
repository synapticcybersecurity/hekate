//! M2.27c — fixture-based smoke for the LastPass CSV parser.
//!
//! Loads `tests/fixtures/lastpass_export.csv` (a real-shape LP
//! export with one of each row variant) and asserts on every
//! projection branch. The unit tests in
//! `hekate_core::import_lastpass::tests` cover the lower-level edge
//! cases inline; this is the human-readable, externally reviewable
//! sample.

use hekate_core::import_lastpass::parse_csv;

const FIXTURE: &str = include_str!("fixtures/lastpass_export.csv");

#[test]
fn fixture_projects_to_expected_counts() {
    let p = parse_csv(FIXTURE).expect("fixture parses");
    // 5 rows: GitHub, Slack, Wifi, Visa (typed-note → skipped), Reminder.
    // 4 imported, 1 warning.
    assert_eq!(p.ciphers.len(), 4);
    assert!(p
        .warnings
        .iter()
        .any(|w| w.contains("Visa (skipped)") && w.contains("Credit Card")));
}

#[test]
fn fixture_login_round_trips_uri_username_password_totp() {
    let p = parse_csv(FIXTURE).unwrap();
    let github = p.ciphers.iter().find(|c| c.name == "GitHub").unwrap();
    assert_eq!(github.cipher_type, 1);
    assert!(github.favorite);
    assert_eq!(github.bitwarden_folder_id.as_deref(), Some("Dev"));
    let data: serde_json::Value = serde_json::from_str(&github.data_json).unwrap();
    assert_eq!(data["username"], "alice@example.com");
    assert_eq!(data["password"], "hunter2");
    assert_eq!(data["uri"], "https://github.com");
    assert!(data["totp"].as_str().unwrap().starts_with("otpauth://"));
    assert_eq!(github.notes.as_deref(), Some("primary dev account"));
}

#[test]
fn fixture_secure_note_keeps_multi_line_body() {
    let p = parse_csv(FIXTURE).unwrap();
    let n = p
        .ciphers
        .iter()
        .find(|c| c.name == "Wifi password")
        .unwrap();
    assert_eq!(n.cipher_type, 2);
    assert_eq!(n.data_json, "{}");
    let body = n.notes.as_deref().unwrap();
    assert!(body.contains("tacocat"));
    assert!(body.contains("muffin"));
}

#[test]
fn fixture_typed_note_is_skipped() {
    let p = parse_csv(FIXTURE).unwrap();
    assert!(!p.ciphers.iter().any(|c| c.name == "Visa (skipped)"));
}

#[test]
fn fixture_groupings_become_leaf_folders() {
    let p = parse_csv(FIXTURE).unwrap();
    let github = p.ciphers.iter().find(|c| c.name == "GitHub").unwrap();
    assert_eq!(github.bitwarden_folder_id.as_deref(), Some("Dev"));
    let slack = p.ciphers.iter().find(|c| c.name == "Slack").unwrap();
    assert_eq!(slack.bitwarden_folder_id.as_deref(), Some("Work"));
    // Reminder has no grouping → no folder.
    let r = p.ciphers.iter().find(|c| c.name == "Reminder").unwrap();
    assert!(r.bitwarden_folder_id.is_none());
}

#[test]
fn fixture_short_secure_note_imports_with_body_only() {
    let p = parse_csv(FIXTURE).unwrap();
    let r = p.ciphers.iter().find(|c| c.name == "Reminder").unwrap();
    assert_eq!(r.cipher_type, 2);
    assert_eq!(r.notes.as_deref(), Some("quick reminder body"));
}
