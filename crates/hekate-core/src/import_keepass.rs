//! M2.27b — KeePass KDBX import (pure parser).
//!
//! KDBX is a binary, password-encrypted format. We delegate the
//! decryption + XML parsing to the `keepass` crate and walk its
//! `Database` tree to project entries onto hekate's plaintext cipher
//! model. KDBX 3.1 + 4 are both supported by the underlying crate.
//!
//! ## Type mapping
//!
//! KeePass entries are free-form key-value bags rather than
//! template-typed records. We don't try to reverse-engineer credit
//! cards / identities from custom strings — that's almost never
//! how real KDBX vaults are structured. Instead:
//!
//! - **Default**: every entry is a login (`cipher_type = 1`) with the
//!   standard `Title` / `UserName` / `Password` / `URL` / `Notes`
//!   strings mapped onto the matching slots. TOTP, when present in
//!   the `otp` field (KeePassXC's KDBX storage location for OTP
//!   URLs), goes into the login's `data.totp` slot.
//! - **Heuristic for secure_note** (`cipher_type = 2`): no
//!   UserName + no Password + no URL + Notes is non-empty → the
//!   entry is treated as a free-text note. Title still becomes the
//!   cipher's display name.
//!
//! ## Group hierarchy
//!
//! KeePass supports nested groups. hekate's folder model is flat. We
//! use the **leaf group name** as the folder name. Entries in the
//! root group (no leaf-group parent) get no folder. This loses some
//! structure on deep hierarchies; users who care can re-organize
//! after import. A full-path-as-folder option could land later.
//!
//! ## What we drop
//!
//! - Binary attachments — KDBX entries can carry attached files; the
//!   first cut doesn't import them. (Wiring through M2.24's tus
//!   attachment flow is a follow-up.)
//! - Per-entry tags + custom fields — appended to notes as
//!   `name: value` lines so the data isn't lost.
//! - Entries in the recycle bin (KeePass marks the recycle bin group
//!   as such; the `keepass` crate exposes the flag) — skipped with a
//!   warning.

use keepass::{
    db::{Entry, Group, Node},
    Database, DatabaseKey,
};

use crate::{Error, Result};

// Re-use the BW import's output types so the CLI can share orchestration.
pub use crate::import_bitwarden::{ImportedCipher, ProjectedImport};

/// Decrypt + project a KDBX database. The master password is
/// consumed once and never persisted.
pub fn project_from_kdbx(bytes: &[u8], password: &str) -> Result<ProjectedImport> {
    let key = DatabaseKey::new().with_password(password);
    let db = Database::parse(bytes, key)
        .map_err(|e| Error::InvalidEncoding(format!("kdbx open failed: {e}")))?;
    Ok(project(&db))
}

/// Test-only path: project a pre-decrypted Database. Useful when the
/// test suite builds + saves a KDBX programmatically and then
/// roundtrips through `Database::parse`, OR wants to project
/// directly without going through encryption.
pub fn project(db: &Database) -> ProjectedImport {
    let mut folders: Vec<String> = Vec::new();
    let mut ciphers: Vec<ImportedCipher> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    walk_group(
        &db.root,
        /* parent_group_name */ None,
        /* depth */ 0,
        &mut folders,
        &mut ciphers,
        &mut warnings,
    );

    // Dedupe folder names — KeePass allows duplicate group names at
    // different depths; the CLI orchestration creates one server-side
    // folder per name regardless.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    folders.retain(|f| seen.insert(f.clone()));

    ProjectedImport {
        folders,
        ciphers,
        warnings,
    }
}

fn walk_group(
    group: &Group,
    parent_name: Option<&str>,
    depth: usize,
    folders: &mut Vec<String>,
    ciphers: &mut Vec<ImportedCipher>,
    warnings: &mut Vec<String>,
) {
    // Skip recycle-bin contents. KeePass conventionally names the bin
    // "Recycle Bin"; the keepass crate doesn't surface the
    // `RecycleBinUUID` cleanly enough to trust, so we go by name.
    if depth > 0 && group.get_name().eq_ignore_ascii_case("recycle bin") {
        warnings.push(format!(
            "skipping {} entries from {:?}",
            group.entries().len(),
            group.get_name()
        ));
        return;
    }

    // The leaf group name becomes the folder. Root group is
    // "treated as no folder" — leaves under root inherit no folder
    // unless you nest at least one level deep.
    let folder_name: Option<String> = if depth == 0 {
        None
    } else {
        let name = group.get_name().trim().to_string();
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    };
    if let Some(name) = &folder_name {
        if !folders.contains(name) {
            folders.push(name.clone());
        }
    }

    for child in &group.children {
        match child {
            Node::Entry(entry) => match project_entry(entry, folder_name.as_deref()) {
                Ok(c) => ciphers.push(c),
                Err(reason) => warnings.push(format!(
                    "skipping {:?}: {reason}",
                    entry.get_title().unwrap_or("<no title>")
                )),
            },
            Node::Group(g) => walk_group(
                g,
                Some(group.get_name()),
                depth + 1,
                folders,
                ciphers,
                warnings,
            ),
        }
    }
    let _ = parent_name; // reserved for future full-path folder mode
}

fn project_entry(
    entry: &Entry,
    folder_name: Option<&str>,
) -> std::result::Result<ImportedCipher, String> {
    let title = entry
        .get_title()
        .map(str::to_string)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "<untitled>".into());
    let username = entry
        .get_username()
        .map(str::to_string)
        .filter(|s| !s.is_empty());
    let password = entry
        .get_password()
        .map(str::to_string)
        .filter(|s| !s.is_empty());
    let url = entry
        .get_url()
        .map(str::to_string)
        .filter(|s| !s.is_empty());
    let notes_raw = entry
        .get("Notes")
        .map(str::to_string)
        .filter(|s| !s.is_empty());

    // KeePassXC stores OTP URLs in the "otp" field (lowercase) — the
    // canonical storage location is well-defined enough across
    // KeePass clients that we can pull it directly.
    let otp = entry
        .get("otp")
        .map(str::to_string)
        .filter(|s| !s.is_empty());

    // Custom fields = anything outside the canonical Title /
    // UserName / Password / URL / Notes / otp. Append them to notes
    // so the data survives the import.
    let mut custom_lines: Vec<String> = Vec::new();
    let canonical: &[&str] = &["Title", "UserName", "Password", "URL", "Notes", "otp"];
    for key in entry.fields.keys() {
        if canonical.contains(&key.as_str()) {
            continue;
        }
        // Use the public `.get()` accessor (string view) to avoid
        // depending on the Value enum's variant shape.
        if let Some(v) = entry.get(key) {
            if !v.is_empty() {
                custom_lines.push(format!("{key}: {v}"));
            }
        }
    }
    custom_lines.sort(); // stable output regardless of HashMap order

    // Tags get appended as `tags: a, b, c` so they survive too.
    let tags_line = if entry.tags.is_empty() {
        None
    } else {
        Some(format!("tags: {}", entry.tags.join(", ")))
    };

    let merged_notes = merge_notes(notes_raw, &custom_lines, tags_line);

    // Heuristic: pure secure_note has no login fields and a non-empty
    // notes body. Otherwise treat as login (even if it has only a
    // password — many people store random tokens this way).
    let has_login_data = username.is_some() || password.is_some() || url.is_some() || otp.is_some();
    let cipher_type = if !has_login_data && merged_notes.is_some() {
        2
    } else {
        1
    };

    let data_json = if cipher_type == 1 {
        let mut data = serde_json::Map::new();
        if let Some(v) = username {
            data.insert("username".into(), serde_json::Value::String(v));
        }
        if let Some(v) = password {
            data.insert("password".into(), serde_json::Value::String(v));
        }
        if let Some(v) = url {
            data.insert("uri".into(), serde_json::Value::String(v));
        }
        if let Some(v) = otp {
            data.insert("totp".into(), serde_json::Value::String(v));
        }
        serde_json::Value::Object(data).to_string()
    } else {
        "{}".into()
    };

    Ok(ImportedCipher {
        cipher_type,
        name: title,
        notes: merged_notes,
        data_json,
        favorite: false, // KeePass doesn't have a favorite flag
        bitwarden_folder_id: folder_name.map(str::to_string),
    })
}

fn merge_notes(
    primary: Option<String>,
    custom_lines: &[String],
    tags_line: Option<String>,
) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(p) = primary {
        parts.push(p);
    }
    if !custom_lines.is_empty() {
        parts.push(custom_lines.join("\n"));
    }
    if let Some(t) = tags_line {
        parts.push(t);
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n\n"))
    }
}

// =====================================================================
// Tests — build a KDBX in-memory, parse it, project it.
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::{Entry, Group, Value};

    /// Build a `Database` from scratch, attach a few entries + groups,
    /// save it as KDBX, and return the bytes. Exercise the full
    /// parse-from-bytes path so any KDBX writer/reader regression
    /// surfaces here.
    fn build_kdbx() -> (Vec<u8>, &'static str) {
        let password = "test-password";

        let mut db = Database::new(Default::default());
        db.root = Group::new("Root");

        // Entry 1: typical login with TOTP.
        let mut e1 = Entry::new();
        e1.fields
            .insert("Title".into(), Value::Unprotected("GitHub".into()));
        e1.fields.insert(
            "UserName".into(),
            Value::Unprotected("alice@example.com".into()),
        );
        e1.fields.insert(
            "Password".into(),
            Value::Protected("hunter2".as_bytes().into()),
        );
        e1.fields.insert(
            "URL".into(),
            Value::Unprotected("https://github.com".into()),
        );
        e1.fields.insert(
            "Notes".into(),
            Value::Unprotected("primary dev account".into()),
        );
        e1.fields.insert(
            "otp".into(),
            Value::Unprotected(
                "otpauth://totp/GH:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub".into(),
            ),
        );

        // Entry 2: secure_note (no login fields, only notes).
        let mut e2 = Entry::new();
        e2.fields
            .insert("Title".into(), Value::Unprotected("Wifi password".into()));
        e2.fields.insert(
            "Notes".into(),
            Value::Unprotected("home: tacocat\nguest: muffin".into()),
        );

        // Entry 3: login with a custom field + tag.
        let mut e3 = Entry::new();
        e3.fields
            .insert("Title".into(), Value::Unprotected("Slack".into()));
        e3.fields
            .insert("UserName".into(), Value::Unprotected("alice@acme".into()));
        e3.fields.insert(
            "Password".into(),
            Value::Protected("slacking".as_bytes().into()),
        );
        e3.fields.insert(
            "Recovery Code".into(),
            Value::Unprotected("abcd-efgh".into()),
        );
        e3.tags = vec!["work".into(), "team".into()];

        // Two leaf groups so we exercise folder threading.
        let mut personal = Group::new("Personal");
        personal.add_child(e1);
        personal.add_child(e2);

        let mut work = Group::new("Work");
        work.add_child(e3);

        db.root.add_child(personal);
        db.root.add_child(work);

        let mut buf: Vec<u8> = Vec::new();
        db.save(&mut buf, DatabaseKey::new().with_password(password))
            .expect("save kdbx");
        (buf, password)
    }

    #[test]
    fn open_then_project_round_trips() {
        let (bytes, pw) = build_kdbx();
        let p = project_from_kdbx(&bytes, pw).expect("decrypt + project");
        // Two leaf folders, three ciphers (e1, e2, e3).
        assert_eq!(p.folders, vec!["Personal", "Work"]);
        assert_eq!(p.ciphers.len(), 3);
        assert!(p.warnings.is_empty());
    }

    #[test]
    fn login_entry_data_round_trips() {
        let (bytes, pw) = build_kdbx();
        let p = project_from_kdbx(&bytes, pw).unwrap();
        let github = p.ciphers.iter().find(|c| c.name == "GitHub").unwrap();
        assert_eq!(github.cipher_type, 1);
        assert_eq!(github.bitwarden_folder_id.as_deref(), Some("Personal"));
        let data: serde_json::Value = serde_json::from_str(&github.data_json).unwrap();
        assert_eq!(data["username"], "alice@example.com");
        assert_eq!(data["password"], "hunter2");
        assert_eq!(data["uri"], "https://github.com");
        assert!(data["totp"].as_str().unwrap().starts_with("otpauth://"));
        assert_eq!(github.notes.as_deref(), Some("primary dev account"));
    }

    #[test]
    fn secure_note_heuristic_triggers_when_no_login_fields() {
        let (bytes, pw) = build_kdbx();
        let p = project_from_kdbx(&bytes, pw).unwrap();
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
    fn custom_fields_and_tags_get_appended_to_notes() {
        let (bytes, pw) = build_kdbx();
        let p = project_from_kdbx(&bytes, pw).unwrap();
        let slack = p.ciphers.iter().find(|c| c.name == "Slack").unwrap();
        let n = slack.notes.as_deref().unwrap_or("");
        assert!(n.contains("Recovery Code: abcd-efgh"));
        assert!(n.contains("tags: work, team"));
    }

    #[test]
    fn wrong_password_returns_error() {
        let (bytes, _pw) = build_kdbx();
        let err = project_from_kdbx(&bytes, "wrong-password").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("kdbx open failed"));
    }

    #[test]
    fn entry_in_root_has_no_folder() {
        // Build a tiny DB with one entry directly under root.
        let pw = "p";
        let mut db = Database::new(Default::default());
        db.root = Group::new("Root");
        let mut e = Entry::new();
        e.fields
            .insert("Title".into(), Value::Unprotected("Top-level".into()));
        e.fields
            .insert("Password".into(), Value::Protected(b"x"[..].into()));
        db.root.add_child(e);
        let mut buf = Vec::new();
        db.save(&mut buf, DatabaseKey::new().with_password(pw))
            .unwrap();

        let p = project_from_kdbx(&buf, pw).unwrap();
        assert_eq!(p.ciphers.len(), 1);
        assert!(p.ciphers[0].bitwarden_folder_id.is_none());
        assert!(p.folders.is_empty());
    }

    #[test]
    fn nested_groups_use_leaf_group_as_folder() {
        let pw = "p";
        let mut db = Database::new(Default::default());
        db.root = Group::new("Root");

        let mut leaf = Group::new("Email");
        let mut e = Entry::new();
        e.fields
            .insert("Title".into(), Value::Unprotected("Gmail".into()));
        e.fields
            .insert("UserName".into(), Value::Unprotected("u@gmail.com".into()));
        leaf.add_child(e);

        let mut middle = Group::new("Personal");
        middle.add_child(leaf);

        db.root.add_child(middle);

        let mut buf = Vec::new();
        db.save(&mut buf, DatabaseKey::new().with_password(pw))
            .unwrap();

        let p = project_from_kdbx(&buf, pw).unwrap();
        let gmail = p.ciphers.iter().find(|c| c.name == "Gmail").unwrap();
        // Leaf group is "Email", not "Personal".
        assert_eq!(gmail.bitwarden_folder_id.as_deref(), Some("Email"));
        assert!(p.folders.contains(&"Email".to_string()));
        // We DO emit "Personal" as a folder too (it's depth=1, contains
        // no entries directly but that's still legitimate). Both
        // folders get materialized server-side.
        assert!(p.folders.contains(&"Personal".to_string()));
    }

    #[test]
    fn recycle_bin_contents_are_skipped() {
        let pw = "p";
        let mut db = Database::new(Default::default());
        db.root = Group::new("Root");

        let mut bin = Group::new("Recycle Bin");
        let mut e = Entry::new();
        e.fields
            .insert("Title".into(), Value::Unprotected("Trashed".into()));
        e.fields
            .insert("Password".into(), Value::Protected(b"x"[..].into()));
        bin.add_child(e);

        db.root.add_child(bin);

        let mut buf = Vec::new();
        db.save(&mut buf, DatabaseKey::new().with_password(pw))
            .unwrap();

        let p = project_from_kdbx(&buf, pw).unwrap();
        assert!(p.ciphers.is_empty());
        assert!(p.warnings.iter().any(|w| w.contains("Recycle Bin")));
    }
}
