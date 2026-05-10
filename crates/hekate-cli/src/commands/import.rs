//! `hekate import bitwarden <file>` — M2.27.
//!
//! Reads an unencrypted Bitwarden JSON export, projects it onto hekate's
//! plaintext cipher model via `hekate_core::import_bitwarden`, then drives
//! the same encrypt-and-create flow that `hekate add login/note/card/identity`
//! uses. Folders are created first; their server-allocated ids are
//! threaded onto the ciphers that reference them.
//!
//! After every successful row the CLI re-signs and uploads the BW04
//! per-user vault manifest so the new cipher rows are committed under
//! the user's signing key (other devices verify on next /sync).

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::{Args as ClapArgs, Subcommand};
use hekate_core::{
    encstring::EncString,
    import_1password,
    import_bitwarden::{self, ImportedCipher, ProjectedImport},
    import_keepass, import_lastpass,
};

use crate::prompt;
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    api::CipherInput,
    commands::{persist_refreshed_tokens, unlock_session},
    crypto::{aad_cipher_data, aad_cipher_name, aad_cipher_notes, encrypt_field, new_cipher_key},
};

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[command(subcommand)]
    pub source: Source,
}

#[derive(Debug, Subcommand)]
pub enum Source {
    /// Import an unencrypted Bitwarden JSON export. Re-export from the
    /// Bitwarden web vault under Tools → Export Vault → "JSON
    /// (unencrypted)".
    Bitwarden(FormatArgs),
    /// Import a 1Password 1PUX export. From 1Password 8: File →
    /// Export → choose accounts → "1Password Unencrypted Export
    /// (.1pux)". The format is a ZIP — pass the .1pux path directly.
    #[command(name = "1password")]
    OnePassword(FormatArgs),
    /// Import a KeePass KDBX 3.1 / 4 database. Prompts for the
    /// database master password — that's separate from hekate's master
    /// password and is consumed once (not cached).
    KeePass(FormatArgs),
    /// Import a LastPass CSV export (`Account → Advanced → Export →
    /// LastPass CSV File`). Plain-text CSV — no extra prompt
    /// required. LastPass typed notes (credit cards, identities)
    /// are skipped in the first cut with a per-row warning so users
    /// can re-enter manually.
    LastPass(FormatArgs),
}

#[derive(Debug, ClapArgs)]
pub struct FormatArgs {
    /// Path to the export file (Bitwarden: .json; 1Password: .1pux).
    pub file: PathBuf,
    /// Parse + project + print a summary, but make no server writes.
    #[arg(long)]
    pub dry_run: bool,
    /// Drop folder structure on import; every cipher lands at the root.
    #[arg(long)]
    pub skip_folders: bool,
}

pub fn run(args: Args) -> Result<()> {
    match args.source {
        Source::Bitwarden(a) => run_format(a, parse_bitwarden, "Bitwarden"),
        Source::OnePassword(a) => run_format(a, parse_1password, "1Password"),
        Source::KeePass(a) => run_format(a, parse_keepass, "KeePass"),
        Source::LastPass(a) => run_format(a, parse_lastpass, "LastPass"),
    }
}

fn parse_bitwarden(file: &std::path::Path) -> Result<ProjectedImport> {
    let raw = std::fs::read_to_string(file).with_context(|| format!("read {}", file.display()))?;
    let export =
        import_bitwarden::parse_export(&raw).map_err(|e| anyhow!("parse Bitwarden export: {e}"))?;
    Ok(import_bitwarden::project(&export))
}

fn parse_1password(file: &std::path::Path) -> Result<ProjectedImport> {
    let bytes = std::fs::read(file).with_context(|| format!("read {}", file.display()))?;
    import_1password::project_from_zip(&bytes).map_err(|e| anyhow!("parse 1Password 1PUX: {e}"))
}

fn parse_lastpass(file: &std::path::Path) -> Result<ProjectedImport> {
    let raw = std::fs::read_to_string(file).with_context(|| format!("read {}", file.display()))?;
    import_lastpass::parse_csv(&raw).map_err(|e| anyhow!("parse LastPass CSV: {e}"))
}

fn parse_keepass(file: &std::path::Path) -> Result<ProjectedImport> {
    let bytes = std::fs::read(file).with_context(|| format!("read {}", file.display()))?;
    // The KDBX master password is collected here (not from
    // unlock_session) — it's separate from hekate's master password
    // and only needed once to decrypt the file. Wrong password
    // surfaces as the parser's "kdbx open failed" error.
    let pw = prompt::password("KeePass database password: ")?;
    let projected = import_keepass::project_from_kdbx(&bytes, &pw)
        .map_err(|e| anyhow!("parse KeePass KDBX: {e}"))?;
    // Drop the password promptly; nothing else needs it.
    drop(pw);
    Ok(projected)
}

/// Shared orchestration for any single-file format. The parser
/// returns a `ProjectedImport` whose `bitwarden_folder_id` is
/// **format-agnostic**: for Bitwarden it's the export's `id` field;
/// for 1Password it's the vault name (no separate id concept).
/// The format-specific parser is responsible for picking a stable
/// key per item and writing it into `bitwarden_folder_id`.
fn run_format(
    args: FormatArgs,
    parse: fn(&std::path::Path) -> Result<ProjectedImport>,
    label: &str,
) -> Result<()> {
    // Parse + project happens before we touch the server, so a bad
    // file fails fast without generating partial state.
    let projected = parse(&args.file)?;

    print_summary(&projected, label);

    if args.dry_run {
        eprintln!("(dry-run; no writes were made)");
        return Ok(());
    }
    if projected.ciphers.is_empty() && projected.folders.is_empty() {
        eprintln!("nothing to import");
        return Ok(());
    }

    let (state, api, unlocked) = unlock_session()?;

    // 1. Materialize folders. Each name → freshly created server-side
    //    folder id. Same name twice → first wins (rare in real exports).
    //    The map key is whatever the format used for its
    //    `bitwarden_folder_id` field — for 1Password that's the vault
    //    name, for Bitwarden it's the opaque id.
    let mut export_folder_to_hekate: HashMap<String, String> = HashMap::new();
    if !args.skip_folders {
        for name in &projected.folders {
            let aad = folder_name_aad();
            let name_enc =
                EncString::encrypt_xc20p("ak:1", &unlocked.account_key, name.as_bytes(), &aad)
                    .map_err(|e| anyhow!("encrypt folder name: {e}"))?
                    .to_wire();
            let new_id = api
                .create_folder(&name_enc)
                .with_context(|| format!("create folder {:?}", name))?;
            // For the Bitwarden parser, `bitwarden_folder_id` on a
            // cipher is an opaque export id that maps via
            // `BitwardenExport.folders[id->name]`. For the 1Password
            // parser we simplified to "name == folder id" — same key
            // appears verbatim on each cipher's
            // `bitwarden_folder_id`. To support both with one
            // orchestration we ALSO map by name as a fallback below.
            export_folder_to_hekate.insert(name.clone(), new_id);
            eprintln!("✓ folder: {}", name);
        }
    }

    // 2. Materialize ciphers. Each one gets a fresh UUIDv7, a fresh
    //    PCK, and AAD-bound encryption of name/notes/data — same
    //    pattern as `hekate add`.
    let total = projected.ciphers.len();
    let mut succeeded = 0usize;
    let mut failed: Vec<(String, String)> = Vec::new();

    for (i, c) in projected.ciphers.iter().enumerate() {
        let progress = format!("[{}/{}]", i + 1, total);
        match import_one(
            &api,
            &unlocked,
            c,
            &export_folder_to_hekate,
            args.skip_folders,
        ) {
            Ok(()) => {
                succeeded += 1;
                eprintln!("{progress} ✓ {} ({})", c.name, type_name(c.cipher_type));
            }
            Err(e) => {
                eprintln!("{progress} ✗ {}: {e}", c.name);
                failed.push((c.name.clone(), e.to_string()));
            }
        }
    }

    // 3. Re-sign the BW04 manifest once at the end (rather than per-row).
    //    The personal-vault manifest covers ciphers we just created.
    if succeeded > 0 {
        if let Err(e) = crate::manifest::sync_and_upload(&api, &unlocked) {
            eprintln!("warning: signed manifest upload failed: {e}");
        }
    }

    persist_refreshed_tokens(&api, state)?;

    println!();
    println!("Imported {succeeded}/{total} ciphers.");
    if !failed.is_empty() {
        println!("{} failed:", failed.len());
        for (name, err) in &failed {
            println!("  - {name}: {err}");
        }
    }
    if !projected.warnings.is_empty() {
        println!("{} skipped during projection:", projected.warnings.len());
        for w in &projected.warnings {
            println!("  - {w}");
        }
    }
    Ok(())
}

fn import_one(
    api: &crate::api::Api,
    unlocked: &crate::crypto::Unlocked,
    c: &ImportedCipher,
    folder_name_to_hekate: &HashMap<String, String>,
    skip_folders: bool,
) -> Result<()> {
    let cipher_id = Uuid::now_v7().to_string();
    let (cipher_key, protected_cipher_key) = new_cipher_key(unlocked, &cipher_id)?;

    let aad_n = aad_cipher_name(&cipher_id, c.cipher_type);
    let aad_o = aad_cipher_notes(&cipher_id, c.cipher_type);
    let aad_d = aad_cipher_data(&cipher_id, c.cipher_type);

    // Both Bitwarden and 1Password parsers now write the resolved
    // folder *name* into `bitwarden_folder_id` (despite the field's
    // historical name).
    let folder_id = if skip_folders {
        None
    } else {
        c.bitwarden_folder_id
            .as_deref()
            .and_then(|name| folder_name_to_hekate.get(name).cloned())
    };

    let body = CipherInput {
        id: cipher_id,
        cipher_type: c.cipher_type,
        folder_id,
        protected_cipher_key,
        name: encrypt_field(&cipher_key, c.name.as_bytes(), &aad_n)?,
        notes: c
            .notes
            .as_deref()
            .map(|n| encrypt_field(&cipher_key, n.as_bytes(), &aad_o))
            .transpose()?,
        data: encrypt_field(&cipher_key, c.data_json.as_bytes(), &aad_d)?,
        favorite: c.favorite,
        // Personal vault only in M2.27 — org-scoped imports are a
        // future milestone.
        org_id: None,
        collection_ids: vec![],
    };
    api.create_cipher(&body)
        .map(|_| ())
        .context("create_cipher")
}

fn print_summary(p: &ProjectedImport, label: &str) {
    let by_type = {
        let mut counts = [0usize; 5]; // index 1..=4
        for c in &p.ciphers {
            if (1..=4).contains(&c.cipher_type) {
                counts[c.cipher_type as usize] += 1;
            }
        }
        counts
    };
    eprintln!("{label} export:");
    eprintln!("  folders:    {}", p.folders.len());
    eprintln!("  ciphers:    {}", p.ciphers.len());
    eprintln!("    logins:   {}", by_type[1]);
    eprintln!("    notes:    {}", by_type[2]);
    eprintln!("    cards:    {}", by_type[3]);
    eprintln!("    identities: {}", by_type[4]);
    if !p.warnings.is_empty() {
        eprintln!("  skipped:    {} (see end of output)", p.warnings.len());
    }
}

/// AAD for the encrypted folder name. Stable across the whole
/// project — folders don't have type/id binding the way ciphers do.
/// (A later milestone could bind the folder_id but the server
/// generates that AFTER the encryption, so we'd need a two-phase
/// create. Skipped today; the existing add-folder code path uses no
/// AAD either.)
fn folder_name_aad() -> Vec<u8> {
    b"pmgr-folder-name-v1".to_vec()
}

fn type_name(t: i32) -> &'static str {
    match t {
        1 => "login",
        2 => "secure_note",
        3 => "card",
        4 => "identity",
        _ => "cipher",
    }
}
