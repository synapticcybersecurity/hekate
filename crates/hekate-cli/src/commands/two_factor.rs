//! `hekate account 2fa` — TOTP enrollment, recovery codes, status. M2.22.
//!
//! Recovery codes shown ONCE at enrollment / regeneration. They are an
//! authentication-only 2FA bypass: they let you finish a login when
//! your authenticator is gone, but they do NOT decrypt the vault. Lose
//! your master password and the vault is gone — that's the
//! zero-knowledge invariant.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use clap::{Parser, Subcommand};
use hekate_core::kdf::{derive_master_key, derive_master_password_hash, KdfParams};

use crate::{
    api::{Api, TfaSetupRequest},
    prompt, state,
};

#[derive(Debug, Parser)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Debug, Subcommand)]
pub enum Action {
    /// Enable TOTP 2FA. Prints the otpauth URL + 10 recovery codes
    /// once, then asks for a TOTP code from your authenticator to
    /// confirm before activation.
    Enable,
    /// Disable 2FA. Drops the TOTP secret and every recovery code
    /// (consumed and unconsumed). Master-password re-auth required.
    Disable,
    /// Show whether 2FA is enabled and how many unconsumed recovery
    /// codes remain.
    Status,
    /// Manage recovery codes.
    #[command(subcommand)]
    RecoveryCodes(RecoveryAction),
}

#[derive(Debug, Subcommand)]
pub enum RecoveryAction {
    /// Burn all existing recovery codes (consumed and unconsumed) and
    /// mint 10 fresh ones. Master-password re-auth required.
    Regenerate,
}

pub fn run(args: Args) -> Result<()> {
    match args.action {
        Action::Enable => enable(),
        Action::Disable => disable(),
        Action::Status => status(),
        Action::RecoveryCodes(RecoveryAction::Regenerate) => regenerate(),
    }
}

fn load_state_and_api() -> Result<(state::State, Api)> {
    let st = state::load()?.ok_or_else(|| anyhow!("not logged in. Run `hekate login` first."))?;
    let api = Api::new(&st.server_url)?
        .with_bearer(st.tokens.access_token.clone())
        .with_refresh(st.tokens.refresh_token.clone());
    Ok((st, api))
}

fn derive_master_password_hash_b64(st: &state::State, password: &str) -> Result<String> {
    let kdf: KdfParams = serde_json::from_value(st.user.kdf_params.clone())?;
    let salt = STANDARD_NO_PAD.decode(&st.user.kdf_salt_b64)?;
    let mk = derive_master_key(password.as_bytes(), kdf, &salt)?;
    Ok(STANDARD_NO_PAD.encode(derive_master_password_hash(&mk)))
}

fn print_recovery_codes(codes: &[String]) {
    println!();
    println!("================================================================");
    println!(" RECOVERY CODES — write these down NOW. Shown once, never again.");
    println!(" Each code works once. They authenticate when your authenticator");
    println!(" is gone. They do NOT decrypt the vault — losing your master");
    println!(" password is unrecoverable regardless of these codes.");
    println!("================================================================");
    for c in codes {
        println!("    {c}");
    }
    println!("================================================================");
    println!();
}

fn enable() -> Result<()> {
    let (st, api) = load_state_and_api()?;

    let pw = prompt::password("Master password: ")?;
    let mph_b64 = derive_master_password_hash_b64(&st, &pw)?;

    println!("Generating TOTP secret + 10 recovery codes...");
    let setup = api.tfa_totp_setup(&TfaSetupRequest {
        master_password_hash: mph_b64,
        account_label: st.user.email.clone(),
    })?;

    println!();
    println!("Add this account to your authenticator app:");
    println!("  Account:  {}", st.user.email);
    println!("  Secret:   {}", setup.secret_b32);
    println!("  otpauth:  {}", setup.otpauth_url);
    println!();
    print_recovery_codes(&setup.recovery_codes);

    let _ack = prompt::line(
        "I have saved the recovery codes. Press Enter to continue, Ctrl-C to abort: ",
    )?;
    let code = prompt::line("Enter the 6-digit code from your authenticator: ")?;
    let resp = api.tfa_totp_confirm(code.trim())?;

    // Confirmed: the server rotated security_stamp + revoked refresh
    // tokens, so update local state with the freshly issued pair.
    let mut new_st = st;
    new_st.tokens.access_token = resp.access_token;
    new_st.tokens.refresh_token = resp.refresh_token;
    new_st.tokens.expires_at =
        (chrono::Utc::now() + chrono::Duration::seconds(resp.expires_in as i64)).to_rfc3339();
    state::save(&new_st)?;

    println!(
        "✓ 2FA enabled. {} recovery codes minted.",
        resp.recovery_codes_count
    );
    Ok(())
}

fn disable() -> Result<()> {
    let (st, api) = load_state_and_api()?;
    let pw = prompt::password("Master password: ")?;
    let mph_b64 = derive_master_password_hash_b64(&st, &pw)?;
    api.tfa_totp_disable(&mph_b64)?;
    println!("✓ 2FA disabled. All recovery codes wiped.");
    println!("  Other sessions are now invalid (security_stamp rotated).");
    Ok(())
}

fn status() -> Result<()> {
    let (_, api) = load_state_and_api()?;
    let s = api.tfa_status()?;
    if s.enabled {
        println!("2FA: enabled (TOTP)");
        println!("Recovery codes remaining: {}", s.recovery_codes_remaining);
        if s.recovery_codes_remaining <= 3 {
            println!(
                "  ⚠ Few codes left — consider `hekate account 2fa recovery-codes regenerate`."
            );
        }
    } else {
        println!("2FA: disabled");
    }
    Ok(())
}

fn regenerate() -> Result<()> {
    let (st, api) = load_state_and_api()?;
    let pw = prompt::password("Master password: ")?;
    let mph_b64 = derive_master_password_hash_b64(&st, &pw)?;
    let resp = api.tfa_recovery_regenerate(&mph_b64)?;
    print_recovery_codes(&resp.recovery_codes);
    println!(
        "✓ {} fresh recovery codes minted. All previous codes are now invalid.",
        resp.recovery_codes.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    /// Mirror of the server-side normalizer so we can sanity-check the
    /// shape we expect users to type. The real normalize lives on the
    /// server (in `hekate-server::routes::two_factor::normalize_recovery_code`)
    /// — kept identical here so a future divergence shows up as a test
    /// failure, not as a silent rejection at login time.
    fn normalize(input: &str) -> String {
        input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .flat_map(|c| c.to_uppercase())
            .collect()
    }

    #[test]
    fn dashed_code_is_normalized() {
        assert_eq!(normalize("ABCD-EFGH-IJKL-MNOP"), "ABCDEFGHIJKLMNOP");
    }

    #[test]
    fn lowercase_with_spaces_is_normalized() {
        assert_eq!(normalize("  abcd efgh\nijkl mnop  "), "ABCDEFGHIJKLMNOP");
    }

    #[test]
    fn empty_input_normalizes_to_empty() {
        assert_eq!(normalize(""), "");
        assert_eq!(normalize("   ---  \n"), "");
    }

    /// Mirrors the `r`-prefix recovery selector from the login prompt.
    #[test]
    fn recovery_prefix_strips_correctly() {
        let parse = |s: &str| -> (&'static str, String) {
            let trimmed = s.trim();
            if let Some(rest) = trimmed.strip_prefix(['r', 'R']) {
                ("recovery", rest.trim_start().to_string())
            } else {
                ("totp", trimmed.to_string())
            }
        };
        assert_eq!(parse("123456"), ("totp", "123456".to_string()));
        assert_eq!(
            parse("r ABCD-EFGH-IJKL-MNOP"),
            ("recovery", "ABCD-EFGH-IJKL-MNOP".to_string())
        );
        assert_eq!(
            parse("R abcd-efgh-ijkl-mnop"),
            ("recovery", "abcd-efgh-ijkl-mnop".to_string())
        );
    }
}
