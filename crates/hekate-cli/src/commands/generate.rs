//! `hekate generate` — cryptographically random password or passphrase.
//!
//! The generation logic (CSPRNG, options, the embedded EFF wordlist) lives in
//! `hekate_core::generate` — the single source of truth shared with the web
//! vault and browser extension (which reach it through wasm). This command is a
//! thin wrapper: argument parsing + the M4.6 `password_generator_rules` policy
//! enforcement that only applies to the CLI.

use anyhow::{anyhow, Result};
use clap::Parser;
use hekate_core::generate::{
    passphrase as core_passphrase, password as core_password, PassphraseOptions, PasswordOptions,
};

#[derive(Debug, Parser)]
pub struct Args {
    /// Generate a passphrase of N space/separator-joined words instead
    /// of a character-class password. Length defaults change to "words"
    /// when this is set: see `--words` and `--separator`.
    #[arg(long)]
    pub passphrase: bool,

    // ---- character-class password options ---------------------------
    /// Number of characters (character mode only). Ignored under
    /// `--passphrase`; use `--words` instead.
    #[arg(short, long, default_value_t = 20)]
    pub length: usize,
    #[arg(long)]
    pub no_lowercase: bool,
    #[arg(long)]
    pub no_uppercase: bool,
    #[arg(long)]
    pub no_numbers: bool,
    #[arg(long)]
    pub no_symbols: bool,
    /// Exclude visually ambiguous characters (`O 0 I l 1`) from the pool.
    #[arg(long)]
    pub avoid_ambiguous: bool,

    // ---- passphrase options -----------------------------------------
    /// Number of words (passphrase mode only). 5 words ≈ 64.6 bits of
    /// entropy on the EFF long list — comfortably above the 60-bit
    /// floor for an attacker doing offline cracking against an
    /// Argon2id-hashed master password.
    #[arg(long, default_value_t = 5)]
    pub words: usize,
    /// Separator between words. Default `-`.
    #[arg(long, default_value = "-")]
    pub separator: String,
    /// Capitalize the first letter of each word.
    #[arg(long)]
    pub capitalize: bool,

    /// Suppress the trailing newline (handy for piping into clipboard).
    #[arg(long)]
    pub no_newline: bool,
}

pub fn run(mut args: Args) -> Result<()> {
    enforce_generator_policy(&mut args)?;
    let pw = if args.passphrase {
        core_passphrase(&PassphraseOptions {
            words: args.words,
            separator: args.separator.clone(),
            capitalize: args.capitalize,
        })?
    } else {
        core_password(&PasswordOptions {
            length: args.length,
            lowercase: !args.no_lowercase,
            uppercase: !args.no_uppercase,
            numbers: !args.no_numbers,
            symbols: !args.no_symbols,
            avoid_ambiguous: args.avoid_ambiguous,
        })?
    };
    if args.no_newline {
        print!("{pw}");
    } else {
        println!("{pw}");
    }
    Ok(())
}

/// M4.6 password_generator_rules — reject CLI flags that violate the
/// active org policy. Best-effort: if the user is offline or not
/// logged in, we skip enforcement rather than block generation
/// entirely (the policy is delivered server-side, so we can't check
/// against it without /sync; future generations will catch up once
/// /sync is reachable).
fn enforce_generator_policy(args: &mut Args) -> Result<()> {
    use crate::api::Api;

    let st = match crate::state::load()? {
        Some(s) => s,
        None => return Ok(()), // not logged in — no policy to enforce
    };
    let api = Api::new(&st.server_url)?
        .with_bearer(st.tokens.access_token.clone())
        .with_refresh(st.tokens.refresh_token.clone());
    let agg = match crate::policies::fetch_aggregate(&api)? {
        Some(a) => a,
        None => return Ok(()), // sync failed (offline) — fail open
    };
    let rules = &agg.generator;

    // min_length applies to the character mode only; in passphrase
    // mode the min_length is in characters of the assembled string,
    // so map across both modes.
    if args.passphrase {
        // Approximate: min ~4-char words + (n-1) separators must clear
        // min_length. Apply the same min_length floor against the
        // shortest plausible passphrase so a too-strict policy still
        // blocks generating a 1-word passphrase.
        if rules.min_length > 0 {
            let approx_min = (4u64 * args.words as u64)
                .saturating_add(args.separator.len() as u64 * args.words.saturating_sub(1) as u64);
            if approx_min < rules.min_length {
                return Err(anyhow!(
                    "passphrase with {} words may be shorter than the {}-character \
                     minimum from password_generator_rules; raise --words.",
                    args.words,
                    rules.min_length
                ));
            }
        }
        // character_classes / no_ambiguous don't apply to passphrase
        // mode — the EFF list is lowercase letters + four hyphens.
        return Ok(());
    }

    if rules.min_length > 0 && (args.length as u64) < rules.min_length {
        return Err(anyhow!(
            "--length {} below the {}-character minimum from \
             password_generator_rules.",
            args.length,
            rules.min_length
        ));
    }
    for class in &rules.character_classes {
        let (flag_off, flag_name) = match class.as_str() {
            "lower" => (args.no_lowercase, "--no-lowercase"),
            "upper" => (args.no_uppercase, "--no-uppercase"),
            "digit" => (args.no_numbers, "--no-numbers"),
            "symbol" => (args.no_symbols, "--no-symbols"),
            other => {
                // Unknown class in the policy — refuse to silently
                // generate without it, since "I asked for X but a
                // newer server expected Y" is exactly the failure
                // mode this enforcement is supposed to surface.
                return Err(anyhow!(
                    "policy requires unknown character class {other:?}; \
                     upgrade `hekate` to the version that defines it"
                ));
            }
        };
        if flag_off {
            return Err(anyhow!(
                "{flag_name} disabled but password_generator_rules \
                 requires {} characters",
                class
            ));
        }
    }
    // no_ambiguous is now enforced for real: force the avoid-ambiguous
    // toggle on so the generated pool drops `O 0 I l 1` regardless of
    // whether the user passed `--avoid-ambiguous`.
    if rules.no_ambiguous {
        args.avoid_ambiguous = true;
    }
    Ok(())
}
