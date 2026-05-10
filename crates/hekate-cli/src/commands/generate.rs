//! `hekate generate` — cryptographically random password or passphrase.

use anyhow::{anyhow, Result};
use clap::Parser;
use rand::{rngs::OsRng, seq::SliceRandom, RngCore};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?/";

/// EFF long wordlist (CC BY 3.0, https://www.eff.org/dice). 7776 words,
/// matched to 5-die rolls so each word carries log2(7776) ≈ 12.925 bits
/// of entropy. Embedded at build time so `hekate generate --passphrase`
/// works fully offline. Source: <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>.
const EFF_LONG_WORDLIST: &str = include_str!("../data/eff_long.txt");

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

pub fn run(args: Args) -> Result<()> {
    enforce_generator_policy(&args)?;
    let pw = if args.passphrase {
        passphrase(args.words, &args.separator, args.capitalize)?
    } else {
        char_password(&args)?
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
fn enforce_generator_policy(args: &Args) -> Result<()> {
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
    // no_ambiguous is a soft preference today; the generator doesn't
    // expose an explicit toggle. Honor it by treating a true policy
    // value as a no-op for now (future: filter ambiguous chars from
    // the pool). Surfacing the gap rather than silently noncompliant:
    if rules.no_ambiguous {
        eprintln!(
            "note: password_generator_rules.no_ambiguous is set but the \
             generator does not yet filter ambiguous characters."
        );
    }
    Ok(())
}

fn char_password(args: &Args) -> Result<String> {
    if args.length == 0 {
        return Err(anyhow!("--length must be > 0"));
    }
    let mut classes: Vec<&str> = Vec::new();
    if !args.no_lowercase {
        classes.push(LOWER);
    }
    if !args.no_uppercase {
        classes.push(UPPER);
    }
    if !args.no_numbers {
        classes.push(NUMBERS);
    }
    if !args.no_symbols {
        classes.push(SYMBOLS);
    }
    if classes.is_empty() {
        return Err(anyhow!("at least one character class must be enabled"));
    }
    if args.length < classes.len() {
        return Err(anyhow!(
            "--length must be at least {} so each enabled class can appear at least once",
            classes.len()
        ));
    }

    let mut rng = OsRng;
    let mut buf: Vec<char> = classes
        .iter()
        .map(|c| pick_one(&mut rng, c))
        .collect::<Result<Vec<_>>>()?;
    let pool: String = classes.concat();
    let pool_chars: Vec<char> = pool.chars().collect();
    while buf.len() < args.length {
        buf.push(pool_chars[random_below(&mut rng, pool_chars.len() as u32) as usize]);
    }
    buf.shuffle(&mut rng);
    Ok(buf.into_iter().collect())
}

fn passphrase(words_n: usize, separator: &str, capitalize: bool) -> Result<String> {
    if words_n == 0 {
        return Err(anyhow!("--words must be > 0"));
    }
    let words: Vec<&str> = EFF_LONG_WORDLIST
        .lines()
        .filter(|l| !l.is_empty())
        .collect();
    if words.len() != 7776 {
        return Err(anyhow!(
            "embedded EFF wordlist has wrong size: {} (expected 7776)",
            words.len()
        ));
    }
    let mut rng = OsRng;
    let mut out: Vec<String> = Vec::with_capacity(words_n);
    for _ in 0..words_n {
        let idx = random_below(&mut rng, words.len() as u32) as usize;
        let w = words[idx];
        out.push(if capitalize {
            capitalize_first(w)
        } else {
            w.to_string()
        });
    }
    Ok(out.join(separator))
}

fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn pick_one(rng: &mut OsRng, s: &str) -> Result<char> {
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return Err(anyhow!("character class is empty"));
    }
    Ok(chars[random_below(rng, chars.len() as u32) as usize])
}

/// Unbiased random integer in `[0, n)` via rejection sampling. `rand`'s
/// `gen_range` is biased on small ranges; this matches the popup's
/// approach in `popup.js` for cross-client consistency.
fn random_below(rng: &mut OsRng, n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    let limit = (u32::MAX / n) * n;
    loop {
        let mut buf = [0u8; 4];
        rng.fill_bytes(&mut buf);
        let v = u32::from_le_bytes(buf);
        if v < limit {
            return v % n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_wordlist_has_exactly_7776_words() {
        let words: Vec<&str> = EFF_LONG_WORDLIST
            .lines()
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(words.len(), 7776);
        for w in &words {
            assert!(!w.is_empty(), "no empty words allowed");
            // Lowercase letters with hyphens (EFF list contains 4 hyphenated
            // entries: drop-down, felt-tip, t-shirt, yo-yo). No whitespace
            // would break the join-by-separator assumption.
            for c in w.chars() {
                assert!(
                    c.is_ascii_lowercase() || c == '-',
                    "unexpected char {c:?} in word {w:?}"
                );
            }
        }
    }

    #[test]
    fn passphrase_yields_n_words_joined_by_separator() {
        // Use a multi-char separator so the hyphenated EFF entries can't
        // accidentally split the wrong way.
        let p = passphrase(5, "::", false).unwrap();
        let parts: Vec<&str> = p.split("::").collect();
        assert_eq!(parts.len(), 5);
        for w in parts {
            assert!(!w.is_empty());
        }
    }

    #[test]
    fn passphrase_capitalize_uppercases_each_word() {
        let p = passphrase(3, "::", true).unwrap();
        for w in p.split("::") {
            let first = w.chars().next().unwrap();
            assert!(first.is_ascii_uppercase(), "word {w:?} not capitalized");
            // Remaining chars are lowercase letters or hyphens (yo-yo, etc.)
            for c in w.chars().skip(1) {
                assert!(
                    c.is_ascii_lowercase() || c == '-',
                    "unexpected char {c:?} in word {w:?}"
                );
            }
        }
    }

    #[test]
    fn passphrase_rejects_zero_words() {
        assert!(passphrase(0, "-", false).is_err());
    }

    #[test]
    fn passphrase_separator_passes_through() {
        let p = passphrase(2, "::SEP::", false).unwrap();
        assert!(p.contains("::SEP::"));
    }

    #[test]
    fn random_below_is_within_range() {
        let mut rng = OsRng;
        for _ in 0..1000 {
            let v = random_below(&mut rng, 7776);
            assert!(v < 7776);
        }
    }
}
