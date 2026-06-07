//! Cryptographically random password & passphrase generation.
//!
//! Single source of truth for every client: the web vault and the browser
//! extension reach this through the wasm bindings (`generatePassword` /
//! `generatePassphrase`), and `hekate generate` calls it directly — replacing
//! three drifting hand-rolled copies (two JS, one in the CLI) with one tested
//! implementation.
//!
//! Randomness is CSPRNG-only (`OsRng` / getrandom). Character and word
//! selection use rejection sampling so there is no modulo bias — `rand`'s
//! `gen_range` is biased on small ranges, so we avoid it. See
//! `docs/secure-coding.md`.

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?/";

/// Characters that are easy to confuse when transcribing a password by eye:
/// uppercase O / digit 0, uppercase I / lowercase l / digit 1. Filtered out of
/// every class when [`PasswordOptions::avoid_ambiguous`] is set. Matches the
/// conventional "avoid ambiguous" set used by other password managers.
const AMBIGUOUS: &[char] = &['O', '0', 'I', 'l', '1'];

/// EFF long wordlist (CC BY 3.0, <https://www.eff.org/dice>). 7776 words,
/// matched to 5-die rolls so each word carries log2(7776) ≈ 12.925 bits of
/// entropy. Embedded at build time so passphrase generation works fully
/// offline (and inside the wasm clients).
/// Source: <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>.
const EFF_LONG_WORDLIST: &str = include_str!("data/eff_long.txt");

/// Options for a character-class password.
///
/// At least one class must be enabled, and `length` must be at least the number
/// of enabled classes so each can be guaranteed at least once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PasswordOptions {
    /// Total number of characters to generate.
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub numbers: bool,
    pub symbols: bool,
    /// Drop visually ambiguous characters (`O 0 I l 1`) from every class.
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    /// The historical default the clients used: a 20-character password with
    /// all four classes and ambiguous characters allowed.
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            numbers: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

/// Options for an EFF-wordlist passphrase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PassphraseOptions {
    /// Number of words. 5 words ≈ 64.6 bits of entropy on the EFF long list.
    pub words: usize,
    /// String inserted between words (e.g. `-`).
    pub separator: String,
    /// Capitalize the first letter of each word.
    pub capitalize: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 5,
            separator: "-".to_string(),
            capitalize: false,
        }
    }
}

/// Generate a character-class password from the given options.
pub fn password(opts: &PasswordOptions) -> Result<String> {
    if opts.length == 0 {
        return Err(Error::InvalidArgument("length must be > 0".into()));
    }

    let filter = |s: &str| -> Vec<char> {
        s.chars()
            .filter(|c| !opts.avoid_ambiguous || !AMBIGUOUS.contains(c))
            .collect()
    };

    let mut classes: Vec<Vec<char>> = Vec::new();
    if opts.lowercase {
        classes.push(filter(LOWER));
    }
    if opts.uppercase {
        classes.push(filter(UPPER));
    }
    if opts.numbers {
        classes.push(filter(NUMBERS));
    }
    if opts.symbols {
        classes.push(filter(SYMBOLS));
    }
    if classes.is_empty() {
        return Err(Error::InvalidArgument(
            "at least one character class must be enabled".into(),
        ));
    }
    // A class can only be emptied by avoid_ambiguous removing every member;
    // none of the four classes shrink to empty for the current ambiguous set,
    // but guard anyway so a future set change can't panic on `pick`.
    if let Some(empty) = classes.iter().find(|c| c.is_empty()) {
        debug_assert!(empty.is_empty());
        return Err(Error::InvalidArgument(
            "a character class is empty after removing ambiguous characters".into(),
        ));
    }
    if opts.length < classes.len() {
        return Err(Error::InvalidArgument(format!(
            "length must be at least {} so each enabled class can appear at least once",
            classes.len()
        )));
    }

    let mut rng = OsRng;
    // Guarantee one character from each enabled class first...
    let mut buf: Vec<char> = classes.iter().map(|c| pick(&mut rng, c)).collect();
    // ...then fill the rest uniformly from the combined pool.
    let pool: Vec<char> = classes.iter().flatten().copied().collect();
    while buf.len() < opts.length {
        buf.push(pick(&mut rng, &pool));
    }
    // Fisher-Yates so the guaranteed positions aren't predictable.
    shuffle(&mut rng, &mut buf);
    Ok(buf.into_iter().collect())
}

/// Generate a passphrase from the EFF long wordlist.
pub fn passphrase(opts: &PassphraseOptions) -> Result<String> {
    if opts.words == 0 {
        return Err(Error::InvalidArgument("words must be > 0".into()));
    }
    let words = wordlist()?;
    let mut rng = OsRng;
    let mut out: Vec<String> = Vec::with_capacity(opts.words);
    for _ in 0..opts.words {
        let w = words[random_below(&mut rng, words.len() as u32) as usize];
        out.push(if opts.capitalize {
            capitalize_first(w)
        } else {
            w.to_string()
        });
    }
    Ok(out.join(&opts.separator))
}

/// The embedded EFF long wordlist as a validated slice of 7776 words.
fn wordlist() -> Result<Vec<&'static str>> {
    let words: Vec<&str> = EFF_LONG_WORDLIST
        .lines()
        .filter(|l| !l.is_empty())
        .collect();
    if words.len() != 7776 {
        return Err(Error::InvalidArgument(format!(
            "embedded EFF wordlist has wrong size: {} (expected 7776)",
            words.len()
        )));
    }
    Ok(words)
}

fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Pick a uniformly-random character from a non-empty slice.
fn pick(rng: &mut OsRng, chars: &[char]) -> char {
    chars[random_below(rng, chars.len() as u32) as usize]
}

/// In-place Fisher-Yates shuffle using the unbiased `random_below`.
fn shuffle<T>(rng: &mut OsRng, items: &mut [T]) {
    for i in (1..items.len()).rev() {
        let j = random_below(rng, (i + 1) as u32) as usize;
        items.swap(i, j);
    }
}

/// Unbiased random integer in `[0, n)` via rejection sampling. `rand`'s
/// `gen_range` is biased on small ranges; rejection sampling matches the JS
/// clients' historical approach for cross-client consistency.
fn random_below(rng: &mut OsRng, n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    let limit = (u32::MAX / n) * n;
    loop {
        let mut b = [0u8; 4];
        rng.fill_bytes(&mut b);
        let v = u32::from_le_bytes(b);
        if v < limit {
            return v % n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(opts: PasswordOptions) -> String {
        password(&opts).unwrap()
    }

    #[test]
    fn default_password_is_20_chars_all_classes() {
        let p = pw(PasswordOptions::default());
        assert_eq!(p.chars().count(), 20);
        assert!(p.chars().any(|c| LOWER.contains(c)));
        assert!(p.chars().any(|c| UPPER.contains(c)));
        assert!(p.chars().any(|c| NUMBERS.contains(c)));
        assert!(p.chars().any(|c| SYMBOLS.contains(c)));
    }

    #[test]
    fn honors_length() {
        for len in [4usize, 8, 32, 128] {
            let p = pw(PasswordOptions {
                length: len,
                ..Default::default()
            });
            assert_eq!(p.chars().count(), len);
        }
    }

    #[test]
    fn single_class_uses_only_that_class() {
        let p = pw(PasswordOptions {
            length: 30,
            lowercase: false,
            uppercase: false,
            numbers: true,
            symbols: false,
            avoid_ambiguous: false,
        });
        assert!(p.chars().all(|c| NUMBERS.contains(c)), "got {p:?}");
    }

    #[test]
    fn avoid_ambiguous_excludes_ambiguous_chars() {
        // Large length + many draws to make an accidental pass unlikely.
        let p = pw(PasswordOptions {
            length: 128,
            avoid_ambiguous: true,
            ..Default::default()
        });
        for c in p.chars() {
            assert!(!AMBIGUOUS.contains(&c), "ambiguous char {c:?} leaked");
        }
    }

    #[test]
    fn no_class_enabled_is_error() {
        let r = password(&PasswordOptions {
            length: 10,
            lowercase: false,
            uppercase: false,
            numbers: false,
            symbols: false,
            avoid_ambiguous: false,
        });
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
    }

    #[test]
    fn length_below_class_count_is_error() {
        // Four classes enabled but length 3 can't seat one of each.
        let r = password(&PasswordOptions {
            length: 3,
            ..Default::default()
        });
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
    }

    #[test]
    fn zero_length_is_error() {
        let r = password(&PasswordOptions {
            length: 0,
            ..Default::default()
        });
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
    }

    #[test]
    fn embedded_wordlist_has_exactly_7776_words() {
        let words = wordlist().unwrap();
        assert_eq!(words.len(), 7776);
        for w in &words {
            assert!(!w.is_empty(), "no empty words allowed");
            // Lowercase letters with hyphens (the EFF list has 4 hyphenated
            // entries: drop-down, felt-tip, t-shirt, yo-yo). No whitespace,
            // which would break the join-by-separator contract.
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
        // Multi-char separator so the hyphenated EFF entries can't split wrong.
        let p = passphrase(&PassphraseOptions {
            words: 5,
            separator: "::".into(),
            capitalize: false,
        })
        .unwrap();
        let parts: Vec<&str> = p.split("::").collect();
        assert_eq!(parts.len(), 5);
        assert!(parts.iter().all(|w| !w.is_empty()));
    }

    #[test]
    fn passphrase_capitalize_uppercases_each_word() {
        let p = passphrase(&PassphraseOptions {
            words: 3,
            separator: "::".into(),
            capitalize: true,
        })
        .unwrap();
        for w in p.split("::") {
            let first = w.chars().next().unwrap();
            assert!(first.is_ascii_uppercase(), "word {w:?} not capitalized");
            for c in w.chars().skip(1) {
                assert!(
                    c.is_ascii_lowercase() || c == '-',
                    "unexpected char {c:?} in word {w:?}"
                );
            }
        }
    }

    #[test]
    fn passphrase_separator_passes_through() {
        let p = passphrase(&PassphraseOptions {
            words: 2,
            separator: "::SEP::".into(),
            capitalize: false,
        })
        .unwrap();
        assert!(p.contains("::SEP::"));
    }

    #[test]
    fn passphrase_rejects_zero_words() {
        assert!(passphrase(&PassphraseOptions {
            words: 0,
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn random_below_is_within_range() {
        let mut rng = OsRng;
        for _ in 0..1000 {
            assert!(random_below(&mut rng, 7776) < 7776);
        }
    }
}
