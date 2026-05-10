//! `hekate peer {fetch,pins,fingerprint,verify,unpin}` — TOFU public-key
//! pinning for other accounts.
//!
//! M2.19 ships a server-side directory of self-signed pubkey bundles.
//! M2.20 closes the loop: every time the CLI fetches a peer's bundle it
//! verifies the self-sig and *pins* the bundle locally. Subsequent
//! fetches must match the pin byte-for-byte; mismatch is a load-bearing
//! error (server attempted substitution OR the peer legitimately
//! rotated keys — the user is the only one who can disambiguate, by
//! re-confirming the new fingerprint out of band).
//!
//! No sharing endpoint consumes pins yet — when M4 lands, every wrap
//! call site is required to fetch via `fetch_and_pin` so the
//! signcryption envelope's recipient pubkey is one we've authenticated
//! out-of-band rather than trusted from the server.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

use crate::{
    api::PubkeyBundle,
    state::{self, PeerPin},
};

#[derive(Debug, Parser)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Debug, Subcommand)]
pub enum Action {
    /// Fetch a peer's pubkey bundle, verify the self-signature, and
    /// pin it locally. First fetch records the pin (TOFU); subsequent
    /// fetches require an exact match.
    Fetch {
        /// Peer user UUID.
        user_id: String,
    },
    /// List locally-pinned peers with their fingerprints.
    Pins,
    /// Print MY OWN pubkey-bundle fingerprint, so a peer can pin me.
    Fingerprint,
    /// Compare a fingerprint a peer read aloud (or sent over Signal,
    /// etc.) against the locally-pinned value. Exits 0 on match, 1
    /// on mismatch, 2 if the peer isn't pinned yet.
    Verify {
        user_id: String,
        /// Expected fingerprint, e.g. `SHA256:M4GW…BPJewI`.
        fingerprint: String,
    },
    /// Drop a pin. Required before a legitimate peer-key rotation can
    /// be re-pinned. Pre-alpha: requires `--yes` so the security-
    /// relevant action isn't a typo.
    Unpin {
        user_id: String,
        #[arg(long)]
        yes: bool,
    },
}

pub fn run(args: Args) -> Result<()> {
    match args.action {
        Action::Fetch { user_id } => cmd_fetch(&user_id),
        Action::Pins => cmd_pins(),
        Action::Fingerprint => cmd_fingerprint(),
        Action::Verify {
            user_id,
            fingerprint,
        } => cmd_verify(&user_id, &fingerprint),
        Action::Unpin { user_id, yes } => cmd_unpin(&user_id, yes),
    }
}

// ---------------- subcommands ---------------------------------------------

fn cmd_fetch(user_id: &str) -> Result<()> {
    let mut st = state::load()?
        .ok_or_else(|| anyhow!("not logged in. Run `hekate login` or `hekate register` first."))?;
    let api = crate::api::Api::new(&st.server_url)?;

    let bundle = api
        .get_pubkeys(user_id)
        .with_context(|| format!("fetching pubkeys for {user_id}"))?;
    let pin = bundle_to_pin(&bundle)?;

    match st.peer_pins.get(user_id) {
        Some(existing) if pin_content_matches(existing, &pin) => {
            println!("✓ pin matches existing entry for {user_id}");
            println!("  fingerprint: {}", pin.fingerprint);
            println!("  first seen: {}", existing.first_seen_at);
        }
        Some(existing) => {
            return Err(anyhow!(
                "PIN MISMATCH for {user_id} — refusing to update.\n\
                 First seen: {}  fingerprint {}\n\
                 Server now claims:           fingerprint {}\n\
                 Either the server is attempting substitution, or the peer \
                 legitimately rotated keys (e.g. master-password change). \
                 Verify out of band, then `hekate peer unpin {user_id} --yes` \
                 followed by `hekate peer fetch {user_id}`.",
                existing.first_seen_at,
                existing.fingerprint,
                pin.fingerprint,
            ));
        }
        None => {
            println!("✓ pinned new peer {user_id}");
            println!("  fingerprint: {}", pin.fingerprint);
            println!(
                "  Verify this with the peer out-of-band before using it for \
                 any sharing operation."
            );
            st.peer_pins.insert(user_id.to_string(), pin);
            state::save(&st)?;
        }
    }
    Ok(())
}

fn cmd_pins() -> Result<()> {
    let st = state::load()?
        .ok_or_else(|| anyhow!("not logged in. Run `hekate login` or `hekate register` first."))?;
    if st.peer_pins.is_empty() {
        println!("(no pinned peers)");
        return Ok(());
    }
    println!("{:<40}  {:<55}  pinned at", "USER", "FINGERPRINT");
    for (id, pin) in &st.peer_pins {
        println!("{:<40}  {:<55}  {}", id, pin.fingerprint, pin.first_seen_at,);
    }
    Ok(())
}

fn cmd_fingerprint() -> Result<()> {
    // Compute MY OWN fingerprint from the local state. We could also go
    // round-trip via /api/v1/users/{my_id}/pubkeys, but that involves
    // trusting the server about ourselves — pointless. The bundle bytes
    // are deterministic from (user_id, signing_pk, x25519_pk).
    let st = state::load()?
        .ok_or_else(|| anyhow!("not logged in. Run `hekate login` or `hekate register` first."))?;
    if st.user.user_id.is_empty() {
        return Err(anyhow!(
            "local state has no user_id — log out and log back in to pick it up \
             from the M2.20 token-response field."
        ));
    }
    let signing_pk = decode_pubkey(&st.user.account_signing_pubkey_b64, "signing")?;
    let x25519_pk = decode_pubkey(&st.user.account_public_key_b64, "x25519")?;
    let canonical = hekate_core::signcrypt::pubkey_bundle_canonical_bytes(
        &st.user.user_id,
        &signing_pk,
        &x25519_pk,
    );
    let fp = fingerprint_from_canonical(&canonical);
    println!("user_id:     {}", st.user.user_id);
    println!("fingerprint: {fp}");
    println!();
    println!("Read the fingerprint aloud (or send via Signal / etc.) so peers");
    println!(
        "can `hekate peer verify {} <fingerprint>` after pinning you.",
        st.user.user_id
    );
    Ok(())
}

fn cmd_verify(user_id: &str, expected_fingerprint: &str) -> Result<()> {
    let st = state::load()?
        .ok_or_else(|| anyhow!("not logged in. Run `hekate login` or `hekate register` first."))?;
    match st.peer_pins.get(user_id) {
        None => {
            // Distinct exit code so scripts can branch.
            eprintln!("no pin for {user_id} yet. Run `hekate peer fetch {user_id}` first.");
            std::process::exit(2);
        }
        Some(pin) if pin.fingerprint == expected_fingerprint => {
            println!("✓ MATCH — pinned fingerprint for {user_id} equals expected.");
            Ok(())
        }
        Some(pin) => {
            eprintln!("✗ MISMATCH for {user_id}");
            eprintln!("  pinned:   {}", pin.fingerprint);
            eprintln!("  expected: {expected_fingerprint}");
            std::process::exit(1);
        }
    }
}

fn cmd_unpin(user_id: &str, yes: bool) -> Result<()> {
    if !yes {
        return Err(anyhow!(
            "unpinning is a security-relevant action. Pass --yes to confirm."
        ));
    }
    let mut st = state::load()?
        .ok_or_else(|| anyhow!("not logged in. Run `hekate login` or `hekate register` first."))?;
    if st.peer_pins.remove(user_id).is_none() {
        return Err(anyhow!("no pin for {user_id}"));
    }
    state::save(&st)?;
    println!("✓ removed pin for {user_id}");
    Ok(())
}

// ---------------- helpers --------------------------------------------------

fn bundle_to_pin(bundle: &PubkeyBundle) -> Result<PeerPin> {
    let signing_pk = decode_pubkey(&bundle.account_signing_pubkey, "signing")?;
    let x25519_pk = decode_pubkey(&bundle.account_public_key, "x25519")?;
    let sig_bytes = STANDARD_NO_PAD
        .decode(&bundle.account_pubkey_bundle_sig)
        .context("account_pubkey_bundle_sig is not base64-no-pad")?;
    if sig_bytes.len() != 64 {
        return Err(anyhow!("bundle signature has wrong length"));
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);

    // Verify the self-signature BEFORE pinning — a server-fabricated
    // bundle without a valid sig would otherwise pollute the pin store
    // with garbage. Combined with TOFU-then-out-of-band verification,
    // this gives the trust path documented in threat-model-gaps.md.
    hekate_core::signcrypt::verify_pubkey_bundle(&bundle.user_id, &signing_pk, &x25519_pk, &sig)
        .map_err(|_| {
            anyhow!(
                "bundle signature did not verify against (user_id, signing_pk, x25519_pk) \
             for {} — server may be attempting substitution",
                bundle.user_id,
            )
        })?;

    let canonical = hekate_core::signcrypt::pubkey_bundle_canonical_bytes(
        &bundle.user_id,
        &signing_pk,
        &x25519_pk,
    );
    let fingerprint = fingerprint_from_canonical(&canonical);

    Ok(PeerPin {
        user_id: bundle.user_id.clone(),
        account_signing_pubkey_b64: bundle.account_signing_pubkey.clone(),
        account_public_key_b64: bundle.account_public_key.clone(),
        account_pubkey_bundle_sig_b64: bundle.account_pubkey_bundle_sig.clone(),
        fingerprint,
        first_seen_at: chrono::Utc::now().to_rfc3339(),
    })
}

fn decode_pubkey(b64: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD_NO_PAD
        .decode(b64)
        .with_context(|| format!("{label} pubkey is not base64-no-pad"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("{label} pubkey has wrong length"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Two pins describe the same peer identity if their signed bundle bytes
/// match. The `first_seen_at` timestamp is metadata about THIS pin
/// record, not the identity itself, so comparing on `==` (which
/// includes it) would falsely flag every re-fetch as a mismatch.
fn pin_content_matches(a: &PeerPin, b: &PeerPin) -> bool {
    a.user_id == b.user_id
        && a.account_signing_pubkey_b64 == b.account_signing_pubkey_b64
        && a.account_public_key_b64 == b.account_public_key_b64
        && a.account_pubkey_bundle_sig_b64 == b.account_pubkey_bundle_sig_b64
        && a.fingerprint == b.fingerprint
}

fn fingerprint_from_canonical(canonical: &[u8]) -> String {
    let digest = Sha256::digest(canonical);
    format!("SHA256:{}", STANDARD_NO_PAD.encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two different bundles → two different fingerprints, deterministic.
    #[test]
    fn fingerprint_is_deterministic_and_distinguishes_bundles() {
        use hekate_core::signcrypt::pubkey_bundle_canonical_bytes;
        let a = pubkey_bundle_canonical_bytes("alice", &[0x11; 32], &[0x22; 32]);
        let b = pubkey_bundle_canonical_bytes("alice", &[0x33; 32], &[0x22; 32]);
        let fa1 = fingerprint_from_canonical(&a);
        let fa2 = fingerprint_from_canonical(&a);
        let fb = fingerprint_from_canonical(&b);
        assert_eq!(fa1, fa2, "deterministic");
        assert_ne!(fa1, fb, "different bundle → different fp");
        assert!(fa1.starts_with("SHA256:"));
    }

    /// `bundle_to_pin` rejects a bundle with a forged signature.
    #[test]
    fn bundle_to_pin_rejects_invalid_signature() {
        use ed25519_dalek::SigningKey;
        use hekate_core::signcrypt::sign_pubkey_bundle;

        let sk = SigningKey::from_bytes(&[0xa5u8; 32]);
        let signing_pk = sk.verifying_key().to_bytes();
        let x25519_pk = [0x11u8; 32];
        let user_id = "0192e0a0-0000-7000-8000-aaaaaaaaaaaa";
        let mut sig = sign_pubkey_bundle(&sk, user_id, &signing_pk, &x25519_pk);
        sig[0] ^= 0x01;

        let bundle = PubkeyBundle {
            user_id: user_id.into(),
            account_signing_pubkey: STANDARD_NO_PAD.encode(signing_pk),
            account_public_key: STANDARD_NO_PAD.encode(x25519_pk),
            account_pubkey_bundle_sig: STANDARD_NO_PAD.encode(sig),
        };
        let err = bundle_to_pin(&bundle).unwrap_err();
        assert!(
            format!("{err}").contains("did not verify"),
            "expected verify-failure message, got: {err}"
        );
    }

    /// `bundle_to_pin` accepts and round-trips a valid self-signed bundle.
    #[test]
    fn bundle_to_pin_accepts_valid_bundle() {
        use ed25519_dalek::SigningKey;
        use hekate_core::signcrypt::sign_pubkey_bundle;

        let sk = SigningKey::from_bytes(&[0xa5u8; 32]);
        let signing_pk = sk.verifying_key().to_bytes();
        let x25519_pk = [0x11u8; 32];
        let user_id = "0192e0a0-0000-7000-8000-aaaaaaaaaaaa";
        let sig = sign_pubkey_bundle(&sk, user_id, &signing_pk, &x25519_pk);

        let bundle = PubkeyBundle {
            user_id: user_id.into(),
            account_signing_pubkey: STANDARD_NO_PAD.encode(signing_pk),
            account_public_key: STANDARD_NO_PAD.encode(x25519_pk),
            account_pubkey_bundle_sig: STANDARD_NO_PAD.encode(sig),
        };
        let pin = bundle_to_pin(&bundle).expect("valid bundle must pin");
        assert_eq!(pin.user_id, user_id);
        assert!(pin.fingerprint.starts_with("SHA256:"));
        assert_eq!(
            pin.account_signing_pubkey_b64,
            bundle.account_signing_pubkey
        );
    }

    /// Re-fetching the same peer must NOT register as a pin mismatch
    /// just because we stamped a fresh `first_seen_at`. Regression
    /// guard for a bug found in the M2.20 smoke.
    #[test]
    fn pin_content_matches_ignores_first_seen_timestamp() {
        let a = PeerPin {
            user_id: "alice".into(),
            account_signing_pubkey_b64: "sk".into(),
            account_public_key_b64: "xk".into(),
            account_pubkey_bundle_sig_b64: "sig".into(),
            fingerprint: "SHA256:abc".into(),
            first_seen_at: "2026-05-02T12:00:00Z".into(),
        };
        let b = PeerPin {
            first_seen_at: "2026-06-01T00:00:00Z".into(), // different timestamp
            ..a.clone()
        };
        assert!(pin_content_matches(&a, &b));

        // Whereas a real key rotation MUST be flagged as a mismatch.
        let c = PeerPin {
            account_public_key_b64: "different-x25519".into(),
            fingerprint: "SHA256:xyz".into(),
            ..a.clone()
        };
        assert!(!pin_content_matches(&a, &c));
    }

    /// Two bundles for the same user with different x25519 pubkeys
    /// produce different fingerprints — fundamental to the
    /// substitution-detection guarantee.
    #[test]
    fn x25519_swap_produces_different_fingerprint() {
        use hekate_core::signcrypt::pubkey_bundle_canonical_bytes;
        let canonical_a = pubkey_bundle_canonical_bytes("alice", &[0x11; 32], &[0x22; 32]);
        let canonical_b = pubkey_bundle_canonical_bytes(
            "alice",
            &[0x11; 32],
            &[0x33; 32], // attacker-controlled X25519
        );
        let fa = fingerprint_from_canonical(&canonical_a);
        let fb = fingerprint_from_canonical(&canonical_b);
        assert_ne!(fa, fb);
    }
}
