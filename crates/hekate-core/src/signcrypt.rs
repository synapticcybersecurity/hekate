//! Signcryption envelope — authenticated public-key encryption.
//!
//! Closes the BW09 / LP07 / DL02 substitution attack from Scarlata et al.
//! (USENIX Security 2026) at the cryptographic layer: every shared-key
//! wrap *commits to the sender's identity* via an Ed25519 signature, so
//! a malicious server can't substitute its own ciphertext for one the
//! sender claimed to produce.
//!
//! This is purely the primitive — wire format, sign, verify. The server
//! endpoints that authenticate public keys (auditable directory or
//! TOFU pinning) and the M4/M6 sharing call sites that *use* this
//! envelope come later. Building the crypto first means we can't
//! accidentally ship a sharing endpoint that wraps under raw
//! `x25519_sealed_box` without the sender's signature.
//!
//! ## Construction
//!
//! Given:
//!   * sender's Ed25519 signing key `sk_S` (private)
//!   * recipient's X25519 public key `pk_R`
//!   * sender + recipient user-ids (utf8 strings — bound into the AAD
//!     so a server can't redirect a wrap to a different recipient)
//!   * plaintext to seal
//!
//! Produce:
//!
//! ```text
//! 1. Generate ephemeral X25519 keypair (esk, epk).
//! 2. shared = X25519(esk, pk_R)                      (32B Diffie-Hellman)
//! 3. content_key = HKDF-SHA256(shared,
//!                              info = HKDF_INFO,
//!                              salt = epk || pk_R)   (32B AEAD key)
//! 4. canonical_header = DST
//!                     || u32_le(sender_id.len) || sender_id
//!                     || u32_le(recipient_id.len) || recipient_id
//!                     || epk (32B)
//!                     || pk_R (32B)
//! 5. ct = XChaCha20-Poly1305(content_key, plaintext, AAD = canonical_header)
//! 6. sig = Ed25519(sk_S, canonical_header || ct)
//! 7. envelope = { epk, ct, sig, sender_id, recipient_id }
//! ```
//!
//! Verify (recipient knows their own `sk_R`, the expected sender's
//! Ed25519 verifying key `vk_S`, and their own user-id):
//!
//! ```text
//! 1. Reconstruct pk_R from sk_R; rebuild canonical_header from envelope
//!    fields + recipient's local pk_R + recipient's local user_id.
//! 2. Verify sig under vk_S over (canonical_header || ct). FAIL → reject.
//! 3. shared = X25519(sk_R, envelope.epk).
//! 4. content_key = HKDF-SHA256(shared, info, salt = epk || pk_R).
//! 5. plaintext = AEAD_decrypt(content_key, ct, AAD = canonical_header).
//! ```
//!
//! Why encrypt-then-sign rather than sign-then-encrypt? The recipient
//! verifies the signature *before* exposing themselves to plaintext from
//! an attacker-controlled ciphertext — defense in depth against AEAD
//! parser bugs. Signature-hiding (the property sign-then-encrypt buys)
//! isn't relevant here: a server reading the envelope already learns
//! sender_id, recipient_id, epk, ct.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroizing;

use crate::{Error, Result};

const DST: &[u8] = b"pmgr-signcrypt-v1\x00";
const HKDF_INFO: &[u8] = b"pmgr-signcrypt-aead-key-v1";

/// Domain separation tag for the self-signed pubkey bundle. Distinct
/// from the signcryption envelope DST so a sig produced for one
/// purpose can never validate as the other.
const PUBKEY_BUNDLE_DST: &[u8] = b"pmgr-pubkey-bundle-v1\x00";

/// Wire form of a signcryption envelope. Three short binary fields
/// (epk, ct, sig) plus the two user-ids that bound sender + recipient
/// into the canonical header. Carry as JSON via base64-no-pad strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedEnvelope {
    pub sender_id: String,
    pub recipient_id: String,
    /// 32-byte ephemeral X25519 public key, base64-no-pad.
    pub epk_b64: String,
    /// 24-byte XChaCha20-Poly1305 nonce, base64-no-pad. Sourced from OsRng;
    /// the 192-bit nonce space makes random nonces collision-safe under
    /// the design's per-envelope ephemeral key, so we never need a counter.
    pub nonce_b64: String,
    /// AEAD ciphertext (with 16-byte Poly1305 tag), base64-no-pad.
    pub ciphertext_b64: String,
    /// 64-byte Ed25519 signature, base64-no-pad.
    pub signature_b64: String,
}

/// Sign + encrypt `plaintext` for a single recipient.
///
/// `recipient_pubkey` is the recipient's 32-byte X25519 public key. The
/// caller is responsible for fetching it from a trusted source — server-
/// supplied pubkeys are NOT trusted by this primitive on their own;
/// pinning / TOFU / directory authentication is the layer above.
pub fn sign_encrypt(
    sender_signing_key: &SigningKey,
    sender_id: &str,
    recipient_id: &str,
    recipient_pubkey: &[u8; 32],
    plaintext: &[u8],
) -> Result<SealedEnvelope> {
    // 1. Ephemeral X25519 keypair. Generate from a random seed so the
    //    secret zeroes on drop without us juggling an extra wrapper.
    let mut esk_bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(esk_bytes.as_mut());
    let esk = X25519Secret::from(*esk_bytes);
    let epk = X25519Public::from(&esk);

    // 2. ECDH against the recipient's static pubkey.
    let recipient_pk = X25519Public::from(*recipient_pubkey);
    let shared = esk.diffie_hellman(&recipient_pk);

    // 3. HKDF the AEAD key. Salt is epk || pk_R so two different
    //    recipients (or two different ephemeral runs) never collide
    //    even if the DH output coincidentally matched.
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(epk.as_bytes());
    salt[32..].copy_from_slice(recipient_pubkey);
    let mut content_key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes())
        .expand(HKDF_INFO, content_key.as_mut())
        .expect("32B HKDF expand within bounds");

    // 4. Canonical header — bound into both AAD and signature.
    let canonical_header =
        build_canonical_header(sender_id, recipient_id, epk.as_bytes(), recipient_pubkey);

    // 5. AEAD encrypt with a fresh 24-byte nonce. XChaCha20-Poly1305's
    //    192-bit nonce space tolerates random selection without the
    //    coordination we'd need under AES-GCM.
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let cipher =
        XChaCha20Poly1305::new_from_slice(content_key.as_ref()).map_err(|_| Error::Crypto)?;
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &canonical_header,
            },
        )
        .map_err(|_| Error::Crypto)?;

    // 6. Sign canonical_header || nonce || ciphertext. The nonce + ct
    //    inclusion is what stops a malicious server from re-using a sig
    //    across nonces.
    let mut sig_input = Vec::with_capacity(canonical_header.len() + 24 + ciphertext.len());
    sig_input.extend_from_slice(&canonical_header);
    sig_input.extend_from_slice(&nonce_bytes);
    sig_input.extend_from_slice(&ciphertext);
    let signature: Signature = sender_signing_key.sign(&sig_input);

    Ok(SealedEnvelope {
        sender_id: sender_id.to_string(),
        recipient_id: recipient_id.to_string(),
        epk_b64: STANDARD_NO_PAD.encode(epk.as_bytes()),
        nonce_b64: STANDARD_NO_PAD.encode(nonce_bytes),
        ciphertext_b64: STANDARD_NO_PAD.encode(&ciphertext),
        signature_b64: STANDARD_NO_PAD.encode(signature.to_bytes()),
    })
}

/// Verify the sender's signature, then decrypt.
///
/// `expected_sender_pubkey` is the Ed25519 verifying key of the sender;
/// the caller passes whatever they've authenticated through their own
/// trust path (org CA, TOFU pin, auditable directory, …) — this
/// primitive does not negotiate that.
///
/// `expected_recipient_id` is the local user-id the recipient expects
/// to see in the envelope. This catches a server that re-points a wrap
/// to a different recipient (or omits the ID and hopes verification
/// works anyway).
pub fn verify_decrypt(
    envelope: &SealedEnvelope,
    expected_sender_pubkey: &VerifyingKey,
    expected_recipient_id: &str,
    recipient_x25519_secret: &[u8; 32],
) -> Result<Vec<u8>> {
    // Reject mismatched recipient before any crypto — gives a cleaner
    // error message and avoids a constant-time-comparison signature
    // failure when the actual problem is a routing mistake.
    if envelope.recipient_id != expected_recipient_id {
        return Err(Error::InvalidEncoding(format!(
            "envelope recipient_id {} != expected {}",
            envelope.recipient_id, expected_recipient_id,
        )));
    }

    let epk = decode_fixed::<32>(&envelope.epk_b64, "epk_b64")?;
    let nonce_bytes = decode_fixed::<24>(&envelope.nonce_b64, "nonce_b64")?;
    let signature_bytes = decode_fixed::<64>(&envelope.signature_b64, "signature_b64")?;
    let ciphertext = STANDARD_NO_PAD
        .decode(&envelope.ciphertext_b64)
        .map_err(|_| Error::InvalidEncoding("ciphertext_b64 not base64-no-pad".into()))?;

    let recipient_pubkey = {
        let secret = X25519Secret::from(*recipient_x25519_secret);
        X25519Public::from(&secret).to_bytes()
    };

    let canonical_header = build_canonical_header(
        &envelope.sender_id,
        &envelope.recipient_id,
        &epk,
        &recipient_pubkey,
    );

    // Verify signature first; a bad sig must not give the AEAD a chance
    // to influence behaviour.
    let mut sig_input = Vec::with_capacity(canonical_header.len() + 24 + ciphertext.len());
    sig_input.extend_from_slice(&canonical_header);
    sig_input.extend_from_slice(&nonce_bytes);
    sig_input.extend_from_slice(&ciphertext);
    let signature = Signature::from_bytes(&signature_bytes);
    // Audit H-2 (2026-05-07): verify_strict rejects non-canonical sig
    // scalars + small-order R points. For a signcryption envelope this
    // is especially load-bearing — sig uniqueness is part of the
    // implicit replay-resistance argument; lax verify lets a server
    // produce two byte-different envelope variants that both decrypt.
    expected_sender_pubkey
        .verify_strict(&sig_input, &signature)
        .map_err(|_| Error::InvalidEncoding("envelope signature did not verify".into()))?;

    // ECDH + HKDF + AEAD decrypt.
    let recipient_secret = X25519Secret::from(*recipient_x25519_secret);
    let shared = recipient_secret.diffie_hellman(&X25519Public::from(epk));
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(&epk);
    salt[32..].copy_from_slice(&recipient_pubkey);
    let mut content_key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes())
        .expand(HKDF_INFO, content_key.as_mut())
        .expect("32B HKDF expand within bounds");

    let cipher =
        XChaCha20Poly1305::new_from_slice(content_key.as_ref()).map_err(|_| Error::Crypto)?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ciphertext,
                aad: &canonical_header,
            },
        )
        .map_err(|_| Error::InvalidEncoding("envelope AEAD did not authenticate".into()))
}

/// Canonical bytes a user signs at registration to bind their
/// `(user_id, ed25519_signing_pubkey, x25519_pubkey)` triple together.
/// Server stores the signature; consumers verify it before trusting any
/// pubkey returned from the directory.
///
/// Layout: `DST || u32_le(user_id.len) || user_id || signing_pk (32B) || x25519_pk (32B)`
pub fn pubkey_bundle_canonical_bytes(
    user_id: &str,
    signing_pubkey: &[u8; 32],
    x25519_pubkey: &[u8; 32],
) -> Vec<u8> {
    let id = user_id.as_bytes();
    let mut out = Vec::with_capacity(PUBKEY_BUNDLE_DST.len() + 4 + id.len() + 64);
    out.extend_from_slice(PUBKEY_BUNDLE_DST);
    out.extend_from_slice(&(id.len() as u32).to_le_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(signing_pubkey);
    out.extend_from_slice(x25519_pubkey);
    out
}

/// Sign a pubkey bundle with the user's Ed25519 signing key. Returns
/// the 64-byte signature.
pub fn sign_pubkey_bundle(
    signing_key: &SigningKey,
    user_id: &str,
    signing_pubkey: &[u8; 32],
    x25519_pubkey: &[u8; 32],
) -> [u8; 64] {
    let bytes = pubkey_bundle_canonical_bytes(user_id, signing_pubkey, x25519_pubkey);
    signing_key.sign(&bytes).to_bytes()
}

/// Verify a self-signed pubkey bundle. Returns Ok if the signature
/// is a valid Ed25519 signature by `signing_pubkey` over the
/// canonical (user_id, signing_pubkey, x25519_pubkey) bytes — i.e.
/// the user is attesting "I, owner of this signing key, bind myself
/// to this user_id and this X25519 pubkey".
pub fn verify_pubkey_bundle(
    user_id: &str,
    signing_pubkey: &[u8; 32],
    x25519_pubkey: &[u8; 32],
    signature: &[u8; 64],
) -> Result<()> {
    let vk = VerifyingKey::from_bytes(signing_pubkey)
        .map_err(|_| Error::InvalidEncoding("signing_pubkey is not a valid Ed25519 key".into()))?;
    let bytes = pubkey_bundle_canonical_bytes(user_id, signing_pubkey, x25519_pubkey);
    let sig = Signature::from_bytes(signature);
    // Audit H-2 (2026-05-07): verify_strict — pubkey-bundle sigs
    // are anchor records for the user-id binding; sig uniqueness
    // matters for any future audit-log / pinning use that compares
    // bundle bytes.
    vk.verify_strict(&bytes, &sig)
        .map_err(|_| Error::InvalidEncoding("pubkey bundle signature did not verify".into()))
}

fn build_canonical_header(
    sender_id: &str,
    recipient_id: &str,
    epk: &[u8; 32],
    recipient_pubkey: &[u8; 32],
) -> Vec<u8> {
    let s = sender_id.as_bytes();
    let r = recipient_id.as_bytes();
    let mut out = Vec::with_capacity(DST.len() + 8 + s.len() + r.len() + 64);
    out.extend_from_slice(DST);
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s);
    out.extend_from_slice(&(r.len() as u32).to_le_bytes());
    out.extend_from_slice(r);
    out.extend_from_slice(epk);
    out.extend_from_slice(recipient_pubkey);
    out
}

fn decode_fixed<const N: usize>(b64: &str, field: &str) -> Result<[u8; N]> {
    let bytes = STANDARD_NO_PAD
        .decode(b64)
        .map_err(|_| Error::InvalidEncoding(format!("{field} not base64-no-pad")))?;
    if bytes.len() != N {
        return Err(Error::InvalidEncoding(format!(
            "{field} expected {N} bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::generate_x25519;
    use ed25519_dalek::SigningKey;

    fn fixed_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn fixed_x25519(seed: u8) -> ([u8; 32], [u8; 32]) {
        // Deterministic so the test is reproducible across runs without
        // touching OsRng. (sign_encrypt's *internal* OsRng calls keep
        // the test stochastic for the ephemeral keys, which is what we
        // want — they exercise the integration path properly.)
        let secret = X25519Secret::from([seed; 32]);
        let public = X25519Public::from(&secret).to_bytes();
        (secret.to_bytes(), public)
    }

    #[test]
    fn round_trips_simple_message() {
        let sk_sender = fixed_signing_key(1);
        let vk_sender = sk_sender.verifying_key();
        let (sk_r, pk_r) = fixed_x25519(2);

        let env = sign_encrypt(&sk_sender, "alice", "bob", &pk_r, b"hello world").unwrap();
        let pt = verify_decrypt(&env, &vk_sender, "bob", &sk_r).unwrap();
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn each_envelope_has_a_fresh_ephemeral_pubkey() {
        let sk_sender = fixed_signing_key(1);
        let (_sk_r, pk_r) = fixed_x25519(2);
        let a = sign_encrypt(&sk_sender, "alice", "bob", &pk_r, b"x").unwrap();
        let b = sign_encrypt(&sk_sender, "alice", "bob", &pk_r, b"x").unwrap();
        assert_ne!(a.epk_b64, b.epk_b64, "epk MUST be fresh per envelope");
        assert_ne!(a.ciphertext_b64, b.ciphertext_b64);
        assert_ne!(a.signature_b64, b.signature_b64);
    }

    #[test]
    fn rejects_ciphertext_tampering() {
        let sk_sender = fixed_signing_key(1);
        let vk_sender = sk_sender.verifying_key();
        let (sk_r, pk_r) = fixed_x25519(2);

        let mut env = sign_encrypt(&sk_sender, "alice", "bob", &pk_r, b"top secret").unwrap();
        // Flip a byte in the ciphertext. Both signature and AEAD bind it,
        // so verification fails at the signature step.
        let mut ct = STANDARD_NO_PAD.decode(&env.ciphertext_b64).unwrap();
        ct[0] ^= 0x01;
        env.ciphertext_b64 = STANDARD_NO_PAD.encode(ct);
        assert!(verify_decrypt(&env, &vk_sender, "bob", &sk_r).is_err());
    }

    #[test]
    fn rejects_signature_tampering() {
        let sk_sender = fixed_signing_key(1);
        let vk_sender = sk_sender.verifying_key();
        let (sk_r, pk_r) = fixed_x25519(2);
        let mut env = sign_encrypt(&sk_sender, "alice", "bob", &pk_r, b"x").unwrap();
        let mut sig = STANDARD_NO_PAD.decode(&env.signature_b64).unwrap();
        sig[5] ^= 0x80;
        env.signature_b64 = STANDARD_NO_PAD.encode(sig);
        assert!(verify_decrypt(&env, &vk_sender, "bob", &sk_r).is_err());
    }

    #[test]
    fn rejects_signature_under_wrong_sender_key() {
        // Server hands recipient a forged "sender pubkey". The signature
        // was issued by the real sender, but the recipient verifies under
        // the attacker's pubkey — fails.
        let sk_real = fixed_signing_key(1);
        let attacker = fixed_signing_key(2);
        let (sk_r, pk_r) = fixed_x25519(3);

        let env = sign_encrypt(&sk_real, "alice", "bob", &pk_r, b"x").unwrap();
        assert!(verify_decrypt(&env, &attacker.verifying_key(), "bob", &sk_r).is_err());
    }

    #[test]
    fn rejects_decrypt_under_wrong_recipient_key() {
        // A different recipient X25519 priv yields a different ECDH
        // output → different content_key → AEAD fails.
        let sk_sender = fixed_signing_key(1);
        let vk_sender = sk_sender.verifying_key();
        let (_sk_intended, pk_intended) = fixed_x25519(2);
        let (sk_other, _pk_other) = fixed_x25519(3);

        let env = sign_encrypt(&sk_sender, "alice", "bob", &pk_intended, b"x").unwrap();
        // Important: verify_decrypt rebuilds canonical_header from the
        // recipient's *own* X25519 pubkey. With sk_other the
        // reconstructed pubkey ≠ what was AAD-bound at encrypt time,
        // so signature verify fails first.
        assert!(verify_decrypt(&env, &vk_sender, "bob", &sk_other).is_err());
    }

    #[test]
    fn rejects_recipient_id_substitution() {
        // Server tries to redirect a wrap from bob → carol by rewriting
        // recipient_id in the envelope. The id is bound into AAD +
        // signature, so verification fails.
        let sk_sender = fixed_signing_key(1);
        let vk_sender = sk_sender.verifying_key();
        let (sk_bob, pk_bob) = fixed_x25519(2);

        let mut env = sign_encrypt(&sk_sender, "alice", "bob", &pk_bob, b"x").unwrap();
        env.recipient_id = "carol".into();
        // verify_decrypt's local-id check trips first; surface that.
        let err = verify_decrypt(&env, &vk_sender, "bob", &sk_bob).unwrap_err();
        assert!(format!("{err:?}").contains("recipient_id"));

        // Even if we ask for carol explicitly, signature fails because
        // canonical_header rebuilt with carol won't match what alice
        // signed.
        assert!(verify_decrypt(&env, &vk_sender, "carol", &sk_bob).is_err());
    }

    #[test]
    fn rejects_sender_id_substitution() {
        // Server tries to take credit for a wrap by claiming "from" was
        // somebody else. The id is bound into the signed canonical
        // header; verify fails.
        let sk_sender = fixed_signing_key(1);
        let vk_sender = sk_sender.verifying_key();
        let (sk_bob, pk_bob) = fixed_x25519(2);

        let mut env = sign_encrypt(&sk_sender, "alice", "bob", &pk_bob, b"x").unwrap();
        env.sender_id = "mallory".into();
        assert!(verify_decrypt(&env, &vk_sender, "bob", &sk_bob).is_err());
    }

    #[test]
    fn rejects_envelope_with_bad_base64() {
        let sk_sender = fixed_signing_key(1);
        let vk_sender = sk_sender.verifying_key();
        let (sk_r, pk_r) = fixed_x25519(2);
        let mut env = sign_encrypt(&sk_sender, "alice", "bob", &pk_r, b"x").unwrap();
        env.epk_b64 = "this is not base64!!!".into();
        assert!(verify_decrypt(&env, &vk_sender, "bob", &sk_r).is_err());
    }

    #[test]
    fn rejects_envelope_with_short_signature() {
        let sk_sender = fixed_signing_key(1);
        let vk_sender = sk_sender.verifying_key();
        let (sk_r, pk_r) = fixed_x25519(2);
        let mut env = sign_encrypt(&sk_sender, "alice", "bob", &pk_r, b"x").unwrap();
        env.signature_b64 = STANDARD_NO_PAD.encode([0u8; 16]);
        assert!(verify_decrypt(&env, &vk_sender, "bob", &sk_r).is_err());
    }

    #[test]
    fn pubkey_bundle_round_trips() {
        let sk = fixed_signing_key(7);
        let signing_pk = sk.verifying_key().to_bytes();
        let x25519_pk = [0xa5u8; 32];
        let sig = sign_pubkey_bundle(&sk, "user-uuid-here", &signing_pk, &x25519_pk);
        verify_pubkey_bundle("user-uuid-here", &signing_pk, &x25519_pk, &sig)
            .expect("self-signed bundle must verify");
    }

    #[test]
    fn pubkey_bundle_rejects_user_id_substitution() {
        let sk = fixed_signing_key(7);
        let signing_pk = sk.verifying_key().to_bytes();
        let x25519_pk = [0xa5u8; 32];
        let sig = sign_pubkey_bundle(&sk, "alice", &signing_pk, &x25519_pk);
        // Server tries to claim the same pubkeys belong to a different user.
        assert!(
            verify_pubkey_bundle("bob", &signing_pk, &x25519_pk, &sig).is_err(),
            "user_id swap must invalidate the bundle sig"
        );
    }

    #[test]
    fn pubkey_bundle_rejects_x25519_substitution() {
        let sk = fixed_signing_key(7);
        let signing_pk = sk.verifying_key().to_bytes();
        let original_x25519 = [0xa5u8; 32];
        let attacker_x25519 = [0xffu8; 32];
        let sig = sign_pubkey_bundle(&sk, "alice", &signing_pk, &original_x25519);
        // Server tries to swap the X25519 (so a sender wraps to the
        // attacker's key) while keeping the original Ed25519 pubkey
        // and sig — must fail.
        assert!(verify_pubkey_bundle("alice", &signing_pk, &attacker_x25519, &sig).is_err());
    }

    #[test]
    fn pubkey_bundle_rejects_signing_pubkey_substitution() {
        let sk = fixed_signing_key(7);
        let attacker = fixed_signing_key(8);
        let original_signing = sk.verifying_key().to_bytes();
        let attacker_signing = attacker.verifying_key().to_bytes();
        let x25519_pk = [0xa5u8; 32];
        let sig = sign_pubkey_bundle(&sk, "alice", &original_signing, &x25519_pk);
        assert!(verify_pubkey_bundle("alice", &attacker_signing, &x25519_pk, &sig).is_err());
    }

    #[test]
    fn json_round_trips_envelope() {
        // serde Serialize/Deserialize is part of the public contract;
        // M4/M6 endpoints will carry envelopes inside JSON wrappers.
        let sk_sender = fixed_signing_key(1);
        let (_sk_r, pk_r) = generate_x25519();
        let env = sign_encrypt(&sk_sender, "alice", "bob", &pk_r, b"x").unwrap();
        let json = serde_json::to_string(&env).unwrap();
        let parsed: SealedEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
    }
}
