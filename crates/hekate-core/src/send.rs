//! M2.25 — Send crypto: HKDF-derived content key, XChaCha20-Poly1305
//! payload, URL-fragment encoding for anonymous recipients.
//!
//! ## Wire model
//!
//! ```text
//! Sender:                                  Recipient:
//!   send_key = random_32B                    fragment = parse(URL)
//!   content_key = HKDF(send_key,             send_id, send_key = fragment
//!                      info=v1,              POST /api/v1/public/sends/{id}/access
//!                      salt=send_id)         server returns: data EncString
//!   data = XC20P(content_key, plaintext,     content_key = HKDF(send_key, ...)
//!                AAD=v1:send_id:type)        plaintext = XC20P_open(content_key, data)
//! ```
//!
//! Server stores the ciphertext + a separate `protected_send_key`
//! (the send_key wrapped under the sender's account key, so the
//! sender can list/edit their own Send from any device). Server
//! never sees the send_key in the clear.
//!
//! The optional access password is **not** fed into key derivation —
//! it's a server-side Argon2id-hashed gate the server checks before
//! returning the ciphertext. Threat model: a server that wants to
//! revoke access can; a server that wants to read the payload can't.
//!
//! ## URL fragment
//!
//! The sender's URL is `https://<host>/send/#/<send_id>/<send_key_b64>`
//! where `<send_key_b64>` is URL-safe base64-no-pad of the 32-byte
//! send_key. Browsers do not transmit the fragment to the server, so
//! the send_key never leaves the client side of the wire. Sharing the
//! URL is morally equivalent to sharing the key.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{encstring::EncString, Error, Result};

/// HKDF info tag for the content key. Bumping this rotates the
/// derivation independently of any other Send changes.
const HKDF_INFO_CONTENT: &[u8] = b"pmgr-send-content-v1";

/// Send type tag baked into AAD so a server can't move ciphertext
/// from a text Send onto a file Send (or vice versa).
pub const SEND_TYPE_TEXT: u8 = 1;
pub const SEND_TYPE_FILE: u8 = 2;

/// 32 bytes. Random; URL-safe-base64-no-pad in the URL fragment.
pub type SendKey = Zeroizing<[u8; 32]>;

/// Generate a fresh random 32-byte send key. The sender embeds this
/// in the URL fragment they share with recipients.
pub fn generate_send_key() -> SendKey {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    Zeroizing::new(k)
}

/// Encode a `SendKey` as the URL-fragment string. Inverse:
/// [`decode_send_key`].
pub fn encode_send_key(send_key: &SendKey) -> String {
    URL_SAFE_NO_PAD.encode(send_key.as_ref())
}

/// Decode a URL-fragment string back to a `SendKey`. Rejects anything
/// that doesn't decode to exactly 32 bytes.
pub fn decode_send_key(s: &str) -> Result<SendKey> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| Error::InvalidEncoding("send_key not URL-safe base64-no-pad".into()))?;
    if bytes.len() != 32 {
        return Err(Error::InvalidEncoding(
            "send_key must decode to exactly 32 bytes".into(),
        ));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Derive the 256-bit content key. `send_id` is mixed in via the HKDF
/// salt so two Sends that happen to share the same send_key (vanishingly
/// unlikely with 256-bit randomness, but defense in depth) still get
/// distinct content keys. AAD on the AEAD additionally binds the
/// ciphertext to its `send_id` and `send_type`.
pub fn derive_content_key(send_key: &SendKey, send_id: &str) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(send_id.as_bytes()), send_key.as_ref());
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO_CONTENT, out.as_mut())
        .expect("HKDF length within bounds");
    out
}

/// AAD for the encrypted Send payload. Binds the ciphertext to the
/// (send_id, send_type) location so a server can't substitute one
/// Send's payload for another's, or claim a text Send's bytes belong
/// to a file Send.
pub fn data_aad(send_id: &str, send_type: u8) -> Vec<u8> {
    let mut a = Vec::with_capacity(32 + send_id.len());
    a.extend_from_slice(b"pmgr-send-data-v1:");
    a.extend_from_slice(send_id.as_bytes());
    a.push(b':');
    a.push(send_type);
    a
}

/// AAD for the wrapped send_key (the `protected_send_key` field).
/// Binds the wrap to the `send_id` so the server can't move a wrapped
/// key from one Send row to another.
pub fn key_wrap_aad(send_id: &str) -> Vec<u8> {
    let mut a = Vec::with_capacity(32 + send_id.len());
    a.extend_from_slice(b"pmgr-send-key-v1:");
    a.extend_from_slice(send_id.as_bytes());
    a
}

/// AAD for the sender-side `name` field on a Send. The Send's name is
/// wrapped under the user's account_key (it's never sent to recipients
/// — recipients only see the `data` field that comes out of the
/// `send_key`-derived content_key). Binds to `send_id` to prevent the
/// server from swapping a name ciphertext between two Sends.
pub fn name_aad(send_id: &str) -> Vec<u8> {
    let mut a = Vec::with_capacity(32 + send_id.len());
    a.extend_from_slice(b"pmgr-send-name-v1:");
    a.extend_from_slice(send_id.as_bytes());
    a
}

/// Encrypt a text-Send plaintext under the content_key derived from
/// `send_key` + `send_id`. Output is the wire-format EncString string.
pub fn encrypt_text(send_key: &SendKey, send_id: &str, plaintext: &[u8]) -> Result<String> {
    let content_key = derive_content_key(send_key, send_id);
    let aad = data_aad(send_id, SEND_TYPE_TEXT);
    // Reuse the EncString v3 envelope so /sync handlers can validate
    // shape uniformly. key_id is fixed for Sends — no rotation today.
    Ok(EncString::encrypt_xc20p("sk:1", &content_key, plaintext, &aad)?.to_wire())
}

/// Decrypt a text-Send EncString. The recipient calls this with the
/// send_key extracted from the URL fragment.
pub fn decrypt_text(send_key: &SendKey, send_id: &str, wire: &str) -> Result<Vec<u8>> {
    let content_key = derive_content_key(send_key, send_id);
    let parsed = EncString::parse(wire)?;
    let aad = data_aad(send_id, SEND_TYPE_TEXT);
    parsed
        .decrypt_xc20p(&content_key, Some(&aad))
        .map_err(|_| Error::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_text() {
        let send_key = generate_send_key();
        let send_id = "0192e0a0-0000-7000-8000-000000000001";
        let plaintext = b"hello recipient";
        let wire = encrypt_text(&send_key, send_id, plaintext).unwrap();
        let pt2 = decrypt_text(&send_key, send_id, &wire).unwrap();
        assert_eq!(pt2, plaintext);
    }

    #[test]
    fn wrong_send_id_aad_fails() {
        let send_key = generate_send_key();
        let wire = encrypt_text(&send_key, "send-A", b"x").unwrap();
        assert!(decrypt_text(&send_key, "send-B", &wire).is_err());
    }

    #[test]
    fn wrong_send_key_fails() {
        let a = generate_send_key();
        let b = generate_send_key();
        let wire = encrypt_text(&a, "id", b"y").unwrap();
        assert!(decrypt_text(&b, "id", &wire).is_err());
    }

    #[test]
    fn url_round_trip() {
        let k = generate_send_key();
        let s = encode_send_key(&k);
        let k2 = decode_send_key(&s).unwrap();
        assert_eq!(k.as_ref(), k2.as_ref());
    }

    #[test]
    fn decode_rejects_short_input() {
        let too_short = URL_SAFE_NO_PAD.encode([0u8; 31]);
        assert!(decode_send_key(&too_short).is_err());
        let too_long = URL_SAFE_NO_PAD.encode([0u8; 33]);
        assert!(decode_send_key(&too_long).is_err());
        assert!(decode_send_key("not-base64!!!").is_err());
    }

    #[test]
    fn hkdf_is_deterministic_per_send_id() {
        let k = generate_send_key();
        let c1 = derive_content_key(&k, "id-1");
        let c2 = derive_content_key(&k, "id-1");
        assert_eq!(c1.as_ref(), c2.as_ref());
        let c3 = derive_content_key(&k, "id-2");
        assert_ne!(c1.as_ref(), c3.as_ref());
    }

    #[test]
    fn data_aad_distinguishes_text_vs_file() {
        let a = data_aad("id", SEND_TYPE_TEXT);
        let b = data_aad("id", SEND_TYPE_FILE);
        assert_ne!(a, b);
    }
}
