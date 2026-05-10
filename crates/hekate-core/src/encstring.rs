//! EncString v3 wire format and AEAD operations.
//!
//! Layout: `v3.<alg>.<key_id>.<nonce_b64>.<aad_b64>.<ct_b64>.<tag_b64>`
//!
//! For XChaCha20-Poly1305 (alg=`xc20p`):
//!   - nonce = 24 random bytes (random nonces are safe for XChaCha20)
//!   - AAD bytes are exposed in the envelope so the verifier can rebuild them;
//!     they are NOT secret. Bound to the ciphertext via Poly1305 — flipping
//!     them causes decryption to fail.
//!   - tag = 16 bytes
//!
//! base64: standard alphabet, no padding (URL-safe-no-pad would also work but
//! standard alphabet is friendlier when the value is logged).

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    /// XChaCha20-Poly1305 (default symmetric)
    XChaCha20Poly1305,
    /// AES-256-GCM-SIV (reserved; not yet implemented)
    AesGcmSiv,
    /// X25519 ECDH key wrap (reserved)
    X25519,
    /// Ed25519 signature (reserved)
    Ed25519,
}

impl Alg {
    pub fn as_str(self) -> &'static str {
        match self {
            Alg::XChaCha20Poly1305 => "xc20p",
            Alg::AesGcmSiv => "agcms",
            Alg::X25519 => "x25519",
            Alg::Ed25519 => "ed25519",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "xc20p" => Ok(Alg::XChaCha20Poly1305),
            "agcms" => Ok(Alg::AesGcmSiv),
            "x25519" => Ok(Alg::X25519),
            "ed25519" => Ok(Alg::Ed25519),
            _ => Err(Error::InvalidEncString("unknown alg")),
        }
    }
}

/// Parsed envelope. Validates structure only; does not decrypt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncString {
    pub alg: Alg,
    pub key_id: String,
    pub nonce: Vec<u8>,
    pub aad: Vec<u8>,
    pub ct: Vec<u8>,
    pub tag: Vec<u8>,
}

impl EncString {
    /// Encrypt with XChaCha20-Poly1305. AAD is bound via Poly1305 (the AEAD's
    /// associated-data feature) and stored on the envelope so the verifier can
    /// reconstruct it. Nonce is generated freshly via OsRng — XChaCha20's
    /// 192-bit nonce makes random sampling safe.
    pub fn encrypt_xc20p(
        key_id: impl Into<String>,
        key: &[u8; 32],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Self> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key));

        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ct_and_tag = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Crypto)?;
        // chacha20poly1305 returns ciphertext || tag concatenated.
        if ct_and_tag.len() < 16 {
            return Err(Error::Crypto);
        }
        let split = ct_and_tag.len() - 16;
        let (ct, tag) = ct_and_tag.split_at(split);

        Ok(Self {
            alg: Alg::XChaCha20Poly1305,
            key_id: key_id.into(),
            nonce: nonce_bytes.to_vec(),
            aad: aad.to_vec(),
            ct: ct.to_vec(),
            tag: tag.to_vec(),
        })
    }

    /// Decrypt and verify. Caller-provided `expected_aad` MUST equal the AAD
    /// that was bound at encrypt time, otherwise this returns `Error::Crypto`.
    /// Passing `None` accepts any AAD value embedded in the envelope (use only
    /// when the AAD is structurally implicit and not security-bearing).
    pub fn decrypt_xc20p(&self, key: &[u8; 32], expected_aad: Option<&[u8]>) -> Result<Vec<u8>> {
        if self.alg != Alg::XChaCha20Poly1305 {
            return Err(Error::InvalidEncString("alg mismatch"));
        }
        if let Some(want) = expected_aad {
            if want != self.aad.as_slice() {
                return Err(Error::Crypto);
            }
        }
        if self.nonce.len() != 24 || self.tag.len() != 16 {
            return Err(Error::InvalidEncString("bad nonce/tag length"));
        }
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
        let nonce = XNonce::from_slice(&self.nonce);

        // Re-concatenate ct || tag for the AEAD API.
        let mut ct_and_tag = Vec::with_capacity(self.ct.len() + self.tag.len());
        ct_and_tag.extend_from_slice(&self.ct);
        ct_and_tag.extend_from_slice(&self.tag);

        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ct_and_tag,
                    aad: &self.aad,
                },
            )
            .map_err(|_| Error::Crypto)
    }

    /// Encode as the canonical wire string `v3.<alg>.<key_id>.<...>`.
    pub fn to_wire(&self) -> String {
        format!(
            "v3.{}.{}.{}.{}.{}.{}",
            self.alg.as_str(),
            self.key_id,
            STANDARD_NO_PAD.encode(&self.nonce),
            STANDARD_NO_PAD.encode(&self.aad),
            STANDARD_NO_PAD.encode(&self.ct),
            STANDARD_NO_PAD.encode(&self.tag),
        )
    }

    pub fn parse(s: &str) -> Result<Self> {
        let mut parts = s.split('.');
        if parts.next() != Some("v3") {
            return Err(Error::InvalidEncString("expected v3"));
        }
        let alg = Alg::parse(parts.next().ok_or(Error::InvalidEncString("missing alg"))?)?;
        let key_id = parts
            .next()
            .ok_or(Error::InvalidEncString("missing key_id"))?
            .to_string();
        let nonce = b64(parts
            .next()
            .ok_or(Error::InvalidEncString("missing nonce"))?)?;
        let aad = b64(parts.next().ok_or(Error::InvalidEncString("missing aad"))?)?;
        let ct = b64(parts.next().ok_or(Error::InvalidEncString("missing ct"))?)?;
        let tag = b64(parts.next().ok_or(Error::InvalidEncString("missing tag"))?)?;
        if parts.next().is_some() {
            return Err(Error::InvalidEncString("trailing data"));
        }
        Ok(Self {
            alg,
            key_id,
            nonce,
            aad,
            ct,
            tag,
        })
    }
}

fn b64(s: &str) -> Result<Vec<u8>> {
    STANDARD_NO_PAD
        .decode(s)
        .map_err(|_| Error::InvalidEncString("bad base64"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        // Deterministic test key. Never use a fixed key in production.
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn parses_valid_string_form() {
        let e = EncString::encrypt_xc20p("kid1", &key(), b"hello", b"aad").unwrap();
        let s = e.to_wire();
        let r = EncString::parse(&s).unwrap();
        assert_eq!(r, e);
    }

    #[test]
    fn rejects_wrong_version() {
        assert!(EncString::parse("v2.xc20p.k.AA.AA.AA.AA").is_err());
    }

    #[test]
    fn rejects_unknown_alg() {
        assert!(EncString::parse("v3.bogus.k.AA.AA.AA.AA").is_err());
    }

    #[test]
    fn rejects_truncated() {
        assert!(EncString::parse("v3.xc20p.k.AA.AA.AA").is_err());
    }

    #[test]
    fn rejects_trailing() {
        assert!(EncString::parse("v3.xc20p.k.AA.AA.AA.AA.extra").is_err());
    }

    #[test]
    fn round_trip_with_aad() {
        let pt = b"the quick brown fox jumps over the lazy dog";
        let aad = b"cipher:abc:field:password";
        let e = EncString::encrypt_xc20p("kid", &key(), pt, aad).unwrap();
        let dec = e.decrypt_xc20p(&key(), Some(aad)).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn round_trip_via_wire_string() {
        let pt = b"secret";
        let aad = b"a";
        let e = EncString::encrypt_xc20p("kid", &key(), pt, aad).unwrap();
        let s = e.to_wire();
        let parsed = EncString::parse(&s).unwrap();
        let dec = parsed.decrypt_xc20p(&key(), Some(aad)).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn aad_mismatch_fails() {
        let e = EncString::encrypt_xc20p("kid", &key(), b"x", b"correct").unwrap();
        let r = e.decrypt_xc20p(&key(), Some(b"wrong"));
        assert!(matches!(r, Err(Error::Crypto)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut e = EncString::encrypt_xc20p("kid", &key(), b"hello", b"aad").unwrap();
        e.ct[0] ^= 0xff;
        assert!(matches!(
            e.decrypt_xc20p(&key(), Some(b"aad")),
            Err(Error::Crypto)
        ));
    }

    #[test]
    fn tampered_tag_fails() {
        let mut e = EncString::encrypt_xc20p("kid", &key(), b"hello", b"aad").unwrap();
        e.tag[0] ^= 0x01;
        assert!(matches!(
            e.decrypt_xc20p(&key(), Some(b"aad")),
            Err(Error::Crypto)
        ));
    }

    #[test]
    fn tampered_aad_in_envelope_fails() {
        // If the envelope's AAD is rewritten to something else, Poly1305 will
        // catch it because the original AAD was bound at encrypt time.
        let mut e = EncString::encrypt_xc20p("kid", &key(), b"hello", b"aad-A").unwrap();
        e.aad = b"aad-B".to_vec();
        // Even passing None (don't validate against expected) the AEAD itself
        // rejects the tampered AAD.
        assert!(matches!(e.decrypt_xc20p(&key(), None), Err(Error::Crypto)));
    }

    #[test]
    fn wrong_key_fails() {
        let e = EncString::encrypt_xc20p("kid", &key(), b"hello", b"aad").unwrap();
        let mut other = key();
        other[0] ^= 0xff;
        assert!(matches!(
            e.decrypt_xc20p(&other, Some(b"aad")),
            Err(Error::Crypto)
        ));
    }
}
