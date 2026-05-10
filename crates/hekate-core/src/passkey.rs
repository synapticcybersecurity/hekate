//! Passkey (WebAuthn) credential storage primitives — GH #1 foundation.
//!
//! Hekate is becoming a credential provider on the browser-extension surface
//! (Chrome's `webAuthenticationProxy` API and the Firefox equivalent). When a
//! site invokes `navigator.credentials.create()` or `.get()`, the extension
//! intercepts the ceremony, asks the user to approve, generates (or looks up)
//! an ECDSA-P256 keypair, signs the WebAuthn assertion, and persists the
//! private key inside the user's vault so the same passkey is available on
//! every device.
//!
//! This module owns:
//!   * ECDSA-P256 keygen + DER signing (the only algorithm we ship in v1 —
//!     it's what every major RP advertises and what passes the FIDO Alliance
//!     interop suite by default).
//!   * The `Fido2Credential` plaintext wire shape that the popup writes into
//!     a login cipher's `fido2Credentials` array. Mirrors Bitwarden's field
//!     names so existing tooling and importers can round-trip the data.
//!
//! The cipher itself is still encrypted with the per-cipher key under the
//! account key (M1 envelope), so this module only deals with the *plaintext*
//! shape that lives inside that envelope. The protected_data blob carries the
//! whole login record (username/password/uri/totp/fido2Credentials) as one
//! JSON payload — we don't per-field-encrypt the way Bitwarden does because
//! the cipher PCK already covers it.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    SecretKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Hekate's authenticator AAGUID — a stable 16-byte identifier the
/// authenticator embeds in every `attestedCredentialData` block at
/// registration time. RPs use it (in policy / metadata-service contexts)
/// to recognise authenticator implementations; for our purposes any
/// fixed v4 UUID will do, as long as we don't change it across releases.
///
/// We pick a memorable v4: ASCII "Hekate" (`48 65 6b 61 74 65`) for the
/// first 6 bytes, followed by `40 72` (version 4 nibble + 2-byte tag),
/// `a0 00` (RFC 4122 variant nibble `a` + slot 0), then a six-byte
/// reserved/serial field starting at `…01`. UUID string form:
/// `48656b61-7465-4072-a000-000000000001`.
///
/// Mirrored verbatim in `clients/extension/popup/popup.js`
/// (`HEKATE_AAGUID`); changing this constant requires changing both
/// (and is a credential-stability decision — doing so makes RP-side
/// AAGUID allowlists stop matching previously-issued Hekate
/// credentials).
pub const HEKATE_AAGUID: [u8; 16] = [
    0x48, 0x65, 0x6b, 0x61, 0x74, 0x65, 0x40, 0x72, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// Output of [`generate_p256_keypair`]. Caller should immediately wrap
/// `private_pkcs8_b64` inside the cipher PCK envelope and drop the plaintext.
pub struct GeneratedPasskey {
    /// PKCS#8 DER, base64-standard-encoded. The shape every WebAuthn
    /// library accepts on re-import. Sensitive — wipe after wrapping.
    pub private_pkcs8_b64: Zeroizing<String>,
    /// Uncompressed SEC1 (`0x04 || x || y`, 65 bytes) base64-encoded.
    /// Useful when the RP wants the raw EC point (rare; most want COSE).
    pub public_sec1_b64: String,
    /// 16 random bytes, base64url-encoded (no padding). The opaque ID the
    /// RP receives in the attestation/assertion so it can reference this
    /// credential in subsequent ceremonies. WebAuthn allows up to 1023 B
    /// but 16 is plenty and matches what most authenticators emit.
    pub credential_id_b64url: String,
}

/// Generate a fresh ECDSA-P256 keypair plus a random credential_id. The
/// credential_id is independent of the keypair (it's just the RP's handle
/// for "which credential is this"); generating both here keeps callers
/// from forgetting to mint one.
pub fn generate_p256_keypair() -> Result<GeneratedPasskey> {
    use rand::RngCore;

    // Generate as SecretKey so we can call EncodePrivateKey on it (the
    // pkcs8 trait impl is on SecretKey, not directly on the ecdsa
    // SigningKey under p256 0.13's default features).
    let secret = SecretKey::random(&mut OsRng);
    let signing_key: SigningKey = (&secret).into();
    let verifying_key = signing_key.verifying_key();

    let pkcs8 = secret.to_pkcs8_der().map_err(|_| Error::Crypto)?;
    let private_pkcs8_b64 = Zeroizing::new(B64.encode(pkcs8.as_bytes()));

    // SEC1 uncompressed: 0x04 || x(32) || y(32) = 65 bytes. The
    // `EncodedPoint` from p256 is exactly this when compressed=false.
    let public_sec1 = verifying_key.to_encoded_point(false);
    let public_sec1_b64 = B64.encode(public_sec1.as_bytes());

    let mut cred_id = [0u8; 16];
    OsRng.fill_bytes(&mut cred_id);
    let credential_id_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred_id);

    Ok(GeneratedPasskey {
        private_pkcs8_b64,
        public_sec1_b64,
        credential_id_b64url,
    })
}

/// Build an `authenticatorData` block for a WebAuthn `get` assertion and
/// sign it together with the supplied client-data hash. Returns the
/// 37-byte authData bytes alongside the DER ECDSA signature so the JS
/// caller can drop both straight into the response payload.
///
/// Audit M-3 (2026-05-07): bringing the rpId binding inside Rust closes
/// a trust gap. Previously the popup constructed `authData = sha256(rpId)
/// || flags || signCount` itself and handed the concatenated bytes to
/// [`sign_p256`]. A bug or compromise in the popup-side concatenation
/// would let an attacker bind a different rpId than the user approved
/// — the WASM happily signs whatever it's given. With this helper, the
/// JS boundary commits the rpId at call-time and the Rust side computes
/// the hash, so the signed bytes always reflect the rpId the caller
/// claimed.
///
/// Inputs:
/// * `private_pkcs8_b64` — PKCS#8 DER, base64-standard, as emitted by
///   [`generate_p256_keypair`].
/// * `rp_id` — relying-party identifier, e.g. `"webauthn.io"`.
/// * `flags` — WebAuthn flags byte. Caller picks (UP=0x01, UV=0x04, …).
/// * `sign_count` — assertion sign counter (we always emit 0; field
///   kept for forward-compat with future per-device counters).
/// * `client_data_hash` — `sha256(clientDataJSON)`, exactly 32 bytes.
pub fn sign_assertion(
    private_pkcs8_b64: &str,
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    client_data_hash: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    use sha2::{Digest, Sha256};
    if client_data_hash.len() != 32 {
        return Err(Error::InvalidEncoding(format!(
            "client_data_hash must be 32 bytes (sha256), got {}",
            client_data_hash.len()
        )));
    }
    // authenticatorData = sha256(rpId)(32) || flags(1) || signCount(4) — 37 B
    let mut authenticator_data = Vec::with_capacity(37);
    let rp_id_hash = Sha256::digest(rp_id.as_bytes());
    authenticator_data.extend_from_slice(&rp_id_hash);
    authenticator_data.push(flags);
    authenticator_data.extend_from_slice(&sign_count.to_be_bytes());

    // Signed message = authenticatorData || sha256(clientDataJSON)
    let mut msg = Vec::with_capacity(37 + 32);
    msg.extend_from_slice(&authenticator_data);
    msg.extend_from_slice(client_data_hash);

    let signature = sign_p256(private_pkcs8_b64, &msg)?;
    Ok((authenticator_data, signature))
}

/// Sign `msg` with a P-256 private key previously emitted by
/// [`generate_p256_keypair`]. Returns a DER-encoded ECDSA signature — the
/// format every WebAuthn relying party expects in the assertion.
///
/// `msg` for WebAuthn authentication is `authenticatorData || sha256(clientDataJSON)`;
/// caller assembles that. We just sign the bytes.
///
/// Prefer [`sign_assertion`] for WebAuthn use — it constructs the
/// authenticatorData inside Rust so the rpId binding crosses the
/// JS/WASM boundary as a string, not as opaque bytes the popup could
/// have miscomputed.
pub fn sign_p256(private_pkcs8_b64: &str, msg: &[u8]) -> Result<Vec<u8>> {
    let pkcs8 = B64
        .decode(private_pkcs8_b64.as_bytes())
        .map_err(|e| Error::InvalidEncoding(format!("p256 private key not base64: {e}")))?;
    let secret = SecretKey::from_pkcs8_der(&pkcs8)
        .map_err(|e| Error::InvalidEncoding(format!("p256 pkcs8 decode failed: {e}")))?;
    let signing_key: SigningKey = (&secret).into();
    let sig: Signature = signing_key.sign(msg);
    Ok(sig.to_der().as_bytes().to_vec())
}

/// CBOR-encode an ES256 (P-256) public key as a COSE_Key map. WebAuthn's
/// attestedCredentialData embeds exactly this byte sequence as the
/// "credentialPublicKey" field; the RP's verifier parses it back out.
///
/// Input: the 65-byte uncompressed SEC1 encoding (`0x04 || x(32) || y(32)`)
/// — same shape [`generate_p256_keypair`]'s `public_sec1_b64` decodes to.
///
/// COSE_Key shape (RFC 8152) for an EC2 P-256 / ES256 key:
///
/// ```text
///   { 1: 2,    // kty: EC2
///     3: -7,   // alg: ES256
///    -1: 1,    // crv: P-256
///    -2: <x>,  // 32-byte big-endian X coordinate
///    -3: <y>   // 32-byte big-endian Y coordinate }
/// ```
///
/// We hand-encode the CBOR — the shape is fixed at 77 bytes total, so
/// there's no ambiguity worth pulling in a CBOR crate to handle. Map keys
/// are emitted in the canonical order (RFC 7049 length-then-lex) which
/// happens to match WebAuthn's expectation (RPs accept any order, but
/// canonical order keeps assertion bytes byte-stable across clients).
pub fn cose_es256_pubkey(sec1_uncompressed: &[u8]) -> Result<Vec<u8>> {
    if sec1_uncompressed.len() != 65 || sec1_uncompressed[0] != 0x04 {
        return Err(Error::InvalidEncoding(format!(
            "expected 65-byte uncompressed SEC1 (0x04 || x || y), got {} bytes",
            sec1_uncompressed.len()
        )));
    }
    // Audit M-2 (2026-05-07): re-parse the SEC1 bytes through the p256
    // curve crate so an off-curve (x, y) pair can't slip through. The
    // length + prefix check above only validates the encoding shape;
    // `EncodedPoint::from_bytes` + `VerifyingKey::from_encoded_point`
    // run the full curve membership check. Internal callers only feed
    // freshly-generated points here, but the WASM binding
    // (`passkey_cose_es256`) accepts arbitrary bytes from JS — without
    // this check, a confused popup could attest a non-curve point and
    // poison a user's stored credential with one no signature would
    // ever match.
    use p256::ecdsa::VerifyingKey;
    use p256::EncodedPoint;
    let point = EncodedPoint::from_bytes(sec1_uncompressed)
        .map_err(|e| Error::InvalidEncoding(format!("SEC1 decode failed: {e}")))?;
    let _vk = VerifyingKey::from_encoded_point(&point)
        .map_err(|_| Error::InvalidEncoding("SEC1 point is not on the P-256 curve".into()))?;

    let x = &sec1_uncompressed[1..33];
    let y = &sec1_uncompressed[33..65];

    // Length: map header (1) + 3 small int pairs (2+2+2) + 2 bytestring pairs
    // each (key=1 + bstr_header=2 + 32) = 1 + 6 + 70 = 77
    let mut out = Vec::with_capacity(77);
    out.push(0xa5); // map(5)

    // 1: 2  (kty: EC2)
    out.push(0x01);
    out.push(0x02);
    // 3: -7 (alg: ES256). Negative int encoded as 0x20 | (|n| - 1).
    out.push(0x03);
    out.push(0x26); // -7 = 0x20 | 6
                    // -1: 1 (crv: P-256)
    out.push(0x20); // -1
    out.push(0x01);
    // -2: <x>
    out.push(0x21); // -2
    out.push(0x58); // bytes(1-byte length follows)
    out.push(0x20); // 32
    out.extend_from_slice(x);
    // -3: <y>
    out.push(0x22); // -3
    out.push(0x58);
    out.push(0x20);
    out.extend_from_slice(y);

    Ok(out)
}

/// One stored passkey. Lives inside a login cipher's plaintext payload as
/// `login.fido2Credentials: [Fido2Credential, ...]`. Field names mirror
/// Bitwarden's wire shape so an export from Hekate could be re-imported by
/// Bitwarden (and vice-versa) with a trivial projection.
///
/// Everything here is plaintext from this module's perspective — the cipher
/// PCK envelope handles confidentiality + integrity for the whole record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Fido2Credential {
    /// Opaque credential handle the RP uses to reference this passkey.
    /// base64url, no padding; 16 bytes from [`generate_p256_keypair`].
    pub credential_id: String,
    /// Always `"public-key"` per the WebAuthn spec; kept as a field so
    /// future credential types can extend the array without a schema bump.
    pub key_type: String,
    /// Always `"ECDSA"` for v1 (we only ship P-256). Bitwarden's shape.
    pub key_algorithm: String,
    /// Always `"P-256"` for v1. Bitwarden's shape.
    pub key_curve: String,
    /// Base64-encoded PKCS#8 DER. Sensitive once decrypted — caller owns
    /// zeroization after extracting for a sign operation.
    pub key_value: String,
    /// Relying party identifier, e.g. `"webauthn.io"`. Authenticator
    /// binds this into every signed assertion (anti-phishing).
    pub rp_id: String,
    /// Opaque handle the RP gave us at registration. base64url, no padding.
    pub user_handle: String,
    /// User name the RP suggested at registration (e.g. an email).
    pub user_name: String,
    /// Sign counter. WebAuthn says authenticators MAY return 0 if they
    /// don't track it; we currently always return 0 (sync'd credentials
    /// can't honestly increment a counter without coordinating across
    /// devices, and most RPs accept 0). Stored as string to match
    /// Bitwarden's wire shape.
    #[serde(default = "zero_counter")]
    pub counter: String,
    /// Friendly RP name the RP advertised at registration.
    #[serde(default)]
    pub rp_name: String,
    /// Friendly user name the RP advertised at registration.
    #[serde(default)]
    pub user_display_name: String,
    /// "true" if the credential is client-side discoverable (resident key
    /// — usable for usernameless sign-in). "false" otherwise. String to
    /// match Bitwarden.
    #[serde(default = "false_str")]
    pub discoverable: String,
    /// When the credential was created. Round-trips via RFC 3339.
    pub creation_date: DateTime<Utc>,
}

fn zero_counter() -> String {
    "0".to_string()
}
fn false_str() -> String {
    "false".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::EncodedPoint;

    #[test]
    fn keygen_emits_pkcs8_and_sec1_pubkey() {
        let kp = generate_p256_keypair().unwrap();
        let pkcs8 = B64.decode(kp.private_pkcs8_b64.as_bytes()).unwrap();
        // PKCS#8 v1 SEQUENCE tag is 0x30 (constructed SEQUENCE).
        assert_eq!(pkcs8[0], 0x30, "pkcs8 should start with SEQUENCE tag");
        let sec1 = B64.decode(&kp.public_sec1_b64).unwrap();
        assert_eq!(sec1.len(), 65, "uncompressed SEC1 is 65 bytes");
        assert_eq!(sec1[0], 0x04, "uncompressed SEC1 prefix is 0x04");
        // credential_id is 16 bytes, base64url-no-pad → 22 chars.
        assert_eq!(kp.credential_id_b64url.len(), 22);
    }

    #[test]
    fn keygen_yields_distinct_keypairs() {
        let a = generate_p256_keypair().unwrap();
        let b = generate_p256_keypair().unwrap();
        assert_ne!(a.private_pkcs8_b64.as_str(), b.private_pkcs8_b64.as_str());
        assert_ne!(a.public_sec1_b64, b.public_sec1_b64);
        assert_ne!(a.credential_id_b64url, b.credential_id_b64url);
    }

    #[test]
    fn sign_roundtrips_through_pkcs8_and_verifies_against_pubkey() {
        let kp = generate_p256_keypair().unwrap();
        let msg = b"authenticatorData || sha256(clientDataJSON) goes here";
        let der = sign_p256(&kp.private_pkcs8_b64, msg).unwrap();
        let sig = Signature::from_der(&der).unwrap();

        // Reconstruct the verifying key from the SEC1 pubkey we exposed
        // and confirm the signature checks out — proves the pubkey we
        // hand to the RP genuinely matches the private key we kept.
        let sec1 = B64.decode(&kp.public_sec1_b64).unwrap();
        let point = EncodedPoint::from_bytes(&sec1).unwrap();
        let verifier = VerifyingKey::from_encoded_point(&point).unwrap();
        verifier.verify(msg, &sig).expect("signature must verify");
    }

    #[test]
    fn sign_rejects_garbage_pkcs8() {
        let err = sign_p256("not-base64!!", b"x").unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(_)));
        let err = sign_p256(&B64.encode(b"not-pkcs8"), b"x").unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(_)));
    }

    #[test]
    fn fido2_credential_roundtrips_through_serde_with_camelcase() {
        let cred = Fido2Credential {
            credential_id: "abc123".to_string(),
            key_type: "public-key".to_string(),
            key_algorithm: "ECDSA".to_string(),
            key_curve: "P-256".to_string(),
            key_value: "BASE64PKCS8==".to_string(),
            rp_id: "webauthn.io".to_string(),
            user_handle: "userhandlebytes".to_string(),
            user_name: "alice@example.com".to_string(),
            counter: "0".to_string(),
            rp_name: "WebAuthn.io".to_string(),
            user_display_name: "Alice".to_string(),
            discoverable: "true".to_string(),
            creation_date: DateTime::parse_from_rfc3339("2026-05-06T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        let json = serde_json::to_string(&cred).unwrap();
        // Spot-check that camelCase actually fired — the popup + WASM
        // glue depends on these exact field names.
        assert!(json.contains("\"credentialId\":\"abc123\""));
        assert!(json.contains("\"keyAlgorithm\":\"ECDSA\""));
        assert!(json.contains("\"rpId\":\"webauthn.io\""));
        assert!(json.contains("\"userHandle\":\"userhandlebytes\""));
        assert!(json.contains("\"userDisplayName\":\"Alice\""));
        let back: Fido2Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cred);
    }

    #[test]
    fn cose_es256_encoding_is_77_bytes_with_correct_header() {
        let kp = generate_p256_keypair().unwrap();
        let sec1 = B64.decode(&kp.public_sec1_b64).unwrap();
        let cose = cose_es256_pubkey(&sec1).unwrap();
        assert_eq!(cose.len(), 77, "ES256 COSE_Key is fixed at 77 bytes");
        assert_eq!(cose[0], 0xa5, "map(5) header");
        // First two pairs: kty=2, alg=-7
        assert_eq!(&cose[1..5], &[0x01, 0x02, 0x03, 0x26]);
        // crv=1 pair
        assert_eq!(&cose[5..7], &[0x20, 0x01]);
        // X coord: header (-2, bstr(32))
        assert_eq!(&cose[7..10], &[0x21, 0x58, 0x20]);
        assert_eq!(&cose[10..42], &sec1[1..33]);
        // Y coord: header (-3, bstr(32))
        assert_eq!(&cose[42..45], &[0x22, 0x58, 0x20]);
        assert_eq!(&cose[45..77], &sec1[33..65]);
    }

    #[test]
    fn cose_rejects_off_curve_sec1_point() {
        // Audit M-2 regression: a 65-byte SEC1-shaped buffer with the
        // 0x04 prefix that's *not* on the P-256 curve must be rejected.
        // Use all-zero x,y (off-curve trivially) and an arbitrary
        // not-on-curve x,y to be thorough.
        let mut bad = vec![0u8; 65];
        bad[0] = 0x04;
        let err = cose_es256_pubkey(&bad).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(_)));

        // x = 0x01.., y = 0x02.. — random-looking but off-curve.
        let mut bad2 = vec![0x04u8; 65];
        bad2[1..33].copy_from_slice(&[0x11; 32]);
        bad2[33..65].copy_from_slice(&[0x22; 32]);
        let err = cose_es256_pubkey(&bad2).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(_)));
    }

    #[test]
    fn cose_rejects_wrong_sec1_length_or_prefix() {
        // Wrong length
        let err = cose_es256_pubkey(&[0u8; 64]).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(_)));
        // Right length, wrong prefix (compressed-form 0x02 instead of 0x04)
        let mut bad = vec![0x02u8; 65];
        bad[0] = 0x02;
        let err = cose_es256_pubkey(&bad).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(_)));
    }

    #[test]
    fn sign_assertion_binds_rp_id_inside_rust() {
        // Audit M-3 regression: the helper builds authenticatorData
        // Rust-side from the rp_id string, then signs (authData ||
        // client_data_hash). A verifier that re-derives sha256(rpId)
        // and re-builds authData must get the same signed message.
        use sha2::{Digest, Sha256};
        let kp = generate_p256_keypair().unwrap();
        let rp_id = "webauthn.io";
        let flags = 0x05; // UP | UV
        let sign_count = 0u32;
        let client_data_hash = [0xab; 32];
        let (auth_data, sig_der) = sign_assertion(
            &kp.private_pkcs8_b64,
            rp_id,
            flags,
            sign_count,
            &client_data_hash,
        )
        .unwrap();

        assert_eq!(auth_data.len(), 37, "authData = 32 + 1 + 4 bytes");
        let expected_rp_hash = Sha256::digest(rp_id.as_bytes());
        assert_eq!(&auth_data[0..32], expected_rp_hash.as_slice());
        assert_eq!(auth_data[32], flags);
        assert_eq!(&auth_data[33..37], &sign_count.to_be_bytes());

        // Verify the sig against the recombined message.
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        use p256::EncodedPoint;
        let mut msg = auth_data.clone();
        msg.extend_from_slice(&client_data_hash);
        let sec1 = B64.decode(&kp.public_sec1_b64).unwrap();
        let point = EncodedPoint::from_bytes(&sec1).unwrap();
        let verifier = VerifyingKey::from_encoded_point(&point).unwrap();
        let sig = Signature::from_der(&sig_der).unwrap();
        verifier
            .verify(&msg, &sig)
            .expect("assertion sig must verify");
    }

    #[test]
    fn sign_assertion_rejects_wrong_client_data_hash_length() {
        let kp = generate_p256_keypair().unwrap();
        let err = sign_assertion(&kp.private_pkcs8_b64, "x.test", 0x05, 0, &[0u8; 16]).unwrap_err();
        assert!(matches!(err, Error::InvalidEncoding(_)));
    }

    #[test]
    fn hekate_aaguid_is_well_formed_uuidv4() {
        let a = HEKATE_AAGUID;
        // Version nibble (high nibble of byte 6) must be 4 for v4.
        assert_eq!(a[6] >> 4, 0x4, "AAGUID byte 6 high nibble must be 4");
        // Variant nibble (high nibble of byte 8) must be 8/9/a/b
        // (RFC 4122). Ours is `a`.
        let variant = a[8] >> 4;
        assert!(
            (0x8..=0xb).contains(&variant),
            "AAGUID byte 8 high nibble must be 8..=b, got {variant:x}"
        );
        // ASCII prefix: "Hekate" (the memorable bit). If someone
        // accidentally bumps the constant, this catches it.
        assert_eq!(&a[0..6], b"Hekate");
        // And the trailing nonzero byte (serial=1).
        assert_eq!(a[15], 0x01);
    }

    #[test]
    fn fido2_credential_defaults_fill_in_optional_fields() {
        // Older clients that haven't been updated yet may omit the newer
        // optional fields. Defaults must keep deserialization working.
        let json = serde_json::json!({
            "credentialId": "abc",
            "keyType": "public-key",
            "keyAlgorithm": "ECDSA",
            "keyCurve": "P-256",
            "keyValue": "k",
            "rpId": "x.test",
            "userHandle": "u",
            "userName": "alice",
            "creationDate": "2026-05-06T12:00:00Z"
        });
        let cred: Fido2Credential = serde_json::from_value(json).unwrap();
        assert_eq!(cred.counter, "0");
        assert_eq!(cred.rp_name, "");
        assert_eq!(cred.user_display_name, "");
        assert_eq!(cred.discoverable, "false");
    }
}
