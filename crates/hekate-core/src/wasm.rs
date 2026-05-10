//! WebAssembly bindings — exposed to JavaScript / TypeScript callers
//! (browser extension, web vault). Thin wrapper around the public Rust
//! API; the JS side gets `Uint8Array`s in/out and JSON objects for the
//! parameter struct.
//!
//! Build with:
//!
//! ```bash
//! cargo build --release --target wasm32-unknown-unknown -p hekate-core
//! wasm-bindgen --target web --out-dir dist/wasm \
//!     target/wasm32-unknown-unknown/release/hekate_core.wasm
//! ```
//!
//! See `make wasm` for the canonical recipe.

use wasm_bindgen::prelude::*;

use crate::{
    encstring::EncString,
    kdf::{
        compute_kdf_bind_mac as core_compute_kdf_bind_mac,
        derive_kdf_bind_key as core_derive_kdf_bind_key,
        derive_master_key as core_derive_master_key,
        derive_master_password_hash as core_derive_master_password_hash,
        derive_stretched_master_key as core_derive_stretched_master_key,
        verify_kdf_bind_mac as core_verify_kdf_bind_mac, KdfParams,
    },
    keypair,
    manifest::{
        compute_attachments_root as core_compute_attachments_root,
        derive_account_signing_seed as core_derive_signing_seed,
        verifying_key_from_seed as core_verifying_key_from_seed, AttachmentTuple, ManifestEntry,
        VaultManifest, ATTACHMENTS_ROOT_LEN, NO_ATTACHMENTS_ROOT,
    },
};
use ed25519_dalek::{Signature, Verifier};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

fn js_err(msg: impl ToString) -> JsValue {
    JsValue::from_str(&msg.to_string())
}

fn key32(bytes: &[u8]) -> Result<[u8; 32], JsValue> {
    if bytes.len() != 32 {
        return Err(js_err(format!(
            "expected 32-byte key, got {} bytes",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Derive the 32-byte master key from a password + KDF params + salt.
/// `kdf_params` is a JS object like
/// `{alg: "argon2id", m_kib: 131072, t: 3, p: 4}`.
#[wasm_bindgen(js_name = deriveMasterKey)]
pub fn derive_master_key(
    password: &[u8],
    kdf_params: JsValue,
    salt: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let params: KdfParams = serde_wasm_bindgen::from_value(kdf_params).map_err(js_err)?;
    let mk = core_derive_master_key(password, params, salt).map_err(js_err)?;
    Ok(mk.to_vec())
}

/// HKDF-Expand the master key into the 32-byte master_password_hash
/// the server expects.
#[wasm_bindgen(js_name = deriveMasterPasswordHash)]
pub fn derive_master_password_hash(master_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mk_bytes = key32(master_key)?;
    let mut wrapped = zeroize::Zeroizing::new([0u8; 32]);
    wrapped.copy_from_slice(&mk_bytes);
    Ok(core_derive_master_password_hash(&wrapped).to_vec())
}

/// HKDF-Expand the master key into the 32-byte stretched master key
/// used to wrap the account key.
#[wasm_bindgen(js_name = deriveStretchedMasterKey)]
pub fn derive_stretched_master_key(master_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mk_bytes = key32(master_key)?;
    let mut wrapped = zeroize::Zeroizing::new([0u8; 32]);
    wrapped.copy_from_slice(&mk_bytes);
    Ok(core_derive_stretched_master_key(&wrapped).to_vec())
}

/// Compute the 32-byte HMAC-SHA256 binding MAC over (params, salt). The
/// caller passes the master key bytes; we derive the bind subkey internally
/// so the JS side never sees it.
#[wasm_bindgen(js_name = computeKdfBindMac)]
pub fn compute_kdf_bind_mac(
    master_key: &[u8],
    kdf_params: JsValue,
    salt: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let mk_bytes = key32(master_key)?;
    let mut wrapped = zeroize::Zeroizing::new([0u8; 32]);
    wrapped.copy_from_slice(&mk_bytes);
    let bind_key = core_derive_kdf_bind_key(&wrapped);
    let params: KdfParams = serde_wasm_bindgen::from_value(kdf_params).map_err(js_err)?;
    Ok(core_compute_kdf_bind_mac(&bind_key, params, salt).to_vec())
}

/// Verify a 32-byte HMAC-SHA256 binding MAC. Returns `true` iff `tag`
/// matches the canonical (params, salt) MAC under the master key. The
/// browser extension MUST call this on the prelogin response and refuse to
/// send the master_password_hash if it returns `false`.
#[wasm_bindgen(js_name = verifyKdfBindMac)]
pub fn verify_kdf_bind_mac(
    master_key: &[u8],
    kdf_params: JsValue,
    salt: &[u8],
    tag: &[u8],
) -> Result<bool, JsValue> {
    let mk_bytes = key32(master_key)?;
    let mut wrapped = zeroize::Zeroizing::new([0u8; 32]);
    wrapped.copy_from_slice(&mk_bytes);
    let bind_key = core_derive_kdf_bind_key(&wrapped);
    let params: KdfParams = serde_wasm_bindgen::from_value(kdf_params).map_err(js_err)?;
    Ok(core_verify_kdf_bind_mac(&bind_key, params, salt, tag))
}

/// Returns `true` iff the supplied KDF params are at or above the
/// client-enforced safety floor (m≥64MiB, t≥2, p≥1, with sanity caps).
/// Browser extension MUST refuse to derive the master key when this is
/// `false`, even if the server-supplied bind MAC verifies.
#[wasm_bindgen(js_name = kdfParamsAreSafe)]
pub fn kdf_params_are_safe(kdf_params: JsValue) -> Result<bool, JsValue> {
    let params: KdfParams = serde_wasm_bindgen::from_value(kdf_params).map_err(js_err)?;
    Ok(params.is_safe())
}

/// XChaCha20-Poly1305 encrypt; returns the EncString v3 wire form.
#[wasm_bindgen(js_name = encStringEncryptXc20p)]
pub fn encstring_encrypt_xc20p(
    key_id: &str,
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<String, JsValue> {
    let k = key32(key)?;
    EncString::encrypt_xc20p(key_id, &k, plaintext, aad)
        .map(|e| e.to_wire())
        .map_err(js_err)
}

/// XChaCha20-Poly1305 decrypt + verify. Pass `null`/`undefined` for
/// `expected_aad` to accept any AAD value embedded in the envelope.
#[wasm_bindgen(js_name = encStringDecryptXc20p)]
pub fn encstring_decrypt_xc20p(
    wire: &str,
    key: &[u8],
    expected_aad: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    let k = key32(key)?;
    let s = EncString::parse(wire).map_err(js_err)?;
    s.decrypt_xc20p(&k, expected_aad.as_deref()).map_err(js_err)
}

/// X25519 keypair. `secret` and `public` are both 32 bytes.
#[wasm_bindgen]
pub struct KeyPair {
    secret: Vec<u8>,
    public: Vec<u8>,
}

#[wasm_bindgen]
impl KeyPair {
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Vec<u8> {
        self.secret.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> Vec<u8> {
        self.public.clone()
    }
}

#[wasm_bindgen(js_name = generateX25519)]
pub fn generate_x25519() -> KeyPair {
    let (secret, public) = keypair::generate_x25519();
    KeyPair {
        secret: secret.to_vec(),
        public: public.to_vec(),
    }
}

/// 32 fresh random bytes from `crypto.getRandomValues()`. Use this for
/// per-cipher keys, account keys, and other CSPRNG-sourced secrets.
#[wasm_bindgen(js_name = randomKey32)]
pub fn random_key_32() -> Vec<u8> {
    keypair::random_key_32().to_vec()
}

/// Returns the package version string. Useful for runtime checks that
/// the JS side and the WASM blob are in sync.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ===========================================================================
// Vault manifest (BW04 set-level integrity)
// ===========================================================================
//
// JS works with a plain object shape: `{version, timestamp, entries: [{
// cipherId, revisionDate, deleted}]}`. The WASM helpers convert that to
// the canonical Rust `VaultManifest`, which controls the on-the-wire
// canonical-bytes encoding (see `hekate-core::manifest`).

/// Wire-shape mirror used solely for serde_wasm_bindgen on the JS object.
/// Keeps JS callers idiomatic (camelCase) while the Rust core uses
/// snake_case. Round-trips through a transformation step.
#[derive(Debug, Serialize, Deserialize)]
struct JsManifest {
    version: u64,
    timestamp: String,
    /// 32 raw bytes carrying the parent canonical SHA-256. JS sends this
    /// as a `Uint8Array`; serde_wasm_bindgen surfaces it as `Vec<u8>`.
    /// All zeros for the genesis (version 1) manifest.
    #[serde(rename = "parentCanonicalSha256")]
    parent_canonical_sha256: Vec<u8>,
    entries: Vec<JsEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsEntry {
    #[serde(rename = "cipherId")]
    cipher_id: String,
    #[serde(rename = "revisionDate")]
    revision_date: String,
    deleted: bool,
    /// 32-byte SHA-256 of the cipher's sorted attachment tuples (M2.24).
    /// Optional in JS for back-compat with older popup builds — when
    /// absent, defaults to the all-zero "no attachments" sentinel.
    /// JS callers that want to bind attachment integrity into the
    /// signed manifest pass this as a `Uint8Array(32)`; everyone else
    /// can leave it off.
    #[serde(default, rename = "attachmentsRoot")]
    attachments_root: Option<Vec<u8>>,
}

impl TryFrom<JsManifest> for VaultManifest {
    type Error = JsValue;
    fn try_from(m: JsManifest) -> std::result::Result<Self, JsValue> {
        if m.parent_canonical_sha256.len() != 32 {
            return Err(js_err(format!(
                "parentCanonicalSha256 must be 32 bytes, got {}",
                m.parent_canonical_sha256.len()
            )));
        }
        let mut parent = [0u8; 32];
        parent.copy_from_slice(&m.parent_canonical_sha256);
        Ok(VaultManifest {
            version: m.version,
            timestamp: m.timestamp,
            parent_canonical_sha256: parent,
            entries: m
                .entries
                .into_iter()
                .map(|e| {
                    let attachments_root = match e.attachments_root {
                        Some(bytes) if bytes.len() == ATTACHMENTS_ROOT_LEN => {
                            let mut a = [0u8; ATTACHMENTS_ROOT_LEN];
                            a.copy_from_slice(&bytes);
                            Ok(a)
                        }
                        Some(bytes) => Err(js_err(format!(
                            "attachmentsRoot must be {ATTACHMENTS_ROOT_LEN} bytes, got {}",
                            bytes.len()
                        ))),
                        None => Ok(NO_ATTACHMENTS_ROOT),
                    }?;
                    Ok::<ManifestEntry, JsValue>(ManifestEntry {
                        cipher_id: e.cipher_id,
                        revision_date: e.revision_date,
                        deleted: e.deleted,
                        attachments_root,
                    })
                })
                .collect::<std::result::Result<Vec<_>, _>>()?,
        })
    }
}

impl From<VaultManifest> for JsManifest {
    fn from(m: VaultManifest) -> Self {
        JsManifest {
            version: m.version,
            timestamp: m.timestamp,
            parent_canonical_sha256: m.parent_canonical_sha256.to_vec(),
            entries: m
                .entries
                .into_iter()
                .map(|e| JsEntry {
                    cipher_id: e.cipher_id,
                    revision_date: e.revision_date,
                    deleted: e.deleted,
                    attachments_root: Some(e.attachments_root.to_vec()),
                })
                .collect(),
        }
    }
}

/// Derive the 32-byte Ed25519 seed from the master key. This is the same
/// HKDF subkey the Rust CLI uses (`pmgr-sign-v1` info tag), so a popup
/// and a CLI logged in to the same account derive identical signing keys.
#[wasm_bindgen(js_name = deriveAccountSigningSeed)]
pub fn derive_account_signing_seed(master_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mk_bytes = key32(master_key)?;
    let mut wrapped = Zeroizing::new([0u8; 32]);
    wrapped.copy_from_slice(&mk_bytes);
    let seed = core_derive_signing_seed(&wrapped);
    Ok(seed.to_vec())
}

/// Compute the 32-byte Ed25519 verifying (public) key from a seed.
#[wasm_bindgen(js_name = verifyingKeyFromSeed)]
pub fn verifying_key_from_seed(seed: &[u8]) -> Result<Vec<u8>, JsValue> {
    let s = key32(seed)?;
    let mut wrapped = Zeroizing::new([0u8; 32]);
    wrapped.copy_from_slice(&s);
    Ok(core_verifying_key_from_seed(&wrapped).as_bytes().to_vec())
}

/// Output of `signManifestCanonical`. JS sees both fields as `Uint8Array`.
#[wasm_bindgen]
pub struct SignedManifestBytes {
    canonical: Vec<u8>,
    signature: Vec<u8>,
}

#[wasm_bindgen]
impl SignedManifestBytes {
    /// The canonical bytes that were signed (length-prefixed, see
    /// `hekate-core::manifest`). Upload this base64-encoded as
    /// `canonical_b64`.
    #[wasm_bindgen(getter, js_name = canonicalBytes)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical.clone()
    }
    /// The 64-byte Ed25519 signature. Upload base64-encoded as
    /// `signature_b64`.
    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

/// Sign a manifest object. Sorts entries deterministically, builds the
/// canonical bytes, signs with the seed, and returns both the canonical
/// bytes (so the caller can upload them) and the 64-byte signature.
///
/// `manifest_obj` shape: `{version, timestamp, entries: [{cipherId,
/// revisionDate, deleted}]}`.
#[wasm_bindgen(js_name = signManifestCanonical)]
pub fn sign_manifest_canonical(
    seed: &[u8],
    manifest_obj: JsValue,
) -> Result<SignedManifestBytes, JsValue> {
    let s = key32(seed)?;
    let mut wrapped = Zeroizing::new([0u8; 32]);
    wrapped.copy_from_slice(&s);

    let js_manifest: JsManifest = serde_wasm_bindgen::from_value(manifest_obj).map_err(js_err)?;
    let mut manifest: VaultManifest = js_manifest.try_into()?;
    manifest.sort_entries();
    let canonical = manifest.canonical_bytes();
    let sk = crate::manifest::signing_key_from_seed(&wrapped);
    use ed25519_dalek::Signer;
    let sig = sk.sign(&canonical);
    Ok(SignedManifestBytes {
        canonical,
        signature: sig.to_bytes().to_vec(),
    })
}

/// Verify an Ed25519 signature over the canonical manifest bytes under
/// the *expected* pubkey, then parse the canonical bytes back into a
/// JS-native manifest object. Throws on invalid signature or malformed
/// canonical bytes.
#[wasm_bindgen(js_name = verifyManifestSignature)]
pub fn verify_manifest_signature(
    expected_pubkey: &[u8],
    canonical_bytes: &[u8],
    signature: &[u8],
) -> Result<JsValue, JsValue> {
    if expected_pubkey.len() != 32 {
        return Err(js_err("expected_pubkey must be 32 bytes"));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(expected_pubkey);
    let pubkey = ed25519_dalek::VerifyingKey::from_bytes(&pk)
        .map_err(|e| js_err(format!("invalid pubkey: {e}")))?;
    let sig = Signature::from_slice(signature).map_err(js_err)?;
    // Audit H-2 (2026-05-07): verify_strict rejects non-canonical sig
    // scalars + small-order R points. The WASM caller is the same
    // popup/web-vault path that decodes manifests, so this matches
    // the Rust-side `manifest::SignedManifest::verify` contract.
    pubkey
        .verify_strict(canonical_bytes, &sig)
        .map_err(|_| js_err("signature did not verify"))?;

    let parsed = crate::manifest::decode_canonical(canonical_bytes).map_err(js_err)?;
    let js_manifest: JsManifest = parsed.into();
    serde_wasm_bindgen::to_value(&js_manifest).map_err(js_err)
}

// ===========================================================================
// M2.24 — attachments (chunked-AEAD body encryption)
// ===========================================================================

/// Encrypt an attachment body in the PMGRA1 chunked-AEAD format. JS
/// passes the raw plaintext bytes; gets back the full ciphertext
/// (header + per-chunk AEAD blocks). For very large files the popup
/// should switch to the streaming `Encryptor` API in a follow-up;
/// the one-shot variant is fine for the M2.24 100 MiB cap.
#[wasm_bindgen(js_name = attachmentEncrypt)]
pub fn attachment_encrypt(
    att_key: &[u8],
    attachment_id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let k = key32(att_key)?;
    crate::attachment::encrypt(&k, attachment_id.as_bytes(), plaintext).map_err(js_err)
}

/// Decrypt + verify an attachment body. Throws on header / tag /
/// truncation / reorder failures.
#[wasm_bindgen(js_name = attachmentDecrypt)]
pub fn attachment_decrypt(
    att_key: &[u8],
    attachment_id: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let k = key32(att_key)?;
    crate::attachment::decrypt(&k, attachment_id.as_bytes(), ciphertext).map_err(js_err)
}

/// BLAKE3 of arbitrary bytes, returned as base64-no-pad.
/// Server's tus finalize verifies against this — the popup uses it
/// to fill in `Upload-Metadata: content_hash_b3=...`.
#[wasm_bindgen(js_name = blake3HashB64)]
pub fn blake3_hash_b64(bytes: &[u8]) -> String {
    crate::attachment::content_hash_b3(bytes)
}

/// Exact ciphertext byte count for a given plaintext length.
/// Server's tus creation refuses uploads where `Upload-Length` !=
/// `ciphertext_size_for(size_pt)`, so the popup pre-computes it.
#[wasm_bindgen(js_name = attachmentCiphertextSize)]
pub fn attachment_ciphertext_size(plaintext_size: u64) -> u64 {
    crate::attachment::ciphertext_size_for(plaintext_size)
}

/// AAD for the wrapped per-attachment AEAD key. Bound to the
/// (attachment_id, cipher_id) location so a server can't substitute
/// another attachment's wrapped key. Mirrors
/// `hekate-core::attachment::att_key_wrap_aad`.
#[wasm_bindgen(js_name = attachmentKeyWrapAad)]
pub fn attachment_key_wrap_aad(attachment_id: &str, cipher_id: &str) -> Vec<u8> {
    crate::attachment::att_key_wrap_aad(attachment_id, cipher_id)
}

/// Compute the per-cipher `attachments_root` from a JS-shaped array
/// `[{attachmentId, revisionDate, deleted}, ...]`. Empty input
/// returns the all-zero sentinel. Used by the popup's manifest
/// signing path to bind attachment integrity into the BW04 v3
/// canonical bytes.
#[wasm_bindgen(js_name = computeAttachmentsRoot)]
pub fn compute_attachments_root(tuples: JsValue) -> Result<Vec<u8>, JsValue> {
    #[derive(Deserialize)]
    struct JsTuple {
        #[serde(rename = "attachmentId")]
        attachment_id: String,
        #[serde(rename = "revisionDate")]
        revision_date: String,
        deleted: bool,
    }
    let parsed: Vec<JsTuple> = serde_wasm_bindgen::from_value(tuples).map_err(js_err)?;
    let core_tuples: Vec<AttachmentTuple> = parsed
        .into_iter()
        .map(|t| AttachmentTuple {
            attachment_id: t.attachment_id,
            revision_date: t.revision_date,
            deleted: t.deleted,
        })
        .collect();
    Ok(core_compute_attachments_root(&core_tuples).to_vec())
}

// ===========================================================================
// M2.25 — Send (HKDF-derived content key, URL-fragment encoding)
// ===========================================================================

/// Generate a fresh 32-byte send_key. Same shape as `randomKey32`;
/// distinct binding so JS callers can grep for the Send-specific
/// generation site.
#[wasm_bindgen(js_name = sendGenerateKey)]
pub fn send_generate_key() -> Vec<u8> {
    let k = crate::send::generate_send_key();
    k.to_vec()
}

/// Encode a send_key as URL-safe base64-no-pad (the form that goes
/// into the share URL fragment).
#[wasm_bindgen(js_name = sendEncodeKey)]
pub fn send_encode_key(send_key: &[u8]) -> Result<String, JsValue> {
    let k = key32(send_key)?;
    let mut wrapped = Zeroizing::new([0u8; 32]);
    wrapped.copy_from_slice(&k);
    Ok(crate::send::encode_send_key(&wrapped))
}

/// Decode a URL-safe base64-no-pad send_key. Throws on bad b64 or
/// non-32-byte payloads.
#[wasm_bindgen(js_name = sendDecodeKey)]
pub fn send_decode_key(s: &str) -> Result<Vec<u8>, JsValue> {
    crate::send::decode_send_key(s)
        .map(|k| k.to_vec())
        .map_err(js_err)
}

/// Encrypt a text Send under content_key = HKDF(send_key, salt=send_id).
/// Returns the EncString v3 wire string — the server stores this
/// verbatim as the `data` field. Mirrors
/// `hekate-core::send::encrypt_text`.
#[wasm_bindgen(js_name = sendEncryptText)]
pub fn send_encrypt_text(
    send_key: &[u8],
    send_id: &str,
    plaintext: &[u8],
) -> Result<String, JsValue> {
    let k = key32(send_key)?;
    let mut wrapped = Zeroizing::new([0u8; 32]);
    wrapped.copy_from_slice(&k);
    crate::send::encrypt_text(&wrapped, send_id, plaintext).map_err(js_err)
}

/// Decrypt a text Send. Used by the popup's "Open shared URL"
/// flow — the recipient extracts the send_key from the URL fragment
/// and HKDFs to the content key client-side.
#[wasm_bindgen(js_name = sendDecryptText)]
pub fn send_decrypt_text(send_key: &[u8], send_id: &str, wire: &str) -> Result<Vec<u8>, JsValue> {
    let k = key32(send_key)?;
    let mut wrapped = Zeroizing::new([0u8; 32]);
    wrapped.copy_from_slice(&k);
    crate::send::decrypt_text(&wrapped, send_id, wire).map_err(js_err)
}

/// AAD for the wrapped `protected_send_key` (the send_key wrapped
/// under the sender's account_key for sender-side list/edit).
#[wasm_bindgen(js_name = sendKeyWrapAad)]
pub fn send_key_wrap_aad(send_id: &str) -> Vec<u8> {
    crate::send::key_wrap_aad(send_id)
}

/// AAD for the sender-side `name` field on a Send (wrapped under the
/// account_key). Binds to `send_id` so two Sends' names can't be
/// swapped on the wire.
#[wasm_bindgen(js_name = sendNameAad)]
pub fn send_name_aad(send_id: &str) -> Vec<u8> {
    crate::send::name_aad(send_id)
}

// ===========================================================================
// M3.14a-d — signcryption + org roster (browser-extension write ops)
// ===========================================================================
//
// Each binding is a thin wrapper over the existing hekate-core APIs. JS
// passes Uint8Arrays for keys + receives JS objects for parsed
// structures. Verification failures throw `JsValue` so the popup's
// try/catch surfaces them as toast errors.

/// Sign-and-encrypt a payload for one recipient (M2.18 signcryption
/// envelope). Used by the popup when inviting a peer to an org —
/// the invite payload (org_sym_key + signing pubkey + role + bundle
/// sig) is sealed under the recipient's X25519 pubkey AND signed by
/// the sender's Ed25519 key.
///
/// `sender_signing_seed` is the 32-byte Ed25519 seed (HKDF-derived
/// from the sender's master key); JS passes the raw bytes. Returns
/// the `SealedEnvelope` JSON (camelCase keys via serde rename for
/// the popup; serde_wasm_bindgen handles the conversion).
#[wasm_bindgen(js_name = signcryptSealEnvelope)]
pub fn signcrypt_seal_envelope(
    sender_signing_seed: &[u8],
    sender_id: &str,
    recipient_id: &str,
    recipient_x25519_pubkey: &[u8],
    plaintext: &[u8],
) -> Result<JsValue, JsValue> {
    let seed = key32(sender_signing_seed)?;
    let mut wrapped = Zeroizing::new([0u8; 32]);
    wrapped.copy_from_slice(&seed);
    let signing_key = crate::manifest::signing_key_from_seed(&wrapped);

    let recipient_pk = key32(recipient_x25519_pubkey)?;
    let envelope = crate::signcrypt::sign_encrypt(
        &signing_key,
        sender_id,
        recipient_id,
        &recipient_pk,
        plaintext,
    )
    .map_err(js_err)?;
    serde_wasm_bindgen::to_value(&envelope).map_err(js_err)
}

/// Verify-and-decrypt a sealed envelope (recipient side). The
/// envelope object is the same JSON the server returns from
/// `GET /api/v1/account/invites`. Throws on signature mismatch or
/// AEAD failure.
#[wasm_bindgen(js_name = signcryptOpenEnvelope)]
pub fn signcrypt_open_envelope(
    envelope: JsValue,
    expected_sender_pubkey: &[u8],
    expected_recipient_id: &str,
    recipient_x25519_secret: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let env: crate::signcrypt::SealedEnvelope =
        serde_wasm_bindgen::from_value(envelope).map_err(js_err)?;
    if expected_sender_pubkey.len() != 32 {
        return Err(js_err("expected_sender_pubkey must be 32 bytes"));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(expected_sender_pubkey);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(js_err)?;
    let secret = key32(recipient_x25519_secret)?;
    crate::signcrypt::verify_decrypt(&env, &vk, expected_recipient_id, &secret).map_err(js_err)
}

/// Sign a self-signed pubkey bundle. The signed canonical bytes
/// commit to `(user_id || signing_pubkey || x25519_pubkey)` so the
/// signature is unforgeable without the user's signing key. Used
/// when registering a new account, when creating a new org (to
/// sign the org's pubkey bundle), and when re-signing after
/// account-key rotation.
#[wasm_bindgen(js_name = signPubkeyBundle)]
pub fn sign_pubkey_bundle(
    signing_seed: &[u8],
    user_id: &str,
    signing_pubkey: &[u8],
    x25519_pubkey: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let seed = key32(signing_seed)?;
    let mut wrapped = Zeroizing::new([0u8; 32]);
    wrapped.copy_from_slice(&seed);
    let signing_key = crate::manifest::signing_key_from_seed(&wrapped);
    let signing_pk = key32(signing_pubkey)?;
    let x25519_pk = key32(x25519_pubkey)?;
    Ok(
        crate::signcrypt::sign_pubkey_bundle(&signing_key, user_id, &signing_pk, &x25519_pk)
            .to_vec(),
    )
}

/// Verify a self-signed pubkey bundle. Returns `true` iff the 64-byte
/// `signature` is valid Ed25519 by `signing_pubkey` over the
/// canonical bytes. The popup uses this when invite-accepting (to
/// confirm the inviter's bundle hasn't been tampered) and when
/// fetching a peer's bundle for invite-send.
#[wasm_bindgen(js_name = verifyPubkeyBundle)]
pub fn verify_pubkey_bundle(
    user_id: &str,
    signing_pubkey: &[u8],
    x25519_pubkey: &[u8],
    signature: &[u8],
) -> Result<bool, JsValue> {
    let signing_pk = key32(signing_pubkey)?;
    let x25519_pk = key32(x25519_pubkey)?;
    if signature.len() != 64 {
        return Err(js_err("signature must be 64 bytes"));
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(signature);
    Ok(crate::signcrypt::verify_pubkey_bundle(user_id, &signing_pk, &x25519_pk, &sig).is_ok())
}

// ---- Org roster (M4.0 / BW08) ------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct JsOrgRoster {
    #[serde(rename = "orgId")]
    org_id: String,
    version: u64,
    /// 32 bytes; all-zero for the genesis (version=1) roster.
    #[serde(rename = "parentCanonicalSha256")]
    parent_canonical_sha256: Vec<u8>,
    timestamp: String,
    entries: Vec<JsOrgRosterEntry>,
    #[serde(rename = "orgSymKeyId")]
    org_sym_key_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsOrgRosterEntry {
    #[serde(rename = "userId")]
    user_id: String,
    role: String,
}

impl TryFrom<JsOrgRoster> for crate::org_roster::OrgRoster {
    type Error = JsValue;
    fn try_from(j: JsOrgRoster) -> std::result::Result<Self, JsValue> {
        if j.parent_canonical_sha256.len() != 32 {
            return Err(js_err(format!(
                "parentCanonicalSha256 must be 32 bytes, got {}",
                j.parent_canonical_sha256.len()
            )));
        }
        let mut parent = [0u8; 32];
        parent.copy_from_slice(&j.parent_canonical_sha256);
        Ok(crate::org_roster::OrgRoster {
            org_id: j.org_id,
            version: j.version,
            parent_canonical_sha256: parent,
            timestamp: j.timestamp,
            entries: j
                .entries
                .into_iter()
                .map(|e| crate::org_roster::OrgRosterEntry {
                    user_id: e.user_id,
                    role: e.role,
                })
                .collect(),
            org_sym_key_id: j.org_sym_key_id,
        })
    }
}

impl From<crate::org_roster::OrgRoster> for JsOrgRoster {
    fn from(r: crate::org_roster::OrgRoster) -> Self {
        JsOrgRoster {
            org_id: r.org_id,
            version: r.version,
            parent_canonical_sha256: r.parent_canonical_sha256.to_vec(),
            timestamp: r.timestamp,
            entries: r
                .entries
                .into_iter()
                .map(|e| JsOrgRosterEntry {
                    user_id: e.user_id,
                    role: e.role,
                })
                .collect(),
            org_sym_key_id: r.org_sym_key_id,
        }
    }
}

/// Sign an org roster with the org's Ed25519 signing key. Sorts
/// entries deterministically, builds the canonical bytes, signs.
/// Returns `{canonicalB64, signatureB64}` matching the
/// `SignedOrgRosterWire` server schema.
#[wasm_bindgen(js_name = signOrgRoster)]
pub fn sign_org_roster(signing_seed: &[u8], roster_obj: JsValue) -> Result<JsValue, JsValue> {
    let seed = key32(signing_seed)?;
    let mut wrapped = Zeroizing::new([0u8; 32]);
    wrapped.copy_from_slice(&seed);
    let signing_key = crate::manifest::signing_key_from_seed(&wrapped);
    let js: JsOrgRoster = serde_wasm_bindgen::from_value(roster_obj).map_err(js_err)?;
    let roster: crate::org_roster::OrgRoster = js.try_into()?;
    let signed = roster.sign(&signing_key);
    #[derive(Serialize)]
    struct Out {
        #[serde(rename = "canonicalB64")]
        canonical_b64: String,
        #[serde(rename = "signatureB64")]
        signature_b64: String,
    }
    serde_wasm_bindgen::to_value(&Out {
        canonical_b64: signed.canonical_b64,
        signature_b64: signed.signature_b64,
    })
    .map_err(js_err)
}

/// Verify an org roster signature under the *expected* signing
/// pubkey (from a TOFU pin / trusted source — the server-supplied
/// pubkey alone is not trusted). Throws on mismatch. On success
/// returns the parsed roster JSON.
#[wasm_bindgen(js_name = verifyOrgRoster)]
pub fn verify_org_roster(
    expected_pubkey: &[u8],
    canonical_b64: &str,
    signature_b64: &str,
) -> Result<JsValue, JsValue> {
    let pk = key32(expected_pubkey)?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(js_err)?;
    let signed = crate::org_roster::SignedOrgRoster {
        canonical_b64: canonical_b64.into(),
        signature_b64: signature_b64.into(),
    };
    let roster = signed.verify(&vk).map_err(js_err)?;
    serde_wasm_bindgen::to_value(&JsOrgRoster::from(roster)).map_err(js_err)
}

/// Parse already-verified canonical roster bytes. Useful when the
/// popup wants to read a roster's contents without re-verifying
/// (e.g. building the next version's parent_canonical_sha256).
#[wasm_bindgen(js_name = decodeOrgRosterCanonical)]
pub fn decode_org_roster_canonical(canonical: &[u8]) -> Result<JsValue, JsValue> {
    let roster = crate::org_roster::decode_canonical(canonical).map_err(js_err)?;
    serde_wasm_bindgen::to_value(&JsOrgRoster::from(roster)).map_err(js_err)
}

/// AAD for an org-collection's encrypted `name` field. Binds the
/// ciphertext to (collection_id, org_id). Mirrors the CLI's
/// `commands::org::collection_name_aad`.
#[wasm_bindgen(js_name = collectionNameAad)]
pub fn collection_name_aad(collection_id: &str, org_id: &str) -> Vec<u8> {
    crate::org_roster::collection_name_aad(collection_id, org_id)
}

/// Build the canonical bytes for a *user* pubkey bundle (binds
/// `user_id`, `signing_pubkey`, `x25519_pubkey`). The popup uses
/// this to compute peer fingerprints when pinning — same shape
/// `hekate peer fetch` produces on the CLI side.
#[wasm_bindgen(js_name = pubkeyBundleCanonicalBytes)]
pub fn pubkey_bundle_canonical_bytes(
    user_id: &str,
    signing_pubkey: &[u8],
    x25519_pubkey: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let s = key32(signing_pubkey)?;
    let x = key32(x25519_pubkey)?;
    Ok(crate::signcrypt::pubkey_bundle_canonical_bytes(
        user_id, &s, &x,
    ))
}

/// Build the canonical bytes for an org bundle. Exposed so the
/// popup can compute the bundle fingerprint (SHA-256 of these
/// bytes) when pinning an org locally without re-implementing
/// the layout.
#[wasm_bindgen(js_name = orgBundleCanonicalBytes)]
pub fn org_bundle_canonical_bytes(
    org_id: &str,
    name: &str,
    org_signing_pubkey: &[u8],
    owner_user_id: &str,
) -> Result<Vec<u8>, JsValue> {
    let pk = key32(org_signing_pubkey)?;
    Ok(crate::org_roster::org_bundle_canonical_bytes(
        org_id,
        name,
        &pk,
        owner_user_id,
    ))
}

/// Sign an org bundle (binds `org_id`, `name`, the org's signing
/// pubkey, and the owner's `user_id`) with the owner's account
/// signing seed. Returns the 64-byte signature. Mirrors the CLI's
/// `bundle_canonical_bytes` + sign step in M3.14b's `create_org`.
#[wasm_bindgen(js_name = signOrgBundle)]
pub fn sign_org_bundle(
    owner_signing_seed: &[u8],
    org_id: &str,
    name: &str,
    org_signing_pubkey: &[u8],
    owner_user_id: &str,
) -> Result<Vec<u8>, JsValue> {
    let seed = key32(owner_signing_seed)?;
    let mut wrapped = Zeroizing::new([0u8; 32]);
    wrapped.copy_from_slice(&seed);
    let signing_key = crate::manifest::signing_key_from_seed(&wrapped);
    let org_pk = key32(org_signing_pubkey)?;
    Ok(
        crate::org_roster::sign_org_bundle(&signing_key, org_id, name, &org_pk, owner_user_id)
            .to_vec(),
    )
}

/// Verify an org bundle signature under the *inviter's* (claimed
/// owner's) signing pubkey. Throws on mismatch.
#[wasm_bindgen(js_name = verifyOrgBundle)]
pub fn verify_org_bundle(
    inviter_signing_pubkey: &[u8],
    org_id: &str,
    name: &str,
    org_signing_pubkey: &[u8],
    owner_user_id: &str,
    signature: &[u8],
) -> Result<bool, JsValue> {
    let inviter_pk = key32(inviter_signing_pubkey)?;
    let inviter_vk = ed25519_dalek::VerifyingKey::from_bytes(&inviter_pk).map_err(js_err)?;
    let org_pk = key32(org_signing_pubkey)?;
    if signature.len() != 64 {
        return Err(js_err("signature must be 64 bytes"));
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(signature);
    Ok(crate::org_roster::verify_org_bundle(
        &inviter_vk,
        org_id,
        name,
        &org_pk,
        owner_user_id,
        &sig,
    )
    .is_ok())
}

/// SHA-256 of arbitrary bytes — exposed so the popup can compute
/// the `parent_canonical_sha256` field on the next-version roster.
#[wasm_bindgen(js_name = sha256)]
pub fn sha256(bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().to_vec()
}

/// Render `text` as a Quick Response (QR) code in the form of an
/// inline SVG string. Used by the popup to render TOTP enrollment
/// `otpauth://` URIs as something an authenticator app can scan;
/// most apps don't accept the URI as text and require a scan.
///
/// Encoding is constrained to a quiet zone of 4 modules (the QR
/// spec's recommended minimum) and an automatically chosen
/// error-correction level / version that fits the input. Returns
/// an error string for inputs longer than the largest QR version
/// can hold (~2.9 KB at low ECC).
#[wasm_bindgen(js_name = qrCodeSvg)]
pub fn qr_code_svg(text: &str) -> Result<String, JsValue> {
    let code = qrcode::QrCode::new(text.as_bytes())
        .map_err(|e| js_err(format!("qr encode failed: {e}")))?;
    let modules: Vec<Vec<bool>> = code
        .to_colors()
        .chunks(code.width())
        .map(|row| row.iter().map(|c| *c == qrcode::Color::Dark).collect())
        .collect();
    let n = code.width();
    let quiet = 4usize;
    let total = n + quiet * 2;

    // Build the SVG string by hand — no `image` / `resvg` deps.
    // `shape-rendering: crispEdges` ensures pixel-aligned modules
    // when the SVG is rendered at non-integer scales.
    let mut s = String::with_capacity(total * total * 8);
    // `r##"..."##` so `"#` inside the SVG (color values) doesn't
    // close the raw string literal early.
    s.push_str(&format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total} {total}" shape-rendering="crispEdges" preserveAspectRatio="xMidYMid meet"><rect width="{total}" height="{total}" fill="#ffffff"/>"##
    ));
    s.push_str(r##"<g fill="#000000">"##);
    for (y, row) in modules.iter().enumerate() {
        for (x, dark) in row.iter().enumerate() {
            if *dark {
                let px = x + quiet;
                let py = y + quiet;
                s.push_str(&format!(
                    r#"<rect x="{px}" y="{py}" width="1" height="1"/>"#
                ));
            }
        }
    }
    s.push_str("</g></svg>");
    Ok(s)
}

// ===========================================================================
// GH #1 — Hekate as passkey provider (browser extension surface)
// ===========================================================================
//
// The service worker registers the extension as a WebAuthn credential
// provider via `chrome.webAuthenticationProxy.attach()`. When a site
// invokes `navigator.credentials.{create,get}`, the SW dispatches to
// the popup for user approval, then calls these bindings to
// generate/sign with ECDSA-P256. Storage rides the existing cipher
// schema — passkeys live in the matching login cipher's plaintext
// payload as a `fido2Credentials: [...]` array (see
// `hekate-core::passkey::Fido2Credential`).

/// Generate a fresh ECDSA-P256 keypair + 16-byte credential_id. Returns
/// `{ privatePkcs8B64, publicSec1B64, credentialIdB64url }`. Caller is
/// expected to immediately wrap `privatePkcs8B64` inside the cipher PCK
/// envelope (the existing per-cipher key) and then drop the plaintext.
#[wasm_bindgen(js_name = passkeyGenerate)]
pub fn passkey_generate() -> Result<JsValue, JsValue> {
    let kp = crate::passkey::generate_p256_keypair().map_err(js_err)?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Out {
        private_pkcs8_b64: String,
        public_sec1_b64: String,
        credential_id_b64url: String,
    }
    serde_wasm_bindgen::to_value(&Out {
        // Move the Zeroizing<String> out as the response (immediately
        // crossing the WASM boundary; the JS side is responsible for
        // wrapping it under the cipher PCK before storing).
        private_pkcs8_b64: kp.private_pkcs8_b64.to_string(),
        public_sec1_b64: kp.public_sec1_b64,
        credential_id_b64url: kp.credential_id_b64url,
    })
    .map_err(js_err)
}

/// Sign `msg` with a P-256 PKCS#8 private key. `private_pkcs8_b64` is
/// what `passkeyGenerate` returned (and what the popup decrypts out of
/// the matching cipher's `fido2Credentials[i].keyValue` field). Returns
/// the DER-encoded ECDSA signature ready to drop into a WebAuthn
/// assertion.
///
/// Prefer [`passkey_sign_assertion`] for WebAuthn `get` flows — that
/// helper builds the authenticator-data block (rpId hash + flags +
/// signCount) Rust-side so the popup can't accidentally bind a
/// different rpId than the user approved.
#[wasm_bindgen(js_name = passkeySignP256)]
pub fn passkey_sign_p256(private_pkcs8_b64: &str, msg: &[u8]) -> Result<Vec<u8>, JsValue> {
    crate::passkey::sign_p256(private_pkcs8_b64, msg).map_err(js_err)
}

/// Sign a WebAuthn `get` assertion. Builds `authenticatorData =
/// sha256(rpId)(32) || flags(1) || signCount(4)` Rust-side, then signs
/// `authData || client_data_hash` with the supplied P-256 PKCS#8 key.
/// Returns `{ authenticatorData: Uint8Array(37), signature: Uint8Array }`
/// — the popup drops both verbatim into the response payload.
///
/// Audit M-3 (2026-05-07): rpId crosses the JS/WASM boundary as a
/// string, so the Rust side controls how it lands in the signed bytes.
/// The popup can no longer accidentally (or maliciously) bind a
/// different rpId than the user approved.
#[wasm_bindgen(js_name = passkeySignAssertion)]
pub fn passkey_sign_assertion(
    private_pkcs8_b64: &str,
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    client_data_hash: &[u8],
) -> Result<JsValue, JsValue> {
    let (authenticator_data, signature) = crate::passkey::sign_assertion(
        private_pkcs8_b64,
        rp_id,
        flags,
        sign_count,
        client_data_hash,
    )
    .map_err(js_err)?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Out {
        authenticator_data: Vec<u8>,
        signature: Vec<u8>,
    }
    serde_wasm_bindgen::to_value(&Out {
        authenticator_data,
        signature,
    })
    .map_err(js_err)
}

/// CBOR-encode an ES256 (P-256) public key as a COSE_Key map. Embedded
/// verbatim in WebAuthn's attestedCredentialData as the
/// `credentialPublicKey`. Input is the 65-byte uncompressed SEC1
/// encoding (`0x04 || x || y`) — same as the `publicSec1B64` decode
/// from `passkeyGenerate`. Output is always 77 bytes for P-256.
#[wasm_bindgen(js_name = passkeyCoseEs256)]
pub fn passkey_cose_es256(sec1_uncompressed: &[u8]) -> Result<Vec<u8>, JsValue> {
    crate::passkey::cose_es256_pubkey(sec1_uncompressed).map_err(js_err)
}
