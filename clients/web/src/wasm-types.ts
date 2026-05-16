/* Type shim for the wasm-bindgen output.
 *
 * The generated `.d.ts` file lives in `public/wasm/hekate_core.d.ts`
 * (copied there by `make web`) and isn't on the TypeScript
 * module-resolution path. This interface enumerates only the bindings
 * we actually call from the web vault, so TS stays strict without us
 * having to ship the giant generated declaration file.
 *
 * Keep this list in lock-step with `crates/hekate-core/src/wasm.rs`.
 * Add new entries as the SPA grows.
 */
/* Opaque KDF-params object from `/accounts/prelogin`. The WASM
 * `deriveMasterKey` / `kdfParamsAreSafe` / `verifyKdfBindMac` bindings
 * round-trip this through `serde_wasm_bindgen` on the Rust side, so
 * the JS layer never introspects it — we just pass the prelogin
 * response field through verbatim. Wire shape today is `{alg: "argon2id",
 * m_kib, t, p}` but the binding owns that contract; treat it as opaque.
 */
export type KdfParams = Record<string, unknown>;

export interface HekateCore {
  version(): string;

  // ---------------------------------------------------------------------
  // Send recipient flow (C.1)
  // ---------------------------------------------------------------------
  sendDecodeKey(b64: string): Uint8Array;
  sendDecryptText(
    sendKey: Uint8Array,
    sendId: string,
    ciphertext: string,
  ): Uint8Array;
  attachmentDecrypt(
    fileAeadKey: Uint8Array,
    attachmentId: string,
    ciphertext: Uint8Array,
  ): Uint8Array;

  // ---------------------------------------------------------------------
  // Send owner-side flow (C.4)
  // ---------------------------------------------------------------------

  /** Generate a fresh 32-byte send_key (CSPRNG). */
  sendGenerateKey(): Uint8Array;

  /** URL-safe base64 (no padding) of the send_key, for the URL fragment. */
  sendEncodeKey(sendKey: Uint8Array): string;

  /** Encrypt text payload under a send_key (HKDF-derives the AEAD
   *  content key internally). Returns the EncString wire form. */
  sendEncryptText(
    sendKey: Uint8Array,
    sendId: string,
    plaintext: Uint8Array,
  ): string;

  /** AAD bytes for wrapping the send_key under the account_key. */
  sendKeyWrapAad(sendId: string): Uint8Array;

  /** AAD bytes for wrapping the Send's display name under the account_key. */
  sendNameAad(sendId: string): Uint8Array;

  /** PMGRA1 chunked-AEAD encryption (used by file Sends + attachments). */
  attachmentEncrypt(
    fileAeadKey: Uint8Array,
    attachmentId: string,
    plaintext: Uint8Array,
  ): Uint8Array;

  /** AAD bytes for wrapping a per-attachment AEAD key under the cipher
   *  key. Format: `<attachment_id>|key|<cipher_id>`. Location-bound so
   *  a malicious server can't move a content_key onto a different
   *  attachment row. */
  attachmentKeyWrapAad(attachmentId: string, cipherId: string): Uint8Array;

  /** BLAKE3 hash of bytes, base64-no-pad. The server enforces this on
   *  tus finalize so a malicious client can't substitute different
   *  ciphertext during upload. */
  blake3HashB64(bytes: Uint8Array): string;

  // ---------------------------------------------------------------------
  // Login + key derivation (C.2)
  // ---------------------------------------------------------------------

  /** Refuses params below the safety floor (BW07/LP04 mitigation #1). */
  kdfParamsAreSafe(params: KdfParams): boolean;

  /** Argon2id master key. `password` is utf-8 bytes, `salt` is base64-decoded. */
  deriveMasterKey(
    password: Uint8Array,
    params: KdfParams,
    salt: Uint8Array,
  ): Uint8Array;

  /** HMAC verify the server-supplied bind MAC (BW07/LP04 mitigation #2). */
  verifyKdfBindMac(
    masterKey: Uint8Array,
    params: KdfParams,
    salt: Uint8Array,
    tag: Uint8Array,
  ): boolean;

  /** Compute the 32-byte HMAC-SHA256 binding MAC over (params, salt) under
   *  the master key's bind subkey. Used during change-password to bind the
   *  new salt+params to the new master key (BW07 mitigation). */
  computeKdfBindMac(
    masterKey: Uint8Array,
    params: KdfParams,
    salt: Uint8Array,
  ): Uint8Array;

  /** HKDF-Expand into the 32-byte master_password_hash sent to the server. */
  deriveMasterPasswordHash(masterKey: Uint8Array): Uint8Array;

  /** HKDF-Expand into the 32-byte stretched master key that wraps account_key. */
  deriveStretchedMasterKey(masterKey: Uint8Array): Uint8Array;

  /** Decrypt EncString v3 (XChaCha20-Poly1305). AAD bytes optional. */
  encStringDecryptXc20p(
    wire: string,
    key: Uint8Array,
    expectedAad?: Uint8Array,
  ): Uint8Array;

  /** Ed25519 signing seed (32 bytes) for the BW04 signed manifest path. */
  deriveAccountSigningSeed(masterKey: Uint8Array): Uint8Array;

  /** Ed25519 public key from a 32-byte signing seed. */
  verifyingKeyFromSeed(seed: Uint8Array): Uint8Array;

  // ---------------------------------------------------------------------
  // BW04 vault manifest verification (C.3a)
  // ---------------------------------------------------------------------

  /** Verify the signed vault manifest under the locally-pinned account
   *  signing pubkey. Returns the parsed manifest (`{version, timestamp,
   *  parentCanonicalSha256, entries}`) on success; throws on mismatch. */
  verifyManifestSignature(
    expectedPubkey: Uint8Array,
    canonicalBytes: Uint8Array,
    signature: Uint8Array,
  ): {
    version: number;
    timestamp: string;
    parentCanonicalSha256: Uint8Array;
    entries: Array<{ cipherId: string; revisionDate: string; deleted: boolean }>;
  };

  // ---------------------------------------------------------------------
  // Cipher write (C.3b) — encrypt + manifest sign
  // ---------------------------------------------------------------------

  /** 32 fresh random bytes from `crypto.getRandomValues()`. Used for
   *  per-cipher keys when creating a new cipher. */
  randomKey32(): Uint8Array;

  /** XChaCha20-Poly1305 encrypt → EncString v3 wire form. */
  encStringEncryptXc20p(
    keyId: string,
    key: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array,
  ): string;

  /** Sign a vault manifest object with an Ed25519 seed. Returns the
   *  canonical bytes + signature; the caller posts them to
   *  `/api/v1/vault/manifest`. */
  signManifestCanonical(
    seed: Uint8Array,
    manifest: {
      version: number;
      timestamp: string;
      parentCanonicalSha256: Uint8Array;
      entries: Array<{ cipherId: string; revisionDate: string; deleted: boolean }>;
    },
  ): {
    canonicalBytes: Uint8Array;
    signature: Uint8Array;
  };

  /** SHA-256 (used to compute the manifest parent hash). */
  sha256(bytes: Uint8Array): Uint8Array;

  // ---------------------------------------------------------------------
  // Orgs read-only (C.5)
  // ---------------------------------------------------------------------

  /** Parse the canonical roster bytes (sync.orgs[].roster.canonical_b64
   *  base64-decoded) without verifying the signature. Useful for
   *  member counts + role lists. C.6 will introduce TOFU pinning of
   *  the org signing pubkey, after which the signed-verify path
   *  becomes available. */
  decodeOrgRosterCanonical(canonical: Uint8Array): {
    orgId: string;
    version: number;
    parentCanonicalSha256: Uint8Array;
    timestamp: string;
    entries: Array<{ userId: string; role: string }>;
    orgSymKeyId: string;
  };

  // ---------------------------------------------------------------------
  // Peer pubkey bundles (C.7d-4)
  // ---------------------------------------------------------------------

  /** Canonical-encode (user_id, signing_pk, x25519_pk) into the bytes
   *  that get signed/hashed for fingerprint + bundle-self-sig
   *  verification. Matches `signcrypt::pubkey_bundle_canonical_bytes`. */
  pubkeyBundleCanonicalBytes(
    userId: string,
    signingPubkey: Uint8Array,
    x25519Pubkey: Uint8Array,
  ): Uint8Array;

  /** Verify the bundle's self-signature is a valid Ed25519 by
   *  `signing_pubkey` over the canonical bytes. Returns false on bad
   *  sig (does not throw). */
  verifyPubkeyBundle(
    userId: string,
    signingPubkey: Uint8Array,
    x25519Pubkey: Uint8Array,
    signature: Uint8Array,
  ): boolean;

  // ---------------------------------------------------------------------
  // Account registration (C.2b)
  // ---------------------------------------------------------------------

  /** Generate a fresh X25519 keypair via OsRng. `secret` and `public`
   *  are both 32-byte Uint8Arrays via the wasm-bindgen getter. The
   *  underlying `KeyPair` is opaque on the JS side. */
  generateX25519(): { readonly secret: Uint8Array; readonly public: Uint8Array };

  /** Sign the canonical (user_id, signing_pk, x25519_pk) bundle with
   *  the Ed25519 signing seed. Returns 64 raw bytes. The server
   *  re-derives the canonical bytes and verifies before persisting. */
  signPubkeyBundle(
    signingSeed: Uint8Array,
    userId: string,
    signingPubkey: Uint8Array,
    x25519Pubkey: Uint8Array,
  ): Uint8Array;

  // ---------------------------------------------------------------------
  // Org write ops (C.6)
  // ---------------------------------------------------------------------

  /** Sign an org roster (sorts entries deterministically, builds the
   *  canonical bytes, signs with the org's Ed25519 signing seed).
   *  Returns the wire-format `{canonicalB64, signatureB64}`. */
  signOrgRoster(
    signingSeed: Uint8Array,
    roster: {
      orgId: string;
      version: number;
      parentCanonicalSha256: Uint8Array;
      timestamp: string;
      entries: Array<{ userId: string; role: string }>;
      orgSymKeyId: string;
    },
  ): { canonicalB64: string; signatureB64: string };

  /** Verify an org roster signature under an *expected* signing pubkey
   *  (from a TOFU pin). Throws on mismatch; returns the parsed roster
   *  on success. */
  verifyOrgRoster(
    expectedPubkey: Uint8Array,
    canonicalB64: string,
    signatureB64: string,
  ): {
    orgId: string;
    version: number;
    parentCanonicalSha256: Uint8Array;
    timestamp: string;
    entries: Array<{ userId: string; role: string }>;
    orgSymKeyId: string;
  };

  /** Canonical bytes for an org bundle — `(org_id, name, org_signing_pk,
   *  owner_user_id)`. Used for fingerprint computation when pinning. */
  orgBundleCanonicalBytes(
    orgId: string,
    name: string,
    orgSigningPubkey: Uint8Array,
    ownerUserId: string,
  ): Uint8Array;

  /** Sign an org bundle with the owner's account signing seed.
   *  Returns 64 raw bytes (Ed25519 signature). */
  signOrgBundle(
    ownerSigningSeed: Uint8Array,
    orgId: string,
    name: string,
    orgSigningPubkey: Uint8Array,
    ownerUserId: string,
  ): Uint8Array;

  /** Verify an org bundle signature under the inviter's signing pubkey.
   *  Returns false on bad sig (does not throw). */
  verifyOrgBundle(
    inviterSigningPubkey: Uint8Array,
    orgId: string,
    name: string,
    orgSigningPubkey: Uint8Array,
    ownerUserId: string,
    signature: Uint8Array,
  ): boolean;

  /** Sign+encrypt a payload to a peer (BW09 signcryption envelope).
   *  Sender authenticates with their Ed25519 signing seed; recipient
   *  is identified by their X25519 pubkey + user_id. Returns the
   *  envelope JSON the server stores in `organization_invites`. */
  signcryptSealEnvelope(
    senderSigningSeed: Uint8Array,
    senderId: string,
    recipientId: string,
    recipientX25519Pubkey: Uint8Array,
    plaintext: Uint8Array,
  ): unknown;

  /** Verify+decrypt an envelope. Throws on signature mismatch / AEAD
   *  failure. `expectedSenderPubkey` must come from a TOFU pin (the
   *  raw envelope's sender_id is not enough — we re-bind to the pin
   *  for security). */
  signcryptOpenEnvelope(
    envelope: unknown,
    expectedSenderPubkey: Uint8Array,
    expectedRecipientId: string,
    recipientX25519Secret: Uint8Array,
  ): Uint8Array;

  /** AAD bytes for encrypting an org-collection's `name` field.
   *  Binds the ciphertext to (collection_id, org_id) so the server
   *  can't move a name between collections. */
  collectionNameAad(collectionId: string, orgId: string): Uint8Array;

  // ---------------------------------------------------------------------
  // 2FA TOTP enrollment (C.7d-1)
  // ---------------------------------------------------------------------

  /** Render `text` as an inline `<svg>` QR code string. Used for TOTP
   *  enrollment so users can scan with their authenticator app — most
   *  apps don't accept the otpauth:// URI as text. */
  qrCodeSvg(text: string): string;

  // ---------------------------------------------------------------------
  // Imports (web vault — D.1+)
  // ---------------------------------------------------------------------

  /** Parse a Bitwarden unencrypted JSON export and project it onto
   *  hekate's plaintext cipher model. Throws (with a human-readable
   *  message) on malformed JSON or encrypted exports. The orchestrator
   *  is responsible for creating folders, generating per-cipher keys,
   *  encrypting fields, and re-signing the BW04 manifest. */
  parseBitwardenJson(json: string): ProjectedImport;
}

/* ---------------------------------------------------------------------
 * Import projection shape (mirrors `hekate-core::import_bitwarden`)
 * ------------------------------------------------------------------- */

export interface ImportedCipher {
  /** 1=login, 2=secure_note, 3=card, 4=identity. */
  cipherType: number;
  name: string;
  notes: string | null;
  /** Type-specific data as a JSON-encoded object string (e.g. for a
   *  login: `{"username":"…","password":"…","uri":"…","totp":"…"}`).
   *  The orchestrator parses this before passing to `saveCipher`. */
  dataJson: string;
  favorite: boolean;
  /** Resolved folder *name* (the Bitwarden parser rewrites the export's
   *  opaque folder id to the name during projection). The orchestrator
   *  looks this up in the server-folder map to thread the freshly-
   *  allocated server folder id onto each cipher. */
  bitwardenFolderId: string | null;
}

export interface ProjectedImport {
  folders: string[];
  ciphers: ImportedCipher[];
  warnings: string[];
}
