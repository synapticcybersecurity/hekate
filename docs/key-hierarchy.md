# Hekate — Key Hierarchy & Cryptographic Material

> Audit-readiness artifact (see [`audit-package.md`](audit-package.md)).
> Consolidates the full key-derivation tree, where each key lives, how each
> is wrapped, and the domain-separation tags — grounded in the source, with
> `file:line` citations. Companion to the narrative in
> [`design.md`](design.md) §5. Verified against `main` at the commit noted
> in [`audit-scope.md`](audit-scope.md).

## 0. Protocol-frozen identifiers (`pmgr` / `PMGRA1`) — read first

Hekate has a deliberate **brand-vs-protocol split**. Code-level identifiers
were renamed to `hekate` (crates, binaries, `HEKATE_*` env vars, brand), but
the **on-the-wire and at-rest cryptographic byte literals keep their original
`pmgr-…` / `pmgr_*` prefixes and the `PMGRA1` magic.** These are not a missed
rename — they are frozen on purpose:

- Every `b"pmgr-…"` string below is an **AEAD AAD**, an **HKDF info**, or an
  **Ed25519 signature DST** baked into existing ciphertexts/signatures.
- `pmgr_sat_*` / `pmgr_pat_*` are **token wire prefixes**; `PMGRA1` is the
  **chunked-AEAD magic** for attachments/Sends.

Changing any of them changes the authenticated bytes, so previously-encrypted
data fails AEAD verification / signature verification / parsing — i.e. it
becomes undecryptable. The split means a future rebrand never touches
ciphertexts. **Auditors: treat the `pmgr`/`PMGRA1` literals as the permanent
protocol namespace.** (See `CLAUDE.md` "Protocol-Frozen Identifiers".)

## 1. Derivation tree

```
Master Password
  │  Argon2id(salt=16B random, m=128MiB, t=3, p=4, V0x13, out=32B)   [kdf.rs:107]
  ▼
Master Key (32B, Zeroizing)                                          [kdf.rs:83]
  ├─ HKDF-SHA256-Expand(info="pmgr-auth-v1")  ─► Master Password Hash (32B) ──► server
  │                                                 [kdf.rs:96,120]   (proof of knowledge; server re-Argon2id-hashes it)
  ├─ HKDF-Expand(info="pmgr-wrap-v1")         ─► Stretched Master Key (SMK, 32B)   [kdf.rs:97,125]
  │                                                 │
  │                                                 ▼ XChaCha20-Poly1305, AAD="pmgr-account-key"
  │                                              Account Key (32B, random/OsRng)   [keypair.rs:9; cli/crypto.rs:29]
  │                                                 │  (stored as `protected_account_key`, EncString v3)
  │                                                 ├─ wraps X25519 private key   AAD="pmgr-account-x25519-priv"
  │                                                 │     (`protected_account_private_key`)        [register.rs:96]
  │                                                 ├─ wraps each personal Per-Cipher Key (PCK)
  │                                                 │     AAD="pmgr-cipher-key-v2:<cipher_id>"      [cli/crypto.rs:36]
  │                                                 ├─ wraps each Org Symmetric Key (per membership)
  │                                                 │     AAD="pmgr-account-key"                    [account.rs:253]
  │                                                 └─ wraps each Send key + Send name
  │                                                       AAD="pmgr-send-key-v1:<id>" / "pmgr-send-name-v1:<id>" [send.rs]
  ├─ HKDF-Expand(info="pmgr-kdf-bind-v1")     ─► KDF-bind key (32B) ─ HMAC-SHA256 ─► kdf_params_mac   [kdf.rs:98,133]
  │                                                 (binds (params,salt); verified before sending the hash — BW07/LP04)
  └─ HKDF-Expand(info="pmgr-sign-v1")         ─► Ed25519 signing seed (32B) ─► signs the BW04 vault manifest  [manifest.rs:117,120]

Per-Cipher Key (PCK, 32B random)  ─ wraps every field of its cipher (XChaCha20-Poly1305).        [cli/crypto.rs:160]
   • personal cipher → PCK wrapped under Account Key
   • org cipher      → PCK wrapped under Org Symmetric Key

Org Symmetric Key (32B random)  ─ wraps org-cipher PCKs; delivered to each member by signcryption
   to their X25519 public key (not by sym-wrapping).                                              [signcrypt.rs]

Send key (32B random, lives in the URL fragment, never sent to server)
  └─ HKDF-Expand(prk=send_key, salt=send_id, info="pmgr-send-content-v1") ─► content key (32B)    [send.rs:44,89]
       • content key encrypts the Send payload/metadata, AAD="pmgr-send-data-v1:<id>:<type>"      [send.rs:103]
       • file Sends: a separate 32B `file_aead_key` (random) encrypts the body (PMGRA1 chunked-AEAD);
         `file_aead_key` is shipped inside the content-key-encrypted metadata, never to the server. [design.md:283]
```

## 2. Key inventory

| Key | Size | Origin | Lives | Wrapped by / signs | AAD or DST | Source |
|---|---|---|---|---|---|---|
| Master Key | 32B | Argon2id(pw,salt) | memory only (Zeroizing) | — | — | `kdf.rs:107` |
| Master Password Hash | 32B | HKDF(MK,"pmgr-auth-v1") | sent to server; server re-hashes (Argon2id) | — | info `pmgr-auth-v1` | `kdf.rs:120` |
| Stretched Master Key | 32B | HKDF(MK,"pmgr-wrap-v1") | memory only | — | info `pmgr-wrap-v1` | `kdf.rs:125` |
| KDF-bind key | 32B | HKDF(MK,"pmgr-kdf-bind-v1") | memory only | HMAC-SHA256 over (params‖salt) | info `pmgr-kdf-bind-v1`; MAC DST `pmgr-kdf-bind-msg-v1\x00` | `kdf.rs:133,103` |
| Ed25519 signing seed | 32B | HKDF(MK,"pmgr-sign-v1") | memory only | signs vault manifest | info `pmgr-sign-v1` | `manifest.rs:120` |
| Account Key | 32B | CSPRNG (OsRng) | wrapped at rest (`protected_account_key`) | SMK, XChaCha20-Poly1305 | `pmgr-account-key` | `keypair.rs:9`, `cli/crypto.rs:29` |
| X25519 private key | 32B | CSPRNG (x25519-dalek) | wrapped (`protected_account_private_key`) | Account Key | `pmgr-account-x25519-priv` | `keypair.rs:18`, `register.rs:96` |
| Per-Cipher Key (PCK) | 32B | CSPRNG | wrapped per cipher (`protected_cipher_key`) | Account Key (personal) / Org Sym Key (org) | `pmgr-cipher-key-v2:<cipher_id>` | `cli/crypto.rs:160` |
| Org Symmetric Key | 32B | CSPRNG | wrapped per member | owner: Account Key (`pmgr-account-key`); members: signcryption | — | `signcrypt.rs` |
| Send key | 32B | CSPRNG | URL fragment + wrapped (`protected_send_key`) | Account Key | `pmgr-send-key-v1:<id>` | `send.rs:56` |
| Send content key | 32B | HKDF(send_key,salt=id,"pmgr-send-content-v1") | derived on demand | — | info `pmgr-send-content-v1`; payload AAD `pmgr-send-data-v1:<id>:<type>` | `send.rs:89,103` |
| File-Send AEAD key | 32B | CSPRNG | inside content-key-encrypted metadata | content key | PMGRA1 chunked-AEAD (loc bytes = send_id) | `design.md:283` |
| Server JWT signing key | 32B | CSPRNG, `signing_keys` table | server only | HS256 (HMAC-SHA256) | — | `server/auth/jwt.rs:100` |

## 3. EncString envelope (the symmetric wrapper for everything above)

Wire format (`design.md:257`; `encstring.rs`):
```
v3.<alg>.<key_id>.<nonce_b64>.<aad_b64>.<ct_b64>.<tag_b64>
```
- `alg` = `xc20p` (XChaCha20-Poly1305; 24-byte nonce, random per encryption via `OsRng`); `agcms`/`x25519`/`ed25519` reserved.
- `key_id` = the wrapping key id (e.g. `ak:1` for the account key), so non-rotated items survive rotation.
- AAD is carried in the envelope (base64, no-pad) **and** authenticated by Poly1305 — it binds the ciphertext to its logical location (`cipher_id‖field`), defeating cross-field/cross-item swaps.

## 4. Signing & domain-separation tags (Ed25519 / signcryption)

| Object | DST / info | Key | Source |
|---|---|---|---|
| Vault manifest (BW04) | `pmgr-vault-manifest-v3\x00` | account Ed25519 seed (HKDF from MK) | `manifest.rs:90` |
| Org roster | `pmgr-org-roster-v1\x00` | org signing seed | `org_roster.rs` |
| Org cipher manifest | `pmgr-org-cipher-manifest-v1\x00` | org signing seed | `org_cipher_manifest.rs` |
| Self-signed pubkey bundle | `pmgr-pubkey-bundle-v1\x00` | account Ed25519 | `keypair.rs`/`signcrypt.rs` |
| Signcryption envelope | sig DST `pmgr-signcrypt-v1\x00`; AEAD-key info `pmgr-signcrypt-aead-key-v1` | X25519 ECDH (ephemeral) + HKDF-SHA256 + XChaCha20-Poly1305, Ed25519 signature | `signcrypt.rs:77,78` |

## 5. Server-side token material

- **User access token** — JWT **HS256**, secret = 32B random from the `signing_keys` table (`kid` per key, rotated on startup if none), 1 h TTL; claims include `stamp` (the user `security_stamp`, checked per request so one DB write invalidates all tokens). `server/auth/jwt.rs:17,47,100`.
  - Note: `design.md:302` describes Ed25519/JWKS as the target token model; **as shipped it is HS256** — an item for the auditor to note (server-held symmetric key, not asymmetric).
- **Refresh token** — opaque 256-bit random, stored Argon2id-hashed, single-use rolling rotation, family-revocation on replay.
- **PAT** — wire `pmgr_pat_<uuidv7>.<b64-secret>`; stored as SHA-256(`"pmgr-pat-v1"‖secret`); constant-time verify. `server/auth/pat.rs:17,58`.
- **Service-account token** — wire `pmgr_sat_<uuidv7>.<b64-secret>`; SHA-256(`"pmgr-sat-v1"‖secret`); org-owned. `server/auth/sat.rs:23,66`.

## 6. Rotation (`account rotate-keys`, M2.26)

Re-wrapped under a fresh Account Key, in one server transaction (`cli/commands/account.rs:414-574`, `design.md:267`):
- every personal PCK (`pmgr-cipher-key-v2:<id>`)
- every Send `protected_send_key` (`pmgr-send-key-v1:<id>`) and Send `name` (`pmgr-send-name-v1:<id>`)
- every membership's `protected_org_key` (`pmgr-account-key`)
- the X25519 private key (`pmgr-account-x25519-priv`)

**Preserved:** the master password (hence Master Key, signing seed, manifest pubkey), the X25519 keypair (peer pins survive), and the PCKs themselves (field ciphertexts are never re-encrypted — only each PCK's wrap rotates). **Also rotates:** every refresh token + the `security_stamp`. Org-owned cipher PCKs are untouched (they wrap under the org sym key, not the account key).

## 7. Cross-client constant consistency (audit note)

The client-side AAD constants (`pmgr-account-key`, `pmgr-account-x25519-priv`, `pmgr-cipher-key-v2:`, the `pmgr-send-*` set) are defined **independently in each client** — e.g. `crates/hekate-cli/src/crypto.rs:29` and `clients/web/src/lib/register.ts:34-35` (and the WASM/extension path). They MUST match byte-for-byte across CLI, web vault, and extension or a cipher written by one client won't decrypt in another. Verifying this cross-client agreement is a worthwhile audit check; the shared `hekate-core` (compiled to native + wasm) holds the derivation/DST constants centrally (`kdf.rs`, `manifest.rs`, `send.rs`, `signcrypt.rs`), but the account-key/x25519 wrap AADs live in the client orchestration layers.
