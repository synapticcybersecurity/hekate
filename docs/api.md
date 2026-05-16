# Hekate — API Reference

Concrete reference for every shipped endpoint, with curl examples. The OpenAPI 3.1 spec is served live at `/api/v1/openapi.json` and rendered as interactive Scalar docs at `/api/v1/docs` — that's the source of truth and includes every wire shape (including `OrgView.member_emails`, the per-attachment `content_hash_b3`, etc.). This file is the curl-driven companion.

> Brand: **Hekate**. Internal package + endpoint paths keep `hekate-…` because the wire format is protocol-frozen.

**Base URL:** `http://hekate.localhost` (Traefik) or `http://localhost:8088` (direct).

**SPA mounts** (Phase C, served by `hekate-server` itself when `HEKATE_WEB_DIR` is set):
- `/web/*` — Hekate web vault, owner mode
- `/send/*` — Hekate web vault, recipient mode for share URLs (`/send/#/<send_id>/<send_key>`)

**Auth:** `Authorization: Bearer <token>` for all `/api/v1/*` (and `/push/v1/*`) endpoints except `/accounts/register`, `/accounts/prelogin`, `/identity/connect/token`, `/users/{user_id}/pubkeys`, `/users/lookup`, `/public/sends/*`, `/health/*`, and `/`. Three token formats are accepted:
- **Access JWTs** issued by `/identity/connect/token` (1-hour TTL, all scopes implicit).
- **Personal Access Tokens** (`pmgr_pat_<id>.<secret>`) issued by `/api/v1/account/tokens` (long-lived, explicit scope set, user-scoped).
- **Service Account Tokens** (`pmgr_sat_<id>.<secret>`) issued by `/api/v1/orgs/{org_id}/service-accounts/{sa_id}/tokens` (long-lived, explicit scope set, org-owned machine identity).

**Scopes:** `vault:read` (GETs + sync + push stream), `vault:write` (cipher/folder mutations), `account:admin` (token + webhook + rotate-keys management), plus per-org scopes (`org:read`, `secrets:read`, `secrets:write`, ...) carried by SATs. Interactive JWTs implicitly carry every scope; PATs and SATs only carry the scopes listed at creation time. Insufficient scope returns 403.

**Wire conventions:**
- Identifiers: UUIDv7 strings.
- Timestamps: RFC 3339 (e.g. `2026-05-02T14:18:26.266562632+00:00`).
- Encrypted fields: `EncString v3` envelope (`v3.<alg>.<kid>.<nonce>.<aad>.<ct>.<tag>`, all base64-no-pad).
- Bytes that travel as JSON: base64-no-pad **standard** alphabet (e.g. `master_password_hash`, `kdf_salt`).
- Refresh tokens: base64-no-pad **URL-safe** alphabet so they survive form encoding.

---

## Discovery

### `GET /`
Root index — JSON list of available endpoints. Useful for browser sanity-check.

```bash
curl -s http://hekate.localhost/ | jq .
```

### `GET /health/live`
Liveness — always 200 if the process is up.

### `GET /health/ready`
Readiness — pings the DB. Returns 200 only when the DB is reachable.

### `GET /api/v1/version`
```json
{"version":"0.0.1","git_sha":"dev"}
```

### `GET /api/v1/openapi.json`
OpenAPI 3.1 specification, auto-generated from handler signatures via [`utoipa`](https://docs.rs/utoipa). Lists every operation, schema, security scheme, and response shape. Use it with Postman, Insomnia, code generators (e.g. `openapi-generator`), or Scalar's online viewer.

### `GET /api/v1/docs`
Self-contained HTML page rendering interactive API documentation via [Scalar](https://scalar.com/) backed by the spec above. Open in a browser for a clickable, searchable view of every endpoint.

---

## Account lifecycle

### `POST /api/v1/accounts/register`

Create a new user. The client derives a 32-byte master key via Argon2id and sends only the HKDF-derived `master_password_hash` — the master password itself never leaves the client.

```bash
curl -X POST http://hekate.localhost/api/v1/accounts/register \
  -H 'content-type: application/json' \
  -d '{
    "email": "alice@example.com",
    "kdf_params": {"alg":"argon2id","m_kib":131072,"t":3,"p":4},
    "kdf_salt": "<base64-std 16+ bytes>",
    "master_password_hash": "<base64-std 32 bytes>",
    "protected_account_key": "v3.xc20p.kid.<...>",
    "account_public_key": "<base64-std 32 bytes>",
    "protected_account_private_key": "v3.xc20p.kid.<...>"
  }'
```

- **201** `{"user_id":"<uuidv7>"}`
- **400** invalid email / bad base64 / wrong byte length / malformed EncString
- **409** email already registered

### `POST /api/v1/accounts/prelogin`

Returns the KDF parameters and salt the client needs to re-derive its master password hash. For unknown emails, returns deterministic-but-fake values keyed off a server-side pepper so existence isn't enumerable.

```bash
curl -X POST http://hekate.localhost/api/v1/accounts/prelogin \
  -H 'content-type: application/json' \
  -d '{"email":"alice@example.com"}'
```

```json
{
  "kdf_params": {"alg":"argon2id","m_kib":131072,"t":3,"p":4},
  "kdf_salt": "<base64-std>"
}
```

### `POST /api/v1/account/rotate-keys` (scope: `account:admin`)

Rotate the symmetric `account_key` and re-wrap every key wrapped under it (M2.26). Master password is unchanged. Required body:

```json
{
  "master_password_hash": "<base64-no-pad of 32 bytes>",
  "new_protected_account_key": "v3.xc20p....",
  "new_protected_account_private_key": "v3.xc20p....",
  "cipher_rewraps": [
    {"cipher_id": "...", "new_protected_cipher_key": "v3.xc20p...."}
  ],
  "send_rewraps": [
    {"send_id": "...", "new_protected_send_key": "v3.xc20p...."}
  ],
  "org_member_rewraps": [
    {"org_id": "...", "new_protected_org_key": "v3.xc20p...."}
  ]
}
```

Server validates each rewrap target belongs to the caller (cross-user cipher/send → 400; org the caller isn't a member of → 400; malformed EncString → 400), then applies all updates in one transaction. On success: bumps `security_stamp`, revokes refresh tokens, returns fresh access + refresh tokens plus per-category counts the client can diff:

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "...",
  "rewrote_ciphers": 12,
  "rewrote_sends": 3,
  "rewrote_org_memberships": 2
}
```

What is preserved across this call: the master password, the BW04 manifest signing key (HKDF derives from master_key, which doesn't change), the X25519 keypair (peer TOFU pins keep working), and existing PCKs (cipher field ciphertexts are never re-encrypted — only the wrap of each PCK rotates). What rotates: `account_key`, every wrap that depends on it, every refresh token, the security stamp.

Org-owned cipher PCKs are deliberately untouched: they wrap under the org symmetric key, not the user's account_key.

### `POST /api/v1/account/change-password`

Rotate the master password without rotating the symmetric `account_key`. The KDF salt + master-password hash + signing seed change; the unwrapped `account_key` value is unchanged so every cipher / send / org wrap that already depends on it keeps decrypting. The BW04 vault manifest is wiped server-side because its signing key derives from the master key — next write uploads a fresh genesis under the new key.

Required body:

```json
{
  "current_master_password_hash": "<base64-no-pad>",
  "new_kdf_params": {"alg":"argon2id","m_kib":131072,"t":3,"p":4},
  "new_kdf_salt": "<base64-std>",
  "new_master_password_hash": "<base64-no-pad>",
  "new_protected_account_key": "v3.xc20p....",
  "new_protected_account_private_key": "v3.xc20p....",
  "new_account_signing_pubkey": "<32B base64>"
}
```

Response: 204. Refresh tokens are revoked; the caller must re-login to obtain a new pair.

### `POST /api/v1/account/delete`

Permanently destroy the account. Required body re-asserts the current master password hash:

```json
{"master_password_hash": "<base64-no-pad>"}
```

Cascades: ciphers, folders, attachments (rows + blob tombstones), sends, org memberships (the user is auto-revoked from any orgs they belong to, triggering the standard rotate-on-revoke), 2FA credentials, PATs, refresh tokens, manifest. Returns 204 on success.

---

## Token endpoint

### `POST /identity/connect/token`

OAuth 2.0 token endpoint. Form-encoded body. Two grants supported:

#### `grant_type=password`

Exchange master password hash for tokens. Initial-login response includes the user's protected account material.

```bash
curl -X POST http://hekate.localhost/identity/connect/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=password' \
  --data-urlencode 'username=alice@example.com' \
  --data-urlencode 'password=<base64-std master_password_hash>'
```

```json
{
  "access_token": "<JWT, 1 h>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<id>.<base64-url-safe>",
  "kdf_params": {...},
  "kdf_salt": "<base64-std>",
  "protected_account_key": "v3.xc20p...",
  "account_public_key": "<base64-std>",
  "protected_account_private_key": "v3.xc20p..."
}
```

- **400** missing/invalid fields
- **401** unknown user, wrong password, or unsupported grant type details

#### `grant_type=refresh_token`

Single-use rolling refresh. Account material is **not** re-shipped (the client already has it).

```bash
curl -X POST http://hekate.localhost/identity/connect/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=refresh_token' \
  --data-urlencode 'refresh_token=<presented>'
```

```json
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<new id>.<new secret>"
}
```

**Replay protection:** Presenting an already-revoked refresh token revokes the entire family (every descendant token). Both legitimate and attacker sessions are forced to re-login.

---

## Personal Access Tokens

Long-lived bearer tokens for scripts and CI. Wire format: `pmgr_pat_<uuidv7>.<url-safe-base64-no-pad>`. Hash-at-rest is SHA-256 of a 256-bit secret.

### `POST /api/v1/account/tokens` (scope: `account:admin`)

```bash
curl -X POST http://hekate.localhost/api/v1/account/tokens \
  -H "Authorization: Bearer $JWT" \
  -H 'content-type: application/json' \
  -d '{"name":"ci-script","scopes":"vault:read,vault:write","expires_in_days":365}'
```

**201**:
```json
{
  "id": "<uuidv7>",
  "token": "pmgr_pat_<uuidv7>.<secret>",
  "name": "ci-script",
  "scopes": "vault:read,vault:write",
  "expires_at": "2027-05-02T15:43:31Z"
}
```

The `token` field is **only returned once**. Store it now.

### `GET /api/v1/account/tokens` (scope: `account:admin`)
Lists token metadata (no secrets). Includes `last_used_at` and `revoked_at`.

### `DELETE /api/v1/account/tokens/{id}` (scope: `account:admin`)
Immediate revocation. Subsequent calls with the revoked PAT return 401.

---

## Webhooks (outbound events)

Subscribe a URL to receive HMAC-signed POSTs whenever vault events fire. Best-effort delivery: one attempt per event, no retry queue (recoverable via `/sync`).

### `POST /api/v1/account/webhooks` (scope: `account:admin`)

```bash
curl -X POST http://hekate.localhost/api/v1/account/webhooks \
  -H "Authorization: Bearer $JWT" \
  -H 'content-type: application/json' \
  -d '{
    "name": "ops-channel",
    "url": "https://example.com/hekate-hook",
    "events": "cipher.changed,cipher.tombstoned"
  }'
```

**201**:
```json
{
  "id": "<uuidv7>",
  "name": "ops-channel",
  "url": "https://example.com/hekate-hook",
  "events": "cipher.changed,cipher.tombstoned",
  "secret": "<URL-safe base64, returned ONCE>"
}
```

Omit or set `events` to `*` to receive every event kind. Known kinds: `cipher.changed`, `cipher.deleted`, `cipher.tombstoned`, `folder.changed`, `folder.tombstoned`.

### Delivery wire format

Every delivery is an HTTP POST to the configured URL:

```
POST <url> HTTP/1.1
Content-Type: application/json
User-Agent: hekate-webhooks/<version>
X-Hekate-Event-Id: <uuidv7>
X-Hekate-Event-Type: cipher.changed
X-Hekate-Signature: t=1777738212,v1=ab8e601d5ea8d36a60af57b65e0c68431b6d96e19b65b0fb82fe29cf4c447abc

{"id":"<event-uuid>","type":"cipher.changed","created_at":"<rfc3339>","data":{"id":"<cipher-uuid>","revision":"<rfc3339>"}}
```

### Verification

In any language:

```python
import base64, hmac, hashlib

def verify(body: bytes, header: str, secret_b64: str) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))
    t, v1 = parts["t"], parts["v1"]
    secret = base64.urlsafe_b64decode(secret_b64 + "=" * (-len(secret_b64) % 4))
    expected = hmac.new(secret, f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, v1)
```

### `GET /api/v1/account/webhooks` (scope: `account:admin`)
Lists subscription metadata (no secrets).

### `DELETE /api/v1/account/webhooks/{id}` (scope: `account:admin`)
Removes the subscription. No further events are delivered.

### `GET /api/v1/account/webhooks/{id}/deliveries` (scope: `account:admin`)

Returns the most recent 50 delivery attempts (newest first). Each item carries `attempts`, `next_attempt_at`, `last_status`, `last_error`, `delivered_at`, `failed_permanently_at`. Useful for diagnosing why a hook isn't firing or for auditing the at-least-once delivery story.

---

## Two-factor authentication (M2.22 + M2.23a)

When 2FA is enabled, `grant_type=password` returns `401` with body `{"error":"two_factor_required","challenge_token":"...","two_factor_providers":[...], "totp":..., "webauthn_challenge":...}`. The client completes a second leg at `/identity/connect/token` with `grant_type=password` plus `challenge_token` + `two_factor_provider` + `two_factor_value`. Refresh grants do not re-prompt — the second factor binds at the password leg only.

Recovery codes are **authentication-only**: they unblock a 2FA challenge but do not decrypt the vault.

### TOTP + recovery codes (M2.22)

```
POST /api/v1/account/2fa/totp/setup                      — issue a provisional secret + provisioning URI
POST /api/v1/account/2fa/totp/confirm                    — supply one valid code to finalize enrollment
POST /api/v1/account/2fa/totp/disable                    — re-asserts master_password_hash
POST /api/v1/account/2fa/recovery-codes/regenerate       — burns the prior set, returns 10 fresh codes
GET  /api/v1/account/2fa/status                          — `{enabled, providers, last_used_at}`
```

Replay defence: TOTP uses ±1-step skew; the highest accepted period is persisted, future codes ≤ that period are refused.

### WebAuthn / FIDO2 (M2.23a)

```
POST /api/v1/account/2fa/webauthn/register/start              — issues a `PublicKeyCredentialCreationOptions`
POST /api/v1/account/2fa/webauthn/register/finish             — submits the attestation; binds nickname
GET  /api/v1/account/2fa/webauthn/credentials                 — list enrolled authenticators
DELETE /api/v1/account/2fa/webauthn/credentials/{id}          — remove a credential
PATCH /api/v1/account/2fa/webauthn/credentials/{id}           — rename a credential
```

The login dance carries `webauthn_challenge` (a `RequestChallengeResponse` from `webauthn-rs`) inside the `two_factor_required` body. Second leg submits the assertion as `two_factor_value`. RP ID + origin come from `HEKATE_WEBAUTHN_RP_ID` / `HEKATE_WEBAUTHN_RP_ORIGIN`.

---

## Public key directory (M2.19 / BW09)

Unauthenticated. The self-signed pubkey bundle (Ed25519 signing key + X25519 wrapping key) is what other clients TOFU-pin via `hekate peer fetch`.

### `GET /api/v1/users/{user_id}/pubkeys`

```json
{
  "user_id": "...",
  "signing_pubkey_b64": "<32B>",
  "x25519_pubkey_b64": "<32B>",
  "self_sig_b64": "<64B Ed25519 over canonical(user_id ∥ signing_pk ∥ x25519_pk)>",
  "fingerprint_b58": "..."
}
```

The client verifies `self_sig_b64` under `signing_pubkey_b64` before pinning. A malicious server can refuse to serve a bundle but cannot forge a valid signature without the user's signing key.

### `GET /api/v1/users/lookup?email=<email>`

Maps an email to its bundled `user_id`. Same enumeration-protection posture as `/accounts/prelogin` — unknown emails return a deterministic-fake row so timing + response shape doesn't reveal account existence.

---

## Vault manifest (BW04 — M2.15c)

Per-user signed manifest of `(cipher_id, revision_date, deleted, attachments_root)` tuples; signed with Ed25519 derived from the master key via HKDF (`pmgr-sign-v1`). Detects server drops, replays, resurrections, and attachment-set tampering.

### `POST /api/v1/vault/manifest`

```json
{
  "version": 12,
  "parent_canonical_sha256_b64": "<32B, all-zero for genesis>",
  "canonical_b64": "<DST || version || parent_hash || entries ...>",
  "signature_b64": "<64B Ed25519>"
}
```

Server enforces strictly-greater `version` and that `parent_canonical_sha256_b64` matches the SHA-256 of the currently-stored canonical bytes. Forked or rolled-back chains return 409.

### `GET /api/v1/vault/manifest`

Returns the currently-stored manifest. Clients cross-check every cipher in `/sync` against the entries; mismatches surface as ⚠ warnings (or block in strict-manifest mode).

---

## Vault — ciphers

`type` enum: `1`=login, `2`=note, `3`=card, `4`=identity, `5`=ssh_key, `6`=totp_only.

### `POST /api/v1/ciphers`

```bash
curl -X POST http://hekate.localhost/api/v1/ciphers \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "type": 1,
    "folder_id": null,
    "protected_cipher_key": "v3.xc20p...",
    "name": "v3.xc20p...",
    "notes": null,
    "data": "v3.xc20p...",
    "favorite": false,
    "reprompt": 0
  }'
```

- **201** full cipher view
- **400** bad type, malformed EncString, unknown folder

### `GET /api/v1/ciphers/{id}`
Returns the cipher view (or 404).

### `PUT /api/v1/ciphers/{id}`

**Requires `If-Match: "<revision_date>"` header** — the design forbids silent last-writer-wins.

```bash
curl -X PUT http://hekate.localhost/api/v1/ciphers/<id> \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -H 'If-Match: "2026-05-02T14:18:26.266562632+00:00"' \
  -d '{...full cipher input...}'
```

- **200** updated cipher view (with new `revision_date`)
- **409** **revision conflict** — body includes `current` cipher in full so the client can resolve:
  ```json
  {"error": "revision conflict", "current": { ...full cipher... }}
  ```
- **428** Precondition Required — `If-Match` header missing
- **404** not owned / not found

### `DELETE /api/v1/ciphers/{id}` — soft delete (trash)
Sets `deleted_date`. Cipher is still readable. **204** on success.

### `POST /api/v1/ciphers/{id}/restore`
Clears `deleted_date`. **200** with restored cipher view.

### `POST /api/v1/ciphers/{id}/move-to-org` (scope: `vault:write`, `If-Match` required)

Move a personal cipher into an org. The client re-wraps the cipher's PCK under the org symmetric key, optionally re-keys, and lists the target collection set:

```json
{
  "org_id": "...",
  "collection_ids": ["..."],
  "protected_cipher_key": "v3.xc20p....",
  "name": "v3.xc20p....",
  "data": "v3.xc20p....",
  "notes": "v3.xc20p...."
}
```

Server validates the caller has `manage` on every target collection. Returns the moved cipher view. AAD on every field now binds `org_id` so the server cannot move the cipher between orgs by rewriting the column.

### `POST /api/v1/ciphers/{id}/move-to-personal` (scope: `vault:write`, `If-Match` required)

Reverse direction: re-wrap the PCK under the caller's account key, remove from every collection, clear `org_id`. Required body shape mirrors `move-to-org` minus `org_id` / `collection_ids`.

### `DELETE /api/v1/ciphers/{id}/permanent` — hard delete + tombstone
Removes the row and writes a tombstone so the next `/sync` informs other devices. **204** on success.

---

## Vault — folders

### `POST /api/v1/folders`
Body: `{"name": "v3.xc20p..."}`. **201** with folder view (`id`, `name`, `revision_date`, `creation_date`).

### `GET /api/v1/folders/{id}`
Returns folder view (or 404).

### `PUT /api/v1/folders/{id}`
Requires `If-Match: "<revision_date>"`. Same conflict semantics as ciphers.

### `DELETE /api/v1/folders/{id}` — hard delete + tombstone
Drops the row, sets `folder_id = NULL` on any contained ciphers (FK cascade), and writes a tombstone. **204** on success.

---

## Vault — attachments (M2.24)

Resumable uploads via [tus 1.0](https://tus.io/) with chunked-AEAD body encryption. Server stores opaque ciphertext; only metadata is plaintext (id, sizes, BLAKE3 hash). Per-attachment AEAD key wrapped under the parent cipher's key.

**File body format** — `PMGRA1` chunked AEAD: 32-byte header (magic + version + 1-MiB chunk size + random nonce prefix), then 1-MiB plaintext chunks each sealed with XChaCha20-Poly1305. Chunk index in the nonce + AAD prevents reorder; final-flag bit on the last chunk's AAD prevents truncation. See `hekate-core::attachment` for the wire format and `ciphertext_size_for(plaintext)` to compute the exact ciphertext byte count.

### `OPTIONS /api/v1/attachments`
Tus capability discovery. **204** with headers:
```
Tus-Resumable: 1.0.0
Tus-Version: 1.0.0
Tus-Extension: creation,creation-with-upload,termination,checksum
Tus-Checksum-Algorithm: sha-256
Tus-Max-Size: 104857600
```

### `POST /api/v1/attachments` (scope: `vault:write`)

Create a tus upload resource and bind it to a cipher. Required headers:
- `Upload-Length: <ciphertext bytes>` — total expected size.
- `Upload-Metadata: ...` — comma-separated `key value` pairs, value base64-encoded. Required keys:
  - `attachment_id` (UUIDv7 generated client-side)
  - `cipher_id` (UUIDv7 of the parent cipher; caller must have write access)
  - `filename` (EncString v3 of the plaintext filename, under cipher key, AAD `pmgr-attachment-filename-v1:<att_id>:<cipher_id>`)
  - `content_key` (EncString v3 of the per-attachment 32-byte AEAD key, under cipher key, AAD `<att_id>|key|<cipher_id>`)
  - `content_hash_b3` (BLAKE3 of the entire ciphertext, base64-no-pad)
  - `size_pt` (plaintext byte count, decimal)

Body MAY carry the first ciphertext chunk via `creation-with-upload` (saves a round trip). Returns **201** with `Location: /api/v1/tus/<token>` and `Upload-Offset: <bytes_received>` (= len(body) for creation-with-upload, else 0).

### `HEAD /api/v1/tus/{token}` (scope: `vault:read`)
Resume probe. Returns **200** with `Upload-Offset` and `Upload-Length`. **404** if the upload was terminated, completed, or expired (24-hour TTL).

### `PATCH /api/v1/tus/{token}` (scope: `vault:write`)
Append bytes at `Upload-Offset`. Requires `Content-Type: application/offset+octet-stream`. Server returns **204** with the new `Upload-Offset`. **409** if `Upload-Offset` doesn't match the server's `bytes_received` (resume mismatch). When the final byte lands the server verifies BLAKE3 against the upload's `content_hash_b3` and atomically promotes the row to `status=1`; mismatch returns **400** and tears down the upload.

### `DELETE /api/v1/tus/{token}` (scope: `vault:write`)
Terminate an in-progress upload. **204**.

### `GET /api/v1/attachments/{id}` (scope: `vault:read`)
Plaintext metadata view (everything except the body):
```json
{
  "id": "...",
  "cipher_id": "...",
  "filename": "v3.xc20p....",
  "content_key": "v3.xc20p....",
  "size_pt": 12345,
  "size_ct": 12393,
  "content_hash_b3": "...",
  "revision_date": "2026-05-03T12:00:00+00:00",
  "creation_date": "2026-05-03T12:00:00+00:00"
}
```

### `GET /api/v1/attachments/{id}/blob` (scope: `vault:read`)
Streams the raw ciphertext. Auth-gated; the body is the chunked-AEAD `PMGRA1` payload exactly as the client uploaded it. (M2.24a will add `object_store`-backed signed URLs for cloud backends; M2.24 always proxies through the server.) **404** if the attachment is in `status=0` (still uploading) or the caller lacks read permission.

### `DELETE /api/v1/attachments/{id}` (scope: `vault:write`)
Permanent delete. Writes a `kind="attachment"` tombstone, queues blob cleanup in `attachment_blob_tombstones`, bumps the parent cipher's `revision_date`. **204**.

### Tombstones + sync

`/api/v1/sync` includes attachment metadata for every finalized attachment whose `revision_date > since`, and tombstones get `kind: "attachment"` rows. Clients feed the attachment tuples into `compute_attachments_root` to verify the per-cipher `attachments_root` field of the BW04 v3 manifest.

### Push events

- `attachment.changed` — fired on finalize and on parent-cipher revision bumps. Payload: `{ id, revision }`.
- `attachment.tombstoned` — fired on hard-delete.

The parent cipher's `cipher.changed` event also fires after every attachment finalize/delete (the cipher's `revision_date` is bumped so /sync re-emits the cipher row too).

### CLI quick reference

```bash
hekate attach upload <cipher_id> <file>           # encrypt + tus-upload + sign new manifest
hekate attach download <attachment_id> [-o out]   # GET blob + verify hash + decrypt + write file
hekate attach list <cipher_id>                    # list (decrypted filenames) for one cipher
hekate attach delete <attachment_id> --yes        # tombstone + queue blob cleanup
```

---

## Vault — Sends (M2.25)

Ephemeral encrypted text shares. The sender generates a 32-byte `send_key` client-side and embeds it in the URL fragment they share (`https://<host>/send/#/<send_id>/<send_key_url_b64>`). Browsers do not transmit fragments, so the server never sees the key. Recipients are anonymous (no Hekate account); they POST to a public access endpoint with the optional password and decrypt client-side.

**Crypto.** Recipient derives the AEAD content key via HKDF-SHA-256 with `info = "pmgr-send-content-v1"` and `salt = send_id`. Payload is XChaCha20-Poly1305 with `AAD = "pmgr-send-data-v1:<send_id>:<send_type>"` so a server can't move ciphertext between Sends or flip text↔file. Optional access password is server-side Argon2id-PHC'd and serves only as a revocation gate — it never feeds key derivation. Both text and file Sends are supported; `send_type = 1` is text and `send_type = 2` is file.

### `POST /api/v1/sends` (scope: `vault:write`)

Create a Send. Body:
```json
{
  "id": "<UUIDv7>",
  "send_type": 1,
  "name": "v3.xc20p....",                  // EncString of sender-side display name under account_key
  "notes": "v3.xc20p....",                 // optional
  "protected_send_key": "v3.xc20p....",    // EncString of the 32-byte send_key under account_key,
                                           //   AAD "pmgr-send-key-v1:<id>"
  "data": "v3.xc20p....",                  // EncString of plaintext payload under HKDF-derived content_key
  "password": "hunter2",                   // optional plaintext; server Argon2id-PHCs and discards
  "max_access_count": 3,                   // optional; nullable = unlimited
  "expiration_date": "2026-05-10T00:00:00Z", // optional time-based expiry
  "deletion_date":   "2026-05-15T00:00:00Z", // required hard auto-delete
  "disabled": false
}
```
Returns **201** with the full `SendView` (carries `has_password: bool` so the owner UI can render the gate flag without ever seeing the PHC).

### `GET /api/v1/sends` (scope: `vault:read`)
List sender-owned Sends, ordered by `revision_date DESC`.

### `GET /api/v1/sends/{id}` (scope: `vault:read`)
Read one. **404** if not owned by caller.

### `PUT /api/v1/sends/{id}` (scope: `vault:write`)
Edit. Requires `If-Match: "<revision_date>"`. Same conflict semantics as ciphers. The `password` field is special: omit to preserve the existing PHC, send `""` to clear the gate, send a non-empty string to re-hash.

### `DELETE /api/v1/sends/{id}` (scope: `vault:write`)
Hard delete + writes a `kind="send"` tombstone. **204**.

### `POST /api/v1/sends/{id}/disable` and `POST /api/v1/sends/{id}/enable` (scope: `vault:write`)
Flip the disabled flag without changing any other state. Disabled Sends return **409 Gone-equivalent** on public access.

### `POST /api/v1/public/sends/{id}/access` (no auth)

Anonymous recipient endpoint. Body:
```json
{ "password": "hunter2" }   // omit / null if the Send is unprotected
```

Response (200) — text Send:
```json
{
  "id": "<send_id>",
  "send_type": 1,
  "data": "v3.xc20p....",       // recipient HKDF-decrypts client-side
  "access_count": 1,
  "max_access_count": 3,
  "expiration_date": null
}
```

Response (200) — file Send (M2.25a) additionally carries a 5-minute
download token and the server-known ciphertext size:
```json
{
  "id": "<send_id>",
  "send_type": 2,
  "data": "v3.xc20p....",       // encrypted-metadata payload (filename + per-file AEAD key)
  "access_count": 1,
  "max_access_count": null,
  "expiration_date": null,
  "download_token": "<32 random bytes, URL-safe-b64-no-pad>",
  "size_ct": 1310762
}
```

Status codes (in order of check):
- **404** — row doesn't exist.
- **409** — disabled, past `deletion_date`, past `expiration_date`, body not yet uploaded (file Sends), or `access_count` already at `max_access_count`. (Surrogate for "Gone"; M2.x may promote to a real 410 variant on `ApiError`.)
- **401** — password missing or wrong (constant-time Argon2id verify).
- **200** — atomic `access_count + 1` then return ciphertext + bumped counter (+ minted download token for file Sends).

### File Sends (M2.25a)

File Sends use `send_type = 2` on creation. The metadata row is created
via the same `POST /api/v1/sends`, but the body is uploaded separately
through tus 1.0 after the row exists. The server stores the body in
the `BlobStore` (local-FS today; same trait as M2.24 attachments). The
recipient never sees `file_aead_key` — it's embedded inside the
encrypted metadata payload that only the URL-fragment send_key can
decrypt.

#### `POST /api/v1/sends/{id}/upload` (scope: `vault:write`)

Sender-authenticated tus creation. Cipher must own the row,
`send_type` must be 2, and no finalized body may already exist.
Headers: `Upload-Length`, `Upload-Metadata` with `content_hash_b3`
(BLAKE3 of the entire ciphertext) and `size_pt` (plaintext byte
count). Body MAY carry the first chunk via `creation-with-upload`.
Returns **201** with `Location: /api/v1/tus-send/<token>`.

#### `HEAD /api/v1/tus-send/{token}` (scope: `vault:read`)
Resume probe. Returns `Upload-Offset` + `Upload-Length`.

#### `PATCH /api/v1/tus-send/{token}` (scope: `vault:write`)
Append bytes at `Upload-Offset`. **204** with the new offset, **409**
on offset mismatch. Final byte triggers BLAKE3 verify against the
upload's `content_hash_b3`; mismatch returns **400** and tears down
the upload (sender retries from scratch).

#### `DELETE /api/v1/tus-send/{token}` (scope: `vault:write`)
Abort an in-progress upload. Resets the parent row's `body_status` to
0 so the sender can start a fresh upload. **204**.

#### `GET /api/v1/public/sends/{id}/blob/{token}` (no auth)
Streams the raw ciphertext to the recipient. The token comes from a
prior `/access` call (5-minute TTL). Multiple GETs within TTL are
allowed (network retry). **404** for unknown/expired tokens; **409**
if the underlying body is no longer finalized.

The recipient HKDFs the URL-fragment `send_key` to derive the metadata
content_key, decrypts `data` to extract `file_aead_key`, then uses
chunked-AEAD-decrypt (M2.24 `hekate-core::attachment`) on the downloaded
bytes with `file_aead_key` and `attachment_id = send_id`.

### Tombstones + sync

`/api/v1/sync` includes sender-owned Sends in `Changes.sends` and tombstones get `kind: "send"` rows. Recipients never `/sync` — they only ever hit `/access`.

### Push events

- `send.changed` — fired on create/update/disable/enable.
- `send.tombstoned` — fired on hard-delete.

(The public-access `access_count` bump intentionally does **not** fire a push event today — it would otherwise leak the recipient's identity to all of the sender's connected devices via the SSE stream. Owners can poll `GET /api/v1/sends/{id}` if they need a live counter.)

### Background GC

The same worker that drains attachment blob tombstones also prunes Sends past their `deletion_date`, writing tombstones so the owner's next `/sync` surfaces the removal.

### CLI quick reference

```bash
hekate send create-text "hello" [--password X] [--max-access N] [--ttl 7d]   # prints share URL
hekate send create-file <path>  [--password X] [--max-access N] [--ttl 7d]   # encrypts + tus-uploads
hekate send list                                       # decrypt names + show access counts
hekate send delete <id> --yes                          # hard delete + tombstone
hekate send disable <id> | hekate send enable <id>     # toggle public access
hekate send open <url> [--password X] [-o out]         # recipient-side fetch + decrypt;
                                                     #   text -> stdout, file -> writes -o (default: original filename)
```

---

## Organizations (M4)

Every membership claim is signed by the org's Ed25519 signing key (BW08); every cross-client wrap is signcryption to a TOFU-pinned X25519 pubkey (BW09 / LP07 / DL02). Cipher-collection assignments inherit per-member effective permissions (`read` / `read_hide_passwords` / `manage`).

Role enum: `owner` / `admin` / `user`. M4 v1 ships a single signer per org (the owner); see [`m4-organizations.md`](m4-organizations.md) for the wire shapes and threat model.

### Lifecycle

```
POST   /api/v1/orgs                                   — create org + genesis roster
GET    /api/v1/account/orgs                           — list orgs the caller belongs to
GET    /api/v1/orgs/{org_id}                          — name + role + roster + active policies
```

Create-org body carries `id` (client-supplied UUIDv7), `name`, `signing_pubkey`, `bundle_sig` (Ed25519 over canonical `(org_id, name, signing_pubkey, owner_user_id)`), `protected_signing_seed` (EncString under owner's account_key), `org_sym_key_id`, `owner_protected_org_key`, and the genesis `roster` (version 1, parent = all-zeros).

### Invites + acceptance (M4.1)

```
POST   /api/v1/orgs/{org_id}/invites                              — owner-only; signcryption envelope to invitee
GET    /api/v1/account/invites                                    — list pending invites for the caller
DELETE /api/v1/orgs/{org_id}/invites/{invitee_user_id}            — owner-only; cancel a pending invite
POST   /api/v1/orgs/{org_id}/accept                               — invitee submits {protected_org_key, org_sym_key_id}
```

Invite body: `{invitee_user_id, role, envelope: SealedEnvelope, next_roster}`. Server validates the next-roster signature + parent chain + version monotonicity, but cannot validate the envelope contents (those are encrypted to the invitee).

### Roster + member management (M4.2 + M4.5b)

```
POST   /api/v1/orgs/{org_id}/members/{user_id}/revoke   — remove member + rotate org sym key
POST   /api/v1/orgs/{org_id}/rotate-confirm             — remaining members consume their fresh envelope
POST   /api/v1/orgs/{org_id}/prune-roster               — recover from a pre-GH#2 roster orphan
```

Revoke body: `{next_roster, next_org_sym_key_id, rewraps: [{user_id, envelope}], cipher_key_rewraps: [{cipher_id, new_protected_cipher_key}], collection_name_rewraps: [{collection_id, new_name}]}`. Server enforces that `rewraps` covers every remaining member and that the next roster + key id are valid and forward-chained. The revoked member's `protected_org_key` row is dropped so subsequent reads return 401.

`rotate-confirm` is the receiver-side counterpart: each remaining member opens their pending envelope (signcryption verify under the owner's pinned signing key), derives a fresh `protected_org_key` wrapped under their own account_key, and submits it.

### Collections (M4.3 + M4.4)

```
POST   /api/v1/orgs/{org_id}/collections                                              — create
GET    /api/v1/orgs/{org_id}/collections                                              — list
DELETE /api/v1/orgs/{org_id}/collections/{collection_id}                              — delete
GET    /api/v1/orgs/{org_id}/collections/{collection_id}/members                      — list members + permissions
PUT    /api/v1/orgs/{org_id}/collections/{collection_id}/members/{user_id}            — grant permission
DELETE /api/v1/orgs/{org_id}/collections/{collection_id}/members/{user_id}            — revoke permission
```

Collection names travel as `EncString` under the org symmetric key with AAD `(collection_id, org_id)`. Permission enum: `"read" | "read_hide_passwords" | "manage"`. Server enforces `read` server-side (refuses PUT/DELETE against the cipher); `read_hide_passwords` is a client hint surfaced in `/sync` per-cipher.

### Org cipher manifest (M2.21 — per-org BW04 analogue)

Per-org signed manifest of org-owned ciphers; only the owner can sign in M4 v1. Non-owner writes leave the manifest stale until the owner refreshes (`hekate org cipher-manifest refresh`).

```
POST   /api/v1/orgs/{org_id}/cipher-manifest      — owner uploads canonical_b64 + signature_b64
GET    /api/v1/orgs/{org_id}/cipher-manifest      — fetch the latest manifest
```

### Org policies (M4.6)

```
GET    /api/v1/orgs/{org_id}/policies                       — list (owner can read every policy; members see their own enforced set)
PUT    /api/v1/orgs/{org_id}/policies/{policy_type}         — owner-only; enable + configure
DELETE /api/v1/orgs/{org_id}/policies/{policy_type}         — owner-only; disable
```

Policy types stored as JSONB so new policy kinds don't need migrations. Shipped today: `master_password_complexity`, `vault_timeout`, `password_generator`, `single_org`, `restrict_send`. `single_org` is enforced server-side (refuses second-org accept when the caller's existing membership has it enabled); the rest are client-enforced hints surfaced in `/sync`.

### CLI quick reference

```bash
hekate org create --name "ACME"
hekate org list
hekate org invite <org_id> <peer_user_id> [--role admin|user]
hekate org invites                                  # pending invites for the caller
hekate org accept <org_id>
hekate org cancel-invite <org_id> <peer_user_id>
hekate org remove-member <org_id> <user_id>          # M4.5b: rotation + rewrap envelopes
hekate org collection create <org_id> --name X
hekate org collection {list,delete,grant,revoke,members} ...
hekate org policy {set,get,list,unset} <org_id> <policy_type>
hekate org cipher-manifest refresh <org_id>
hekate move-to-org <cipher_id> <org_id>
hekate move-to-personal <cipher_id>
```

---

## Service accounts (M2.5)

Org-scoped machine identities. Owned by an organization and managed by org owners; the SA itself authenticates via `pmgr_sat_<id>.<secret>` tokens.

```
POST   /api/v1/orgs/{org_id}/service-accounts                                  — owner-only; create SA
GET    /api/v1/orgs/{org_id}/service-accounts                                  — owner-only; list
POST   /api/v1/orgs/{org_id}/service-accounts/{sa_id}/disable                  — owner-only
DELETE /api/v1/orgs/{org_id}/service-accounts/{sa_id}                          — owner-only; cascades to tokens
POST   /api/v1/orgs/{org_id}/service-accounts/{sa_id}/tokens                   — owner-only; issue a SAT
GET    /api/v1/orgs/{org_id}/service-accounts/{sa_id}/tokens                   — owner-only; list tokens
DELETE /api/v1/orgs/{org_id}/service-accounts/{sa_id}/tokens/{token_id}        — owner-only; revoke a single SAT
GET    /api/v1/service-accounts/me                                             — SAT-authenticated introspection
```

Tokens carry explicit scopes (`org:read`, `secrets:read`, `secrets:write`, ...) and a configurable expiry. The M6 Secrets Manager will add the `secrets:*` scope-check call sites; today the routes simply accept the scope set as the SA's effective authorization.

---

## Sync

### `GET /api/v1/sync?since=<rfc3339>`

Returns every cipher and folder owned by the caller whose `revision_date > since`, plus tombstones recorded after `since`. Omit `since` on first call to get everything.

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "http://hekate.localhost/api/v1/sync?since=2026-05-02T14:00:00Z"
```

```json
{
  "changes": {
    "ciphers":     [ ... ],
    "folders":     [ ... ],
    "tombstones":  [{"kind":"cipher","id":"...","deleted_at":"..."},
                    {"kind":"attachment","id":"...","deleted_at":"..."},
                    {"kind":"send","id":"...","deleted_at":"..."}],
    "attachments": [{"id":"...","cipher_id":"...","filename":"v3...","content_key":"v3...",
                     "size_pt":1234,"size_ct":1282,"content_hash_b3":"...",
                     "revision_date":"...","creation_date":"..."}],
    "sends":       [{"id":"...","send_type":1,"name":"v3...","data":"v3...",
                     "protected_send_key":"v3...","has_password":false,
                     "access_count":0,"max_access_count":null,"deletion_date":"...",
                     "disabled":false,"revision_date":"...","creation_date":"..."}]
  },
  "high_water":  "2026-05-02T14:18:26.426979507+00:00",
  "server_time": "2026-05-02T14:18:26.802111000+00:00",
  "complete":    true
}
```

Persist `high_water` and pass it as the next call's `since`.

---

## Push

### `GET /push/v1/stream`

Server-Sent Events stream, **bearer-authenticated**. Per-user filtered. 15-second `heartbeat` keep-alive. Push is **best-effort**; clients must still drive convergence via `/sync`.

```bash
curl --no-buffer -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://hekate.localhost/push/v1/stream
```

Event format:

```
event: cipher.changed
id: 2026-05-02T14:32:03.556380055+00:00
data: {"id":"019de91a-88e4-71b3-b071-d20cd3ffd023","revision":"2026-05-02T14:32:03.556380055+00:00"}
```

Event types currently emitted:
- `cipher.changed` — create or update
- `cipher.deleted` — soft-delete (trash)
- `cipher.tombstoned` — permanent delete
- `folder.changed` — create or update
- `folder.tombstoned` — permanent delete

Use the `id` field with `Last-Event-ID` to resume on reconnect (server treats it as opaque; clients should re-sync from the last received `revision`).

---

## Errors — common shapes

All errors return JSON `{"error": "<message>"}` plus the relevant status:

| Code | Meaning |
|---:|---|
| 400 | Bad input / malformed body / invalid EncString |
| 401 | Missing or invalid bearer token / wrong credentials / replayed refresh |
| 404 | Resource not found OR not owned by caller (no enumeration leak) |
| 409 | Conflict (duplicate email, revision mismatch). Revision-mismatch body includes `current`. |
| 428 | Precondition Required — `If-Match` missing on `PUT` |
| 500 | Server error (logged server-side) |

---

## Quick end-to-end smoke

The shortest path from cold start to a working vault entry, via Traefik:

```bash
EMAIL="alice@example.com"
MPH=$(python3 -c "import base64; print(base64.b64encode(b'\\x42'*32).decode().rstrip('='))")
SALT=$(python3 -c "import base64; print(base64.b64encode(b'\\x07'*16).decode().rstrip('='))")
ENC="v3.xc20p.kid.AA.AA.AA.AAAAAAAAAAAAAAAAAAAAAA"

# 1. register
curl -fsS -X POST http://hekate.localhost/api/v1/accounts/register \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"kdf_params\":{\"alg\":\"argon2id\",\"m_kib\":131072,\"t\":3,\"p\":4},\"kdf_salt\":\"$SALT\",\"master_password_hash\":\"$MPH\",\"protected_account_key\":\"$ENC\",\"account_public_key\":\"$ENC\",\"protected_account_private_key\":\"$ENC\"}"

# 2. log in
LOGIN=$(curl -fsS -X POST http://hekate.localhost/identity/connect/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=password" \
  --data-urlencode "username=$EMAIL" \
  --data-urlencode "password=$MPH")
ACCESS=$(echo "$LOGIN" | jq -r .access_token)

# 3. create a cipher
curl -fsS -X POST http://hekate.localhost/api/v1/ciphers \
  -H "Authorization: Bearer $ACCESS" -H 'content-type: application/json' \
  -d "{\"type\":1,\"folder_id\":null,\"protected_cipher_key\":\"$ENC\",\"name\":\"$ENC\",\"data\":\"$ENC\",\"favorite\":false,\"reprompt\":0}"

# 4. sync
curl -fsS -H "Authorization: Bearer $ACCESS" http://hekate.localhost/api/v1/sync | jq .
```
