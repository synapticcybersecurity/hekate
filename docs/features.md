# Hekate — Shipped feature inventory

Snapshot as of 2026-05-06. Lists what's actually implemented across
all three first-party clients and the server. For roadmap (what's
planned but not built), see [`status.md`](status.md).

## Clients

- **CLI** (`hekate`) — full feature set: register, login, vault CRUD,
  sends, attachments, orgs (create / invite / accept / collections /
  rotate), 2FA TOTP, account rotate-keys, exports, imports, peer
  pin management, SSH agent + `unlock` daemon.
- **Browser extension** (Chromium MV3, `clients/extension/`) — vault,
  autofill, TOTP entries inline in the vault, sends (text + file),
  attachments, orgs (read + write), 2FA TOTP / WebAuthn enroll +
  login, rotate-keys, peer pin TOFU.
- **Web vault** (SolidJS SPA, `clients/web/`) — vault CRUD, sends
  (text + file), attachments, orgs (read + write), 2FA TOTP /
  WebAuthn, register / login / account-mgmt, rotate-keys, encrypted
  account export, peer pin TOFU, account delete. Mounted at
  `/web/*` (owner mode) and `/send/*` (recipient mode for share
  links).

## Personal vault

- Cipher CRUD with soft-delete + restore + permanent-purge +
  tombstone-based delta sync.
- Six cipher types creatable: login, secure note, card, identity,
  SSH key, TOTP. An additional API-key type (7) is imported from
  other vaults and rendered read-only by the popup.
- Folders.
- TOTP entries inline in the vault (CLI + popup show countdown
  codes; web vault decodes alongside the cipher detail).
- Vault-wide search + type filters.
- Resumable encrypted attachments per cipher (tus 1.0 + PMGRA1
  chunked AEAD; BLAKE3 finalize verify).
- Encrypted account export (passphrase-sealed JSON; bytes
  cross-compatible between CLI + web vault).

## Sharing

- **Sends** — text and file, end-to-end encrypted, anonymous
  recipients, password-gated (Argon2id-PHC server check), max-access-
  count + TTL gates, atomic access-count enforcement, GC worker
  prunes expired rows + blobs.
- **Org sharing** — signcryption-envelope invite to a TOFU-pinned
  peer, single-pending-invite-per-org invariant, BW08 signed roster
  with parent-hash chain, per-org symmetric key wrapped under each
  member's account_key, collections with encrypted names (AAD-bound
  to `(collection_id, org_id)`), member roles (owner / admin / user),
  permission matrix (`read` / `read_hide_passwords` / `manage`),
  owner-only key rotation with member rewrap envelopes,
  receiver-side rotate-confirm consumption, `prune-roster` recovery
  for pre-GH#2 roster orphans.
- **Cipher movement** — `move-to-org` (re-wrap PCK under org sym
  key, assign to collections) and `move-to-personal` (re-wrap PCK
  under account_key, drop from every collection). `org_id` is bound
  into the cipher AAD so the server cannot move ciphers between
  orgs by rewriting the column.

## Imports

Bitwarden JSON · 1Password 1PUX · KeePass KDBX · LastPass CSV.
Pure-parser projection onto a shared `ProjectedImport` shape — folders
materialize first, ciphers thread the new server-side folder ids,
custom fields fold into notes, unsupported categories surface
per-row warnings. CLI-only entry point today (`hekate import …`); web
vault picks them up via the same projection.

## Auth + 2FA

- Argon2id master password derivation; HKDF-derived auth + wrap +
  signing subkeys.
- BW07/LP04 KDF-bind MAC: client refuses to derive if server-supplied
  KDF params aren't bound by a valid HMAC under the master key.
- JWT access tokens (HS256 today; Ed25519 tracked for v1.0).
- Single-use rolling refresh tokens with family-revocation on
  replay.
- TOTP + recovery codes (recovery codes are auth-only, never decrypt
  the vault).
- WebAuthn / FIDO2: popup + web vault drive enrollment + login;
  CLI relies on libfido2 binding (tracked separately).
- Personal access tokens with scopes.
- Service accounts with org-owner-managed tokens (`pmgr_sat_*` wire
  format, `AuthService` extractor).
- Master-password change (rotates KDF salt + signing seed; the
  unwrapped `account_key` value is unchanged so all dependents keep
  decrypting).
- Account-key rotate-keys: atomically re-wraps every personal-cipher
  PCK + Send protected_send_key + Send name + org membership
  protected_org_key + X25519 priv key + signed-manifest re-sign in
  one transaction.

## Server features

- Postgres (multi-tenant) or SQLite (single-binary mode).
- Server-side push (SSE): popup + CLI consume `cipher.changed`,
  `cipher.deleted`, `cipher.tombstoned`, `folder.changed`,
  `folder.tombstoned`, `attachment.changed`, `attachment.tombstoned`,
  `send.changed`, `send.tombstoned` events for live refresh.
- Background GC worker: 60-second tick drains attachment blob
  tombstones, prunes expired tus uploads, expires past-deletion Sends
  + their blobs.
- Outbound webhooks with HMAC signatures + persistent retry queue.
- BW04 signed vault manifest v3 (per-cipher `attachments_root`
  binding so the manifest commits to the attachment set).
- BW08 signed org rosters (parent-hash chain enforced).
- User-enumeration protection on prelogin (deterministic-fake KDF
  values for unknown emails).
- OpenAPI 3.1 spec (auto-generated via `utoipa`) + Scalar docs UI.
- Distroless container image (~42 MB), multi-stage build.
- Structured JSON logging (`tracing`).
- Health endpoints (`/health/live`, `/health/ready`).

## Crypto stack

XChaCha20-Poly1305 (AEAD) · Argon2id (KDF) · Ed25519 (signing) ·
X25519 (key agreement) · BLAKE3 (hashing) · HKDF (subkey
derivation). EncString v3 wire format with AAD binding throughout.
PMGRA1 chunked-AEAD format for attachments + file Sends. TOFU pin
stores (peer + org) on every client; pins are independent per client
today (no server-synced pins yet).

## Threat-model posture

- Master password never leaves the device (only its HKDF-derived
  hash transits).
- `account_key` is unwrapped client-side; the server only sees its
  EncString-wrapped form.
- Send recipient keys live in URL fragments only (never transmitted
  to the server).
- Server is treated as untrusted for envelope contents: every signed
  artifact (vault manifest, org roster, org bundle, peer bundle,
  send envelope) is verified client-side under a TOFU-pinned key.
- Per-cipher AAD binds ciphertexts to their cipher_id + field name
  so the server can't move ciphertext between rows or fields.

## Intentional non-goals

- Wire-format compatibility with any existing vendor's API (chose
  greenfield protocol — modern crypto + delta sync over migration
  ease).
- Hosted SaaS (self-host first; volunteer-operated public instances
  may follow).
- Federated multi-server (UUIDv7 ids + tombstones reserve the door
  for v2).
- Post-quantum primitives (the EncString `alg_id` byte reserves the
  migration path; no PQ in v1).
