# Hekate — Architecture & Cryptography Specification

> **A note on naming.** This document is the project's architecture
> north-star. Code-level identifiers all use `hekate-*` (`hekate-core`,
> `hekate-server`, `hekate-cli`, `hekate` binary, `HEKATE_*` env vars).
> Protocol-frozen byte literals (AAD strings like
> `pmgr-cipher-key-v2:`, `pmgr-vault-manifest-v3`, signature DSTs,
> token wire formats `pmgr_sat_*` / `pmgr_pat_*`, the `PMGRA1`
> chunked-AEAD magic) keep their original `pmgr-` form because they're
> baked into ciphertexts on disk; renaming them would invalidate every
> deployed vault.

A Rust-native, greenfield alternative to Bitwarden targeting full enterprise parity at a fraction of the operational footprint. This document is an architecture/design specification — no code yet.

---

## Context

Bitwarden is the most popular open-source password manager and the reasonable feature target. Its self-hosted .NET stack idles at 1–2 GB across 9 microservices (4 GB practical floor); browser extension cold-start is reported at 3–10 s; the unofficial Rust reimplementation (Vaultwarden) idles at ~50 MB but is API-locked to Bitwarden's 2018-era protocol decisions (full-snapshot `/sync`, AES-CBC+HMAC, PBKDF2 default, SignalR push). The Bitwarden mobile app's poor performance under Xamarin drove a full native rewrite shipped in Jan 2025. There is room for a successor that combines Vaultwarden's footprint with native clients on every platform, modern cryptography, delta sync, and full enterprise features (SSO/SCIM/Key Connector/Secrets Manager) that neither Vaultwarden nor any other open-source alternative covers.

**Goals.** Open-source (AGPL-3.0 server + GPLv3 clients), Rust-native, single-binary self-host with 100 MB idle memory floor, sub-200 ms autofill TTI, full enterprise feature parity with Bitwarden Enterprise. Greenfield wire protocol — no compatibility with Bitwarden's existing API. Native clients on every platform from day one (no Electron, no Angular popup).

**Non-goals.** Bitwarden-client compatibility. Cross-vendor import/export beyond CSV/KDBX/1Pux/Bitwarden-export. Hosted SaaS (initially) — focus on self-host first.

### Design pillars (non-negotiable)

These two are the user-facing pain points with Bitwarden today. Every architecture decision is checked against them.

1. **Sync that "just works"** — sub-2 s cross-device propagation p95, automatic recovery from network/push failures, explicit conflict surfacing (no silent last-writer-wins data loss), full offline support with queued writes, no third-party push relay required (mobile push goes APNs/FCM direct). Sync correctness is testable and tested as a first-class invariant. See §4.
2. **Everything has a stable, documented API** — every action available in *any* client (web, desktop, mobile, browser extension) is available over REST under `/api/v1` with the same authentication model. The CLI is a thin wrapper, not a privileged side door. The "Public API" is not a separate restricted surface — there is one API. Personal access tokens, OAuth client credentials, and webhooks are first-class. See §7.

---

## 1. High-Level Architecture

```
                       ┌─────────────────────────────────────────────┐
                       │             hekate server (single binary)     │
   Browser ext ──┐     │  ┌─────────────────────────────────────┐    │
   Desktop ──────┤     │  │  axum HTTP/2 + SSE + WebSocket      │    │
   iOS / Android─┼─────┤  │  /api  /identity  /push  /admin     │    │
   Web vault ────┤     │  │  /scim  /public  /secrets           │    │
   CLI ──────────┘     │  └────────────┬────────────────────────┘    │
                       │               │                             │
                       │  ┌────────────▼────────────┐  ┌──────────┐  │
                       │  │ core domain (Rust)      │  │ workers  │  │
                       │  │ - vault, orgs, sync     │  │ - events │  │
                       │  │ - auth, KDF, RSA wrap   │  │ - email  │  │
                       │  │ - secrets manager       │  │ - icons  │  │
                       │  │ - SSO/SCIM/policies     │  │ - reports│  │
                       │  └────────────┬────────────┘  └────┬─────┘  │
                       │               │                    │        │
                       │  ┌────────────▼────────────────────▼──────┐ │
                       │  │ sqlx (Postgres or SQLite)              │ │
                       │  └────────────────────────────────────────┘ │
                       └─────────────────────────────────────────────┘
                                       │
                                       ├── Object store (attachments): local FS via `BlobStore` trait (M2.24); S3/MinIO via `object_store` crate (M2.24a)
                                       ├── Push relay (mobile): APNs + FCM
                                       └── Optional Redis (multi-replica pub/sub fanout)
```

Single-process by default. Long-running async workers run on the same tokio runtime as the HTTP server (separate task pool). Horizontal scale-out adds a Redis pub/sub bus for cross-replica WebSocket/SSE fanout — optional, only needed beyond ~50k concurrent clients per node.

---

## 2. Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Rust 2024 edition | Memory safety for crypto-handling daemon; lowest per-connection memory; shared crate for clients via WASM/FFI |
| HTTP | axum + tower + hyper | Lowest memory of major Rust frameworks; first-class HTTP/2; tower middleware ecosystem |
| Async runtime | tokio (multi-thread) | Industry standard; works with sqlx, hyper, tonic if gRPC is added later |
| DB driver | sqlx (compile-time-checked queries) | Async; one query type for both Postgres and SQLite |
| Database | Postgres 16+ (multi-tenant) / SQLite-WAL (single-tenant) | Postgres for SaaS, large orgs; SQLite for self-host home/SMB. Switched via cargo feature + URL scheme. |
| Migrations | sqlx-cli + handwritten SQL | Avoid ORM-level abstractions over schema |
| Crypto | RustCrypto (`aes-gcm-siv`, `chacha20poly1305`, `argon2`, `hkdf`, `x25519-dalek`, `ed25519-dalek`, `p256`) | Pure-Rust, audited subset, no FFI; one stack on server + WASM client |
| Object storage | `BlobStore` trait + local FS (M2.24); `object_store` crate for S3/MinIO/Azure/GCS (M2.24a) | Trait keeps backends pluggable. We deliberately did NOT pick OpenDAL — `object_store` covers our four target backends at ~3× lower compile cost, and most Hekate deployments are single-host on local FS anyway. |
| Push (mobile) | `a2` (APNs) + `fcm-rs` | First-party — no relay dependency |
| Email | `lettre` + ARC/DKIM via opendkim | Self-host friendly |
| Observability | `tracing` + OpenTelemetry exporter | OTLP to any backend |
| Config | `figment` (TOML + env) | Single `hekate.toml` |
| CLI for ops | `clap` v4 derive | `hekate-server admin create-user`, etc. |

Single statically-linked binary (~25 MB stripped, musl). Distributed as Docker image (~30 MB scratch base), `.deb`/`.rpm`, Homebrew tap, and raw binary. Memory budget: ≤100 MB RSS at idle for a 100-user instance.

---

## 3. Data Model

All sensitive fields are stored as `EncString` (see §5). Plaintext on the server is intentionally kept to identifiers, type tags, timestamps, and revision cursors — nothing that leaks vault contents.

### Core tables

- **`users`** — `id`, `email` (lowercased, unique), `kdf_params` (JSONB: alg=`argon2id`, m, t, p, salt), `master_password_hash`, `protected_account_key` (EncString), `account_public_key`, `protected_account_private_key`, `revision_date`, `security_stamp` (UUIDv7, rotates on password change / 2FA add / device revoke).
- **`devices`** — `id`, `user_id`, `name`, `type` (web/ext/desktop/ios/android/cli), `push_token`, `public_key` (X25519), `protected_device_key` (EncString — for trusted-device unlock), `last_seen`, `created_at`.
- **`ciphers`** — `id` (UUIDv7), `user_id` NULLABLE, `org_id` NULLABLE, `folder_id` NULLABLE, `type` (1–6: login, secure_note, card, identity, ssh_key, totp_only), `protected_cipher_key` (EncString — wrapped by user or org symmetric key), `data` (EncString blob — JSON-encoded type-specific fields), `name` (EncString), `notes` (EncString, nullable), `favorite` (bool), `reprompt` (smallint), `revision_date`, `creation_date`, `deleted_date` NULLABLE (soft-delete trash). Exactly one of `user_id`/`org_id` is set.
- **`folders`** — user-private grouping. `id`, `user_id`, `name` (EncString), `revision_date`.
- **`organizations`** — `id`, `name`, `billing_email`, `plan_type`, `protected_org_private_key`, `org_public_key`, `created_at`. Org symmetric key is wrapped per-member in `org_users`.
- **`org_users`** — `org_id`, `user_id`, `role` (owner/admin/manager/user/custom), `status` (invited/accepted/confirmed/revoked), `protected_org_key` (EncString — org sym key wrapped to user's RSA pubkey), `access_all` (bool), `external_id` (for SCIM).
- **`groups`** — `org_id`, `name`, `external_id`. Membership in `group_users`. Group→collection access in `group_collections`.
- **`collections`** — `org_id`, `name` (EncString), `external_id`. Membership: `collection_users` and `collection_groups` with `read_only` / `hide_passwords` / `manage` flags.
- **`cipher_collections`** — many-to-many.
- **`attachments`** (M2.24) — `id` (UUIDv7), `cipher_id`, `user_id` (uploader, nullable post-deletion), `org_id` (denormalized), `filename` (EncString under cipher key), `content_key` (EncString — per-attachment 32-byte AEAD key, wrapped under cipher key), `size_pt` / `size_ct` (plaintext / ciphertext byte counts), `storage_key` (backend-relative blob path), `content_hash_b3` (BLAKE3 of ciphertext, base64-no-pad), `status` (0 uploading / 1 finalized), `revision_date`, `creation_date`. Wire format for the file body: `PMGRA1` chunked AEAD (1 MiB plaintext chunks, XChaCha20-Poly1305 with chunk_index in nonce + AAD final-flag truncation guard) — see `hekate-core::attachment`. Companion tables: `attachment_uploads` (tus 1.0 state machine: `upload_token`, `bytes_received`, `expected_size`, `expires_at`) and `attachment_blob_tombstones` (durable cleanup queue for blob backend).
- **`sends`** — ephemeral encrypted text/file; `id` (UUIDv7 with embedded base62 token), `user_id`, `type`, `data` (EncString), `key` (EncString), `password` (Argon2id hash for access gate), `max_access_count`, `access_count`, `expiration_date`, `deletion_date`, `disabled`.
- **`policies`** — `org_id`, `type` (master_pw_complexity, two_factor_required, single_org, personal_vault_disable, generator_constraint, max_vault_timeout, disable_send, send_options, password_generator_policy, restrict_provider_admin), `enabled`, `data` (JSONB).
- **`events`** — append-only audit log. `id`, `org_id` NULLABLE, `user_id` NULLABLE, `device_id`, `cipher_id` NULLABLE, `type` (enum), `actor_user_id`, `actor_ip`, `created_at`. Partitioned by month in Postgres.
- **`auth_requests`** — passwordless / device-approval / TDE. `id`, `requesting_device_id`, `approving_device_id` NULLABLE, `request_public_key` (X25519), `response_protected_key` (EncString), `status`, `expires_at`.
- **`emergency_access`** — grantor/grantee, `protected_grantor_key` (wrapped to grantee pubkey), wait_days, type (view/takeover), status.
- **Secrets Manager:** `projects`, `secrets`, `service_accounts`, `access_tokens` — see §10.

### Identifier conventions

- **UUIDv7** everywhere — time-ordered, B-tree friendly, no `created_at` index needed for chronological scans.
- **`revision_date`** is `TIMESTAMPTZ` with millisecond precision. Sync uses `(revision_date, id)` cursors for stable pagination.
- **`security_stamp`** is rotated server-side on any auth-affecting change, invalidating all existing tokens.

---

## 4. Sync Protocol

**The single most important system.** Bitwarden returns the entire vault on every sync, has occasional 5–60 min cross-device lags (Cloudflare-routing regression in 2024), silently last-writer-wins on conflicts, and requires a third-party Bitwarden cloud relay for mobile push even on self-host. Hekate's sync is designed to fix all of this.

### Design invariants

- **Convergence:** Any two clients that both see the network within a bounded window converge to the same vault state.
- **Eventual consistency under partition:** A client offline for hours/days reconverges as soon as connectivity returns. Queued writes apply in order.
- **No silent data loss:** Concurrent edits on the same cipher produce a *visible* conflict (both versions retained, user resolves), never overwritten silently.
- **Push is an optimization, never a correctness requirement:** Every client's poll loop alone is sufficient to converge; push only reduces latency.
- **No third-party relays:** Self-hosters' mobile push goes directly through their own APNs/FCM credentials, not through any vendor-controlled relay.
- **Observability:** Every client surfaces sync state (last-sync timestamp, queue depth, last error) so users see what's happening.

### Cursor-based delta sync

- `GET /api/v1/sync?since=<watermark>&cursor=<opaque>&include=ciphers,folders,collections,sends,policies` returns:
  ```json
  {
    "changes": {
      "ciphers":     [{...}, ...],
      "folders":     [...],
      "collections": [...],
      "policies":    [...],
      "sends":       [...],
      "tombstones":  [{"id": "...", "kind": "cipher", "deleted_at": "..."}, ...]
    },
    "next_cursor":   "...",
    "high_water":    "2026-05-02T12:34:56.789012Z",
    "complete":      true,
    "server_time":   "2026-05-02T12:34:56.802111Z"
  }
  ```
- Client persists `high_water` and uses it on the next call. Multi-page handled by `cursor` within a watermark window for transactional consistency.
- **Page size auto-tuning:** server caps response size at ~512 KB; clients with slow links get smaller pages, fast clients fewer round trips.
- **Bandwidth efficiency:** HTTP/2 + brotli; binary cipher blobs not re-base64'd unnecessarily.
- Tombstones live for 90 days. Clients that fall behind beyond that get a forced full re-sync (rare; surfaced in UI).
- Per-resource `revision_date` ensures *only* changed objects are sent across every resource type.

### Conflict detection and resolution

Every cipher write carries the client's last-known `revision_date` as an `If-Match`-style precondition (`X-Hekate-If-Revision: <timestamp>`).

- **No conflict** (server `revision_date` matches): write applied, new `revision_date` returned.
- **Conflict** (server has been updated since): server returns `409 Conflict` with the current server version. Client materializes a **conflict twin** — both versions persist as separate ciphers with `conflict_of: <orig_id>` metadata; UI surfaces a "two versions of this item" banner with a side-by-side diff and lets the user pick or merge. No silent overwrite, ever.
- **Field-level merge** for the common case where two clients edited disjoint fields: the protocol exposes the prior known state via a Merkle-ish hash chain on `(cipher_id, field_name, content_hash)`; the client can detect that the conflicting edits don't touch the same fields and auto-merge with explicit user notification. Auto-merge is opt-in per-org policy — defaults off for safety.

This is the explicit conflict surfacing Bitwarden lacks.

### Offline-first client model

- Every client runs against a local SQLite store as the source of truth for *reads*. Every read is offline by definition; UI never blocks on the network.
- Writes are appended to a local **outbox** (`outbox(id, operation, payload, created_at, attempts, last_error)`) before optimistically updating the local store.
- A background sync worker drains the outbox when online; failed writes retry with exponential backoff (1 s, 2 s, 4 s, …, 5 min cap).
- On network reconnect, the worker first **drains pending writes** (in order), then **fetches deltas**, then **resolves conflicts**, then notifies UI of any conflicts that need user attention.
- Outbox is durable across app restarts. Devices offline for weeks still converge cleanly when they come back.

### Push channels (multi-transport, automatic failover)

Every client supports **all available** push channels and falls back automatically. Push is treated as best-effort wake-up.

| Channel | Used by | Transport | Wake latency |
|---|---|---|---|
| **Server-Sent Events** | Web vault, browser extension, desktop, CLI daemon | `GET /push/v1/stream` over HTTP/2 with `Last-Event-ID` resume; auto-reconnect with jittered backoff | <100 ms p50 |
| **WebSocket** | Optional for clients behind picky proxies that buffer SSE | `GET /push/v1/ws`, same payloads | <100 ms p50 |
| **APNs (direct)** | Native iOS — silent push (`content-available: 1`) | `a2` crate; tenant-supplied APNs key in self-host config | <2 s p95 |
| **FCM (direct)** | Native Android — high-priority data message | `fcm-rs` crate; tenant-supplied service-account JSON | <2 s p95 |
| **Web Push (VAPID)** | PWA / web vault background | `web-push` crate | <5 s p95 |
| **Polling** | Always — fallback when nothing else works | Adaptive: 30 s when active, 5 min when idle, exponential backoff on failures | bounded |

Payloads are 64–256 byte typed envelopes (`{"v":1,"t":"cipher.changed","ids":["..."],"rev":"..."}`); the wake triggers a delta-sync. Push **never** carries cipher contents — the encrypted vault is fetched over the authenticated REST channel.

**Failure handling:**
- Each client tracks `last_push_received_at`. If it falls behind the polling cadence by 2× without a push event, the client logs a sync-health warning and increases poll frequency until pushes resume.
- Server tracks per-device last-delivery timestamps and exposes them at `/api/v1/devices/me/sync-health` for client diagnostics.

### Multi-replica fanout (server side)

- **Single-node:** in-process tokio broadcast channel. Zero ops cost.
- **Multi-node:** Redis Streams (preferred) or NATS. Each replica subscribes; events fanned out to locally-connected SSE/WS sessions. Consumer groups ensure exactly-once delivery to each replica.
- Sticky sessions **not required** — any replica can serve any device.
- Push delivery to APNs/FCM/WebPush is a worker job pulled from the same stream; mobile push works the same on a 1-node and N-node deployment.

### Real-time live editing (optional, opt-in per collection)

For shared org collections where multiple admins may edit simultaneously, an optional **presence channel** (`/push/v1/presence/{collection_id}`) lets clients announce which item they're currently editing. UIs show a "user X is editing this item" badge before submission, eliminating most conflicts before they happen. Presence is opt-in to avoid leaking activity metadata in default deployments.

### Attachment sync (M2.24)

- **Resumable uploads** via the [tus 1.0](https://tus.io/) protocol — implemented as a tight axum-native subset (`creation`, `creation-with-upload`, `termination`, `checksum` extensions) rather than depending on the unmaintained `tower-tus` crate. Surface: `OPTIONS /api/v1/attachments` (discovery), `POST /api/v1/attachments` (create + bind to cipher), `HEAD/PATCH/DELETE /api/v1/tus/{token}`. Large files survive flaky networks via `Upload-Offset` resume.
- **Auth model:** every endpoint requires JWT/PAT bearer with `vault:write` (creation/PATCH/DELETE) or `vault:read` (HEAD/GET). Creation binds to a specific `cipher_id`; the cipher must be writeable (personal owner or `effective_permission == Manage` for org). The `upload_token` is a 32-byte random capability — unguessable so a leaked URL cannot be hijacked.
- **No signed URLs.** M2.24 always proxies the blob body through the auth-gated server (`GET /api/v1/attachments/{id}/blob`). Signed URLs are reserved for M2.24a once we add the S3/MinIO `object_store` backend; for the local-FS backend they would just leak the path.
- **Per-attachment encryption keys** (32 bytes random) wrapped under the cipher key with AAD `attachment_id || "|key|" || cipher_id`. Body uses the chunked-AEAD `PMGRA1` format so neither side has to buffer the full file before AEAD verifies (chunk-by-chunk).
- **Integrity:** client computes BLAKE3 of the entire ciphertext at upload time and ships it in `Upload-Metadata: content_hash_b3=...`. Server re-hashes from disk on finalize and rejects on mismatch. Per-AEAD-chunk integrity is provided by the chunked-AEAD format itself; we deliberately do **not** use tus per-PATCH `Upload-Checksum: sha-256` since it would force the client to checksum every transport chunk on top of the AEAD work, and the AEAD already covers tamper detection at decryption time.
- **Quotas** (config-driven): `max_attachment_bytes` (per-file, default 100 MiB), `max_cipher_attachment_bytes` (default 1 GiB), `max_account_attachment_bytes` (default 10 GiB). Enforced at tus creation against `SUM(size_ct) WHERE status=1` plus reserved bytes from in-progress uploads. Org-policy-driven attachment limits land alongside M4.6 policies.
- **BW04 set-level integrity** extends to attachments via a per-cipher `attachments_root` field on every entry of the v3 vault manifest (SHA-256 of the sorted `(att_id, revision_date, deleted)` tuples for that cipher). The client signs the manifest under the user's Ed25519 account-signing key after every attachment write; other devices verify on /sync, so a malicious server cannot drop, replay, or resurrect an attachment without detection.

### Sync verification (testing)

- **Property-based** sync state-machine tests with `proptest`: random sequences of writes/reads/network partitions/recoveries on N simulated clients must always converge.
- **Jepsen-style** linearizability tests on the server side: concurrent mutations + replica failures cannot produce stale reads or lost writes within the contracted consistency model.
- **End-to-end p95 sync latency** measured continuously in CI across simulated geographic regions.

---

## 5. Cryptography

### Defaults (2026)

- **Master KDF:** Argon2id, m=128 MiB, t=3, p=4, salt = random 16 bytes (NOT email; salt is stored alongside `master_password_hash`). Auto-tunable on enrollment to ~500 ms on the device.
- **Symmetric:** **XChaCha20-Poly1305** (24-byte nonce — random nonces are safe; no need for nonce coordination across clients). AES-GCM-SIV is the alternative if FIPS profile is needed.
- **Asymmetric:** X25519 for ECDH key wrapping (replaces RSA-OAEP), Ed25519 for signatures. RSA stays only for SSO assertion verification where IdPs require it.
- **HKDF-SHA-256** for sub-key derivation.
- **Per-cipher random key** (32 bytes, XChaCha20-Poly1305) wrapping every field of that item; Cipher Key wrapped by user or org symmetric key. Bitwarden adopted this in 2023; we ship it from day 1.

### Key hierarchy

```
Master Password ─Argon2id(salt)─► Master Key (32B)
                                  │
                                  ├─HKDF("auth")─► Master Password Hash → server (1 PBKDF2 round, then server Argon2id-stored)
                                  └─HKDF("wrap")─► Stretched Master Key (32B)
                                                   │
                                                   └─[XChaCha20-Poly1305]─► Account Key (32B, random)
                                                                              │
                                                                              ├─wraps Account Private Key (X25519 + Ed25519)
                                                                              ├─wraps Org Symmetric Key (one per org membership)
                                                                              └─wraps Cipher Keys (one per personal cipher)

Account Public Key ──used by other users to wrap shared keys to you
Org Symmetric Key  ──wraps Cipher Keys for org-owned ciphers; wrapped per-member to their Account Public Key (X25519)
```

Never PBKDF2 by default. Bitwarden's "design flaw" of relying on weak server-side iterations as a substitute for client-side strength is explicitly avoided — server stores `Argon2id(master_password_hash, server_salt, m=64MiB)` solely as a defense-in-depth measure, not as the only barrier.

### EncString format

```
v3.<alg_id>.<key_id>.<nonce_b64>.<aad_b64>.<ct_b64>.<tag_b64>
```

- `v3` — protocol version. Future-proofs algorithm migration.
- `alg_id` — `xc20p` (XChaCha20-Poly1305), `agcms` (AES-GCM-SIV), `x25519` (asymmetric wrap), `ed25519` (signature).
- `key_id` — the wrapping key's UUIDv7 (so we can rotate without re-encrypting non-rotated items).
- AAD includes `cipher_id || field_name` to bind ciphertext to its location — prevents mix-and-match attacks across fields.

### Key rotation

Per-cipher keys (PCK) make rotation cheap: re-wrap PCKs only, leave field ciphertexts untouched. A single `POST /api/v1/account/rotate-keys` atomically swaps the Account Key, the wrapping of the Account Private Key under it, every personal-cipher PCK wrap, every Send `protected_send_key`, and every `organization_members.protected_org_key` for the caller's memberships — all in one transaction. Org-key rotation re-wraps to all confirmed members; pending invites get re-issued.

**Implementation status (M2.26).** Shipped end-to-end:

- Server: `POST /api/v1/account/rotate-keys` requires master-password re-auth + `account:admin` scope, validates every cipher/send/org-id in the rewrap arrays belongs to the caller, applies all updates in a single SQL transaction, bumps `security_stamp`, revokes refresh tokens, issues new tokens. Org-owned cipher PCKs are deliberately untouched — they wrap under the org symmetric key, not the user's account key, so swapping the user's account_key doesn't reach them.
- CLI: `hekate account rotate-keys` prompts for the master password, /sync's everything that needs re-wrapping, generates a fresh 32-byte account_key, decrypts every PCK / send_key / org_sym_key wrap under the old key + re-wraps under the new key, re-wraps the X25519 private key, and POSTs one bundle. Local state is updated atomically with the new wraps + tokens.
- **What is preserved:** the master password (and therefore the master key, the HKDF-derived signing seed, and the BW04 manifest signing pubkey — manifests keep verifying without re-upload), the X25519 keypair (peer TOFU pins keep working), and the existing PCKs themselves (cipher field ciphertexts are never re-encrypted; only the wrap of each PCK rotates).
- **What rotates:** the symmetric `account_key`, every wrap that depends on it, every refresh token, and the `security_stamp` (so other devices' access tokens are invalidated on next use). Other devices need to re-login.
- A separate `--full` flag that also rotates the X25519 keypair (forces every peer to re-pin) is reserved for a future milestone; M2.26 only ships the symmetric rotation.

### Send

Each Send carries a 256-bit URL-fragment secret (`#/send_id/key`). Client derives a 256-bit content key via HKDF (`info=pmgr-send-content-v1`, salt=send_id) and encrypts payload with XChaCha20-Poly1305 (AAD = `pmgr-send-data-v1:<send_id>:<send_type>` so a server cannot move payload bytes between Sends or flip text↔file). Optional access password is a server-side Argon2id-hashed gate, never feeds encryption (matches Bitwarden's threat model — server can revoke but not decrypt).

**Implementation status:** text and file Sends both shipped — `hekate-core::send`, `crates/hekate-server/src/routes/sends.rs` (authenticated owner CRUD + `POST /api/v1/public/sends/{id}/access` for anonymous recipients + sender-authenticated tus body upload at `POST /api/v1/sends/{id}/upload` and `HEAD/PATCH/DELETE /api/v1/tus-send/{token}` + anonymous `GET /api/v1/public/sends/{id}/blob/{download_token}`), `hekate send {create-text, create-file, list, delete, disable, enable, open}` CLI. Sender-stored `protected_send_key` is the 32-byte send_key wrapped under the account key with AAD bound to the send_id, so the sender can list/edit from any device without re-typing the URL fragment. Background GC drops rows past `deletion_date` (and enqueues the file-Send body for the blob-tombstone drain). Public access enforces (in order) row exists → not disabled → not past deletion_date → not past expiration_date → for file Sends, body finalized → password matches (Argon2id-PHC, constant time) → atomic `access_count < max_access_count` bump. For file Sends, `/access` additionally mints a 5-minute `download_token` for `/blob/{token}`; multiple GETs within TTL are allowed (network retry).

**File-Send wire model.** Sender generates `send_key` (32B random, URL fragment) AND `file_aead_key` (32B random, separate). The body is encrypted with `file_aead_key` using the M2.24 `PMGRA1` chunked-AEAD format unchanged — AAD's location bytes are the `send_id`. The encrypted metadata payload (`data` field) carries JSON `{filename, size_pt, file_aead_key_b64}` encrypted with `content_key = HKDF(send_key, salt=send_id)`. Recipients HKDF-decrypt the metadata to extract `file_aead_key`, then chunked-AEAD-decrypt the downloaded body. Server never sees either key in the clear.

### SSH agent

Vault item type 5. Generates Ed25519 by default; imports OpenSSH RSA/ECDSA. Desktop client runs a local `SSH_AUTH_SOCK` (UNIX socket on macOS/Linux, named pipe on Windows). Each signature requires per-use approval (configurable: always-prompt, prompt-once-per-app, allow-list). Forwarding supported with explicit per-host opt-in.

### WebAuthn / Passkeys

Hekate is a credential provider on every platform: iOS 17+ AutoFill Provider, Android 14+ Credential Manager, browser extension `chrome.credentials` shim. Passkeys stored as cipher type 1 with a `passkey` sub-record (credential_id, rp_id, user_handle, counter, encrypted_private_key). Sync end-to-end encrypted like any other cipher. Passkey-as-2FA, login-with-passkey, and storing site passkeys are all free.

---

## 6. Auth & Identity

### Token model

OAuth 2.0 + OIDC. Identity is internal (no separate Identity microservice) — one axum router under `/identity/`.

- `POST /identity/connect/token` — `grant_type=password|refresh_token|sso|client_credentials|webauthn`
- Access token: signed JWT (Ed25519, 1 h TTL), `kid` rotates monthly.
- Refresh token: opaque random 256 bits, stored hashed (Argon2id, m=8MiB) server-side, single-use rolling refresh.
- Device binding: every refresh-token row carries `device_id`; revoking a device invalidates the chain.
- All access tokens validated by checking the user's `security_stamp` matches the JWT claim, so a single DB write invalidates every outstanding token.

### Two-factor providers

- TOTP (RFC 6238, SHA-1, 30 s)
- WebAuthn / FIDO2 — multiple credentials; default for everyone
- Email OTP (fallback, never primary)
- Duo (org policy)
- Recovery codes (10 × base32)
- Hardware OTP (YubiKey OTP via Yubico cloud or self-host validation server)

Priority order: WebAuthn → Duo → TOTP → YubiKey → Email.

### Deferred to managed-service tier

The following enterprise capabilities are **not** on the open-source
roadmap. They're positioned for a future managed-service offering on
top of the self-host-first OSS core. Self-host operators can build
their own equivalents through the standard org / policy / token
primitives; the OSS protocol does not block any of them.

- **SSO (SAML 2.0 / OIDC)** with JIT provisioning.
- **Trusted Device Encryption** (master-password-less SSO).
- **Key Connector** (self-hosted key-server tier).
- **SCIM 2.0** for IdP-driven user/group provisioning.
- **Directory Connector** (LDAP/AD/Entra/Okta/G-Workspace pull).
- **Emergency access** (grantor-to-grantee X25519 wrap with
  configurable wait period).

### Active Trust UX redesign — see `m5-trust-ux.md`

M5 replaces the current per-pair TOFU pinning model with an
owner-set-rooted trust model: every member TOFU-pins the org owner-set,
and the owner-set endorses every member's fingerprint in a signed
roster. Per-owner Ed25519 keypairs, 2-of-N quorum for owner-set changes,
1-of-N signing for routine ops, fingerprint-bound roster entries,
strong-mode toggle, and FROST-Ed25519 threshold recovery as a deferred
M5.x extension. See `m5-trust-ux.md` for the locked design.

---

## 7. APIs

**One unified, fully-documented REST API.** Bitwarden has two: an internal `/api` consumed only by its own clients, and a separate `/public/api` that explicitly excludes vault items (you cannot create/read/update/delete a cipher via Bitwarden's Public API — only org admin operations). Hekate collapses these. **Every action available in any client is available over `/api/v1` to any caller with appropriate auth.** The CLI is a thin client of this API; clients have no special back door.

### API completeness contract

This is a binding rule, not aspirational:

- Every cipher type, every field, every action (create/read/update/delete/restore/share/move/import/export/attach/detach/generate/audit) → REST endpoint.
- Every org operation (members, groups, collections, policies, events, billing, SSO config, SCIM tokens) → REST endpoint.
- Every personal account operation (KDF settings, 2FA enroll/disable, device list/revoke, key rotation, emergency contacts, vault export, account delete) → REST endpoint.
- Every Secrets Manager operation → REST endpoint.
- Every push/sync operation → REST endpoint.
- The CLI implementation is required to use only public REST endpoints — enforced in CI by a test that diffs `cli.allowed_endpoints()` against `openapi.json`. Any CLI feature without an API endpoint is a build break.
- New features land "API first": the OpenAPI spec is updated and merged before the corresponding client code.

### Surface map

| Surface | Path | Auth | Purpose |
|---|---|---|---|
| **Core API** | `/api/v1/...` | Bearer JWT (user, service account, or PAT) | Everything. Ciphers, folders, collections, orgs, members, groups, policies, events, sends, attachments, devices, account, 2FA, KDF, key rotation, emergency, reports, sync, import/export, webhooks. |
| Identity | `/identity/connect/{token,authorize,revoke,jwks}` | n/a (issues tokens) | OAuth 2.0 + OIDC token endpoint, refresh, device approval, JWKS publication |
| Push | `/push/v1/{stream,ws,presence}` | Bearer JWT | SSE / WS / presence channels |
| SCIM | `/scim/v2/...` | Per-org SCIM bearer token | IdP-driven user/group provisioning |
| Server admin | `/api/v1/server/...` | Bearer JWT + `server_admin` role | Operator-only: license, server settings, global user list, server health. Lives under same prefix; just role-gated. |
| Health | `/health/{live,ready}` | none | k8s probes |
| Metrics | `/metrics` | optional bearer | Prometheus exposition |
| OpenAPI | `/api/v1/openapi.json`, `/api/v1/docs` | none | Spec + Scalar/Swagger UI |

All endpoints versioned by URL path. Rate-limited (`tower-governor`) with per-IP and per-token buckets; aggressive on auth endpoints. CORS allow-list configurable for self-host.

### Authentication tokens

Three first-class token types — all interchangeable everywhere a bearer token is accepted:

1. **User access token (JWT, 1 h)** — standard interactive login. Refreshed via OAuth refresh-token rotation.
2. **Personal Access Token (PAT)** — long-lived, user-issued, scoped (e.g. `ciphers:read`, `secrets:write`, `org:42:admin`), revocable, last-used timestamp tracked. Created in the web vault under Account → Tokens or via API. Replaces "I have to use the CLI for that" — you can `curl` your vault with a PAT.
3. **Service Account access token** — machine identity owned by an org (Secrets Manager and beyond). Same shape as PAT but org-scoped and managed by org admins.

Scope grammar: `<resource>:<action>[:<id>]`. Examples: `ciphers:read`, `ciphers:write:org:42`, `secrets:read:project:abc`, `org:42:admin`, `account:export`. Tokens display their scopes in UI. A PAT cannot exceed the issuing user's permissions.

### Webhooks (outbound API)

Every event in the audit log is publishable as a signed webhook. Org admins configure HTTPS endpoints under `/api/v1/orgs/{id}/webhooks` with:
- Event-type filter (`cipher.created`, `member.invited`, `policy.changed`, `secret.rotated`, …).
- HMAC-SHA-256 signature in `X-Hekate-Signature` (same scheme as Stripe).
- At-least-once delivery with exponential backoff and a 7-day retention queue.
- Per-webhook delivery log visible in the UI.

Closes the loop: external systems can react to vault changes without polling.

### OpenAPI 3.1 spec

- Generated from Rust types via `utoipa` — handler signatures are the source of truth, spec drift is impossible.
- Published at `/api/v1/openapi.json` on every server.
- Used to generate official client SDKs (`hekate-sdk-{rust,py,node,go,ruby,java,dotnet,php}`) automatically in CI.
- A copy of the spec lives in the repo and is diffed in PRs — breaking changes require a new version path (`/api/v2`).

### CLI is just a wrapper

`hekate` (human CLI) and `pms` (machine CLI) call only public endpoints, like any third-party SDK. Two consequences:
- **Parity by construction:** anything `hekate` can do, `curl` can do.
- **No special-snowflake CLI:** if a feature is missing from the API, it's missing from the CLI too — surfaces the gap immediately.

### Developer ergonomics

- `curl https://vault.example.com/api/v1/openapi.json | npx @scalar/cli` for instant docs.
- Every endpoint has request/response examples in the spec.
- A `hekate-sdk` for each major language is generated, versioned, published.
- Postman / Insomnia collections auto-generated.

---

## 8. Clients

All clients share a Rust core (`hekate-core`) compiled to:
- Native lib for desktop (Tauri direct call)
- iOS XCFramework via `cargo-xcframework`
- Android `.aar` via `cargo-ndk` + JNI bindings
- WASM (`wasm-bindgen`) for web vault and browser extension

`hekate-core` provides: KDF, EncString encode/decode, Cipher Key wrap/unwrap, sync state machine, local SQLite store, search index, token client. Each platform shell handles UI, biometrics, autofill provider integration, push registration.

### Desktop — Tauri 2

- ~30 MB idle vs Electron's ~250 MB; ~10 MB installer vs ~120 MB.
- Native menus, system tray, OS keychain integration (macOS Keychain, Windows DPAPI, Linux Secret Service / kwallet).
- Biometric unlock via Touch ID / Windows Hello / fprintd.
- SSH agent socket lives in the desktop process.

### iOS — Swift / SwiftUI

- AutoFill Credential Provider extension (iOS 17+ unified passkey + password).
- App Group shared keychain between main app and extension.
- WidgetKit lock-screen widget for TOTP.
- Apple Watch companion for TOTP push approvals (login-with-device).

### Android — Kotlin / Jetpack Compose

- Credential Manager API (Android 14+) for passwords + passkeys.
- Accessibility-service autofill fallback (older Android).
- Wear OS companion.

### Web vault — SolidJS (or Svelte)

- Not Angular. Solid's fine-grained reactivity gives sub-50 ms render on 10k-item lists with no virtualization tricks.
- WASM `hekate-core` for crypto.
- IndexedDB for encrypted vault cache; FTS via `hekate-core` in-memory index after unlock.

### Browser extension — Manifest V3

- Service worker holds a small encrypted hot-cache in `chrome.storage.session` (cleared on browser close — never on-disk).
- **Pre-warm by origin**: content script at `document_start` posts `{origin}` → worker decrypts matching ciphers into session cache before form-detection completes.
- Autofill UI rendered as Shadow DOM in the content script (popup is **not** on autofill critical path; TTI < 100 ms target).
- WebAuthn delegation: content-script intercepts `navigator.credentials.{create,get}`, forwards to worker, which calls `hekate-core` and returns a synthesized credential. Falls back to platform authenticator when user prefers.
- All cross-context messages typed via shared TypeScript types generated from Rust via `ts-rs`.

### CLI — `hekate`

- Single Rust binary, `clap` derive.
- `hekate serve` runs a localhost REST shim on a random port + ephemeral token (replaces `bw serve` for scripts).
- Daemon mode caches unlocked keys for a configurable TTL (default 5 min) so subsequent commands respond <50 ms.

### On-device storage (all clients)

- SQLite (or sqlite-wasm in browser) with the same schema shape.
- **FTS5** virtual table indexed on decrypted name + URI host + tags.
- Items stored encrypted-at-rest; FTS index lives in an OS-keychain-protected file.
- Lazy decryption: full plaintext only when displayed/autofilled.

---

## 9. Performance Targets

| Operation | Target | Bitwarden today |
|---|---|---|
| Browser-ext autofill TTI (warm) | <50 ms | 200–800 ms |
| Browser-ext autofill TTI (cold worker) | <200 ms | 3–10 s (pain point) |
| Web vault search across 10k items | <100 ms | 20–30 s on slow connections |
| Mobile app cold open → vault visible | <500 ms | 7–50 s (Xamarin era) |
| Cross-device sync after edit (push path) | <2 s p95, <500 ms p50 | <60 s typical, 5–60 min regressions |
| Cross-device sync (push failed, polling fallback) | <30 s p95 | indeterminate |
| Conflict on concurrent edit | always surfaced, never silent loss | silent last-writer-wins |
| Offline writes queued and replayed on reconnect | yes, durable | partial / silent failures |
| Server idle RAM (100 users) | <100 MB | 1.5 GB |
| Server p99 sync latency | <100 ms | 500 ms+ |
| Self-host install size | <30 MB binary | 4 GB recommended RAM, multi-container |

---

## 10. Enterprise Modules

### Secrets Manager (developer/machine secrets)

Distinct schema, same server, separate URL prefix. Modeled after Bitwarden Secrets Manager but with a Rust SDK from day 1 (Bitwarden's SDK is also Rust — confirms the choice).

- **Projects** — top-level grouping, ACL via group/role.
- **Secrets** — `(project_id, key, EncString value)`. Versioned; full history retained.
- **Service Accounts** — non-human identities with their own X25519 keypair.
- **Access Tokens** — `<sa_id>.<random_64>` format, hashed at rest, scoped to a project + permission set.
- **SDKs** — Rust core (`hekate-secrets`), with Python/Node/Go/Ruby/PHP/.NET bindings via `uniffi-rs`.
- **CLI** — `pms` (machine-oriented; `hekate` is human-oriented).
- **Integrations** — GitHub Actions, Kubernetes operator (CRD `Secret`), Terraform provider, Ansible vault plugin, Vault-style env injection (`pms run -- env`).

### Provider Portal (MSP)

- `provider_id` foreign key on `organizations`.
- Provider admins can list, create, suspend, and bill their managed orgs without joining them.
- Cross-org event log roll-up. Self-host supported (Bitwarden's is cloud-only).

### Policies (org)

Stored as JSONB so new policies don't need migrations. Initial set:
- `master_password_complexity` — min length, require classes, min strength score (zxcvbn).
- `two_factor_required`
- `single_org` — user can't be a member of any other Hekate org.
- `personal_vault_disable` — user's personal vault becomes read-only.
- `vault_timeout` — max client-side timeout.
- `password_generator` — required length / classes for generated passwords.
- `restrict_send` — disable Send entirely or restrict file Send.
- `restrict_provider_admin` — block external provider access to specific orgs.

### Event log

Append-only `events` partition. ~80 event types (login, login_failed, cipher_created, cipher_updated, cipher_deleted, collection_assigned, member_invited, policy_changed, etc.). Retention policy per-org. Export to S3/SIEM via webhook or scheduled job.

### Vault health reports

Run client-side over decrypted vault (privacy-preserving):
- Reused passwords (hash compare in-memory)
- Weak passwords (zxcvbn)
- HIBP exposed (k-anonymity range query)
- Unsecured websites (HTTP URIs)
- Inactive 2FA (cross-reference with HIBP-2FA list)
- Data breach (HIBP per-account email)

Org admin reports run on the server only over plaintext metadata they can already see (counts, ratios) — never on cipher contents.

---

## 11. Threat Model & Security

- **In scope:** Server compromise (cipher contents, KDF parameters), network adversary (TLS-stripped or MITM), malicious org admin (cross-collection access), client-side malware (autofill scraping), phishing-resistant 2FA.
- **Out of scope (documented):** Compromised endpoint with unlocked vault; quantum adversary (post-quantum migration tracked separately for v2).

**Known gaps:** see [`threat-model-gaps.md`](threat-model-gaps.md) for
the live punch-list of mitigations that aren't yet implemented and the
features that require each one before shipping. Notably: vault-level
integrity (signed manifest) is needed before audit-log workflows;
authenticated public keys + signcryption are gating requirements for
**any** sharing, account-recovery, or trusted-device-encryption work
in M4/M5.

Specific defenses:
- **Server compromise:** All cipher contents EncStringed with keys never seen server-side. Master password stored as Argon2id-of-Argon2id; one-password DB dump still requires per-account memory-hard cracking.
- **AAD binding:** every EncString includes `(scope, item_id, field_name)` AAD — server can't swap fields between items.
- **Constant-time MAC verify** on every decryption.
- **CSP, COOP, COEP, CORP** headers everywhere. No third-party scripts in web vault.
- **No telemetry** by default. Optional anonymized counters opt-in.
- **No external icon fetches** by default — favicon proxy is opt-in (Bitwarden's icons service leaks browsing patterns).
- **Reproducible builds** (Cargo + `cargo-vet` + SLSA L3 provenance via GitHub Actions).
- **Audit cadence:** target one independent crypto audit before v1.0, one full code audit before v1.0, annually thereafter. Bug bounty via HackerOne or self-managed.

---

## 12. Operations

### Deployment shapes

1. **Single-host self-host** — one Docker container or one binary + SQLite + local FS attachments. Resource floor: 100 MB RAM, 200 MB disk (excl. attachments). Fits on a Raspberry Pi.
2. **Small-team self-host** — single binary + Postgres + S3-compatible attachment store (MinIO). 256 MB RAM.
3. **Multi-replica self-host** — N binaries behind a load balancer + Postgres + Redis + object store. ~512 MB RAM per replica, scales linearly with sessions.
4. **SaaS** — Same as (3) plus per-tenant org isolation and managed billing. Out of v1 scope.

### Observability

- `tracing` spans on every request, OTLP export.
- Prometheus metrics: `hekate_http_requests_total`, `hekate_sync_latency_seconds`, `hekate_active_sessions`, `hekate_cipher_count{tenant}`, `hekate_kdf_iterations_p50`.
- Structured JSON logs at `info`+, redacted of any encrypted field.

### Backup / DR

- Postgres: WAL-G to S3.
- SQLite: VACUUM INTO + nightly snapshot to attachment object store.
- Encrypted client-side export (single `.hekate` file) on a schedule, optionally pushed to user-controlled storage.
- Documented RTO/RPO.

### License

- Server: **AGPL-3.0**. (Forces SaaS forks to upstream changes.)
- Clients (desktop, web, mobile, extension): **GPLv3**.
- SDKs (Secrets Manager, integrations): **Apache-2.0** so they can be vendored into proprietary apps.
- CLA: **DCO sign-off** (no Contributor License Agreement). Avoids the licensing-shift risk that has hurt other open-source projects.

---

## 13. Roadmap (suggested milestones)

| Phase | Deliverable | Approx scope |
|---|---|---|
| **M0 — Foundation** | `hekate-core` crate (KDF, EncString, sync state machine), schema, axum skeleton, sqlx migrations. | 4–6 weeks |
| **M1 — Personal vault MVP** | Single-user register/login, ciphers (login type only), folders, delta sync, SSE push, CLI client. | 6–8 weeks |
| **M2 — Full personal** | All cipher types, attachments, Send, password generator, TOTP, vault export, browser ext (Chrome). | 8–10 weeks |
| **M3 — Multi-platform clients** | Tauri desktop, native iOS, native Android, Firefox/Safari ext, web vault. | 12–16 weeks |
| **M4 — Organizations** | Orgs, collections, groups, basic roles, public API, event log. | 8 weeks |
| **M5 — Trust UX redesign** | Owner-set-rooted trust (replaces per-pair TOFU pinning), per-owner Ed25519 keys, 1-of-N / 2-of-N quorum, fingerprint-bound rosters, strong-mode toggle. FROST-Ed25519 threshold recovery is M5.x (direction locked, implementation deferred). See `m5-trust-ux.md`. | 8–12 weeks |
| **M6 — Secrets Manager** | Projects, secrets, service accounts, Rust SDK + 5 language bindings, GH Actions integration, K8s operator. | 8 weeks |
| **M7 — Hardening** | External crypto audit, external code audit, bug bounty, reproducible builds, SBOM, SLSA L3. | 6 weeks (calendar; less engineering time) |
| **v1.0** | All of the above; AGPL-3.0 server, GPLv3 clients shipped to stores. | — |

Total: ~14–18 months for a small (3–5 person) team to v1.

---

## 14. Open Design Questions

1. **Post-quantum readiness** — track ML-KEM-768 (X-Wing hybrid) and ML-DSA-65 for v2; design EncString format already supports algorithm migration via `alg_id`.
2. **Group end-to-end encryption (MLS)** — large-org key distribution today uses N RSA wraps per cipher; an MLS-style group key would scale better at >1k member orgs. Defer to v2 unless specifically requested.
3. **Federated multi-server sync** — out of scope for v1, but design IDs (UUIDv7) and tombstones to be globally unique, leaving the door open.
4. **Hosted SaaS** — defer until self-host is rock-solid; SaaS economics differ enough that it should be a separate product decision.
5. **Anti-abuse for free SaaS tier (when offered)** — proof-of-work, captcha, rate limiting; design now to avoid retrofitting.

---

## 15. Critical Files (when implementation starts)

This is a green-field design doc, so there are no files to modify. When implementation begins, the workspace should look approximately:

```
hekate/
├─ Cargo.toml                  # workspace
├─ crates/
│  ├─ hekate-core/             # shared: KDF, EncString, sync FSM
│  ├─ hekate-server/           # axum binary
│  ├─ hekate-cli/              # human CLI
│  └─ hekate-secrets/          # Secrets Manager core (M6, re-exported from hekate-core)
├─ clients/
│  ├─ desktop/                 # Tauri 2 (planned)
│  ├─ web/                     # SolidJS
│  ├─ extension/               # MV3
│  ├─ ios/                     # Swift Package + XCFramework consumer (planned)
│  └─ android/                 # Gradle module + .aar consumer (planned)
├─ migrations/                 # sqlx migrations (Postgres + SQLite via Any)
├─ docs/
└─ ops/
   ├─ docker/
   ├─ k8s/
   └─ terraform/
```

---

## 16. Verification Plan

How we'll know the design works once implementation begins:

1. **Crypto correctness** — vector tests against published Argon2id, XChaCha20-Poly1305, X25519, Ed25519, HKDF test vectors. Differential fuzz of EncString round-trip. Rejection tests for malformed/truncated/MAC-flipped inputs.
2. **Protocol compliance** — automated golden-test corpus for every API endpoint (recorded request/response pairs). Cross-implementation conformance suite for the wire protocol.
3. **Performance** — `criterion` benchmarks for KDF, EncString, sync delta computation. Load test (`oha`/`drill`) hitting targets in §9. Continuous benchmark CI; PR fails on >5% regression.
4. **Sync correctness** — Jepsen-style linearizability tests for concurrent edits across clients. Property-based tests on the sync state machine (`proptest`).
5. **Security review** — internal threat-model review at every milestone; external crypto audit before M7; external code audit before v1.0.
6. **End-to-end** — Playwright tests for web vault and extension; XCUITest for iOS; Espresso for Android; `cargo-tarpaulin` for coverage on `hekate-core` (target ≥85%).
7. **Migration validation** — implement importers for Bitwarden encrypted JSON, 1Password .1pux, KeePass KDBX4, LastPass CSV; round-trip tests verify no data loss.
8. **Self-host smoke test** — `docker run synapticcybersecurity/hekate` on a fresh box → register user → CLI sync → completes in <30 s and uses <100 MB RAM.

---

## Summary of recommended stack

- **Server:** Rust + axum + sqlx + tokio; SQLite default, Postgres for SaaS/enterprise.
- **Crypto:** Argon2id (m=128 MiB), XChaCha20-Poly1305, X25519, Ed25519. Per-cipher keys, EncString v3 with AAD binding.
- **Sync (design pillar #1):** Cursor-based delta sync, multi-transport push with automatic failover (SSE + WebSocket + APNs + FCM + Web Push, polling as floor), durable client outbox for offline writes, explicit conflict surfacing — no silent data loss. Direct mobile push (no third-party relay).
- **APIs (design pillar #2):** One unified `/api/v1` covering every action in every client; CLI is a thin wrapper enforced by CI; PATs and service-account tokens as first-class auth; signed outbound webhooks; auto-generated OpenAPI 3.1 spec and SDKs in 8 languages.
- **Clients:** Tauri desktop, native Swift iOS, native Kotlin Android, SolidJS web, MV3 browser ext, Rust CLI. All share `hekate-core` via WASM/FFI.
- **OSS scope:** policies, event log, Trust UX redesign (M5), Secrets Manager with Rust SDK (M6).
- **Deferred to a future managed-service offering:** SAML+OIDC SSO, Trusted Device Encryption, SCIM, Directory Connector, Provider Portal, emergency access.
- **License:** AGPL-3.0 server, GPLv3 clients, Apache-2.0 SDKs. DCO sign-off, no CLA.
- **Targets:** <100 MB server idle, <200 ms autofill TTI, <2 s cross-device sync p95, single static binary self-host.
