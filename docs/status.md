# Hekate — Implementation Status

> Brand: **Hekate**. Code-level identifiers (`hekate-core`, `hekate-server`, `hekate-cli`, the `hekate` binary, `HEKATE_*` env vars) all use `hekate`. Protocol-frozen identifiers (every `b"pmgr-…"` AAD string, `pmgr_sat_*` / `pmgr_pat_*` token prefixes, `PMGRA1` magic) keep the original `pmgr-…` / `pmgr_*` prefix because they're baked into ciphertexts.

Tracks what is shipped vs planned against the milestones in [`design.md`](design.md) §13. Update this with every commit that lands or removes a feature.

**Legend:** ✅ shipped · 🚧 in flight · ⬜ planned · ❌ deliberately out of scope (with reason)

---

## Milestone progress

### M0 — Foundation ✅

- ✅ Rust 2024 cargo workspace (`hekate-core`, `hekate-server`)
- ✅ axum + tokio HTTP server, JSON tracing, figment config
- ✅ sqlx pool — SQLite default, Postgres for multi-tenant
- ✅ Health endpoints (`/health/live`, `/health/ready`)
- ✅ Root index (`/`) + version (`/api/v1/version`)
- ✅ OpenAPI 3.1 stub at `/api/v1/openapi.json` (auto-generation in M2)
- ✅ Multi-stage Dockerfile, distroless/cc runtime, ~42 MB image
- ✅ docker-compose for Postgres and SQLite
- ✅ Traefik labels for `hekate.localhost`
- ✅ Makefile — all dev workflows run inside Docker

### M1 — Personal vault MVP (auth + crypto) ✅

- ✅ Argon2id master-key derivation; HKDF auth/wrap subkeys
- ✅ EncString v3 envelope (XChaCha20-Poly1305 + AAD binding)
- ✅ JWT issuance (HS256, secret in `signing_keys`)
- ✅ Server-side Argon2id-PHC of master password hash
- ✅ Register / prelogin / password-grant token endpoints
- ✅ User-enumeration protection on prelogin

### M1.5 — Ciphers, folders, delta sync ✅

- ✅ Bearer-token extractor (`AuthUser`)
- ✅ Cipher CRUD + soft-delete + restore + permanent (tombstone)
- ✅ Folder CRUD + permanent (tombstone)
- ✅ `If-Match` revision precondition on `PUT`; 409 returns current server cipher (no silent last-writer-wins)
- ✅ `GET /api/v1/sync?since=<rfc3339>` delta endpoint with tombstones

### M1.6 — Refresh tokens + SSE push ✅

- ✅ `grant_type=refresh_token` with single-use rolling rotation
- ✅ Family-revocation on replay (token-replay defense)
- ✅ `GET /push/v1/stream` SSE channel with per-user filter
- ✅ Push events on cipher/folder writes (`cipher.changed`, etc.)

### M2 — Pre-clients + organizations 🚧

In flight / next:

- 🚧 `hekate` CLI (Rust) — first real API client
  - ✅ `register`, `login`, `status`, `logout` (M2.1)
  - ✅ `list`, `show`, `add login`, `sync` (M2.2)
  - ✅ `edit login`, `delete`, `restore`, `purge`, `generate`, auto-refresh on 401 (M2.3)
  - ✅ `add note`, `add card`, `watch` (SSE consumer) (M2.4)
  - ✅ `token create / list / revoke` (PATs) (M2.5)
  - ✅ `webhook create / list / delete` (M2.7)
  - ✅ `unlock` / `lock` daemon mode — 40× faster commands (M2.8)
  - ✅ identity / ssh-key / totp cipher types (M2.9)
  - ✅ `webhook deliveries <id>` (M2.10)
  - ✅ `account change-password / delete / export` (M2.11)
  - ✅ `account 2fa {enable, disable, status, recovery-codes regenerate}` (M2.22)
  - ✅ `account rotate-keys` — rotate the symmetric account_key + all dependent wraps (PCKs, Send keys, org member keys, X25519 private wrap) in one atomic server call. Master password unchanged; manifest + peer pins unaffected (M2.26)
  - ✅ `import bitwarden <file>` — import an unencrypted Bitwarden JSON export. Parser in `hekate-core::import_bitwarden` (pure, no I/O); CLI orchestrates folder-create → cipher-create with the same AAD-bound encryption `hekate add` uses, then re-signs the BW04 manifest. Custom fields are appended to notes; org-owned items + unsupported types are skipped with warnings. `--dry-run` and `--skip-folders` flags. (M2.27)
  - ✅ `import 1password <file.1pux>` — import a 1Password 1PUX (zip) export. Parser in `hekate-core::import_1password`; same CLI orchestration as Bitwarden. Maps Login (001), Card (002), Secure Note (003), Identity (004), Password (005). Vaults become folders; trashed items + unsupported categories (Documents, SSH Key, Software License, etc.) skipped with warnings. (M2.27a)
  - ✅ `import keepass <file.kdbx>` — import a KeePass KDBX 3.1 / 4 database. Prompts for the database master password (separate from Hekate's). Maps every entry to login by default; entries with no UserName/Password/URL/otp + non-empty Notes get the secure_note heuristic. Leaf group name → folder. Custom fields + tags appended to notes. Recycle Bin contents skipped. (M2.27b)
  - ✅ `import lastpass <file.csv>` — import a LastPass CSV export. Standard logins → cipher_type 1 with username/password/uri/totp; sentinel-URL rows (`http://sn`) → secure_note. Leaf segment of `grouping` (slash-separated) → folder. LastPass typed-notes (credit cards / identities encoded with `NoteType:` prefix) skipped with per-row warnings — re-enter manually. (M2.27c)
  - ✅ `attach {upload, download, list, delete}` — chunked-AEAD attachments via tus 1.0, BW04 manifest v3 with `attachments_root` (M2.24)
  - ✅ `send {create-text, create-file, list, delete, disable, enable, open}` — ephemeral encrypted text + file shares with HKDF-derived content key, optional Argon2id-PHC server-gate password, max-access-count + expiration + auto-delete. File Sends use the M2.24 chunked-AEAD format unchanged + tus 1.0 transport + 5-min download tokens for anonymous recipients (M2.25, M2.25a)
  - ✅ `edit` for note / card / identity / ssh-key / totp (M2.13)
  - ✅ Passphrase-mode generator (EFF long wordlist) (M2.16)
  - ✅ Built-in SSH agent socket — Ed25519 (M2.17); RSA/ECDSA tracked
  - ✅ SSH-agent per-use approval via `--approve-cmd` (M2.17a)
- ✅ Personal access tokens (PATs) with scopes (M2.5)
- ✅ Service-account tokens (M2.5) — `pmgr_sat_*` wire format, org-owner-only management, `AuthService` principal extractor, `/api/v1/orgs/{org_id}/service-accounts/...` + `/api/v1/service-accounts/me`. M6 Secrets Manager will add the call sites that gate on the `secrets:*` scopes.
- ✅ TOTP 2FA + recovery codes (M2.22) — `/api/v1/account/2fa/{totp/setup,totp/confirm,totp/disable,recovery-codes/regenerate,status}`
- ✅ WebAuthn / FIDO2 server (M2.23a) — `/api/v1/account/2fa/webauthn/{register/start,register/finish,credentials,credentials/{id}}`. `two_factor_providers` array now includes `"webauthn"`; challenge body carries `webauthn_challenge` (a `RequestChallengeResponse`)
- ✅ Browser-extension WebAuthn UI (M2.23b) — popup `Manage 2FA…` panel for enroll/list/rename/delete, login dance auto-prompts the OS authenticator sheet
- ⬜ CLI WebAuthn (post-M2.23 — needs libfido2 binding)
- ✅ OpenAPI 3.1 spec auto-generated via `utoipa` + Scalar docs UI (M2.6)
- ✅ Outbound webhooks with HMAC signatures + persistent retry queue (M2.7, M2.10)
- ✅ Organizations: members, collections, cipher org-ownership flow — shipped via the M4 track (see below)
- ✅ Org policies (JSONB-stored) — M4.6 server routes + CLI subcommands + popup/web UI
- ⬜ Event log / audit trail
- ⬜ Public role-gated admin endpoints
- ⬜ Groups (sub-org permission bundles) — currently flat: members get role + per-collection permissions directly
- ✅ Resumable attachment uploads (tus 1.0) — M2.24. Server endpoints (`OPTIONS/POST /api/v1/attachments`, `HEAD/PATCH/DELETE /api/v1/tus/{token}`, `GET /api/v1/attachments/{id}[/blob]`), `BlobStore` trait + local-FS impl, chunked-AEAD `PMGRA1` body format, BLAKE3 finalize verify, BW04 manifest v3 with per-cipher `attachments_root`, CLI `hekate attach {upload, download, list, delete}`. Personal ciphers only on the CLI side; org-cipher attachments tracked for M2.24a.
- ✅ Send (text only) — **M2.25**. `hekate-core::send` (HKDF-derived content key with send_id salt, XChaCha20-Poly1305 with text/file-distinguishing AAD, URL-fragment encoder/decoder), authenticated owner CRUD at `/api/v1/sends[/{id}]` plus disable/enable, anonymous public access at `POST /api/v1/public/sends/{id}/access` with optional Argon2id-PHC server gate, atomic access-count enforcement, GC worker prunes past-deletion_date rows.
- ✅ **M2.27c — LastPass CSV import.** `hekate-core::import_lastpass` (pure CSV parser via the `csv` crate); same `ProjectedImport` output as the other formats. Maps standard logins (`url=https://...`) to cipher_type 1 and secure-note rows (`url=http://sn`) to cipher_type 2. LastPass typed notes (credit cards, identities — `extra` field starts with `NoteType:`) skipped with per-row warnings; users re-enter manually. CLI: `hekate import lastpass <file.csv>`. 10 unit tests + 6 fixture-based integration tests.

  **Imports track now feature-complete for the four major formats.** Remaining ⬜ on this track: encrypted Bitwarden exports (PBKDF2/AES); 1PUX attachments via tus; KDBX attachments via tus; LastPass typed-note projection onto hekate's typed cipher shapes (best-effort, lossy).
- ✅ **M2.27b — KeePass KDBX import.** `hekate-core::import_keepass` (uses the `keepass` crate to decrypt + parse KDBX 3.1 / 4); same `ProjectedImport` output as Bitwarden / 1Password so the CLI orchestration is shared. Prompts for the KDBX master password (separate from Hekate's). Heuristic: every entry → login by default; no UserName/Password/URL/otp + non-empty Notes → secure_note. Leaf group name → folder. Custom fields + tags appended to notes. Recycle Bin contents skipped. CLI: `hekate import keepass <file.kdbx>`. 8 in-tree unit tests build a real KDBX from scratch + encrypt + decrypt + project (highest-coverage shape; no separate fixture file since the format is opaque binary).
- ✅ **M2.27a — 1Password 1PUX import.** `hekate-core::import_1password` (pure parser; reads the ZIP's `export.data` JSON and projects accounts → vaults → items onto the same `ProjectedImport` shape Bitwarden uses, so the CLI shares one orchestration). Maps the five common categories (Login / Card / Secure Note / Identity / Password). Vaults become folders; trashed items + unsupported categories (Documents, SSH Key, Software License, Bank Account, etc.) skipped with per-item warnings. CLI: `hekate import 1password <file.1pux>`. 14 parser unit tests + 7 fixture-based integration tests. KeePass (M2.27b) and LastPass (M2.27c) follow.
- ✅ **M2.27 — Bitwarden JSON import.** `hekate-core::import_bitwarden` (pure parser + projection onto Hekate's plaintext cipher model), `hekate import bitwarden <file> [--dry-run] [--skip-folders]` CLI. Maps the four standard Bitwarden item types (login / secure_note / card / identity) onto Hekate's types; folders are materialized first, ciphers thread the new server-side folder ids; custom fields are merged into notes; org-owned items + unsupported types are skipped with per-item warnings; the BW04 manifest is re-signed once at the end. 14 parser unit tests + 6 fixture-based integration tests. 1Password / KeePass / LastPass land as M2.27a/b/c.
- ✅ **M2.26 — `account rotate-keys`.** New endpoint `POST /api/v1/account/rotate-keys` atomically rotates the symmetric `account_key` + re-wraps the X25519 private key + every personal-cipher PCK + every Send `protected_send_key` + every `organization_members.protected_org_key` in one transaction. Master password (and therefore the BW04 manifest signing key) is unchanged. CLI: `hekate account rotate-keys`. 6 integration tests in `tests/rotate_keys.rs`.
- ✅ **M2.25a — File Sends.** Schema columns on `sends` (`storage_key`, `size_ct`, `content_hash_b3`, `body_status`) plus `send_uploads` (tus state) and `send_download_tokens` (5-min anonymous bearers granted by `/access`). Sender authenticated tus at `POST /api/v1/sends/{id}/upload` + `HEAD/PATCH/DELETE /api/v1/tus-send/{token}`, anonymous `GET /api/v1/public/sends/{id}/blob/{token}`. Body uses the M2.24 PMGRA1 chunked-AEAD format unchanged — `file_aead_key` is shipped inside the encrypted metadata payload, `send_key` never leaves the URL fragment. GC drops file-Send blobs alongside row expiry.
- ✅ **M2.24-followup — load-bearing close-out:**
  - ✅ Background GC worker (`crates/hekate-server/src/attachments_gc.rs`) — runs on bootstrap and every 60 s; drains `attachment_blob_tombstones` (delete blob, then row, idempotent on missing blob) and prunes `attachment_uploads` past `expires_at` (delete partial blob, upload row, and `attachments` row in `status=0`). 4 unit tests.
  - ✅ Org-owned cipher attachments in the CLI — `hekate attach upload/download/list` now route through the same org-sym-key unwrap path `hekate show` uses (`unwrap_cipher_key_under(org_sym_key, ...)`). Server already supported org-cipher attachments since M2.24; this closes the CLI parity gap.
- ⬜ **M2.24a — Attachments follow-ups** (deliberately deferred — not load-bearing for current single-host local-FS deployments):
  - ⬜ S3/MinIO/Azure/GCS backend behind the existing `BlobStore` trait, via the `object_store` crate. Switched on by a new `attachments_backend = "fs" | "s3"` config knob.
  - ⬜ Signed-URL downloads for cloud backends — auth check stays on the server, body bytes go straight from S3 to the client. Local-FS keeps proxying through `GET /api/v1/attachments/{id}/blob`.
  - ⬜ Range-request / chunked download (`Range: bytes=...` on `GET /attachments/{id}/blob`) so the client can stream-decrypt huge files without buffering the full ciphertext. The `BlobStore::read_range` API already exists; the route handler buffers via `read_full` for now.
  - ⬜ Browser-extension attachments UI (popup form + WASM-driven encrypt/upload/decrypt path). Tracked under M3 as well — see "Browser extension" below.
  - ⬜ Streaming hash on PATCH so finalize doesn't re-read the whole file from disk to compute BLAKE3. Today: server reads the whole blob back at finalize, which is fine ≤100 MiB but wastes IO on the larger limits we'll allow once cloud backends ship.
  - ⬜ Per-org `attachment_size_limit` policy slot, gated on the M4.6 policies framework.
- ✅ Per-cipher-key client flow exercised end-to-end — every cipher write/read in the CLI, popup, and web vault routes through PCKs (`pmgr-cipher-key-v2:<cipher_id>` AAD); PCKs are re-wrapped under the new `account_key` on `account rotate-keys` and under the new `org_sym_key` on M4.5b member-removal rotation
- ✅ X25519 wrap for org keys — owners' org sym key is wrapped under their `account_key`; receivers get the new sym key via signcryption to their X25519 pubkey on rotation; signcryption envelopes used for invites + key rotations

### M3 — Multi-platform clients 🚧

- ⬜ Tauri desktop (macOS / Windows / Linux)
- ⬜ Native iOS (Swift / SwiftUI)
- ⬜ Native Android (Kotlin / Jetpack Compose)
- 🚧 Manifest V3 browser extension
  - ✅ Popup skeleton: login + vault list + copy password (M3.1)
  - ✅ Autofill: tab-host matching + one-click Fill via `chrome.scripting` (M3.2)
  - ✅ Auto-refresh on 401 + add / edit / soft-delete / restore / purge (M3.3)
  - ✅ Per-cipher-type forms (login / note / card / identity / ssh / totp) + live TOTP codes (M3.4)
  - ✅ Vault-level integrity sign + verify via WASM (M3.5)
  - ✅ Clipboard auto-clear with configurable timer (M3.6)
  - ✅ SSE refresh — popup-only (M3.7)
  - ✅ SSE refresh — service-worker-owned, survives popup close (M3.8)
  - ✅ Clipboard auto-clear — SW + offscreen document, survives popup close (M3.9)
  - ⬜ Inline content-script overlay (M3.10+)
  - ✅ TOTP matches against the active tab via issuer/account heuristic (M3.10)
  - ✅ 2FA UI: TOTP enroll/disable, recovery-codes regenerate, WebAuthn enroll/list/rename/delete, login challenge dispatcher (M2.23b)
  - ⬜ Inline content-script autofill overlay (Shadow DOM)
  - ✅ Sends UI — text (M3.11) + file (M3.13). Top-level "📤 Sends" toolbar button → list + create text/file Send + open shared link. Files use the M2.24 PMGRA1 chunked-AEAD format unchanged + tus single-shot upload + 5-min download tokens for recipients. WASM-driven HKDF + XChaCha20-Poly1305 + URL-fragment encode/decode; the send_key never leaves the client.
  - ✅ Attachments UI (M3.12) — list + upload + download + delete inside the cipher edit view (personal ciphers only, matching the CLI surface). File picker → WASM-encrypt with PMGRA1 chunked-AEAD → tus creation-with-upload (single-shot for popup-bounded sizes; chunked PATCH stays in the CLI for very large files). Auto re-signs the BW04 manifest after writes.
  - ✅ Orgs UI — list + detail (M3.14). Top-level "🏢 Orgs" toolbar button → list orgs the caller belongs to with role + member count + roster version + active policy count.
  - ✅ **M3.14a-d — popup org write ops.** Accept invite (a), create org (b), invite peer + cancel pending invite (c), collection management (d). All four flows wired through the WASM bindings (`signcryptSealEnvelope`, `signcryptOpenEnvelope`, `signPubkeyBundle`, `verifyPubkeyBundle`, `signOrgRoster`, `verifyOrgRoster`, `decodeOrgRosterCanonical`, `sha256` in `hekate-core::wasm`). End-to-end smoke green 2026-05-09 (member removal + receiver-side rotate-confirm in the popup).
  - ✅ `account rotate-keys` (M3.15) — Settings → "Rotate keys…". Re-prompts for master password, /sync's everything, generates new account_key, decrypts every personal-cipher PCK + send key + org-member key under old, re-wraps under new, re-wraps the X25519 private key, POSTs `/api/v1/account/rotate-keys`. Master password unchanged; pinned peers + BW04 manifest unaffected. 2FA-enabled accounts must use the CLI for now (popup's 2FA challenge dispatcher isn't wired into this flow yet).
- ✅ Web vault (SolidJS, Phase C; `clients/web/`) — `make web` builds the SPA into `clients/web/dist`; `hekate-server` mounts it at `/web/*` (owner mode) and `/send/*` (recipient mode for share links). Same `hekate-core` WASM crypto core as the popup + CLI.
  - ✅ C.0 scaffold — Vite + Solid skeleton, multi-stage Dockerfile builds SPA into `/app/web-dist`, `routes::web_app` ServeDir mount, `/web` → `/web/` 308 redirect, favicon
  - ✅ C.1 recipient mode — anonymous Send decryption (text + file + password gate), reads URL fragment, BLAKE3 verify on file body
  - ✅ C.2 login + Resume — Argon2id derivation, BW07/LP04 KDF-bind verify before sending credentials, TOTP / recovery-code 2FA, "Remember me" tier, slim Resume form for per-device unlock
  - ✅ C.3a vault list (read-only) — type-tinted rows, filter chips, search, inline copy actions, live TOTP ticker
  - ✅ C.3b cipher add/edit — type picker (Login/Note/Card/Identity/SSH/TOTP), AAD-bound encryption, password generator, manifest re-sign on every write
  - ✅ C.3c trash + restore + purge
  - ✅ C.4 Sends owner-side — create text/file shares, list, disable/enable, delete; tus single-shot upload for files
  - ✅ C.5 orgs read-only — list orgs, drill into roster + policies + cipher manifest, members rendered with email when known (server-side `OrgView.member_emails` extension, 2026-05-04)
  - ✅ C.6 orgs write ops — create org, invite peer, accept invite, collection CRUD, member removal + rotate-confirm (end-to-end smoke green 2026-05-09)
  - ✅ C.7 settings + lock + rotate-keys + strict-manifest toggle — full `account rotate-keys` flow honoring the rewrap invariant (cipher PCK + send key + send name + X25519 priv + org member keys + manifest re-sign)
  - ✅ C.7d settings extras — change password, 2FA management (TOTP + recovery codes), peer pin list, account export, account delete
  - ✅ C.8 attachments — embedded inside cipher detail; encrypt + tus upload + BLAKE3 verify on download + decrypt
  - ✅ C.2a WebAuthn 2FA in the web vault — `lib/webauthn.ts` + `TwoFactor.tsx` / `TwoFactorSettings.tsx`
- ✅ `hekate-core` WASM bindings (M2.12; FFI for iOS/Android via uniffi tracked separately)

### M4 — Organizations ✅

See [`docs/m4-organizations.md`](m4-organizations.md) for the design.

- ✅ M4.0 schema + create-org + `hekate org {create,list}`
- ✅ M4.1 invite + accept + cancel-invite
- ✅ M4.2 roster verification on `/sync`
- ✅ M4.3 collections + cipher org-ownership
- ✅ M4.4 permissions matrix
- ✅ M4.5 cipher org move + member removal + key rotation
    - ✅ M4.5a cipher org-move
    - ✅ M4.5b member removal + key rotation — owner-side rotation (CLI + popup + web), receiver-side rotate-confirm consume across all three clients, collection-name re-encryption, pre-GH#2 roster-orphan recovery (`prune-roster`), pinning negative paths verified end-to-end
- ✅ M4.6 policies (basic) — server `routes/policies.rs` + per-org JSONB store, CLI `hekate org policy {set, get, list, unset}`, popup + web-vault owner-only Policies toggles. `single_org` enforced server-side (refuses second-org accept when the existing membership has it enabled). Test coverage in `orgs.rs` integration suite.

### M5 — Trust UX redesign ⬜

Replaces "every member TOFU-pins every other member" with "every
member TOFU-pins the org owner-set, and the owner-set endorses
every member's fingerprint in a signed roster" — see
[`docs/m5-trust-ux.md`](m5-trust-ux.md) for the locked design.

- ⬜ Per-owner Ed25519 signing keys; roster signed by any one owner (1-of-N)
- ⬜ 2-of-N quorum for adding/removing owners
- ⬜ Fingerprint-bound roster entries (`signingPubkeyFingerprint`)
- ⬜ Strong-mode toggle (per-org bool, default off)
- ⬜ Logging + alerting on roster / quorum events
- ⬜ Threshold recovery (FROST-Ed25519, M5.x — direction locked, implementation deferred)

### M6 — Secrets Manager ⬜

- ⬜ Projects / secrets / service accounts schema
- ⬜ Rust SDK + 5 language bindings (uniffi-rs)
- ⬜ `pms` CLI
- ⬜ GitHub Actions, Kubernetes operator, Terraform, Ansible integrations

### Deferred to a future managed-service offering

These features are not on the open-source roadmap. They are
positioned for a future managed-service tier on top of the
self-host-first OSS core; nothing in the OSS protocol blocks
them, and self-host operators can build their own equivalents
through the standard org / policy / token primitives.

- ❌ SSO (SAML 2.0, OIDC) with JIT provisioning
- ❌ Trusted Device Encryption (master-password-less SSO)
- ❌ SCIM 2.0 provisioning
- ❌ Directory Connector
- ❌ Custom roles, advanced policies
- ❌ Provider Portal (MSP) cross-org management
- ❌ Emergency access

### M7 — Hardening ⬜

- ⬜ External crypto audit
- ⬜ External code audit
- ⬜ Bug bounty
- ⬜ Reproducible builds + SLSA L3 provenance
- ⬜ SBOM in releases

### Out-of-scope for v1.0 (deliberate) ❌

- ❌ Wire-format compatibility with any existing vendor's API — chose greenfield protocol; trades migration ease for modern crypto + delta sync
- ❌ Hosted SaaS — self-host first
- ❌ Federated multi-server — IDs (UUIDv7) and tombstones reserve the door for v2
- ❌ Post-quantum primitives — EncString `alg_id` field reserves the migration path
- ❌ Ed25519 JWT signing (using HS256 for M1; Ed25519 tracked for v1.0 hardening)

---

## Feature coverage scorecard

Honest snapshot, updated each milestone. Categories cover the
personal-vault → team → enterprise scope Hekate targets at v1.0.

| Category | Now | Notes |
|---|---|---|
| Server protocol (personal vault) | 100% | register/login/refresh/CRUD/sync/conflict/push/PATs/OpenAPI/webhooks/change-password/delete/security_stamp/2FA(TOTP+WebAuthn)/attachments(tus+chunked-AEAD+BW04)/Send(text+file+anonymous-access+password-gate)/account_key rotation done. |
| Crypto primitives | ~98% | KDF + EncString + per-cipher-key schema + signed vault manifest + signcryption envelope (M2.18) + self-signed pubkey bundle (M2.19) + TOFU pinning (M2.20). Per-cipher-key flow exercised end-to-end across CLI/popup/web. Signcryption call sites: org invites + M4.5b key rotations. |
| Auth | ~90% | password + refresh + PATs + TOTP 2FA + recovery codes + WebAuthn + service-account tokens done. SSO / device approval / emergency access are deferred to a future managed-service offering. |
| CLI | ~99% | all 6 cipher types incl. edit, full lifecycle, generate (chars + EFF passphrase), sync, watch (SSE), auto-refresh, daemon mode, live TOTP codes, SSH agent (Ed25519). Missing: RSA/ECDSA in SSH agent + per-use approval prompt |
| Org / sharing | ~40% | M4.0–M4.6 ship: full org lifecycle (create/invite/accept/cancel), roster verification on /sync, collections (CRUD + encrypted names + permissions matrix), org-owned ciphers, cipher move-to-org / move-to-personal with client-side re-key, member removal + key rotation (rotate-confirm verified across CLI/popup/web 2026-05-09), policies (basic). Missing: groups, advanced policies, audit log |
| Trust UX redesign | 0% | M5 |
| Secrets Manager | 0% | M6 |
| SSO / SCIM / advanced policies / MSP | n/a | deferred to a future managed-service offering — not on the OSS roadmap |
| Clients (web, ext, desktop, mobile, CLI) | ~75% | CLI: ~99%. Browser extension (Hekate, Chromium MV3): ~98% — vault, sends, orgs full read+write (incl. M4.5b removal + rotate-confirm), attachments, TOTP, WebAuthn, rotate-keys, passkey provider (smoke green); remaining: inline content-script autofill overlay. Web vault (Hekate, SolidJS, Phase C): ~98% — vault, sends, orgs full read+write, settings (change password, 2FA TOTP+WebAuthn, peer pins, account export, account delete), rotate-keys + strict-manifest, attachments. Desktop / mobile: 0% (Tauri / native still M3 backlog) |
| Imports (1Password / Bitwarden / KeePass / LastPass) | ~90% | Bitwarden JSON (M2.27) + 1Password 1PUX (M2.27a) + KeePass KDBX 3.1/4 (M2.27b) + LastPass CSV (M2.27c) all shipped. Remaining: encrypted-export variants for each format + per-format attachment imports |
| Vault health reports | 0% | M4 |
| **Overall by feature count** | **~6%** | of the full v1.0 scope (personal vault + team sharing + enterprise modules) |

---

## Test coverage snapshot

| Suite | Tests | Status |
|---|---:|---|
| `hekate-core` (KDF, KDF-bind MAC, EncString, keypair, vault manifest, signcrypt + pubkey bundle, org roster, chunked-AEAD attachment + manifest v3 attachments_root, send HKDF/AAD/URL-fragment, Bitwarden + 1Password 1PUX + KeePass KDBX + **LastPass CSV** import parsers + projection) | 139 | ✅ |
| `hekate-core` integration (M2.27 Bitwarden fixture: counts, login round-trip, card field-name mapping, identity drops empty, custom fields, secure note body) | 6 | ✅ |
| `hekate-core` integration (M2.27a 1Password fixture: counts, login round-trip with TOTP, card extraction, identity structured address, password-only category, vault → folder threading, secure note body) | 7 | ✅ |
| `hekate-core` integration (M2.27c LastPass fixture: counts, login round-trip with TOTP, multi-line secure note body, typed-note skip, leaf folder threading, short note body) | 6 | ✅ |
| `hekate-server` unit (auth, jwt, password, refresh, scope, extractor, webhooks signing, kdf-params-mac, perms lattice, 2FA recovery-code generator + alphabet + TOTP secret length, local-FS BlobStore, **attachments GC worker**) | 40 | ✅ |
| `tfa.rs` integration (M2.22: enroll round-trip, recovery single-use, totp replay block, invalid challenge token, disable, regenerate, status, refresh-grant bypass) | 9 | ✅ |
| `webauthn.rs` integration (M2.23a: enroll + login via SoftPasskey, replay rejected, list/delete/rename round-trip, per-user scoping, refresh-grant bypass) | 5 | ✅ |
| `service_accounts.rs` integration (M2.5: owner-only create, non-owner rejected, SAT/JWT cross-principal isolation, revoke, disable cascades to verify, delete cascades to tokens, scope validation, list) | 9 | ✅ |
| `manifest.rs` integration (BW04 signed vault manifest, parent-hash chain) | 9 | ✅ |
| `pubkeys.rs` integration (BW09/LP07/DL02 self-signed pubkey bundle) | 6 | ✅ |
| `orgs.rs` integration (M4.0–M4.6: create-org, invite/accept, sync roster, collection CRUD, org-cipher visibility, permissions grant/revoke/max, cipher move round-trip, member removal + key rotation, policies) | 34 | ✅ |
| `register_login.rs` integration | 9 | ✅ |
| `vault.rs` integration (cipher / folder / sync) | 11 | ✅ |
| `refresh.rs` integration | 4 | ✅ |
| `pats.rs` integration (PAT scope enforcement) | 6 | ✅ |
| `webhooks.rs` integration (signed delivery, filtering) | 3 | ✅ |
| `rotate_keys.rs` integration (M2.26: master-password re-auth, cross-user cipher rejected, non-member org rejected, invalid EncString rejected, refresh tokens revoked, full success path) | 6 | ✅ |
| `attachments.rs` integration (M2.24: tus discover, full upload+download round-trip, HEAD-resume after partial PATCH, wrong-offset rejection, BLAKE3 mismatch rejection, cross-user denial, unowned-cipher rejection, per-file quota, /sync surfaces attachments + tombstones, terminate, metadata view) | 11 | ✅ |
| `sends.rs` integration (M2.25: owner CRUD round-trip, public-access decryption with send_key from URL, password gate accept/reject, max-access-count enforcement, expiration enforcement, disable rejection, /sync delta + tombstone, disable→enable round trip, cross-user owner-endpoint isolation) + (M2.25a: full file-Send tus upload + anonymous /blob round trip, blob endpoint rejects unknown token, finalize hash-mismatch rejection, cross-user upload denial, double-upload rejection, password gate blocks token issuance) | 15 | ✅ |
| `hekate-cli` unit (TTL parser, unlock state-MAC verify, passphrase, ssh-agent, peer TOFU, org bundle canonical, org_sync roster verifier, strict-manifest prefs round-trip + legacy load, send share-URL parser) | 50 | ✅ |
| **Total** | **385** | ✅ all passing |

End-to-end smoke through Docker + Traefik verified each milestone.
