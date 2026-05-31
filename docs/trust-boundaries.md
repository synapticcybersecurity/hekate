# Hekate — Trust Boundaries & Data Flow

> Audit-readiness artifact (see [`audit-package.md`](audit-package.md)).
> Shows the trust boundaries, what crosses each in plaintext vs ciphertext,
> and what the server can and cannot learn. Companion to
> [`key-hierarchy.md`](key-hierarchy.md) (the keys) and [`design.md`](design.md)
> §5 (the constructions). The governing property: **the server is untrusted
> for confidentiality** — all vault plaintext is encrypted client-side under
> keys rooted in the master password before it ever leaves the client.

## Boundary diagram

```
┌──────────────────────────── CLIENT (trusted) ─────────────────────────────┐
│  CLI / web vault (SolidJS+wasm) / browser extension / Tauri desktop        │
│                                                                            │
│  Master Password ─Argon2id─► Master Key ─HKDF─► auth/wrap/sign/bind subkeys│
│  Account Key, Per-Cipher Keys, Send keys, X25519 priv  — all derived/      │
│  unwrapped HERE, held in memory (Zeroizing), NEVER persisted in plaintext. │
│  Encrypt/decrypt + manifest sign/verify happen here (hekate-core).         │
└───────────────┬────────────────────────────────────────────────────────────┘
                │  (B1) HTTPS  —  Bearer JWT/PAT/SAT
                │  crosses: EncString CIPHERTEXTS, signed manifests, PUBLIC keys,
                │           master_password_hash (HKDF output), KDF params+salt+bindMAC,
                │           metadata (revision dates, folder/collection ids, access counts).
                │  NEVER crosses: master password, master key, account key (plaintext),
                │                 PCKs (plaintext), Send key (URL fragment), X25519 priv.
                ▼
┌──────────────────────────── SERVER (untrusted for confidentiality) ───────┐
│  axum: auth, access control, sync, rate-limit (governor), CORS, webhooks.  │
│  Holds its OWN secret: the HS256 JWT signing key (server-only).            │
│  Re-hashes the master_password_hash with Argon2id (defense-in-depth).      │
│  Cannot decrypt any vault item — has no wrap key.                          │
└──────────┬─────────────────────────────────────────┬──────────────────────┘
           │ (B2) sqlx/AnyPool                          │ (B3) BlobStore trait
           ▼                                            ▼
┌──────── DATABASE (SQLite/Postgres) ────────┐  ┌──── BLOB STORE (local FS) ───┐
│ At rest: EncString ciphertexts, signed     │  │ Attachment/Send file bodies: │
│ manifests, public keys, Argon2id-PHC of    │  │ PMGRA1 chunked-AEAD          │
│ master_password_hash + refresh tokens,     │  │ CIPHERTEXT only; BLAKE3      │
│ SHA-256 token hashes, KDF params/salt.     │  │ verified on finalize.        │
│ A full dump yields NO vault plaintext.     │  └──────────────────────────────┘
└────────────────────────────────────────────┘

(B4) Anonymous Send recipient ── HTTPS ──► server gates (exists/enabled/not-expired/
     access-count/optional Argon2id password) then serves CIPHERTEXT. Recipient holds
     the send_key from the URL FRAGMENT (#/id/key) — never sent to the server — and
     derives the content key client-side. Server cannot decrypt the Send.

(B5) Configured-server boundary (desktop / split-host): the client trusts the
     user-configured server URL ONLY as a sync/storage target. Decryption stays
     client-side; the desktop CSP locks scripts/styles to bundled assets so the
     server cannot inject executable content. (clients/desktop CSP; secure-coding §8)
```

## What the server sees vs never sees

| Server **sees** (ciphertext / non-secret / hashed) | Server **never sees** (plaintext secrets) |
|---|---|
| EncString ciphertexts (cipher fields, Account Key wrap, PCK wraps, Send key wrap, X25519 priv wrap) | Master password |
| Signed vault manifests: canonical bytes + Ed25519 signature + **public** key | Master Key, Stretched Master Key, KDF-bind key, signing seed |
| Account / org **public** keys (X25519, Ed25519) | Account Key (plaintext) |
| `master_password_hash` (HKDF output), then stored Argon2id-PHC of it | Per-Cipher Keys / Org Symmetric Key (plaintext) |
| KDF params, salt, `kdf_params_mac` (HMAC) | X25519 private key (plaintext) |
| Refresh tokens (Argon2id-hashed), PAT/SAT (SHA-256-hashed) | Send key (URL fragment) / Send content key / file AEAD key |
| Metadata: revision dates, folder/collection ids, org membership + roles, Send access counts, expiry, attachment sizes | Any decrypted vault item, attachment, or Send payload |

## Boundary-by-boundary

- **B1 — client ↔ server (network).** HTTPS (WebAuthn requires it; `localhost`
  is the documented dev exception). Auth is a bearer token (JWT/PAT/SAT). The
  client sends only ciphertext + the HKDF-derived `master_password_hash` +
  non-secret metadata. The KDF-bind MAC must be verified **before** the hash
  is sent (BW07/LP04 downgrade defense — `kdf.rs`). CORS is an explicit
  per-origin allowlist (`cors.rs`); no wildcards.
- **B2 — server ↔ database.** Everything secret-bearing is already ciphertext
  or a one-way hash before it reaches the DB. The server adds defense-in-depth
  (Argon2id-PHC of the `master_password_hash`, m≈64 MiB per `design.md`), so a
  stolen DB still faces a client-side-strong KDF, not the only barrier.
- **B3 — server ↔ blob store.** Attachment and file-Send bodies are `PMGRA1`
  chunked-AEAD ciphertext; the server stores opaque bytes and verifies a BLAKE3
  hash on finalize. Keys live only on clients.
- **B4 — anonymous Send recipient.** The server enforces, in order, row
  exists → not disabled → not past deletion/expiration → (file) body finalized
  → optional Argon2id password gate (constant-time) → atomic access-count bump,
  then serves ciphertext. It gates and revokes but cannot decrypt; the
  `send_key` lives in the URL fragment and never reaches the server.
- **B5 — configured-server trust (desktop/split-host).** The desktop app
  treats the user-chosen server URL as a sync target only. It must never accept
  executable content or plaintext-secret authority from the server; the CSP
  pins scripts/styles to bundled assets and the IPC surface is empty.

## Notable trust assumptions (for the reviewer)

- The **master password** is the root of trust; its compromise is total
  compromise (out of scope to defend).
- The server is trusted for **availability** and **honest gating** of
  Sends/access — not for confidentiality.
- The **HS256 JWT signing key is server-held** (symmetric); a server compromise
  lets an attacker mint access tokens (but still cannot decrypt vaults). See
  the HS256-vs-Ed25519 note in [`key-hierarchy.md`](key-hierarchy.md) §5.
- Clients must agree byte-for-byte on the `pmgr-…` AADs/DSTs (cross-client
  consistency — [`key-hierarchy.md`](key-hierarchy.md) §7).
