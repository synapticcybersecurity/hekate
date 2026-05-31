# Hekate — Cryptographic Primitive & Version Inventory

> Audit-readiness artifact (see [`audit-package.md`](audit-package.md)).
> Exact primitives, crate versions, and parameters, so a reviewer can
> verify the construction choices at a glance. Versions are pinned in
> `Cargo.lock` at the audit commit baseline (see [`audit-scope.md`](audit-scope.md)).
> Constructions and DSTs are detailed in [`key-hierarchy.md`](key-hierarchy.md).

## Toolchain

- Rust **edition 2021**, **rustc 1.89** (workspace `Cargo.toml`).
- `hekate-core` also compiles to **wasm32** for the web vault + extension.
- Supply chain gated by `cargo deny` (`deny.toml`) + `cargo audit`
  (`.cargo/audit.toml`).

## Primitives

| Purpose | Primitive | Crate @ version | Parameters | Source |
|---|---|---|---|---|
| Password KDF | **Argon2id** (v0x13) | `argon2` 0.5.3 | m=128 MiB, t=3, p=4, 32 B out, 16 B random salt. Client safety floor: m∈[64 MiB, 512 MiB], t∈[2, 100], p∈[1, 16] | `kdf.rs:46,71,107` |
| Subkey derivation | **HKDF-SHA-256** (Expand-only) | `hkdf` 0.12.4 + `sha2` 0.10.9 | Master Key is a uniform 32 B PRK → Expand only. Infos: `pmgr-{auth,wrap,kdf-bind,sign}-v1`, `pmgr-send-content-v1` | `kdf.rs:96-98,187`, `manifest.rs:117`, `send.rs:44` |
| Symmetric AEAD | **XChaCha20-Poly1305** | `chacha20poly1305` 0.10.1 | 24 B nonce, **random per encryption** (OsRng), 16 B tag. EncString v3 `xc20p`; AAD binds location | `encstring.rs` |
| File/attachment AEAD | **`PMGRA1` chunked-AEAD** | (XChaCha20-Poly1305 per chunk) + `blake3` 1.8.5 | Per-chunk AEAD with location AAD; BLAKE3 content hash verified on finalize | `attachment.rs` |
| Digital signature | **Ed25519** (`verify_strict`) | `ed25519-dalek` 2.2.0 | Signs vault manifest / org roster / org-cipher manifest / pubkey bundle / signcryption header (DSTs in key-hierarchy §4) | `manifest.rs`, `signcrypt.rs` |
| Key agreement | **X25519** | `x25519-dalek` 2.0.1 (`curve25519-dalek` 4.1.3) | ECDH for signcryption (ephemeral sender key × recipient static key) | `signcrypt.rs` |
| Signcryption (composite) | X25519 ECDH + HKDF-SHA-256 + XChaCha20-Poly1305 + Ed25519 | (above crates) | AEAD-key info `pmgr-signcrypt-aead-key-v1`; sig DST `pmgr-signcrypt-v1\x00` | `signcrypt.rs:77,78` |
| MAC (KDF-param bind) | **HMAC-SHA-256** | `hmac` 0.12.1 + `sha2` 0.10.9 | Over `DST‖alg‖params‖0x00‖salt`; verified before sending the password hash (BW07/LP04 defense) | `kdf.rs:103,163` |
| Token hashing (PAT/SAT) | **SHA-256** | `sha2` 0.10.9 | `SHA-256("pmgr-{pat,sat}-v1"‖secret)` stored; constant-time verify | `server/auth/{pat,sat}.rs` |
| Constant-time comparison | `subtle` 2.6.1 (`ConstantTimeEq`) | — | Token / MAC / auth-tag / password-hash comparisons | `kdf.rs:24,184`, auth modules |
| Memory hygiene | `zeroize` 1.8.2 (`Zeroizing`/`ZeroizeOnDrop`) | — | Master Key, subkeys, account key, PCKs, send keys, X25519 priv | `kdf.rs:83-90`, `keypair.rs`, `send.rs` |
| CSPRNG | **OsRng** | `getrandom` 0.2.17 / `rand_core` 0.6.4 | Account key, PCKs, send keys, X25519/Ed25519 keys, AEAD nonces, salts, server token secrets | `keypair.rs:9`, `encstring.rs`, `send.rs:56` |
| Server access-token signing | **JWT HS256** (HMAC-SHA-256) | `jsonwebtoken` 9.3.1 | 32 B random secret in `signing_keys` table (`kid` rotates); 1 h TTL; `stamp` claim checked per request | `server/auth/jwt.rs:11,17,100` |

## Server-side hardening (confirm against server source during review)

The following are documented in [`design.md`](design.md) and should be
verified line-by-line by the reviewer:

- **`master_password_hash` storage:** server re-hashes the client-sent hash
  with **Argon2id** (m≈64 MiB per `design.md:252`) as defense-in-depth — not
  the only barrier.
- **Refresh tokens:** opaque 256-bit random, stored **Argon2id**-hashed
  (m≈8 MiB per `design.md:303`), single-use rolling rotation with
  family-revocation on replay.
- **TOTP 2FA:** RFC 6238, **SHA-1**, 30 s step (`design.md:309`) — SHA-1 here
  is per the TOTP standard (HMAC-SHA-1), not a general hash choice.

## Reviewer notes

- No hand-rolled primitives — all from the RustCrypto / dalek ecosystems.
- XChaCha20-Poly1305's 24 B nonce makes **random** nonces safe (no
  per-(key,nonce) coordination across clients) — verify nonces are always
  freshly random and never reused with a key.
- `agcms` (AES-GCM-SIV), `x25519`, `ed25519` alg ids are **reserved** in the
  EncString format; confirm only `xc20p` is emitted in the shipped code.
- The access-token MAC key (HS256) is **server-held symmetric** — see the
  HS256-vs-Ed25519 note in [`key-hierarchy.md`](key-hierarchy.md) §5.
