# Internal Security Review — existing crypto/auth code

Expert internal review of the **shipped** code (not M5, which is reviewed
in [`m5-security-review.md`](m5-security-review.md)), conducted 2026-05-30.
Method: read-only fan-out to locate every AEAD call site, secret-handling
path, secret comparison, RNG use, and untrusted-input panic surface, then
manual cryptographic-engineering evaluation of the excerpts, with the
highest-stakes sites read in full.

> **Status & limits.** Internal pass by a single reviewer — catches the
> majority of findable issues and makes a paid audit shorter, but is **not
> a substitute** for an independent external crypto/code audit (see the
> pre-publish gate in [`followups.md`](followups.md), `status.md` M7). This
> pass focused on the crypto core, auth, and wire-format parsers; it
> sampled — did not exhaustively cover — the ~400 panic sites and the
> client (WASM/extension/web/desktop) surfaces.

**Severity:** 🔴 critical · 🟡 medium · 🟢 low/hygiene · 🔵 verify-deeper.
**Headline: the cryptographic foundation is strong. No critical findings.**
The issues below are hardening and consistency items, mostly cheap.

---

## What the code gets right (verified, not assumed)

- **AEAD nonce discipline is correct.** XChaCha20-Poly1305 with fresh
  192-bit `OsRng` nonces per message — the large nonce makes random
  generation safe with no counter state. Attachments use a fresh random
  key **and** random 20-byte nonce prefix **per file** + a u32 chunk
  counter, so cross-file nonce reuse is impossible.
- **AAD binds everything.** Wrapped keys bind `pmgr-cipher-key-v2:<cipher_id>`,
  Sends bind `pmgr-send-data-v1:<send_id>:<type>`, attachment chunks bind
  `attachment_id ‖ chunk_index ‖ final_flag`. The chunked format is
  truncation- and reorder-resistant (tests confirm).
- **Substitution defense works:** decrypting a wrapped key with the
  expected `cipher_id` AAD rejects a server that swaps ciphertext between
  slots.
- **All secret comparisons are constant-time** — `subtle::ct_eq` or
  Argon2's verifier — for PAT/SAT/refresh tokens, KDF-param MAC, TOTP,
  recovery codes, password hashes.
- **Hash-at-rest for bearer secrets:** PAT/SAT/refresh store only a hash;
  presented secrets are hashed then compared constant-time.
- **CSPRNG throughout** (`OsRng`) for keys, nonces, salts, tokens; good
  entropy (256-bit tokens, 160-bit TOTP, 80-bit recovery codes).
- **Signcryption is a sound construction:** ephemeral X25519 +
  `HKDF(salt = epk ‖ recipient_pk)` + encrypt-then-sign over
  `header ‖ nonce ‖ ciphertext`, **signature verified before** AEAD
  decrypt, with a domain-separation tag and sender/recipient identity
  bound into the signed header.
- **Login enumeration is defended:** uniform prelogin + a **dummy Argon2
  verify** for nonexistent users equalizes timing.
- **JWT is configured safely:** HS256 with `Validation::new(HS256)` (no
  `alg=none`/confusion), required claims enforced, `security_stamp`
  revocation, `kid` rotation, and a manual `Debug` on `Signer` that never
  prints the key.
- **Key material is almost universally `Zeroizing`** (master key,
  account_key, PCKs, Send keys, signing seeds, X25519 private keys, org
  sym keys).

That's a genuinely solid base. Findings:

---

## 🟡 Medium

### E1. `attachment::ciphertext_size_for(size_pt)` integer overflow on untrusted size
`routes/attachments.rs` caps `upload_length ≤ max_attachment_bytes` and rejects `size_pt < 0`, but **does not upper-bound `size_pt`** before calling `ciphertext_size_for(size_pt)`, which computes `n_chunks * TAG_LEN + size_pt` with **unchecked** arithmetic (`crates/hekate-core/src/attachment.rs:172-173`). A `size_pt` near `i64::MAX` overflows: **panic in debug (DoS), wrap in release** → `expected_ct` could wrap to a value matching the (capped) `upload_length` and **bypass the size/quota validation**.

**Fix:**
```rust
// attachment.rs
pub fn ciphertext_size_for(pt_size: u64) -> Option<u64> {
    if pt_size == 0 { return Some(HEADER_LEN as u64); }
    let n_chunks = pt_size.div_ceil(CHUNK_SIZE as u64);
    n_chunks.checked_mul(TAG_LEN as u64)
        .and_then(|t| t.checked_add(HEADER_LEN as u64))
        .and_then(|t| t.checked_add(pt_size))
}
```
…and in the handler, reject `size_pt > max_attachment_bytes` **before** the call. Add a test with `size_pt = u64::MAX`.

### E2. Send download tokens stored in plaintext + matched with SQL `=`
`send_download_tokens.token` is stored and looked up in **plaintext** (`WHERE t.token = $1`), unlike PAT/SAT/refresh which store a hash and compare constant-time. Two deviations: (a) a DB read (backup, malicious DBA, SQLi elsewhere) exposes **live** download tokens; (b) the SQL `=` is variable-time. Mitigated by 256-bit entropy + 5-minute TTL, which makes the timing oracle impractical and limits exposure — but it breaks the otherwise-uniform hash-at-rest invariant.

**Fix:** store `BLAKE3(token)` (or SHA-256), look up by hash, constant-time compare — same pattern as the other token types. Also **verify the tus attachment upload token** (`routes/attachments.rs:348`) isn't stored/compared the same plaintext way.

### E3. Master password held in a plaintext `String`, never zeroized (CLI)
`hekate-cli/src/prompt.rs::password()` returns the master password as a `String`. It's the crown-jewel secret, yet it lingers un-wiped in memory after the master key is derived (and `String`'s drop doesn't zero). Everything *downstream* (master key, account_key, …) is correctly `Zeroizing`; the raw password is the gap.

**Fix:** return `Zeroizing<String>` (or `secrecy::SecretString`); ensure it's consumed by the KDF and dropped promptly, not cloned into other `String`s.

---

## 🟢 Low / hygiene

### E4. `IssuedSat` / `CreateTokenResponse` derive `Debug` over a plaintext token
Token wire values live in structs that `#[derive(Debug)]`; a stray `{:?}`/`tracing` of one leaks a live credential. **Fix:** manual redacting `Debug` (print the id, redact the secret) or drop `Debug`.

### E5. `MasterPasswordHash`/server `master_password_hash` not zeroized
`kdf.rs: pub type MasterPasswordHash = [u8; 32]` and `auth/password.rs::{hash,verify}(&[u8])` handle the password-equivalent without `Zeroizing`. Transient, but cheap to wrap. **Fix:** `Zeroizing<[u8;32]>` for the type; accept `&[u8]` but avoid retaining copies.

### E6. `decrypt_xc20p(None)` allows skipping AAD binding (latent footgun)
The API permits `expected_aad = None`, which accepts whatever AAD is embedded in the envelope. Every *security-bearing* caller currently passes `Some(...)` (verified across the call-site sweep), so this is latent, not live. **Fix:** make AAD mandatory for wrapped-key/secret decrypts (a distinct method or a newtype), reserve `None` for genuinely non-security AAD, and add a regression test that a substituted-AAD wrapped key fails closed.

### E7. `try_into().unwrap()` in signed-wire parsers
`manifest.rs`, `org_cipher_manifest.rs`, `org_roster.rs` read `u32/u64` LE via `p[..N].try_into().unwrap()` on server-received signed bytes. A preceding length check guards each today, so it's **not a live panic** — but it's refactor-fragile on an untrusted-input path. **Fix:** `p[..N].try_into().map_err(|_| Error::InvalidEncoding(...))?`.

### E8. `thread_rng()` for temp-dir suffixes
`blob.rs` and `attachments_gc.rs` name temp dirs with `rand::thread_rng()` (not a CSPRNG). Predictable temp names can enable TOCTOU/symlink mischief if the parent dir is shared. **Fix:** `OsRng` + atomic creation (`create_new` / `O_EXCL`).

---

## 🔵 Verify in a deeper pass

- **KDF parameter floor.** Confirm the client/server reject implausibly weak Argon2 params (low `m`/`t`) even with a valid KDF-params MAC, so a coerced-downgrade can't cheapen the master-key derivation.
- **Signcryption envelope-level replay.** The construction has no internal anti-replay (no timestamp/nonce-ledger); the application layer must guarantee idempotency/version-monotonicity for invites and rotations. This is exactly M5 finding **F6** (version high-water-mark) — track them together.
- **`x25519_pk` provenance** in org sym-key wrapping / signcryption — must be the fingerprint-bound key, not a server-supplied one (M5 finding **F9**).
- **JWT signing-key storage/rotation** in `signing_keys` (at rest protection, rotation cadence).
- **Panic-site sweep is incomplete.** This pass sampled parser hot-paths; the full ~400 `unwrap`/`expect`/`panic` triage on request paths remains (per `secure-coding.md`).
- **Client surfaces** (WASM/extension/web/desktop): CSP, storage of refresh tokens/pins, the desktop server-URL trust boundary — not covered here.

---

## Bottom line

The cryptographic core is **well-built** — correct AEAD/nonce/AAD
discipline, constant-time secret handling, sound signcryption, good
enumeration and JWT hygiene. There are **no critical findings**. The work
is: fix E1–E3 (medium, cheap), clean up E4–E8 (low), and run the deeper
🔵 items. This materially de-risks — and shortens — an eventual external
audit, but does not replace it.
