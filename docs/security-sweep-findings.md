# Security Sweep — Findings (multi-agent, 2026-05-31)

Exhaustive multi-agent security sweep of the Hekate codebase: ~10 parallel
finders across attack dimensions (crypto, secrets, authn, authz, DoS,
injection, wire-format, isolation, clients, config), each candidate
adversarially verified against the real code, then synthesized. Goes
beyond the single-pass review in [`security-review-existing.md`](security-review-existing.md);
findings here are **new** (do not overlap E1–E8 or M5 F1–F4).

> **Status & limits.** Automated multi-agent pass; each finding was
> adversarially re-checked against the code, but this still does **not**
> replace an independent external audit (pre-publish gate, `status.md`
> M7). The `authn` dimension's verification errored on the first run and
> was **re-run** (see "Authn re-run" below) — coverage gap closed.

8 candidates → **5 confirmed** (3 refuted by the adversarial pass). The
authn re-run added **2 more confirmed** (4 candidates → 2).

**Fix status:** H1 + M1–M3 + L1 and **M-A1** are fixed (PRs #23). **M-A2**
is a tracked hardening milestone (see below).

---

## 🔴 HIGH

### H1 — Unauthenticated Send blob download buffers the whole file into RAM (memory-amplification DoS)
**Location:** `crates/hekate-server/src/routes/sends.rs` (`public_blob_download`) → `crates/hekate-server/src/blob.rs` (`read_full`, `vec![0u8; len]`)

The anonymous File-Send download endpoint (`GET /api/v1/public/sends/{id}/blob/{token}`, no `AuthUser`) calls `read_full`, materializing the entire blob (up to `max_attachment_bytes`, default 100 MiB) into one `Vec<u8>` before streaming. The download token is **reusable** within its 5-minute TTL (`public_blob_download` only checks `expires_at`; the `max_access_count` gate lives only in `/access`), and the blob path is **deliberately excluded from the strict auth rate-limiter**, so it rides the lenient general limiter. An attacker mints one token via `/access`, then hammers `/blob`; each in-flight request pins ~100 MB resident → OOM/thrash on a single-host self-host instance. No credential needed if a password-less File Send exists (the password gate is on `/access`, not `/blob`).

**Fix:** stream the blob (e.g. `tokio_util::io::ReaderStream` over the file) so per-request memory is a small chunk; add a global concurrency bound on the blob path; consider making the download token single-use (decrement `max_access_count` on the blob GET, not only at `/access`).

---

## 🟡 MEDIUM

### M2 — Web vault SPA served with no CSP / anti-framing / MIME headers
**Location:** `crates/hekate-server/src/routes/web_app.rs` (`spa_router`); no header middleware in `lib.rs` `build_router`; no CSP `<meta>` in `clients/web/index.html`

The zero-knowledge web vault (`/web/*`, `/send/*`) is served via `ServeDir`/`ServeFile` with **no** `Content-Security-Policy`, `frame-ancestors`/`X-Frame-Options`, or `X-Content-Type-Options`. On the surface that holds the in-memory `accountKey`/`signingSeed` + refresh token, any future script-injection foothold runs with full privilege and can exfiltrate them; the pages can be framed/clickjacked; assets are MIME-sniffable. The browser extension ships a tight CSP and `docs/design.md`/`secure-coding.md` claim CSP "everywhere" — so this is an inconsistency against stated posture. Not directly exploitable without a separate injection/framing vector (none found in-repo), so: missing hardening on the most critical client surface.

**Fix:** response-header middleware on the SPA routes emitting a strict CSP (`default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; object-src 'none'; base-uri 'none'`), `X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`.

### M3 — Default `fake_salt_pepper` regenerates every restart → prelogin existence oracle
**Location:** `crates/hekate-server/src/config.rs` (`default_fake_salt_pepper`); consumed in `crates/hekate-server/src/routes/accounts.rs`

Prelogin returns a deterministic-looking fake KDF salt for unknown emails so an attacker can't distinguish real accounts. The fake salt is `SHA256("…fake-salt-v1" || pepper || email)[..16]`; a real user's salt is stable from the DB. But `default_fake_salt_pepper()` generates a fresh 32-byte `OsRng` value on **every** `Config::load()` and never persists it (the "auto-generated on first run" doc is misleading — nothing writes it back). With no `HEKATE_FAKE_SALT_PEPPER` set (neither compose file sets it; both `restart: unless-stopped`), the fake salt for an email **changes on restart** while a real user's does not → record `kdf_salt`, induce/await a restart, re-query: unchanged ⇒ real account; changed ⇒ nonexistent. Bounded to existence disclosure; dormant on a never-restarted instance.

**Fix:** persist a server-local pepper on first run (write the generated value to the data dir or a DB settings row, reload thereafter), or derive it from an already-persistent server secret. At minimum, log a loud startup warning when an ephemeral pepper is in use.

### M1 — Decrypted SSH private keys held in non-zeroized `String` + raw seed in the ssh-agent
**Location:** `crates/hekate-cli/src/commands/ssh_agent.rs` (`load_ed25519_identities`)

`load_ed25519_identities` decrypts each ssh-key cipher into a plain heap `String` (the OpenSSH-armored private key) and copies the raw Ed25519 seed into a plain `[u8; 32]` — none wrapped in `Zeroizing`. This runs in a long-lived daemon that loads all keys at startup and re-runs on every SSE hot-reload, leaving un-wiped copies (incl. stale ones from prior reloads) in freed heap/stack. Process-memory access (same-uid ptrace, core dump, swap) recovers full SSH keys. Same family as E3/E5; the same file already uses `Zeroizing` elsewhere, so it's an inconsistent omission.

**Fix:** wrap the decrypted `String`(s) in `Zeroizing<String>` and the seed in `Zeroizing<[u8;32]>`.

---

## 🟢 LOW

### L1 — Unlock-daemon socket round-trip leaves un-zeroized key/seed copies
**Location:** `crates/hekate-cli/src/daemon/server.rs`, `crates/hekate-cli/src/daemon/client.rs`

The unlock daemon serializes the account key + signing seed into plain base64 `String`s, JSON-serializes to a plain `Vec<u8>`, and the client decodes into `Vec<u8>` — only the final copied-out `[u8;32]` arrays are `Zeroizing`. The transient base64/JSON/Vec carriers are never wiped, leaving residue on every cached `GetUnlocked` round-trip. Low: the authoritative copies are zeroized, these are transient, and the socket is per-uid `0600` (an attacker who can read this heap is already inside the trust boundary).

**Fix:** wrap the transient carriers in `Zeroizing` end-to-end and zeroize the JSON body buffers.

---

## Authn re-run (2026-05-31)

The `authn` dimension was re-run (3 finders: tokens/session, password/
enumeration, 2FA/recovery; each verdict wrapped so a verifier error can't
drop the dimension). 4 candidates → **2 confirmed**, 0 uncertain.

### M-A1 (MEDIUM) — disabling 2FA didn't revoke refresh tokens — ✅ FIXED (PR #23)
`totp_disable` (`routes/two_factor.rs`) rotated `security_stamp` and its
docstring promised "revoking all other sessions," but — unlike the sibling
stamp-rotating handlers (`totp_confirm`, change-password, rotate-keys) — it
omitted the `UPDATE refresh_tokens SET revoked_at` step. `refresh::rotate`
never checks the stamp, so a **leaked refresh token survived a 2FA-disable**
and could be exchanged for a fresh full-scope JWT for up to the 30-day
refresh TTL — silently breaking the handler's documented session-eviction
contract. (Mitigated: disabling 2FA requires the master password, so this
is a secondary session-eviction gap, not a primary bypass.)
**Fix:** added the refresh-token revocation to the `totp_disable`
transaction; extended `tests/tfa.rs::disable_drops_2fa_and_codes` to assert
a pre-disable refresh token is rejected afterward.

### M-A2 (MEDIUM) — no per-account brute-force lockout / alerting — ⬜ tracked milestone
The only auth throttle is the per-IP governor (`rate_limit.rs`); there is
**no per-`user_id` failed-attempt counter, lockout, backoff, or alerting**
on the password grant or the 2FA/recovery legs. An attacker distributing
source IPs gets N×/min against one account with no account-side resistance
and no notification. Compounded by the TOTP **±1 step window** (3 valid
codes per guess). Severity held at medium: the password leg fights
double-Argon2id (only weak/reused passwords are realistically reachable)
and distributed TOTP brute-force needs large IP diversity against rotating
30s windows — but the total absence of a per-account ceiling **and** any
alerting is a genuine hardening gap.
**Deferred** (own milestone — needs persisted per-account failure state +
lockout/backoff + audit/alerting, per the "logging + alerting alongside
every security design" standard). Also: tighten the TOTP window to ±0 (or
document why ±1), and cap the recovery-code verification loop.

## Bottom line

The core security architecture is sound: the zero-knowledge model holds,
the KDF floor is enforced, secrets are zeroized in most hot paths, and the
most serious previously-found issues are already fixed/tracked (PRs
#20/#21). The residual findings are real but mostly **defense-in-depth
gaps plus one availability bug** — none grants an external attacker the
vault on its own. The pattern worth correcting: controls applied
*inconsistently* (zeroize in some functions but not adjacent ones; CSP on
the extension but not the web vault) and a default config that quietly
weakens an anti-enumeration control. Fix the DoS streaming path first,
then close the consistency gaps.
