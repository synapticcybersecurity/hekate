# Hekate — Secure Coding Standards

Hekate is a password manager built on custom cryptography — the
highest-stakes software category. These are the **project-specific**
secure-coding rules that sit on top of the general Rust hygiene in the
shared standards (`sdlc_template/global-claude.md` §5). Where the global
file says "compare secrets in constant time" or "zero sensitive memory,"
this document says *which* secrets, *where*, and *with what invariants*
for Hekate specifically.

**Legend:** ✅ established pattern in the codebase · ⬜ to adopt / verify
in the security-analysis pass.

> **Publish gate.** No public binary (Apple notarized `.app`, any app
> store, signed release) ships until these standards are met *and* a
> comprehensive security analysis is complete. This is a hard gate, not
> advisory — see [`followups.md`](followups.md) and `status.md` M7. An
> internal review gets us audit-ready; it does **not** substitute for an
> independent external crypto/code audit.

---

## 1. Key material & memory hygiene

- ✅ Wrap all secret material — master-password-derived keys, `account_key`,
  per-cipher keys (PCKs), Send keys, X25519/Ed25519 private keys, org sym
  keys — in `zeroize` / `ZeroizeOnDrop`. Already used across
  `hekate-cli` and `hekate-core`.
- ⬜ Audit for plaintext-secret copies left behind by `String`/`Vec`
  growth or `.clone()`. Prefer fixed-size buffers (`[u8; N]`) for keys;
  zeroize intermediate derivations, not just the final key.
- Never serialize a plaintext secret into a log line, error, `Debug`
  impl, or panic message. Derive `Debug` manually for secret-bearing
  structs (redact the secret fields).

## 2. Constant-time comparison

- ✅ Compare tokens, auth tags, MACs, and password-hash outputs with
  `subtle` (`ConstantTimeEq`) — never `==`. Established in
  `auth/pat.rs`, `auth/sat.rs`, `auth/refresh.rs`, `routes/identity.rs`,
  `core/kdf.rs` (KDF-params MAC).
- Any new secret-equality check (recovery codes, download tokens, Send
  password gate, webhook HMAC verify) MUST use the constant-time path.
  Adding a `==` on a secret is a review-blocking finding.

## 3. EncString / AEAD discipline

- ✅ Every EncString binds context with **AAD** (the `b"pmgr-…"` domain
  strings). Encryption and decryption MUST pass the same AAD; a decrypt
  that ignores AAD is a vulnerability, not a convenience.
- **Nonce uniqueness is non-negotiable.** XChaCha20-Poly1305 nonces come
  from the CSPRNG per message; never derive a nonce deterministically
  from reused inputs, never reuse a `(key, nonce)` pair.
- ✅ Protocol-frozen identifiers (`b"pmgr-…"` AAD, `pmgr_sat_*` /
  `pmgr_pat_*` token prefixes, `PMGRA1` magic, KDF/DST strings) are
  **frozen** — they're baked into shipped ciphertexts. Do not "rename to
  hekate"; changing them silently breaks decryption of existing data.
- New wrapped fields must be threaded through *every* rewrap site
  (`account rotate-keys`, member-removal rotation) — a field that isn't
  rewrapped becomes undecryptable after rotation. See the
  rotate-keys rewrap invariant.

## 4. KDF & password handling

- ✅ Argon2id for master-key derivation; HKDF for auth/wrap subkeys;
  server-side Argon2id-PHC of the master-password hash.
- ✅ User-enumeration resistance on prelogin (uniform responses for
  unknown accounts). Preserve this on any new account-probing endpoint.
- ⬜ Treat Argon2 cost parameters as a tuned security control; document
  them and review before changing. Reject absurdly-low client-supplied
  KDF params (the KDF-params MAC already binds them — keep it).
- The master password and its derived material never leave the client in
  plaintext and never reach the server. The server is zero-knowledge by
  design; any change that weakens that is a material security tradeoff
  requiring explicit sign-off.

## 5. Randomness & identifiers

- Use a CSPRNG (`getrandom` / `OsRng`) for everything security-bearing:
  keys, nonces, salts, tokens, recovery codes, Send IDs used as secrets.
- UUIDv7 is fine for **non-secret** row IDs (it encodes a timestamp and
  is guessable) — never use it where unpredictability is the security
  property. Secret tokens must be full-entropy CSPRNG output.

## 6. No panics on untrusted input

- ⬜ **Audit the ~400 `unwrap()`/`expect()`/`panic!`/`unreachable!`
  sites in non-test code**, prioritizing request-handling paths
  (`hekate-server/src/routes/**`, extractors, deserialization). On any
  attacker-reachable path these must become `Result` + `?`; a panic
  there is a DoS. `expect()` is acceptable only for genuine startup
  invariants with an explanatory message.
- Bare slice indexing (`buf[n]`), `unwrap()` on `from_slice`, and
  array-length assumptions on decoded input are the usual offenders —
  validate length first.

## 7. Input validation & limits (DoS resistance)

- ✅ Per-attachment / per-cipher / per-account size caps; tus upload
  bounds. Keep new endpoints bounded the same way.
- Validate sizes, counts, and lengths at the boundary before allocating
  or decrypting. Bound any loop driven by client-supplied counts.
- ✅ Rate limiting exists (governor) — keep new sensitive endpoints
  behind it; surface logging/alerting alongside (audit posture).

## 8. Client surfaces (WASM / extension / web / desktop)

- The crypto core is the same `hekate-core` everywhere — keep crypto in
  the core, not re-implemented per client.
- ✅ Web/desktop CSP locks scripts/styles to bundled assets; the Tauri
  desktop IPC surface is empty (no custom commands). Adding an IPC
  command or relaxing CSP is a security change requiring review.
- The desktop app trusts the user-configured server URL only as a sync
  target — it must never accept executable content or plaintext-secret
  authority from the server. Decryption stays client-side.
- ⬜ Review what lands in `localStorage` / `chrome.storage` — refresh
  tokens and pins are expected; plaintext vault secrets are not.

## 9. Logging & audit

- Audit + alerting are first-class design concerns, not follow-ups. Any
  feature relying on detection-and-response as a mitigation must answer:
  logged where, visible to whom, alertable, tamper-evident.
- Log security-relevant events (auth, rotation, member changes, token
  issuance/revocation) — never the secrets themselves.

## 10. Supply chain

- ✅ `deny.toml` gates licenses/advisories/sources via `cargo deny`.
- ⬜ Wire `cargo deny check` + `cargo audit` into CI as blocking gates
  (not ad-hoc). Keep crate features minimal; review new dependencies,
  especially anything pulled into the crypto or client crates.

---

## Security-analysis pass (the gate)

Before any public binary, run and remediate:

1. **Tooling sweep** — `/security-review` and `/code-review ultra` over
   the release branch; `cargo deny check`, `cargo audit`, `cargo clippy
   --all-targets -- -D warnings`.
2. **Manual crypto review** — every AEAD call site (AAD + nonce), every
   key-rewrap path, KDF params, constant-time comparisons, randomness
   sources.
3. **Panic/DoS triage** — §6 audit of untrusted-input paths.
4. **Threat-model the surface being shipped** — for desktop: CSP, IPC,
   the server-URL trust boundary, secret-at-rest on the client.
5. **External audit** — independent crypto/code audit (`status.md` M7).
   Internal review does not replace this for a password manager.

Findings get tracked in [`threat-model-gaps.md`](threat-model-gaps.md)
and remediated before sign-off.
