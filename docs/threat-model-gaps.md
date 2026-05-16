# Threat Model — Known Gaps

This document tracks security mitigations that Hekate does **not** yet
implement, scoped against the malicious-server threat model from Scarlata
et al., *"Zero Knowledge (About) Encryption: A Comparative Security
Analysis of Three Cloud-based Password Managers"* (USENIX Security 2026).

> **A note on `pmgr-` literals.** Strings like `pmgr-sign-v1`,
> `pmgr-vault-manifest-v3`, and the `pmgr_sat_` / `pmgr_pat_` token
> prefixes are protocol-frozen byte values baked into ciphertexts,
> AAD, signature DSTs, and stored tokens. They are part of the
> wire format and cannot be renamed without re-encrypting every
> object on disk; they will keep their original spelling
> indefinitely. Everything else in this doc uses **Hekate**.

It is the working list. When a feature lands that *requires* one of these
mitigations to ship safely, the corresponding section here is the gating
checklist — do not merge the feature without satisfying it.

The "shipped" mitigations are documented for context so we don't lose
track of why a given file exists. See [`design.md`](design.md) §5 for the
full crypto architecture.

---

## Already shipped

| Ref | Attack | Mitigation in Hekate | Where |
|---|---|---|---|
| BW07 / LP04 | KDF parameter downgrade | Client-side allowlist (`KdfParams::is_safe`) + HMAC-SHA256 binding of `(params, salt)` to the master key, verified before sending the master_password_hash | `crates/hekate-core/src/kdf.rs` |
| BW04 / LP06 | Unprotected item metadata (esp. `reprompt`) | `reprompt` removed from the wire entirely; will live in the encrypted `data` blob when re-introduced | `crates/hekate-server/src/routes/ciphers.rs` |
| BW04 / vault row swap | Server substitutes one cipher's row for another | Client-generated `id` + AAD binding `(cipher_id, cipher_type)` on every encrypted field, `cipher_id` on the wrap key | `crates/hekate-cli/src/crypto.rs::aad_*`, `clients/extension/popup/popup.js::aad*` |
| BW05 / LP02 | Item field swapping within an item | Distinct AAD per field role (`name` / `notes` / `data`) | same |
| BW10 | Per-item key downgrade | Per-cipher keys are mandatory; the server validator rejects ciphers without `protected_cipher_key` | `crates/hekate-server/src/routes/ciphers.rs::validate_input` |
| BW11 / BW12 / DL03–06 / LP05 | Backwards-compatibility downgrade to AES-CBC, padding-oracle attacks, malleable vault | Greenfield: no AES-CBC code path, no `alg_id` for legacy formats. XChaCha20-Poly1305 only. | `crates/hekate-core/src/encstring.rs` |
| BW06 / LP03 | Icon-URL field decryption oracle | No client-side icon-fetch by URL is implemented; server-side icon proxy is opt-in per design §11 | n/a |
| (defense in depth) | On-disk state-file tampering of `kdf_params` between login and next unlock | `unlock` re-verifies `kdf_params_mac` against the just-derived master key; mismatch errors out before the master_password_hash is ever produced under attacker-chosen params | `crates/hekate-cli/src/crypto.rs::unlock` |
| BW04 (set level) | Server drops / replays / resurrects ciphers without client detection | Per-user signed vault manifest: client uploads `(cipher_id, revision_date, deleted, attachments_root)` for every owned row, signed with Ed25519 derived from the master key (HKDF `pmgr-sign-v1`); server enforces strictly-greater version on upload; CLI verifies signature + cross-checks every `/sync` cipher against the signed manifest, warns on mismatch. **(M2.24)** Each entry now carries a per-cipher `attachments_root` — SHA-256 of the cipher's sorted `(att_id, revision_date, deleted)` tuples — so attachment drops/replays/resurrections are caught by the same chain. Format bumped to v3 (`pmgr-vault-manifest-v3\x00`). | `crates/hekate-core/src/manifest.rs`, `crates/hekate-server/src/routes/vault_manifest.rs`, `crates/hekate-cli/src/manifest.rs` |
| BW09 / LP07 / DL02 (cryptographic primitive) | Server substitutes its own ciphertext for a sender-claimed wrap | Signcryption envelope: X25519 sealed-box ECDH + Ed25519 sender signature, with sender id + recipient id + ephemeral pubkey + recipient pubkey AAD-bound into both the AEAD ciphertext and the signed canonical header. **First call site shipped — M4.1 org invite/accept** wraps the org sym key + signing pubkey + bundle sig + role to the invitee under TOFU-pinned X25519 + sender Ed25519. | `crates/hekate-core/src/signcrypt.rs`, `crates/hekate-cli/src/commands/org.rs` |
| BW08 | Server fabricates organization membership for a user (or hides one) | Per-org signed roster: every membership change re-signs canonical bytes with the org's Ed25519 signing key and chains parent hashes; the server cannot forge a roster entry without the org's signing seed. Invitee verifies at accept time (M4.1) **and on every `/sync`** (M4.2) — checks: pin exists, sig under pinned signing key, monotonic version, parent-hash chains from cached canonical, self ∈ roster at the role the server claims. Pin advance only on full success | `crates/hekate-core/src/org_roster.rs`, `crates/hekate-cli/src/org_sync.rs`, `crates/hekate-server/src/routes/orgs.rs`, `crates/hekate-server/src/routes/sync.rs` |
| BW09 / LP07 / DL02 (self-attestation) | Server fabricates a (user_id, pubkey) pair for a user that didn't actually choose it | Self-signed pubkey bundle: client picks a UUIDv7 client-side at registration, Ed25519-signs canonical `(user_id ∥ signing_pk ∥ x25519_pk)`, server validates the sig before persisting and serves it via `GET /api/v1/users/{id}/pubkeys`. A malicious server still can't fabricate a sig without the user's signing key, so consumers (with the right out-of-band trust path on top — see remaining open) can detect substitution | `crates/hekate-core/src/signcrypt.rs::sign_pubkey_bundle`, `crates/hekate-server/src/routes/pubkeys.rs` |
| BW09 / LP07 / DL02 (TOFU pin) | Server swaps a peer's pubkey bundle between fetches | `hekate peer {fetch,pins,fingerprint,verify,unpin}`: first `fetch` verifies the self-sig and pins `(signing_pk, x25519_pk, fingerprint)` locally; subsequent fetches require byte-identical match; mismatch errors with "server may be attempting substitution". `peer fingerprint` prints the user's own fingerprint for OOB verification with peers. End-to-end smoke verified | `crates/hekate-cli/src/commands/peer.rs`, `crates/hekate-cli/src/state.rs::PeerPin` |
| (auth) | Stolen / cracked master password used to log in remotely | TOTP 2FA + recovery codes. Password-grant on a 2FA-enabled user returns 401 + `two_factor_required` + a 5-min `purpose=tfa` challenge JWT bound to `(user_id, security_stamp)`; second leg re-verifies the password (defense in depth), validates the challenge, then dispatches to TOTP (±1 step skew, replay block via monotonic `last_used_period`) or recovery-code (Argon2id PHC compare, atomic single-use consume). Refresh grants intentionally do not re-prompt — the second factor binds at the password leg only. Recovery codes are authentication-only: they let you finish a login challenge but do NOT decrypt the vault (zero-knowledge invariant: lose the master password and the vault is gone, codes or no codes) | `crates/hekate-server/src/routes/two_factor.rs`, `crates/hekate-server/src/routes/identity.rs`, `crates/hekate-server/src/auth/jwt.rs`, `crates/hekate-cli/src/commands/two_factor.rs` |
| (auth, phishing) | Stolen master password + a phisher who can also relay a TOTP code in real-time | WebAuthn / FIDO2 (server + browser-extension UI). Phishing-resistant by design: the authenticator binds the RP ID + origin into every signed assertion, so a credential created for `hekate.example.com` can't be used at `evil.com`. Slots into the same `two_factor_required` dance — challenge body adds `webauthn_challenge` (a `RequestChallengeResponse`); second leg sends the assertion as `two_factor_value`; server runs `Webauthn::finish_passkey_authentication`, advances sign_counter, refreshes last_used_at. Mid-ceremony state stashed in `two_factor_webauthn_pending` so the server stays stateless across requests. Recovery codes still rescue WebAuthn-only users. Browser-extension popup drives `navigator.credentials.{create,get}` directly (works in MV3 popup contexts as of Chrome 116+) | `crates/hekate-server/src/routes/two_factor_webauthn.rs`, `crates/hekate-server/src/routes/identity.rs`, `clients/extension/popup/popup.js` (`render2faPanel`, `complete2faChallenge`) |

---

## Open: Vault-level integrity (followups)

The CLI now signs and uploads a per-user vault manifest after every
write, and verifies the signature plus cross-checks every cipher
against the signed entries on every full `hekate sync`. Server drops,
server replays of old `revision_date`s, and server resurrections of
soft-deleted rows all surface as `⚠` warnings on `hekate sync`.
End-to-end smoke verified: deleting a cipher row directly from the
database emits the expected warning on the next sync.

What's still open under this banner:

- **(shipped — M2.x)** ~~Treat warnings as errors.~~ Per-user
  opt-in via `hekate config strict-manifest on` (CLI) or the
  "Strict manifest verification (BW04)" checkbox in the popup's
  Settings panel. When on: `hekate sync` exits non-zero on a
  personal-manifest mismatch (after still printing the full
  warning context); the popup replaces the vault view with a
  blocking integrity-failure screen. Default is OFF (warn-mode)
  so an upgrade can never lock a user out of their data —
  recovery scenarios may legitimately produce warnings. Scope is
  intentionally limited to the **personal** manifest; org roster
  + per-org cipher manifest stay non-fatal because M4 v1's
  single-signer model leaves the cipher manifest legitimately
  stale until the owner refreshes. Extending strict mode there
  is gated on M4 v2 multi-admin signing.
- **(shipped — M2.x)** ~~Browser extension verification UI.~~
  Same "Strict manifest" toggle, with `renderStrictManifestBlock()`
  surfacing the failure as a red full-page interstitial on every
  render — the user cannot reach the cipher list while in this
  state. See `clients/extension/popup/popup.js`.
- **(shipped — M2.15c)** ~~Hash chaining for replay defense across
  versions.~~ Each manifest now embeds `parent_canonical_sha256`
  (32 bytes, all zeros for genesis); server enforces uploaded
  parent matches the SHA-256 of the currently-stored canonical
  bytes. Forked or rolled-back chains return 409.
- **Multi-device concurrent edit conflict resolution.** Currently
  last-writer-wins on the manifest row. Two devices that both sign
  forward from the same parent will produce a "split chain" we
  don't yet handle. Same conflict-twin model as cipher conflicts
  applies; design open.
- **(shipped — M2.15c)** ~~change-password updates the server's
  signing pubkey.~~ The CLI now sends `new_account_signing_pubkey`
  on `hekate account change-password`; server rotates the column in
  the same transaction as the account-key re-wrap and wipes the
  user's `vault_manifests` row. Next write uploads a fresh genesis
  under the new key.

---

## Open: Authenticated public keys (gating M4 sharing)

**Threat:** Every public-key wrap in the system today (none exist yet,
because orgs are M4) has the same root failure mode the paper documents
across BW09 / LP07 / DL02: the server hands the sender a public key for
the recipient with no authentication. The sender encrypts the shared
key under that public key, and the (malicious) server walks away with
plaintext.

**Required mitigations before any sharing endpoint is added:**

1. **(shipped — M2.20)** ~~Authenticate recipient public keys via TOFU.~~
   The CLI now ships TOFU pinning: every `hekate peer fetch <user_id>`
   verifies the self-signed bundle from M2.19 and pins the
   `(signing_pk, x25519_pk, fingerprint)` triple in the local state
   file. Subsequent fetches require a byte-identical match; mismatch
   surfaces as a load-bearing error documenting the two possible
   causes (server substitution vs. legit peer rotation). End-to-end
   smoke verified: with bob's stored bundle row server-tampered to
   mallory's pubkeys + sig, alice's `hekate peer fetch <bob_id>`
   refuses with *"bundle signature did not verify … server may be
   attempting substitution"*. Two stronger options remain available
   for environments that need them:
   - **Verified Key Directory** (Auditable Key Directory style — what
     WhatsApp / iMessage are converging on). Long-term answer when
     scale demands it.
   - **Per-organisation CA** (org administrator signs member public
     keys). Suitable for enterprise deployments and complements the SSO
     story already in the design.

2. **(shipped — M2.18 + M4.1 first call site)** ~~Use signcryption, not
   raw public-key encryption.~~ The cryptographic primitive lives in
   `hekate-core::signcrypt`: X25519 sealed-box ECDH + Ed25519 sender
   signature, with a length-prefixed canonical header binding sender
   id, recipient id, ephemeral pubkey, and recipient pubkey into both
   the AEAD AAD and the signed payload. Encrypt-then-sign so a bad
   sig short-circuits before the AEAD even runs. **First call site
   is `hekate org invite` / `accept` (M4.1):** the org-sym-key + signing
   pubkey + bundle sig + role are signcrypted to the invitee's
   M2.20-pinned X25519 pubkey, signed by the owner's account signing
   key. Acceptance refuses unless the inviter's signing pubkey is
   already pinned, the org bundle sig verifies under it, and the
   server's signed roster verifies under the org signing pubkey from
   the envelope.

3. **(shipped — M4.0 + M4.1 + M4.2)** ~~Authenticate org membership
   cryptographically.~~ Every org carries a roster (BW08 mitigation,
   modeled exactly on the M2.15c vault manifest): canonical-bytes
   parent-hash chain plus an Ed25519 signature under the org's own
   signing key. The server cannot forge a roster without the org's
   signing seed. The client verifies at accept (M4.1) **and on every
   `/sync`** (M4.2): pin exists, sig under pinned signing key,
   monotonic version, parent-hash chains from cached canonical, self
   listed at the role the server claims. Replays, hidden removals,
   server-side role substitutions, and unilateral promotion are all
   caught and surfaced as load-bearing warnings.

---

## ~~Open: Org-cipher set-level integrity (M4.5 follow-up)~~ — shipped (M2.21)

**Threat:** The per-user signed vault manifest (M2.15c, BW04) covers
ciphers a user owns. M4.3 introduces org-owned ciphers — `user_id =
NULL, org_id = ?` — which sit in a different ownership scope and so
are deliberately excluded from the per-user manifest cross-check.

**Mitigation (shipped — M2.21):** Per-org signed cipher manifest,
modeled on the M2.15c shape: canonical bytes + parent-hash chain +
Ed25519 sig under the org signing key. Every org-cipher write the
*owner* performs auto-rebuilds the manifest (single-signer model in
M4 v1; non-owner writes leave it stale until the owner runs
`hekate org cipher-manifest refresh`). Members verify on every `/sync`
against their TOFU-pinned org signing pubkey (M4.2 already pins this)
and cross-check every org-owned cipher in `changes.ciphers` against
the manifest entries. Drops, replays of old `revision_date`, and
resurrections of soft-deleted org ciphers all surface as ⚠ warnings
on `hekate sync`.

**Code:**
- `crates/hekate-core/src/org_cipher_manifest.rs`
- `crates/hekate-server/src/routes/org_cipher_manifest.rs`
- `crates/hekate-cli/src/org_cipher_manifest.rs`,
  `crates/hekate-cli/src/commands/{add,edit,delete,restore,purge,move_cipher,org}.rs`

**Known limitation in v1:** Multi-admin signing is M4 v2 work; until
then, non-owner writes to org ciphers leave the manifest stale until
the owner refreshes. Members' /sync surfaces this as ⚠ "cipher
returned by server is NOT in the signed manifest". The owner's next
write (or explicit `cipher-manifest refresh`) catches up.

---

## Open: 1Password-style vault substitution defence

**Threat:** When a vault key (or any other client-self-encrypted secret)
is encrypted to the user's own public key and stored on the server, the
server can substitute its own ciphertext encrypting a server-known key,
and the client cannot tell. The client decrypts to the server's chosen
key and uses it for new ciphers. Paper Appendix D describes this
against 1Password's vault keyset.

**Why Hekate is *not* exposed today:** the account key is wrapped under
the **stretched master key** (symmetric), not under the user's own
public key. The server cannot forge a valid stretched-master-key
ciphertext without the master password.

**Why this becomes a risk later:** As soon as Hekate introduces *any*
public-key self-wrap — likely candidates: account-recovery escrow,
Trusted Device Encryption, shared vault keys — the same flaw applies.

**Required mitigation when those features ship:** Sign the wrap with
the user's Ed25519 signing key before encrypting it with the public
key, and verify the signature on retrieval. (This is the same
"signcryption" requirement as for sharing above.)

---

## Open: Account recovery / Key Connector / TDE (gating M5)

**Threat:** All admin-assisted recovery features (BW01–03, LP01) come
down to the same problem as sharing: the client encrypts its keys to a
public key the server hands it, with no authentication. Same
mitigations apply.

**Specific requirements for M5:**

1. The list of recovery-eligible administrators must be authenticated
   end-to-end — not retrieved unauthenticated from the server like in
   the paper's BW01 / LP01 attacks. Bind to the org's CA signing key
   (see sharing requirement #1) or to a TOFU-pinned admin set.

2. Recovery-enrolment ciphertexts must use signcryption — the user
   signs the key-wrap before encrypting it to the admin, so an admin
   recovering the vault can verify the wrap was actually produced by
   the user (not injected by the server). Same primitive as the sharing
   mitigation; build it once.

3. **No SSO-only flow without HSM-backed escrow.** The Key-Connector-
   style design the paper attacks (BW02 in §6) delegates key storage to
   a self-hosted application that has nothing forcing it to behave
   honestly. If Hekate ships an analogous service, the keys it holds
   must be in an HSM with attested access logs (per the paper's
   "Securing a backdoor" discussion in §6, mirroring the Signal /
   WhatsApp / Apple Advanced Data Protection direction).

4. The "remove master password" UX (paper's BW03) must surface the
   target key-server URL prominently and require an explicit
   confirmation that names the URL — never accept a server-injected
   "organisation name" as the only label.

---

## References

- Scarlata, M., Torrisi, G., Backendal, M., Paterson, K. G. "Zero
  Knowledge (About) Encryption: A Comparative Security Analysis of
  Three Cloud-based Password Managers." USENIX Security 2026.
- Backendal, M., Davis, H., Günther, F., Haller, M., Paterson, K. G.
  "A formal treatment of end-to-end encrypted cloud storage." CRYPTO
  2024 — referenced by §6 of the paper as the right starting point for
  formalising password-manager security.
