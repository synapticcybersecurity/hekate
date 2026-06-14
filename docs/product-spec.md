# Hekate — Product & Feature Specification

> **What this doc is.** A single end-to-end description of *what Hekate is
> and does*, written from the product/functionality angle (not the
> architecture angle — that's [`design.md`](design.md)). It covers every
> capability area, what's shipped today, and what's still planned, so a
> reader can see the whole product in one place.
>
> **Companion docs.** [`design.md`](design.md) = architecture & crypto
> spec · [`status.md`](status.md) = milestone scorecard · [`features.md`](features.md)
> = shipped inventory · [`build-plan.md`](build-plan.md) = sequenced,
> story-level plan for the remaining work · [`followups.md`](followups.md)
> = durable TODO queue.
>
> **Status legend:** ✅ shipped · 🚧 in flight · ⬜ planned · ❌ deliberately
> out of scope · 🏢 deferred to a future managed-service tier.
>
> Snapshot date: **2026-06-13**. Update when a capability lands or its
> scope changes.

---

## 1. Product Vision

Hekate is a **self-hosted, end-to-end-encrypted password and secrets
manager**. The server is treated as untrusted: it stores only encrypted
envelopes and verifies nothing it could forge. Every secret is encrypted
and signed client-side under keys derived from a master password that
never leaves the device.

**Who it's for:**
- **Individuals** who want a private, self-hostable vault with first-class
  CLI, browser, web, and (soon) desktop/mobile clients.
- **Teams** who need to share secrets with cryptographic, server-can't-cheat
  trust (signed rosters, per-org keys, member-removal-with-rotation).
- **Developers / machines** (M6) who need a secrets manager with SDKs and
  CI/CD/infra integrations.

**Product pillars (non-negotiable):**
1. **Zero-knowledge server** — the server never sees plaintext, master
   passwords, or unwrapped keys.
2. **Client-verified trust** — every signed artifact (vault manifest, org
   roster, peer/org bundle, Send envelope) is verified client-side against
   a TOFU-pinned key; the server cannot substitute keys or contents.
3. **Modern greenfield crypto** — XChaCha20-Poly1305, Argon2id, Ed25519,
   X25519, BLAKE3, HKDF, with AAD binding throughout. No wire-format
   compatibility with legacy vendors (deliberate — see §11).
4. **Self-host first** — a managed SaaS may layer on top later, but the OSS
   core never depends on it.

**Distribution model:** OSS self-host core (free) + an optional future
managed-SaaS tier at `hekate.synapticcyber.com`, operated by **Synaptic
Cybersecurity Alliance, Inc.** (brand: *Synapticcyber*). The managed tier
is where 🏢 features live; nothing in the OSS protocol blocks a self-host
operator from building equivalents.

---

## 2. Platform Surfaces (clients)

Hekate is one protocol with five (soon seven) client surfaces, all sharing
the same `hekate-core` crypto via native Rust or WebAssembly.

| Surface | Status | Coverage |
|---|---|---|
| **CLI** (`hekate`) | ✅ ~99% | Full vault lifecycle, all 6 cipher types, sends, attachments, orgs, 2FA, imports, rotate-keys, SSH agent, daemon mode |
| **Browser extension** (Chromium MV3) | 🚧 ~98% | Vault, autofill, sends, attachments, orgs (read+write), TOTP, WebAuthn, generator, rotate-keys, passkey provider |
| **Browser extension** (Firefox MV3) | 🚧 | Build target + AMO-clean artifact shipped; passkey provider absent (blocked on `browser.webAuthn` — #4) |
| **Web vault** (SolidJS SPA) | 🚧 ~98% | Vault, sends, orgs (read+write), settings, 2FA, attachments, rotate-keys, graphical import |
| **Desktop** (Tauri 2) | 🚧 macOS foundation | Apple-Silicon shell, tray, signing plumbing; Touch ID / auto-update / Win+Linux pending |
| **iOS** (Swift/SwiftUI) | ⬜ | Not started — no design doc yet |
| **Android** (Kotlin/Compose) | ⬜ | Not started — no design doc yet |

Detail on each surface's feature parity is in §3–§9 by capability. Client
distribution (app stores, package managers) is in §13.

---

## 3. Personal Vault

The core single-user experience.

### 3.1 Cipher management ✅
- **Six creatable cipher types:** Login, Secure Note, Card, Identity, SSH
  Key, TOTP. A seventh **API-key type (7)** is imported from other vaults
  and rendered read-only (popup).
- **Full lifecycle:** create, read, edit, soft-delete (trash), restore,
  permanent purge (tombstone).
- **Per-cipher encryption keys (PCKs):** every cipher field is encrypted
  under its own key, AAD-bound to `cipher_id` + field name, so the server
  cannot move ciphertext between rows or fields.
- **Folders:** flat folder model with CRUD + tombstones.
- **Search + type filters** across the vault.
- **Live TOTP:** countdown codes shown inline for TOTP ciphers and for
  Login ciphers carrying an `otpauth` secret (CLI + popup + web).

### 3.2 Sync ✅
- **Cursor-based delta sync** (`GET /api/v1/sync?since=`) with tombstones.
- **Conflict detection:** `If-Match` revision precondition on writes; a 409
  returns the current server cipher rather than silently overwriting.
- **Offline-first** client model.
- **Real-time push** over SSE (`cipher.changed`, `folder.changed`,
  `attachment.changed`, `send.changed`, and `.tombstoned` variants); popup
  push is service-worker-owned and survives popup close.

### 3.3 Attachments ✅
- Resumable encrypted attachments per cipher via **tus 1.0** transport +
  **PMGRA1 chunked-AEAD** body format, with BLAKE3 finalize verification.
- BW04 signed vault manifest v3 commits to the attachment set via a
  per-cipher `attachments_root`.
- Surfaces: CLI (`hekate attach …`), popup (cipher edit view, personal
  ciphers), web vault (embedded in cipher detail).
- **Planned (⬜ M2.24a):** cloud blob backends (S3/MinIO/Azure/GCS) behind
  the `BlobStore` trait; signed-URL downloads; range/streaming download;
  streaming finalize hash; per-org attachment-size policy.

### 3.4 Password & passphrase generator ✅
- Consolidated in `hekate-core` (CSPRNG via `OsRng`): character-class
  password generation (length, per-class toggles, avoid-ambiguous) and EFF
  long-wordlist passphrases (word count, separator, capitalize).
- Surfaces: standalone **Generator tab** in web vault + popup; inline
  password-field button; CLI `hekate generate`.

### 3.5 Import ✅ (~90%)
- **Four formats shipped:** Bitwarden JSON, 1Password 1PUX, KeePass KDBX
  3.1/4, LastPass CSV. Pure-parser projection onto a shared
  `ProjectedImport` shape; folders materialize first, ciphers thread new
  folder ids, custom fields fold into notes, unsupported categories surface
  per-row warnings. Parsing is always client-side (KDBX master password and
  plaintext export blobs never reach the server).
- **Surfaces:** CLI covers all four formats; web vault Settings → Import
  has the graphical Bitwarden JSON flow (WASM-bound parser).
- **Planned (⬜ #5 D.2–D.4):** web-vault graphical surfaces for LastPass /
  1Password / KeePass; extension popup shortcut (opens `/web/import`).
- **Planned (⬜):** encrypted-export variants per format; per-format
  attachment import via tus.

### 3.6 Export ✅
- Encrypted account export (passphrase-sealed JSON, byte-compatible between
  CLI and web vault).

---

## 4. Authentication & Account Security

### 4.1 Master-password auth ✅
- **Argon2id** master-key derivation; **HKDF** auth/wrap/signing subkeys.
- **EncString v3** envelope (XChaCha20-Poly1305 + AAD binding).
- **KDF-bind MAC (BW07/LP04):** the client refuses to derive keys unless
  the server-supplied KDF params are bound by a valid HMAC under the master
  key — defeats a server lying about KDF params.
- **User-enumeration protection:** prelogin returns deterministic-fake
  salt/MAC for unknown emails.
- **Master-password change:** rotates KDF salt + signing seed while leaving
  the unwrapped `account_key` unchanged, so all dependents keep decrypting.

### 4.2 Tokens & sessions ✅
- **JWT access tokens** (HS256 today; Ed25519 tracked for v1.0 hardening).
- **Single-use rolling refresh tokens** with family-revocation on replay.
- **Personal access tokens (PATs)** with scopes.
- **Service-account tokens** (`pmgr_sat_*` wire format, org-owner-managed,
  `AuthService` principal). M6 adds the `secrets:*`-scoped call sites.

### 4.3 Two-factor ✅
- **TOTP + recovery codes.** Recovery codes are **auth-only by design** —
  they never decrypt the vault (vault recovery is M5 territory).
- **WebAuthn / FIDO2** — popup + web vault drive enroll + login; CLI is
  gated on a libfido2 binding (⬜ tracked separately).

### 4.4 Key rotation ✅
- **`account rotate-keys`** atomically re-wraps **every** `account_key`-wrapped
  field in one transaction: personal-cipher PCKs, Send `protected_send_key`,
  Send `name`, org-membership `protected_org_key`, the X25519 private key,
  plus a manifest re-sign. Master password (and manifest signing key)
  unchanged. Available in CLI, popup, web vault.
  - **Invariant:** any new `account_key`-wrapped field must be added to the
    server rewrap loops *and* both client rewrap loops, or rotation silently
    orphans it.

---

## 5. Sharing — Sends

Ephemeral, end-to-end-encrypted one-to-many shares. ✅
- **Text and file Sends**, anonymous recipients.
- **Content key:** HKDF-derived with a `send_id` salt; the `send_key` lives
  only in the URL fragment and never reaches the server.
- **Gates:** optional Argon2id-PHC server-side password gate; max-access-count;
  expiration/TTL; atomic access-count enforcement.
- **File body:** PMGRA1 chunked-AEAD + tus transport + 5-minute anonymous
  download tokens.
- **GC worker** prunes past-deletion Sends and their blobs (60s tick).
- **Surfaces:** CLI, popup (📤 Sends), web vault owner mode + `/send/*`
  recipient mode.

---

## 6. Sharing — Organizations & Teams

Cryptographically-enforced team sharing. ✅ for M4.0–M4.6 (~40% of the
full team/enterprise scope).

### 6.1 Org lifecycle ✅
- Create org, invite a peer, accept invite, cancel pending invite.
- **Single-pending-invite-per-org** invariant; roster excludes an invitee
  until they accept (#2).

### 6.2 Trust & rosters ✅ (today's model)
- **Signcryption-envelope invites** to a TOFU-pinned peer.
- **BW08 signed org roster** with parent-hash chain, verified on `/sync`.
- **Per-org symmetric key** wrapped under each member's `account_key`;
  receivers get a rotated key via signcryption to their X25519 pubkey.
- **TOFU pin stores are per-client** (CLI / popup / web each maintain their
  own peer + org pin store) — a known friction point that M5 redesigns.

### 6.3 Collections, roles, permissions ✅
- **Collections** with encrypted names (AAD-bound to `collection_id`+`org_id`),
  full CRUD.
- **Roles:** owner / admin / user. **Multi-owner is the required default**
  (≥2 owners; single-owner is treated as an availability bug).
- **Permission matrix:** `read` / `read_hide_passwords` / `manage`.

### 6.4 Cipher ownership ✅
- **Org-owned ciphers**; `move-to-org` (re-wrap PCK under org sym key,
  assign collections) and `move-to-personal` (re-wrap under account_key,
  drop collections). `org_id` is AAD-bound so the server can't move ciphers
  between orgs by rewriting a column.

### 6.5 Member removal + rotation ✅
- Owner-side key rotation on member removal (CLI + popup + web),
  receiver-side rotate-confirm consumption across all three clients,
  collection-name re-encryption, `prune-roster` recovery for orphaned
  rosters.

### 6.6 Policies ✅ (basic, M4.6)
- Per-org JSONB policy store; CLI `org policy {set,get,list,unset}`;
  owner-only toggles in popup + web. `single_org` enforced server-side.

### 6.7 Org gaps (⬜)
- **Groups** (sub-org permission bundles) — currently flat.
- **Event log / audit trail** — not yet shipped; folds into M5 (see §10).
- **Public role-gated admin endpoints.**
- **Advanced policies** beyond M4.6 — 🏢 managed-service tier.
- **Org nesting** — deliberate likely-"no" (inheritance of roster signing /
  key derivation / rotation across a tree is too costly).

---

## 7. Trust UX Redesign (M5) ⬜ — design locked

Replaces "every member TOFU-pins every other member" with "every member
TOFU-pins the **owner-set**, and the owner-set endorses every member's
fingerprint in a signed roster." Full design + audit-facing threat model in
[`m5-trust-ux.md`](m5-trust-ux.md) (citation-verified 2026-05-10).

**Planned capabilities:**
- **Per-owner Ed25519 signing keys**; roster signed by any one owner (1-of-N
  for day-to-day).
- **2-of-N quorum** for adding/removing owners.
- **Fingerprint-bound roster entries** (`signingPubkeyFingerprint`).
- **Strong-mode toggle** (per-org bool, default off).
- **Rotation envelopes** (Flow A) for owner-set changes.
- **Recovery-owner primitive** (BIP39 + hex file in v1; hardware key
  deferred).
- **Logging + alerting** on roster / quorum / rotation events — a
  first-class part of the spec, since several M5 threats (e.g. compromised
  master password producing an attacker rotation envelope) are mitigated by
  detection-and-response, not crypto.
- **Multi-owner invariant** enforced at org-create when an org has non-owner
  members.
- **Alpha → no migration:** ship the v2 schema directly.

**Deferred sub-milestone (⬜ M5.x):** Threshold recovery via **FROST-Ed25519**.
Direction locked; v1 schema reserves the `threshold_share` owner_type +
`ThresholdShareSet` table. Honest framing required in the audit doc: Crites
& Stewart (CRYPTO 2025) showed FROST isn't provably *fully* adaptively
secure without modification; Hekate's recovery use operates under
static-corruption assumptions, so the finding doesn't block M5.x but must be
stated.

---

## 8. Secrets Manager (M6) ⬜ — design locked

Developer/machine secrets, distinct from the human password vault. Design in
[`m6-secrets-manager.md`](m6-secrets-manager.md). **Not deferred** — an
active OSS milestone (do not conflate with the 🏢 managed-service list).

**Planned capabilities:**
- **Projects / secrets / service-account access** schema. (Open design
  decision: flat-projects-with-paths vs hierarchical-projects-with-subtree-ACLs
  — see [`followups.md`](followups.md) "Display hierarchy.")
- **Rust SDK** + **5 language bindings** via uniffi-rs.
- **`pms` CLI** for machine/developer workflows.
- **Integrations:** GitHub Actions, Kubernetes operator, Terraform, Ansible.
- **Audit:** `sm_audit_events` for secrets access (per the logging/alerting
  standard).

---

## 9. Cross-cutting Security & Crypto

### 9.1 Crypto stack ✅
XChaCha20-Poly1305 (AEAD) · Argon2id (KDF) · Ed25519 (signing) · X25519 (key
agreement) · BLAKE3 (hashing) · HKDF (subkeys). EncString v3 with AAD
binding throughout; PMGRA1 chunked-AEAD for attachments + file Sends;
signcryption envelopes; self-signed pubkey bundles; TOFU pinning.

### 9.2 Threat-model posture ✅
- Master password never leaves the device (only its HKDF-derived hash
  transits).
- `account_key` unwrapped client-side; server sees only the wrapped form.
- Send recipient keys live in URL fragments only.
- Server is untrusted for envelope contents — every signed artifact is
  verified client-side under a TOFU-pinned key.
- Per-cipher AAD binds ciphertext to `cipher_id` + field name.

### 9.3 Server features ✅
- Postgres (multi-tenant) or SQLite (single-binary) over `sqlx`/`AnyPool`.
- Outbound webhooks with HMAC signatures + persistent retry queue
  (redirect-following disabled — SSRF guard, #56/#57).
- BW04 signed vault manifest v3; BW08 signed org rosters.
- OpenAPI 3.1 (auto-generated via `utoipa`) + Scalar docs UI.
- Distroless image (~42 MB); structured JSON logging (`tracing`); health
  endpoints.
- Rate-limiting (`governor`); CORS allowlist; figment config.

### 9.4 Hardening (M7) ⬜ — publish gate
See [`secure-coding.md`](secure-coding.md) and [`build-plan.md`](build-plan.md)
§ M7. **No public signed binary ships** until secure-coding standards are met
(✅ drafted) and a comprehensive **internal** security analysis is complete +
remediated (⬜).
- **External audit posture (decided 2026-05-31):** an independent external
  crypto/code audit is **deferred** (cost-prohibitive for now). The completed
  in-house review/sweep + remediation is the working bar; surface residual
  risk once per major shipping decision, then proceed. Recommend the external
  audit when resources allow. (The in-repo M7/gate language still reads as an
  external-audit gate; align it on request.)
- Remaining M7 items: internal analysis pass, reproducible builds + SLSA L3
  provenance, SBOM in releases, Ed25519 JWT signing, bug bounty (post-GA).

---

## 10. Audit Logging & Alerting (cross-cutting) ⬜

Audit + alerting is a **first-class design concern** for every
security-sensitive feature, not a follow-up. Currently **unbuilt** and split
across milestones — a known gap worth unifying:
- M5 reserves an org-level `events` table (member removal, owner add/remove,
  strong-mode toggles, rotation envelopes applied).
- M6 defines `sm_audit_events` for secrets access.
- No unified audit-log design yet. Each security event must answer: **logged
  where** (server table / client log / both), **visible to whom** (org
  owners / affected user / admins), **alertable** (page / in-app / log-only),
  **tamper-evidence** (append-only / signed / server-trusted).

---

## 11. Intentional Non-Goals & Deferrals

**Deliberately out of scope for v1.0 ❌:**
- Wire-format compatibility with any existing vendor's API (chose greenfield
  protocol — modern crypto + delta sync over migration ease).
- Hosted SaaS as a *requirement* (self-host first; managed tier is additive).
- Federated multi-server (UUIDv7 ids + tombstones reserve the door for v2).
- Post-quantum primitives (EncString `alg_id` byte reserves the migration
  path).
- Ed25519 JWT signing (HS256 for now; tracked for v1.0 hardening).

**Deferred to a future managed-service tier 🏢** (not on the OSS roadmap;
self-host operators can build equivalents via org/policy/token primitives):
- SSO (SAML 2.0, OIDC) + JIT provisioning
- Trusted Device Encryption (master-password-less SSO)
- SCIM 2.0 provisioning
- Directory Connector (LDAP/AD/Entra/Okta/G-Workspace)
- Advanced policies beyond M4.6
- Provider Portal (MSP cross-org management)
- Emergency access (grantor→grantee X25519 wrap with wait period)

---

## 12. Quality & Test Posture ✅

427 tests passing across `hekate-core`, server unit, and integration suites
(KDF/EncString/manifest/roster/signcrypt/attachments/sends/import parsers,
plus org/auth/2FA/rotate-keys/webhooks integration). End-to-end smoke through
Docker + Traefik verified at each milestone. CI gates: `cargo fmt --check`,
`clippy -D warnings`, `cargo test`, plus supply-chain `cargo deny` +
`cargo audit`. See [`status.md`](status.md) for the per-suite breakdown.

---

## 13. Distribution & Go-to-Market (pre-GA) ⬜

Table-stakes for being installable as a real product. Full sequencing in
[`build-plan.md`](build-plan.md) §D; durable checklist in
[`followups.md`](followups.md).

- **Browser extensions:** Chrome Web Store (#32), Edge Add-ons (#33), Firefox
  AMO (#34), Safari (#35, heaviest port). Opera/Vivaldi/Brave consume the
  Chrome listing for free. *Store screenshots are now un-gated by the
  shipped generator (#41).*
- **Mobile:** iOS App Store + Android Play Store + F-Droid, each with native
  autofill platform integration (a major engineering effort, §2 mobile +
  build plan).
- **Desktop:** macOS .dmg / Mac App Store, Windows (MSI + Store), Linux
  (Flatpak/Snap/AppImage).
- **CLI:** GitHub releases (signed, SLSA), `cargo install`, Homebrew,
  Chocolatey, apt/dnf/AUR.
- **Server:** Docker Hub + ghcr.io, Helm chart, Terraform module, VM images.
- **Signing infra (blocks all of the above):** Apple Developer account (✅
  acquired 2026-05-30), Windows EV cert (⬜), Android signing keys (⬜),
  HSM-backed custody (⬜), per-channel auto-update + release-pipeline
  automation (⬜).

---

## 14. GA Product Readiness (beyond distribution) ⬜

- **User-facing docs site** (separate from dev docs) under
  `hekate.synapticcyber.com/docs`.
- **Internationalization / localization** — multi-language from launch
  across all client surfaces + server error strings; a dedicated milestone,
  not a polish pass.
- **Accessibility audit** (WCAG 2.1 AA; Section 508 / EN 301 549 for
  gov/enterprise).
- **Mobile autofill platform integration** — iOS `ASCredentialProvider` +
  QuickType + Face/Touch ID; Android Autofill Framework + `BiometricPrompt`
  + Inline Suggestions.
- **SaaS operations** — public status page; customer support tooling scoped
  so it can never become an unauthorized access channel (support actions on
  signed objects are logged + owner-visible under M5 audit primitives).
- **Enterprise / legal** — privacy policy + ToS (✅ extension privacy policy
  drafted, #31); SOC 2 Type II / ISO 27001 / HIPAA BAA / GDPR DPA / PCI scope
  / (FedRAMP only if federal is a serious target).

---

## 15. Open Product Decisions

- **Marketing surface** — bare root vs subdomain vs separate domain (TBD).
- **Docs-site path** — `/docs` sub-path vs `docs.` subdomain (pick when
  tooling lands).
- **M6 project model** — flat-with-paths vs hierarchical-with-subtree-ACLs.
- **Desktop Touch ID** — DECISION PENDING on (a) persisting the 32-byte
  master key in a biometric-gated Keychain item at all, and (b)
  access-control strictness. See [`desktop-touch-id.md`](desktop-touch-id.md).
- **Vault-item display hierarchy** — render `A/B/C`-style names as a
  client-side tree (pure UX polish, can ship anytime).
- **Align M7/gate docs** with the deferred-external-audit posture (offer
  standing).
