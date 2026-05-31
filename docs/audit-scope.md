# Hekate — Security Audit Scope Statement

> Engagement brief for a security reviewer (the in-house security-analysis
> pass and/or a future external crypto + code audit). Defines the subject,
> what is in/out of scope, the trust model, and the deliverables sought.
> Companion to [`audit-package.md`](audit-package.md) (document index) and
> [`key-hierarchy.md`](key-hierarchy.md) (cryptographic material).

## Subject

- **Project:** Hekate — self-hosted, end-to-end-encrypted password/secrets
  manager. Repository `synapticcybersecurity/hekate` (AGPL-3.0).
- **Commit baseline:** pin a **tagged release commit** at engagement start.
  Current `main` baseline at the time of writing: `f3e30a9`. (The reviewed
  source must match a specific commit; the auditor verifies the hash.)
- **Maturity:** **alpha.** Feature-rich on the personal-vault and org
  tracks; **not previously independently audited**; schema is pre-1.0 (no
  migration guarantees); no production users. The protocol byte literals
  (`pmgr-…` / `PMGRA1`) are deliberately frozen — see
  [`key-hierarchy.md`](key-hierarchy.md) §0.

## In scope

The **shipped surface**. Authoritative inventory: [`status.md`](status.md)
and [`features.md`](features.md). Concretely:

| Area | Components / paths |
|---|---|
| **Cryptographic core** (highest priority) | `crates/hekate-core/` — `kdf.rs`, `encstring.rs`, `keypair.rs`, `signcrypt.rs`, `manifest.rs`, `org_roster.rs`, `org_cipher_manifest.rs`, `send.rs`, `attachment.rs` (PMGRA1 chunked-AEAD), `cipher_id.rs`, `passkey.rs`, `wasm.rs` |
| **Server** | `crates/hekate-server/` — auth (`auth/jwt.rs`, `pat.rs`, `sat.rs`, refresh, scopes, extractors), routes (ciphers, folders, sync, sends, attachments/tus, orgs, collections, policies, 2FA TOTP+WebAuthn, webhooks, account/rotate-keys), CORS middleware (`cors.rs`), rate-limiting, prelogin user-enumeration defense, persistence over `sqlx`/`AnyPool` (SQLite + Postgres) |
| **Clients** | CLI (`crates/hekate-cli/`), web vault (`clients/web/`, SolidJS + `hekate-core` wasm), browser extension (`clients/extension/`, Chromium MV3 + Firefox), desktop shell (`clients/desktop/`, Tauri 2 — empty IPC, CSP) |
| **Protocols / formats** | EncString v3 envelope, BW04 signed vault manifest, signcryption envelope, per-cipher-key scheme, PMGRA1 chunked-AEAD, token wire formats (`pmgr_pat_*`/`pmgr_sat_*`), the KDF-bind MAC (BW07/LP04 downgrade defense) |
| **Imports** | `import_{bitwarden,1password,keepass,lastpass}` parsers (untrusted-input parsing) |

Primary questions for the reviewer:
- Are the KDF, AEAD, signing, and signcryption constructions sound and
  correctly applied (nonce handling, AAD binding, domain separation,
  constant-time comparisons, key zeroization)?
- Does the zero-knowledge property hold — can a malicious/compromised
  **server** learn vault plaintext or forge accepted ciphertexts/manifests?
- Auth/session correctness: token issuance/validation, refresh rotation +
  replay defense, `security_stamp` invalidation, scope enforcement.
- Untrusted-input safety: panic/DoS on malformed input across server
  handlers, import parsers, and the wasm boundary.
- Web/desktop client surface: CSP, the (empty) Tauri IPC, what lands in
  `localStorage`/`chrome.storage`, the configured-server trust boundary.

## Out of scope (not shipped — review as *design* only, if at all)

- **M5 — Trust UX redesign** ([`m5-trust-ux.md`](m5-trust-ux.md)): per-owner
  keypairs, fingerprint-bound rosters, FROST-Ed25519 threshold recovery.
  **Design + threat model only; no implementation.**
- **M6 — Secrets Manager** ([`m6-secrets-manager.md`](m6-secrets-manager.md)):
  not built.
- **Desktop Touch ID unlock** ([`desktop-touch-id.md`](desktop-touch-id.md)):
  design, decision pending; no code.
- **Managed-service-tier features** (SSO/SAML/OIDC, SCIM, Directory
  Connector, Trusted Device Encryption, Emergency Access, MSP portal): not
  on the OSS roadmap, not implemented.
- Third-party dependencies beyond Hekate's usage of them (covered by
  `cargo deny`/`cargo audit`, not a source audit of upstream crates).
- Production deployment/infra hardening (no live deployment exists yet).

## Trust model & assumptions

- **Client-side encryption; the server is untrusted for confidentiality.**
  All vault plaintext is encrypted under keys derived from / wrapped by the
  master password before leaving the client. The server stores ciphertext,
  enforces auth/access control, and routes sync — it must not be able to
  decrypt vault contents.
- The server **is** trusted for availability and for honest enforcement of
  access-count/expiry/revocation on Sends (it gates, it cannot decrypt).
- The master password is the root of trust; its compromise is full
  compromise (out of scope to defend against).
- Transport is HTTPS in production (WebAuthn requires it); `localhost` dev
  is the documented exception.
- The KDF-bind MAC assumes the client verifies it **before** sending the
  master-password hash (BW07/LP04) — a property to confirm holds in every
  client.

## Deliverables sought

- Findings with severity, affected `file:line`, reproduction, and
  remediation guidance.
- Specific attention to: any deviation from the documented key hierarchy;
  AAD/nonce/DST misuse; the HS256-vs-Ed25519 token note in
  [`key-hierarchy.md`](key-hierarchy.md) §5; cross-client AAD constant
  agreement (§7); panic/DoS in untrusted-input paths.
- A statement of residual risk for the alpha posture.

## Reference package

[`audit-package.md`](audit-package.md) (index) · [`design.md`](design.md)
(architecture + crypto) · [`key-hierarchy.md`](key-hierarchy.md) ·
[`threat-model-gaps.md`](threat-model-gaps.md) ·
[`secure-coding.md`](secure-coding.md) ·
[`security-review-existing.md`](security-review-existing.md) ·
[`security-sweep-findings.md`](security-sweep-findings.md) ·
[`api.md`](api.md).
