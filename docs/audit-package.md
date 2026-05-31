# Hekate — Audit Package Index

> Purpose: a single entry point for a security reviewer — whether the
> **in-house security-analysis pass** (the working bar, see
> [`followups.md`](followups.md) "Pre-publish security gate" item 2) or a
> future **external crypto/code audit** (currently deferred). It maps the
> documents and artifacts an auditor needs to where they live, states the
> audit scope, and lists the gaps still to produce.
>
> Keep this current: when a doc is added/renamed or a gap is filled,
> update the matching row.

## Audit scope (read first)

- **In scope — the shipped surface.** Authoritative inventory:
  [`status.md`](status.md) (milestone-by-milestone) and
  [`features.md`](features.md). At time of writing that is M0–M1.6
  (auth + vault + sync + push), M2 (CLI, PATs/SATs, 2FA TOTP+WebAuthn,
  attachments, Sends, imports, key rotation), M4.0–M4.6 (organizations,
  collections, permissions, member-removal + key rotation, basic
  policies), and the clients (CLI, web vault, browser extension, desktop
  shell).
- **Out of scope — designed but not implemented.** M5 (Trust UX
  redesign — [`m5-trust-ux.md`](m5-trust-ux.md) is design + threat model
  only), M6 (Secrets Manager — [`m6-secrets-manager.md`](m6-secrets-manager.md)),
  and all managed-service features (SSO/SCIM/etc.). Review these as
  *design* if at all, not as shipped code.
- **Maturity:** alpha — feature-rich, not yet independently audited;
  schema is pre-1.0 (no migration guarantees). No production users.

## Document map

### 1. Architecture & cryptography (the core of the review)
| Document | What the auditor gets |
|---|---|
| [`design.md`](design.md) | Primary spec: architecture, the crypto stack (Argon2id KDF, HKDF subkeys, EncString XChaCha20-Poly1305 envelope + AAD binding, per-cipher keys, signed BW04 manifest, signcryption envelope, `PMGRA1` chunked-AEAD attachments/Sends), token formats, data model, milestone map (§13). |
| [`key-hierarchy.md`](key-hierarchy.md) | The consolidated key-derivation tree, key inventory (origin / where it lives / wrap key / AAD), the EncString envelope, the signing/DST table, server token material, and rotation — all with `file:line` citations. Opens with the `pmgr`/`PMGRA1` protocol-frozen-identifier explanation. |
| [`audit-scope.md`](audit-scope.md) | Engagement brief: subject + commit baseline, in/out-of-scope components, trust model & assumptions, and deliverables sought. |
| [`trust-boundaries.md`](trust-boundaries.md) | Trust-boundary / data-flow map: what crosses client↔server↔DB↔blob-store in plaintext vs ciphertext, and what the server can/cannot learn. |
| [`crypto-inventory.md`](crypto-inventory.md) | Exact primitive + crate-version + parameter table (Argon2id cost, nonce strategy, signing/DSTs, server token hashing). |
| [`api.md`](api.md) | HTTP API surface — every endpoint, auth requirements, request/response shapes. The attack surface to enumerate. |
| `README.md` (top of contents in `CLAUDE.md`) | The **protocol-frozen identifiers** split (`pmgr-…` AAD strings, `pmgr_sat_*`/`pmgr_pat_*` token prefixes, `PMGRA1` magic baked into ciphertexts). Critical for understanding why some byte literals must not change. |

### 2. Threat model & secure-coding posture
| Document | What the auditor gets |
|---|---|
| [`threat-model-gaps.md`](threat-model-gaps.md) | Known threat-model gaps and accepted risks. |
| [`secure-coding.md`](secure-coding.md) | The crypto/protocol secure-coding non-negotiables + the definition of the "security-analysis pass" gate. |
| [`m5-security-review.md`](m5-security-review.md) | Internal adversarial *design* review (M5 trust model). |
| [`m5-trust-ux.md`](m5-trust-ux.md) | M5 trust-model redesign with an audit-facing threat model + citations. **Design only — not implemented.** |

### 3. Internal review evidence (what we've already done)
| Document | What the auditor gets |
|---|---|
| [`security-review-existing.md`](security-review-existing.md) | Internal security review of the existing crypto/auth code. |
| [`security-sweep-findings.md`](security-sweep-findings.md) | Findings from the multi-agent security sweep (2026-05-31) + remediation status. |
| Supply-chain gates | `deny.toml` (`cargo deny` — licenses/advisories/sources) and `.cargo/audit.toml` (`cargo audit`). Run `make deny audit`. |
| Test coverage | The test snapshot table at the bottom of [`status.md`](status.md) (suite-by-suite counts). |

### 4. Client surfaces
| Document | What the auditor gets |
|---|---|
| [`browser-extension.md`](browser-extension.md) | Extension (Chromium MV3 + Firefox) architecture, storage tiers, autofill, passkey provider. |
| [`ssh-agent.md`](ssh-agent.md) | Built-in SSH agent scope + approval model. |
| `clients/desktop/README.md` | Tauri desktop shell: CSP, empty IPC posture, signing/notarization. |
| [`desktop-touch-id.md`](desktop-touch-id.md) | Biometric-unlock design + at-rest-key tradeoff. **Decision pending — not implemented.** |

### 5. Process / disclosure
| Document | What the auditor gets |
|---|---|
| `SECURITY.md` | Supported versions + vulnerability disclosure process. |
| `CONTRIBUTING.md`, [`development.md`](development.md) | Build/run, DCO, validation commands. |
| `CHANGELOG.md` | Change history. |

## Gaps to produce (audit readiness checklist)

Documents/artifacts a thorough auditor will expect that we don't yet have
as standalone deliverables (some content exists inside `design.md` and
should be extracted/linked):

- [x] **Key hierarchy / lifecycle diagram** — ✅
      [`key-hierarchy.md`](key-hierarchy.md): full derivation tree, key
      inventory, EncString envelope, DST/AAD tables, and rotation, with
      `file:line` citations.
- [x] **Data-flow / trust-boundary diagram** — ✅
      [`trust-boundaries.md`](trust-boundaries.md).
- [x] **Written audit scope statement** — ✅
      [`audit-scope.md`](audit-scope.md): subject + commit baseline,
      in/out-of-scope, trust model, deliverables.
- [ ] **SBOM** — dependency bill of materials for a tagged build
      (tracked in `status.md` M7 / `followups.md`).
- [ ] **Reproducible-build attestation** — so the auditor can verify the
      reviewed source matches a distributed binary (M7 / `followups.md`).
- [ ] **Consolidated test/coverage report** — beyond the count table;
      coverage by crypto-critical module.
- [x] **Crypto primitive/version inventory** — ✅
      [`crypto-inventory.md`](crypto-inventory.md).

## Notes

- The in-house pass and an external audit consume the same package; the
  in-house pass is the current working bar (external audit deferred until
  resources allow — surface residual risk per shipping decision, don't
  hard-block on it).
- This index is documentation only; producing the gap items above is
  separate, tracked work.
