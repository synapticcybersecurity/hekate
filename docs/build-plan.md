# Hekate — Build Plan

> **What this doc is.** The sequenced, story-level plan for building Hekate
> end to end: completed epics (compressed), and — the part that was
> missing — a decomposed, dependency-ordered roadmap for the remaining work
> with acceptance criteria per story. It answers *"how and in what order,"*
> where [`product-spec.md`](product-spec.md) answers *"what,"* and
> [`design.md`](design.md) answers *"how it's architected."*
>
> **Source of truth split:** milestone status lives in [`status.md`](status.md);
> the live queue lives in [`followups.md`](followups.md). This doc is the
> bridge — it turns those into epics → stories with acceptance criteria so
> work can be picked up (and, if desired, minted as GitHub issues).
>
> **Legend:** ✅ done · 🚧 in flight · ⬜ planned · 🏢 deferred (managed tier).
> Snapshot: **2026-06-13**.
>
> **Live tracking (source of truth for status):** all epics and stories below
> are mirrored as GitHub issues on the **Hekate Roadmap** project board
> (`github.com/orgs/synapticcybersecurity/projects/2`). Status = issue state
> (closed = shipped, open = planned, `in-progress` label = in flight). This
> doc holds the rationale + acceptance criteria; the board holds live status.
> Epic issues: M0 #58 · M1 #59 · M2 #60 · M3-Web #61 · M3-Ext #62 · M3-Desktop
> #63 · M4 #64 · M5 #65 · M6 #66 · M7 #67 · E1 #68 · E2 #69 · E4 #70 · D #71 ·
> G #72. Milestones M0–M7 + Distribution + GA created (M0/M1/M4 closed).

---

## A. Completed epics (compressed)

These are shipped and test-covered (427 tests, see [`status.md`](status.md)).
Listed so the plan is complete end to end; detail lives in `status.md`.

| Epic | Milestone | Outcome |
|---|---|---|
| Foundation | M0 ✅ | Rust workspace, axum server, sqlx (SQLite/Postgres), health, OpenAPI stub, Docker, Makefile |
| Personal vault MVP | M1 ✅ | Argon2id KDF, EncString v3, JWT, register/prelogin/password-grant |
| Ciphers + sync | M1.5 ✅ | Cipher/folder CRUD, soft-delete/restore/purge, `If-Match` conflict, delta sync |
| Refresh + push | M1.6 ✅ | Rolling refresh tokens, family revocation, SSE push |
| CLI | M2.1–M2.27c ✅ | Full client: all cipher types, sends, attachments, orgs, 2FA, imports, rotate-keys, SSH agent, daemon mode |
| Tokens & 2FA | M2.5/M2.22/M2.23 ✅ | PATs, service accounts, TOTP+recovery, WebAuthn (server + popup + web) |
| Attachments | M2.24 ✅ | tus 1.0 + PMGRA1 chunked-AEAD + BW04 v3 manifest + GC worker |
| Sends | M2.25/M2.25a ✅ | Text + file, anonymous access, password gate, TTL/count gates, GC |
| Imports | M2.27–M2.27c ✅ | Bitwarden / 1Password / KeePass / LastPass (CLI); Bitwarden web |
| Account-key rotation | M2.26 ✅ | Atomic rewrap of all account_key-wrapped fields |
| Web vault | C.0–C.8 ✅ | SolidJS SPA, full vault/sends/orgs/settings/attachments/rotate-keys |
| Browser extension | M3.1–M3.15 ✅ | Chromium MV3 full client; Firefox build target |
| Organizations | M4.0–M4.6 ✅ | Lifecycle, rosters, collections, permissions, move, member-removal+rotation, basic policies |
| Password generator | #41 ✅ | Consolidated in core; standalone tab (web+popup) + inline |
| Desktop foundation | #8 (partial) 🚧 | Tauri 2 macOS shell, configurable API base, tray, bug fixes, signing plumbing |

---

## B. GitHub issue reconciliation

Before sequencing, reconcile the open GitHub issues against doc status.
Issues live at `synapticcybersecurity/hekate`.

| Issue | Title | Maps to | Note |
|---|---|---|---|
| #3 | Popup mark pending-invite entries | Epic E1 (extension polish) | Small UX |
| #4 | Passkey provider — Firefox port | Epic E2 (Firefox) | **Blocked** on Firefox `browser.webAuthn` |
| #5 | Web vault import D.2–D.4 + ext shortcut | Epic E1 | Story-decomposed below |
| #6 | Firefox MV3 port | Epic E2 | ✅ **Closed 2026-06-13** — build target verified in code; passkey piece remains under #4 |
| #7 | Web vault secure-note title not reflected (Firefox) | Epic E1 | Bug |
| #8 | Desktop apps via Tauri | Epic E3 (desktop) | Active; story-decomposed below |
| #16 | M5 design-review findings | Epic M5 | Resolve before M5 impl |
| #18 | Existing-code security review findings | Epic M7 | Hardening |
| #22 | Security sweep findings H1/M1–M3/L1 | Epic M7 | Hardening |
| #26 | Desktop Send delete + Copy-URL | Epic E3 | ✅ **Closed 2026-06-13** — both bugs verified fixed in code (`dialog.ts` + `shareBaseUrl()`) |
| #31 | Extension privacy policy | Epic D1 (stores) | ✅ drafted (closed) |
| #32/#33/#34 | Chrome / Edge / AMO publication | Epic D1 | Un-gated by #41; operator upload task |
| #35 | Safari extension | Epic D1 | Heaviest port; may piggyback on macOS app |
| #36 | Distribution & publishing (tracking) | Epic D (umbrella) | Keep as tracking issue |
| #43 | Extension save/update password | Epic E1 | Needs content script |
| #52 | Suppress Chrome "save password?" prompt | Epic E1 | `privacy.passwordSavingEnabled` toggle |

**Action:** close/rescope #6 and #26 to match doc reality; everything else
slots into the epics below.

---

## C. Remaining roadmap — dependency-ordered

The critical path is **Desktop signing → M7 internal security pass → first
public binary → store/channel publication**. M5 and M6 are large parallel
tracks that can proceed independently of distribution but should clear their
design-review findings first.

```
   (now)
     │
     ├─ E1  Client polish & parity ──────────────┐ (small, parallelizable)
     ├─ E2  Firefox passkey (blocked) ............│
     ├─ E3  Desktop tier-A completion ───────────┤
     │                                            │
     │   ┌── M7  Internal security pass ◀─────────┘  (GATES first public binary)
     │   │        │
     │   │        ▼
     │   │   D    Distribution + publishing  (stores, packages, signing infra)
     │   │        │
     │   │        ▼
     │   │   G    GA readiness (i18n, a11y, mobile autofill, SaaS ops, legal)
     │   │
     ├─ M5  Trust UX redesign  (independent track; clear #16 first)
     │        │
     │        └─ M5.x  FROST threshold recovery (after M5 v1)
     │
     ├─ M6  Secrets Manager   (independent track; ~8 wks, M6.0–M6.4)
     │
     └─ E4  Mobile clients (iOS/Android)  ⬜ needs design doc FIRST
```

---

## Epic E1 — Client polish & parity 🚧

Small, mostly-independent stories. Closes the long tail on the three shipped
clients. No hard ordering except where noted.

- **E1.1 — Web-vault import D.2 (LastPass CSV) (#5).** Un-gate the `csv`
  crate for wasm32; add `parseLastpassCsv` to `wasm.rs`; add CSV to the
  Import format radio. *Done when:* a LastPass CSV imports graphically with a
  dry-run preview + per-row warnings, parsing fully client-side, reusing the
  existing folder/cipher loop + BW04 re-sign.
- **E1.2 — Web-vault import D.3 (1Password 1PUX) (#5).** Un-gate `zip`
  (`default-features = false` + explicit `deflate`; verify no native backend);
  add `parse1passwordZip`; accept `.1pux`. *Done when:* a 1PUX imports
  graphically, client-side, with preview + warnings.
- **E1.3 — Web-vault import D.4 (KeePass KDBX) (#5).** Un-gate `keepass`
  (highest wasm dep risk — flag if it won't compile); add `parseKeepassKdbx`;
  add a master-password prompt step before preview. *Done when:* a KDBX
  imports graphically, master password never leaving the browser.
- **E1.4 — Extension import shortcut (#5).** Popup "Import" button opens
  `/web/import` in a new tab. *Done when:* no parser code lives in the
  extension; the SPA handles everything. *Depends on:* E1.1+ (something to
  open).
- **E1.5 — Extension save/update-password capture (#43).** Add a content
  script (both manifests) detecting credential submissions + a
  confirm-before-save/update prompt routed through the normal E2EE
  create/update path. *Done when:* entering creds on a site offers to
  save/update, host-scoped, top-frame-only (Audit C2), no plaintext logged.
- **E1.6 — Suppress Chrome's native save prompt (#52).** Toggle
  `privacy.passwordSavingEnabled`. *Done when:* a setting suppresses the
  browser's competing prompt; complements E1.5.
- **E1.7 — Popup: mark pending-invite member entries (#3).** *Done when:*
  the popup member list visually distinguishes accepted vs pending invitees.
- **E1.8 — Firefox secure-note title refresh bug (#7).** *Done when:* a
  secure-note title edit reflects in the list view without re-navigation on
  Firefox.
- **E1.9 — Inline content-script autofill overlay (Shadow DOM) (M3.10+).**
  The remaining ~2% of extension scope. *Done when:* an in-page overlay
  offers autofill without opening the popup, isolated in a Shadow DOM,
  top-frame-only.
- **E1.10 — `make` ergonomics.** Make `make wasm`/`make web` rebuild stale
  popup assets (today `make extension` is a separate step). *Done when:*
  editing core/web doesn't silently leave the extension stale.

---

## Epic E2 — Firefox passkey provider ⬜ (BLOCKED)

- **E2.1 — Firefox passkey provider (#4).** Reuse `passkey.rs` + popup
  approval UI unchanged; only `background.js` event wiring needs the Firefox
  variant. **Blocked** on Firefox shipping the `browser.webAuthn` extension
  API (WICG draft, flagged in Nightly). *Done when:* the API is available and
  a webauthn.io round-trip passes in Firefox. *Action:* keep parked;
  re-evaluate when Firefox ships the API.

---

## Epic E3 — Desktop tier-A completion 🚧 (#8)

Apple-Silicon macOS. Foundation, tray, bug fixes, and signing plumbing are
done. Ordered remaining slices:

- **E3.1 — ✅ Send-delete + Copy-URL fixes (#26, closed 2026-06-13).** In-app
  `dialog.ts`/`DialogHost.tsx` replaced the no-op `window.confirm`;
  `shareBaseUrl()` fixed the `tauri://` share link. Verified in code.
- **E3.2 — Touch ID unlock (DECISION PENDING).** Store the 32-byte master key
  in a biometric-gated Keychain item; adds the first custom IPC command (both
  flagged review-required in `secure-coding.md` §8). *Blocked on a product
  decision:* (a) persist the key at all? (b) access-control strictness? See
  [`desktop-touch-id.md`](desktop-touch-id.md). *Done when:* the decision is
  signed off, implemented, and tested in a **signed** build (biometrics only
  work in `make desktop-release`).
- **E3.3 — Auto-update.** Tauri built-in updater plugin + signed update
  manifest endpoint. *Depends on:* a release channel existing (Epic D).
  *Done when:* a signed update is delivered + verified end-to-end.
- **E3.4 — In-app "change server."** Add a Settings affordance to switch
  servers post-first-run. *Done when:* a user can re-point the desktop app
  without reinstall.
- **E3.5 — Windows / Linux bundles.** MSI/MSIX + winget;
  AppImage/Flatpak/deb/rpm. *Done when:* a signed installer exists per OS
  (Windows signing depends on the EV cert, Epic D).
- **E3.6 — Tier B/C (later).** Tier C in-app SSH agent; Tier B native
  credential provider (macOS first). *Done when:* scoped as their own
  milestones when tier-A ships.

> **Gate:** the first public desktop binary is the first thing through the M7
> publish gate. E3.2+ produce a *signable* app, but **publication waits on
> M7**.

---

## Epic M7 — Internal security hardening pass ⬜ (PUBLISH GATE)

Gates the first public signed binary. External audit is **deferred**
(cost-prohibitive, decided 2026-05-31) — the in-house pass is the working
bar; surface residual risk once per shipping decision and proceed.

- **M7.1 — Secure-coding standards.** ✅ drafted ([`secure-coding.md`](secure-coding.md)).
- **M7.2 — Tooling sweep.** Run `/security-review`, `/code-review ultra`,
  `cargo deny`, `cargo audit`, clippy `-D warnings` over the shipped surface;
  resolve #18 + #22 findings. *Done when:* all gates green and tracked
  findings remediated.
- **M7.3 — Manual crypto-call-site review.** Every AEAD/KDF/signing/AAD call
  site reviewed against `secure-coding.md`. *Done when:* reviewed + signed
  off with notes.
- **M7.4 — Panic/DoS triage** of untrusted-input paths (no `unwrap`/`expect`/
  `panic!` in lib/service code). *Done when:* triaged + fixed.
- **M7.5 — Threat-model of the shipped surface** (vs `threat-model-gaps.md`).
  *Done when:* documented, residual risks listed.
- **M7.6 — Ed25519 JWT signing.** Replace HS256 (tracked for v1.0). *Done
  when:* tokens sign/verify under Ed25519 with a migration path.
- **M7.7 — Reproducible builds + SLSA L3 provenance + SBOM in releases.**
  *Done when:* a tagged release produces a verifiable, reproducible binary +
  attestation + SBOM.
- **M7.8 — Align gate docs** with the deferred-external-audit posture (offer
  standing). *Done when:* `status.md` M7 + `followups.md` gate language match
  the 2026-05-31 decision.
- **M7.9 — Bug bounty (post-GA).** HackerOne/Intigriti. *Done when:* a
  program is live after GA.

---

## Epic M5 — Trust UX redesign ⬜ (independent track)

Design + audit-facing threat model locked in [`m5-trust-ux.md`](m5-trust-ux.md)
(session kickoff prompt at the bottom of that doc). **Clear #16
(design-review findings) before implementation.** Alpha → no migration; ship
the v2 schema directly. Suggested story sequence (server-first, since clients
call it):

- **M5.0 — Server schema + per-owner signing keys.** Co-owner-set table,
  fingerprint-bound roster entries, `threshold_share` owner_type +
  `ThresholdShareSet` table reserved, `events` audit table. *Done when:*
  schema + server routes exist with integration tests; multi-owner invariant
  enforced at org-create when non-owner members exist.
- **M5.1 — Rotation envelope flow (Flow A).** Owner-set change → rotation
  envelope. *Done when:* an owner add/remove produces a verifiable rotation
  envelope; receivers consume it; tested across the rotate-confirm path.
- **M5.2 — 1-of-N roster signing + 2-of-N owner-change quorum.** *Done when:*
  any one owner can sign the roster; adding/removing an owner requires 2-of-N;
  quorum enforced server-side + verified client-side.
- **M5.3 — Recovery-owner primitive.** BIP39 + hex file in v1 (hardware key
  deferred). *Done when:* a recovery owner can be enrolled + exercised.
- **M5.4 — Strong-mode toggle** (per-org bool, default off). *Done when:* the
  toggle changes enforcement and is owner-only.
- **M5.5 — Audit + alerting** on roster/quorum/rotation events (logged where /
  visible to whom / alertable / tamper-evidence answered per the
  logging-alerting standard). *Done when:* every M5 security event is logged
  + owner-visible.
- **M5.6 — Client rollout (CLI → popup → web).** Wire each client to the new
  trust model. *Done when:* all three clients drive M5 flows; end-to-end smoke
  green; old per-peer TOFU pinning retired.
- **M5.x — FROST-Ed25519 threshold recovery (DEFERRED).** After M5 v1 ships
  and the OSS/SaaS push is underway. *Done when:* threshold recovery works
  under static-corruption assumptions, with honest audit-doc framing of the
  Crites & Stewart (CRYPTO 2025) adaptive-security caveat.

---

## Epic M6 — Secrets Manager ⬜ (independent track, ~8 weeks)

Design in [`m6-secrets-manager.md`](m6-secrets-manager.md). **Active OSS
milestone — not deferred.** Sub-milestones exist in the design doc but aren't
yet surfaced in `status.md` — surface M6.0–M6.4 there when work starts.

- **M6.0 — Schema + core model.** Projects / secrets / service-account access.
  **Resolve the open design decision first:** flat-projects-with-paths vs
  hierarchical-projects-with-subtree-ACLs (see `followups.md` "Display
  hierarchy"). *Done when:* schema + server routes + `sm_audit_events` exist
  with tests; service-account `secrets:*` scopes gate access.
- **M6.1 — `pms` CLI.** Machine/developer secrets workflows. *Done when:*
  `pms` can read/write/list project secrets via a service-account token.
- **M6.2 — Rust SDK.** *Done when:* a published Rust crate wraps the API with
  ergonomic types.
- **M6.3 — 5 language bindings** via uniffi-rs. *Done when:* bindings build +
  smoke-pass in all five target languages.
- **M6.4 — Integrations.** GitHub Actions, Kubernetes operator, Terraform,
  Ansible. *Done when:* each integration injects secrets in its native
  workflow with docs + an example.

---

## Epic E4 — Mobile clients ⬜ (needs design doc FIRST)

**Currently the biggest planning hole.** iOS and Android are roadmap slots
with no design doc, no acceptance criteria, no effort estimate — unlike every
other client. **Do not start implementation until E4.0 lands.**

- **E4.0 — Mobile architecture design doc.** Decide: native (Swift / Kotlin)
  vs shared-core-via-uniffi reuse of `hekate-core`; offline/sync model;
  secure local storage (Keychain / Keystore); biometric unlock; how the WASM
  vs FFI boundary maps. *Done when:* a `docs/mobile-clients.md` exists with
  the same fidelity as the desktop/web docs, including an effort estimate and
  a prerequisite list. *Or:* explicitly mark mobile deferred with a rationale
  so it stops reading as vaporware.
- **E4.1 — iOS app.** SwiftUI vault client + sync. *Gated on E4.0.*
- **E4.2 — iOS autofill integration.** `ASCredentialProvider`, QuickType,
  Face/Touch ID gating, optional iCloud Keychain passkey bridge. *Major
  effort; each is its own surface.*
- **E4.3 — Android app.** Kotlin/Compose vault client + sync. *Gated on E4.0.*
- **E4.4 — Android autofill integration.** Autofill Framework, `BiometricPrompt`,
  per-site heuristics + long-press fallback, Inline Suggestions. *Notoriously
  fiddly; budget tuning + a large test matrix.*

---

## Epic D — Distribution & publishing ⬜ (umbrella #36)

Gated on **M7** for anything signed/public. Full checklist in
[`followups.md`](followups.md). Grouped into shipping waves with their
blockers made explicit.

**D0 — Signing infrastructure (blocks every channel):**
- Apple Developer account ✅ (2026-05-30).
- Windows EV code-signing cert ⬜ (~$300–400/yr; without it, SmartScreen
  warns on every install).
- Android signing keys ⬜ (HSM-backed upload-key custody).
- HSM-backed custody for all high-value signing keys ⬜.
- Release-pipeline automation ⬜ (one tagged release → build+sign+publish to
  every channel; without it, releases drift between channels).
- Per-channel auto-update (stable/beta/nightly) ⬜.

**D1 — Browser extensions** (un-gated by #41 store screenshots): Chrome Web
Store (#32), Edge Add-ons (#33), Firefox AMO (#34 — upload the
`make extension-firefox-zip` artifact), Safari (#35, heaviest). Privacy policy
✅ (#31). *Blocker:* App Store review prep — password managers often get
rejected for cosmetic reasons; budget weeks.

**D2 — Desktop:** macOS .dmg / Mac App Store (depends E3 + Apple cert),
Windows (depends EV cert), Linux Flatpak/Snap/AppImage.

**D3 — CLI:** GitHub releases (signed, SLSA), `cargo install hekate-cli`
(fast win), Homebrew (on the M6.0–M6.1 timeline per `m6` Q7), Chocolatey,
apt/dnf/AUR.

**D4 — Server:** Docker Hub + ghcr.io (partially via `make image`; needs
publication automation), Helm chart, Terraform module, VM images (AWS AMI /
DO Marketplace / Linode).

---

## Epic G — GA product readiness ⬜ (post-distribution)

- **G1 — User-facing docs site** under `hekate.synapticcyber.com/docs`
  (install/register/autofill/recovery/plain-language threat model). *Decision:*
  sub-path vs subdomain.
- **G2 — Internationalization / localization** — i18n infra across all client
  surfaces + server error strings; translation tooling (Crowdin/Weblate);
  initial language set + RTL. **A dedicated milestone, not a polish pass.**
- **G3 — Accessibility audit** (WCAG 2.1 AA; Section 508 / EN 301 549).
  Engage an auditor; budget a remediation pass. Focus on M5 OOB-confirmation
  modals.
- **G4 — Mobile autofill** — tracked under E4.2/E4.4 (called out separately
  because it's engineering, not a checkbox).
- **G5 — SaaS operations** — status page (`status.hekate.synapticcyber.com`);
  customer support tooling scoped so support actions on signed objects are
  logged + owner-visible (never plaintext vault access).
- **G6 — Enterprise / legal** — SaaS ToS + privacy policy (distinct from the
  OSS self-host doc); SOC 2 Type II (Type I interim), ISO 27001, HIPAA BAA,
  GDPR DPA, PCI scope, FedRAMP only if federal sales are serious.

---

## D. Sequencing summary (recommended order)

1. **E1 client polish** (parallel, low-risk) + **E3 desktop tier-A** in
   parallel — these are the most user-visible near-term wins.
2. **M7 internal security pass** — the gate. Start M7.2/M7.3/M7.4 as soon as
   the shipped surface is stable; it blocks every public binary.
3. **D0 signing infra + D1 store publication** — once M7 clears, ship the
   extension stores (screenshots already un-gated) and the signed desktop app.
4. **M5** and **M6** as independent parallel tracks (clear #16 before M5;
   resolve the M6.0 schema decision before M6). Neither blocks distribution of
   what's already built.
5. **E4 mobile** — only after **E4.0 design doc**. This is the longest pole;
   start the design doc early even if implementation waits.
6. **G GA readiness** — i18n, a11y, SaaS ops, legal — sequenced toward the
   managed-SaaS launch.

> **One open meta-decision:** whether to mint these epics/stories as GitHub
> issues (mirroring the `S#.#` story pattern used in the sister `sessionzero`
> project) so work is tracked per the team's SDLC standard, or keep them
> doc-only. Recommended: mint M5/M6/E4/M7 as tracked issues under a Hekate
> project board, since those have no GitHub coverage today.
