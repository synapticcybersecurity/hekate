# Hekate — open follow-ups

Single durable list of work that's queued, deferred, or pending
verification. Not for milestone-level status (that's
[`status.md`](status.md)) and not for the shipped feature inventory
(that's [`features.md`](features.md)). Update this file as items move.

## Smoke debts (verify before stacking more on top)

## Queued work (with kickoff plans)

- **next: M5 v1 — Trust UX implementation.** Design + audit-facing
  threat model in [`m5-trust-ux.md`](m5-trust-ux.md); citation pass
  complete; session kickoff prompt at the bottom of the spec doc.
  Substantial code: per-owner-keypair co-owner sets, fingerprint
  bindings on rosters, rotation envelope flow, recovery-owner
  primitive (BIP39 + hex file in v1; hardware key deferred), the
  strong-mode policy bool, audit + alerting events. Multi-owner
  invariant enforced at org-create.

## Deferred to a future managed-service offering

These features are not on the OSS roadmap. They sit in a future
managed-service tier on top of the self-host-first OSS core; the
OSS protocol does not block self-host operators from building
their own equivalents through the standard org / policy / token
primitives.

- **SSO** (SAML 2.0, OIDC) with JIT provisioning.
- **Trusted Device Encryption** (master-password-less SSO).
- **SCIM 2.0** for IdP-driven user/group provisioning.
- **Directory Connector** (LDAP/AD/Entra/Okta/G-Workspace pull).
- **Advanced policies** beyond M4.6.
- **Provider Portal** (MSP cross-org management).
- **Emergency access** (grantor-to-grantee X25519 wrap with a
  configurable wait period).

## Deferred OSS sub-milestones

- **M5.x — Threshold recovery (FROST-Ed25519).** Design direction
  locked in [`m5-trust-ux.md`](m5-trust-ux.md); the v1 schema
  reserves the `threshold_share` owner_type and the
  `ThresholdShareSet` table. Deferred until M5 v1 ships and the
  OSS / SaaS GA push is well underway.

## Client parity gaps

- **§6.5-popup owner-side TOFU pin negative path — re-verify.**
  Attempted 2026-05-09 by deleting an unpinned member's entry from
  `chrome.storage.local` and clicking Remove on another member; the
  rotation went through both times instead of refusing. Source check
  at `popup.js:6106-6113` (`loadPins` → `pins.peer_pins[entry.userId]`,
  throws on missing) is correct, and the receiver-side counterpart
  (`orgWrite.ts:916-924`) was confirmed working in the §8b smoke.
  Most likely the DevTools snippet didn't actually persist the
  delete (e.g., write race or popup window held a stale ref). When
  next exercising a 3-member rotation, re-run the snippet, then
  `chrome.storage.local.get(...)` to confirm the entry is missing
  *before* clicking Remove. If the pin really is gone and Remove
  still proceeds, that's a real popup bug worth fixing.

## Trust UX (M5 — design locked, implementation queued)

- **M5 — Trust UX redesign.** Architecture and decisions locked
  2026-05-09; full design + audit-facing threat model in
  [`m5-trust-ux.md`](m5-trust-ux.md). Replaces per-peer TOFU
  pinning with fingerprint-bound rosters under a per-owner
  keypair co-owner-set. Adds rotation envelopes (Flow A),
  recovery-owner identity primitive, strong-mode opt-out, and
  audit + alerting throughout. Multi-owner required when an org
  has non-owner members. Pre-alpha → no migration; ship v2
  schema directly. Session kickoff prompt at the bottom of the
  spec doc.

  Citation pass completed 2026-05-10. Corrections folded back
  into the doc: Buterin essay URL migrated to vitalik.eth.limo,
  Crites/Komlo/Maller corrected from CRYPTO 2021 → CRYPTO 2023
  (Sparkle+ scheme), CGGMP21 confirmed CCS 2020 (not 2021), RFC
  4880 noted as obsoleted by RFC 9580 (2024). Added significant
  threat-model update: Crites & Stewart (CRYPTO 2025) showed
  FROST cannot be proven *fully* adaptively secure without
  modifications. Static security unaffected; Hekate's recovery
  use case operates under static-corruption assumptions, so the
  finding doesn't block M5.x but requires honest framing in the
  audit doc. Zcash Foundation `frost` crate at v3.0.0 (May 2026),
  partially audited by NCC.

## Passkey provider — residual follow-ups

The Chromium passkey-provider track is shipped + smoke-green
(webauthn.io round-trip verified; closed as #1). What's still open:

- **Firefox port** — tracked as #4. Blocked on Firefox shipping
  its `browser.webAuthn` extension API (WICG draft, currently
  flagged in Nightly). The Chrome-side code in
  `crates/hekate-core/src/passkey.rs` and the popup approval UI
  will be reused unchanged once the API is available; only
  `clients/extension/background.js` event wiring needs a Firefox
  variant. Separate AMO publication path.
- **Web vault parity** — informational UI only. A SPA can't be
  a passkey provider (same-origin policy + no equivalent
  privileged-context API for regular web pages), so the web
  vault scope here is showing the user their stored passkeys,
  rename/delete, last-used timestamps. Not actionable.
- **CLI enroll / list / sign** — gated on a libfido2 binding so
  the CLI can drive a USB / NFC authenticator. Not load-bearing
  for the browser-extension flow.

## Display hierarchy

- **People expect hierarchical organization for vault items.**
  Three distinct layers, each with its own decision point:
    1. **Vault item display** (personal folders + org collections)
       — flat in the data model; `Engineering/AWS/Prod`-style
       names rendered as a tree client-side is a pure UX feature.
       Can ship anytime as a polish item.
    2. **Org structure itself** — flat by design; nesting orgs
       would require inheritance of roster signing, sym key
       derivation chains, member-removal-with-rotation semantics
       across the tree. Likely a deliberate "no" rather than a
       "later."
    3. **Secrets-manager projects (M6)** — the schema decision
       between flat-projects-with-paths and hierarchical-projects-
       with-subtree-ACLs is part of M6 design. See
       [`m6-secrets-manager.md`](m6-secrets-manager.md).

## Canonical SaaS deployment (locked 2026-05-09)

**Vendor entity:** Synaptic Cybersecurity Alliance, Inc. (operating
brand: Synapticcyber). Primary domain `synapticcyber.com`.

**Hekate managed-SaaS domain:** `hekate.synapticcyber.com`.

**URL structure (locked):**

| Path | Purpose |
|---|---|
| `hekate.synapticcyber.com/web/*` | Web vault (owner mode) |
| `hekate.synapticcyber.com/send/*` | Send recipient mode (share links) |
| `hekate.synapticcyber.com/api/v1/*` | REST API (existing structure) |
| `hekate.synapticcyber.com/docs` | User-facing docs site |
| `status.hekate.synapticcyber.com` | Status page (CNAME to hosted provider) |

**Open:** marketing surface (bare root vs separate subdomain vs
separate domain) — TBD.

The dev / self-host default is still `hekate.localhost`. Self-host
customers configure their own domains via `HEKATE_WEBAUTHN_RP_ID`
and `HEKATE_WEBAUTHN_RP_ORIGIN`. Generic example domains in user
docs (e.g., `vault.example.com`) stay generic — those represent
self-host customers, not the SaaS.

## Distribution + publishing (pre-GA milestone)

Ship Hekate to where users actually install software. Items here
are not "polish" — they're table stakes for being usable as a
real product.

### Browser extensions

- [ ] **Chrome Web Store** publication (clients/extension/).
- [ ] **Microsoft Edge Add-ons** listing (separate store from
      Chrome Web Store; same Chromium extension passes review
      separately).
- [ ] **Mozilla AMO (Firefox)** — verify Manifest V3 compatibility,
      port WebExtension API differences, get AMO-signed.
- [ ] **Safari Extension** — likely the heaviest port; Safari uses
      a different extension model (App Extension wrapped in a
      macOS/iOS app bundle). May piggyback on the macOS standalone
      app once that exists.
- [ ] **Opera / Vivaldi / Brave** — all consume Chrome Web Store
      directly; covered by the Chrome Web Store listing. No extra
      work expected.

### Mobile apps

- [ ] **iOS app + App Store** publication. Includes
      ASCredentialProvider integration for system autofill,
      biometric unlock (FaceID / TouchID), local keychain
      integration, push notifications for sync events.
- [ ] **Android app + Google Play Store** publication. Includes
      Android Autofill Framework integration, biometric prompt,
      sync push.
- [ ] **F-Droid** publication (Android, open-source-only).
      Important for privacy-focused users who avoid Google Play.
      Requires reproducible builds + source publication meeting
      F-Droid standards.

### Desktop standalone apps

- [ ] **macOS app** — likely Tauri or similar wrapping the web
      vault SPA + local IPC to a daemon. Includes Mac App Store
      publication (sandboxed) and direct download (.dmg, less
      sandboxed).
- [ ] **Windows app** — Tauri / Electron / native; includes
      Microsoft Store publication and direct download (.msi /
      .exe installer).
- [ ] **Linux desktop app** — the same Tauri / web-vault wrapper;
      shipped via Flatpak (cross-distro), Snap (Ubuntu), and
      AppImage (portable).

### CLI distribution

- [ ] **Direct GitHub releases** — static binaries for
      Linux/macOS/Windows × x86_64/aarch64, signed checksums,
      SLSA provenance attestation. First-class channel for power
      users.
- [ ] **`cargo install hekate-cli`** — native to Hekate's stack;
      fast win.
- [ ] **Homebrew (macOS)** — formula in `homebrew-core` once
      `hekate-cli` has stable releases. Already on the M6.0–M6.1
      plan timeline (see `m6-secrets-manager.md` Q7).
- [ ] **Chocolatey (Windows)** — package in the community repo.
- [ ] **Linux package managers** (biggest gap given Hekate's
      target audience):
    - `apt` repository for Debian / Ubuntu (signed deb packages).
    - `dnf`/`yum` for Fedora / RHEL (signed rpm packages).
    - Arch AUR + eventually official repos.
    - Snap and Flatpak for distro-agnostic Linux desktop.

### Server distribution

- [ ] **Docker Hub + ghcr.io** images for `hekate-server`.
      Already partially in place (`make image`); needs publication
      automation.
- [ ] **Helm chart** for Kubernetes deployments.
- [ ] **Terraform module** for infrastructure-as-code self-host.
- [ ] **Pre-configured VM images** (AWS AMI, DigitalOcean
      Marketplace, Linode StackScript) for one-click self-host.

### Distribution infrastructure (must-haves, not channels)

These don't surface to end users but block all of the above:

- [ ] **Apple Developer account** ($99/year) — required for
      macOS notarization, iOS App Store, Mac App Store, Safari
      Extension. Includes ongoing key custody discipline.
- [ ] **Windows EV code-signing certificate** (~$300–400/year) —
      required for SmartScreen reputation; without it, every
      Windows install gets a "Windows protected your PC" warning.
- [ ] **Android signing keys** — Google Play App Signing handles
      custody after first upload, but the upload key still needs
      HSM-backed custody.
- [ ] **HSM-backed custody for all signing keys** (consistent with
      the M5 threat-model posture for high-value keys).
- [ ] **Auto-update mechanism** for non-store distributions —
      Sparkle (macOS) / WinSparkle (Windows) / self-hosted update
      server with signed manifests. Per-channel tracks
      (stable / beta / nightly).
- [ ] **Release pipeline automation** — CI/CD that builds +
      signs + publishes to every channel from a single tagged
      release. Without this, a release is N manual steps that
      drift between channels.
- [ ] **Reproducible builds + SLSA provenance attestation** —
      privacy/security users expect to verify the binary they
      downloaded was built from the source tag they audited.
      Particularly important for a password manager.

### Pre-GA blockers (not distribution, but adjacent and required)

- [ ] **External security audit** before any GA shipping. Strong
      recommendation given M5's FROST work — threshold
      cryptography is easy to implement subtly wrong; an
      independent crypto audit is worth the budget.
- [ ] **Bug bounty program** post-GA, hosted on
      HackerOne / Intigriti / similar.
- [ ] **Privacy policy + ToS** for the Synapticcyber
      managed-SaaS offering (and a different document for
      open-source self-hosted users).
- [ ] **App Store review preparation** — Apple and Google both
      have specific guidelines for password managers; first
      submission often gets rejected for cosmetic reasons. Budget
      weeks, not days.

## Product readiness for GA (beyond distribution)

### End-user product polish

- [ ] **User-facing docs site** — separate from developer docs.
      End-user help: how to install, how to register, how to use
      autofill, recovering from lost master password, threat
      model summary in plain language. Likely a static-site
      generator (Hugo / mdBook / Docusaurus). Hosting structure
      under `hekate.synapticcyber.com` (the canonical Hekate
      SaaS domain) — sub-path vs. subdomain (e.g.
      `hekate.synapticcyber.com/docs` vs.
      `docs.hekate.synapticcyber.com`) is an open
      decision; pick when the doc tooling lands. Should
      integrate with the web vault / extension / mobile apps
      via in-context links.

- [ ] **Internationalization / localization (i18n).** Most
      password managers ship in 20+ languages; expectation for
      consumer adoption is multi-language from launch. Scope:
      i18n infrastructure in all four client surfaces (web vault,
      browser extension, mobile apps, desktop apps), translation
      tooling (Crowdin / Weblate), initial language set
      (English + likely Spanish, French, German, Japanese,
      Brazilian Portuguese as a start), RTL support (Arabic,
      Hebrew). Server-side error messages also need localization
      since clients surface them. **Not a small effort** — plan
      a dedicated milestone, not a polish pass.

- [ ] **Accessibility audit (WCAG 2.1 AA target).** Required for
      government/enterprise sales (Section 508 in the US,
      EN 301 549 in EU). Scope: web vault, browser extension
      popup, mobile apps. Focus areas: keyboard navigation, screen
      reader support (ARIA labels), color contrast, focus
      management in modals + multi-step flows (especially the
      M5 OOB-confirmation prompts). Engage an accessibility
      auditor; budget a remediation pass after the audit.

- [ ] **Mobile autofill platform integration** — flagged
      separately from the mobile-app distribution line items
      because it's a major engineering effort, not a checkbox.
    - **iOS:** `ASCredentialProvider` extension for system-wide
      autofill; QuickType bar integration; Face ID / Touch ID
      gating; cross-device passkey support via iCloud Keychain
      bridge if we want to interop. Each is its own non-trivial
      surface.
    - **Android:** Android Autofill Framework integration;
      `BiometricPrompt`; per-site heuristics for autofill
      detection (notoriously imperfect on Android, requires
      tuning + a fallback "long-press to autofill" UX);
      Inline Suggestions API for the keyboard.
    - Both platforms have OS-version-specific quirks; testing
      matrix is large.

### SaaS operations

- [ ] **Status page** — public uptime + incident history for the
      Synapticcyber-managed SaaS. Standard tooling:
      Statuspage / Instatus / a self-hosted alternative
      (Cachet / Gatus). Linked from the marketing site, the web
      vault, and the in-app "trouble connecting?" path.
      Required for enterprise sales (uptime SLAs need
      observable evidence).

- [ ] **Customer support tooling** for the managed-SaaS
      offering. Minimum: a ticketing system (Zendesk / HelpScout
      / Plain), customer-side chat for in-app help, internal
      admin tools for support staff to **observe** customer-side
      issues without breaking E2E (e.g., view roster history /
      audit log entries the customer's owners would also see —
      *never* the encrypted vault contents). Carefully scoped so
      the support tool itself doesn't become an unauthorized
      access channel — every support action that touches a
      customer's signed objects is logged + visible to the
      customer's owners under the standard M5 audit primitives.

### Enterprise / legal

- [ ] **Compliance certifications** — required for enterprise
      sales beyond a certain size. Tiered approach:
    - **SOC 2 Type II** — table stakes for any B2B SaaS; ~12-18
      month process (Type I first as an interim deliverable).
    - **ISO 27001** — international counterpart; often pursued
      alongside SOC 2 for European customers.
    - **HIPAA Business Associate Agreement** (US healthcare
      market) — requires specific controls + audit log retention
      + customer-signed BAA.
    - **GDPR data processing addenda** — for any EU customer
      (already required by law; enterprise customers want
      explicit DPA contracts).
    - **PCI DSS scope considerations** — relevant only if
      Synapticcyber's billing infrastructure touches card
      data directly (most SaaS uses Stripe / similar to keep PCI
      scope minimal).
    - **FedRAMP** (US federal market) — multi-year, ~$500k+
      effort; pursue only if federal sales are a serious target.
      Typically post-GA, post-revenue-validation.
    - **EU AI Act compliance** — relevant if Hekate ever
      integrates AI features (nothing in the current roadmap,
      but flag in case future product directions add ML).

## Polish / smaller wins

- **Extension auto-rebuild on `make web` / `make wasm`.** Today
  `make extension` is a separate target users have to remember.
  Probably make `make wasm` a dependency or have `make up` rebuild
  popup assets when they're stale.

## Stale state to clean up periodically

- The dev DB accumulates orphan invites / partial test orgs / etc.
  When they cause confusion mid-smoke, drop and re-create the
  Postgres volume (`make down && docker volume rm hekate_pgdata`)
  or delete the SQLite file from the `hekate_data` volume.

- The CLI volume (`hekate_cli_state`) holds a single session at a
  time. When you switch CLI users, run `make pmgr ARGS="logout"`
  first or the new register/login fails with "local state already
  exists."

## Format conventions

When you finish an item, delete it. When you defer something
mid-implementation, add it here with a one-line "where to pick
up" hint and a code-pointer. Don't let this file grow past two
screens — if it does, audit for stale entries first.
