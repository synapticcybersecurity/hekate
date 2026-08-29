# Hekate — open follow-ups

Single durable list of work that's queued, deferred, or pending
verification. Not for milestone-level status (that's
[`status.md`](status.md)) and not for the shipped feature inventory
(that's [`features.md`](features.md)). Update this file as items move.

## ⛔ Pre-publish security gate (HARD)

**No public binary ships before this is satisfied.** The first public
binary will be the Apple notarized desktop `.app` (#8); the same gate
applies to every store/signed-release channel after it.

Required before signing/notarizing/publishing anything:
1. **Rust secure-coding standards in place** — general hygiene in the
   shared Rust stack template (`sdlc_template/project-claude-template-rust.md`);
   Hekate crypto/protocol specifics in [`secure-coding.md`](secure-coding.md).
   ✅ drafted 2026-05-30.
2. **Comprehensive security analysis complete + findings remediated** —
   tooling sweep (`/security-review`, `/code-review ultra`, `cargo deny`,
   `cargo audit`, clippy `-D warnings`), manual crypto-call-site review,
   panic/DoS triage of untrusted-input paths, threat-model of the shipped
   surface. See [`secure-coding.md`](secure-coding.md) "Security-analysis
   pass" and [`threat-model-gaps.md`](threat-model-gaps.md).
3. **External crypto/code audit** — the internal pass makes us
   audit-ready; for a password manager it does **not** substitute for an
   independent audit (`status.md` M7).

Do not treat the desktop signing slice (#8) as unblocked until 1–3 hold.

## Smoke debts (verify before stacking more on top)

## M7.2 tooling sweep — in progress (2026-07-21)

Status snapshot so a fresh session can resume from this file alone.
Story #172; epic #67.

**Gates** (run in the dev image against `main`):

| Gate | Result |
|---|---|
| `make fmt-check` | ✅ |
| `make clippy` (`--all-targets -D warnings`) | ✅ 0 warnings |
| `make deny` | ✅ |
| `make audit` | ❌ → ✅ via PR #234 |

`cargo audit` flagged RUSTSEC-2026-0185 (quinn-proto 0.11.14, 7.5 high).
Not reachable — `cargo tree -i quinn-proto --target all -e all` finds
nothing, i.e. a stale lockfile entry from reqwest's optional HTTP/3
path. Bumped to 0.11.15 anyway (PR #234) rather than leave a vulnerable
version in a committed lockfile.

> **Gotcha worth remembering:** `cargo deny` resolves the *feature
> graph*, `cargo audit` scans the *whole lockfile*. They legitimately
> disagree. A green `deny` is not a clean bill of health on its own —
> #172's acceptance requires both.
>
> This is why `RUSTSEC-2023-0071` is listed in **both** `deny.toml` and
> `.cargo/audit.toml`. The duplication looks redundant and is not:
> cargo-deny never matches it (MySQL off → `rsa` outside the graph, so
> it warns `advisory was not encountered`), while cargo-audit sees
> `rsa 0.9.10` sitting in `Cargo.lock` and needs the ignore. Verified
> 2026-08-29 that the entry stays unmatched under `cargo deny
> --all-features` too, so the warning is permanent and expected. Do not
> "clean up" either copy.

**RUSTSEC-2026-0258 — h2 unbounded empty DATA frames (PR #238,
2026-08-29).** `h2` 0.4.14 → 0.4.19, lockfile-only. Unlike the
quinn-proto case above, this one **was reachable**: `hyper` is built
with `["server", "http1", "http2"]`, `axum` with `"http2"`, and
`axum::serve` serves HTTP/2 — so the upgrade was the fix, not an ignore.

> **The failure mode worth remembering:** nothing in the tree changed.
> The advisory was published 2026-08-17, three weeks after `Cargo.lock`
> was last touched (#234) and after `main`'s last green run
> (2026-07-25). A repo sitting untouched went red because the *advisory
> database* moved. Every open branch failed the same check
> simultaneously, and the fix belonged on `main`, not on any of them.
> When a supply-chain gate goes red with no relevant diff, check the
> advisory's publication date before hunting for a cause in the branch.

> **Corollary — a base-branch fix does not un-red an open PR by
> itself.** `.github/workflows/ci.yml` triggers on `pull_request`, which
> fires on *head* changes; pushing to `main` does not re-trigger it, and
> `gh run rerun` replays the original recorded merge SHA. So #30 kept
> failing `cargo-deny` after #238 merged even though its own merge
> result was clean. Confirmed via `git merge-tree --write-tree` that the
> merged tree carries h2 0.4.19. **The stale check clears on the next
> push to the branch — it does not need a rebase**, and force-pushing
> to "fix" it would be rewriting history for a CI artifact.

**Open — RUSTSEC-2026-0221 (`event-listener` 5.4.1).** `!Send` tags can
cross thread boundaries via `StackSlot`. Classified **unsound** rather
than **vulnerability**, so neither `make deny` nor `make audit` fails on
it and CI stays quiet — it surfaces only as an allowed warning. Left
undecided deliberately rather than by default. *Pick up:* confirm
whether our use (transitively via `sqlx`/`flume`) can construct the
unsound case, then either bump past it or record an ignore with the
usual justification.

**#18 + #22 findings — 12 of 13 fully remediated.** Verified against the
code, not assumed. Fixed: E1, E3, E4, E5, E6, E7, E8, H1, M1, M2, M3, L1.
Remaining:

- **E2 (PARTIAL) — hash the tus upload token at rest.** Send *download*
  tokens were fixed (`sends.rs` `hash_download_token()`, SHA-256 + DST,
  `WHERE token_hash = $1`), but the attachment **upload** token is still
  stored and matched in plaintext with SQL `=` in
  `crates/hekate-server/src/routes/attachments.rs` (queries around lines
  356, 400, 531, 554, 575, 673, 848). *Pick up:* mirror the Send fix —
  hash at rest + constant-time compare. Needs a migration, so it's the
  larger of the two remaining.
- **H1 (DONE) — Send `/blob` download token** (PR for #22, 2026-07-24).
  All three sub-issues closed, server-side only, no schema change:
  1. *Memory-amplification* (fixed earlier) — `public_blob_download`
     streams via `read_range` in 64 KiB chunks.
  2. *Single-use token* — the token is now consumed atomically on entry
     with `DELETE FROM send_download_tokens ... RETURNING expires_at`
     (one statement, so concurrent requests can't both win; the loser
     matches 0 rows → 404). **Consume-on-start**, chosen over
     consume-on-success: race-free and simple, and a mid-stream failure
     is recoverable by re-calling `/access` for a fresh token (bounded by
     `max_access_count`). Verified `DELETE ... RETURNING` on both
     backends (SQLite 3.46 bundled ≥ the 3.35 floor; Postgres native).
  3. *Strict limiter* — `is_auth_path()` now matches the `/blob/` path,
     so anonymous downloads use the strict bucket; the unit test that
     asserted the opposite was flipped.
  Coverage: `file_send_blob_download_token_is_single_use`
  (succeeds once → 404 on reuse → fresh `/access` works) in
  `tests/sends.rs`; `rate_limit::tests::auth_path_classifier` updated.
  *Residual:* none for H1. (The token stays plaintext-in-transit in the
  URL path — inherent to an anonymous link-based download, already
  hashed at rest per E2.)
- **M2 (cosmetic)** — `web_app.rs::placeholder_router()` (the
  "SPA not built" fallback) doesn't carry the CSP/nosniff/frame-deny
  headers the real SPA gets. No secrets on that page; one-line fix if
  wanted.

**Still owed for #172's acceptance:** `/code-review ultra` over the
shipped surface — operator-triggered and billed, so it can't be run by
an agent. `/security-review` is best pointed at a diff (it reviews
pending branch changes), so run it per-PR rather than over all of `main`.

**Note:** issues #18 and #22 are still **open** on GitHub even though
most of their contents shipped; they read far more alarming than the
code warrants. Worth closing or annotating.

**In flight (as of 2026-08-29):** #30 desktop Touch ID is the only open
PR — needs security review + signed-build smoke. Merged since this line
was last written: #233 docs reconciliation, #234 quinn-proto bump, #235
E6 mandatory-AAD fix (all 2026-07-22), #237 H1 Send `/blob` token
(2026-07-25), #238 h2 advisory bump (2026-08-29).

## Queued work (with kickoff plans)

- **DONE (PR open): #41 — password generator (standalone + options +
  passphrase).** Consolidated password + passphrase generation into
  `hekate-core` (`crates/hekate-core/src/generate.rs` — CSPRNG via `OsRng`,
  options struct, bundled EFF long wordlist, unit tests), exposed via wasm
  (`generatePassword` / `generatePassphrase`); the CLI now calls core too and
  the two JS copies are deleted (mirrors the #49 TOTP move). Standalone surface
  shipped as a top-level **Generator tab** in both the web vault and the
  extension popup (mode toggle, length, per-class toggles, avoid-ambiguous;
  passphrase word-count / separator / capitalize); the inline password-field
  button calls the same core. Both clients browser-smoked. **This un-gates the
  Chrome/Edge/AMO store screenshots (#32/#33/#34)** — the last operator task for
  those listings. Out of scope (still): generator on #43's save/signup flow.
    - Follow-ups filed while shipping #41: **#52** — suppress Chrome's native
      "save password?" prompt via a `privacy.passwordSavingEnabled` toggle (the
      complementary "take over saving" is #43); **#53** — serve the wasm core
      `no-cache` so a stale crypto core isn't kept across deploys (PR #54;
      surfaced when a browser cached the pre-generator `hekate_core.js`).

- **queued: #43 — extension save/update-password capture.** Autofill today is
  popup-initiated and fill-only (`fillActiveTab`/`pageFill` in
  `clients/extension/popup/popup.js`); there is **no content script**, so the
  extension never offers to save a new login or update an existing one when a
  user enters credentials on a site. Needs a content script (both manifests)
  detecting credential submissions + a confirm-before-save/update prompt routed
  through the normal E2EE create/update path (no plaintext logged, host-scoped,
  top-frame-only per Audit C2). Relates to #6/#41/#42.

- **active: Desktop app (Tauri) — issue #8.** Foundation (tier A,
  Apple-Silicon macOS) shipped: `clients/desktop/` Tauri 2 shell wrapping
  the SPA, configurable API base (`apiUrl()` + first-run server screen),
  `make desktop` / `make desktop-build`, binary verified on
  aarch64-apple-darwin. Shipped since: run-on-device smoke; code signing +
  notarization (`make desktop-release`, bundle id
  `com.synapticcyber.hekate`); **system tray + native menu + hide-to-tray**
  (#8); desktop bug fixes (#26 — Copy-URL share base, in-app dialogs
  replacing the no-op `window.confirm/alert/prompt`, macOS-padded app
  icon); **in-app "change server"** in Settings (#227 / story E3.4 #144).

  **Signing works; notarization is blocked on an Apple agreement**
  (2026-07-21). The Developer ID Application cert for Synaptic
  Cybersecurity Alliance, Inc. (`PKKD5DLS7L`) is in the keychain and all
  four notarization env vars are set; a `make desktop-release` signed the
  `.app` cleanly. But the notarytool submit then failed **HTTP 403 "A
  required agreement is missing or has expired."** The Account Holder must
  re-accept the Apple Developer Program License Agreement at
  developer.apple.com/account (and check App Store Connect → Business)
  before Apple will notarize — an account-portal action, not a code/config
  change. `make desktop-sign-check` passing is **not** sufficient proof
  notarization will work: it only checks that creds *exist*, not that the
  agreement is in effect (that gap is what let this bite after a full
  build; `desktop-notary-check` now probes the live agreement — run it
  first). For local Touch ID smoke a signed-but-not-notarized build
  (`make desktop-build`) is enough — notarization only affects Gatekeeper
  trust on *other* machines. *Publishing* is still separately behind the
  pre-publish security gate above.

  **Next slices, in order:**
    1. **Touch ID unlock** (tier A) — **decisions locked; code complete on
       PR #30** (rebased onto main 2026-07-21, all five CI checks green).
       Design: [`desktop-touch-id.md`](desktop-touch-id.md). A random
       32-byte unlock key in a `.biometryCurrentSet` Keychain item wraps
       the master key; adds the app's first four custom IPC commands (both
       flagged in `secure-coding.md` §8 as review-required). **Where to
       pick up:** security review of the branch + a biometric smoke against
       a *signed* build (`make desktop-release` — biometrics don't work in
       an unsigned `cargo tauri dev` binary), then merge.
    2. **Auto-update** — Tauri built-in updater plugin + signed update
       manifest endpoint (needs a release channel first).
    3. **Windows / Linux bundles**, then **tier C** (SSH agent) / **tier
       B** (macOS credential provider) as later milestones.
  - **Resolved (Dock icon white tile):** the prior icns was a blue squircle
    composited onto an *opaque white* background (corners `255,255,255,255`),
    so the Dock showed a white tile. The new `icon-src.svg` regeneration
    produces transparent corners (`0,0,0,0`); confirmed against a bundled
    `make desktop-build` `.app` (after `killall Dock`). Note `cargo tauri
    dev` embeds the icon at *compile* time, so a dev run without a Rust
    recompile keeps showing the stale icon — judge icons from a bundle.

- **next (after desktop): M5 v1 — Trust UX implementation.** Design +
  audit-facing threat model in [`m5-trust-ux.md`](m5-trust-ux.md);
  citation pass
  complete; session kickoff prompt at the bottom of the spec doc.
  Substantial code: per-owner-keypair co-owner sets, fingerprint
  bindings on rosters, rotation envelope flow, recovery-owner
  primitive (BIP39 + hex file in v1; hardware key deferred), the
  strong-mode policy bool, audit + alerting events. Multi-owner
  invariant enforced at org-create.

- **Web vault import — D.2 / D.3 / D.4 (issue #5).** D.1
  (Bitwarden JSON) shipped 2026-05-16. Three slices left, each
  un-gates one of the currently CLI-only crates for the wasm32
  target and adds a parser export to `wasm.rs`:
    - **D.2 — LastPass CSV.** Un-gate `csv` crate, add
      `parseLastpassCsv`. UI gains CSV to the format selector;
      commit pipeline is unchanged.
    - **D.3 — 1Password 1PUX.** Un-gate `zip` crate (verify
      default features don't pull a non-WASM compression
      backend; likely needs `default-features = false` +
      explicit `deflate`). Add `parse1passwordZip`. UI accepts
      `.1pux`.
    - **D.4 — KeePass KDBX.** Un-gate `keepass` crate (highest
      dep risk — flag if it doesn't compile to wasm32). Add
      `parseKeepassKdbx`. UI gains a master-password prompt step
      before the dry-run preview.

  Parsing must stay client-side regardless of format — KDBX
  takes a separate master password that mustn't hit the server,
  and the other two are plaintext export blobs that would
  otherwise break the zero-knowledge posture. The SPA commit
  pipeline (`Import.tsx`) is already format-agnostic; each
  slice extends the upload-phase format radio + dispatches to
  the right WASM binding, then reuses the same folder/cipher
  loop and BW04 re-sign.

- **Extension popup shortcut for import (issue #5).** Once D.1
  is shipped, the extension's "Import" entry point becomes a
  popup button that opens `/web/import` in a new tab. No parser
  code in the extension itself — the SPA handles everything.

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
  has non-owner members. Alpha → no migration; ship v2
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

- **Firefox port** — the *vault / autofill / TOTP / sends / orgs*
  surface shipped under #6 (`make extension-firefox` →
  `dist/extension-firefox/`; `make extension-firefox-zip` →
  AMO-uploadable artifact). The *passkey-provider* piece stays
  tracked as **#4**, blocked on Firefox shipping its
  `browser.webAuthn` extension API (WICG draft, currently flagged
  in Nightly). The Chrome-side code in
  `crates/hekate-core/src/passkey.rs` and the popup approval UI
  will be reused unchanged once the API is available; only the
  `background.js` event wiring needs the Firefox variant.
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
- [ ] **Mozilla AMO (Firefox)** — submission of the
      `make extension-firefox-zip` artifact (#6 landed the build target
      and `web-ext lint`-clean manifest; this checkbox is the actual
      AMO upload + signing).
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

- [ ] **macOS app** — Tauri wrapper around the web vault SPA.
      Foundation (tier A) shipped under #8 (`clients/desktop/`,
      `make desktop-build` → .app/.dmg, Apple-Silicon). Signing +
      notarization are **configured** (2026-07-21) — `make desktop-release`
      signs, notarizes and staples. Still open: choosing Mac App Store
      publication (sandboxed) vs direct .dmg download, and auto-update.
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

- [x] **Apple Developer account** ($99/year) — acquired 2026-05-30.
      Required for macOS notarization, iOS App Store, Mac App Store,
      Safari Extension. **Signing wired in as of 2026-07-21**: Developer ID
      Application cert (`PKKD5DLS7L`) in the keychain + App Store Connect
      API key and the four `APPLE_*` env vars set; `make desktop-release`
      signs the `.app` cleanly. **Notarization is blocked** on an
      Account-Holder Program License Agreement that Apple reports as
      missing/expired (notarytool 403 on 2026-07-21) — re-accept at
      developer.apple.com/account + App Store Connect → Business, then
      re-run `make desktop-notary-check` to confirm before rebuilding.
      Ongoing key-custody discipline still applies (HSM-backed custody is
      still open, below).
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
  time. When you switch CLI users, run `make hekate ARGS="logout"`
  first or the new register/login fails with "local state already
  exists."

## Format conventions

When you finish an item, delete it. When you defer something
mid-implementation, add it here with a one-line "where to pick
up" hint and a code-pointer. Don't let this file grow past two
screens — if it does, audit for stale entries first.
