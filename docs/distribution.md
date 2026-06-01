# Hekate — Distribution & Publishing Plan

> Per-channel plan + prerequisites for shipping Hekate to users. Tracking
> umbrella: **#36**. The browser-extension push is the near-term focus.
>
> ⚠️ **Pre-publish security gate.** Publishing any public binary (extension
> or app) is gated on the in-house security-analysis pass (see
> [`followups.md`](followups.md) "Pre-publish security gate"). **Prep**
> — accounts, listings, privacy disclosure, build pipelines — proceeds in
> parallel; only the final "submit to the public" step waits on the gate.

## Browser extensions (near-term)

The extension code is built and lint-clean; "publishing properly" is
accounts + listing assets + review.

### Build artifacts
| Target | Command | Output | Covers |
|---|---|---|---|
| Chromium MV3 | `make extension` then `make extension-zip` | `dist/hekate-chromium-extension.zip` | Chrome, Edge, Brave, Opera, Vivaldi |
| Firefox MV3 | `make extension-firefox-zip` | `dist/hekate-<version>.zip` (web-ext lint-clean) | Firefox (AMO) |

Current manifest version: `clients/extension/manifest.json` → bump per
release. The Firefox manifest (`manifest.firefox.json`) drops `offscreen`
and `webAuthenticationProxy` and declares `data_collection_permissions`
(Firefox 142+).

### Shared prerequisites (do once)
- **Privacy disclosure (#31) — BLOCKER.** The current policy
  (https://synapticcyber.com/policies/privacy) is a *generic corporate*
  policy; it doesn't describe the extension's data handling. Stores (CWS,
  AMO) require the policy to match actual behavior. Add a Hekate
  extension-specific disclosure: zero-knowledge (the vault is E2E-encrypted
  to the user's own server; the vendor can't read it), no telemetry, and
  what each permission is for. Use that URL in every listing.
- **Listing assets:** store icon (have a 128px; stores also want 440×280 /
  1280×800 promo + screenshots), short + detailed description, category
  (Productivity / Tools), support + homepage URL.
- **Permission justifications** (reviewers require a rationale per
  permission):

  | Permission | Justification |
  |---|---|
  | `storage` | local encrypted vault cache + settings |
  | `clipboardWrite` | copy password / TOTP (auto-cleared on a timer) |
  | `scripting` | inject autofill into the active tab on user action |
  | `activeTab` | read the current tab to match/fill on user action |
  | `alarms` | schedule clipboard auto-clear + sync timers |
  | `offscreen` | run clipboard-clear / SSE in an offscreen document so it survives popup close |
  | `webAuthenticationProxy` | act as a passkey/WebAuthn provider (Chromium only) |
  | `host_permissions` `http://*/*`, `https://*/*` | **broadest scrutiny point** — a password manager must match and fill credentials on any site the user has them for. Standard + accepted for the category; expect reviewer questions and answer with this rationale. |

### Channels
- **Chrome Web Store — #32.** Developer account ($5 one-time) → create item
  → upload `hekate-chromium-extension.zip` → complete the data-usage
  (privacy) form → submit → review (password managers get extra scrutiny).
- **Microsoft Edge Add-ons — #33.** Free Partner Center account → upload the
  *same* Chromium zip → submit. Separate review.
- **Firefox AMO — #34.** Free Mozilla account → upload
  `hekate-<version>.zip` (AMO signs it) → review. **Source submission** is
  likely required because the build uses wasm/tooling — extend
  `clients/extension/COMPILEandDEBUG.md` with exact build steps. Passkey
  provider intentionally absent on Firefox (#4).
- **Safari — #35 (later).** Different model: convert via Xcode
  (`safari-web-extension-converter`), wrap in a macOS/iOS app, sign +
  notarize, distribute via Mac App Store or direct. Defer until the macOS
  desktop signing/provisioning is settled.
- **Opera / Vivaldi / Brave.** Consume the Chrome Web Store listing — no
  extra work.

## Desktop apps

- **macOS.** `make desktop-release` → signed + notarized `.dmg`/`.app`
  (working). Direct download for now; Mac App Store is a later option.
  Touch ID is **parked** pending a Developer ID provisioning profile — see
  [`desktop-touch-id.md`](desktop-touch-id.md).
- **Windows (#8).** Same Tauri codebase (WebView2), but: needs a **Windows
  build environment** (a Windows box or a CI windows runner — not
  cross-compilable from macOS), a **Windows code-signing certificate** (EV
  ~$300–400/yr for instant SmartScreen trust; OV cheaper, earns reputation
  slowly), Windows bundle targets added to `tauri.conf.json` (MSI/NSIS),
  then Microsoft Store (MSIX) / winget / direct download. Windows Hello is
  the biometric-unlock equivalent (later).
- **Linux (#8).** AppImage / Flatpak / deb / rpm from the same wrapper.

## CLI (future)
`cargo install hekate-cli`, Homebrew formula, signed GitHub releases with
checksums + SLSA provenance.

## Status
See **#36** (umbrella) and the per-channel issues: privacy disclosure
**#31**, Chrome **#32**, Edge **#33**, Firefox AMO **#34**, Safari **#35**,
Windows/Linux desktop **#8**.
