# Hekate desktop (Tauri)

A native desktop wrapper around the SolidJS web vault (`clients/web/`),
built with [Tauri 2](https://tauri.app). It renders the same SPA — and
the same `hekate-core` WASM crypto core — in a native window, talking to
whichever Hekate server the user configures on first run.

This is **tier A** of the desktop track (issue #8): a thin wrapper. It
ships a native menu bar and a menu-bar tray icon (hide-to-tray on window
close); Touch ID / Hello unlock, auto-update, an in-app SSH agent (tier C),
and the native credential provider (tier B) are follow-up milestones.

## Desktop tiers (the #8 roadmap)

The desktop track is scoped in three tiers of **increasing OS
integration**. They're separable scopes, not a strict priority order — A
is foundational; B and C are independent deeper integrations layered on
later. Status is tracked in [`../../docs/status.md`](../../docs/status.md)
(M3) and [`../../docs/followups.md`](../../docs/followups.md).

- **Tier A — the app itself (foundation + polish).** A proper native app
  with no deep privileged OS hooks.
  - *Foundation (shipped):* Tauri 2 shell wrapping the web vault + wasm
    core, empty IPC, locked CSP, configurable server (first-run screen),
    `make desktop`/`desktop-build`, code-signing + notarization plumbing.
  - *Polish:* ✅ system tray + native menu + hide-to-tray; ⬜ Touch ID /
    Hello unlock (design in [`../../docs/desktop-touch-id.md`](../../docs/desktop-touch-id.md),
    decision pending); ⬜ auto-update (needs a release channel); ⬜ in-app
    "change server" in Settings (first-run selection exists today).
- **Tier B — native credential provider (macOS first).** Register Hekate
  as a system credential / autofill provider so it can fill passwords and
  passkeys **OS-wide** (other apps, system sheets), not just in the Hekate
  window. Not started.
- **Tier C — in-app SSH agent.** Serve a local `SSH_AUTH_SOCK` (named pipe
  on Windows) from the desktop app so terminals, `git`, and `ssh` can use
  vault-stored SSH keys with per-use approval — the capability the CLI
  already ships (`crates/hekate-cli/src/commands/ssh_agent.rs`, Ed25519),
  served from the desktop app. Not started.

## Why Tauri

- Crypto stays in `hekate-core` (same code as the web + extension builds).
- Uses the OS-patched system WebView, not a bundled Chromium — no shipping
  CVEs with the app.
- IPC is allowlisted (currently empty — no custom commands exposed).
- CSP is locked to bundled assets for scripts/styles; `connect-src` allows
  the configured server over HTTPS (plus localhost for self-host dev).

## Layout

```
clients/desktop/
  src-tauri/
    Cargo.toml          # standalone workspace — NOT part of the root
                        #   workspace, so Docker server/CLI builds never
                        #   pull in Tauri's native deps
    tauri.conf.json     # frontendDist → ../../web/dist; CSP; bundle config
    build.rs
    src/main.rs         # Builder + native menu + tray + hide-to-tray
    capabilities/       # core window permissions only
    icon-src.svg        # macOS app-icon master (824px body in a 1024
                        #   canvas; transparent padding per Apple's grid).
                        #   Regenerate icons/ with `cargo tauri icon icon-src.svg`.
                        #   Distinct from the full-bleed web/extension icon.
    icons/              # generated from icon-src.svg
```

## Prerequisites (host toolchain)

The rest of Hekate builds in Docker, but a native macOS `.app` needs a
native toolchain:

- **Xcode Command Line Tools** — `xcode-select --install`
- **Rust** (rustup) — provides `cargo`
- **Tauri CLI** — `cargo install tauri-cli --version "^2.0" --locked`

macOS target: **Apple Silicon only** (`aarch64-apple-darwin`).

## Build & run

From the repo root:

```sh
make desktop          # build the web SPA, then `cargo tauri dev`
make desktop-build    # build the web SPA, then bundle a .app/.dmg
```

`make desktop` first runs `make web` (which builds the WASM core and the
SPA into `clients/web/dist`), then launches the Tauri dev shell pointed at
that dist.

## Code signing & notarization (Developer ID + direct `.dmg`)

`make desktop-release` produces a **signed + notarized** `.app`/`.dmg` for
direct download (Gatekeeper-clean; no App Store). Signing and notarization
are driven by environment variables Tauri reads at build time — **no
secrets live in the repo**. One-time setup on the signing Mac (needs your
Apple Developer account):

**1. Developer ID Application certificate** (signs the app)
- Keychain Access → *Certificate Assistant → Request a Certificate From a
  Certificate Authority* → "Saved to disk" → save the CSR.
- Apple Developer portal → Certificates → **+** → **Developer ID
  Application** → upload the CSR → download the `.cer` → double-click to
  install into the **login** keychain.
- Confirm + copy its exact name:
  ```sh
  security find-identity -v -p codesigning
  # → "Developer ID Application: Your Name (TEAMID)"
  ```

**2. App Store Connect API key** (authenticates notarization)
- App Store Connect → **Users and Access → Integrations → App Store Connect
  API** → generate a key (role **Developer** suffices for notarytool).
- Download `AuthKey_XXXXXXXXXX.p8` **once** (Apple won't let you re-download
  it); store it **outside the repo**, e.g. `~/.config/hekate/` (`chmod 600`).
  Note the **Issuer ID** (above the keys table) and the **Key ID** (the row).

**3. Export the env vars** (shell profile; never committed):
  ```sh
  export APPLE_SIGNING_IDENTITY="Developer ID Application: Your Name (TEAMID)"
  export APPLE_API_ISSUER="<issuer-uuid>"
  export APPLE_API_KEY="<key-id>"
  export APPLE_API_KEY_PATH="$HOME/.config/hekate/AuthKey_XXXXXXXXXX.p8"
  ```

**4. Build:**
  ```sh
  make desktop-release   # builds the SPA, then signs + notarizes + staples
  ```
  `make desktop-sign-check` runs first and fails fast if the cert or any of
  the env vars is missing.

**5. Verify** (output under `src-tauri/target/release/bundle/`):
  ```sh
  codesign --verify --deep --strict --verbose=2 <Hekate.app>
  spctl -a -vvv -t exec <Hekate.app>          # "accepted, source=Notarized Developer ID"
  xcrun stapler validate <Hekate_x.y.z.dmg>   # "The validate action worked!"
  ```

**Never commit** the `.p8` key, the CSR/`.cer`, or your keychain — only the
env-var *names* and this guide live in the repo. Public distribution is
still subject to the project's pre-publish security posture (`docs/`).

## Shipped (tier A)
- **System tray + native menu** — a menu-bar tray icon (Show / Hide / Quit;
  left-click re-shows the window) and a native menu bar (Hekate / Edit /
  View / Window) so the standard clipboard + undo accelerators reach the
  webview. Closing the window hides it to the tray instead of quitting;
  tray Quit / Cmd-Q exit. All driven from `src/main.rs` — the webview IPC
  surface stays empty.

## Not yet wired (follow-ups)
- **Touch ID unlock** — macOS `LocalAuthentication` wired into the vault
  lock flow (tier A); needs a signed build to test biometrics.
- **Auto-update** — strategy chosen (Tauri's built-in updater); plugin +
  signed-manifest endpoint to be wired once a release channel exists.
- **In-app "change server"** — first-run selection is implemented; a
  Settings affordance to switch servers later is a follow-up.
- SSH agent (tier C); native credential provider (tier B).
