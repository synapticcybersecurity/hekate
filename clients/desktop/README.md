# Hekate desktop (Tauri)

A native desktop wrapper around the SolidJS web vault (`clients/web/`),
built with [Tauri 2](https://tauri.app). It renders the same SPA — and
the same `hekate-core` WASM crypto core — in a native window, talking to
whichever Hekate server the user configures on first run.

This is **tier A** of the desktop track (issue #8): a thin wrapper. Touch
ID / Hello unlock, system tray, native menu, auto-update, an in-app SSH
agent (tier C), and the native credential provider (tier B) are follow-up
milestones.

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
    src/main.rs         # thin Builder::default().run(...)
    capabilities/       # core window permissions only
    icons/              # generated from clients/web/public/icons/icon-128.png
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

## Not yet wired (follow-ups)

- **Code signing + notarization** with the Apple Developer account — the
  account exists; the signing/notarization step in `make desktop-build` is
  a follow-up.
- **Auto-update** — strategy chosen (Tauri's built-in updater); plugin +
  signed-manifest endpoint to be wired once a release channel exists.
- **In-app "change server"** — first-run selection is implemented; a
  Settings affordance to switch servers later is a follow-up.
- Touch ID unlock, system tray, native menu (tier A polish); SSH agent
  (tier C); native credential provider (tier B).
