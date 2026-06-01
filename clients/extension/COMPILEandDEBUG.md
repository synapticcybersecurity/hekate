Where it lives

  clients/extension/
  ├── manifest.json            ← MV3 manifest (the only required file Chrome reads first)
  ├── popup/
  │   ├── popup.html           ← shell that loads popup.js as an ES module
  │   ├── popup.css            ← styling (light/dark via prefers-color-scheme)
  │   └── popup.js             ← all the logic — login, list, copy, autofill
  ├── wasm/                    ← .gitignored; populated by `make extension`
  │   ├── hekate_core_bg.wasm    ← compiled crypto core
  │   ├── hekate_core.js         ← JS glue from wasm-bindgen
  │   ├── hekate_core.d.ts       ← TypeScript types (informational)
  │   └── hekate_core_bg.wasm.d.ts
  └── README.md                ← contributor quickref

  The Rust source for the WASM module lives in crates/hekate-core/src/wasm.rs — that's where deriveMasterKey, encStringEncryptXc20p, etc. are defined. The whole crypto surface comes from a single Rust file compiled
   to WebAssembly.

  What's compile-time vs runtime

  The extension itself has no JS compile step — no webpack, no esbuild, no TypeScript compiler, no npm. The only "compilation" is on the Rust side:

  1. Rust → WASM (in Docker): cargo build --release --target wasm32-unknown-unknown -p hekate-core produces target/wasm32-unknown-unknown/release/hekate_core.wasm
  2. wasm-bindgen post-process (in Docker): converts the raw .wasm into a JS-importable module with TS bindings
  3. Copy into the extension tree: make extension does steps 1+2 and copies into clients/extension/wasm/

  Steps 1+2 require:
  - Rust toolchain (we have it via the dev Docker image)
  - wasm32-unknown-unknown target (installed in dev image)
  - wasm-bindgen-cli 0.2.120 (installed in dev image)

  But none of that is needed once clients/extension/wasm/ is populated. The extension is just static files at that point — Chrome loads them directly.

  What you actually need to use it

  ┌───────────────────────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │         Tool          │                                                     Why                                                     │
  ├───────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Docker                │ Builds the WASM (no host Rust required)                                                                     │
  ├───────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ GNU make              │ make extension orchestrates the build                                                                       │
  ├───────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ A Chromium browser    │ Chrome / Chromium / Edge / Brave / Vivaldi / Arc — anything based on Chromium 88+. Firefox MV3 is untested. │
  ├───────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ A running hekate server │ The extension is a client — needs a server to log in to. make up brings one up at http://hekate.localhost.    │
  ├───────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ A registered account  │ Until we add a register UI to the popup, register via CLI: pmgr register --server ... --email ...           │
  └───────────────────────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  That's it. No Node.js, no npm, no bundler, no signing. The whole build pipeline is one make target.

  Build + load flow

  # 1. Build (one time, or whenever hekate-core/src/wasm.rs changes)
  make extension
  #    Output: clients/extension/wasm/{hekate_core_bg.wasm, hekate_core.js, ...}

  # 2. Make sure server is up
  make up
  curl http://hekate.localhost/health/ready

  # 3. Register an account (one time — popup register UI is M3.3)
  make cli
  docker run --rm -it \
    -v "$PWD":/workspace -v hekate_target:/workspace/target -w /workspace \
    -v "$HOME/.hekate-cli":/state \
    -e XDG_CONFIG_HOME=/state -e HOME=/state \
    hekate-dev:latest /workspace/target/release/hekate \
    register --server http://hekate.localhost --email you@example.com

  # 4. Load in Chrome
  #    chrome://extensions → Developer mode → Load unpacked → clients/extension/
  #    Pin the icon to the toolbar.

  # 5. Click the toolbar icon → log in with your master password

  What runs where at runtime

  ┌───────────────────────────────────────────┬────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                   Thing                   │                                               Where                                                │
  ├───────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ popup.html / popup.js / WASM              │ Inside the popup window (not a tab — the popup is its own ephemeral DOM, dies when you click away) │
  ├───────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ chrome.storage.session                    │ RAM only, scoped per-extension, cleared on browser close                                           │
  ├───────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ chrome.scripting.executeScript (autofill) │ Injected into the active tab's page context, runs once per Fill click                              │
  ├───────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Network calls                             │ Same-origin from the popup window to the configured server URL (http://hekate.localhost etc.)        │
  ├───────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ localStorage (server URL, email)          │ Per-extension, persists across browser restarts (non-secret)                                       │
  └───────────────────────────────────────────┴────────────────────────────────────────────────────────────────────────────────────────────────────┘

  There's no background service worker in M3.2 — every action is initiated from the popup. The popup is short-lived (lives only while open) which is by design: there's no always-on extension code to compromise.

  Total size shipped to the user

  Everything that goes into a real .zip for distribution:

  clients/extension/
  ├── manifest.json     ~600 B
  ├── popup/popup.html  ~200 B
  ├── popup/popup.css   ~3 KB
  ├── popup/popup.js    ~13 KB
  └── wasm/             ~232 KB total

  So ~250 KB delivered, of which 195 KB is the WASM blob.

  Where to look in the source

  If you're debugging or want to extend it:

  - What the extension exposes: manifest.json (permissions, popup, CSP)
  - Login + vault flow: clients/extension/popup/popup.js — top-to-bottom, single file
  - WASM API: crates/hekate-core/src/wasm.rs (Rust) → produces the JS surface in hekate_core.d.ts after make extension
  - API contract the popup talks to: docs/api.md and live at http://hekate.localhost/api/v1/openapi.json

  Useful for development:
  - Right-click the toolbar icon → Inspect popup opens DevTools attached to the popup
  - After editing popup.js, no rebuild needed — just click the reload icon on the extension card at chrome://extensions
  - After editing hekate-core/src/wasm.rs, run make extension to regenerate the WASM, then reload the extension card

---

## Building from source (for AMO / store reviewers)

Mozilla AMO requires reviewers to reproduce the uploaded add-on from
source. Hekate's extension is **plain static files plus one WebAssembly
module compiled from Rust** — there is no JS bundler, minifier, or
transpiler; the JS/HTML/CSS shipped are the source verbatim.

### Toolchain
- **Docker** — builds the Rust→WASM; no host Rust toolchain needed.
- **GNU make** — orchestrates the build.
- **Node.js 18+** — only used by `npx web-ext` to lint + package the
  Firefox build.
- Pinned build tools live in the dev Docker image
  (`docker/dev.dockerfile`): the Rust toolchain (rustc 1.89), the
  `wasm32-unknown-unknown` target, and `wasm-bindgen-cli` 0.2.120.

### Reproduce the uploaded artifacts (from the repo root)
```
# Firefox (what AMO receives) → dist/hekate-<version>.zip
make extension-firefox-zip

# Chromium (Chrome Web Store / Edge) → dist/hekate-chromium-extension.zip
make extension-zip
```
`make extension-firefox-zip` (1) compiles `hekate-core` to wasm32 in
Docker and runs `wasm-bindgen`, (2) copies the bindings into
`clients/extension/wasm/`, (3) stages the tree to `dist/extension-firefox/`
swapping in `manifest.firefox.json`, runs `web-ext lint`, and (4) emits the
uploadable zip.

### Source ↔ package mapping
- `popup/`, `background.js`, `offscreen.*`, `manifest(.firefox).json`,
  `icons/` — shipped **verbatim** from `clients/extension/`.
- `wasm/hekate_core_bg.wasm` + `hekate_core.js` — **compiled** from
  `crates/hekate-core/` (wasm entrypoint `src/wasm.rs`) via the steps above;
  never hand-edited.
- **No remote code**: nothing is fetched or `eval`'d at runtime; the CSP
  forbids it. All executable code (including the WASM) is in the package.
- The Firefox build drops the `offscreen` and `webAuthenticationProxy`
  permissions (event-page background instead).

### Verify
Re-running the command above on the submitted commit regenerates the same
static source tree and the WASM from the pinned toolchain. Source repo:
https://github.com/synapticcybersecurity/hekate (AGPL-3.0).
