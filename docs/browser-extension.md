# Hekate — Browser extension

A Chromium-family Manifest V3 extension. Drives the same protocol as
the server, the CLI, and the web vault (`clients/web/`); uses the
`hekate-core` WebAssembly module for all crypto so JavaScript code is
never trusted with plaintext keys.

> Brand: **Hekate**. Code-level identifiers (`hekate-core`, `hekate-server`,
> `hekate-cli`, the `hekate` binary, `HEKATE_*` env vars) all use `hekate`.
> Protocol-frozen identifiers (every `b"pmgr-…"` AAD string, `pmgr_sat_*` /
> `pmgr_pat_*` token prefixes, `PMGRA1` magic) keep the original `pmgr-…`
> prefix because they're baked into ciphertexts.
>
> **Status (current):** full vault CRUD across all cipher types,
> sends (text + file), attachments inside ciphers, organizations
> (full read + write incl. create / invite / accept / collections /
> policies / member removal + key rotation), `account rotate-keys`,
> autofill, 2FA management (TOTP + WebAuthn + recovery codes),
> strict-manifest toggle, passkey provider (`webAuthenticationProxy`),
> settings.
>
> The popup and the web vault (`clients/web/`) are peer first-party
> clients now. They share the same `hekate-core`
> WASM crypto + EncString v3 / BW04 / BW07 / BW08 / signcryption /
> PMGRA1 wire formats. Use whichever fits your workflow; vaults
> created in either round-trip cleanly through the other.

---

## Prerequisites

1. **A running hekate server.** See the top-level [`README.md`](../README.md):
   ```bash
   make up                       # Postgres + server, default
   curl http://hekate.localhost/health/ready
   ```
2. **A registered account.** The popup can log in but does not yet
   register. Until that lands in the popup, register via the CLI:
   ```bash
   make cli
   docker run --rm -it \
     -v "$PWD":/workspace -v hekate_target:/workspace/target -w /workspace \
     -v "$HOME/.hekate-cli":/state \
     -e XDG_CONFIG_HOME=/state -e HOME=/state \
     hekate-dev:latest /workspace/target/release/hekate \
       register --server http://host.docker.internal:8088 \
       --email you@example.com
   ```

   > **Why `host.docker.internal:8088` and not `hekate.localhost`?** From
   > the host, `hekate.localhost` resolves via Traefik. From *inside a
   > container* it doesn't — containers have their own DNS namespace.
   > `host.docker.internal:8088` reaches the same server via the port
   > `docker-compose.yml` exposes directly. The browser extension
   > runs on the host, so it can still use `http://hekate.localhost`.

   (Or any other `hekate` invocation: see [`api.md`](api.md).)
3. **A browser**: any Chromium-family browser (Chrome, Chromium,
   Edge, Brave, Vivaldi, Arc, Opera, etc.) or **Firefox 142+** — see
   the *Firefox* section below for the build target and the small
   feature delta (no passkey provider on Firefox; tracked as #4).

## Build

From the workspace root:

```bash
make extension
```

What this does:

1. Builds `hekate-core` for `wasm32-unknown-unknown` inside the dev
   Docker image.
2. Runs `wasm-bindgen --target web` against the resulting `.wasm` to
   emit JS glue + TypeScript types.
3. Copies the artefacts into `clients/extension/wasm/` (which is
   gitignored — the source of truth is `crates/hekate-core/src/wasm.rs`).

Output:
```
clients/extension/wasm/
├── hekate_core_bg.wasm        ~195 KB
├── hekate_core.js             ~30 KB JS glue
├── hekate_core.d.ts           TypeScript bindings
└── hekate_core_bg.wasm.d.ts   wasm-side bindings
```

Re-run `make extension` whenever the `hekate-core` Rust source changes.

## Loading the extension

### Chrome / Chromium / Edge / Brave

1. Open `chrome://extensions` (or `edge://extensions`,
   `brave://extensions`).
2. Toggle **Developer mode** on (top right).
3. Click **Load unpacked**.
4. Pick the `clients/extension/` directory — *not* the `wasm/`
   subdirectory or the workspace root.
5. The extension appears with name "Hekate" and version "0.0.6". Pin it
   to the toolbar (puzzle-piece icon → pin) for one-click access.

If you change the source, click the circular reload icon on the
extension card after rebuilding.

### Firefox

Firefox uses a separate manifest variant
(`clients/extension/manifest.firefox.json`) plus an event-page
background (Firefox MV3 service workers can't reach
`navigator.clipboard`, so the clipboard-clear path needs a different
host). The Makefile stages a build for you:

```bash
make extension-firefox       # → dist/extension-firefox/ (load unpacked)
make extension-firefox-zip   # → dist/hekate-<version>.zip (AMO upload)
```

What this does:
1. Runs `make extension` (so `wasm/` is up to date).
2. Stages the extension tree to `dist/extension-firefox/`, swaps the
   manifest for the Gecko variant (gecko id, `strict_min_version:
   "142.0"` — that floor is set by AMO's `data_collection_permissions`
   requirement, not by feature use — event-page background, no
   `offscreen` / `webAuthenticationProxy` permissions), and drops
   `offscreen.html`/`offscreen.js` (Chrome-only dead weight).
3. Runs `npx web-ext lint` against the staged build so anything AMO
   will reject surfaces locally. Requires Node 18+ on the host.

To load unpacked:
1. `about:debugging#/runtime/this-firefox` → **Load Temporary
   Add-on** → pick `dist/extension-firefox/manifest.json`.
2. Extensions loaded this way are unloaded when Firefox restarts.

**Feature delta vs Chromium:** the *passkey provider*
(`chrome.webAuthenticationProxy`) is intentionally absent on Firefox
— it's blocked on Firefox shipping `browser.webAuthn` and is tracked
separately as **#4**. Every other surface — vault, autofill, copy +
auto-clear, TOTP, Sends, Orgs, 2FA management, `account rotate-keys`
— ships unchanged.

## First-time use

1. Click the Hekate toolbar icon. The popup shows a login form:
   ```
   Server:           http://hekate.localhost
   Email:            you@example.com
   Master password:  ••••••••
   ```
2. Click **Unlock**. The popup:
   - calls `/api/v1/accounts/prelogin` for the KDF parameters,
   - derives the master key in WASM (Argon2id, ~150 ms-1 s
     depending on hardware),
   - exchanges for tokens at `/identity/connect/token`,
   - decrypts the account-key wrap,
   - stores everything in `chrome.storage.session`.
3. The vault screen lists every non-trashed cipher, sorted by name,
   with the username (or URI / type label) below each.
4. The non-secret bits (server URL, email) are remembered in
   `localStorage` so subsequent unlocks only require the master
   password.

## Day-to-day use

| Action | What happens |
|---|---|
| **Click toolbar icon** | Popup opens. If session is still alive, vault is shown immediately. Otherwise, login form. |
| **+ Add** (toolbar) | Type picker → form for the chosen type (Login, Note, Card, Identity, SSH key, TOTP). 👁 reveals secret fields, ⚄ generates a 20-char password on the Login form. |
| **Edit** (any row) | Same form populated with current values; saves with `If-Match: "<revision>"` so concurrent edits surface as a conflict instead of overwriting. Works on every type. |
| **Fill** (login row only) | Injects username + password into the most likely fields on the active tab. Popup closes so you can hit Enter to submit. |
| **Copy** (login row) | Password copied; the popup wipes the clipboard after the configured auto-clear interval (default 30s, set via the ⚙ Settings pane; `0` disables). |
| **Copy code** (TOTP row) | Live 6-digit code copied; auto-clears on the same timer. The row also shows a live countdown to the next 30-second window. |
| **⚙ Settings** | Configure clipboard auto-clear seconds. The timer runs in the extension's background service worker via `chrome.alarms` + an offscreen document, so it fires even after the popup closes. Chromium clamps the alarm minimum to ~30 seconds. |
| (automatic) | The service worker stays subscribed to `/push/v1/stream` while the user is logged in. When another device edits a cipher, the SW broadcasts to any open popup (debounced 250 ms) and stamps `vault_dirty_at` in `chrome.storage.session` for popups that aren't open yet. SW-level lifetime: as long as the SSE stream is active the SW stays alive; on disconnect it reconnects with backoff up to 30 s. Hard MV3 limit: if Chrome forcibly evicts the SW it picks up again on the next popup open / chrome.runtime startup event. |
| **Matches for `<host>`** | When the popup is opened on a real page (not `chrome://` etc.) it shows ciphers that match the tab. Login matches use the URI host with sub-domain support; **TOTP matches** use a heuristic over the issuer / accountName fields against the host's second-level label (e.g. a TOTP entry with issuer `GitHub` matches both `github.com` and `gist.github.com`). Both surface their per-row actions — Fill/Copy for logins, Copy code for TOTPs (with the live ticker). |
| **Copy #** (card row) | Card number copied. |
| **Copy pub** (SSH row) | Public key copied. |
| **Copy ✉** (identity row) | Email copied. |
| **Trash** (any row) | Soft-delete (moves to the Trash view). |
| **Trash** (toolbar) | Switch to the trashed-items view; per-row **Restore** or **Delete forever**. |
| **Lock** | Wipes `chrome.storage.session`. Next popup open requires the master password. |
| **Close the browser** | `chrome.storage.session` is cleared automatically. Next browser launch requires the master password. |
| **📤 Sends** (toolbar) | M3.11 + M3.13 — opens the Sends panel: list owned text + file Sends with access counts + expiry, "+ New text Send" / "+ New file Send" creates one with optional password / max-access / TTL and prints the share URL, "Open shared link" pastes a URL and walks the public access flow client-side (text → stdout-equivalent display; file → browser save dialog). The send_key lives only in the URL fragment; the server can revoke but cannot decrypt. |
| **Attachments** (cipher edit view) | M3.12 — every personal cipher's edit view grows an "Attachments" section. + Add file picks a file, encrypts it with PMGRA1 chunked-AEAD, BLAKE3-hashes the ciphertext, and tus-uploads single-shot. Download fetches the ciphertext, BLAKE3-verifies, decrypts, triggers a browser save. Delete removes the row + queues blob cleanup. The BW04 manifest is auto re-signed after every write so the per-cipher `attachments_root` binding stays current. |
| **🏢 Orgs** (toolbar) | M3.14 + M3.14a–d — list orgs you belong to with role, member count, roster version, active-policy count, pending org-key rotation flag if any. Full owner-side writes: create org, invite peer, cancel pending invite, accept invite, collection CRUD + member permissions, member removal + receiver-side rotate-confirm, policies UI (M4.6 — master_password_complexity, vault_timeout, password_generator, single_org, restrict_send), prune-roster recovery. All writes go through signcryption-envelope WASM (`signcryptSealEnvelope` / `signcryptOpenEnvelope` / `signOrgRoster` / `verifyOrgRoster`). |
| **Rotate keys…** (Settings) | M3.15 — generates a fresh symmetric `account_key` and re-wraps every personal-cipher PCK + Send key + org-membership key + the X25519 private key under it. Master password (and therefore the BW04 manifest signing key) stays the same; pinned peers + the manifest are unaffected. Other devices need to re-login afterwards. 2FA-enabled accounts must use `hekate account rotate-keys` on the CLI for now (popup's 2FA challenge dispatcher isn't wired into this flow yet). |

The popup transparently refreshes the access token on 401 using the
saved refresh token, so a 1-hour-long browsing session doesn't kick
you back to the master-password screen mid-task.

### Autofill (M3.2)

When you open the popup on a page like `https://github.com/login`,
the popup queries the active tab and shows a highlighted section at
the top:

```
Matches for github.com
   GitHub        alice          [Fill] [Copy]
```

Click **Fill** to inject username and password into the most likely
form on that page. The injection runs in the page's own context via
`chrome.scripting.executeScript({allFrames: true, ...})` so iframed
login dialogs (e.g. some SSO flows) still get filled.

#### How matching works

A cipher matches the active tab when the URI on the cipher and the
tab host are equal, or when the tab is a sub-domain of the cipher
host. Examples:

| Cipher URI | Tab host | Match? |
|---|---|---|
| `https://github.com/` | `github.com` | ✓ |
| `https://github.com/` | `gist.github.com` | ✓ |
| `https://github.com/` | `evilgithub.com` | ✗ |
| `https://github.com/login` | `github.com` | ✓ |

#### How field detection works

Heuristic, kept intentionally simple in M3.2:

1. Find the first visible, non-disabled `input[type=password]`.
2. Username is the latest visible
   `input[type=email|text|tel|<unset>]` that appears before the
   password input in the same `<form>` (or anywhere if there is no
   form).
3. After setting `.value` via the prototype-level setter (so React /
   Vue / Angular controlled inputs see the change), dispatch
   `input` and `change` events.

This handles ~95% of real login forms. Pages with multi-step flows
(enter username → click "next" → enter password) require two clicks
of **Fill** today — once on each screen. Smarter form-detection is a
follow-up iteration.

#### Why popup-driven instead of inline overlay?

Popup-driven autofill is intentional for M3.2: zero always-on
content scripts, no in-page UI, no DOM injection until the user
explicitly asks. That trade-off is "user clicks toolbar icon for
each fill" instead of "browser detects every form" — slower per
form, much smaller attack surface and zero performance impact when
not in use. Inline content-script autofill (with a Shadow-DOM
overlay near each detected form) lands in M3.3.

## Session model

The extension is designed so plaintext key material lives in memory
only:

- **Master password** — never written anywhere. Lives only in the
  password-input element until the form is submitted.
- **Master key** (Argon2id output) — lives in a `Uint8Array` only
  during the WASM call; not persisted.
- **Account key** (32 bytes used to unwrap per-cipher keys) — held
  base64-encoded in `chrome.storage.session`. RAM-only; cleared on
  browser close.
- **Access token / refresh token** — held in `chrome.storage.session`.
  RAM-only.
- **Per-cipher keys** — derived on demand from the account key when
  rendering each row; never stored.
- **Server URL + email** — held in `localStorage` (non-secret) so the
  user doesn't retype them.

Nothing on disk that an attacker can read after a steal.

## Permissions explained

The manifest declares:

| Permission | Why |
|---|---|
| `storage` | `chrome.storage.session` + `chrome.storage.local` for pinned-peer / pinned-org keys and TOFU state. |
| `clipboardWrite` | Copy-password buttons. |
| `host_permissions: ["http://*/*", "https://*/*"]` | Cross-origin `fetch` to whatever hekate server URL the user enters. Will be tightened to a configured origin once that UX exists. |
| `scripting` | Inject the `pageFill` function into the active tab on a click of **Fill**. |
| `activeTab` | Query the active tab's URL so the popup can host-match ciphers without needing always-on tab listeners. |
| `alarms` | Drives the clipboard auto-clear timer in the service worker so it fires after the popup closes. Chromium clamps the alarm minimum to ~30 s. |
| `offscreen` *(Chromium only)* | Hosts an offscreen document that owns the clipboard between fires so the auto-clear still works when no popup is open. Firefox uses an event-page background that has direct clipboard access and doesn't need this. |
| `webAuthenticationProxy` *(Chromium only)* | Implements the passkey provider that intercepts `navigator.credentials.create` / `.get` and routes ceremonies through the vault. Requires Chrome 115+. Firefox port tracked as #4, blocked on `browser.webAuthn`. |

The CSP is `script-src 'self' 'wasm-unsafe-eval'`. The `wasm-unsafe-eval`
clause is required by Chromium to compile WebAssembly inside an MV3
extension page. No other JS sources are allowed.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Popup says "Loading…" forever | `make extension` wasn't run (`wasm/` missing). Rebuild and reload the extension. |
| `Failed to fetch` on Unlock | Server isn't running, or the URL is wrong. Try `curl http://hekate.localhost/health/ready`. |
| `invalid credentials` on Unlock | Email or master password is wrong. Verify with `hekate login` from the CLI. |
| `Session expired; please log in again.` on the vault screen | Both the access token (1 h) and refresh token (30 d) are exhausted, or the server's `security_stamp` rotated (e.g. master password changed elsewhere). Re-enter master password. |
| `Conflict: this item changed on the server` on Save | Another client edited the same cipher; close the form, hit **Lock** then **Unlock** to refresh, and re-apply your edit. |
| Browser console shows `wasm-bindgen` errors after a rebuild | Stale `wasm/` directory. Re-run `make extension`, then reload the extension at `chrome://extensions`. |
| Permission denied opening clipboard | First click on **Copy** asks the user to allow clipboard write; allow it. |
| Registering from the CLI fails with `dns error: failed to lookup address information` | Docker container can't resolve `hekate.localhost`. Use `--server http://host.docker.internal:8088` instead (or pass `--add-host=hekate.localhost:host-gateway` to `docker run`). The browser extension itself runs on the host and continues to use `http://hekate.localhost` normally. |
| Popup shows `No matches for extensions` (or another internal page) | You're on a `chrome://`, `about:`, or `chrome-extension://` page. The popup now suppresses the matches block on these — pull `make extension` again if you don't see the fix. |

To open the popup's devtools: right-click the toolbar icon → **Inspect
popup**.

## Cipher types

The popup uses the same wire shape as the CLI for every type — JSON
keys, AAD strings, EncString algorithm, all identical. A cipher
created by `hekate add card …` round-trips through the popup's edit
form with no field mapping; a TOTP cipher created in the popup is
shown by `hekate show <id>` exactly the same.

| Type | Fields exposed in the popup form |
|---|---|
| **Login** | name, username, password, URI, notes |
| **Secure note** | name, notes (notes is required) |
| **Card** | name, cardholder, brand, number, exp month/year, CVV, notes |
| **Identity** | name, title, first/middle/last, company, email, phone, address1+2, city/state/postal/country, SSN, passport, license, notes |
| **SSH key** | name, public key, private key, fingerprint, notes |
| **TOTP** | name, secret (`otpauth://` URL or BASE32), issuer, account, notes |
| **API key** | imported from other vaults; popup renders read-only (no add-form entry). |

TOTP rows live-update their 6-digit code with a 30-second countdown.
Both `otpauth://` URLs and bare base32 secrets are accepted; the
`algorithm` (SHA-1, SHA-256, SHA-512), `digits`, and `period`
parameters from an `otpauth://` URL are honoured.

## What's coming next

See `docs/followups.md` for the durable popup-side work queue.
Recurring items:

- **Masked re-auth modal** — replace the current `window.prompt()`
  used for MFA setup re-confirmation; Chrome can't mask `prompt()`
  inputs natively. Custom HTML modal with `<input type="password">`.
- **TOTP enrollment QR code** — currently shows the raw `otpauth://`
  URI text; most authenticators expect a scan.
- **Invite peer accepts email OR UUID** — currently UUID-only,
  unfriendly. Needs a small server endpoint for email→pubkey-bundle
  lookup with prelogin-style enumeration guards.

Longer-term:

- **Inline content-script autofill** with a Shadow-DOM overlay near
  each detected form (M3.5+ — the sophisticated version of M3.2's
  popup-driven fill).
- **Background SSE listener for real-time refresh** — service worker
  already subscribes; tighten the popup→SW handoff so opened popups
  refresh on push events without a manual reload.
- **Firefox compat** — shipped under #6 (`make extension-firefox` →
  unpacked, `make extension-firefox-zip` → AMO artifact; sans
  passkey provider, which is #4). Safari is its own packaging story.

## Source layout

```
clients/extension/
├── manifest.json                  MV3 declaration
├── background.js                  service worker — SSE subscription,
│                                   passkey-provider ceremonies,
│                                   clipboard-clear alarm dispatch
├── offscreen.html                 offscreen document host
├── offscreen.js                   clipboard-clear logic that survives
│                                   popup closure
├── popup/
│   ├── popup.html                 shell that loads popup.js as an ES module
│   ├── popup.css                  minimal light/dark UI
│   └── popup.js                   complete login + vault flow (calls WASM)
├── wasm/                          generated by `make extension` (gitignored)
└── README.md                      short load-unpacked walkthrough
```

`popup.js` carries the vault flow; `background.js` owns the
service-worker-level concerns (SSE, passkey ceremonies, alarm
dispatch). Both load the same `hekate-core` WASM module.
