# Hekate — Browser Extension Store Listing Copy

> Ready-to-paste copy for the Chrome Web Store (#32), Microsoft Edge
> Add-ons (#33), and Firefox AMO (#34). Written to be accurate to what the
> extension actually does (store review compares the listing + data
> disclosures against real behavior). Privacy policy:
> https://synapticcyber.com/policies/hekate-privacy
>
> Screenshots are an operator task (see end). Bump the version per release.

## Common fields

- **Name:** Hekate
- **Category:** Productivity (Chrome/Edge) · "Privacy & Security" or
  "Bookmarks & Tabs"→ pick Privacy/Security on AMO if offered
- **Primary language:** English
- **Privacy policy URL:** https://synapticcyber.com/policies/hekate-privacy
- **Homepage / support URL:** https://github.com/synapticcybersecurity/hekate
  (swap for a product site if/when one exists)
- **Support email:** privacy@synapticcyber.com (or a dedicated support alias)

## Short description (≤132 chars — Chrome/Edge "summary")

> Open-source, end-to-end-encrypted password & secrets manager. Self-host
> your vault or use the managed service. Zero-knowledge.

(126 chars.)

## Summary (AMO, ≤250 chars)

> Hekate is a fast, open-source, end-to-end-encrypted password and secrets
> manager. Store logins, cards, notes, identities, SSH keys and TOTP codes;
> autofill on your sites; share encrypted Sends. Self-host your own server or
> use the managed service. Zero-knowledge — your vault is encrypted on your
> device.

## Detailed description

> **Hekate is an open-source, end-to-end-encrypted password and secrets
> manager.** Everything in your vault is encrypted on your device with keys
> derived from your master password *before* it’s ever sent anywhere — the
> server only ever stores ciphertext, and no one but you can read your data.
> Your master password never leaves your device.
>
> **Requires a Hekate server.** Hekate syncs your encrypted vault to a Hekate
> server — either one you self-host or the managed service at
> hekate.synapticcyber.com. On first use, you point the extension at your
> server.
>
> **What you can store and do:**
> • Logins, secure notes, cards, identities, SSH keys, and TOTP (2FA) codes
> • One-click autofill on the sites you have logins for
> • A built-in password / passphrase generator and live TOTP codes
> • Passkeys / WebAuthn (Chromium)
> • Encrypted “Sends” — share a secret via a link that the server can’t read
> • Organizations & collections for sharing with a team
> • Import from Bitwarden, 1Password, KeePass, and LastPass
>
> **Privacy by design:**
> • Zero-knowledge: the server (yours or ours) can’t decrypt your vault
> • No analytics, no tracking, no telemetry — the extension only talks to the
>   Hekate server you choose
> • Clipboard auto-clear after copying a password or code
> • Open source (AGPL-3.0): https://github.com/synapticcybersecurity/hekate
>
> Privacy policy: https://synapticcyber.com/policies/hekate-privacy

## Single purpose (Chrome Web Store requires this)

> Hekate is a password and secrets manager. Its single purpose is to let a
> user securely store their own credentials and secrets — end-to-end
> encrypted — and fill them into websites on request. All other features
> (generator, TOTP, passkeys, Sends, sharing, import) serve that purpose.

## Permission justifications (Chrome Web Store form)

| Permission | Justification to paste |
|---|---|
| `storage` | Stores the user’s encrypted vault cache and the extension’s settings locally. |
| `clipboardWrite` | Copies a selected password or one-time code to the clipboard (auto-cleared after a short timer). |
| `scripting` | Fills the user’s saved credentials into the page they’re on, only when they invoke autofill. |
| `activeTab` | Reads the active tab (its URL/forms) to match saved logins and fill them, on the user’s action. |
| `alarms` | Schedules the clipboard auto-clear and background sync timers. |
| `offscreen` | Runs clipboard-clear and live sync in an offscreen document so they keep working after the popup closes. |
| `webAuthenticationProxy` | Lets Hekate act as a passkey/WebAuthn provider in Chromium. |
| Host permissions (`http://*/*`, `https://*/*`) | A password manager must recognize and autofill on any site the user has a login for. Page content is accessed only for matching/filling on the user’s action and is never sent to the developer. |

**Remote code:** No. All code (including the WebAssembly crypto core) is
bundled in the package; nothing is fetched or `eval`’d at runtime (CSP
forbids it). Answer the CWS "remote code" question **No**.

## Data-usage / privacy-practices disclosures (Chrome Web Store)

The extension handles the **user’s own** vault data and transmits it
**encrypted** to the Hekate server the user configures, solely to provide
sync/storage. It does not collect data for the developer. When completing
the form:

- **Data handled** (the vault can contain any of these, so disclose them):
  *Authentication information* (passwords/credentials), and — because the
  vault is general-purpose — *financial info* (payment cards),
  *personal communications* (secure notes), and *website content*
  (attachments/notes). It is end-to-end encrypted and synced only to the
  user’s chosen server.
- **Certifications you can truthfully make:**
  - ✅ Not sold or transferred to third parties (outside approved use cases).
  - ✅ Not used or transferred for any purpose unrelated to the single
    purpose above.
  - ✅ Not used or transferred to determine creditworthiness / for lending.

> Note: answer the *live* form against current behavior — these are guidance,
> not a substitute for the operator’s attestation.

## Per-store notes

- **Chrome Web Store (#32):** upload `dist/hekate-chromium-extension.zip`
  (`make extension-zip`). Expect password-manager scrutiny on host
  permissions — the justification above is the answer.
- **Microsoft Edge Add-ons (#33):** same Chromium zip; reuse all copy above.
- **Firefox AMO (#34):** upload `dist/hekate-<version>.zip`
  (`make extension-firefox-zip`). Use the *Summary* (≤250) + *Detailed
  description*. AMO will likely request **source + build steps** (the build
  produces WebAssembly) — point them at the repo + `clients/extension/COMPILEandDEBUG.md`
  (extend it with exact `make extension`/`extension-firefox-zip` steps + the
  toolchain). The Firefox build omits `offscreen` and `webAuthenticationProxy`.

## Screenshots (operator task)

Capture 1280×800 (Chrome/Edge) / and AMO-sized images of: the unlocked
vault list, autofill on a login page, the generator, a TOTP code, and the
Sends screen. Avoid real credentials in the shots.
