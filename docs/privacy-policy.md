# Hekate — Privacy Policy

**Last updated:** 2026-05-31

This Privacy Policy explains how the **Hekate** password and secrets
manager handles your information. Hekate is published by **Synaptic
Cybersecurity Alliance, Inc.** ("we", "us"). It covers the Hekate browser
extension, web vault, desktop app, and command-line interface (the
"apps"), and the optional managed service at
`hekate.synapticcyber.com` (the "Managed Service").

## The short version

Hekate is **end-to-end encrypted and zero-knowledge**. Everything in your
vault — passwords, notes, cards, attachments, and other secrets — is
encrypted on your device with keys derived from your master password
**before** it is sent anywhere. **We cannot read your vault.** Your master
password never leaves your device and is never sent to any server. The apps
contain **no analytics, tracking, or telemetry**, and we do **not** sell
personal information.

## Self-hosted vs. the Managed Service

Hekate is self-host-first. **Who holds your encrypted data depends on which
server you connect to:**

- **Self-hosted.** If you (or your organization) run your own Hekate
  server, your encrypted vault and account data live on **your** server.
  We do not receive, process, or store any of it, and this policy's
  "Managed Service" sections do not apply to you — your server operator's
  practices govern.
- **Managed Service (`hekate.synapticcyber.com`).** If you connect to our
  hosted server, we store your **encrypted** vault and account data as
  described below — still without the ability to decrypt it.

## What the apps do on your device

The apps perform all encryption and decryption locally. On your device they
store, in local app/browser storage:

- Your **encrypted** vault data and a cached copy for offline-free use.
- A **session token** (to stay signed in) and local preferences.
- For the browser extension, trust "pins" and settings.

Your **master password** and the keys derived from it exist only in memory
while the app is unlocked and are **never persisted to disk and never
transmitted**. Locking or closing the app discards them.

The apps communicate **only** with the Hekate server you configure. They do
not contact any third-party analytics, advertising, or tracking service.

## What a Hekate server stores

Whether self-hosted or the Managed Service, a Hekate server stores:

- Your **encrypted** vault items, attachments, and shares (ciphertext only).
- Your account **email address** (your sign-in identifier).
- Cryptographic material that does **not** reveal your secrets: your public
  keys, signed integrity manifests, key-derivation parameters and salt, and
  **hashed** (not reversible) forms of your authentication credentials and
  tokens.
- Non-content **metadata** needed to sync: item revision timestamps, folder
  and collection identifiers, organization membership and roles, and share
  access counts / expiry.

A Hekate server **cannot** access: your master password, the keys derived
from it, or the decrypted contents of any vault item, attachment, or share.

## Information the Managed Service collects

If you use `hekate.synapticcyber.com`, in addition to the encrypted data
above we process:

- **Account email** — to create and identify your account and for essential
  service communication.
- **Encrypted vault data + sync metadata** — as described above, to provide
  the sync service. We cannot decrypt it.
- **Network/security data** — we process your **IP address** transiently to
  enforce **rate limiting and abuse prevention**, and it may appear in
  short-lived security/operational logs. We do not use it to build
  advertising or behavioral profiles.
- **Optional billing data** (if/when paid plans exist) — handled by a
  third-party payment processor; we do not store full card numbers.

We use this information only to operate, secure, and support the service,
and to comply with legal obligations. We do **not** sell it or use it for
advertising.

## How vault data is encrypted (plain-language)

Your master password is run through a strong key-derivation function on
your device to produce keys that encrypt a per-item key for every vault
item; those item keys encrypt each field. The server only ever receives the
already-encrypted results plus a proof-of-knowledge value that is itself
derived and then re-hashed server-side. This is why neither we nor a
server operator can read your vault, and why **if you lose your master
password, your data cannot be recovered** by us.

## Browser-extension permissions

The Hekate browser extension requests only the permissions it needs to
function as a password manager:

| Permission | Why it's needed |
|---|---|
| `storage` | Store your encrypted vault cache and settings locally. |
| `clipboardWrite` | Copy a password or one-time code to your clipboard (auto-cleared after a short timer). |
| `scripting` / `activeTab` | Fill credentials into the page you're on, only when you ask it to. |
| `alarms` | Run the clipboard auto-clear and sync timers. |
| `offscreen` | Keep the clipboard-clear and live-sync working after the popup closes. |
| `webAuthenticationProxy` | Let Hekate act as a passkey provider (Chromium browsers). |
| Access to websites (`http`/`https`) | A password manager must recognize the sites you have logins for, so it can offer to fill them. Page content is read **only** for matching and filling, on your action, and is never sent to us. |

## Sharing & third parties

We do not sell or rent personal information. Limited sharing occurs only:

- **Hosting/infrastructure** for the Managed Service (a cloud provider
  acting as our processor under contract), which stores the **encrypted**
  data on our behalf.
- **App stores** (Chrome Web Store, Microsoft Edge Add-ons, Mozilla AMO,
  Apple) when you install the apps, per their own policies.
- **Endpoints you configure** — e.g. if you set up an outbound webhook or
  connect to a specific server, data flows where you direct it.
- **Legal compliance** — if required by valid legal process; note that
  encrypted vault contents remain undecryptable to us regardless.

## Data retention & deletion

- **Self-hosted:** retention is controlled by your server operator.
- **Managed Service:** your encrypted data is retained while your account is
  active. You can delete individual items at any time, and **deleting your
  account removes your account and its encrypted vault data from our
  servers** (subject to routine backup-rotation windows and any legally
  required retention). Transient security logs are short-lived.

## Your rights

Depending on where you live (e.g. EEA/UK under GDPR, California under
CCPA/CPRA), you may have rights to access, correct, delete, or export your
personal data, and to object to or restrict certain processing. Because
your vault content is end-to-end encrypted, much of it is already directly
accessible and exportable from within the app. To exercise rights regarding
account data we hold for the Managed Service, contact us at
privacy@synapticcyber.com. We do not discriminate against you for exercising
these rights.

## Children

Hekate is not directed to children under 13 (or the equivalent age in your
jurisdiction), and we do not knowingly collect their personal information.

## Security

All vault content is end-to-end encrypted with vetted, modern cryptography;
decryption happens only on your devices. Transport to the server uses HTTPS.
No system is perfectly secure, but our design ensures that even a full
compromise of a Hekate server does not expose your decrypted vault.

## Changes

We may update this policy; we will revise the "Last updated" date and, for
material changes, provide a more prominent notice.

## Contact

Synaptic Cybersecurity Alliance, Inc. — privacy@synapticcyber.com.
