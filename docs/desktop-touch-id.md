# Desktop Touch ID unlock — design (DECISION PENDING)

> **Status:** proposed, **not implemented**. This document exists so the
> security tradeoff can be weighed before any key-handling code is
> written. Touch ID unlock changes the desktop client's at-rest posture
> and adds the first custom Tauri IPC command — per
> [`secure-coding.md`](secure-coding.md) §8 both are "security changes
> requiring review." Nothing ships until the open decisions below are
> settled. Tracked under the desktop track (issue #8).

## What it is

Let a desktop user unlock their vault with Touch ID instead of retyping
the master password, while keeping decryption fully client-side.

## Why it needs a decision

Today the client's root secrets live in **volatile JS memory only**. The
`accountKey`, `signingSeed`, and `masterKey` are never persisted; a page
reload (or app restart) always discards them and forces master-password
re-derivation via the Resume screen (`clients/web/src/lib/session.ts`,
`Resume.tsx`). That is the strongest possible at-rest posture: an attacker
with the powered-off / locked machine gets nothing.

Biometric unlock is fundamentally incompatible with "never persist a root
secret," because biometrics cannot *derive* the key — they can only *gate
release* of a key that was stored earlier. So Touch ID unlock necessarily
means **persisting a root secret at rest**, protected by the Secure
Enclave's biometric access control. This is the same bargain every
password manager (Bitwarden, 1Password, …) makes for biometric unlock, but
it is a real, deliberate reduction of Hekate's current posture and is
therefore opt-in, off by default, and per-device.

## How it would work

The entire login pipeline derives from the 32-byte Argon2 output
`masterKey` (`clients/web/src/lib/auth.ts`):

- `deriveMasterPasswordHash(masterKey)` → the password-grant credential
- `deriveStretchedMasterKey(masterKey)` → unwraps `protected_account_key`
  → `accountKey`
- `deriveAccountSigningSeed(masterKey)` → `signingSeed`

So **storing the 32-byte `masterKey`** (not the password, not the
`accountKey`) is both necessary and sufficient to reconstruct a full
session. That is the proposed unit of storage — it never exposes the
plaintext master password, and a `loginWithMasterKey(email, masterKey)`
variant reuses the existing flow (still honoring the BW07/LP04 KDF-bind
verify; 2FA still applies; a stale key from a changed master password just
401s on the grant → fall back to password login + re-enroll).

### Rust side (`clients/desktop/src-tauri`)

- New dependency: `security-framework` (macOS Keychain `SecItem` +
  `SecAccessControl`). Desktop crate only — it is a standalone workspace,
  so this does **not** touch the wasm / server / CLI builds. (Caveat: the
  desktop workspace isn't covered by the root `make deny`/`make audit`
  gates — run `cargo audit` against it explicitly and review the dep.)
- Minimal, capability-gated IPC command set (the first custom commands;
  the surface was previously empty):
  - `biometric_available() -> bool`
  - `biometric_store(email, master_key_b64)` — store under the access
    control flag chosen below
  - `biometric_unlock(email) -> master_key_b64` — retrieval triggers the
    OS Touch ID prompt
  - `biometric_clear(email)`
- Key material crosses the in-process JS↔Rust IPC boundary as base64
  (local, not network). Zeroize the Rust-side buffers after use.

### SPA side (`clients/web`)

- `isDesktop()`-gated. After a successful master-password login, offer
  "Enable Touch ID for this device" → `biometric_store`.
- On the Resume / lock screen, an "Unlock with Touch ID" button →
  `biometric_unlock` → `loginWithMasterKey`.
- "Disable Touch ID" in Settings → `biometric_clear`. Also clear on logout
  and on a detected master-password change.

## Threat-model delta (the part to weigh)

| | Today (memory-only) | With Touch ID enabled |
|---|---|---|
| Root secret at rest | none | 32-byte `masterKey` in Keychain, Secure-Enclave biometric-gated |
| Powered-off / locked Mac, attacker has disk | no vault access | no vault access (Keychain item requires live biometric) |
| Logged-in Mac, attacker can present the enrolled fingerprint | needs master password | **unlocks the vault** |
| IPC attack surface | empty | 4 commands; `biometric_unlock` releases the root key on biometric success |
| Master password compromise | full access (unchanged) | full access (unchanged) |

Net: it trades a slice of at-rest strength for convenience, scoped to a
single device the user explicitly opted in on. It does **not** weaken the
server-side or cross-device posture, and the master password remains the
ultimate authority.

## Open decisions

1. **Approve persisting the master key at all?** (The core tradeoff
   above.) If no → defer Touch ID; there is no biometric-unlock design
   that avoids storing a root secret.
2. **Access-control strictness:**
   - **`.biometryCurrentSet` — biometric-only, no fallback (recommended).**
     Touch ID only; the item is auto-invalidated if the enrolled
     fingerprint set changes (so adding a fingerprint can't unlock an
     existing item). The only non-biometric path is re-typing the master
     password (which re-derives — no stored-key access). Strongest fit for
     a password manager.
   - **Device-password fallback (`.userPresence` / `.biometryAny` +
     fallback).** If Touch ID fails/unavailable, the macOS *account*
     password releases the item. More convenient, but widens access to
     anyone who knows the Mac login password — which is not the master
     password. Weaker; generally not recommended here.

## Testing / shipping constraints

- LocalAuthentication + the Secure-Enclave access control only work in a
  **signed** build (`make desktop-release`); an unsigned `cargo tauri dev`
  binary cannot exercise the real biometric path.
- Add an audit/log line on enable / disable / unlock (per `secure-coding.md`
  §9 — security-relevant events are logged, never the secret).
- Subject to the pre-publish security gate ([`followups.md`](followups.md))
  like everything else on the desktop track.
