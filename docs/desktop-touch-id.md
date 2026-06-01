# Desktop Touch ID unlock — design

> **Status:** approved in principle; **core decisions locked** (below);
> implementation in progress on the desktop track (issue #8). Touch ID
> unlock changes the desktop client's at-rest posture and adds the first
> custom Tauri IPC commands — per [`secure-coding.md`](secure-coding.md) §8
> both are "security changes requiring review," and it remains subject to
> the pre-publish security gate ([`followups.md`](followups.md)).

## What it is

Let a desktop user unlock their vault with **Touch ID** instead of
retyping the master password, while keeping decryption fully client-side.
Opt-in, off by default, per-device.

## The deliberate tradeoff (decided)

Today the client's root secrets live in **volatile memory only**: the
`masterKey`, `accountKey`, and `signingSeed` are never persisted; an app
restart always forces master-password re-derivation via the Resume screen
(`clients/web/src/lib/session.ts`, `Resume.tsx`). That's the strongest
at-rest posture — a powered-off/locked Mac yields nothing.

Biometric unlock cannot *derive* a key; it can only *gate release* of a
key stored earlier. So Touch ID necessarily means **persisting a root
secret at rest**, protected by the Secure Enclave's biometric access
control. This is the standard biometric-unlock bargain; it is a deliberate,
opt-in, per-device reduction of the default posture. **Decision: accepted.**

## Locked decisions

1. **Persist a biometric-gated secret at rest** — accepted (above).
2. **Implementation: a small Swift helper**, called from Rust via Tauri
   commands. Uses Apple's first-party APIs (`SecAccessControlCreateWithFlags`
   + `SecItemAdd`/`SecItemCopyMatching` + `LAContext`). The Rust
   `security-framework` crate was evaluated and **rejected**: its high-level
   keychain API can't attach a biometric `SecAccessControl` on item add, so
   it would force hand-rolled `SecItemAdd` FFI. The Swift helper is the
   blessed path and is **reused by Tier B**'s (Swift) credential-provider
   extension. (`objc2-security` + `objc2-local-authentication` was the
   pure-Rust alternative; not chosen.)
3. **What's stored: an unlock key wraps the master key.** A random 32-byte
   **unlock key** is stored in the Secure-Enclave-gated Keychain item; it
   encrypts a small blob `{ master_key, email }` held in the app's data dir.
   Biometric releases the unlock key → decrypt blob → `masterKey`. (Storing
   a random wrapping key, not the literal master key, keeps the Keychain
   item fixed-size and rotatable.)
4. **Access control: `kSecAccessControlBiometryCurrentSet`** + accessibility
   `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (never syncs to iCloud
   Keychain, never migrates off this Mac, not exportable).

### Unlock paths (and what is *not* one)

With `.biometryCurrentSet` there are exactly two ways to unlock, and the
**macOS login password is not one of them**:

1. **Touch ID** — the Secure Enclave releases the unlock key on a biometric
   match.
2. **Hekate master password** (fallback) — typed in the app; re-derives the
   master key via Argon2id and never touches the Keychain item.

There is **no device-passcode fallback** (that's precisely the option we
declined). The master password remains the only credential that can derive
the vault from nothing — biometric unlock is just a shortcut to a key the
master password originally unlocked and stored on this device.

## How it works

The whole login pipeline derives from the 32-byte Argon2 output `masterKey`
(`clients/web/src/lib/auth.ts`): `deriveMasterPasswordHash` → the grant
credential; `deriveStretchedMasterKey` → unwraps `protected_account_key`;
`deriveAccountSigningSeed` → signing seed. So the **master key is necessary
and sufficient** to reconstruct a session — it is the unit we protect.

### Native side (`clients/desktop/src-tauri`)

- **Swift helper** compiled into the app (via `swift-rs` / a `build.rs`
  `swiftc` step), exposing a tiny C-ABI surface. It owns: generate the
  unlock key, create the biometric Keychain item, wrap/unwrap the blob,
  trigger the Touch ID prompt, delete the item.
- **Tauri commands** (the first custom IPC; capability-gated in
  `capabilities/`):
  - `biometric_available() -> bool` (`LAContext.canEvaluatePolicy`)
  - `biometric_enable(account, master_key_b64)` — generate unlock key, store
    in Keychain (biometric ACL), wrap `{master_key,email}`, persist blob
  - `biometric_unlock(account) -> master_key_b64` — Touch ID prompt →
    release unlock key → unwrap blob → return master key
  - `biometric_disable(account)` — delete Keychain item + blob
- Key material crosses the in-process JS↔Rust↔Swift boundary as base64
  (local, not network). Zeroize native buffers after use. Log
  enable/disable/unlock events (never the secret), per `secure-coding.md` §9.

### SPA side (`clients/web`)

- `isDesktop()`-gated throughout; `lib/biometric.ts` wraps the `invoke`
  calls (no-op in the browser build).
- **Enable:** after a successful master-password login, if
  `biometric_available()`, offer "Enable Touch ID for this device" (a
  one-time prompt + a Settings toggle). Requires surfacing the in-memory
  `masterKey` to the enable call.
- **Unlock:** the Resume/lock screen shows "Unlock with Touch ID" when an
  item exists → `biometric_unlock` → **`loginWithMasterKey(email, masterKey)`**
  (a new `auth.ts` variant factored out of `login()`: derive MPH → password
  grant → `finalizeLogin`). Re-running the grant means unlock always gets
  **fresh tokens** and never depends on stale stored tokens.
- **Disable/clear:** Settings "Disable Touch ID"; also auto-clear on logout,
  on master-password change, and on account delete.

## Edge cases & handling

| Case | Handling |
|---|---|
| Touch ID absent / not enrolled / non-TouchID Mac | "Enable" is hidden (gated on `biometric_available`); unlock screen shows master-password only. |
| Prompt cancelled / biometric fails / lockout | Fall back to the always-present master-password field. **No** Mac-password fallback (by design). |
| Enrolled fingerprint set changes | `.biometryCurrentSet` auto-invalidates the item; the unlock read fails → fall back to master password → offer a one-time "Re-enable Touch ID?". |
| **Master password changed** (change-password flow) | The stored master key is now wrong → **clear the item** on change-password completion; user re-enables. |
| `account rotate-keys` | Master password + master key are **unchanged** → **keep** the item; the next unlock re-grants for fresh tokens/account_key. No action. |
| Stale tokens / `security_stamp` invalidated elsewhere | Not relied upon — unlock re-runs the grant from the master key. If the grant 401s (e.g. password changed on another device), fall back to master password + clear/re-enable. |
| Logout / account delete | Clear the Keychain item + blob. |
| Multiple accounts on one Mac | Keychain item + blob are keyed by account (email/user_id); no collision when switching. |
| Server unreachable / offline | Unlock re-runs the grant, so it needs the server — same as normal login today (no offline vault in the current architecture). Fail with a clear message. |
| Keychain item left after app uninstall | Harmless — biometric-gated and useless without the app + the (deleted) blob. |

## 2FA-enabled accounts (decided: support)

For an account with 2FA, biometric unlock replaces the *master-password
typing*, but the password grant still returns `two_factor_required`.
**Decision: support it.** After biometric → master key → the grant returns
`needTwoFactor`, route to the existing 2FA screen (`TwoFactor.tsx`) carrying
the in-memory master key, then `finalizeLogin`. Biometric still saves the
password step; 2FA is still enforced. `loginWithMasterKey` therefore
returns the same `LoginResult` union as `login()` (`ok` | `needTwoFactor`).

## Threat-model delta

| | Today (memory-only) | With Touch ID enabled |
|---|---|---|
| Root secret at rest | none | random unlock key (SEP, biometric-gated) wrapping the 32-byte master key |
| Powered-off / locked Mac, attacker has disk | no vault access | no vault access (Keychain item needs a live biometric) |
| Logged-in Mac, attacker can present the enrolled fingerprint | needs master password | **unlocks the vault** |
| macOS login password | not an unlock path | **still not** an unlock path (`.biometryCurrentSet`, no passcode fallback) |
| IPC attack surface | empty | 4 capability-gated commands; `biometric_unlock` releases the unlock key on biometric success |
| Master password compromise | full access (unchanged) | full access (unchanged) |

Net: trades a slice of at-rest strength for convenience on a single
opted-in device; does not weaken the server-side or cross-device posture;
the master password stays the ultimate authority.

## Testing / shipping constraints

- LocalAuthentication + Secure-Enclave access control only work in a
  **signed** build (`make desktop-release`); an unsigned `cargo tauri dev`
  binary can't exercise the real biometric path. Plan to verify against a
  signed build.
- Subject to the pre-publish security gate like everything on the desktop
  track.
