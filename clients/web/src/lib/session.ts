/* Session state for owner mode.
 *
 * Authoritative state lives in module memory (a `Session` object).
 * Persistence is split intentionally:
 *
 *   - **localStorage** (always): non-secret hints — last-used email and
 *     the BW04 signing pubkey (so the SPA can verify signed manifests
 *     across tab loads without re-deriving). Plus a `remember_me` flag
 *     that controls whether the next visit lands on the slim Resume
 *     form or the full Login form. The flag is a UI hint only; it does
 *     NOT control any secret-bearing storage tier.
 *   - **sessionStorage** (always): the `refresh_token` — bearer
 *     credential, scoped per-tab and cleared the moment the tab
 *     closes. Aligns with the browser-extension's
 *     `chrome.storage.session` tier. NEVER persisted to disk-backed
 *     localStorage even with Remember-me on; an XSS sink or local
 *     profile read would otherwise be enough to mint live sessions.
 *
 * Everything else — the unwrapped `accountKey`, `signingSeed`,
 * `accessToken`, `protectedAccountPrivateKey` — stays in JS memory
 * only. A page reload always discards them; the user re-authenticates
 * with their master password.
 */

const LS_EMAIL = "hekate.email";
const LS_SIGNING_PUBKEY = "hekate.signing_pubkey_b64";
const LS_REMEMBER_ME = "hekate.remember_me";
const SS_REFRESH = "hekate.refresh_token";
// Builds before 2026-05-07 wrote refresh tokens to disk-backed
// localStorage when Remember-me was on. The C1 fix moved them to
// sessionStorage exclusively; we scrub the legacy key on every read so
// an upgrading user has no leftover token sitting on disk.
const LS_REFRESH_LEGACY = "hekate.refresh_token";

export interface Session {
  email: string;
  /** 32 raw bytes — the unwrapped symmetric vault key. Never persisted. */
  accountKey: Uint8Array;
  /** 32 raw bytes — Ed25519 signing seed for BW04 manifests. Never persisted. */
  signingSeed: Uint8Array;
  /** 32 bytes base64url — Ed25519 verifying key. Persisted (non-secret). */
  signingPubkeyB64: string;
  accessToken: string;
  refreshToken: string;
  /** Wrapped X25519 private key (`EncString` blob). Used by org-invite
   *  signcryption flows; null if the server didn't return it on this
   *  grant. Lives in memory only. */
  protectedAccountPrivateKey: string | null;
}

let current: Session | undefined;

/** Hints loaded from storage; used to pre-fill the login form and to
 *  decide whether to render Resume vs the full Login. */
export interface SessionHints {
  email: string | null;
  rememberMe: boolean;
  signingPubkeyB64: string | null;
}

export function loadHints(): SessionHints {
  // Retroactive scrub: remove any pre-upgrade refresh token sitting in
  // disk-backed localStorage. New tokens never land there.
  if (localStorage.getItem(LS_REFRESH_LEGACY) !== null) {
    localStorage.removeItem(LS_REFRESH_LEGACY);
  }
  return {
    email: localStorage.getItem(LS_EMAIL),
    rememberMe: localStorage.getItem(LS_REMEMBER_ME) === "1",
    signingPubkeyB64: localStorage.getItem(LS_SIGNING_PUBKEY),
  };
}

export interface PersistOptions {
  rememberMe: boolean;
}

export function setSession(session: Session, opts: PersistOptions): void {
  current = session;
  localStorage.setItem(LS_EMAIL, session.email);
  localStorage.setItem(LS_SIGNING_PUBKEY, session.signingPubkeyB64);
  localStorage.setItem(LS_REMEMBER_ME, opts.rememberMe ? "1" : "0");
  sessionStorage.setItem(SS_REFRESH, session.refreshToken);
  // Belt-and-braces — older builds may have left a disk-backed copy.
  localStorage.removeItem(LS_REFRESH_LEGACY);
}

export function getSession(): Session | undefined {
  return current;
}

/** Update the in-memory access + refresh tokens after a successful
 *  refresh-grant, without re-running the full login pipeline. */
export function replaceTokens(accessToken: string, refreshToken: string): void {
  if (!current) return;
  current.accessToken = accessToken;
  current.refreshToken = refreshToken;
}

/** Re-persist the refresh token after a rolling-token refresh so the
 *  sessionStorage value tracks the latest issued one. */
export function persistRefreshToken(refreshToken: string): void {
  sessionStorage.setItem(SS_REFRESH, refreshToken);
}

/** Full logout — user pressed Log out. Clears in-memory state, the
 *  refresh-token bucket, AND the remember-me flag (so the next visit
 *  shows the full login form, not the slim Resume one). Email +
 *  signing_pubkey hints persist; they're non-secret and pre-fill the
 *  email field for convenience. */
export function clearSession(): void {
  current = undefined;
  sessionStorage.removeItem(SS_REFRESH);
  localStorage.removeItem(LS_REMEMBER_ME);
  localStorage.removeItem(LS_REFRESH_LEGACY);
}

/** Session expired or refresh-grant failed. Same as logout in terms of
 *  secret material cleared, BUT keeps the remember-me flag so the next
 *  visit lands on the slim Resume form instead of the full Login.
 *  Used by `authedFetch`'s SessionExpiredError path. */
export function expireSession(): void {
  current = undefined;
  sessionStorage.removeItem(SS_REFRESH);
  localStorage.removeItem(LS_REFRESH_LEGACY);
  // Intentionally KEEP LS_REMEMBER_ME so Owner.tsx routes to Resume.
}
