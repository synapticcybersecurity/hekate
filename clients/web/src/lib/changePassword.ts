/* Change-master-password pipeline (C.7d-2) — port of
 * crates/hekate-cli/src/commands/account.rs::change_password.
 *
 * What rotates:
 *   - master_password_hash (server-stored Argon2id PHC).
 *   - kdf_salt (fresh 16 random bytes), kdf_params_mac (HMAC binding).
 *   - protected_account_key wrapping (re-wrapped under the NEW stretched
 *     master key; the unwrapped account_key VALUE doesn't change).
 *   - account_signing_pubkey_b64 (BW04 signing seed is HKDF-derived from
 *     the master key, so it rotates whenever the password does). The
 *     server wipes its stored vault_manifest row atomically so the next
 *     write uploads a fresh genesis.
 *   - security_stamp (revokes every other access token + refresh token
 *     on the next request from any device).
 *
 * What does NOT rotate:
 *   - account_key VALUE (only its wrapping). All cipher PCKs, send keys,
 *     org membership keys, etc. continue to decrypt fine.
 *   - protected_account_private_key (X25519 priv is wrapped under the
 *     account_key, not the stretched master key).
 *   - kdf_params (we reuse the current params; the user can bump them
 *     via a future "advanced" toggle, but reusing keeps the migration
 *     small).
 *
 * 2FA gating: the change-password endpoint is `AuthUser`-extracted
 * (regular bearer auth), NOT a fresh password-grant — re-auth is via
 * the supplied `current_master_password_hash`. So this works on 2FA-
 * enabled accounts without driving the second-factor challenge, unlike
 * rotate-keys (which DOES need the password grant for the
 * protected_account_private_key blob).
 */
import { ApiError, authedFetch, postJSON } from "./api";
import { b64decode, b64encode, b64urlEncode } from "./base64";
import {
  getSession,
  loadHints,
  persistRefreshToken,
  setSession,
} from "./session";
import { loadHekateCore } from "../wasm";
import type { KdfParams } from "../wasm-types";

const AAD_PROTECTED_ACCOUNT_KEY = "pmgr-account-key";
const enc = new TextEncoder();

interface PreloginResponse {
  kdf_params: KdfParams;
  kdf_salt: string;
  kdf_params_mac: string;
}

interface ChangePasswordResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
}

/** Run the full change-master-password pipeline. Throws on any failure;
 *  on success the in-memory session is updated with the new signing
 *  seed/pubkey + fresh tokens (the unwrapped account_key value is
 *  unchanged). */
export async function changePassword(
  currentPassword: string,
  newPassword: string,
): Promise<void> {
  const session = getSession();
  if (!session) throw new Error("session expired — log in again");
  const hekate = await loadHekateCore();

  // 1. Re-prelogin (BW07/LP04 mitigation, applied to the current pw).
  const pre = await postJSON<PreloginResponse>("/api/v1/accounts/prelogin", {
    email: session.email,
  });
  if (!hekate.kdfParamsAreSafe(pre.kdf_params)) {
    throw new Error(
      "Server returned KDF params below the safety floor — refusing to derive.",
    );
  }
  const curSalt = b64decode(pre.kdf_salt);
  const curMk = hekate.deriveMasterKey(
    enc.encode(currentPassword),
    pre.kdf_params,
    curSalt,
  );
  if (!pre.kdf_params_mac) {
    throw new Error("Server omitted kdf_params_mac — refusing to change pw.");
  }
  if (
    !hekate.verifyKdfBindMac(curMk, pre.kdf_params, curSalt, b64decode(pre.kdf_params_mac))
  ) {
    throw new Error(
      "Wrong current master password, or server is attempting to downgrade the KDF (BW07/LP04). Did NOT send credentials.",
    );
  }
  const curMphB64 = b64encode(hekate.deriveMasterPasswordHash(curMk));

  // 2. Mint a fresh 16-byte salt for the new derivation. Reuse the
  //    current KDF params — bumping params is a separate concern.
  const newSalt = new Uint8Array(16);
  crypto.getRandomValues(newSalt);
  const newKdfParams = pre.kdf_params;

  const newMk = hekate.deriveMasterKey(enc.encode(newPassword), newKdfParams, newSalt);
  const newSmk = hekate.deriveStretchedMasterKey(newMk);
  const newMphB64 = b64encode(hekate.deriveMasterPasswordHash(newMk));
  const newKdfParamsMacB64 = b64encode(
    hekate.computeKdfBindMac(newMk, newKdfParams, newSalt),
  );

  // 3. Re-wrap the (unchanged) account_key under the new stretched
  //    master key. `session.accountKey` already holds the unwrapped
  //    bytes — no need to round-trip through the wrapped form.
  const newProtectedAccountKey = hekate.encStringEncryptXc20p(
    "smk:1",
    newSmk,
    session.accountKey,
    enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
  );

  // 4. The BW04 signing seed is HKDF-Expand(master_key) — master key
  //    changed, so seed + pubkey change too. Server updates the
  //    `account_signing_pubkey_b64` column atomically and wipes the
  //    stored vault_manifest row; next write rebuilds genesis.
  const newSigningSeed = hekate.deriveAccountSigningSeed(newMk);
  const newSigningPubkey = hekate.verifyingKeyFromSeed(newSigningSeed);
  const newSigningPubkeyB64 = b64urlEncode(newSigningPubkey);
  const newSigningPubkeyB64NoPad = b64encode(newSigningPubkey);

  // 5. POST. The current access token is still valid for THIS request —
  //    the security_stamp rotation only invalidates it on the NEXT
  //    request. Replace tokens immediately on the response so we never
  //    re-use the now-stale pair.
  const r = await authedFetch("POST", "/api/v1/account/change-password", {
    body: {
      current_master_password_hash: curMphB64,
      new_master_password_hash: newMphB64,
      new_kdf_params: newKdfParams,
      new_kdf_salt: b64encode(newSalt),
      new_kdf_params_mac: newKdfParamsMacB64,
      new_protected_account_key: newProtectedAccountKey,
      new_account_signing_pubkey: newSigningPubkeyB64NoPad,
    },
  });
  if (!r.ok) {
    let body: unknown = null;
    try {
      body = await r.json();
    } catch {
      /* empty / non-JSON */
    }
    let msg = `change-password failed: ${r.status} ${r.statusText}`;
    if (body && typeof body === "object" && "error" in body) {
      const e = (body as { error?: unknown }).error;
      if (typeof e === "string" && e) msg = e;
    }
    throw new ApiError(r.status, msg, body);
  }
  const tok = (await r.json()) as ChangePasswordResponse;

  // 6. Replace in-memory session: same email + accountKey, NEW signing
  //    seed + signing pubkey + tokens. protectedAccountPrivateKey is
  //    wrapped under accountKey (not the stretched master key) so it
  //    survives untouched.
  const remember = loadHints().rememberMe;
  setSession(
    {
      email: session.email,
      accountKey: session.accountKey,
      signingSeed: newSigningSeed,
      signingPubkeyB64: newSigningPubkeyB64,
      accessToken: tok.access_token,
      refreshToken: tok.refresh_token,
      protectedAccountPrivateKey: session.protectedAccountPrivateKey,
    },
    { rememberMe: remember },
  );
  // setSession already wrote LS_REFRESH/SS_REFRESH per the remember-me
  // tier. Mirror what other rotation flows do for parity.
  persistRefreshToken(tok.refresh_token);
}
