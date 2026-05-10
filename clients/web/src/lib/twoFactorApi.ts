/* TOTP 2FA management (C.7d-1) — typed wrappers around the server's
 * /api/v1/account/2fa/* endpoints, plus a re-derive-mph helper that all
 * sensitive endpoints need before they accept a request.
 *
 * Mirrors the popup's flow in clients/extension/popup/popup.js's
 * `render2faPanel` / `renderTotpEnroll` / `onTotpDisable` /
 * `onRecoveryRegenerate`. Server contract is owned by
 * crates/hekate-server/src/routes/two_factor.rs.
 *
 * Recovery-code semantics: auth-only by design (see the project memory
 * `project_recovery_codes_auth_only`). They let the user finish a
 * password-grant 2FA challenge when the authenticator is gone — they
 * do NOT decrypt the vault.
 */
import { ApiError, apiGet, authedFetch, postJSON } from "./api";
import { b64decode, b64encode } from "./base64";
import { getSession, replaceTokens, persistRefreshToken } from "./session";
import { loadHekateCore } from "../wasm";
import type { KdfParams } from "../wasm-types";

const enc = new TextEncoder();

interface PreloginResponse {
  kdf_params: KdfParams;
  kdf_salt: string;
  kdf_params_mac: string;
}

/** Derive the master_password_hash (base64-no-pad) the server expects
 *  as re-auth proof on every privileged 2FA endpoint. Re-runs the full
 *  prelogin → BW07/LP04 verification chain so a wrong password is
 *  caught client-side without leaking a derivation oracle to the
 *  server. */
export async function deriveMphB64(masterPassword: string): Promise<string> {
  const session = getSession();
  if (!session) throw new Error("session expired — log in again");
  const hekate = await loadHekateCore();
  const pre = await postJSON<PreloginResponse>("/api/v1/accounts/prelogin", {
    email: session.email,
  });
  if (!hekate.kdfParamsAreSafe(pre.kdf_params)) {
    throw new Error(
      "Server returned KDF params below the safety floor — refusing to derive.",
    );
  }
  const salt = b64decode(pre.kdf_salt);
  const masterKey = hekate.deriveMasterKey(
    enc.encode(masterPassword),
    pre.kdf_params,
    salt,
  );
  if (!pre.kdf_params_mac) {
    throw new Error("Server omitted kdf_params_mac — refusing to re-auth.");
  }
  if (
    !hekate.verifyKdfBindMac(masterKey, pre.kdf_params, salt, b64decode(pre.kdf_params_mac))
  ) {
    throw new Error(
      "Wrong master password, or server is attempting to downgrade the KDF (BW07/LP04). Did NOT send credentials.",
    );
  }
  return b64encode(hekate.deriveMasterPasswordHash(masterKey));
}

// ---- /2fa/status ---------------------------------------------------------

export interface TwoFactorStatus {
  enabled: boolean;
  recovery_codes_remaining: number;
}

export function getTwoFactorStatus(): Promise<TwoFactorStatus> {
  return apiGet<TwoFactorStatus>("/api/v1/account/2fa/status");
}

// ---- /2fa/totp/setup -----------------------------------------------------

export interface TotpSetupResponse {
  secret_b32: string;
  otpauth_url: string;
  recovery_codes: string[];
}

/** Phase 1 of TOTP enrollment. Stages a pending secret + recovery codes
 *  and returns them. Nothing is active until `confirmTotpEnrollment`. */
export async function startTotpEnrollment(
  mphB64: string,
  accountLabel: string,
): Promise<TotpSetupResponse> {
  const r = await authedFetch("POST", "/api/v1/account/2fa/totp/setup", {
    body: {
      master_password_hash: mphB64,
      account_label: accountLabel,
    },
  });
  if (!r.ok) throw await apiErrorFromResponse(r);
  return (await r.json()) as TotpSetupResponse;
}

// ---- /2fa/totp/confirm ---------------------------------------------------

export interface TotpConfirmResponse {
  recovery_codes_count: number;
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
}

/** Phase 2: verify the 6-digit code and commit the enrollment. The
 *  server rotates `security_stamp` and revokes all other refresh
 *  tokens, so we replace our in-memory + persisted tokens with the
 *  fresh pair the response carries. */
export async function confirmTotpEnrollment(code: string): Promise<TotpConfirmResponse> {
  const r = await authedFetch("POST", "/api/v1/account/2fa/totp/confirm", {
    body: { totp_code: code.trim() },
  });
  if (!r.ok) throw await apiErrorFromResponse(r);
  const body = (await r.json()) as TotpConfirmResponse;
  // The previous access + refresh tokens are revoked atomically with
  // the enrollment. Without this swap, the next authedFetch 401s and
  // bounces the user to Resume.
  replaceTokens(body.access_token, body.refresh_token);
  persistRefreshToken(body.refresh_token);
  return body;
}

// ---- /2fa/totp/disable ---------------------------------------------------

export async function disableTotp(mphB64: string): Promise<void> {
  const r = await authedFetch("POST", "/api/v1/account/2fa/totp/disable", {
    body: { master_password_hash: mphB64 },
  });
  if (!r.ok && r.status !== 204) throw await apiErrorFromResponse(r);
}

// ---- /2fa/recovery-codes/regenerate -------------------------------------

export interface RegenRecoveryCodesResponse {
  recovery_codes: string[];
}

export async function regenerateRecoveryCodes(
  mphB64: string,
): Promise<RegenRecoveryCodesResponse> {
  const r = await authedFetch(
    "POST",
    "/api/v1/account/2fa/recovery-codes/regenerate",
    { body: { master_password_hash: mphB64 } },
  );
  if (!r.ok) throw await apiErrorFromResponse(r);
  return (await r.json()) as RegenRecoveryCodesResponse;
}

// ---- shared error wrap --------------------------------------------------

async function apiErrorFromResponse(r: Response): Promise<ApiError> {
  let body: unknown = null;
  try {
    body = await r.json();
  } catch {
    /* empty / non-JSON */
  }
  let msg = `${r.status} ${r.statusText}`;
  if (body && typeof body === "object" && "error" in body) {
    const err = (body as { error?: unknown }).error;
    if (typeof err === "string" && err) msg = err;
  }
  return new ApiError(r.status, msg, body);
}
