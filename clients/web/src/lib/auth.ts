/* Login + key-derivation flow.
 *
 * Mirrors clients/extension/popup/popup.js:1071-1166 (`onLogin`) and
 * the `complete2faChallenge` retry. Server-relative URLs only (the web
 * vault is same-origin with the server it talks to).
 *
 * BW07/LP04 mitigations preserved verbatim:
 *   1. `kdfParamsAreSafe` — refuse weak server-supplied params.
 *   2. `verifyKdfBindMac` — refuse to send the master_password_hash if
 *      the params/salt aren't bound by a valid HMAC under the master
 *      key the user just typed.
 */
import { ApiError, postJSON } from "./api";
import { b64decode, b64encode, b64urlEncode } from "./base64";
import { setSession } from "./session";
import { loadHekateCore } from "../wasm";
import type { KdfParams, HekateCore } from "../wasm-types";

const AAD_PROTECTED_ACCOUNT_KEY = "pmgr-account-key";
const enc = new TextEncoder();

interface PreloginResponse {
  kdf_params: KdfParams;
  kdf_salt: string;
  kdf_params_mac: string;
}

interface TokenResponse {
  access_token: string;
  refresh_token: string;
  protected_account_key?: string;
  protected_account_private_key?: string | null;
}

interface FormResult {
  status: number;
  body: unknown;
}

async function postForm(
  url: string,
  body: Record<string, string>,
): Promise<FormResult> {
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
  });
  let json: unknown = null;
  try {
    json = await r.json();
  } catch {
    /* empty / non-JSON */
  }
  return { status: r.status, body: json };
}

export interface TwoFactorChallenge {
  twoFactorToken: string;
  twoFactorProviders: string[];
  /** `RequestChallengeResponse` JSON when the account has any WebAuthn
   *  credential enrolled. Caller decodes it via `lib/webauthn.ts` and
   *  feeds it to `navigator.credentials.get()`. Null/absent for
   *  TOTP-only accounts. */
  webauthnChallenge: unknown | null;
}

export interface PendingLogin {
  email: string;
  mphB64: string;
  masterKey: Uint8Array;
}

export type LoginResult =
  | { kind: "ok" }
  | { kind: "needTwoFactor"; pending: PendingLogin; challenge: TwoFactorChallenge };

export async function login(
  rawEmail: string,
  password: string,
  rememberMe: boolean,
): Promise<LoginResult> {
  const email = rawEmail.trim().toLowerCase();
  const pre = await postJSON<PreloginResponse>("/api/v1/accounts/prelogin", { email });

  const hekate = await loadHekateCore();

  if (!hekate.kdfParamsAreSafe(pre.kdf_params)) {
    throw new Error(
      "Server returned KDF parameters below the safe floor — refusing to derive a master_password_hash that could be brute-forced.",
    );
  }

  const salt = b64decode(pre.kdf_salt);
  const masterKey = hekate.deriveMasterKey(enc.encode(password), pre.kdf_params, salt);

  if (!pre.kdf_params_mac) {
    throw new Error("Server omitted kdf_params_mac — refusing to log in.");
  }
  const serverMac = b64decode(pre.kdf_params_mac);
  if (!hekate.verifyKdfBindMac(masterKey, pre.kdf_params, salt, serverMac)) {
    throw new Error(
      "Wrong master password, or the server is attempting to downgrade the KDF (BW07/LP04). Did NOT send credentials.",
    );
  }

  const mphB64 = b64encode(hekate.deriveMasterPasswordHash(masterKey));

  const first = await postForm("/identity/connect/token", {
    grant_type: "password",
    username: email,
    password: mphB64,
  });

  if (first.status >= 200 && first.status < 300) {
    finalizeLogin(hekate, masterKey, email, first.body as TokenResponse, rememberMe);
    return { kind: "ok" };
  }

  if (first.status === 401 && isTwoFactorRequired(first.body)) {
    return {
      kind: "needTwoFactor",
      pending: { email, mphB64, masterKey },
      challenge: {
        twoFactorToken: first.body.two_factor_token,
        twoFactorProviders: first.body.two_factor_providers ?? [],
        webauthnChallenge: first.body.webauthn_challenge ?? null,
      },
    };
  }

  throw apiError(first);
}

export async function completeTwoFactor(
  pending: PendingLogin,
  challenge: TwoFactorChallenge,
  provider: "totp" | "recovery" | "webauthn",
  /** For totp/recovery, the user-typed code. For webauthn, the
   *  JSON-stringified output of `encodeCredentialForServer()` — the
   *  server `serde_json::from_str`'s it back into a
   *  `PublicKeyCredential`. */
  value: string,
  rememberMe: boolean,
): Promise<void> {
  const r = await postForm("/identity/connect/token", {
    grant_type: "password",
    username: pending.email,
    password: pending.mphB64,
    two_factor_token: challenge.twoFactorToken,
    two_factor_provider: provider,
    two_factor_value: value,
  });
  if (r.status >= 200 && r.status < 300) {
    const hekate = await loadHekateCore();
    finalizeLogin(hekate, pending.masterKey, pending.email, r.body as TokenResponse, rememberMe);
    return;
  }
  throw apiError(r);
}

function finalizeLogin(
  hekate: HekateCore,
  masterKey: Uint8Array,
  email: string,
  tok: TokenResponse,
  rememberMe: boolean,
): void {
  if (!tok.protected_account_key) {
    throw new Error("Server omitted protected_account_key on the password grant.");
  }
  const stretched = hekate.deriveStretchedMasterKey(masterKey);
  const accountKey = hekate.encStringDecryptXc20p(
    tok.protected_account_key,
    stretched,
    enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
  );
  const signingSeed = hekate.deriveAccountSigningSeed(masterKey);
  const signingPubkey = hekate.verifyingKeyFromSeed(signingSeed);

  setSession(
    {
      email,
      accountKey,
      signingSeed,
      signingPubkeyB64: b64urlEncode(signingPubkey),
      accessToken: tok.access_token,
      refreshToken: tok.refresh_token,
      protectedAccountPrivateKey: tok.protected_account_private_key ?? null,
    },
    { rememberMe },
  );
}

interface TwoFactorRequiredBody {
  error: "two_factor_required";
  two_factor_token: string;
  two_factor_providers?: string[];
  webauthn_challenge?: unknown | null;
}

function isTwoFactorRequired(body: unknown): body is TwoFactorRequiredBody {
  return (
    typeof body === "object" &&
    body !== null &&
    (body as { error?: unknown }).error === "two_factor_required" &&
    typeof (body as { two_factor_token?: unknown }).two_factor_token === "string"
  );
}

function apiError(r: FormResult): Error {
  let msg = `${r.status}`;
  if (
    typeof r.body === "object" &&
    r.body !== null &&
    typeof (r.body as { error?: unknown }).error === "string"
  ) {
    msg = (r.body as { error: string }).error;
  }
  return new ApiError(r.status, msg, r.body);
}
