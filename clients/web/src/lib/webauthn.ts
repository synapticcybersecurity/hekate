/* WebAuthn 2FA (C.2a).
 *
 * Two responsibilities:
 *
 * 1. **Wire-format adapters** — `webauthn-rs` emits / accepts JSON where
 *    every binary field is base64url-no-pad, but the
 *    `navigator.credentials.{create,get}` Web APIs expect ArrayBuffers
 *    in those positions. Mirror of the popup's helpers
 *    (clients/extension/popup/popup.js:659-716) so the two clients
 *    produce byte-identical wire requests.
 *
 * 2. **Typed wrappers** around the five server endpoints in
 *    crates/hekate-server/src/routes/two_factor_webauthn.rs:
 *      - register/start  (re-auth via master_password_hash)
 *      - register/finish
 *      - list credentials
 *      - delete credential
 *      - rename credential
 *
 * Login-leg WebAuthn lives in `lib/auth.ts::completeTwoFactor` (with
 * "webauthn" provider). The challenge JSON is decoded here via
 * `decodeRequestOptions` and the resulting credential encoded back via
 * `encodeCredentialForServer` before being JSON-stringified into the
 * `two_factor_value` form field.
 */
import { ApiError, apiGet, authedFetch } from "./api";
import { b64urlDecode, b64urlEncode } from "./base64";

// ---- wire-format adapters -----------------------------------------------

/** Decode a `CreationChallengeResponse` (the body returned by
 *  /webauthn/register/start.creation_options) into the shape
 *  `navigator.credentials.create()` accepts. The server already nests
 *  under `publicKey`. */
export function decodeCreationOptions(
  json: unknown,
): CredentialCreationOptions {
  if (!json || typeof json !== "object") {
    throw new Error("creation_options is not an object");
  }
  const root = json as { publicKey?: unknown };
  if (!root.publicKey || typeof root.publicKey !== "object") {
    throw new Error("creation_options.publicKey is missing");
  }
  // Deep clone so we don't mutate the caller's object on the b64 → buf
  // rewrite.
  const pk = JSON.parse(JSON.stringify(root.publicKey)) as Record<string, unknown> & {
    challenge: string;
    user: { id: string } & Record<string, unknown>;
    excludeCredentials?: Array<{ id: string } & Record<string, unknown>>;
  };
  pk.challenge = b64urlDecode(pk.challenge) as unknown as string;
  pk.user.id = b64urlDecode(pk.user.id) as unknown as string;
  if (Array.isArray(pk.excludeCredentials)) {
    pk.excludeCredentials = pk.excludeCredentials.map((c) => ({
      ...c,
      id: b64urlDecode(c.id) as unknown as string,
    }));
  }
  return { publicKey: pk } as unknown as CredentialCreationOptions;
}

/** Decode a `RequestChallengeResponse` (the `webauthn_challenge` field
 *  carried alongside `two_factor_required` on the password grant) into
 *  the shape `navigator.credentials.get()` accepts. */
export function decodeRequestOptions(
  json: unknown,
): CredentialRequestOptions {
  if (!json || typeof json !== "object") {
    throw new Error("webauthn_challenge is not an object");
  }
  const root = json as { publicKey?: unknown };
  if (!root.publicKey || typeof root.publicKey !== "object") {
    throw new Error("webauthn_challenge.publicKey is missing");
  }
  const pk = JSON.parse(JSON.stringify(root.publicKey)) as Record<string, unknown> & {
    challenge: string;
    allowCredentials?: Array<{ id: string } & Record<string, unknown>>;
  };
  pk.challenge = b64urlDecode(pk.challenge) as unknown as string;
  if (Array.isArray(pk.allowCredentials)) {
    pk.allowCredentials = pk.allowCredentials.map((c) => ({
      ...c,
      id: b64urlDecode(c.id) as unknown as string,
    }));
  }
  return { publicKey: pk } as unknown as CredentialRequestOptions;
}

/** Encode the result of `navigator.credentials.{create,get}` into the
 *  JSON shape `webauthn-rs` deserializes from. Used for both
 *  `RegisterPublicKeyCredential` (create) and `PublicKeyCredential`
 *  (get). All binary fields go out as base64url-no-pad. */
export function encodeCredentialForServer(
  credential: PublicKeyCredential,
): Record<string, unknown> {
  const out: Record<string, unknown> = {
    id: credential.id,
    rawId: b64urlEncode(new Uint8Array(credential.rawId)),
    type: credential.type,
    extensions: credential.getClientExtensionResults
      ? credential.getClientExtensionResults()
      : {},
  };
  const r = credential.response as
    | AuthenticatorAttestationResponse
    | AuthenticatorAssertionResponse;
  const response: Record<string, unknown> = {};

  if ("attestationObject" in r) {
    // navigator.credentials.create()
    response.attestationObject = b64urlEncode(new Uint8Array(r.attestationObject));
    response.clientDataJSON = b64urlEncode(new Uint8Array(r.clientDataJSON));
    if (typeof r.getTransports === "function") {
      response.transports = r.getTransports();
    }
  } else {
    // navigator.credentials.get()
    response.authenticatorData = b64urlEncode(new Uint8Array(r.authenticatorData));
    response.clientDataJSON = b64urlEncode(new Uint8Array(r.clientDataJSON));
    response.signature = b64urlEncode(new Uint8Array(r.signature));
    if (r.userHandle && r.userHandle.byteLength > 0) {
      response.userHandle = b64urlEncode(new Uint8Array(r.userHandle));
    }
  }
  out.response = response;
  return out;
}

// ---- typed API wrappers --------------------------------------------------

export interface WebauthnCredential {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

export function listWebauthnCredentials(): Promise<WebauthnCredential[]> {
  return apiGet<WebauthnCredential[]>("/api/v1/account/2fa/webauthn/credentials");
}

interface RegisterStartResponse {
  /** `CreationChallengeResponse` JSON; pass to `decodeCreationOptions`. */
  creation_options: unknown;
}

/** Phase 1: master-pw re-auth + name → server stashes pending state and
 *  returns the `CreationChallengeResponse` JSON. Caller decodes it,
 *  feeds it to `navigator.credentials.create()`, then calls
 *  `webauthnRegisterFinish` with the result. */
export async function webauthnRegisterStart(
  mphB64: string,
  name: string,
): Promise<RegisterStartResponse> {
  const r = await authedFetch("POST", "/api/v1/account/2fa/webauthn/register/start", {
    body: { master_password_hash: mphB64, name },
  });
  if (!r.ok) throw await apiErrorFromResponse(r);
  return (await r.json()) as RegisterStartResponse;
}

interface RegisterFinishResponse {
  credential_id: string;
  name: string;
}

/** Phase 2: forward the encoded credential to the server, which
 *  validates the attestation and persists the Passkey row. */
export async function webauthnRegisterFinish(
  credential: Record<string, unknown>,
): Promise<RegisterFinishResponse> {
  const r = await authedFetch("POST", "/api/v1/account/2fa/webauthn/register/finish", {
    body: { credential },
  });
  if (!r.ok) throw await apiErrorFromResponse(r);
  return (await r.json()) as RegisterFinishResponse;
}

export async function webauthnDeleteCredential(id: string): Promise<void> {
  const r = await authedFetch(
    "DELETE",
    `/api/v1/account/2fa/webauthn/credentials/${encodeURIComponent(id)}`,
  );
  if (!r.ok && r.status !== 204) throw await apiErrorFromResponse(r);
}

export async function webauthnRenameCredential(id: string, name: string): Promise<void> {
  const r = await authedFetch(
    "PATCH",
    `/api/v1/account/2fa/webauthn/credentials/${encodeURIComponent(id)}`,
    { body: { name } },
  );
  if (!r.ok && r.status !== 204) throw await apiErrorFromResponse(r);
}

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
