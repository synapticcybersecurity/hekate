/* Rotate-keys flow (M2.26) — port of clients/extension/popup/popup.js's
 * `onRotateKeys` (lines 3619-3848).
 *
 * What rotates:
 *   - account_key (fresh 32 random bytes; replaces the in-memory + the
 *     wrapped one stored under the stretched master key).
 *   - The wrapping of the X25519 account private key (under new account_key).
 *   - Every personal-cipher `protected_cipher_key`.
 *   - Every Send `protected_send_key` AND `name` (both wrap under the
 *     account_key; missing the `name` was the bug captured in
 *     `project_rotate_keys_rewrap_invariant.md`).
 *   - Every org membership's `my_protected_org_key`.
 *
 * What does NOT rotate:
 *   - Master password (use `change-password` for that — CLI-only today).
 *   - Per-cipher data ciphertexts (their PCK still decrypts them).
 *   - Per-send body / metadata (still under the unchanged send_key).
 *   - Org symmetric keys (rotated only via the org owner's revoke flow).
 *
 * Every new account_key-wrapped field added in the future MUST get a
 * rewrap entry here AND on the server's `RotateKeysRequest` shape, or
 * rotation silently strands the field. See the rewrap-invariant memory.
 */
import { authedFetch, ApiError, apiGet } from "./api";
import { b64decode, b64encode, b64urlEncode } from "./base64";
import { uploadManifestQuiet } from "./manifest";
import {
  getSession,
  persistRefreshToken,
  replaceTokens,
  setSession,
  type Session,
} from "./session";
import type { SyncResponse } from "./sync";
import { loadHekateCore } from "../wasm";

const AAD_PROTECTED_ACCOUNT_KEY = "pmgr-account-key";
const AAD_X25519_PRIV = "pmgr-account-x25519-priv";
const enc = new TextEncoder();

interface CipherRewrap {
  cipher_id: string;
  new_protected_cipher_key: string;
}
interface SendRewrap {
  send_id: string;
  new_protected_send_key: string;
  new_name: string;
}
interface OrgMemberRewrap {
  org_id: string;
  new_protected_org_key: string;
}

interface RotateKeysResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
  rewrote_ciphers: number;
  rewrote_sends: number;
  rewrote_org_memberships: number;
}

interface PreloginResponse {
  kdf_params: Record<string, unknown>;
  kdf_salt: string;
  kdf_params_mac: string;
}

interface PasswordGrantBody {
  access_token: string;
  refresh_token: string;
  protected_account_private_key?: string | null;
  error?: string;
}

export interface RotateKeysSuccess {
  rewroteCiphers: number;
  rewroteSends: number;
  rewroteOrgMemberships: number;
  skippedSendIds: string[];
}

/** Run the full rotate-keys pipeline. Throws on any failure; mutates
 *  the in-memory session on success (new account_key + signing-seed
 *  unchanged + new tokens). */
export async function rotateKeys(masterPassword: string): Promise<RotateKeysSuccess> {
  const hekate = await loadHekateCore();
  const session = getSession();
  if (!session) throw new Error("session expired — log in again");

  // 1. Re-prelogin (BW07/LP04 mitigation re-applied).
  const pre = await postJSON<PreloginResponse>("/api/v1/accounts/prelogin", {
    email: session.email,
  });
  if (!hekate.kdfParamsAreSafe(pre.kdf_params)) {
    throw new Error(
      "Server returned KDF params below the safety floor — refusing to derive.",
    );
  }
  const salt = b64decode(pre.kdf_salt);
  const masterKey = hekate.deriveMasterKey(enc.encode(masterPassword), pre.kdf_params, salt);
  const macTag = b64decode(pre.kdf_params_mac);
  if (!hekate.verifyKdfBindMac(masterKey, pre.kdf_params, salt, macTag)) {
    throw new Error(
      "Wrong master password, or server is attempting to downgrade the KDF (BW07/LP04). Did NOT send credentials.",
    );
  }
  const mph = hekate.deriveMasterPasswordHash(masterKey);
  const mphB64 = b64encode(mph);

  // 2. Fresh password grant — confirms credentials AND captures the
  //    `protected_account_private_key` blob (not always cached in
  //    session memory after a refresh-grant).
  const grant = await postFormCapture("/identity/connect/token", {
    grant_type: "password",
    username: session.email,
    password: mphB64,
  });
  if (grant.status === 401 && grant.body?.error === "two_factor_required") {
    throw new Error(
      "This account has 2FA enabled — web-vault rotate-keys can't drive the second-factor challenge yet. Use `hekate account rotate-keys` from the CLI.",
    );
  }
  if (grant.status < 200 || grant.status >= 300) {
    throw new Error(grant.body?.error ?? `password grant failed: ${grant.status}`);
  }
  const tok = grant.body!;
  if (!tok.protected_account_private_key) {
    throw new Error(
      "Server didn't return protected_account_private_key on grant — server may be older than M2.26.",
    );
  }

  // 3. Generate the new account_key. Old still lives in session.
  const oldAccountKey = session.accountKey;
  const newAccountKey = hekate.randomKey32();

  const oldPrivBytes = hekate.encStringDecryptXc20p(
    tok.protected_account_private_key,
    oldAccountKey,
    enc.encode(AAD_X25519_PRIV),
  );
  const newProtectedPriv = hekate.encStringEncryptXc20p(
    "ak:1",
    newAccountKey,
    oldPrivBytes,
    enc.encode(AAD_X25519_PRIV),
  );
  const newProtectedAccountKey = hekate.encStringEncryptXc20p(
    "smk:1",
    hekate.deriveStretchedMasterKey(masterKey),
    newAccountKey,
    enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
  );

  // 4. Use the freshly issued tokens for subsequent calls.
  replaceTokens(tok.access_token, tok.refresh_token);
  persistRefreshToken(tok.refresh_token);

  const sync = await apiGet<SyncResponse>("/api/v1/sync");

  // 5. Per-cipher rewraps (personal only — org ciphers wrap under the
  //    org sym key, not the account_key).
  const cipherRewraps: CipherRewrap[] = [];
  for (const c of sync.changes.ciphers ?? []) {
    if (c.org_id) continue;
    const aad = enc.encode(`pmgr-cipher-key-v2:${c.id}`);
    let pck: Uint8Array;
    try {
      pck = hekate.encStringDecryptXc20p(c.protected_cipher_key, oldAccountKey, aad);
    } catch (err) {
      throw new Error(
        `Could not unwrap PCK for cipher ${c.id}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    cipherRewraps.push({
      cipher_id: c.id,
      new_protected_cipher_key: hekate.encStringEncryptXc20p(
        "ak:1",
        newAccountKey,
        pck,
        aad,
      ),
    });
  }

  // 6. Per-send rewraps. Per the rewrap-invariant memory:
  //    BOTH protected_send_key AND name wrap under the account_key.
  //    Skip orphaned sends rather than aborting on one corrupt row.
  const sendRewraps: SendRewrap[] = [];
  const skippedSendIds: string[] = [];
  for (const sd of sync.changes.sends ?? []) {
    try {
      const keyAad = hekate.sendKeyWrapAad(sd.id);
      const sendKey = hekate.encStringDecryptXc20p(
        sd.protected_send_key,
        oldAccountKey,
        keyAad,
      );
      const nameAad = hekate.sendNameAad(sd.id);
      const namePt = hekate.encStringDecryptXc20p(sd.name, oldAccountKey, nameAad);
      sendRewraps.push({
        send_id: sd.id,
        new_protected_send_key: hekate.encStringEncryptXc20p(
          "ak:1",
          newAccountKey,
          sendKey,
          keyAad,
        ),
        new_name: hekate.encStringEncryptXc20p("ak:1", newAccountKey, namePt, nameAad),
      });
    } catch (err) {
      console.warn(`rotate: skipping orphaned send ${sd.id}`, err);
      skippedSendIds.push(sd.id);
    }
  }

  // 7. Per-org membership rewraps. /sync orgs[] doesn't carry
  //    `my_protected_org_key`; need to fetch each org row directly.
  const orgMemberRewraps: OrgMemberRewrap[] = [];
  for (const o of sync.orgs ?? []) {
    const orgFull = await apiGet<{ my_protected_org_key?: string | null }>(
      `/api/v1/orgs/${encodeURIComponent(o.org_id)}`,
    );
    if (!orgFull.my_protected_org_key) continue;
    const aad = enc.encode(AAD_PROTECTED_ACCOUNT_KEY);
    const symKey = hekate.encStringDecryptXc20p(
      orgFull.my_protected_org_key,
      oldAccountKey,
      aad,
    );
    orgMemberRewraps.push({
      org_id: o.org_id,
      new_protected_org_key: hekate.encStringEncryptXc20p(
        "ak:1",
        newAccountKey,
        symKey,
        aad,
      ),
    });
  }

  // 8. POST the rotation. Server applies it atomically.
  const r = await authedFetch("POST", "/api/v1/account/rotate-keys", {
    body: {
      master_password_hash: mphB64,
      new_protected_account_key: newProtectedAccountKey,
      new_protected_account_private_key: newProtectedPriv,
      cipher_rewraps: cipherRewraps,
      send_rewraps: sendRewraps,
      org_member_rewraps: orgMemberRewraps,
    },
  });
  if (!r.ok) {
    let body: unknown = null;
    try {
      body = await r.json();
    } catch {
      /* */
    }
    let msg = `${r.status} ${r.statusText}`;
    if (body && typeof body === "object" && "error" in body) {
      const e = (body as { error?: unknown }).error;
      if (typeof e === "string" && e) msg = e;
    }
    throw new ApiError(r.status, msg, body);
  }
  const resp = (await r.json()) as RotateKeysResponse;

  // 9. Replace in-memory session (account_key changes; signing seed,
  //    email, signingPubkeyB64 stay; tokens are fresh from the
  //    rotation response).
  const remember = localStorage.getItem("hekate.remember_me") === "1";
  const updated: Session = {
    email: session.email,
    accountKey: newAccountKey,
    signingSeed: session.signingSeed,
    signingPubkeyB64: session.signingPubkeyB64,
    accessToken: resp.access_token,
    refreshToken: resp.refresh_token,
    protectedAccountPrivateKey: newProtectedPriv,
  };
  setSession(updated, { rememberMe: remember });

  // 10. Re-sign the BW04 manifest. The server bumped every personal
  //     cipher's revision_date when it re-wrapped the PCKs, so the
  //     previous signed manifest is now stale.
  await uploadManifestQuiet();

  return {
    rewroteCiphers: resp.rewrote_ciphers,
    rewroteSends: resp.rewrote_sends,
    rewroteOrgMemberships: resp.rewrote_org_memberships,
    skippedSendIds,
  };
}

async function postJSON<T>(url: string, body: unknown): Promise<T> {
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    let bodyJson: unknown = null;
    try {
      bodyJson = await r.json();
    } catch {
      /* */
    }
    let msg = `${r.status} ${r.statusText}`;
    if (bodyJson && typeof bodyJson === "object" && "error" in bodyJson) {
      const e = (bodyJson as { error?: unknown }).error;
      if (typeof e === "string" && e) msg = e;
    }
    throw new ApiError(r.status, msg, bodyJson);
  }
  return (await r.json()) as T;
}

async function postFormCapture(
  url: string,
  body: Record<string, string>,
): Promise<{ status: number; body: PasswordGrantBody | null }> {
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
  });
  let json: PasswordGrantBody | null = null;
  try {
    json = (await r.json()) as PasswordGrantBody;
  } catch {
    /* empty / non-JSON */
  }
  return { status: r.status, body: json };
}

// Export `b64urlEncode` re-import to suppress the unused-warning
// guard if a future field starts using it directly. Cheap.
void b64urlEncode;
