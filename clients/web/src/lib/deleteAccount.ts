/* Account-delete pipeline (C.7d-rest) — port of
 * crates/hekate-cli/src/commands/account.rs::delete.
 *
 * Re-derives the master password hash via the same prelogin →
 * deriveMasterKey → deriveMasterPasswordHash dance the login flow uses,
 * then POSTs `/api/v1/account/delete` with `{ master_password_hash }`.
 * Server cascades through ciphers, folders, refresh tokens, PATs,
 * webhooks, deliveries.
 *
 * On success the account no longer exists, so we wipe every locally-
 * persisted artifact tied to this email — refresh-token bucket, the
 * email + signing-pubkey hints, the strict-manifest preference, and
 * the `hekate.peer_pins:<email>` TOFU store. The in-memory session
 * goes via `clearSession()`.
 *
 * Re-prelogin matters for the same reason as change-password: it forces
 * KDF-param verification (BW07/LP04) so a malicious server can't trick
 * the client into deriving with downgraded params right before sending
 * the irrevocable destructive request.
 */
import { ApiError, authedFetch, postJSON } from "./api";
import { b64decode, b64encode } from "./base64";
import { clearSession, getSession } from "./session";
import { loadHekateCore } from "../wasm";
import type { KdfParams } from "../wasm-types";

const enc = new TextEncoder();

interface PreloginResponse {
  kdf_params: KdfParams;
  kdf_salt: string;
  kdf_params_mac: string;
}

/** Run the full account-delete pipeline. Throws on any failure (wrong
 *  password is the common case — surfaces as 401). On success the
 *  caller should route the user back to the login screen; the in-memory
 *  session and all persisted hints have been cleared. */
export async function deleteAccount(masterPassword: string): Promise<void> {
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
  const mk = hekate.deriveMasterKey(enc.encode(masterPassword), pre.kdf_params, salt);
  if (!pre.kdf_params_mac) {
    throw new Error("Server omitted kdf_params_mac — refusing to delete.");
  }
  if (!hekate.verifyKdfBindMac(mk, pre.kdf_params, salt, b64decode(pre.kdf_params_mac))) {
    throw new Error(
      "Wrong master password, or server is attempting to downgrade the KDF (BW07/LP04). Did NOT send delete request.",
    );
  }
  const mphB64 = b64encode(hekate.deriveMasterPasswordHash(mk));

  const r = await authedFetch("POST", "/api/v1/account/delete", {
    body: { master_password_hash: mphB64 },
  });
  if (!r.ok) {
    let body: unknown = null;
    try {
      body = await r.json();
    } catch {
      /* empty / non-JSON */
    }
    let msg = `delete-account failed: ${r.status} ${r.statusText}`;
    if (body && typeof body === "object" && "error" in body) {
      const e = (body as { error?: unknown }).error;
      if (typeof e === "string" && e) msg = e;
    }
    throw new ApiError(r.status, msg, body);
  }

  // Wipe every persisted artifact tied to this account. clearSession
  // handles in-memory + the refresh-token buckets + the remember-me
  // flag; we additionally drop the non-secret hints (email,
  // signing pubkey, strict-manifest preference) and the per-email
  // peer-pin store, since the account they describe no longer exists.
  const email = session.email;
  clearSession();
  localStorage.removeItem("hekate.email");
  localStorage.removeItem("hekate.signing_pubkey_b64");
  localStorage.removeItem("hekate.strict_manifest");
  localStorage.removeItem(`hekate.peer_pins:${email.toLowerCase()}`);
}
