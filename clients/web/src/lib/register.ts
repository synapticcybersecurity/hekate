/* New-account registration (parity with `hekate register` from
 * crates/hekate-cli/src/commands/register.rs). All keys are derived
 * client-side; the server only ever sees `master_password_hash`,
 * the wrapped `protected_account_key`, the wrapped X25519 private
 * key, and the public halves.
 *
 * Flow:
 *   1. Pick KDF defaults + fresh 16-byte salt.
 *   2. Derive master key → MPH, SMK, kdf_params_mac.
 *   3. Random 32-byte account_key + X25519 keypair.
 *   4. Wrap account_key under SMK (AAD `pmgr-account-key`).
 *      Wrap X25519 priv under account_key (AAD `pmgr-account-x25519-priv`).
 *   5. Derive Ed25519 signing seed from MK; pubkey from seed.
 *   6. Generate UUIDv7 client-side, sign the (user_id, signing_pk,
 *      x25519_pk) bundle so consumers can verify end-to-end via
 *      GET /api/v1/users/{id}/pubkeys (server refuses to serve a
 *      bundle without a valid sig).
 *   7. POST /api/v1/accounts/register.
 *   8. Immediately password-grant for tokens; finalize the in-memory
 *      session the same way login() does.
 *
 * BW07/LP04 mitigation point: kdf_params_mac is computed and uploaded
 * here so future logins can verify it via the prelogin path. The same
 * pattern landed in change-password (C.7d-2) — both flows persist a
 * fresh MAC the next prelogin returns.
 */
import { ApiError, postJSON } from "./api";
import { b64encode, b64urlEncode } from "./base64";
import { setSession } from "./session";
import { loadHekateCore } from "../wasm";
import type { KdfParams, HekateCore } from "../wasm-types";

const AAD_PROTECTED_ACCOUNT_KEY = "pmgr-account-key";
const AAD_PROTECTED_ACCOUNT_PRIV = "pmgr-account-x25519-priv";
const enc = new TextEncoder();

/** CLI default. Server enforces the safety floor via
 *  `kdfParamsAreSafe`; these values clear it comfortably. Bump only
 *  alongside the CLI/popup defaults so cross-client logins stay
 *  consistent. */
const DEFAULT_KDF_PARAMS: KdfParams = {
  alg: "argon2id",
  m_kib: 131072,
  t: 3,
  p: 4,
};

interface TokenResponse {
  access_token: string;
  refresh_token: string;
  protected_account_key?: string;
  protected_account_private_key?: string | null;
}

/** Generate a UUIDv7 (timestamp-prefixed UUID, monotonic enough for our
 *  purposes — we just need a stable per-account id). Spec: draft-ietf-
 *  uuidrev-rfc4122bis. 48-bit unix-ms timestamp || 4-bit version (7) ||
 *  12 random bits || 2-bit variant (10) || 62 random bits. */
function uuidv7(): string {
  const ts = Date.now();
  const rand = new Uint8Array(10);
  crypto.getRandomValues(rand);

  const b = new Uint8Array(16);
  // 48-bit big-endian timestamp (ms since unix epoch)
  b[0] = (ts / 2 ** 40) & 0xff;
  b[1] = (ts / 2 ** 32) & 0xff;
  b[2] = (ts >>> 24) & 0xff;
  b[3] = (ts >>> 16) & 0xff;
  b[4] = (ts >>> 8) & 0xff;
  b[5] = ts & 0xff;
  b[6] = (rand[0] & 0x0f) | 0x70; // version 7
  b[7] = rand[1];
  b[8] = (rand[2] & 0x3f) | 0x80; // variant RFC4122
  b[9] = rand[3];
  for (let i = 10; i < 16; i += 1) b[i] = rand[i - 6];

  const hex: string[] = [];
  for (let i = 0; i < 16; i += 1) hex.push(b[i].toString(16).padStart(2, "0"));
  return (
    hex.slice(0, 4).join("") +
    "-" +
    hex.slice(4, 6).join("") +
    "-" +
    hex.slice(6, 8).join("") +
    "-" +
    hex.slice(8, 10).join("") +
    "-" +
    hex.slice(10, 16).join("")
  );
}

export interface RegisterResult {
  userId: string;
}

/** Run the full register pipeline + log in. On success, the in-memory
 *  session is populated identically to login(); caller can route
 *  straight into the unlocked shell. */
export async function register(
  rawEmail: string,
  password: string,
  rememberMe: boolean,
): Promise<RegisterResult> {
  const email = rawEmail.trim().toLowerCase();
  if (!email.includes("@")) throw new Error("Invalid email address.");
  if (password.length < 8)
    throw new Error("Master password must be at least 8 characters.");

  const hekate = await loadHekateCore();

  if (!hekate.kdfParamsAreSafe(DEFAULT_KDF_PARAMS)) {
    throw new Error(
      "Bundled KDF defaults are below the safety floor — refusing to register.",
    );
  }

  // 1. Salt + KDF defaults.
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  // 2. Master key derivatives.
  const mk = hekate.deriveMasterKey(enc.encode(password), DEFAULT_KDF_PARAMS, salt);
  const mphB64 = b64encode(hekate.deriveMasterPasswordHash(mk));
  const smk = hekate.deriveStretchedMasterKey(mk);
  const kdfParamsMacB64 = b64encode(hekate.computeKdfBindMac(mk, DEFAULT_KDF_PARAMS, salt));

  // 3. Account key + X25519 keypair.
  const accountKey = hekate.randomKey32();
  const x25519 = hekate.generateX25519();
  const accountPriv = x25519.secret;
  const accountPub = x25519.public;

  // 4. Wrap account_key under SMK + priv under account_key.
  const protectedAccountKey = hekate.encStringEncryptXc20p(
    "smk:1",
    smk,
    accountKey,
    enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
  );
  const protectedAccountPrivateKey = hekate.encStringEncryptXc20p(
    "ak:1",
    accountKey,
    accountPriv,
    enc.encode(AAD_PROTECTED_ACCOUNT_PRIV),
  );

  // 5. Signing seed + pubkey.
  const signingSeed = hekate.deriveAccountSigningSeed(mk);
  const signingPubkey = hekate.verifyingKeyFromSeed(signingSeed);

  // 6. UUIDv7 + bundle sig.
  const userId = uuidv7();
  const bundleSig = hekate.signPubkeyBundle(signingSeed, userId, signingPubkey, accountPub);

  // 7. Register.
  await postJSON<{ user_id: string }>("/api/v1/accounts/register", {
    email,
    kdf_params: DEFAULT_KDF_PARAMS,
    kdf_salt: b64encode(salt),
    kdf_params_mac: kdfParamsMacB64,
    master_password_hash: mphB64,
    protected_account_key: protectedAccountKey,
    account_public_key: b64encode(accountPub),
    protected_account_private_key: protectedAccountPrivateKey,
    account_signing_pubkey: b64encode(signingPubkey),
    user_id: userId,
    account_pubkey_bundle_sig: b64encode(bundleSig),
  });

  // 8. Token grant + finalize. A freshly-registered account can't have
  //    2FA enrolled yet, so we never expect the two_factor_required
  //    branch — surface it as an error if the server somehow returns it.
  const tokR = await fetch("/identity/connect/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "password",
      username: email,
      password: mphB64,
    }).toString(),
  });
  let tokBody: unknown = null;
  try {
    tokBody = await tokR.json();
  } catch {
    /* empty / non-JSON */
  }
  if (!tokR.ok) {
    let msg = `login after register failed: ${tokR.status}`;
    if (
      typeof tokBody === "object" &&
      tokBody !== null &&
      typeof (tokBody as { error?: unknown }).error === "string"
    ) {
      msg = (tokBody as { error: string }).error;
    }
    throw new ApiError(tokR.status, msg, tokBody);
  }
  const tok = tokBody as TokenResponse;

  finalizeRegistration(hekate, mk, accountKey, signingSeed, signingPubkey, email, tok, rememberMe);

  return { userId };
}

function finalizeRegistration(
  _hekate: HekateCore,
  _mk: Uint8Array,
  accountKey: Uint8Array,
  signingSeed: Uint8Array,
  signingPubkey: Uint8Array,
  email: string,
  tok: TokenResponse,
  rememberMe: boolean,
): void {
  // Mirrors auth.ts::finalizeLogin, but we already have the unwrapped
  // account_key on hand (we just generated it), so skip the
  // protected_account_key round-trip the login path needs.
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
