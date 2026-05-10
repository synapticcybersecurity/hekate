/* Peer-pin (TOFU) management (C.7d-4).
 *
 * Pins are entirely client-side — there's no server endpoint. Each
 * pin is a `(user_id, signing_pubkey, x25519_pubkey, bundle_sig,
 * fingerprint, first_seen_at)` snapshot of a peer's pubkey bundle the
 * first time we encountered it. Subsequent encounters MUST match
 * byte-for-byte; a mismatch is either an attempted server substitution
 * or a legitimate peer-key rotation, and the user has to disambiguate
 * out-of-band before re-pinning.
 *
 * Storage: localStorage under `hekate.peer_pins:<email>` so a different
 * user logging in on the same browser doesn't inherit prior trust set.
 * Email is stable per-account today (no change-email flow); when one
 * lands, this key migrates to user_id.
 *
 * The web vault's pin store is INDEPENDENT of the popup's
 * `chrome.storage.local["hekate_pins:<user_id>"]` and the CLI's
 * state-file pins. Pinning in one client doesn't propagate to others;
 * future work could add a server-backed sync (encrypted under
 * account_key) but for now each client maintains its own trust set.
 */
import { ApiError, apiGet } from "./api";
import { b64decode, b64encode } from "./base64";
import { getSession } from "./session";
import { loadHekateCore } from "../wasm";

export interface PeerPin {
  user_id: string;
  /** Email captured at pin time, only when the user looked up via the
   *  email-based `/users/lookup?email=` path. UUID-based pins start
   *  with this missing and pick it up on the next email-based
   *  re-encounter. Optional because the by-id pubkey endpoint
   *  (`/users/{id}/pubkeys`) doesn't return email. */
  email?: string;
  account_signing_pubkey_b64: string;
  account_public_key_b64: string;
  account_pubkey_bundle_sig_b64: string;
  /** `SHA256:<base64-no-pad>` over the canonical pubkey-bundle bytes. */
  fingerprint: string;
  first_seen_at: string;
}

/** Wire shape returned by `/api/v1/users/lookup?email=` and
 *  `/api/v1/users/{user_id}/pubkeys`. */
export interface PubkeyBundle {
  user_id: string;
  account_signing_pubkey: string;
  account_public_key: string;
  account_pubkey_bundle_sig: string;
}

const PIN_PREFIX = "hekate.peer_pins:";

function pinKey(email: string): string {
  return PIN_PREFIX + email.toLowerCase();
}

/** Load all locally-pinned peers for the current account. Empty list
 *  if no session or no pins yet. */
export function loadPeerPins(): PeerPin[] {
  const session = getSession();
  if (!session) return [];
  const raw = localStorage.getItem(pinKey(session.email));
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed as PeerPin[];
  } catch {
    return [];
  }
}

/** Replace the persisted pin list. Caller is responsible for
 *  generating a sensibly-ordered list (insertion order is preserved). */
function savePeerPins(pins: PeerPin[]): void {
  const session = getSession();
  if (!session) throw new Error("session expired — log in again");
  localStorage.setItem(pinKey(session.email), JSON.stringify(pins));
}

/** Compute `SHA256:<b64-no-pad>` from the canonical bytes the server
 *  signed (and that hekate-core's `pubkey_bundle_canonical_bytes`
 *  derives from `(user_id, signing_pk, x25519_pk)`). */
async function fingerprintFor(
  userId: string,
  signingPk: Uint8Array,
  x25519Pk: Uint8Array,
): Promise<string> {
  const hekate = await loadHekateCore();
  const canonical = hekate.pubkeyBundleCanonicalBytes(userId, signingPk, x25519Pk);
  const digest = hekate.sha256(canonical);
  return `SHA256:${b64encode(digest)}`;
}

/** Compute the caller's OWN fingerprint from their session — useful
 *  for printing in the UI so peers can pin them. Round-trips
 *  through `/api/v1/users/lookup?email=` since the session doesn't
 *  carry the X25519 pubkey, but the lookup is auth'd and trustworthy
 *  enough for "tell me about myself" purposes. */
export async function myFingerprint(): Promise<{
  userId: string;
  fingerprint: string;
}> {
  const session = getSession();
  if (!session) throw new Error("session expired — log in again");
  const bundle = await apiGet<PubkeyBundle>(
    `/api/v1/users/lookup?email=${encodeURIComponent(session.email)}`,
  );
  const signingPk = b64decode(bundle.account_signing_pubkey);
  const x25519Pk = b64decode(bundle.account_public_key);
  const fp = await fingerprintFor(bundle.user_id, signingPk, x25519Pk);
  return { userId: bundle.user_id, fingerprint: fp };
}

/** Resolve an email-or-uuid input into a pubkey bundle. Email goes
 *  through the auth'd `lookup` endpoint; UUID goes through the
 *  unauthenticated by-id endpoint (server already rate-limits). */
async function fetchBundle(emailOrUuid: string): Promise<PubkeyBundle> {
  const trimmed = emailOrUuid.trim();
  if (!trimmed) throw new Error("peer email or user_id is required");
  const url = trimmed.includes("@")
    ? `/api/v1/users/lookup?email=${encodeURIComponent(trimmed)}`
    : `/api/v1/users/${encodeURIComponent(trimmed)}/pubkeys`;
  try {
    return await apiGet<PubkeyBundle>(url);
  } catch (err) {
    if (
      err instanceof ApiError &&
      err.status === 404 &&
      trimmed.includes("@")
    ) {
      throw new Error(
        `no user found for "${trimmed}" on this server — confirm the address with the peer.`,
      );
    }
    throw err;
  }
}

/** Either a fresh pin to confirm (TOFU first-seen) or an existing
 *  match. The UI shows the fingerprint and asks the user to confirm
 *  out-of-band before committing. `email` is set only when the user
 *  resolved via the email path; it's threaded through `commitPin` so
 *  the persisted pin record can show a human-readable label. */
export type ResolveResult =
  | { kind: "fresh"; bundle: PubkeyBundle; fingerprint: string; email?: string }
  | { kind: "match"; pin: PeerPin };

/** Look up a peer + verify the bundle self-sig + decide whether this
 *  is a TOFU first-seen (caller confirms then commits) or a clean
 *  re-encounter of an existing pin. Mismatch throws — UI surfaces the
 *  full diagnostic so the user can `unpin` after out-of-band
 *  reconciliation. */
export async function resolvePeer(emailOrUuid: string): Promise<ResolveResult> {
  const hekate = await loadHekateCore();
  const trimmed = emailOrUuid.trim();
  const lookedUpByEmail = trimmed.includes("@");
  const bundle = await fetchBundle(trimmed);
  const signingPk = b64decode(bundle.account_signing_pubkey);
  const x25519Pk = b64decode(bundle.account_public_key);
  const sig = b64decode(bundle.account_pubkey_bundle_sig);
  if (!hekate.verifyPubkeyBundle(bundle.user_id, signingPk, x25519Pk, sig)) {
    throw new Error(
      "peer bundle self-signature did not verify — server may be attempting substitution. Refusing to pin.",
    );
  }
  const fingerprint = await fingerprintFor(bundle.user_id, signingPk, x25519Pk);
  const pins = loadPeerPins();
  const existing = pins.find((p) => p.user_id === bundle.user_id);
  if (existing) {
    if (
      existing.account_signing_pubkey_b64 === bundle.account_signing_pubkey &&
      existing.account_public_key_b64 === bundle.account_public_key &&
      existing.account_pubkey_bundle_sig_b64 === bundle.account_pubkey_bundle_sig
    ) {
      // Backfill the email if we just learned it via the lookup path
      // and the stored pin (e.g. one created by UUID, or pre-email
      // schema) doesn't have it yet.
      if (lookedUpByEmail && !existing.email) {
        existing.email = trimmed.toLowerCase();
        savePeerPins(pins);
      }
      return { kind: "match", pin: existing };
    }
    throw new Error(
      `Pin mismatch for ${bundle.user_id} — first seen ${existing.first_seen_at} ` +
        `with fingerprint ${existing.fingerprint}; server now claims ${fingerprint}. ` +
        `Either the server is attempting substitution, or the peer legitimately ` +
        `rotated their keys. Verify out-of-band, unpin, then re-pin.`,
    );
  }
  return {
    kind: "fresh",
    bundle,
    fingerprint,
    email: lookedUpByEmail ? trimmed.toLowerCase() : undefined,
  };
}

/** Commit a fresh pin (caller has already confirmed the fingerprint
 *  out-of-band). Idempotent — re-committing the same bundle is a
 *  no-op. `email` is the address the user typed when looking up by
 *  email; pass undefined for UUID-based lookups (the by-id pubkey
 *  endpoint doesn't return email). */
export function commitPin(
  bundle: PubkeyBundle,
  fingerprint: string,
  email?: string,
): PeerPin {
  const pin: PeerPin = {
    user_id: bundle.user_id,
    email: email?.toLowerCase(),
    account_signing_pubkey_b64: bundle.account_signing_pubkey,
    account_public_key_b64: bundle.account_public_key,
    account_pubkey_bundle_sig_b64: bundle.account_pubkey_bundle_sig,
    fingerprint,
    first_seen_at: new Date().toISOString(),
  };
  const pins = loadPeerPins();
  const existingIdx = pins.findIndex((p) => p.user_id === pin.user_id);
  if (existingIdx >= 0) {
    pins[existingIdx] = pin;
  } else {
    pins.push(pin);
  }
  savePeerPins(pins);
  return pin;
}

/** Drop the pin for `userId`. Returns true if a pin was removed,
 *  false if none existed. */
export function unpinPeer(userId: string): boolean {
  const pins = loadPeerPins();
  const idx = pins.findIndex((p) => p.user_id === userId);
  if (idx < 0) return false;
  pins.splice(idx, 1);
  savePeerPins(pins);
  return true;
}
