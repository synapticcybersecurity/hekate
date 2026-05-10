/* Org write pipelines (C.6) — port of popup.js's M3.14a-d flows.
 *
 * Five surfaces:
 *   - createOrg       — generate org keypair, sign bundle, build genesis
 *                        roster, POST. Pin our own org locally.
 *   - invitePeer      — fetch + verify peer bundle, advance roster,
 *                        signcrypt the org_sym_key + payload, POST.
 *   - listInvites     — GET /api/v1/account/invites.
 *   - acceptInvite    — verify-decrypt envelope under inviter's pinned
 *                        signing key, verify roster, re-wrap org_sym_key
 *                        under our account_key, POST accept, pin org.
 *   - collections     — list + create + delete; names are encrypted
 *                        under the org_sym_key, AAD-bound to
 *                        (collection_id, org_id).
 *
 * Cryptographic invariants preserved verbatim from the CLI/popup:
 *   - Owner signs the org bundle; consumers verify under the OWNER's
 *     pubkey (TOFU-pinned).
 *   - Roster signed under the org's Ed25519 key; consumers verify under
 *     the org's pubkey (TOFU-pinned, learned at accept time).
 *   - Invitee's protected_org_key is freshly wrapped under THEIR
 *     account_key on accept (server never sees plaintext).
 *   - Collection names AAD-bound to (collection_id, org_id) so server
 *     can't move a name between collections.
 */
import { ApiError, apiGet, authedFetch } from "./api";
import { b64decode, b64encode, b64urlDecode } from "./base64";
import { getSession, type Session } from "./session";
import { loadOrgPins, pinOrg } from "./orgPins";
import { commitPin, loadPeerPins, type PeerPin } from "./peerPins";
import type { OrgFull, PolicyView, SignedOrgRosterWire } from "./orgs";
import { loadHekateCore } from "../wasm";

const AAD_PROTECTED_ACCOUNT_KEY = "pmgr-account-key";
const AAD_ORG_SIGNING_SEED = "pmgr-org-signing-seed";
const enc = new TextEncoder();
const dec = new TextDecoder();

/** Pull our own user_id from the access token's `sub` claim. The web
 *  session doesn't carry it explicitly today; decoding the JWT avoids
 *  an extra /whoami round-trip. Same approach as the popup. */
function currentUserId(s: Session): string {
  const parts = s.accessToken.split(".");
  if (parts.length !== 3) throw new Error("malformed access_token");
  const claims = JSON.parse(dec.decode(b64urlDecode(parts[1]))) as { sub?: string };
  if (!claims.sub) throw new Error("access_token has no sub claim");
  return claims.sub;
}

function requireSession(): Session {
  const s = getSession();
  if (!s) throw new Error("session expired — log in again");
  return s;
}

// =====================================================================
// Create org
// =====================================================================

export interface CreateOrgResult {
  orgId: string;
  fingerprint: string;
}

export async function createOrg(name: string): Promise<CreateOrgResult> {
  const trimmed = name.trim();
  if (!trimmed) throw new Error("name is required");
  const s = requireSession();
  const hekate = await loadHekateCore();
  const ownerUserId = currentUserId(s);

  // 1. Org Ed25519 signing keypair.
  const orgSigningSeed = hekate.randomKey32();
  const orgSigningPubkey = hekate.verifyingKeyFromSeed(orgSigningSeed);

  // 2. IDs.
  const orgId = uuidv4();
  const orgSymKeyId = uuidv4();

  // 3. Owner signs the org bundle (binds owner identity → org id +
  //    name + org signing pubkey). Verifiable end-to-end by anyone
  //    who has TOFU-pinned the owner.
  const bundleSig = hekate.signOrgBundle(
    s.signingSeed,
    orgId,
    trimmed,
    orgSigningPubkey,
    ownerUserId,
  );

  // 4. Wrap the org signing seed under owner account_key.
  const protectedSigningSeed = hekate.encStringEncryptXc20p(
    "ak:1",
    s.accountKey,
    orgSigningSeed,
    enc.encode(AAD_ORG_SIGNING_SEED),
  );

  // 5. Generate org symmetric key + wrap under account_key.
  const orgSymKey = hekate.randomKey32();
  const ownerProtectedOrgKey = hekate.encStringEncryptXc20p(
    "ak:1",
    s.accountKey,
    orgSymKey,
    enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
  );

  // 6. Genesis roster (version 1, all-zero parent).
  const noParent = new Uint8Array(32);
  const signedRoster = hekate.signOrgRoster(orgSigningSeed, {
    orgId,
    version: 1,
    parentCanonicalSha256: noParent,
    timestamp: new Date().toISOString(),
    entries: [{ userId: ownerUserId, role: "owner" }],
    orgSymKeyId,
  });

  // 7. POST.
  await authedFetchJSON("POST", "/api/v1/orgs", {
    id: orgId,
    name: trimmed,
    signing_pubkey: b64encode(orgSigningPubkey),
    bundle_sig: b64encode(bundleSig),
    protected_signing_seed: protectedSigningSeed,
    org_sym_key_id: orgSymKeyId,
    owner_protected_org_key: ownerProtectedOrgKey,
    roster: {
      canonical_b64: signedRoster.canonicalB64,
      signature_b64: signedRoster.signatureB64,
    },
  });

  // 8. Pin our own org locally — /sync verification needs an anchor.
  const bundleCanonical = hekate.orgBundleCanonicalBytes(
    orgId,
    trimmed,
    orgSigningPubkey,
    ownerUserId,
  );
  const fingerprint = "SHA256:" + b64encode(hekate.sha256(bundleCanonical));
  pinOrg(orgId, {
    org_id: orgId,
    signing_pubkey_b64: b64encode(orgSigningPubkey),
    fingerprint,
    first_seen_at: new Date().toISOString(),
    last_roster_version: 1,
    last_roster_canonical_b64: signedRoster.canonicalB64,
  });

  return { orgId, fingerprint };
}

// =====================================================================
// Invite peer
// =====================================================================

interface PubkeyBundle {
  user_id: string;
  account_signing_pubkey: string;
  account_public_key: string;
  account_pubkey_bundle_sig: string;
}

export interface PendingInviteFingerprint {
  /** Caller resolves the peer first; if the bundle is fresh (not
   *  pinned), the UI shows this fingerprint for out-of-band
   *  confirmation. After confirm, caller invokes
   *  `commitInvitePeer(prepared, role)`. */
  bundle: PubkeyBundle;
  fingerprint: string;
  /** Set when looked up by email; undefined for UUID lookups. */
  email?: string;
}

export type ResolvePeerForInvite =
  | { kind: "fresh"; pending: PendingInviteFingerprint }
  | { kind: "match"; bundle: PubkeyBundle; pin: PeerPin };

/** Step 1 of invite — fetch peer bundle, verify self-sig, decide
 *  whether to TOFU-confirm (fresh) or proceed (pin matches). Throws
 *  on pin mismatch. Mirrors the resolvePeer flow in lib/peerPins.ts. */
export async function resolvePeerForInvite(
  emailOrUuid: string,
): Promise<ResolvePeerForInvite> {
  const trimmed = emailOrUuid.trim();
  if (!trimmed) throw new Error("peer email or user_id is required");
  const hekate = await loadHekateCore();
  const lookedUpByEmail = trimmed.includes("@");
  const url = lookedUpByEmail
    ? `/api/v1/users/lookup?email=${encodeURIComponent(trimmed)}`
    : `/api/v1/users/${encodeURIComponent(trimmed)}/pubkeys`;
  let bundle: PubkeyBundle;
  try {
    bundle = await apiGet<PubkeyBundle>(url);
  } catch (err) {
    if (lookedUpByEmail && err instanceof ApiError && err.status === 404) {
      throw new Error(
        `no user found for "${trimmed}" on this server — confirm the address with the peer.`,
      );
    }
    throw err;
  }
  const signingPk = b64decode(bundle.account_signing_pubkey);
  const x25519Pk = b64decode(bundle.account_public_key);
  const sig = b64decode(bundle.account_pubkey_bundle_sig);
  if (!hekate.verifyPubkeyBundle(bundle.user_id, signingPk, x25519Pk, sig)) {
    throw new Error(
      "peer bundle self-sig did not verify — server may be attempting substitution",
    );
  }
  const canonical = hekate.pubkeyBundleCanonicalBytes(bundle.user_id, signingPk, x25519Pk);
  const fingerprint = "SHA256:" + b64encode(hekate.sha256(canonical));

  // Compare against existing peer pin (cross-store w/ peerPins.ts).
  const pins = loadPeerPins();
  const existing = pins.find((p) => p.user_id === bundle.user_id);
  if (existing) {
    if (
      existing.account_signing_pubkey_b64 !== bundle.account_signing_pubkey ||
      existing.account_public_key_b64 !== bundle.account_public_key ||
      existing.account_pubkey_bundle_sig_b64 !== bundle.account_pubkey_bundle_sig
    ) {
      throw new Error(
        `pin mismatch for ${bundle.user_id} — first seen ${existing.first_seen_at} ` +
          `with fingerprint ${existing.fingerprint}, server now claims ${fingerprint}. ` +
          `Refusing to overwrite.`,
      );
    }
    return { kind: "match", bundle, pin: existing };
  }
  return {
    kind: "fresh",
    pending: {
      bundle,
      fingerprint,
      email: lookedUpByEmail ? trimmed.toLowerCase() : undefined,
    },
  };
}

/** Step 2 of invite — caller has either confirmed the fresh fingerprint
 *  (TOFU) or skipped because the pin matched. Pins the peer (idempotent
 *  for matches) and posts the invite. */
export async function commitInvitePeer(
  orgId: string,
  bundle: PubkeyBundle,
  role: "admin" | "user",
): Promise<void> {
  const s = requireSession();
  const hekate = await loadHekateCore();
  const ownerUserId = currentUserId(s);

  // Pin (or refresh existing pin idempotently). Reuses peerPins
  // store — invite + share have the same trust set.
  const peerSigningPk = b64decode(bundle.account_signing_pubkey);
  const peerX25519Pk = b64decode(bundle.account_public_key);
  const peerCanonical = hekate.pubkeyBundleCanonicalBytes(
    bundle.user_id,
    peerSigningPk,
    peerX25519Pk,
  );
  const peerFp = "SHA256:" + b64encode(hekate.sha256(peerCanonical));
  // Add (or no-op refresh) the peer pin via the existing peerPins
  // helper so the user's invite-side trust matches their share-side.
  commitPin(bundle, peerFp, /* email */ undefined);

  // Pull the org so we can advance the roster + unwrap the org sym
  // key + signing seed.
  const org = await apiGet<OrgFull>(`/api/v1/orgs/${encodeURIComponent(orgId)}`);
  if (org.owner_user_id !== ownerUserId) {
    throw new Error("only the org owner can invite members");
  }
  if (!org.owner_protected_signing_seed) {
    throw new Error("server omitted owner_protected_signing_seed");
  }
  const orgSymKey = hekate.encStringDecryptXc20p(
    org.my_protected_org_key,
    s.accountKey,
    enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
  );
  const orgSigningSeed = hekate.encStringDecryptXc20p(
    org.owner_protected_signing_seed,
    s.accountKey,
    enc.encode(AAD_ORG_SIGNING_SEED),
  );

  const currentCanonical = b64decode(org.roster.canonical_b64);
  const current = hekate.decodeOrgRosterCanonical(currentCanonical);
  if (current.entries.some((e) => e.userId === bundle.user_id)) {
    throw new Error("peer is already in the roster");
  }
  const nextRoster = {
    orgId: org.id,
    version: current.version + 1,
    parentCanonicalSha256: hekate.sha256(currentCanonical),
    timestamp: new Date().toISOString(),
    entries: current.entries.concat([{ userId: bundle.user_id, role }]),
    orgSymKeyId: org.org_sym_key_id,
  };
  const signedNext = hekate.signOrgRoster(orgSigningSeed, nextRoster);

  // Build payload + signcrypt.
  const orgPin = loadOrgPins()[orgId];
  if (!orgPin) {
    throw new Error(
      "we don't have a pin for this org — re-pin via the org list before inviting.",
    );
  }
  const payload = JSON.stringify({
    org_id: org.id,
    org_signing_pubkey_b64: org.signing_pubkey,
    org_bundle_sig_b64: org.bundle_sig,
    org_name: org.name,
    org_sym_key_id: org.org_sym_key_id,
    org_sym_key_b64: b64encode(orgSymKey),
    role,
  });
  const envelope = hekate.signcryptSealEnvelope(
    s.signingSeed,
    ownerUserId,
    bundle.user_id,
    peerX25519Pk,
    enc.encode(payload),
  );

  await authedFetchJSON("POST", `/api/v1/orgs/${encodeURIComponent(orgId)}/invites`, {
    invitee_user_id: bundle.user_id,
    role,
    envelope,
    next_roster: {
      canonical_b64: signedNext.canonicalB64,
      signature_b64: signedNext.signatureB64,
    },
  });
}

// =====================================================================
// Invites (recipient side)
// =====================================================================

export interface InviteView {
  org_id: string;
  org_name: string;
  inviter_user_id: string;
  role: "admin" | "user";
  envelope: unknown;
  invited_at: string;
  roster_version: number;
  roster: SignedOrgRosterWire;
}

export function listInvites(): Promise<InviteView[]> {
  return apiGet<InviteView[]>("/api/v1/account/invites");
}

/** Accept an invite. Requires the inviter to be peer-pinned already
 *  (so we can verify the envelope's signer). On success, pins the org
 *  locally and returns its fingerprint for UI display. */
export async function acceptInvite(invite: InviteView): Promise<{ fingerprint: string }> {
  const s = requireSession();
  const hekate = await loadHekateCore();
  if (!s.protectedAccountPrivateKey) {
    throw new Error(
      "session is missing protected_account_private_key — log out and back in",
    );
  }
  const myUserId = currentUserId(s);

  // Inviter must be pinned. We re-bind to the pin (not the envelope's
  // self-claim) for security.
  const peerPins = loadPeerPins();
  const inviterPin = peerPins.find((p) => p.user_id === invite.inviter_user_id);
  if (!inviterPin) {
    throw new Error(
      `inviter ${invite.inviter_user_id} is not pinned — pin them via the peer pins panel before accepting.`,
    );
  }
  const inviterSigningPk = b64decode(inviterPin.account_signing_pubkey_b64);

  // Decrypt our own X25519 priv (wrapped under account_key).
  const myX25519Priv = hekate.encStringDecryptXc20p(
    s.protectedAccountPrivateKey,
    s.accountKey,
    enc.encode("pmgr-account-x25519-priv"),
  );

  // Verify-decrypt envelope.
  const plaintext = hekate.signcryptOpenEnvelope(
    invite.envelope,
    inviterSigningPk,
    myUserId,
    myX25519Priv,
  );
  const payload = JSON.parse(dec.decode(plaintext)) as {
    org_id: string;
    org_signing_pubkey_b64: string;
    org_bundle_sig_b64: string;
    org_name: string;
    org_sym_key_id: string;
    org_sym_key_b64: string;
    role: string;
  };
  if (payload.org_id !== invite.org_id) {
    throw new Error("envelope org_id != invite org_id — server tampering?");
  }
  if (payload.role !== invite.role) {
    throw new Error("envelope role != invite role — server tampering?");
  }

  const orgSigningPk = b64decode(payload.org_signing_pubkey_b64);
  const orgBundleSig = b64decode(payload.org_bundle_sig_b64);
  if (orgSigningPk.length !== 32) throw new Error("org signing key wrong length");
  if (orgBundleSig.length !== 64) throw new Error("org bundle sig wrong length");

  // Verify org bundle sig under inviter's PINNED key.
  if (
    !hekate.verifyOrgBundle(
      inviterSigningPk,
      invite.org_id,
      payload.org_name,
      orgSigningPk,
      invite.inviter_user_id,
      orgBundleSig,
    )
  ) {
    throw new Error("org bundle sig did not verify under inviter's pinned key");
  }

  // Verify roster under (now-trusted) org signing key + we're listed.
  const roster = hekate.verifyOrgRoster(
    orgSigningPk,
    invite.roster.canonical_b64,
    invite.roster.signature_b64,
  );
  const me = roster.entries.find((entry) => entry.userId === myUserId);
  if (!me) throw new Error("roster does not list us — server tampering?");
  if (me.role !== invite.role) {
    throw new Error("roster role != claimed invite role — server tampering?");
  }

  // Re-wrap the org sym key under our account_key.
  const orgSymKey = b64decode(payload.org_sym_key_b64);
  if (orgSymKey.length !== 32) throw new Error("org sym key wrong length");
  const protectedOrgKey = hekate.encStringEncryptXc20p(
    "ak:1",
    s.accountKey,
    orgSymKey,
    enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
  );

  await authedFetchJSON(
    "POST",
    `/api/v1/orgs/${encodeURIComponent(invite.org_id)}/accept`,
    {
      protected_org_key: protectedOrgKey,
      org_sym_key_id: payload.org_sym_key_id,
    },
  );

  // Pin the org locally for /sync verification.
  const bundleCanonical = hekate.orgBundleCanonicalBytes(
    invite.org_id,
    payload.org_name,
    orgSigningPk,
    invite.inviter_user_id,
  );
  const fingerprint = "SHA256:" + b64encode(hekate.sha256(bundleCanonical));
  pinOrg(invite.org_id, {
    org_id: invite.org_id,
    signing_pubkey_b64: payload.org_signing_pubkey_b64,
    fingerprint,
    first_seen_at: new Date().toISOString(),
    last_roster_version: roster.version,
    last_roster_canonical_b64: invite.roster.canonical_b64,
  });
  return { fingerprint };
}

// =====================================================================
// Collections
// =====================================================================

export interface CollectionView {
  id: string;
  org_id: string;
  /** Encrypted (XChaCha20-Poly1305, AAD-bound to (id, org_id)). */
  name: string;
  revision_date: string;
  creation_date: string;
}

export interface DecodedCollection extends CollectionView {
  decryptedName: string;
}

/** List collections in an org. Decrypts names client-side using the
 *  org sym key from the OrgFull's `my_protected_org_key`. */
export async function listCollections(orgId: string): Promise<DecodedCollection[]> {
  const s = requireSession();
  const hekate = await loadHekateCore();

  const [org, raw] = await Promise.all([
    apiGet<OrgFull>(`/api/v1/orgs/${encodeURIComponent(orgId)}`),
    apiGet<CollectionView[]>(`/api/v1/orgs/${encodeURIComponent(orgId)}/collections`),
  ]);
  const orgSymKey = hekate.encStringDecryptXc20p(
    org.my_protected_org_key,
    s.accountKey,
    enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
  );
  return raw.map((c) => {
    let decryptedName = "<undecryptable>";
    try {
      const aad = hekate.collectionNameAad(c.id, c.org_id);
      decryptedName = dec.decode(
        hekate.encStringDecryptXc20p(c.name, orgSymKey, aad),
      );
    } catch {
      /* leave placeholder */
    }
    return { ...c, decryptedName };
  });
}

export async function createCollection(orgId: string, name: string): Promise<void> {
  const trimmed = name.trim();
  if (!trimmed) throw new Error("name is required");
  const s = requireSession();
  const hekate = await loadHekateCore();

  const org = await apiGet<OrgFull>(`/api/v1/orgs/${encodeURIComponent(orgId)}`);
  const orgSymKey = hekate.encStringDecryptXc20p(
    org.my_protected_org_key,
    s.accountKey,
    enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
  );

  const collectionId = uuidv4();
  const aad = hekate.collectionNameAad(collectionId, orgId);
  const nameWire = hekate.encStringEncryptXc20p(
    "ok:1",
    orgSymKey,
    enc.encode(trimmed),
    aad,
  );
  await authedFetchJSON(
    "POST",
    `/api/v1/orgs/${encodeURIComponent(orgId)}/collections`,
    { id: collectionId, name: nameWire },
  );
}

export async function deleteCollection(orgId: string, collectionId: string): Promise<void> {
  const r = await authedFetch(
    "DELETE",
    `/api/v1/orgs/${encodeURIComponent(orgId)}/collections/${encodeURIComponent(collectionId)}`,
  );
  if (!r.ok && r.status !== 204) {
    let body: unknown = null;
    try {
      body = await r.json();
    } catch {
      /* empty */
    }
    let msg = `${r.status} ${r.statusText}`;
    if (body && typeof body === "object" && "error" in body) {
      const e = (body as { error?: unknown }).error;
      if (typeof e === "string" && e) msg = e;
    }
    throw new ApiError(r.status, msg, body);
  }
}

// =====================================================================
// Helpers
// =====================================================================

/** Generic authed fetch + JSON response handling, tolerant of empty
 *  bodies (matches the popup's checkResponse fix in commit 2738eed:
 *  201/204 with no body shouldn't blow up r.json()). */
async function authedFetchJSON<T>(
  method: "POST" | "PUT" | "PATCH" | "DELETE",
  path: string,
  body?: unknown,
): Promise<T | null> {
  const r = await authedFetch(method, path, { body });
  if (!r.ok) {
    let errBody: unknown = null;
    try {
      errBody = await r.json();
    } catch {
      /* empty */
    }
    let msg = `${r.status} ${r.statusText}`;
    if (errBody && typeof errBody === "object" && "error" in errBody) {
      const e = (errBody as { error?: unknown }).error;
      if (typeof e === "string" && e) msg = e;
    }
    throw new ApiError(r.status, msg, errBody);
  }
  if (r.status === 204) return null;
  const text = await r.text();
  if (!text) return null;
  return JSON.parse(text) as T;
}

/** RFC 4122 v4 UUID — random 122 bits + version + variant. The web
 *  vault already has a v7 generator in lib/register.ts (timestamp-
 *  prefixed); for org/collection ids we follow the popup's
 *  `crypto.randomUUID()` which is v4. */
function uuidv4(): string {
  // crypto.randomUUID() is widely supported (Chrome 92+, Firefox 95+,
  // Safari 15.4+); web vault is targeting evergreen browsers.
  return crypto.randomUUID();
}

// =====================================================================
// Member removal + org-key rotation (M4.5b)
// =====================================================================

const AAD_CIPHER_KEY_PREFIX = "pmgr-cipher-key-v2:";

interface SyncCipherShape {
  id: string;
  protected_cipher_key: string;
  org_id?: string | null;
}

/** Owner-only. Atomically remove `targetUserId` from the org and
 *  rotate the org symmetric key. Mirrors
 *  `crates/hekate-cli/src/commands/org.rs::remove_member`.
 *
 *  Steps:
 *    1. Verify caller is owner; target ≠ self; target is in roster
 *       and not the owner.
 *    2. Unwrap org signing seed + old org sym key.
 *    3. Build + sign next roster (drop target, version+1, parent hash,
 *       NEW key_id).
 *    4. Generate new org sym key + wrap under owner account_key.
 *    5. For each remaining non-owner: verify TOFU pin matches the
 *       live pubkey bundle, signcrypt the new sym key under their
 *       X25519 pubkey. Refusal here is loud — a missing pin or a
 *       pin/live mismatch means we can't safely re-key to that
 *       member, and silently dropping them would defeat the purpose.
 *    6. Re-wrap every org-owned cipher's per-cipher key under the
 *       new sym key. Per-cipher keys themselves don't change — just
 *       the wrap. Server enforces 1:1 enumeration so silent skips
 *       can't leave a cipher readable only by the revoked member.
 *    7. POST /api/v1/orgs/{org_id}/members/{user_id}/revoke. */
export async function revokeMember(
  orgId: string,
  targetUserId: string,
): Promise<void> {
  const s = requireSession();
  const hekate = await loadHekateCore();
  const myUserId = currentUserId(s);

  if (targetUserId === myUserId) {
    throw new Error(
      "the owner cannot revoke themselves; transfer ownership first (M4 v2)",
    );
  }

  // Fetch org + signing seed + current roster + sym key.
  const org = await apiGet<OrgFull>(`/api/v1/orgs/${encodeURIComponent(orgId)}`);
  if (org.owner_user_id !== myUserId) {
    throw new Error("only the org owner can remove members");
  }
  if (!org.owner_protected_signing_seed) {
    throw new Error("server omitted owner_protected_signing_seed");
  }
  const orgSigningSeed = hekate.encStringDecryptXc20p(
    org.owner_protected_signing_seed,
    s.accountKey,
    enc.encode(AAD_ORG_SIGNING_SEED),
  );
  const oldOrgSymKey = hekate.encStringDecryptXc20p(
    org.my_protected_org_key,
    s.accountKey,
    enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
  );

  // Parse current roster + verify target is removable.
  const currentCanonical = b64decode(org.roster.canonical_b64);
  const current = hekate.decodeOrgRosterCanonical(currentCanonical);
  const targetEntry = current.entries.find((e) => e.userId === targetUserId);
  if (!targetEntry) {
    throw new Error(
      `${targetUserId} is not in the current roster — nothing to revoke`,
    );
  }
  if (targetEntry.role === "owner") {
    throw new Error("cannot revoke the org owner");
  }

  // Build next roster.
  const nextEntries = current.entries.filter((e) => e.userId !== targetUserId);
  const newOrgSymKeyId = uuidv4();
  const nextRoster = {
    orgId: org.id,
    version: current.version + 1,
    parentCanonicalSha256: hekate.sha256(currentCanonical),
    timestamp: new Date().toISOString(),
    entries: nextEntries,
    orgSymKeyId: newOrgSymKeyId,
  };
  const signedNext = hekate.signOrgRoster(orgSigningSeed, nextRoster);

  // Generate new org sym key + owner's wrap.
  const newOrgSymKey = hekate.randomKey32();
  const ownerProtectedOrgKey = hekate.encStringEncryptXc20p(
    "ak:1",
    s.accountKey,
    newOrgSymKey,
    enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
  );

  // Signcrypt new sym key to every remaining non-owner.
  const peerPins = loadPeerPins();
  const rewrapEnvelopes: Array<{ user_id: string; envelope: unknown }> = [];
  for (const entry of nextEntries) {
    if (entry.userId === myUserId) continue; // owner uses owner_protected_org_key
    const pin = peerPins.find((p) => p.user_id === entry.userId);
    if (!pin) {
      throw new Error(
        `remaining member ${entry.userId} is not pinned — pin them via Settings → Manage peer pins (verify the fingerprint out of band) before revoking, otherwise they can't be re-wrapped to.`,
      );
    }
    // Verify the live directory bundle still matches the pin — refuses
    // the rotation if the server has diverged so a malicious server
    // can't substitute a key under cover of the rotation flow.
    const live = await apiGet<{
      account_signing_pubkey: string;
      account_public_key: string;
      account_pubkey_bundle_sig: string;
    }>(`/api/v1/users/${encodeURIComponent(entry.userId)}/pubkeys`);
    if (
      live.account_signing_pubkey !== pin.account_signing_pubkey_b64 ||
      live.account_public_key !== pin.account_public_key_b64 ||
      live.account_pubkey_bundle_sig !== pin.account_pubkey_bundle_sig_b64
    ) {
      throw new Error(
        `server-returned pubkey bundle for ${entry.userId} does not match TOFU pin — refusing to wrap the new org key. Investigate before retrying.`,
      );
    }
    const peerX25519Pk = b64decode(pin.account_public_key_b64);
    const payload = JSON.stringify({
      kind: "pmgr-org-key-rotation-v1",
      org_id: org.id,
      org_sym_key_id: newOrgSymKeyId,
      org_sym_key_b64: b64encode(newOrgSymKey),
    });
    const envelope = hekate.signcryptSealEnvelope(
      s.signingSeed,
      myUserId,
      entry.userId,
      peerX25519Pk,
      enc.encode(payload),
    );
    rewrapEnvelopes.push({ user_id: entry.userId, envelope });
  }

  // Re-wrap every org-owned cipher's PCK under the new sym key.
  // Server requires 1:1 enumeration (silent skips would leave ciphers
  // readable only by the revoked member).
  const sync = await apiGet<{ changes: { ciphers: SyncCipherShape[] } }>(
    "/api/v1/sync",
  );
  const cipherRewraps: Array<{ cipher_id: string; protected_cipher_key: string }> = [];
  for (const c of sync.changes.ciphers) {
    if (c.org_id !== orgId) continue;
    const aad = enc.encode(AAD_CIPHER_KEY_PREFIX + c.id);
    let cipherKeyBytes: Uint8Array;
    try {
      cipherKeyBytes = hekate.encStringDecryptXc20p(
        c.protected_cipher_key,
        oldOrgSymKey,
        aad,
      );
    } catch (err) {
      throw new Error(
        `failed to unwrap cipher ${c.id} under the old org sym key — ` +
          `refusing to rotate; member may already have been removed by another client. ` +
          (err instanceof Error ? err.message : String(err)),
      );
    }
    const newProtected = hekate.encStringEncryptXc20p(
      "ok:1",
      newOrgSymKey,
      cipherKeyBytes,
      aad,
    );
    cipherRewraps.push({ cipher_id: c.id, protected_cipher_key: newProtected });
  }

  // Re-encrypt every collection name under the new sym key. Same 1:1
  // enumeration contract as cipher_rewraps; without it the server
  // would (correctly) reject the revoke. Collection names use the
  // collectionNameAad binding which is independent of the sym key,
  // so we decrypt under old + re-encrypt under new with the same AAD.
  const collections = await apiGet<CollectionView[]>(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/collections`,
  );
  const collectionRewraps: Array<{ collection_id: string; name: string }> = [];
  for (const c of collections) {
    const aad = hekate.collectionNameAad(c.id, c.org_id);
    let nameBytes: Uint8Array;
    try {
      nameBytes = hekate.encStringDecryptXc20p(c.name, oldOrgSymKey, aad);
    } catch (err) {
      throw new Error(
        `failed to decrypt collection ${c.id} name under the old org sym key — ` +
          `refusing to rotate; the collection may have been pre-rotation orphaned ` +
          `(see /prune-roster) or written under a different key. ` +
          (err instanceof Error ? err.message : String(err)),
      );
    }
    const newName = hekate.encStringEncryptXc20p("ok:1", newOrgSymKey, nameBytes, aad);
    collectionRewraps.push({ collection_id: c.id, name: newName });
  }

  // POST.
  await authedFetchJSON(
    "POST",
    `/api/v1/orgs/${encodeURIComponent(orgId)}/members/${encodeURIComponent(targetUserId)}/revoke`,
    {
      next_roster: {
        canonical_b64: signedNext.canonicalB64,
        signature_b64: signedNext.signatureB64,
      },
      next_org_sym_key_id: newOrgSymKeyId,
      owner_protected_org_key: ownerProtectedOrgKey,
      rewrap_envelopes: rewrapEnvelopes,
      cipher_rewraps: cipherRewraps,
      collection_rewraps: collectionRewraps,
    },
  );

  // Refresh our own org pin to track the new sym key id (the
  // signing pubkey is unchanged by a member-removal rotation, so the
  // fingerprint stays the same — we just bump last_roster_*).
  pinOrg(orgId, {
    org_id: orgId,
    signing_pubkey_b64: org.signing_pubkey,
    fingerprint:
      "SHA256:" +
      b64encode(
        hekate.sha256(
          hekate.orgBundleCanonicalBytes(
            orgId,
            org.name,
            b64decode(org.signing_pubkey),
            org.owner_user_id,
          ),
        ),
      ),
    first_seen_at: loadOrgPins()[orgId]?.first_seen_at ?? new Date().toISOString(),
    last_roster_version: nextRoster.version,
    last_roster_canonical_b64: signedNext.canonicalB64,
  });
}

// =====================================================================
// Rotate-confirm — consume an org-key-rotation envelope (member side)
// =====================================================================

const AAD_ACCOUNT_X25519_PRIV = "pmgr-account-x25519-priv";

/** Member-side consumer of the org-key-rotation envelope. The owner
 *  signcrypts the new sym key to each remaining member during a
 *  member-removal rotation; this function verifies + decrypts under
 *  the owner's pinned signing key, re-wraps under the caller's
 *  account_key, and POSTs `/rotate-confirm` to swap the membership
 *  row's `protected_org_key` and clear the pending field.
 *
 *  Cross-checks (see CLI `consume_pending_envelope` for rationale):
 *    - envelope.sender_id MUST equal the org's owner_user_id
 *    - owner MUST be in our peer pins (refuses unpinned envelopes)
 *    - decrypts under our X25519 priv (held in session as
 *      `protectedAccountPrivateKey`, wrapped under account_key)
 *    - payload `kind` MUST be `pmgr-org-key-rotation-v1`
 *    - payload `org_id` MUST equal the entry's org_id
 *    - payload `org_sym_key_id` MUST equal the roster's claimed
 *      orgSymKeyId (the roster is BW08-verified upstream by C.5
 *      strict-manifest checks; this closes the gap where the
 *      server lies about one but not the other) */
export async function confirmRotation(
  orgEntry: { org_id: string; pending_envelope: unknown; roster: { canonical_b64: string } },
): Promise<void> {
  const s = requireSession();
  const hekate = await loadHekateCore();
  if (!s.protectedAccountPrivateKey) {
    throw new Error(
      "session is missing protected_account_private_key — log out and back in",
    );
  }
  const myUserId = currentUserId(s);

  if (!orgEntry.pending_envelope) {
    throw new Error("no pending envelope on this org");
  }

  // Cross-check sender_id against the server-reported owner.
  const owner = await apiGet<{ owner_user_id: string }>(
    `/api/v1/orgs/${encodeURIComponent(orgEntry.org_id)}`,
  );
  const env = orgEntry.pending_envelope as { sender_id?: string };
  if (typeof env.sender_id !== "string" || env.sender_id !== owner.owner_user_id) {
    throw new Error(
      `envelope sender ${env.sender_id ?? "<missing>"} does not match the org ` +
        `owner ${owner.owner_user_id} — possible rotation injection`,
    );
  }

  // Owner must be in our peer pins. Refuses unpinned senders so a
  // malicious server can't substitute its own envelope.
  const peerPins = loadPeerPins();
  const ownerPin = peerPins.find((p) => p.user_id === owner.owner_user_id);
  if (!ownerPin) {
    throw new Error(
      `org owner ${owner.owner_user_id} is not in peer pins — pin them ` +
        `(via Settings → Manage peer pins) and verify the fingerprint out ` +
        `of band before consuming the rotation.`,
    );
  }
  const ownerSigningPk = b64decode(ownerPin.account_signing_pubkey_b64);

  // Decrypt our X25519 priv (wrapped under account_key).
  const myX25519Priv = hekate.encStringDecryptXc20p(
    s.protectedAccountPrivateKey,
    s.accountKey,
    enc.encode(AAD_ACCOUNT_X25519_PRIV),
  );

  const plaintext = hekate.signcryptOpenEnvelope(
    orgEntry.pending_envelope,
    ownerSigningPk,
    myUserId,
    myX25519Priv,
  );
  const payload = JSON.parse(dec.decode(plaintext)) as {
    kind?: string;
    org_id?: string;
    org_sym_key_id?: string;
    org_sym_key_b64?: string;
  };
  if (payload.kind !== "pmgr-org-key-rotation-v1") {
    throw new Error("envelope payload kind is not pmgr-org-key-rotation-v1");
  }
  if (payload.org_id !== orgEntry.org_id) {
    throw new Error(
      "envelope org_id does not match the org being rotated — refusing to consume",
    );
  }
  if (!payload.org_sym_key_id) {
    throw new Error("envelope payload missing org_sym_key_id");
  }

  // Cross-check the claimed key_id against what the verified roster
  // says is current. The roster is signed under the org's pinned
  // key (BW08); the membership row's org_sym_key_id is still the
  // OLD value until /rotate-confirm lands, so we can't compare
  // against that here — the roster is the authoritative source.
  const roster = hekate.decodeOrgRosterCanonical(b64decode(orgEntry.roster.canonical_b64));
  if (payload.org_sym_key_id !== roster.orgSymKeyId) {
    throw new Error(
      `envelope org_sym_key_id (${payload.org_sym_key_id}) does not match the ` +
        `current org_sym_key_id (${roster.orgSymKeyId}) bound into the verified ` +
        `roster — refusing to consume`,
    );
  }

  if (!payload.org_sym_key_b64) {
    throw new Error("envelope payload missing org_sym_key_b64");
  }
  const newSymKey = b64decode(payload.org_sym_key_b64);
  if (newSymKey.length !== 32) {
    throw new Error("new org sym key has wrong length");
  }

  // Re-wrap under our account_key.
  const protectedOrgKey = hekate.encStringEncryptXc20p(
    "ak:1",
    s.accountKey,
    newSymKey,
    enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
  );

  await authedFetchJSON(
    "POST",
    `/api/v1/orgs/${encodeURIComponent(orgEntry.org_id)}/rotate-confirm`,
    {
      protected_org_key: protectedOrgKey,
      org_sym_key_id: payload.org_sym_key_id,
    },
  );

  // Refresh local pin to track the new roster (signing pubkey
  // unchanged by member-removal rotation).
  const existing = loadOrgPins()[orgEntry.org_id];
  if (existing) {
    pinOrg(orgEntry.org_id, {
      ...existing,
      last_roster_version: roster.version,
      last_roster_canonical_b64: orgEntry.roster.canonical_b64,
    });
  }
}

// =====================================================================
// Prune roster (owner-only) — scrub orphans
// =====================================================================

/** Owner-only. Re-sign the roster after dropping `orphanUserIds` —
 *  user_ids that are in the signed roster but have no
 *  `organization_members` row server-side. Pre-GH#2 (migration 0023)
 *  the invite-time roster advancement could leave orphans baked into
 *  the live signed roster; this is the recovery path.
 *
 *  Mirrors the server validation invariants (see
 *  `crates/hekate-server/src/routes/orgs.rs::prune_roster`):
 *  - entries omit each `orphanUserIds` entry
 *  - owner stays at role=owner
 *  - org_sym_key_id unchanged (prune does NOT rotate)
 *  - version + parent hash chain forward */
export async function pruneRoster(
  orgId: string,
  orphanUserIds: string[],
): Promise<void> {
  const s = requireSession();
  const hekate = await loadHekateCore();
  const myUserId = currentUserId(s);

  if (orphanUserIds.length === 0) {
    throw new Error("no orphan user_ids supplied");
  }

  const org = await apiGet<OrgFull>(`/api/v1/orgs/${encodeURIComponent(orgId)}`);
  if (org.owner_user_id !== myUserId) {
    throw new Error("only the org owner can prune the roster");
  }
  if (!org.owner_protected_signing_seed) {
    throw new Error("server omitted owner_protected_signing_seed");
  }
  const orgSigningSeed = hekate.encStringDecryptXc20p(
    org.owner_protected_signing_seed,
    s.accountKey,
    enc.encode(AAD_ORG_SIGNING_SEED),
  );

  const currentCanonical = b64decode(org.roster.canonical_b64);
  const current = hekate.decodeOrgRosterCanonical(currentCanonical);
  const orphanSet = new Set(orphanUserIds);
  const nextEntries = current.entries.filter((e) => !orphanSet.has(e.userId));
  if (nextEntries.length === current.entries.length) {
    throw new Error(
      "no entries match the supplied user_ids — roster may have been pruned by another client",
    );
  }
  if (!nextEntries.some((e) => e.userId === myUserId && e.role === "owner")) {
    throw new Error("refusing to prune the owner from the roster");
  }
  const next = {
    orgId: org.id,
    version: current.version + 1,
    parentCanonicalSha256: hekate.sha256(currentCanonical),
    timestamp: new Date().toISOString(),
    entries: nextEntries,
    orgSymKeyId: org.org_sym_key_id,
  };
  const signedNext = hekate.signOrgRoster(orgSigningSeed, next);

  await authedFetchJSON(
    "POST",
    `/api/v1/orgs/${encodeURIComponent(orgId)}/prune-roster`,
    {
      next_roster: {
        canonical_b64: signedNext.canonicalB64,
        signature_b64: signedNext.signatureB64,
      },
    },
  );

  // Refresh local org pin so /sync verification tracks the new
  // roster_version. Signing pubkey is unchanged, so the bundle
  // fingerprint stays the same.
  const existing = loadOrgPins()[orgId];
  if (existing) {
    pinOrg(orgId, {
      ...existing,
      last_roster_version: next.version,
      last_roster_canonical_b64: signedNext.canonicalB64,
    });
  }
}

// =====================================================================
// Cancel invite (owner-only)
// =====================================================================

/** Owner-only. Cancel an outstanding invite. Server-side this drops
 *  the row from `organization_invites` (and its pending roster); the
 *  live signed roster is untouched because GH#2 means it never
 *  advanced for an invite-only state. Idempotent caller-side: the
 *  server returns 404 when no pending invite exists, which we map to
 *  ApiError(404). */
export async function cancelInvite(
  orgId: string,
  inviteeUserId: string,
): Promise<void> {
  const r = await authedFetch(
    "DELETE",
    `/api/v1/orgs/${encodeURIComponent(orgId)}/invites/${encodeURIComponent(inviteeUserId)}`,
    { body: {} },
  );
  if (!r.ok && r.status !== 204) {
    let body: unknown = null;
    try {
      body = await r.json();
    } catch {
      /* empty */
    }
    let msg = `${r.status} ${r.statusText}`;
    if (body && typeof body === "object" && "error" in body) {
      const e = (body as { error?: unknown }).error;
      if (typeof e === "string" && e) msg = e;
    }
    throw new ApiError(r.status, msg, body);
  }
}

// =====================================================================
// Org policies (M4.6)
// =====================================================================

/** All policy types this server build understands. Mirrors
 *  `POLICY_TYPES` in `crates/hekate-server/src/routes/policies.rs`. */
export const POLICY_TYPES = [
  "master_password_complexity",
  "vault_timeout",
  "password_generator_rules",
  "single_org",
  "restrict_send",
] as const;
export type PolicyType = (typeof POLICY_TYPES)[number];

/** Member-readable. List every policy on this org (both enabled and
 *  disabled rows). The wire field is `config` — same shape /sync
 *  surfaces inline on each `OrgSyncEntry`. */
export async function listPolicies(orgId: string): Promise<PolicyView[]> {
  return apiGet<PolicyView[]>(
    `/api/v1/orgs/${encodeURIComponent(orgId)}/policies`,
  );
}

/** Owner-only. Upsert a policy row. `config` round-trips opaquely so
 *  toggling enabled doesn't drop per-type knobs the user set elsewhere;
 *  defaults to `{}` for first-write. */
export async function setPolicy(
  orgId: string,
  policyType: string,
  enabled: boolean,
  config: unknown = {},
): Promise<PolicyView> {
  const r = await authedFetchJSON<PolicyView>(
    "PUT",
    `/api/v1/orgs/${encodeURIComponent(orgId)}/policies/${encodeURIComponent(policyType)}`,
    { enabled, config },
  );
  if (!r) throw new Error("server returned empty body for policy upsert");
  return r;
}

/** Owner-only. Delete the policy row outright. Idempotent — server
 *  returns 204 even when no row exists. */
export async function removePolicy(
  orgId: string,
  policyType: string,
): Promise<void> {
  const r = await authedFetch(
    "DELETE",
    `/api/v1/orgs/${encodeURIComponent(orgId)}/policies/${encodeURIComponent(policyType)}`,
  );
  if (!r.ok && r.status !== 204) {
    let body: unknown = null;
    try {
      body = await r.json();
    } catch {
      /* empty */
    }
    let msg = `${r.status} ${r.statusText}`;
    if (body && typeof body === "object" && "error" in body) {
      const e = (body as { error?: unknown }).error;
      if (typeof e === "string" && e) msg = e;
    }
    throw new ApiError(r.status, msg, body);
  }
}

// Re-exports for callers that just want the types
export type { OrgPin } from "./orgPins";
