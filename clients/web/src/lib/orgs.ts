/* Orgs read-only types + helpers (C.5).
 *
 * Mirrors the wire shape from
 * `crates/hekate-server/src/routes/sync.rs::OrgSyncEntry`. The web
 * vault doesn't accept invites or create orgs yet — that's C.6, gated
 * on the popup's M3.14a-d browser smoke. Until then we just decode
 * what /sync hands us.
 */
import { apiGet } from "./api";
import { b64decode } from "./base64";
import { loadHekateCore } from "../wasm";

export interface SignedOrgRosterWire {
  org_id: string;
  version: number;
  canonical_b64: string;
  signature_b64: string;
  updated_at: string;
}

export interface PolicyView {
  policy_type: string;
  enabled: boolean;
  /** Per-type config blob; opaque to the M4.6 toggle UI. Schemas live
   *  in the server's `validate_config` (`crates/hekate-server/src/routes/
   *  policies.rs`). */
  config: unknown;
  updated_at: string;
}

export interface OrgCipherManifestView {
  version: number;
  canonical_b64: string;
  signature_b64: string;
  updated_at: string;
}

export interface OrgSyncEntry {
  org_id: string;
  name: string;
  role: "owner" | "admin" | "user";
  org_sym_key_id: string;
  roster_version: number;
  roster_updated_at: string;
  roster: SignedOrgRosterWire;
  pending_envelope?: unknown | null;
  policies?: PolicyView[];
  cipher_manifest?: OrgCipherManifestView | null;
}

export interface DecodedRoster {
  orgId: string;
  version: number;
  parentCanonicalSha256: Uint8Array;
  timestamp: string;
  entries: Array<{ userId: string; role: string }>;
  orgSymKeyId: string;
}

/** Decode roster canonical bytes via the WASM binding. Throws on
 *  malformed bytes. NO signature verification (that's C.6). */
export async function decodeRoster(roster: SignedOrgRosterWire): Promise<DecodedRoster> {
  const hekate = await loadHekateCore();
  return hekate.decodeOrgRosterCanonical(b64decode(roster.canonical_b64));
}

/** Subset of `GET /api/v1/orgs/{id}` we need for the read-only
 *  detail view. Mirrors `crates/hekate-server/src/routes/orgs.rs::OrgView`.
 *  C.6 will reach for the rest (my_protected_org_key, signing_pubkey,
 *  owner_protected_signing_seed) when invite/accept/rotate flows ship.
 */
export interface OrgFull {
  id: string;
  name: string;
  signing_pubkey: string;
  /** Owner's signature over the org bundle (org_id, name, signing_pubkey,
   *  owner_user_id). Threaded into invite payloads so invitees verify
   *  end-to-end under the inviter's pinned key. */
  bundle_sig: string;
  owner_user_id: string;
  org_sym_key_id: string;
  roster: SignedOrgRosterWire;
  roster_version: number;
  roster_updated_at: string;
  my_role: string;
  /** EncString v3 — caller's wrapped copy of the org symmetric key,
   *  unwrapped under their account_key. Needed for any write op that
   *  produces ciphertext under the org sym key (collections, org
   *  ciphers). */
  my_protected_org_key: string;
  /** EncString v3 of the org signing seed under the OWNER's account_key.
   *  Only present when the caller IS the owner — they need it to sign
   *  new rosters when inviting / removing members. */
  owner_protected_signing_seed?: string;
  /** Map user_id → email for co-members (server-side join against
   *  the users table). Lets the client render emails instead of
   *  raw UUIDs. May be missing entries for deleted users / cascade
   *  races; render the user_id as a fallback. */
  member_emails?: Record<string, string>;
  /** GH #2/#3: users who have a pending invite for this org but
   *  haven't accepted yet. Owner sees this populated; non-owner
   *  members see an empty/absent map. Each value carries `role` and
   *  optional `email` so the UI can render the row identically to
   *  accepted members but tagged as pending. */
  pending_invitees?: Record<string, { role: string; email?: string }>;
}

export async function fetchOrgFull(orgId: string): Promise<OrgFull> {
  return apiGet<OrgFull>(`/api/v1/orgs/${encodeURIComponent(orgId)}`);
}
