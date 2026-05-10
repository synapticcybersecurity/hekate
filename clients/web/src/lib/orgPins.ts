/* Org pin store (C.6).
 *
 * TOFU pins for orgs the user is a member of — keyed by org_id, value
 * carries the org's signing pubkey + bundle fingerprint + last-known
 * signed roster. Without a pin, /sync responses for the org can't be
 * trusted (a malicious server could substitute a different signing key).
 *
 * Storage: localStorage under `hekate.org_pins:<email>` so a different
 * user logging in on the same browser doesn't inherit prior trust.
 * Same boundary the popup uses — `chrome.storage.local["hekate_pins:<user_id>"]`
 * — but localStorage instead of chrome.storage. The web vault and the
 * popup are independent trust sets, just like peer pins.
 *
 * Pin shape mirrors the CLI/popup verbatim so a future migration that
 * sync's pins server-side under account_key is byte-compatible.
 */
import { getSession } from "./session";

export interface OrgPin {
  org_id: string;
  signing_pubkey_b64: string;
  /** `SHA256:<base64-no-pad>` over org bundle canonical bytes. */
  fingerprint: string;
  first_seen_at: string;
  last_roster_version: number;
  last_roster_canonical_b64: string;
}

const PIN_PREFIX = "hekate.org_pins:";

function pinKey(email: string): string {
  return PIN_PREFIX + email.toLowerCase();
}

/** Load all pinned orgs for the current account. */
export function loadOrgPins(): Record<string, OrgPin> {
  const session = getSession();
  if (!session) return {};
  const raw = localStorage.getItem(pinKey(session.email));
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return {};
    return parsed as Record<string, OrgPin>;
  } catch {
    return {};
  }
}

function saveOrgPins(pins: Record<string, OrgPin>): void {
  const session = getSession();
  if (!session) throw new Error("session expired — log in again");
  localStorage.setItem(pinKey(session.email), JSON.stringify(pins));
}

/** Pin or update an org. Used immediately after createOrg / acceptInvite
 *  when we already trust the bundle (we just signed it / verified it
 *  under the inviter's pinned key). */
export function pinOrg(orgId: string, pin: OrgPin): void {
  const pins = loadOrgPins();
  pins[orgId] = pin;
  saveOrgPins(pins);
}

/** Look up a single pin. Returns undefined if not pinned. */
export function getOrgPin(orgId: string): OrgPin | undefined {
  return loadOrgPins()[orgId];
}

/** Remove an org's pin. Used when leaving / being removed from an org;
 *  no-op if not pinned. */
export function unpinOrg(orgId: string): void {
  const pins = loadOrgPins();
  if (!(orgId in pins)) return;
  delete pins[orgId];
  saveOrgPins(pins);
}
