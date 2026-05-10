/* Strict-manifest toggle.
 *
 * Off by default (warn-only) to match the popup default. When on, a
 * manifest signature mismatch blocks vault rendering instead of just
 * surfacing a banner. Persisted in localStorage.
 */

const KEY = "hekate.strict_manifest";

export function isStrictManifest(): boolean {
  return localStorage.getItem(KEY) === "1";
}

export function setStrictManifest(on: boolean): void {
  localStorage.setItem(KEY, on ? "1" : "0");
}
