/* Share-URL parser, ported verbatim from the popup.
 * Source: clients/extension/popup/popup.js:2626-2644 (parseShareUrl).
 *
 * Share URLs have the canonical form
 *   <server>/send/#/<send_id>/<send_key_b64>
 * where the recipient key is in the URL fragment so it never reaches
 * the server. The web vault is mounted at /send/* and reads the
 * fragment client-side via this helper.
 */

export interface ParsedShareUrl {
  sendId: string;
  sendKeyB64: string;
}

export function parseShareFragment(hash: string): ParsedShareUrl {
  const frag = hash.replace(/^#?\/?/, "");
  const slash = frag.indexOf("/");
  if (slash < 0) {
    throw new Error("URL fragment must be #/<send_id>/<send_key>");
  }
  const sendId = frag.slice(0, slash);
  const sendKeyB64 = frag.slice(slash + 1);
  if (!sendId || !sendKeyB64) {
    throw new Error("URL fragment must be #/<send_id>/<send_key>");
  }
  return { sendId, sendKeyB64 };
}
