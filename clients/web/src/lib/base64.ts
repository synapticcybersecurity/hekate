/* Base64 helpers — both alphabets, no-pad on output, padding-tolerant
 * on input. Mirrors clients/extension/popup/popup.js:363-378 so the wire
 * format the SPA produces is byte-identical to the popup's. The server
 * accepts both standard (`+/`) and URL-safe (`-_`) variants.
 */

export function b64decode(s: string): Uint8Array {
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

export function b64encode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 1) {
    s += String.fromCharCode(bytes[i]);
  }
  return btoa(s).replace(/=+$/, "");
}

export function b64urlEncode(bytes: Uint8Array): string {
  return b64encode(bytes).replace(/\+/g, "-").replace(/\//g, "_");
}

export function b64urlDecode(s: string): Uint8Array {
  return b64decode(s.replace(/-/g, "+").replace(/_/g, "/"));
}
