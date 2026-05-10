/* TOTP code computation. Lifted from
 * clients/extension/popup/popup.js:3319-3379. Pure browser crypto
 * (`crypto.subtle.sign`); no WASM call needed.
 *
 * Accepts either a bare base32 secret or a full `otpauth://` URI.
 */

export interface TotpResult {
  code: string;
  /** Seconds remaining in the current period. */
  remaining: number;
  /** Period length in seconds (typically 30). */
  period: number;
}

export async function totpCode(secretOrUrl: string): Promise<TotpResult> {
  let secret = secretOrUrl.trim();
  let period = 30;
  let digits = 6;
  let algo: "SHA-1" | "SHA-256" | "SHA-512" = "SHA-1";

  if (secret.startsWith("otpauth://")) {
    const url = new URL(secret);
    const params = url.searchParams;
    secret = params.get("secret") || "";
    const periodParam = params.get("period");
    if (periodParam) period = parseInt(periodParam, 10) || 30;
    const digitsParam = params.get("digits");
    if (digitsParam) digits = parseInt(digitsParam, 10) || 6;
    const a = (params.get("algorithm") || "SHA1").toUpperCase().replace("-", "");
    if (a === "SHA1") algo = "SHA-1";
    else if (a === "SHA256") algo = "SHA-256";
    else if (a === "SHA512") algo = "SHA-512";
    else throw new Error(`unsupported algorithm: ${params.get("algorithm")}`);
  }
  if (!secret) throw new Error("no secret");

  const keyBytes = base32Decode(secret.replace(/\s+/g, "").toUpperCase());
  const now = Math.floor(Date.now() / 1000);
  const counter = Math.floor(now / period);
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes as unknown as ArrayBuffer,
    { name: "HMAC", hash: algo },
    false,
    ["sign"],
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBuf));
  const offset = sig[sig.length - 1] & 0x0f;
  const truncated =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  const code = (truncated % 10 ** digits).toString().padStart(digits, "0");
  return { code, remaining: period - (now % period), period };
}

function base32Decode(s: string): Uint8Array {
  const ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = s.replace(/=+$/, "").toUpperCase();
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const c of clean) {
    const v = ALPH.indexOf(c);
    if (v < 0) throw new Error(`bad base32 char: ${c}`);
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}
