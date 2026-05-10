/* CSPRNG password generator. Lifted from clients/extension/popup/popup.js
 * (generatePassword + randomBelow). Each character class is guaranteed
 * to appear at least once; the rest are uniform across all classes.
 * Uses rejection sampling on `crypto.getRandomValues` to avoid the
 * modulo bias that a naive `% n` introduces.
 */

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/";

export function generatePassword(length = 20): string {
  if (length < 4) {
    throw new Error("password length must be ≥ 4 to satisfy class minimums");
  }
  const all = LOWER + UPPER + DIGITS + SYMBOLS;
  const out: string[] = [
    pickChar(LOWER),
    pickChar(UPPER),
    pickChar(DIGITS),
    pickChar(SYMBOLS),
  ];
  while (out.length < length) out.push(pickChar(all));
  // Fisher-Yates so the four guaranteed positions aren't predictable.
  for (let i = out.length - 1; i > 0; i -= 1) {
    const j = randomBelow(i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out.join("");
}

function pickChar(s: string): string {
  return s[randomBelow(s.length)];
}

function randomBelow(n: number): number {
  const buf = new Uint32Array(1);
  const limit = Math.floor(0x100000000 / n) * n;
  // Rejection sample so the modulo doesn't bias the output for n that
  // doesn't divide 2^32 evenly.
  // eslint-disable-next-line no-constant-condition
  while (true) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % n;
  }
}
