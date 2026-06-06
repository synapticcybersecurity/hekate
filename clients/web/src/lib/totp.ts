/* TOTP code computation.
 *
 * RFC 6238 generation now lives in hekate-core (Rust, validated against the
 * RFC 6238 Appendix B vectors) and is reached through the wasm binding — the
 * web vault no longer hand-rolls the crypto. Accepts either a bare base32
 * secret or a full `otpauth://` URI.
 */
import { loadHekateCore } from "../wasm";

export interface TotpResult {
  code: string;
  /** Seconds remaining in the current period. */
  remaining: number;
  /** Period length in seconds (typically 30). */
  period: number;
}

export async function totpCode(secretOrUrl: string): Promise<TotpResult> {
  const core = await loadHekateCore();
  const now = Math.floor(Date.now() / 1000);
  return core.totpCode(secretOrUrl, now);
}
