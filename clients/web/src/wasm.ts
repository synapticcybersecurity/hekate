/* WASM core loader.
 *
 * The same `hekate_core` WebAssembly module the browser extension uses
 * (built via `make wasm`). C.0 only proves the wiring works — the
 * module's exported functions get called for real in C.1 (recipient
 * Send decryption: sendDecodeKey, sendDecryptText, attachmentDecrypt).
 *
 * We resolve the WASM URL at runtime against `location.pathname` so the
 * same bundle serves correctly under /web/* AND /send/*. The
 * `@vite-ignore` hint keeps Vite from trying to follow the dynamic
 * import at build time — the file is in `public/wasm/` and Vite copies
 * it verbatim into `dist/wasm/`.
 */
import type { HekateCore } from "./wasm-types";

let cached: Promise<HekateCore> | undefined;

function wasmBaseUrl(): string {
  const path = window.location.pathname;
  if (path.startsWith("/send/") || path === "/send") return "/send/wasm";
  if (path.startsWith("/web/") || path === "/web") return "/web/wasm";
  // `vite dev` serves at /, so honor that for local iteration.
  return "/wasm";
}

export async function loadHekateCore(): Promise<HekateCore> {
  if (!cached) {
    cached = (async () => {
      const base = wasmBaseUrl();
      const mod = await import(/* @vite-ignore */ `${base}/hekate_core.js`);
      // Newer wasm-bindgen deprecated the positional URL form of the
      // init function; the object form is the supported path forward.
      await mod.default({ module_or_path: `${base}/hekate_core_bg.wasm` });
      return mod as unknown as HekateCore;
    })();
  }
  return cached;
}
