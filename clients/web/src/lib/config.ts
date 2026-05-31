/* Runtime configuration for the SPA.
 *
 * The web vault is served *by* `hekate-server` itself (mounted at
 * `/web/*`), so it talks to the API same-origin: every request uses a
 * bare relative path like `/api/v1/sync` and the browser supplies the
 * host. The desktop app (Tauri) loads its UI from inside the app bundle
 * (`tauri://localhost`), so those relative paths have no server to hit —
 * it must prepend the URL of whichever Hekate server the user points it
 * at.
 *
 * `apiUrl(path)` is the single indirection point. The base defaults to
 * the empty string, which means same-origin — so the web build behaves
 * exactly as before. Only the desktop config screen ever sets a non-empty
 * base (persisted in localStorage), so the web vault is unaffected.
 */

const STORAGE_KEY = "hekate.api_base";

let apiBase = "";

/** Strip trailing slashes so `apiBase + path` never doubles the `/`. */
function normalize(base: string): string {
  return base.trim().replace(/\/+$/, "");
}

// Load any persisted base on startup. Absent in the web build (nothing
// writes the key there), so `apiBase` stays "" and same-origin holds.
try {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored) apiBase = normalize(stored);
} catch {
  /* localStorage unavailable (e.g. SSR / sandboxed context) — keep "". */
}

/** Current API base (no trailing slash). Empty string means same-origin. */
export function getApiBase(): string {
  return apiBase;
}

/** Whether a non-empty server base has been configured. */
export function hasApiBase(): boolean {
  return apiBase !== "";
}

/** Set and persist the API base. Pass "" to clear (back to same-origin). */
export function setApiBase(base: string): void {
  apiBase = normalize(base);
  try {
    if (apiBase) localStorage.setItem(STORAGE_KEY, apiBase);
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* best-effort persistence */
  }
}

/** Whether the SPA is running inside the Tauri desktop shell (vs a
 *  browser). Tauri 2 injects `__TAURI_INTERNALS__` into the webview;
 *  `__TAURI__` is present when `withGlobalTauri` is enabled. Either
 *  signals the desktop build, which is the only context that needs a
 *  configurable server URL. */
export function isDesktop(): boolean {
  if (typeof window === "undefined") return false;
  const w = window as unknown as Record<string, unknown>;
  return "__TAURI_INTERNALS__" in w || "__TAURI__" in w;
}

/** Resolve an API path against the configured base.
 *  - Same-origin (web build): base is "" → returns the path unchanged.
 *  - Desktop: base is the server URL → returns an absolute URL.
 *  Absolute URLs are passed through untouched. */
export function apiUrl(path: string): string {
  if (/^https?:\/\//i.test(path)) return path;
  return apiBase + path;
}

/** Origin to build user-facing share links (Send URLs) against.
 *  - Web build: base is "" → the page is served by the server itself, so
 *    `window.location.origin` is the right, browsable origin.
 *  - Desktop: the page is served from the app bundle (`tauri://localhost`),
 *    so `window.location.origin` would produce an unusable `tauri://` link.
 *    Use the configured server base instead, which is where the recipient
 *    mode (`/send/*`) is actually mounted.
 *  Falls back to `getApiBase()` when `window` is absent (SSR/sandboxed). */
export function shareBaseUrl(): string {
  const base = getApiBase();
  if (base) return base;
  if (typeof window !== "undefined") return window.location.origin;
  return "";
}
