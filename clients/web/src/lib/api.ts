/* Fetch wrappers for the web vault.
 *
 * Public/anonymous flow (C.1): `postJSON` for the Send recipient path.
 *
 * Authenticated flow (C.3+): `authedFetch` injects the in-memory access
 * token, transparently refreshes once on 401 by hitting
 * `/identity/connect/token` with `grant_type=refresh_token`, updates
 * the in-memory session (rolling refresh tokens are single-use —
 * replaying an old one revokes the family), and retries. A second 401
 * means the user must re-authenticate.
 */
import { getSession, persistRefreshToken, replaceTokens } from "./session";

export class ApiError extends Error {
  status: number;
  body: unknown;
  constructor(status: number, message: string, body: unknown) {
    super(message);
    this.status = status;
    this.body = body;
    this.name = "ApiError";
  }
}

async function readErrorMessage(r: Response): Promise<{ message: string; body: unknown }> {
  let body: unknown = null;
  try {
    body = await r.json();
  } catch {
    /* empty / non-JSON */
  }
  let message = `${r.status} ${r.statusText}`;
  if (body && typeof body === "object" && "error" in body) {
    const err = (body as { error?: unknown }).error;
    if (typeof err === "string" && err) message = err;
  }
  return { message, body };
}

export async function postJSON<T>(url: string, body: unknown): Promise<T> {
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const { message, body: errBody } = await readErrorMessage(r);
    throw new ApiError(r.status, message, errBody);
  }
  if (r.status === 204) return null as T;
  return (await r.json()) as T;
}

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface AuthedFetchOptions {
  body?: unknown;
  headers?: Record<string, string>;
}

/** Authenticated fetch with one-shot refresh-on-401 retry. Throws
 *  `SessionExpiredError` if the refresh fails — caller should send the
 *  user back to the login screen. */
export async function authedFetch(
  method: HttpMethod,
  path: string,
  opts: AuthedFetchOptions = {},
): Promise<Response> {
  const session = getSession();
  if (!session) throw new SessionExpiredError("no active session");

  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  // The body can be:
  //   - undefined / null  → no body
  //   - string             → sent as-is (caller already serialized)
  //   - ArrayBuffer / typed array → sent as-is for opaque uploads (tus)
  //   - anything else      → JSON.stringify + content-type if not set
  let body: BodyInit | undefined;
  if (opts.body !== undefined && opts.body !== null) {
    if (typeof opts.body === "string") {
      body = opts.body;
    } else if (opts.body instanceof ArrayBuffer || ArrayBuffer.isView(opts.body)) {
      body = opts.body as BodyInit;
    } else {
      body = JSON.stringify(opts.body);
      if (!headers["content-type"]) headers["content-type"] = "application/json";
    }
  }

  const exec = (token: string) =>
    fetch(path, {
      method,
      headers: { ...headers, authorization: `Bearer ${token}` },
      body,
    });

  let r = await exec(session.accessToken);
  if (r.status !== 401) return r;

  const refreshed = await tryRefreshToken(session.refreshToken);
  if (!refreshed) throw new SessionExpiredError("refresh failed");

  replaceTokens(refreshed.accessToken, refreshed.refreshToken);
  if (refreshed.protectedAccountPrivateKey !== undefined) {
    session.protectedAccountPrivateKey = refreshed.protectedAccountPrivateKey;
  }
  // Persist the new refresh token under whichever tier the user picked
  // at login (sessionStorage vs localStorage); the helper inspects
  // localStorage["hekate.remember_me"] to decide.
  persistRefreshToken(refreshed.refreshToken);

  r = await exec(refreshed.accessToken);
  return r;
}

/** Convenience: GET + JSON body parse. Throws `ApiError` on non-2xx. */
export async function apiGet<T>(path: string): Promise<T> {
  const r = await authedFetch("GET", path);
  if (!r.ok) {
    const { message, body } = await readErrorMessage(r);
    throw new ApiError(r.status, message, body);
  }
  if (r.status === 204) return null as T;
  return (await r.json()) as T;
}

interface RefreshResult {
  accessToken: string;
  refreshToken: string;
  protectedAccountPrivateKey?: string | null;
}

async function tryRefreshToken(refreshToken: string): Promise<RefreshResult | null> {
  try {
    const r = await fetch("/identity/connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      }).toString(),
    });
    if (!r.ok) return null;
    const body = (await r.json()) as {
      access_token: string;
      refresh_token: string;
      protected_account_private_key?: string | null;
    };
    return {
      accessToken: body.access_token,
      refreshToken: body.refresh_token,
      protectedAccountPrivateKey: body.protected_account_private_key,
    };
  } catch {
    return null;
  }
}

export class SessionExpiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SessionExpiredError";
  }
}
