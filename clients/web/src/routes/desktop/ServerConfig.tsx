/* Desktop first-run: pick a Hekate server.
 *
 * The web vault is served by `hekate-server` itself, so it talks to the
 * API same-origin and never needs to ask where the server is. The
 * desktop app loads its UI from inside the app bundle, so on first run it
 * must learn which Hekate server to point at — a self-hosted box or the
 * managed `hekate.synapticcyber.com`. We validate the URL by hitting the
 * unauthenticated `/api/v1/version` endpoint before persisting it, so a
 * typo or a non-Hekate host is caught here rather than at login.
 *
 * Only ever rendered in the desktop shell (see DesktopOwner). The web
 * build keeps the empty same-origin base and never mounts this.
 */
import { createSignal, Show } from "solid-js";

import { setApiBase } from "../../lib/config";

interface VersionResponse {
  version?: string;
}

/** Upper bound on the first-run version probe so an unreachable host can't
 *  hang the screen indefinitely (global standard: timeout every outbound
 *  call). */
const PROBE_TIMEOUT_MS = 10_000;

/** Trim and strip a trailing slash; prepend https:// if no scheme given. */
function normalizeInput(raw: string): string {
  let v = raw.trim().replace(/\/+$/, "");
  if (v && !/^https?:\/\//i.test(v)) v = `https://${v}`;
  return v;
}

export function ServerConfig(props: {
  onSaved: () => void;
  /** Pre-fill (used by the Settings "Change server" flow). */
  initialUrl?: string;
  /** When set, render a Cancel button (change-server can back out;
   *  first-run cannot — a server must be picked). */
  onCancel?: () => void;
}) {
  const [url, setUrl] = createSignal(props.initialUrl ?? "");
  const [error, setError] = createSignal<string | null>(null);
  const [checking, setChecking] = createSignal(false);

  async function onSubmit(e: Event) {
    e.preventDefault();
    setError(null);
    const base = normalizeInput(url());
    if (!base) {
      setError("Enter your Hekate server URL.");
      return;
    }
    setChecking(true);
    // Bound the probe: an unreachable or black-holed host must not hang the
    // first-run screen forever. Abort after 10s and report it distinctly.
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
    try {
      // Probe the unauthenticated version endpoint to confirm the URL
      // really points at a Hekate server before we commit it.
      const r = await fetch(`${base}/api/v1/version`, {
        headers: { accept: "application/json" },
        signal: controller.signal,
      });
      if (!r.ok) {
        setError(`Server responded ${r.status} ${r.statusText}. Check the URL.`);
        return;
      }
      const body = (await r.json().catch(() => null)) as VersionResponse | null;
      if (!body || typeof body.version !== "string") {
        setError("That URL responded, but doesn't look like a Hekate server.");
        return;
      }
      setApiBase(base);
      props.onSaved();
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") {
        setError(
          `Server didn't respond within ${PROBE_TIMEOUT_MS / 1000}s. Check the URL and your connection.`,
        );
      } else {
        setError("Couldn't reach that server. Check the URL and your connection.");
      }
    } finally {
      clearTimeout(timeout);
      setChecking(false);
    }
  }

  return (
    <main class="page">
      <h1>{props.onCancel ? "Change server" : "Hekate"}</h1>
      <p class="muted" style="margin: 0 0 1.25rem;">
        {props.onCancel
          ? "Point the app at a different Hekate server. Switching servers signs you out of the current one."
          : "Connect to your Hekate server. Enter the address of a self-hosted server or the managed service. You can change this later in Settings."}
      </p>

      <form class="card" onSubmit={onSubmit}>
        <div class="field">
          <label for="server-url">Server URL</label>
          <input
            id="server-url"
            type="text"
            inputmode="url"
            autocapitalize="none"
            autocomplete="off"
            spellcheck={false}
            autofocus
            placeholder="https://hekate.synapticcyber.com"
            value={url()}
            onInput={(e) => setUrl(e.currentTarget.value)}
          />
        </div>
        <Show when={error()}>
          <div class="banner banner-error">{error()}</div>
        </Show>
        <div style="display: flex; gap: 0.5rem; align-items: center;">
          <button class="btn" type="submit" disabled={checking()}>
            {checking() ? "Connecting…" : "Connect"}
          </button>
          <Show when={props.onCancel}>
            <button
              class="btn btn-secondary"
              type="button"
              disabled={checking()}
              onClick={() => props.onCancel?.()}
            >
              Cancel
            </button>
          </Show>
        </div>
      </form>

      <p class="muted" style="font-size: 0.85rem; margin-top: 1rem;">
        Decryption always happens on this device; the server never sees
        your master password. Choosing a server only tells the app where
        to sync your encrypted vault.
      </p>
    </main>
  );
}
