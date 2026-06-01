/* Desktop owner-mode gate.
 *
 * In the browser the web vault is same-origin, so it goes straight to
 * the Owner shell. In the desktop shell we first ensure a server URL is
 * configured: if none is set, show the one-time ServerConfig screen;
 * once a base exists, hand off to the normal Owner flow unchanged.
 *
 * The Owner shell can request re-configuration ("Change server" in
 * Settings), which drops back to ServerConfig; saving a new server clears
 * the session so the next login targets the new backend.
 */
import { createSignal, Show } from "solid-js";

import { getApiBase, hasApiBase } from "../../lib/config";
import { clearSession } from "../../lib/session";
import { Owner } from "../owner/Owner";
import { ServerConfig } from "./ServerConfig";

export function DesktopOwner() {
  const [configured, setConfigured] = createSignal(hasApiBase());
  return (
    <Show
      when={configured()}
      fallback={
        <ServerConfig
          initialUrl={getApiBase()}
          onSaved={() => {
            // New backend → drop any in-memory/persisted session so the
            // next screen is a clean login against the chosen server.
            clearSession();
            setConfigured(true);
          }}
          // First run (no base yet) can't cancel — a server must be picked.
          // The Settings-driven change flow can back out.
          onCancel={hasApiBase() ? () => setConfigured(true) : undefined}
        />
      }
    >
      <Owner onChangeServer={() => setConfigured(false)} />
    </Show>
  );
}
