/* Desktop owner-mode gate.
 *
 * In the browser the web vault is same-origin, so it goes straight to
 * the Owner shell. In the desktop shell we first ensure a server URL is
 * configured: if none is set, show the one-time ServerConfig screen;
 * once a base exists, hand off to the normal Owner flow unchanged.
 */
import { createSignal, Show } from "solid-js";

import { hasApiBase } from "../../lib/config";
import { Owner } from "../owner/Owner";
import { ServerConfig } from "./ServerConfig";

export function DesktopOwner() {
  const [configured, setConfigured] = createSignal(hasApiBase());
  return (
    <Show
      when={configured()}
      fallback={<ServerConfig onSaved={() => setConfigured(true)} />}
    >
      <Owner />
    </Show>
  );
}
